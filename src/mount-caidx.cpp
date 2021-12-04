#define FUSE_USE_VERSION 26

#include <cassert>
#include <cstdarg>
#include <cstring>
#include <exception>
#include <iostream>
#include <list>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>
#include <unistd.h>
#include <fuse/fuse_lowlevel.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>

extern "C" {
#include "caformat.h"
#include "caindex.h"
#include "castore.h"
#include "log.h"
#include "signal-handler.h"
#include "siphash24.h"
}

#define NONCOPYABLE(X) X(X&) = delete; X& operator=(X&);

using std::exception;
using std::make_unique;
using std::map;
using std::move;
using std::string;
using std::string_view;
using std::vector;

class CaSyncError final : public std::runtime_error
{
    using runtime_error::runtime_error;
};

class VolumeError final : public std::runtime_error
{
    int m_err_code;

public:
    VolumeError(int err_code, std::string message)
        : runtime_error(move(message))
        , m_err_code(err_code)
    {
    }

    int err_code() const { return m_err_code; }
};

struct CaIndexDeleter
{
    void operator()(CaIndex* i) const noexcept { ca_index_unref(i); }
};

using CaIndexPtr = std::unique_ptr<CaIndex, CaIndexDeleter>;

struct CaStoreDeleter
{
    void operator()(CaStore* s) const noexcept { ca_store_unref(s); }
};

using CaStorePtr = std::unique_ptr<CaStore, CaStoreDeleter>;

static void check_return_code(int r, const char* fmt, ...) __attribute__ ((format (printf, 2, 3)));

static void check_return_code(int r, const char* fmt, ...)
{
    va_list ap;
    if (r < 0) {
        va_start(ap, fmt);
        int save_errno = errno;
        errno = -r;
        char* text_cstr = nullptr;
        vasprintf(&text_cstr, fmt, ap);
        errno = save_errno;
        va_end(ap);
        string text(text_cstr);
        free(text_cstr);
        throw CaSyncError(move(text));
    }
}

static uint64_t filename_hash(string_view filename)
{
    static const uint8_t key[16] = CA_FORMAT_GOODBYE_HASH_KEY;
    return siphash24(filename.data(), filename.size(), key);
}

struct DirEntry
{
    ino_t ino;
    string_view name;
};

struct NameTable
{
    struct Item
    {
        uint64_t hash;
        string name;
        ino_t node_index;
    };

    vector<Item> items;

    void add(uint64_t hash, string name, ino_t node_index)
    {
        items.push_back({hash, move(name), node_index});
    }
};

class Node
{
public:
    using Ref = std::unique_ptr<Node>;
    Node() = default;

    NONCOPYABLE(Node)

    virtual ~Node() {}

    mode_t mode;
    uint64_t flags;
    uid_t uid;
    gid_t gid;
    uint64_t mtime;

    virtual ino_t get_parent_node_index() const
    {
        throw VolumeError(ENOTDIR, "Not a directory.");
    }

    virtual void set_parent_node_index(ino_t ino) {}

    virtual const vector<DirEntry>& get_dir_entries() const
    {
        throw VolumeError(ENOTDIR, "Not a directory.");
    }

    virtual void set_name_table(NameTable name_table)
    {
        throw VolumeError(ENOTDIR, "Not a directory.");
    }

    virtual const char* get_symlink_target_c_str() const
    {
        throw VolumeError(EINVAL, "Not a symlink.");
    }

    virtual void set_symlink_target(string value)
    {
        throw VolumeError(EINVAL, "Not a symlink.");
    }

    virtual void set_device(dev_t value)
    {
        throw VolumeError(EINVAL, "Not a device.");
    }

    virtual dev_t get_rdev() const { return 0; }
    virtual off_t get_size() const { return 0; }

    virtual void set_content(off_t start, off_t length)
    {
        throw VolumeError(EISDIR, "Not a regular file.");
    }

    virtual std::pair<off_t, off_t> get_content()
    {
        throw VolumeError(EISDIR, "Not a regular file.");
    }

    virtual std::optional<ino_t> find_entry(string_view name) const
    {
        throw VolumeError(ENOTDIR, "Not a directory.");
    }
};

class DirNode final : public Node
{
    NameTable m_name_table;
    ino_t m_parent_ino = FUSE_ROOT_ID;
    vector<DirEntry> m_entries;

    static int cmp(uint64_t hash, string_view name, const NameTable::Item& item)
    {
        if (hash != item.hash) {
            return hash < item.hash ? -1 : 1;
        }

        // TODO: primary key is (hash, start_offset), check that casync make
        // sorts entries by name.
        if (name != item.name) {
            return name < item.name ? -1 : 1;
        }

        return 0;
    }

    std::optional<ino_t> binary_search(uint64_t hash, string_view name) const
    {
        auto& items = m_name_table.items;
        size_t i = 0, n = items.size();
        for (;;) {
            if (i >= n) {
                return std::nullopt;
            }

            auto& item = items[i];
            int r = cmp(hash, name, item);
            if (r == 0) {
                return item.node_index;
            }

            i = 2 * i + (r < 0 ? 1 : 2);
        }
    }

public:
    off_t get_size() const override { return 0x1000; }

    ino_t get_parent_node_index() const override
    {
        return m_parent_ino;
    }

    void set_parent_node_index(ino_t ino) override
    {
        m_parent_ino = ino;
    }

    void set_name_table(NameTable name_table) override
    {
        m_name_table = move(name_table);
        for (auto& item : m_name_table.items) {
            DirEntry de = {
                .ino = item.node_index,
                .name = item.name
            };

            m_entries.push_back(de);
        }
    }

    const vector<DirEntry>& get_dir_entries() const override { return m_entries; }

    std::optional<ino_t> find_entry(string_view name) const override
    {
        auto hash = filename_hash(name);
        return binary_search(hash, name);
    }
};

class DevNode final : public Node
{
    dev_t m_rdev = 0;

public:
    dev_t get_rdev() const override { return m_rdev; }

    void set_device(dev_t value) override
    {
        m_rdev = value;
    }
};

class RegNode final : public Node
{
    off_t m_start = 0;
    off_t m_size = 0;

public:
    off_t get_size() const override { return m_size; }

    std::pair<off_t, off_t> get_content() override
    {
        return {m_start, m_size};
    }

    void set_content(off_t start, off_t size) override
    {
        m_start = start;
        m_size = size;
    }
};

class SymlinkNode final : public Node
{
    string m_target;

public:
    off_t get_size() const override { return m_target.size(); }

    void set_symlink_target(string value) override
    {
        m_target = move(value);
    }

    const char* get_symlink_target_c_str() const override
    {
        return m_target.c_str();
    }
};

class StoreReader
{
    string m_path;
    CaStorePtr m_cas;

public:
    StoreReader(string path)
        : m_path(move(path))
        , m_cas(ca_store_new())
    {
        int r = ca_store_set_path(m_cas.get(), m_path.c_str());
        check_return_code(r, "ca_store_set_path failed %s : %m", m_path.c_str());
    }

    bool has(const CaChunkID& id) const
    {
        return ca_store_has(m_cas.get(), &id);
    }

    auto get(const CaChunkID& id)
    {
        char id_str[CA_CHUNK_ID_FORMAT_MAX];
        if (false) printf("get chunk %s\n", ca_chunk_id_format(&id, id_str));
        const void* chunk_data = nullptr;
        size_t chunk_size = 0;
        CaChunkCompression compression;
        int r = ca_store_get(m_cas.get(), &id, CA_CHUNK_UNCOMPRESSED, &chunk_data, &chunk_size, &compression);
        check_return_code(r, "ca_store_get failed : %m");
        assert(compression == CA_CHUNK_UNCOMPRESSED);
        if (false) printf("chunk_size=%zu\n", chunk_size);
        return std::make_pair(chunk_data, chunk_size);
    }
};

class IndexReader
{
    string m_path;
    map<off_t, std::tuple<CaChunkID, off_t>> m_chunk_map;
    off_t m_size;

public:
    IndexReader(string path)
        : m_path(move(path))
    {
        auto cai = CaIndexPtr(ca_index_new_read());
        int r;
        r = ca_index_set_path(cai.get(), m_path.c_str());
        check_return_code(r, "Unable to set index file %s: %m", m_path.c_str());

        r = ca_index_open(cai.get());
        check_return_code(r, "Failed to open index file %s: %m", m_path.c_str());

        uint64_t nchunks;
        r = ca_index_get_total_chunks(cai.get(), &nchunks);
        check_return_code(r, "ca_index_get_total_chunks : %m");

        off_t pos = 0;
        for (uint64_t i = 0; i < nchunks; ++i) {
            CaChunkID id;
            uint64_t offset_end, chunk_size;
            r = ca_index_read_chunk(cai.get(), &id, &offset_end, &chunk_size);
            check_return_code(r, "ca_index_read_chunk failed : %m");
            assert(pos + chunk_size == offset_end);
            assert(chunk_size != 0);
            auto p = m_chunk_map.insert({offset_end, std::make_tuple(id, chunk_size)});
            assert(p.second);
            pos += chunk_size;
        }

        m_size = pos;
    }

    auto get_size() const { return m_size; }

    auto find_chunk(off_t pos) const
    {
        auto it = m_chunk_map.upper_bound(pos);
        if (it == m_chunk_map.end()) {
            throw std::runtime_error("Chunk not found.");
        }

        auto end = it->first;
        auto [id, size] = it->second;
        auto start = end - size;
        assert(start <= pos && pos < end);
        return std::make_tuple(id, start, size);
    }
};

static bool operator<(const CaChunkID& lhs, const CaChunkID& rhs) noexcept
{
    return std::lexicographical_compare(
        std::begin(lhs.u64), std::end(lhs.u64),
        std::begin(rhs.u64), std::end(rhs.u64));
}

static bool operator==(const CaChunkID& lhs, const CaChunkID& rhs) noexcept
{
    return std::equal(
        std::begin(lhs.u64), std::end(lhs.u64),
        std::begin(rhs.u64), std::end(rhs.u64));
}

struct CompareCaChunkIDs
{
    bool operator()(const CaChunkID& lhs, const CaChunkID& rhs) const noexcept
    {
        return lhs < rhs;
    }
};

class IndexStoreCache
{
    IndexReader& m_index;
    StoreReader& m_store;

    static const constexpr size_t MaxLru = 4;

    using IDList = std::list<CaChunkID>;
    IDList m_ids; // from most to least frequently used

#if 0
    struct LruEntry
    {
        IDList::iterator it;
        vector<uint8_t> content;
    };

    std::map<CaChunkID, LruEntry, CompareCaChunkIDs> m_map;

    auto get_chunk_data(const CaChunkID& id)
    {
        char id_str[CA_CHUNK_ID_FORMAT_MAX];
        auto map_it = m_map.find(id);
        if (map_it != m_map.end()) {
            if (false) printf("get chunk %s: hit\n", ca_chunk_id_format(&id, id_str));
            auto& e = map_it->second;
            if (e.it != m_ids.begin()) {
                m_ids.erase(e.it);
                m_ids.push_front(id);
                e.it = m_ids.begin();
            }

            return std::make_pair(e.content.data(), e.content.size());
        }

        if (false) printf("get chunk %s: miss\n", ca_chunk_id_format(&id, id_str));
        auto [chunk_data, chunk_size] = m_store.get(id);
        auto chunk_bytes = reinterpret_cast<const uint8_t*>(chunk_data);
        vector<uint8_t> content(chunk_bytes, chunk_bytes + chunk_size);
        auto p = std::make_pair(content.data(), content.size());
        if (m_map.size() >= MaxLru) {
            // evict least-recently used
            auto lru_id = m_ids.back();
            m_ids.pop_back();
            m_map.erase(lru_id);
        }

        m_ids.push_front(id);
        LruEntry e;
        e.it = m_ids.begin();
        e.content = move(content);
        auto r = m_map.insert({id, move(e)});
        assert(r.second);
        assert(m_map.size() == m_ids.size());

        return p;
    }
#endif

#if 1
    struct LruEntry
    {
        CaChunkID id;
        IDList::iterator it;
        vector<uint8_t> content;
    };

    std::array<LruEntry, MaxLru> m_cache;
    size_t m_cache_length = 0;

    auto find_cache_chunk(const CaChunkID& id)
    {
        auto cache_begin = m_cache.begin();
        auto cache_end = cache_begin + m_cache_length;
        auto cache_it = std::lower_bound(
            cache_begin,
            cache_end,
            id,
            [] (auto& x, auto& y) { return x.id < y; });
        if (cache_it != cache_end && cache_it->id == id) {
            return cache_it;
        }

        return cache_end;
    }

    auto get_chunk_data(const CaChunkID& id)
    {
        char id_str[CA_CHUNK_ID_FORMAT_MAX];

        auto cache_begin = m_cache.begin();
        auto cache_end = cache_begin + m_cache_length;
        auto cache_it = find_cache_chunk(id);
        if (cache_it != cache_end) {
            auto& e = *cache_it;
            assert(e.id == id);
            if (false) printf("get chunk %s: hit\n", ca_chunk_id_format(&id, id_str));
            if (e.it != m_ids.begin()) {
                m_ids.erase(e.it);
                m_ids.push_front(id);
                e.it = m_ids.begin();
            }

            return std::make_pair(e.content.data(), e.content.size());
        }

        if (false) printf("get chunk %s: miss\n", ca_chunk_id_format(&id, id_str));

        auto [chunk_data, chunk_size] = m_store.get(id);
        auto chunk_bytes = reinterpret_cast<const uint8_t*>(chunk_data);
        vector<uint8_t> content(chunk_bytes, chunk_bytes + chunk_size);
        auto p = std::make_pair(content.data(), content.size());
        LruEntry* e;
        if (m_cache_length >= MaxLru) {
            // evict least-recently used
            auto lru_id = m_ids.back();

            cache_it = find_cache_chunk(lru_id);
            assert(cache_it != cache_end);
            e = &*cache_it;
            assert(e->id == lru_id);
            m_ids.pop_back();
        } else {
            e = &m_cache[m_cache_length++];
            ++cache_end;
        }

        m_ids.push_front(id);
        e->id = id;
        e->it = m_ids.begin();
        e->content = move(content);
        std::sort(cache_begin, cache_end, [] (auto& lhs, auto& rhs) { return lhs.id < rhs.id; });

        assert(m_cache_length == m_ids.size());

        return p;
    }
#endif

public:
    IndexStoreCache(IndexReader& index, StoreReader& store)
        : m_index(index)
        , m_store(store)
    {
    }

    void read_bytes(off_t pos, void* data, size_t size)
    {
        auto dst = reinterpret_cast<uint8_t*>(data);
        while (size != 0) {
            auto [id, chunk_start, chunk_size] = m_index.find_chunk(pos);
            auto [chunk_data, chunk_size2] = get_chunk_data(id);
            assert((size_t)chunk_size == (size_t)chunk_size2);
            auto chunk_pos = pos - chunk_start;
            auto src = reinterpret_cast<const uint8_t*>(chunk_data) + chunk_pos;
            auto n = std::min(size, (size_t)(chunk_size - chunk_pos));
            memcpy(dst, src, n);
            pos += n;
            dst += n;
            size -= n;
        }
    }
};

class Decoder
{
    IndexReader& m_index;
    IndexStoreCache& m_index_store_cache;
    vector<Node::Ref> m_nodes;
    int m_level = 0;

    map<uint64_t, string> m_filename_map;
    map<uint64_t, ino_t> m_node_map;
    Node* m_current_node = nullptr;

    void read_bytes(off_t pos, void* data, size_t size)
    {
        return m_index_store_cache.read_bytes(pos, data, size);
    }

    string read_string(off_t pos, const CaFormatHeader& h, size_t offset)
    {
        auto size = h.size;
        if (!(size >= offset + 1)) {
            throw std::runtime_error("Invalid string.");
        }

        string s;
        s.resize(size - (offset + 1));
        read_bytes(pos + offset, &s[0], s.size());
        return s;
    }

    void decode_entry(ptrdiff_t pos, const CaFormatHeader& h);
    void decode_symlink(ptrdiff_t pos, const CaFormatHeader& h);
    void decode_device(ptrdiff_t pos, const CaFormatHeader& h);
    void decode_payload(ptrdiff_t pos, const CaFormatHeader& h);
    void decode_filename(ptrdiff_t pos, const CaFormatHeader& h);
    void decode_goodbye(ptrdiff_t pos, const CaFormatHeader& h);

public:
    Decoder(IndexReader& index, IndexStoreCache& index_store_cache)
        : m_index(index)
        , m_index_store_cache(index_store_cache)
    {
    }

    void load_tree();
    vector<Node::Ref> get_nodes() { return move(m_nodes); }
};

void Decoder::decode_entry(ptrdiff_t pos, const CaFormatHeader& h)
{
    CaFormatEntry e;
    read_bytes(pos, &e, sizeof e);
    auto feature_flags = read_le64(&e.feature_flags);
    auto mode = read_le64(&e.mode);
    auto flags = read_le64(&e.flags);
    auto uid = read_le64(&e.uid);
    auto gid = read_le64(&e.gid);
    auto mtime = read_le64(&e.mtime);

    Node::Ref node_ptr;
    switch (mode & S_IFMT) {
    case S_IFDIR: node_ptr = make_unique<DirNode>(); break;
    case S_IFCHR: node_ptr = make_unique<DevNode>(); break;
    case S_IFBLK: node_ptr = make_unique<DevNode>(); break;
    case S_IFREG: node_ptr = make_unique<RegNode>(); break;
    case S_IFIFO: node_ptr = make_unique<Node>(); break;
    case S_IFLNK: node_ptr = make_unique<SymlinkNode>(); break;
    case S_IFSOCK: node_ptr = make_unique<Node>(); break;
    default: throw std::runtime_error("Unsupported node type.");
    }

    m_current_node = node_ptr.get();
    auto& node = *m_current_node;
    node.mode = mode;
    node.flags = flags;
    node.uid = uid;
    node.gid = gid;
    node.mtime = mtime;
    ino_t node_index = m_nodes.size() + 1;
    m_nodes.emplace_back(move(node_ptr));
    auto p = m_node_map.insert({(uint64_t)pos, node_index});
    assert(p.second);

    if (S_ISDIR(mode)) {
        ++m_level;
    }
}

#define READ_STRING(pos, obj, field) read_string(pos, obj.header, offsetof(std::decay_t<decltype(obj)>, field))

void Decoder::decode_symlink(ptrdiff_t pos, const CaFormatHeader& h)
{
    CaFormatSymlink s;
    read_bytes(pos, &s, sizeof s);
    auto target = READ_STRING(pos, s, target);
    // TODO: validate
    assert(m_current_node != nullptr);
    m_current_node->set_symlink_target(target);
}

void Decoder::decode_device(ptrdiff_t pos, const CaFormatHeader& h)
{
    CaFormatDevice d;
    read_bytes(pos, &d, sizeof d);
    auto maj = read_le64(&d.major);
    auto min = read_le64(&d.minor);
    // TODO: validate
    assert(m_current_node != nullptr);
    m_current_node->set_device(makedev(maj, min));
}

void Decoder::decode_payload(ptrdiff_t pos, const CaFormatHeader& h)
{
    auto size = read_le64(&h.size);
    auto offset = offsetof(CaFormatPayload, data);
    assert(size >= offset); // TODO
    assert(m_current_node != nullptr);
    m_current_node->set_content(pos + offset, size - offset);
}

void Decoder::decode_filename(ptrdiff_t pos, const CaFormatHeader& h)
{
    CaFormatFilename f;
    read_bytes(pos, &f, sizeof f);
    auto filename = READ_STRING(pos, f, name);
    // TODO: validate
    auto p = m_filename_map.insert({(uint64_t)pos, move(filename)});
    assert(p.second); // TODO
}

void Decoder::decode_goodbye(ptrdiff_t pos, const CaFormatHeader& h)
{
    NameTable name_table;
    auto size = read_le64(&h.size);
    assert(size >= offsetof(CaFormatGoodbye, items));
    auto length = size - offsetof(CaFormatGoodbye, items);
    assert(length % sizeof(CaFormatGoodbyeItem) == 0);
    auto nitems = length / sizeof(CaFormatGoodbyeItem);
    assert(nitems != 0);
    for (size_t i = 0; i < nitems; ++i) {
        CaFormatGoodbyeItem gi;
        read_bytes(pos + offsetof(CaFormatGoodbye, items) + i * sizeof(gi), &gi, sizeof gi);
        auto item_offset = pos - read_le64(&gi.offset);
        auto item_size = read_le64(&gi.size);
        auto item_hash = read_le64(&gi.hash);
        if (item_hash != CA_FORMAT_GOODBYE_TAIL_MARKER) {
            assert(i != nitems - 1);
            auto it = m_filename_map.find(item_offset);
            assert(it != m_filename_map.end());
            auto name = it->second;
            assert(filename_hash(name) == item_hash);
            auto it2 = m_node_map.lower_bound(item_offset); // TODO: check against item_size
            assert(it2 != m_node_map.end());
            auto node_index = it2->second;
            m_nodes.at(node_index - 1);
            name_table.add(item_hash, name, node_index);
        } else {
            assert(i == nitems - 1);
            auto it = m_node_map.find(item_offset);
            assert(it != m_node_map.end());
            assert(m_level > 0);
            --m_level;
            auto node_index = it->second;
            auto& node = *m_nodes.at(node_index - 1);
            for (auto& item : name_table.items) {
                auto& child_node = *m_nodes.at(item.node_index - 1);
                child_node.set_parent_node_index(node_index);
            }

            node.set_name_table(move(name_table));
        }
    }
}

static void warn_once_format_type(uint64_t type)
{
    static std::set<uint64_t> warned;
    if (warned.find(type) == warned.end()) {
        fprintf(stderr, "TODO: format type=%#" PRIx64 "\n", type);
        warned.insert(type);
    }
}

void Decoder::load_tree()
{
    for (off_t pos = 0; pos < m_index.get_size();) {
        CaFormatHeader header;
        read_bytes(pos, &header, sizeof header);
        auto size = read_le64(&header.size);
        auto type = read_le64(&header.type);

        switch (type) {
        case CA_FORMAT_ENTRY:
            decode_entry(pos, header);
            break;

        case CA_FORMAT_USER:
        case CA_FORMAT_GROUP:
            // ignored
            break;

        case CA_FORMAT_ACL_USER:
        case CA_FORMAT_ACL_GROUP:
        case CA_FORMAT_ACL_GROUP_OBJ:
            warn_once_format_type(type);
            break;

        case CA_FORMAT_SYMLINK:
            decode_symlink(pos, header);
            break;

        case CA_FORMAT_DEVICE:
            decode_device(pos, header);
            break;

        case CA_FORMAT_PAYLOAD:
            decode_payload(pos, header);
            break;

        case CA_FORMAT_FILENAME:
            decode_filename(pos, header);
            break;

        case CA_FORMAT_GOODBYE:
            decode_goodbye(pos, header);
            break;

        default:
            fprintf(stderr, "Unsupported format type=%#" PRIx64 "\n", type);
            abort(); // TODO
            break;
        }

        pos += size;
    }

    assert(m_level == 0);
}

class Volume
{
    IndexStoreCache* m_index_store_cache = nullptr;
    vector<Node::Ref> m_nodes;
    size_t m_fs_size = 0;

public:
    Volume() = default;

    NONCOPYABLE(Volume)

    void start(IndexStoreCache& index_store_cache, vector<Node::Ref> nodes)
    {
        m_index_store_cache = &index_store_cache;
        m_nodes = move(nodes);
        assert(!m_nodes.empty());
        for (auto& node : m_nodes) {
            m_fs_size += node->get_size();
        }
    }

    Node& get_node_by_index(ino_t ino)
    {
        if (ino == 0 || ino > m_nodes.size()) {
            throw VolumeError(ENOENT, "Invalid node index.");
        }

        return *m_nodes[ino - 1];
    }

    void read_bytes(off_t pos, void* data, size_t size)
    {
        assert(m_index_store_cache != nullptr);
        m_index_store_cache->read_bytes(pos, data, size);
    }

    size_t get_size() const { return m_fs_size; }

    size_t get_node_count() const { return m_nodes.size(); }
};

static void dump_node(Volume& volume, ino_t node_index, string_view path)
{
    auto& node = volume.get_node_by_index(node_index);
    string_view type_str;

    switch (node.mode & S_IFMT) {
    case S_IFDIR: type_str = "dir"; break;
    case S_IFCHR: type_str = "char"; break;
    case S_IFBLK: type_str = "block"; break;
    case S_IFREG: type_str = "file"; break;
    case S_IFIFO: type_str = "fifo"; break;
    case S_IFLNK: type_str = "link"; break;
    case S_IFSOCK: type_str = "socket"; break;
    default: throw std::runtime_error("Unsupported node type.");
    }

    char mode_str[10];
    sprintf(mode_str, "%04o", node.mode & 07777);

    char time_str[30];
    uint32_t mtime_nsec = node.mtime % 1'000'000'000;
    uint64_t mtime_sec = node.mtime / 1'000'000'000;
    sprintf(time_str, "%" PRIu64 ".%09" PRIu32, mtime_sec, mtime_nsec);

    std::cout << (path.empty() ? string_view(".") : path) << " "
        "type=" << type_str << " "
        "mode=" << mode_str << " "
        "uid=" << node.uid << " "
        "gid=" << node.gid << " "
        // TODO: uname, gname, flags
        "time=" << time_str << "\n";

    if (S_ISDIR(node.mode)) {
        auto& entries = node.get_dir_entries();
        for (auto& de : entries) {
            string child_path;
            if (!path.empty()) {
                child_path = path;
                child_path += "/";
            }

            child_path += de.name;
            dump_node(volume, de.ino, child_path);
        }
    }
}

struct FuseArgs
{
    struct fuse_args args;

    FuseArgs(int argc, char* argv[])
    {
        args = FUSE_ARGS_INIT(argc, argv);
    }

    NONCOPYABLE(FuseArgs)

    ~FuseArgs()
    {
        fuse_opt_free_args(&args);
    }
};


class ScopedFuseMount
{
    string m_mountpoint;

public:
    NONCOPYABLE(ScopedFuseMount)

    struct fuse_chan* chan = nullptr;

    ScopedFuseMount(string mountpoint, FuseArgs& fa)
        : m_mountpoint(move(mountpoint))
        , chan(fuse_mount(m_mountpoint.c_str(), &fa.args))
    {
        if (chan == nullptr) {
            throw std::runtime_error("fuse_mount failed.");
        }
    }

    ~ScopedFuseMount()
    {
        fuse_unmount(m_mountpoint.c_str(), chan);
    }
};

class ScopedFuseSession
{
public:
    NONCOPYABLE(ScopedFuseSession)

    struct fuse_session* session = nullptr;

    ScopedFuseSession(FuseArgs& fa, const struct fuse_lowlevel_ops* op, size_t op_size, void* userdata)
        : session(fuse_lowlevel_new(&fa.args, op, op_size, userdata))
    {
        if (session == nullptr) {
            throw std::runtime_error("Cannot create FUSE session.");
        }
    }

    ~ScopedFuseSession()
    {
        if (session != nullptr) {
            fuse_session_destroy(session);
        }

        session = nullptr;
    }
};

class ScopedFuseSignalHandlers
{
    struct fuse_session* m_session;

public:
    NONCOPYABLE(ScopedFuseSignalHandlers)

    ScopedFuseSignalHandlers(ScopedFuseSession& fs)
        : m_session(fs.session)
    {
        if (fuse_set_signal_handlers(m_session)) {
            throw std::runtime_error("Cannot set fuse signal handlers.");
        }
    }

    ~ScopedFuseSignalHandlers()
    {
        fuse_remove_signal_handlers(m_session);
    }
};

class ScopedFuseSessionChannel
{
    struct fuse_chan* m_chan;

public:
    NONCOPYABLE(ScopedFuseSessionChannel)

    ScopedFuseSessionChannel(ScopedFuseSession& fs, ScopedFuseMount& fm)
        : m_chan(fm.chan)
    {
        fuse_session_add_chan(fs.session, m_chan);
    }

    ~ScopedFuseSessionChannel()
    {
        fuse_session_remove_chan(m_chan);
    }
};

static const constexpr struct timespec nsec_to_timespec(uint64_t u)
{
    return timespec {
        .tv_sec = u != UINT64_MAX ? static_cast<time_t>(u / 1'000'000'000) : -1,
        .tv_nsec = u != UINT64_MAX ? static_cast<long>(u % 1'000'000'000) : -1
    };
}

static void fill_stat(struct stat& st, ino_t ino, Node& node)
{
    std::memset(&st, 0, sizeof st);
    st.st_ino = ino;
    st.st_mode = node.mode;
    st.st_nlink = S_ISDIR(node.mode) ? 2 : 1;
    st.st_size = node.get_size();
    st.st_rdev = node.get_rdev();
    st.st_uid = node.uid;
    st.st_gid = node.gid;
    auto tim = nsec_to_timespec(node.mtime);
    st.st_ctim = tim;
    st.st_atim = tim;
    st.st_mtim = tim;
}

static auto& volume_from_req(fuse_req_t req)
{
    return *reinterpret_cast<Volume*>(fuse_req_userdata(req));
}

static void op_lookup(fuse_req_t req, fuse_ino_t parent, const char* name)
{
    try {
        if (false) printf("op_lookup parent=%lu name=%s\n", parent, name);
        auto& volume = volume_from_req(req);
        auto& node = volume.get_node_by_index(parent);
        auto ino_opt = node.find_entry(name);
        if (ino_opt == std::nullopt) {
            fuse_reply_err(req, ENOENT);
            return;
        }

        struct fuse_entry_param ep;
        std::memset(&ep, 0, sizeof ep);
        ep.ino = *ino_opt;
        ep.attr_timeout = 3600.0; // TODO: forever
        ep.entry_timeout = 3600.0; // TODO: forever
        auto& child_node = volume.get_node_by_index(ep.ino);
        fill_stat(ep.attr, ep.ino, child_node);
        fuse_reply_entry(req, &ep);
    }
    catch (const VolumeError& e) {
        fuse_reply_err(req, e.err_code());
    }
}

static void op_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi)
{
    try {
        auto& volume = volume_from_req(req);
        auto& node = volume.get_node_by_index(ino);
        struct stat st;
        fill_stat(st, ino, node);
        fuse_reply_attr(req, &st, 3600.0); // TODO: forever
    }
    catch (const VolumeError& e) {
        fuse_reply_err(req, e.err_code());
    }
}

static void op_readlink(fuse_req_t req, fuse_ino_t ino)
{
    try {
        auto& volume = volume_from_req(req);
        auto& node = volume.get_node_by_index(ino);
        // TODO: access control
        fuse_reply_readlink(req, node.get_symlink_target_c_str());
    }
    catch (const VolumeError& e) {
        fuse_reply_err(req, e.err_code());
    }
}

static void op_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi)
{
    try {
        if (false) printf("op_open ino=%lu\n", ino);
        auto& volume = volume_from_req(req);
        auto& node = volume.get_node_by_index(ino);
        if (!S_ISREG(node.mode)) {
            fuse_reply_err(req, EISDIR);
            return;
        }

        if ((fi->flags & O_ACCMODE) != O_RDONLY) {
            fuse_reply_err(req, EROFS);
            return;
        }

        fi->keep_cache = true;
        fi->fh = reinterpret_cast<uint64_t>(&node);
        if (false) printf("reply_open\n");
        fuse_reply_open(req, fi);
    }
    catch (const VolumeError& e) {
        fuse_reply_err(req, e.err_code());
    }
}

static void op_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info* fi)
{
    try {
        if (false) printf("op_read ino=%lu size=%zu\n", ino, size);
        auto& volume = volume_from_req(req);
        auto& node = *reinterpret_cast<Node*>(fi->fh);
        auto [content_start, content_size] = node.get_content();
        if (off < content_size) {
            auto length = std::min((size_t)(content_size - off), size);
            if (length <= 0x1000) {
                char data[0x1000];
                volume.read_bytes(content_start + off, data, length);
                fuse_reply_buf(req, data, length);
            } else {
                string data(length, '\000');
                volume.read_bytes(content_start + off, &data[0], length);
                fuse_reply_buf(req, data.data(), length);
            }
        } else {
            fuse_reply_buf(req, nullptr, 0);
        }
    }
    catch (const VolumeError& e) {
        fuse_reply_err(req, e.err_code());
    }
}

static void op_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi)
{
    if (false) printf("op_release ino=%lu\n", ino);
    // TODO
    fuse_reply_err(req, 0);
}

static void push_dirent(fuse_req_t req, Volume& volume, vector<char>& buf, string_view name, ino_t ino)
{
    char name_buf[NAME_MAX + 1];
    auto name_length = name.copy(name_buf, NAME_MAX);
    assert(name_length == name.size());
    name_buf[name_length] = 0;
    auto size = fuse_add_direntry(req, nullptr, 0, name_buf, nullptr, 0);
    auto pos = buf.size();
    buf.insert(buf.end(), size, 0);
    struct stat st;
    fill_stat(st, ino, volume.get_node_by_index(ino));
    fuse_add_direntry(req, &buf[pos], buf.size() - pos, name_buf, &st, buf.size());
}

struct ReaddirState
{
    vector<char> buf;
    Node* node = nullptr;
    size_t index = 0;
};

static void op_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi)
{
    try {
        if (false) printf("op_opendir ino=%lu flags=%#x\n", ino, fi->flags);
        auto& volume = volume_from_req(req);
        auto& node = volume.get_node_by_index(ino);
        // TODO: access control. Needed with 'default_permissions'?
        vector<char> buf;
        push_dirent(req, volume, buf, ".", ino);
        push_dirent(req, volume, buf, "..", node.get_parent_node_index());
        auto state = new ReaddirState();
        state->node = &node;
        state->buf = move(buf);
        fi->fh = reinterpret_cast<uint64_t>(state);
        fi->keep_cache = true;
        fuse_reply_open(req, fi);
    }
    catch (const VolumeError& e) {
        fuse_reply_err(req, e.err_code());
    }
}

static void op_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info* fi)
{
    try {
        if (false) printf("op_readdir ino=%lu size=%zu off=%ld\n", ino, size, off);
        auto& volume = volume_from_req(req);
        auto& state = *reinterpret_cast<ReaddirState*>(fi->fh);
        auto& buf = state.buf;
        auto& entries = state.node->get_dir_entries();
        while (buf.size() < off + size && state.index < entries.size()) {
            auto& de = entries[state.index];
            push_dirent(req, volume, buf, de.name, de.ino);
            ++state.index;
        }

        if ((size_t)off < buf.size()) {
            auto length = std::min(buf.size() - off, size);
            if (false) printf("reply_buf length=%zu\n", length);
            fuse_reply_buf(req, &buf[off], length);
        } else {
            if (false) printf("reply_buf length=%zu\n", (size_t)0);
            fuse_reply_buf(req, nullptr, 0);
        }
    }
    catch (const VolumeError& e) {
        fuse_reply_err(req, e.err_code());
    }
}

static void op_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    try {
        if (false) printf("op_releasedir ino=%lu\n", ino);
        delete reinterpret_cast<ReaddirState*>(fi->fh);
        fuse_reply_err(req, 0);
    }
    catch (const VolumeError& e) {
        fuse_reply_err(req, e.err_code());
    }
}

static void op_statfs(fuse_req_t req, fuse_ino_t ino)
{
    auto& volume = volume_from_req(req);
    struct statvfs st;
    std::memset(&st, 0, sizeof st);
    st.f_bsize = 1024;
    static const constexpr size_t FragmentSize = 1024;
    st.f_frsize = FragmentSize;
    st.f_blocks = (volume.get_size() + FragmentSize - 1) / FragmentSize;
    st.f_files = volume.get_node_count();
    st.f_namemax = NAME_MAX;
    st.f_flag = ST_RDONLY | ST_NOATIME | ST_NODIRATIME;
    fuse_reply_statfs(req, &st);
}

static void op_ioctl(fuse_req_t req, fuse_ino_t ino, int cmd, void *arg,
                 struct fuse_file_info *fi, unsigned flags,
                 const void *in_buf, size_t in_bufsz, size_t out_bufsz)
{
    switch (cmd) {
    case TCGETS:
        // Some buggy program calls this ioctl on regular files.
        fuse_reply_err(req, ENOTTY);
        break;

    default:
        fprintf(stderr, "TODO: ioctl %lu %#x\n", ino, cmd);
        fuse_reply_err(req, ENOSYS);
        break;
    }
}

static const struct fuse_lowlevel_ops ops = {
    .lookup = &op_lookup,
    .getattr = &op_getattr,
    .readlink = &op_readlink,
    .open = &op_open,
    .read = &op_read,
    .release = &op_release,
    .opendir = &op_opendir,
    .readdir = &op_readdir,
    .releasedir = &op_releasedir,
    .statfs = &op_statfs,
    .ioctl = &op_ioctl
};

struct VolumeOpts
{
    char* mountpoint = nullptr;
    int multithreaded = false;
    int foreground = false;
    char* index_path = nullptr;
    char* store_path = nullptr;
};

static const struct fuse_opt volume_options[] = {
    { "index=%s", offsetof(VolumeOpts, index_path), 0 },
    { "store=%s", offsetof(VolumeOpts, store_path), 0 },
    FUSE_OPT_END
};

static void print_help(char* exec_path)
{
    char opt_help[] = "--help";
    char* argv[] = { exec_path, opt_help, nullptr };
    struct fuse_args args = FUSE_ARGS_INIT(2, argv);
    // Print general options
    fuse_parse_cmdline(&args, nullptr, nullptr, nullptr);
    // Print FUSE options
    fuse_lowlevel_new(&args, nullptr, 0, nullptr);
    // Print mount.caidx options
    fprintf(stderr,
        "\n"
        "mount.caidx options:\n"
        "    -o index=PATH          set .caidx path\n"
        "    -o store=PATH          set store path\n");
}

static bool is_help(const FuseArgs& fa)
{
    for (int i = 1; i < fa.args.argc; ++i) {
        string_view arg = fa.args.argv[i];
        if (arg == "--help" || arg == "-h") {
            return true;
        }
    }

    return false;
}

class Daemonizer
{
    bool m_foreground = true;
    int m_fds[2];

public:
    NONCOPYABLE(Daemonizer);

    Daemonizer()
    {
        std::fill(std::begin(m_fds), std::end(m_fds), -1);
    }

    void start(bool foreground)
    {
        m_foreground = foreground;
        if (m_foreground) {
            return;
        }

        pipe2(m_fds, O_CLOEXEC); // TODO: check return code

        auto pid = fork();
        if (pid == -1) {
            throw std::runtime_error("fork failed.");
        }

        if (pid != 0) {
            // parent
            close(std::exchange(m_fds[1], -1));
            int exit_code;
            // TODO: timeout?
            read(m_fds[0], &exit_code, sizeof exit_code);
            _exit(exit_code);
        } else {
            // child
            close(std::exchange(m_fds[0], -1));
            int devnull = open("/dev/null", O_RDONLY); // TODO: check return code
            dup2(devnull, STDIN_FILENO);
            close(devnull);
        }
    }

    void notify_exit(int exit_code) noexcept
    {
        int fd = std::exchange(m_fds[1], -1);
        if (fd >= 0) {
            write(fd, &exit_code, sizeof exit_code);
            close(fd);
        }
    }

    ~Daemonizer()
    {
        if (!m_foreground) {
            notify_exit(EXIT_FAILURE);
        }
    }
};

static void inner_main(int argc, char* argv[])
{
    FuseArgs fa(argc, argv);
    if (is_help(fa)) {
        print_help(argv[0]);
        return;
    }

    VolumeOpts opts;
    if (fuse_parse_cmdline(&fa.args, &opts.mountpoint, &opts.multithreaded, &opts.foreground) < 0) {
        throw std::runtime_error("fuse_parse_cmdline failed.");
    }

    Daemonizer daemonizer;
    daemonizer.start(opts.foreground != 0);

    if (fuse_opt_parse(&fa.args, &opts, volume_options, nullptr) < 0) {
        throw std::runtime_error("fuse_opt_parse failed.");
    }

    if (opts.mountpoint == nullptr) {
        throw std::runtime_error("mountpoint not specified.");
    }

    ScopedFuseMount fm(opts.mountpoint, fa);

    Volume volume;
    ScopedFuseSession fs(fa, &ops, sizeof ops, &volume);

    if (opts.index_path == nullptr) {
        throw std::runtime_error("index not specified.");
    }

    if (opts.store_path == nullptr) {
        throw std::runtime_error("store not specified.");
    }

    StoreReader store(opts.store_path);
    IndexReader index(opts.index_path);
    IndexStoreCache index_store_cache(index, store);
    Decoder decoder(index, index_store_cache);
    decoder.load_tree();
    auto nodes = decoder.get_nodes();
    if (nodes.empty()) {
        throw std::runtime_error("Index is empty.");
    }

    volume.start(index_store_cache, move(nodes));
    if (false) dump_node(volume, 1, "");

    ScopedFuseSignalHandlers fsh(fs);
    ScopedFuseSessionChannel fsc(fs, fm);

    if (access("/etc/initrd-release", F_OK) >= 0) {
        argv[0][0] = '@';
    }

    daemonizer.notify_exit(EXIT_SUCCESS);

    int err;
    if (false && opts.multithreaded) {
        err = fuse_session_loop_mt(fs.session); // TODO
    } else {
        err = fuse_session_loop(fs.session);
    }

    if (err < 0) {
        throw std::runtime_error("General fuse error.");
    }
}

int main(int argc, char* argv[])
{
    try {
        inner_main(argc, argv);
        return 0;
    }
    catch (const exception& e) {
        fprintf(stderr, "Error: %s\n", e.what());
        return 1;
    }
}
