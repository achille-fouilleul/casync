from libc.stdint cimport uint8_t, uint64_t

cdef extern from "cachunk.h":
    cdef enum CaChunkCompression:
        UNCOMPRESSED, COMPRESSED, AS_IS

cdef extern from "cachunkid.h":
    enum: CA_CHUNK_ID_SIZE
    ctypedef union CaChunkID:
        uint8_t bytes[CA_CHUNK_ID_SIZE]
        uint64_t u64[4]

cdef extern from "caindex.h":
    cdef struct CaIndex:
        pass

    CaIndex *ca_index_new_read()
    CaIndex *ca_index_unref(CaIndex *i)
    int ca_index_set_path(CaIndex *i, const char *path)
    int ca_index_open(CaIndex *i)
    int ca_index_read_chunk(CaIndex *i, CaChunkID *id, uint64_t *ret_offset_end, uint64_t *ret_size)
    int ca_index_set_position(CaIndex *i, uint64_t position)
    int ca_index_get_position(CaIndex *i, uint64_t *ret)
    int ca_index_get_total_chunks(CaIndex *i, uint64_t *ret)

cdef extern from "castore.h":
    cdef struct CaStore:
        pass

    CaStore *ca_store_new()
    CaStore *ca_store_unref(CaStore *store)
    int ca_store_set_path(CaStore *store, const char *path)
    int ca_store_get(CaStore *store, const CaChunkID *chunk_id, CaChunkCompression desired_compression, const void **ret, uint64_t *ret_size, CaChunkCompression *ret_effective_compression)
    int ca_store_has(CaStore *store, const CaChunkID *chunk_id)
