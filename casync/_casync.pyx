#cython: language_level=3

from ._casync_defn cimport *

def _check_return_code(rc, message):
    if rc < 0:
        raise RuntimeError("%s (errno=%d)" % (message, -rc))

cdef class IndexReader:
    cdef CaIndex *handle

    def __cinit__(self):
        self.handle = ca_index_new_read()
        if self.handle is NULL:
            raise MemoryError("ca_index_new_read failed.")

    def __dealloc__(self):
        ca_index_unref(self.handle)

    def set_path(self, path):
        path_bytes = path.encode()
        r = ca_index_set_path(self.handle, path_bytes)
        _check_return_code(r, "ca_index_set_path failed.")

    def open(self):
        r = ca_index_open(self.handle)
        _check_return_code(r, "ca_index_open failed.")

    def read_chunks(self):
        cdef uint64_t nchunks
        cdef CaChunkID chunk_id
        cdef uint64_t offset_end, chunk_size

        r = ca_index_get_total_chunks(self.handle, &nchunks)
        _check_return_code(r, "ca_index_get_total_chunks failed.")

        r = ca_index_set_position(self.handle, 0)
        _check_return_code(r, "ca_index_set_position failed.")

        chunks = []
        cdef uint64_t pos = 0
        for i in range(nchunks):
            r = ca_index_read_chunk(self.handle, &chunk_id, &offset_end, &chunk_size)
            _check_return_code(r, "ca_index_read_chunk failed.")
            if pos + chunk_size != offset_end:
                raise RuntimeError("Index inconsistency.")

            if chunk_size == 0:
                raise RuntimeError("Zero-size chunk.")

            chunks.append((pos, bytes(chunk_id.bytes[:CA_CHUNK_ID_SIZE]), chunk_size))
            pos += chunk_size

        return chunks

cdef class StoreReader:
    cdef CaStore *handle

    def __cinit__(self):
        self.handle = ca_store_new()
        if self.handle is NULL:
            raise MemoryError("ca_store_new failed.")

    def __dealloc__(self):
        ca_store_unref(self.handle)

    def set_path(self, path):
        path_bytes = path.encode()
        r = ca_store_set_path(self.handle, path_bytes)
        _check_return_code(r, "ca_store_set_path failed.")

    def has(self, id):
        cdef CaChunkID chunk_id
        chunk_id.bytes = id[:]
        return ca_store_has(self.handle, &chunk_id) != 0