#include <string.h>
#include "steady.h"
#include "lz4/lz4frame.h"

struct steady_compresser* steady_compresser_new(unsigned char* dst, uint64_t dst_max_size) {
  // attempt to create lz4 compression context
  struct steady_compresser *c = steady_mem_alloc(sizeof(struct steady_compresser));
  if (LZ4F_createCompressionContext(&c->lz4, LZ4F_VERSION) != 0) {
    steady_mem_free(c);
    return NULL;
  }

  c->lz4_pref = steady_mem_alloc(sizeof(LZ4F_preferences_t));
  memset(c->lz4_pref, 0, sizeof(LZ4F_preferences_t));
  c->lz4_pref->frameInfo.blockMode = LZ4F_blockIndependent;

  c->total_written = LZ4F_compressBegin(c->lz4, dst, dst_max_size, c->lz4_pref);
  if (c->total_written == 0) { // failed to being compressing
    steady_mem_free(c->lz4_pref);
    steady_mem_free(c);
    return NULL;
  }

  c->dst = dst;
  c->buffer_current = 0;
  c->dst_max_size = dst_max_size;
  return c;
}

uint64_t steady_compresser_done(struct steady_compresser *c) {
  steady_compresser_flush(c);
  uint64_t size = LZ4F_compressEnd(c->lz4,
    c->dst+c->total_written, c->dst_max_size-c->total_written, NULL);
  LZ4F_freeCompressionContext(c->lz4);
  if (LZ4F_isError(size))
    size = 0; // 0 signals error
  else
    size += c->total_written;
  steady_mem_free(c->lz4_pref);
  steady_mem_free(c);

  return size;
}

int steady_compresser_flush(struct steady_compresser *c) {
  uint64_t size = LZ4F_compressUpdate(c->lz4,
  c->dst+c->total_written, c->dst_max_size-c->total_written,
  c->buffer, c->buffer_current, NULL);
  if (LZ4F_isError(size))
    return 0;
  c->total_written += size;
  c->buffer_current = 0;

  return c->total_written;
}

int steady_compresser_write(struct steady_compresser *c, unsigned char* src, uint64_t len) {
  if (c->buffer_current + len > steady_compressor_buffer_size) {
    if (steady_compresser_flush(c) == 0)
      return 0;
  }
  memcpy(c->buffer+c->buffer_current, src, len);
  c->buffer_current += len;

  return len;
}
