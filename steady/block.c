#include <string.h>
#include "steady.h"

// make_payload attempts to make the payload, returning 0 on error, otherwise
// the length of the constructed payload.
uint64_t steady_make_payload(unsigned char *payload, uint64_t payload_max_size,
  struct steady_event* events, uint64_t events_num,
  struct steady_policy* p, int encrypt, int compress,
  unsigned char *payload_hash, unsigned char *root_hash) {
    uint64_t payload_size = 0;

    // merkle tree and random IV
    unsigned char iv[steady_iv_size];
    randombytes_buf(iv, steady_iv_size);
    steady_merkle_tree_hash(events, events_num, root_hash);

    if (compress != 0) {
      unsigned char buffer[2];
      struct steady_compresser *c = steady_compresser_new(payload, payload_max_size);
      if (c == NULL)
        return 0;

      for (int i = 0; i < events_num; i++) {
        steady_write16be(buffer, events[i].size);
        if (steady_compresser_write(c, buffer, 2) == 0)
          return 0;
        if (steady_compresser_write(c, events[i].data, events[i].size) == 0)
          return 0;
      }
      if (steady_compresser_write(c, iv, steady_iv_size) == 0)
        return 0;

      payload_size = steady_compresser_done(c);
      if (payload_size <= 0)
        return 0;
    } else { // no compression: just put the data there...or nothing? enc
      for (int i = 0; i < events_num; i++) {
        if (payload_size + 2 + events[i].size > payload_max_size) {
          return 0;
        }
        steady_write16be(payload+payload_size, events[i].size);
        payload_size += 2;
        memcpy(payload+payload_size, events[i].data, events[i].size);
        payload_size += events[i].size;
      }

      // copy over IV
      if (payload_size + steady_iv_size > payload_max_size) {
        return 0;
      }
      memcpy(payload+payload_size, iv, steady_iv_size);
      payload_size += steady_iv_size;
    }

    // encrypt payload?
    if (encrypt != 0) {
      payload_size = steady_encrypt_overwrite(p->pub, payload, payload_size,
        payload_max_size);
      if (payload_size == 0)
          return 0;
    }

    // calculate root_hash
    steady_khash(root_hash, iv, steady_iv_size, root_hash, steady_hash_size);

    // calculate payload_hash
    steady_khash(payload_hash, p->id, steady_identifier_size, payload, payload_size);

    return payload_size;
}

// returns 0 on error, otherwise the size of the resulting block
uint64_t steady_make_block(unsigned char *dst, uint64_t dst_size,
  uint64_t index, uint64_t len_prev, uint64_t timestamp,
  struct steady_event* data, uint64_t data_num,
  struct steady_policy* p, int encrypt, int compress, unsigned char *sk) {
    if (dst_size < steady_wire_block_header_size ||
        dst_size > steady_max_block_size) {
      return 0;
    }

    // helpers below, maybe can turn into defines?
    unsigned char *payload_hash = dst+8*3;
    unsigned char *header_hash = payload_hash+steady_hash_size;
    unsigned char *root_hash = header_hash+steady_hash_size;

    // attempt to make the payload
    uint64_t len_cur = steady_make_payload(dst+steady_wire_block_header_size,
      dst_size-steady_wire_block_header_size,
      data, data_num, p, encrypt, compress, payload_hash, root_hash);
    if (len_cur == 0) // failed to make payload
      return 0;

    len_cur += steady_wire_block_header_size; //OK, see args to make_payload
    if (len_cur > p->space) // we can never get bigger than what policy allows
      return 0;

    // write integers of header
    steady_write64be(dst, index);
    steady_write64be(dst+8, len_cur);
    steady_write64be(dst+16, len_prev);
    steady_write64be(dst+24+3*steady_hash_size, timestamp);

    // calculate header_hash
    unsigned char opt[2];
    (encrypt != 0) ? (opt[0] = steady_wire_true) : (opt[0] = steady_wire_false);
    (compress != 0) ? (opt[1] = steady_wire_true) : (opt[1] = steady_wire_false);
    steady_khash2(header_hash, p->id, steady_identifier_size,
      dst, 24+steady_hash_size, opt, 2);

    // sign header_hash||root_hash||time
    if (steady_sign(dst+32+3*steady_hash_size,
      dst+24+1*steady_hash_size, 2*steady_hash_size+8, sk) != 0) {
      return 0;
    }

    return len_cur;
}

int steady_check_block_header(unsigned char *bh, unsigned char *id, unsigned char *vk) {
  if (steady_verify(bh+32+3*steady_hash_size, bh+24+1*steady_hash_size,
    2*steady_hash_size+8, vk) != 0)
      return -1;


    // verify block header hash
    int options(unsigned char *b, unsigned char *id, int encrypt, int compress) {
      unsigned char opt[2];
      unsigned char header_hash[steady_hash_size];
      (encrypt != 0) ? (opt[0] = steady_wire_true) : (opt[0] = steady_wire_false);
      (compress != 0) ? (opt[1] = steady_wire_true) : (opt[1] = steady_wire_false);
      steady_khash2(header_hash, id, steady_identifier_size,
        b, 24+steady_hash_size, opt, 2);
      return strncmp((const char*)(b+24+steady_hash_size),
        (const char*)header_hash, steady_hash_size) == 0;
    }

  if (options(bh, id, 0, 0) || options(bh, id, 0, 1) ||
    options(bh, id, 1, 0) || options(bh, id, 1, 1))
    return 0;

  return -1;
}

uint64_t steady_get_max_block_size(struct steady_policy* p) {
  if (steady_max_block_size > p->space)
    return p->space;
  return steady_max_block_size;
}
