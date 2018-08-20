#ifndef STEADY_HEADER
#define STEADY_HEADER

#include <math.h>
#include <sodium.h>
#include "lz4/lz4frame.h"

// commands for the simple wire protocol
#define steady_wire_version 0x42 // default version
#define steady_wire_cmd_status 0x0
#define steady_wire_cmd_setup  0x1
#define steady_wire_cmd_read   0x2
#define steady_wire_cmd_write  0x3
#define steady_wire_true  0x1
#define steady_wire_false 0x0
#define steady_wire_more 0xA
#define steady_wire_auth_error 0xF
#define steady_wire_auth_size steady_hash_size

// cryptographic keys
#define steady_public_key_size crypto_box_PUBLICKEYBYTES
#define steady_private_key_size crypto_box_SECRETKEYBYTES
int steady_enc_key_gen(unsigned char *pub, unsigned char *pk);

#define steady_verification_key_size crypto_sign_PUBLICKEYBYTES
#define steady_signature_size crypto_sign_BYTES
int steady_signing_key_gen(unsigned char *vk, unsigned char *sk);

// policy
#define steady_identifier_size 32
struct steady_policy {
  unsigned char id[steady_identifier_size], vk[steady_verification_key_size], pub[steady_public_key_size];
  uint64_t timeout, space, time;
  unsigned char signature[steady_signature_size];
};

int steady_make_policy(struct steady_policy* p,
  unsigned char *sk, unsigned char *vk, unsigned char *pub,
  uint64_t timeout, uint64_t space, uint64_t timestamp);
void steady_encode_policy(struct steady_policy* p, unsigned char* buf);
int steady_verify_encoded_policy(unsigned char* encoded, uint64_t size);

#define steady_wire_policy_size (steady_identifier_size + steady_signature_size \
 + steady_verification_key_size + steady_public_key_size + 3*8)

// events are what makes up a block that are sent
struct steady_event {
  unsigned char *data;
  uint16_t size;
};
#define steady_max_event_size 65535
#define steady_wire_block_overhead (steady_wire_block_header_size +  LZ4F_HEADER_SIZE_MAX \
  + steady_enc_overhead + steady_iv_size)
uint64_t steady_make_block(unsigned char *dst, uint64_t dst_size,
  uint64_t index, uint64_t len_prev, uint64_t timestamp,
  struct steady_event* events, uint64_t events_num,
  struct steady_policy* p, int encrypt, int compress, unsigned char *sk);
uint64_t steady_get_max_block_size(struct steady_policy* p);
#define steady_wire_block_header_size (4*8 + 3*steady_hash_size \
  + steady_signature_size)
int steady_check_block_header(unsigned char *bh, unsigned char *id, unsigned char *vk);

/*
 * Below here only supporting functions and defines that a user should not have
 * to care about.
 */

#define steady_max_block_size (104857600) // 100 MiB

// supporting memory management functions
void* steady_mem_alloc(uint64_t num);
void steady_mem_free(void *address);

// supporting host-to-network byte order functions
void steady_write64be(unsigned char out[8], uint64_t in);
void steady_write16be(unsigned char out[2], uint16_t in);
uint64_t steady_be64toh(unsigned char *in);

// supporting crypto defines and functions, arguments inspired by libsodium
#define steady_hash_size crypto_generichash_BYTES
#define steady_signing_key_size crypto_sign_SECRETKEYBYTES
#define steady_enc_overhead (steady_public_key_size + crypto_aead_aes256gcm_ABYTES)
#define steady_iv_size 32
#define steady_leaf_prefix ((unsigned char) 0x00)
#define steady_node_prefix ((unsigned char) 0x01)
int steady_hash(unsigned char *out,
  const unsigned char *in, unsigned long long inlen);
int steady_khash(unsigned char *out,
  const unsigned char *key, unsigned long long keylen,
  const unsigned char *in, unsigned long long inlen);
int steady_khash2(unsigned char *out,
  const unsigned char *key, unsigned long long keylen,
  const unsigned char *in1, unsigned long long in1len,
  const unsigned char *in2, unsigned long long in2len);
int steady_khash3(unsigned char *out,
  const unsigned char *key, unsigned long long keylen,
  const unsigned char *in1, unsigned long long in1len,
  const unsigned char *in2, unsigned long long in2len,
  const unsigned char *in3, unsigned long long in3len);
int steady_sign(unsigned char *signature,
  const unsigned char *m, unsigned long long mlen, const unsigned char *sk);
int steady_verify(const unsigned char *signature,
  const unsigned char *m, unsigned long long mlen, const unsigned char *vk);
int steady_encrypt_overwrite(unsigned char *pub, unsigned char *data,
  uint64_t msg_size, uint64_t total_size);
int steady_decrypt(unsigned char *out, uint64_t outlen,
  unsigned char *ct, uint64_t ctlen,
  unsigned char *pub, unsigned char *pk);
void steady_randbytes(void * const buf, const size_t size);
void steady_merkle_tree_hash(struct steady_event* events, uint64_t n,
  unsigned char* digest);
int steady_kdf(unsigned char *out, unsigned char *secret,
  unsigned char *p1, unsigned char *p2, unsigned char *use, uint64_t use_len);

// compression
#define steady_compressor_buffer_size (64*1024) // 64KiB ideal for lz4?
struct steady_compresser {
  LZ4F_cctx* lz4;
  LZ4F_preferences_t* lz4_pref;
  unsigned char buffer[steady_compressor_buffer_size];
  uint64_t buffer_current, total_written, dst_max_size;
  unsigned char *dst;
};
struct steady_compresser* steady_compresser_new(unsigned char* dst,
  uint64_t dst_max_size);
uint64_t steady_compresser_done(struct steady_compresser *c);
int steady_compresser_flush(struct steady_compresser *c);
int steady_compresser_write(struct steady_compresser *c,
  unsigned char* src, uint64_t len);

#endif
