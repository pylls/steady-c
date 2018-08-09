#include <math.h>
#include <string.h>
#include <arpa/inet.h>
#include "steady.h"

void steady_write64be(unsigned char out[8], uint64_t in) {
  uint64_t be = __builtin_bswap64(in);
  memcpy(out, &be, 8);
}

void steady_write16be(unsigned char out[2], uint16_t in) {
  uint64_t be = htons(in);
  memcpy(out, &be, 2);
}

uint64_t steady_be64toh(unsigned char in[8]) {
  uint64_t be;
  memcpy(&be, in, 8);
  return __builtin_bswap64(be);
}

int steady_hash(unsigned char *out,
  const unsigned char *in, unsigned long long inlen) {
    return crypto_generichash(out, crypto_generichash_BYTES, in, inlen, NULL, 0);
}

int steady_khash(unsigned char *out,
  const unsigned char *key, unsigned long long keylen,
  const unsigned char *in, unsigned long long inlen) {
    return crypto_generichash(out, crypto_generichash_BYTES, in, inlen, key, keylen);
}

int steady_khash2(unsigned char *out,
  const unsigned char *key, unsigned long long keylen,
  const unsigned char *in1, unsigned long long in1len,
  const unsigned char *in2, unsigned long long in2len) {
    crypto_generichash_state state;
    crypto_generichash_init(&state, key, keylen, steady_hash_size);
    crypto_generichash_update(&state, in1, in1len);
    crypto_generichash_update(&state, in2, in2len);
    return crypto_generichash_final(&state, out, steady_hash_size);
}

int steady_khash3(unsigned char *out,
  const unsigned char *key, unsigned long long keylen,
  const unsigned char *in1, unsigned long long in1len,
  const unsigned char *in2, unsigned long long in2len,
  const unsigned char *in3, unsigned long long in3len) {
    crypto_generichash_state state;
    crypto_generichash_init(&state, key, keylen, steady_hash_size);
    crypto_generichash_update(&state, in1, in1len);
    crypto_generichash_update(&state, in2, in2len);
    crypto_generichash_update(&state, in3, in3len);
    return crypto_generichash_final(&state, out, steady_hash_size);
}

int steady_signing_key_gen(unsigned char *vk, unsigned char *sk) {
  return crypto_sign_keypair(vk, sk);
}

int steady_sign(unsigned char *signature,
  const unsigned char *m, unsigned long long mlen,
  const unsigned char *sk) {
    return crypto_sign_detached(signature, NULL, m, mlen, sk);
}

int steady_verify(const unsigned char *signature,
  const unsigned char *m, unsigned long long mlen,
  const unsigned char *vk) {
    return crypto_sign_verify_detached(signature, m, mlen, vk);
}

int steady_enc_key_gen(unsigned char *pub, unsigned char *pk) {
  steady_randbytes(pk, steady_public_key_size);
  return crypto_scalarmult_base(pub, pk);
}

// data MUST have at least steady_enc_overhead bytes left after size,
// returns 0 on error, otherwise lenght of ciphertext
int steady_encrypt_overwrite(unsigned char *pub, unsigned char *data,
  uint64_t msg_size, uint64_t total_size) {
    unsigned char ephm_pub[steady_public_key_size];
    unsigned char ephm_pk[steady_private_key_size];
    unsigned char secret[steady_public_key_size];

    steady_enc_key_gen(ephm_pub, ephm_pk); // ephemeral public
    if(crypto_scalarmult(secret, ephm_pk, pub) != 0) // compute secret
      return 0;

    unsigned char key[crypto_generichash_BYTES];
    unsigned char nonce[crypto_generichash_BYTES]; // only use the first 12 bytes
    steady_kdf(key, secret, pub, ephm_pub, (unsigned char *) "key", 3);
    steady_kdf(nonce, secret, pub, ephm_pub, (unsigned char *) "nonce", 5);

    long long unsigned int total_size_rewritten = total_size;
    crypto_aead_aes256gcm_encrypt(data,
      &total_size_rewritten, //overwrite
      data, msg_size, // the message
      ephm_pub, steady_public_key_size, // associated data
      NULL, nonce, key);
    memcpy(data+msg_size+crypto_aead_aes256gcm_ABYTES,
      ephm_pub, steady_public_key_size);

    return msg_size+steady_enc_overhead;
}

int steady_decrypt(unsigned char *out, uint64_t outlen,
  unsigned char *ct, uint64_t ctlen,
  unsigned char *pub, unsigned char *pk) {
    unsigned char *ephm_pub;
    unsigned char secret[steady_public_key_size];

    if (ctlen < steady_public_key_size+crypto_aead_aes256gcm_ABYTES)
      return -1;

    ephm_pub = ct+ctlen-steady_public_key_size;
    if(crypto_scalarmult(secret, pk, ephm_pub) != 0)
      return -1;

    unsigned char key[crypto_generichash_BYTES];
    unsigned char nonce[crypto_generichash_BYTES];
    steady_kdf(key, secret, pub, ephm_pub, (unsigned char *) "key", 3);
    steady_kdf(nonce, secret, pub, ephm_pub, (unsigned char *) "nonce", 5);

    long long unsigned int outlen_rewritten = outlen;
    return crypto_aead_aes256gcm_decrypt(out, &outlen_rewritten,
                                  NULL,
                                  ct, ctlen-steady_public_key_size,
                                  ephm_pub, steady_public_key_size,
                                  nonce, key);
}

int steady_kdf(unsigned char *out, unsigned char *secret,
  unsigned char *p1, unsigned char *p2, unsigned char *use, uint64_t use_len) {
    crypto_generichash_state state;
    crypto_generichash_init(&state, NULL, 0, steady_hash_size);
    crypto_generichash_update(&state, secret, steady_public_key_size);
    crypto_generichash_update(&state, p1, steady_public_key_size);
    crypto_generichash_update(&state, p2, steady_public_key_size);
    crypto_generichash_update(&state, use, use_len);
    return crypto_generichash_final(&state, out, steady_hash_size);
  }

void steady_randbytes(void * const buf, const size_t size) {
  return randombytes_buf(buf, size);
}

void steady_merkle_tree_hash(struct steady_event* events, uint64_t n,
  unsigned char* digest) {
    crypto_generichash_state state;
    crypto_generichash_init(&state, NULL, 0, steady_hash_size);
    unsigned char leaf_prefix = steady_leaf_prefix;
    unsigned char node_prefix = steady_node_prefix;

    if (n <= 0) {
      steady_hash(digest, NULL, 0);
      return;
    } else if (n == 1) {
      crypto_generichash_update(&state, &leaf_prefix, sizeof leaf_prefix);
      crypto_generichash_update(&state, events->data, events->size);
      crypto_generichash_final(&state, digest, steady_hash_size);
      return;
    }

    // MTH(D[n]) = HASH(0x01 || MTH(D[0:k]) || MTH(D[k:n])), where
  	// k is the largest power of two smaller than n (i.e., k < n <= 2k)
    int k = pow(2,ceil(log2(n)-1));
    crypto_generichash_update(&state, &node_prefix, sizeof node_prefix);
    steady_merkle_tree_hash(events, k, digest);
    crypto_generichash_update(&state, digest, steady_hash_size);
    steady_merkle_tree_hash(&events[k], n-k, digest);
    crypto_generichash_update(&state, digest, steady_hash_size);
    crypto_generichash_final(&state, digest, steady_hash_size);
    return;
}
