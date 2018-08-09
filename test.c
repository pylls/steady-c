#include <stdio.h>
#include <string.h>
#include "minunit.h"
#include "steady/steady.h"

#define _test_hash_0 "03170a2e7597b7b7e3d84c05391d139a62b157e78786d8c082f29dcf4c111314"
#define _test_data_1 ((unsigned char*) "\x00")
#define _test_size_1 1
#define _test_hash_1 "607844f4b0299f5c45d63dd035de1f8d697711c7f092b8fa82325f670f6d386a"
#define _test_data_2 ((unsigned char*) "\x10")
#define _test_size_2 1
#define _test_hash_2 "6ee5d7ded74104b2316b73f9843e14d16d9c5f553a39cbd7da7c3c8238fe0b0e"
#define _test_data_3 ((unsigned char*) "\x20\x21")
#define _test_size_3 2
#define _test_hash_3 "dad1013557a71536d36ab10db2ea4847bed7ded78aa9d2682ffc0e221e758444"
#define _test_data_4 ((unsigned char*) "\x30\x31")
#define _test_size_4 2
#define _test_hash_4 "a69507075082f2f7bd0e3e23bd31d7082c4c78ce98d87d897f7990eecf7d6ec5"
#define _test_data_5 ((unsigned char*) "\x40\x41\x42\x43")
#define _test_size_5 4
#define _test_hash_5 "76840409bd8cc8be20c053d9569472d0bbea7b4f483cd5ae0624ef253c64f227"
#define _test_data_6 ((unsigned char*) "\x50\x51\x52\x53\x54\x55\x56\x57")
#define _test_size_6 8
#define _test_hash_6 "ae8349a901b95ac305157e4ff4f5cf486653fed085ea4dd59a59c9375682933e"
#define _test_data_7 ((unsigned char*) "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f")
#define _test_size_7 16
#define _test_hash_7 "59cc7108743d34853ea37ea07558da3407712c7f0fdb76e59753eb243e0c438e"

int tests_run = 0;

// eqhex2bin returns 0 iff the hex equals the hex encoding of the provided binary data.
int eqhex2bin(char* const hex, const int hex_len,
    const unsigned char * const bin, const int bin_len) {
      char* bex = steady_mem_alloc(bin_len*2 + 1);
      sodium_bin2hex(bex, bin_len*2 + 1, bin, bin_len);
      int result = sodium_memcmp(hex, bex, hex_len);
      steady_mem_free(bex);
      return result;
}

static char * test_steady_merkle_tree_hash() {
  unsigned char* digest = steady_mem_alloc(steady_hash_size);
  struct steady_event* events = steady_mem_alloc(8* sizeof(struct steady_event));

  events[0].size = 0; // empty data
  steady_merkle_tree_hash(events, 1, digest);
  if (eqhex2bin(_test_hash_0, sizeof _test_hash_0, digest, steady_hash_size) != 0) {
    return "invalid hash for test hash #0";
  }
  events[1].data = _test_data_1;
  events[1].size = _test_size_1;
  steady_merkle_tree_hash(events, 2, digest);
  if (eqhex2bin(_test_hash_1, sizeof _test_hash_1, digest, steady_hash_size) != 0) {
    return "invalid hash for test hash #1";
  }
  events[2].data = _test_data_2;
  events[2].size = _test_size_2;
  steady_merkle_tree_hash(events, 3, digest);
  if (eqhex2bin(_test_hash_2, sizeof _test_hash_2, digest, steady_hash_size) != 0) {
    return "invalid hash for test hash #2";
  }
  events[3].data = _test_data_3;
  events[3].size = _test_size_3;
  steady_merkle_tree_hash(events, 4, digest);
  if (eqhex2bin(_test_hash_3, sizeof _test_hash_3, digest, steady_hash_size) != 0) {
    return "invalid hash for test hash #3";
  }
  events[4].data = _test_data_4;
  events[4].size = _test_size_4;
  steady_merkle_tree_hash(events, 5, digest);
  if (eqhex2bin(_test_hash_4, sizeof _test_hash_4, digest, steady_hash_size) != 0) {
    return "invalid hash for test hash #4";
  }
  events[5].data = _test_data_5;
  events[5].size = _test_size_5;
  steady_merkle_tree_hash(events, 6, digest);
  if (eqhex2bin(_test_hash_5, sizeof _test_hash_5, digest, steady_hash_size) != 0) {
    return "invalid hash for test hash #5";
  }
  events[6].data = _test_data_6;
  events[6].size = _test_size_6;
  steady_merkle_tree_hash(events, 7, digest);
  if (eqhex2bin(_test_hash_6, sizeof _test_hash_6, digest, steady_hash_size) != 0) {
    return "invalid hash for test hash #6";
  }
  events[7].data = _test_data_7;
  events[7].size = _test_size_7;
  steady_merkle_tree_hash(events, 8, digest);
  if (eqhex2bin(_test_hash_7, sizeof _test_hash_7, digest, steady_hash_size) != 0) {
    return "invalid hash for test hash #7";
  }

  steady_mem_free(digest);
  steady_mem_free(events);
  return 0;
}

static char * test_steady_make_policy() {
  unsigned char vk[steady_verification_key_size], sk[steady_signing_key_size];
  if (steady_signing_key_gen(vk,sk) < 0) {
    return "failed to generate signing key-pair";
  }
  unsigned char pub[steady_public_key_size], pk[steady_private_key_size];
  if (steady_enc_key_gen(pub, pk) < 0) {
    return "failed to generate encryption key-pair";
  }
  struct steady_policy p;

  if (steady_make_policy(&p, sk, vk, pub, 0, 1, 2) < 0) {
    return "failed to make policy";
  }

  return 0;
}

static char * test_steady_make_block() {
  // tested above, needed to make block
  unsigned char vk[steady_verification_key_size], sk[steady_signing_key_size];
  steady_signing_key_gen(vk,sk);
  unsigned char pub[steady_public_key_size], pk[steady_private_key_size];
  steady_enc_key_gen(pub, pk);
  struct steady_policy p;
  steady_make_policy(&p, sk, vk, pub, 10, 100*1024, 2);

  struct steady_event* events = steady_mem_alloc(2* sizeof(struct steady_event));
  events[0].data = ((unsigned char*) "hello");
  events[0].size = 5;
  events[1].data = ((unsigned char*) "world");
  events[1].size = 5;
  uint64_t block_size = steady_wire_block_header_size+steady_iv_size+10+2*2;
  unsigned char *block = steady_mem_alloc(block_size+steady_iv_size);

  // checks on block without compression (predictable size)
  if (steady_make_block(block, block_size, 0, 1, 2, events, 2, &p, 0, 0, sk) == 0) {
    return "failed to make block with just enough space";
  }
  if (steady_make_block(block, block_size-1, 0, 1, 2, events, 2, &p, 0, 0, sk) != 0) {
    return "made block with too little space";
  }
  if (steady_make_block(block, block_size+1, 0, 1, 2, events, 2, &p, 0, 0, sk) == 0) {
    return "failed to make block with extra space";
  }
  if (steady_make_block(block, 0, 0, 1, 2, events, 2, &p, 0, 0, sk) != 0) {
    return "made block with too little space";
  }

  steady_mem_free(events);
  steady_mem_free(block);
  return 0;
}

static char * test_compresser() {
  size_t plain_len = 12;
  unsigned char block[100], plain[plain_len];
  char* msg = "hello world";

  struct steady_compresser *c = steady_compresser_new(block, 100);
  if (c == NULL)
    return "failed to create compresser";

  for (int i = 0; i < 12; i++) {
    if (steady_compresser_write(c, (unsigned char*)msg+i, 1) == 0)
      return "failed to compress";
  }
  uint64_t size = steady_compresser_done(c);
  if (size == 0)
    return "failed to complete compresser_done";

  LZ4F_dctx *dec;
  LZ4F_errorCode_t err = LZ4F_createDecompressionContext(&dec, LZ4F_VERSION);
  if (LZ4F_isError(err))
    return "failed to create LZ4 decompression context";

  size_t ret = LZ4F_decompress(dec, plain, &plain_len, block, &size, NULL);
  if (LZ4F_isError(ret))
    return "failed to decompress :/\n";

  if (strncmp((const char*)msg, (const char*)plain, plain_len) != 0)
    return "different message after decompression";

  LZ4F_freeDecompressionContext(dec);
  return 0;
}

static char * test_steady_encrypt_decrypt() {
  #define TEST_MSG (unsigned char *) "test"
  #define TEST_MSG_LEN 4

  unsigned char pub[steady_public_key_size], pk[steady_private_key_size];
  steady_enc_key_gen(pub, pk);

  unsigned char data[TEST_MSG_LEN+steady_enc_overhead];
  memcpy(data, TEST_MSG, TEST_MSG_LEN);

  if (steady_encrypt_overwrite(pub, data, TEST_MSG_LEN,
    TEST_MSG_LEN+steady_enc_overhead) == 0)
      return "failed to encrypt";

  unsigned char out[TEST_MSG_LEN];
  if (steady_decrypt(out, TEST_MSG_LEN,
    data, TEST_MSG_LEN+steady_enc_overhead,
    pub, pk) != 0)
      return "failed to decrypt";

  if (strncmp((char *)out, (char *)TEST_MSG, TEST_MSG_LEN) != 0)
    return "got different message after decryption";

  return 0;
}

static char * all_tests() {
    mu_run_test(test_steady_merkle_tree_hash);
    mu_run_test(test_steady_make_policy);
    mu_run_test(test_steady_make_block);
    mu_run_test(test_steady_encrypt_decrypt);
    mu_run_test(test_compresser);

    return 0;
}

int main(int argc, char **argv) {
    char *result = all_tests();
    if (result != 0) {
        printf("%s\n", result);
    }
    else {
        printf("ALL TESTS PASSED\n");
    }
    printf("Tests run: %d\n", tests_run);

    return result != 0;
}
