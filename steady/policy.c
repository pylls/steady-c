#include <string.h>
#include "steady.h"

// for internal use only
void _steady_encode_policy(struct steady_policy* p, unsigned char* buf) {
  int i = 0;
  memcpy(buf, p->id, steady_identifier_size);
  i += steady_identifier_size;
  memcpy(buf+i, p->vk, steady_verification_key_size);
  i += steady_verification_key_size;
  memcpy(buf+i, p->pub, steady_public_key_size);
  i += steady_public_key_size;
  steady_write64be(&buf[i], p->timeout);
  i+=8;
  steady_write64be(&buf[i], p->space);
  i+=8;
  steady_write64be(&buf[i], p->time);
}

int steady_make_policy(struct steady_policy* p,
  unsigned char *sk, unsigned char *vk, unsigned char *pub,
  uint64_t timeout, uint64_t space, uint64_t time) {
    steady_randbytes(p->id, steady_identifier_size);
    memcpy(p->vk, vk, steady_verification_key_size);
    memcpy(p->pub, pub, steady_public_key_size);
    p->timeout = timeout;
    p->space = space;
    p->time = time;

    unsigned char encoded[steady_wire_policy_size-steady_signature_size];
    _steady_encode_policy(p, encoded);
    steady_sign(p->signature, encoded, steady_wire_policy_size-steady_signature_size, sk);

    return 0;
  }

void steady_encode_policy(struct steady_policy* p,
  unsigned char buf[steady_wire_policy_size]) {
    _steady_encode_policy(p, buf);
    memcpy(buf+steady_wire_policy_size-steady_signature_size,
      p->signature, steady_signature_size);
}

int steady_verify_encoded_policy(unsigned char* encoded, uint64_t size) {
  if (size != steady_wire_policy_size)
    return -1;

  return steady_verify(encoded+steady_wire_policy_size-steady_signature_size,
    encoded, steady_wire_policy_size-steady_signature_size,
    encoded+steady_identifier_size);
}
