#include "steady.h"

void* steady_mem_alloc(uint64_t num) {
  return malloc(num);
}

void steady_mem_free(void *address) {
  free(address);
}
