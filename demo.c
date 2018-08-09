#include <stdio.h>
#include <unistd.h>
#include "steady/device.h"

int main(int argc, char const *argv[]) {
  if (sodium_init() == -1) {
    printf("failed to initalize sodium\n");
    return 1;
  }
  if (argc != 5) {
    printf("need exactly four arguments: server_ip mem_limit(MiB) encrypt_flag compress_flag\n");
    return 1;
  }
  struct steady_device device;
  uint64_t mem_limit = atoi(argv[2])*1024*1024;
  uint64_t flush_size = 512*1024;
  int encrypt = atoi(argv[3]);
  int compress = atoi(argv[4]);
  printf("flush size = %ld, memory limit %ld, encrypt = %d, compress = %d\n",
    flush_size, mem_limit, encrypt, compress);

  int err = steady_load_device(&device, "test", (char *)argv[1], 22333, (unsigned char *)"secret",
  6, encrypt, compress, flush_size, mem_limit);
  switch(err) {
    case -1:
      printf("missing config file at %s\n", "test");
      return -1;
    case -2:
      printf("unreasonable memory limitation (%ld) given flush size (%ld) and policy space (%ld)\n",
      mem_limit, flush_size, device.policy.space);
      return -2;
    case -3:
      printf("network error with relay at %s:%d\n", (char *)argv[1], 22333);
      return -3;
    case -4:
      printf("invalid auth token for relay\n");
      return -4;
    case -5:
      printf("failed to get consistent state with relay\n");
      return -5;
    case -6:
      printf("failed to create logging threads\n");
      return -6;
  }

  char msg[steady_max_event_size];
  int return_value, count = 0, size = 0;
  uint64_t total_size = 0;
  while (1) {
    if (fgets(msg, steady_max_event_size, stdin) == NULL)
      break;

    for (int i = 0; i < steady_max_event_size; i++) {
      if (msg[i] == '\0')
        break;
      size = i+1;
    }

    do {
        return_value = steady_log(&device, msg, size);
    } while (return_value != 0);
    count++;
    total_size += size;
  }

  steady_close(&device);
  printf("sent %d events (%lu KiB), state is %ld\n", count, total_size/1024, device.state_next_index);

  return 0;
}
