#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

#include "steady/steady.h"

typedef struct {
  // generated during setup, read from fs, the policy for the device and its signing key
  struct steady_policy policy;
  unsigned char sk[steady_signing_key_size];

  // steady state, read from fs and persisted before exit, can recover if lost
  uint64_t state_next_index, state_prev_time, state_prev_len;

  // a socket for talking to the relay, its access token, and an associated address struct
  int socket, token_len;
  unsigned char *token;
  struct sockaddr_in address;

  // the filesystem path for state
  char* path;

  // encrypt and compress flags
  int encrypt, compress;

  // set at load, how much log data to buffer before making a block
  uint64_t mem_flush_size;

  // working copy of the data to log
  unsigned char *mem_log_data;
  uint64_t mem_log_data_size;

  // working memory for making a block
  unsigned char *mem_block;
  uint64_t mem_block_size;

} steady_mini_device;

#define steady_fs_device_size (steady_signing_key_size + steady_wire_policy_size)
#define steady_fs_state_size 8*3 // three uint64_t
#define steady_fs_device_format ((char*) "%s.device") // shared with demo.c
#define steady_fs_state_format ((char*) "%s.state") // shared with demo.c
#define steady_fs_path_max 4096 // just useful when reading/writing to filesystem
#define steady_device_buffer_num (1024*8) // each one takes 10 bytes

// cleanup: free memory and close socket
void steady_cleanup(steady_mini_device *device);

// connect and send wrappers
int steady_mini_connect(steady_mini_device *device);
size_t steady_mini_send_full(int socket, const void *buf, size_t len);

// from filesystem, read device and read/write state
int steady_fs_mini_state(steady_mini_device* device);
int steady_fs_mini_state_write(steady_mini_device* device);
int steady_fs_mini_device(steady_mini_device* device);

// talk to relay: check status and send a block
int steady_check_status(steady_mini_device* device);
void steady_send_block(steady_mini_device *device, uint64_t block_size);

// core logging logic: read from stdin, buffer, make block and send
int steady_log_stdin(steady_mini_device *device);
int steady_read_stdin(steady_mini_device *device,
  struct steady_event events[steady_device_buffer_num], int *more);

int main(int argc, char const *argv[]) {
  steady_mini_device device;
  // lazy hardcoded settings, these should all be configuration options
  device.path = "test";
  device.encrypt = 1;
  device.compress = 1;
  device.mem_flush_size = 1024*1024;
  device.token = (unsigned char *)"secret";
  device.token_len = 6;
  int port = 22333;
  const char *server = "127.0.0.1";

  // allocate working memory (freed in steady_cleanup)
  device.mem_log_data = steady_mem_alloc(device.mem_flush_size);
  device.mem_block_size = device.mem_flush_size + steady_wire_block_overhead
               + LZ4F_compressFrameBound(device.mem_flush_size + steady_wire_block_overhead, NULL);
  device.mem_block = steady_mem_alloc(device.mem_block_size);

  /*
   * Read policy from config file, generated by someone else (e.g., the Golang implementation
   * steady/cmd/stdy-make-device).
   */
  if (steady_fs_mini_device(&device) <0) {
    printf("missing config file at %s\n", device.path);
    steady_cleanup(&device);
    return -1;
  }

  // attempt to read state from disk
  if (steady_fs_mini_state(&device) != 0) {
    /*
     * Failed to read from filesystem, using defaults below. This is safe _IF_:
     * - losing state is relatively rare, and
     * - an attacker cannot reliably make the device lose state (e.g., by triggering a crash).
     * How safe is "rare" depends on if the attacker is risk averse or not. If an attacker tries
     * to trick us and we did not fail to read state then we'll detect it in steady_check_status.
     */
      device.state_next_index = 0;
      device.state_prev_time = device.policy.time;
      device.state_prev_len = 0;
  }

  // attempt to connect to relay
  device.socket = -1; // not a valid file descriptor
  device.address.sin_family = AF_INET;
  device.address.sin_port = htons(port);
  device.address.sin_addr.s_addr = inet_addr(server);
  if (steady_mini_connect(&device) < 0) {
    printf("failed to connect to relay\n");
    steady_cleanup(&device);
    return -1;
  }

  // check status at relay
  int check = steady_check_status(&device);
  if (check == -5) {
    printf("state is inconsistent with relay, this might be an attack\n");
    steady_cleanup(&device);
    return -1;
  } else if (check != 0) {
    printf("failed to get consistent state with relay\n");
    steady_cleanup(&device);
    return -1;
  }

  // log all data from stdin
  if (steady_log_stdin(&device) <0) {
    printf("failed to log all data from stdin\n");
    steady_cleanup(&device);
    return -1;
  }

  /*
   * The only thing missing here in main to be a compliant Steady device is to make sure a block
   * is sent at least once every policy->timeout second. This makes no sense in this demo (since
   * we just send all data from stdin then exit), but important for implementations of a device
   * as a long-lived service.
   */

  // write state
  if (steady_fs_mini_state_write(&device) <0)
    printf("failed to write state, but that's something we can recover from\n");

  steady_cleanup(&device);
  return 0;
}

void steady_cleanup(steady_mini_device *device) {
  steady_mem_free(device->mem_log_data);
  steady_mem_free(device->mem_block);
  if (device->socket != -1) // attempt to close any socket we got before reconnecting
    close(device->socket);
}

int steady_log_stdin(steady_mini_device *device) {
  struct timeval now;
  struct steady_event events[steady_device_buffer_num];
  int more = 1, num = 0;
  uint64_t block_size;
  do {
    // read events from stdin
    num = steady_read_stdin(device, events, &more);
    if (num < 0)
      return -1;

    // attempt to make block
    gettimeofday(&now, NULL);
    block_size = steady_make_block(device->mem_block, device->mem_block_size,
      device->state_next_index, device->state_prev_len, now.tv_sec,
      events, num, &device->policy, device->encrypt, device->compress, device->sk);
    if (block_size == 0) {
      fprintf(stderr, "failed to steady_make_block, this should never happen\n");
      abort();
    }

    // send the block
    steady_send_block(device, block_size);

    // update state
    device->state_next_index++;
    device->state_prev_len = block_size;
    device->state_prev_time = now.tv_sec;
  } while(more);

  return 0;
}

void steady_send_block(steady_mini_device *device, uint64_t block_size) {
  uint16_t num_blocks = 1; // the number of blocks to send, one at a time in this example
  // buffer is the bytes we need to send to the relay to write: version || cmd_write || block_num
  unsigned char buffer[2+steady_identifier_size+2] = {steady_wire_version,steady_wire_cmd_write};
  memcpy(buffer+2, device->policy.id, steady_identifier_size);
  steady_write16be(buffer+2+steady_identifier_size, num_blocks);
  unsigned char reply[8+steady_wire_auth_size], auth[steady_hash_size]; // the reply from the relay

  while (1) { // attempt to send, on fail reconnect / wait / retry
    if (errno == ECONNRESET || errno == EBADF || errno == ENOTCONN || errno == ENOTSOCK ||
        errno == EPIPE || errno == ECONNREFUSED) { // reasons to reconnect
      while (steady_mini_connect(device) < 0) {}
    }

    if (steady_mini_send_full(device->socket, &buffer, 4+steady_identifier_size) < 0)
      continue; // errno will be set, triggering re-connect above

    if (steady_mini_send_full(device->socket, device->mem_block, block_size) < 0)
      continue; // errno will be set, triggering re-connect above

    // wait for reply
    if (recv(device->socket, &reply, 8+steady_wire_auth_size, 0) < 0)
      continue; // errno will be set, triggering re-connect above

    // check that we got the block index as reply, if not, an error so we try again
    if (strncmp((const char *)reply, (const char *)device->mem_block, 8) != 0) {
      errno = EPIPE;
      continue;
    }

    // make sure the block index is authenticated by the server
    steady_khash3(auth, device->token, device->token_len,
      (unsigned char *)"write", 5, device->policy.id, steady_identifier_size,
      device->mem_block, 8);
    if (strncmp((const char *)(reply+8), (const char *)auth, steady_wire_auth_size) != 0) {
      printf("authentication error, this should never happen...we try to reconnect\n");
      errno = EPIPE;
      continue;
    }

    break; // all good
  }
}

int steady_read_stdin(steady_mini_device *device,
  struct steady_event events[steady_device_buffer_num], int *more) {
  char msg[steady_max_event_size];
  int num = 0, size = 0, total_size = 0;

  while (1) {
    if (fgets(msg, steady_max_event_size, stdin) == NULL) {
      *more = 0; // flag for steady_log_stdin to not attempt to read stdin again
      break;
    }
    // find size of msg we just read
    for (int i = 0; i < steady_max_event_size; i++) {
      if (msg[i] == '\0')
        break;
      size = i+1;
    }

    // copy over
    memcpy(device->mem_log_data+total_size, msg, size);
    events[num].data = device->mem_log_data+total_size;
    events[num].size = size;
    total_size += size;
    num++;

    // return if we're full, either due to flush size or number of events
    if (total_size+steady_max_event_size > device->mem_flush_size ||
      num >= steady_device_buffer_num)
      return num;
  }

  return num;
}

int steady_mini_connect(steady_mini_device *device) {
  if (device->socket != -1) // attempt to close any socket we got before reconnecting
    close(device->socket);

  if ((device->socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) // create a new socket
      return -1;

  struct timeval timeout; // set timeout parameters before connecting
  timeout.tv_sec = device->policy.timeout+5; // rather timeout and reconnect then wait too long
  timeout.tv_usec = 0;
  if (setsockopt(device->socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
    return -1;
  if (setsockopt(device->socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
    return -1;

  return connect(device->socket, (struct sockaddr *)&device->address, sizeof(device->address));
}

size_t steady_mini_send_full(int socket, const void *buf, size_t len) {
  size_t done = 0;
  do {
    ssize_t reply = send(socket, buf+done, len-done, 0);
    if (reply < 0)
      return reply;

    done += reply;
  } while(done < len);

  return done;
}

int steady_fs_mini_device(steady_mini_device* device) {
  char fname[steady_fs_path_max];
  sprintf(fname, steady_fs_device_format, device->path);
  FILE *fp = fopen(fname, "rb");
  if (fp == NULL)
    return -1;

  unsigned char buffer[steady_fs_device_size];
  if (fread(buffer, 1, steady_fs_device_size, fp) != steady_fs_device_size)
    return -1;

  fclose(fp);

  // verify encoded policy and copy over data
  if (steady_verify_encoded_policy(buffer+steady_signing_key_size,
    steady_fs_device_size-steady_signing_key_size) !=0)
    return -2;
  memcpy(device->sk, buffer, steady_signing_key_size);
  int i = steady_signing_key_size;
  memcpy(device->policy.id, buffer+i, steady_identifier_size);
  i += steady_identifier_size;
  memcpy(device->policy.vk, buffer+i, steady_verification_key_size);
  i += steady_verification_key_size;
  memcpy(device->policy.pub, buffer+i, steady_public_key_size);
  i += steady_public_key_size;
  device->policy.timeout = steady_be64toh(buffer+i);
  i+=8;
  device->policy.space = steady_be64toh(buffer+i);
  i+=8;
  device->policy.time = steady_be64toh(buffer+i);

  // to verify the signing key we self-sign the identifier and see if the verification key
  // in the policy can be used to verify the signature
  unsigned char signature[steady_signature_size];
  steady_sign(signature, device->policy.id, steady_identifier_size, device->sk);
  if (steady_verify(signature, device->policy.id, steady_identifier_size, device->policy.vk) != 0)
    return -1;

  return 0;
}

int steady_fs_mini_state(steady_mini_device* device) {
  char fname[steady_fs_path_max];
  sprintf(fname, steady_fs_state_format, device->path);
  FILE *fp = fopen(fname, "rb");
  if (fp == NULL)
    return -1;

  unsigned char buffer[steady_fs_state_size];
  if (fread(buffer, 1, steady_fs_state_size, fp) != steady_fs_state_size) {
    return -1;
  }
  fclose(fp);

  device->state_next_index = steady_be64toh(buffer);
  device->state_prev_time = steady_be64toh(buffer+8);
  device->state_prev_len = steady_be64toh(buffer+16);
  return 0;
}

int steady_fs_mini_state_write(steady_mini_device* device) {
  char fname[steady_fs_path_max];
  sprintf(fname, steady_fs_state_format, device->path);
  FILE *fp = fopen(fname, "wb");
  if (fp == NULL)
    return -1;

  unsigned char buffer[steady_fs_state_size];
  steady_write64be(buffer, device->state_next_index);
  steady_write64be(buffer+8, device->state_prev_time);
  steady_write64be(buffer+16, device->state_prev_len);

  if (fwrite(buffer, 1, steady_fs_state_size, fp) != steady_fs_state_size)
    return -2;

  return 0;
}

int steady_check_status(steady_mini_device* device) {
  unsigned char buffer[2+steady_identifier_size+steady_wire_auth_size] = {steady_wire_version,
    steady_wire_cmd_status};
  memcpy(buffer+2, device->policy.id, steady_identifier_size);
  steady_khash2(buffer+2+steady_identifier_size, device->token, device->token_len,
    (unsigned char *)"status", 6, device->policy.id, steady_identifier_size);

  steady_mini_send_full(device->socket, &buffer, 2+steady_identifier_size+steady_wire_auth_size);

  unsigned char reply; // below, the return-values match that of steady_load_device
  if (recv(device->socket, &reply, 1, 0) < 0)
    return -3; // failed to recieve reply
  if (reply == steady_wire_auth_error)
    return -4; // auth error
  if (reply == steady_wire_false)
    return -5; // inconsistent, relay said not setup
  if (reply == steady_wire_true && device->state_next_index == 0)
    return 0; // this is OK (unless we dropped all state at the same time the relay decided to lie)

  if (reply == steady_wire_more) { // compared to implied state from last block header
    unsigned char bh[steady_wire_block_header_size];
    if (recv(device->socket, bh, steady_wire_block_header_size, 0) < 0) {
      return -3; // failed to recieve block header
    }

    // verify block header
    if (steady_check_block_header(bh, device->policy.id, device->policy.vk) != 0)
      return -5; // inconsistent, relay sent invalid block header

    // extract and compare to state (except for first undef state where index == 0)
    if (steady_be64toh(bh)+1 < device->state_next_index && device->state_next_index != 0)
      return -5; // inconsistent, relay sent old block header

    device->state_next_index = steady_be64toh(bh)+1;
    device->state_prev_len = steady_be64toh(bh+8);
    device->state_prev_time = steady_be64toh(bh+24+3*steady_hash_size);
    return 0;
  }

  return -5; // inconsistent, time to panic
}
