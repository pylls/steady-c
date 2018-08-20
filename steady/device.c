#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <unistd.h>

#include "device.h"

int steady_log(struct steady_device* device, char *msg, int len) {
  if ((uint64_t)len > steady_max_event_size) // too big message
    return -1;

  pthread_mutex_lock(&device->mutex_logging); // use mtx_timedlock?
  if (device->closed_logging)
    return -1; // device closed, no more logging possible

  if (device->mem_active_size + (uint64_t)len > device->mem_active_max ||
      device->mem_active_event_num >= steady_device_buffer_num/2) {
    // TODO: we do not have room, flag as dropped
    pthread_cond_signal(&device->cond_logging);
    pthread_mutex_unlock(&device->mutex_logging);
    return -2; // dropped (due to too high load)
  }

  // copy over log msg
  memcpy(device->mem_active_data+device->mem_active_size, msg, len);
  device->mem_active_event[device->mem_active_event_num].data = device->mem_active_data+device->mem_active_size;
  device->mem_active_event[device->mem_active_event_num].size = len;
  device->mem_active_size += (uint64_t)len;
  device->mem_active_event_num++;

  pthread_cond_signal(&device->cond_logging);
  pthread_mutex_unlock(&device->mutex_logging);
  return 0;
}

int steady_close(struct steady_device* device) {
  pthread_mutex_lock(&device->mutex_logging);
  device->closed_logging = 1;
  printf("signaled closed_logging\n");
  pthread_cond_signal(&device->cond_logging);
  pthread_mutex_unlock(&device->mutex_logging);
  if(pthread_join(device->thread_logging, NULL)) // wait for main thread to make and send
    return -1;

  if (steady_fs_state_write(device) != 0)
    printf("failed to write state, this is not catastrophic, but should be addressed\n");

  steady_mem_free(device->mem_event_data);
  steady_mem_free(device->mem_block);

  return 0;
}

int steady_load_device(struct steady_device* device,
  char *path, char *server, int port, unsigned char *token, int token_len,
  int encrypt, int compress, uint64_t flush_size, uint64_t mem_limit) {
    // read config from disk
    if (steady_fs_device(device, path) != 0)
      return -1;

    /*
     * check if flush_size, mem_limit and policy.space parameters are reasonable:
     * - we use 3xflush_size for event data and ~1.5x flush_size for block working memory,
     *   and without compression one block can be at most the same size as the block working memory.
     * - we can never log a block bigger than the policy space, and with overhead (dynamic, thanks
    *    to LZ4 compression) the flush_size should be less than half of the policy space to be safe.
     */
    if (7*flush_size+steady_wire_block_overhead*2 > mem_limit ||
      flush_size*2 > device->policy.space)
        return -2;

    // memory allocation
    device->mem_flush_size = flush_size;
    device->mem_active_max = (uint64_t)(flush_size*1.5);
    device->mem_event_data = steady_mem_alloc((device->mem_active_max)*2);
    device->mem_block_size = device->mem_active_max + steady_wire_block_overhead
                             + LZ4F_compressFrameBound(device->mem_active_max, NULL);
    device->mem_block = steady_mem_alloc(device->mem_block_size);
    device->mem_max_block_alloc = mem_limit - ((device->mem_active_max)*2 + device->mem_block_size);

    // explicity set as much as possible of device
    device->mem_active_data = device->mem_event_data;
    device->mem_active_size = 0;
    device->mem_active_event = device->mem_event;
    device->mem_active_event_num = 0;
    device->token = token;
    device->token_len = token_len;
    device->path = path;
    device->encrypt = encrypt;
    device->compress = compress;
    device->num_pending_blocks = 0;
    device->allocated_blocks_size = 0;

    // attempt to read state from disk
    if (steady_fs_state(device, path) != 0) {
        // failed to read from filesystem, populating with defaults
        device->state_next_index = 0;
        device->state_prev_time = device->policy.time;
        device->state_prev_len = 0;
    }

    // attempt to connect to relay
    device->socket = -1; // not a valid file descriptor
    device->address.sin_family = AF_INET;
    device->address.sin_port = htons(port);
    device->address.sin_addr.s_addr = inet_addr(server);
    if (steady_connect(device) < 0)
        return -3;

    // check state relative to what relay claims
    int check = steady_statusCheckState(device);
    if (check != 0)
      return check;

    // make all three threads: logging, block, and send
    if (steady_make_thread(&device->thread_logging, &device->mutex_logging, &device->cond_logging,
      &device->closed_logging, steady_thread_logging, device) != 0)
        return -6;
    if (steady_make_thread(&device->thread_block, &device->mutex_block, &device->cond_block,
      &device->closed_block, steady_thread_block, device) != 0)
        return -6;
    if (steady_make_thread(&device->thread_send, &device->mutex_send, &device->cond_send,
      &device->closed_send, steady_thread_send, device) != 0)
        return -6;

    return 0;
}

int steady_connect(struct steady_device *device) {
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

int steady_make_thread(pthread_t *t, pthread_mutex_t *m, pthread_cond_t *c, int *i,
void *(*start_routine) (void *), void *arg) {
  *i = 0;
  if (pthread_mutex_init(m, NULL) != 0 || pthread_cond_init(c, NULL) != 0 ||
      pthread_create(t, NULL, start_routine, arg))
    return -1;

  return 0;
}

void steady_get_next_block_time(struct timespec *when, struct steady_device *device) {
  struct timeval now;
  gettimeofday(&now, NULL);
  if (device->mem_block_events == NULL) { // use of state is safe, we're only thread calling
    if (device->state_prev_time + device->policy.timeout < now.tv_sec)
      when->tv_sec = now.tv_sec; // we are late, timeout now
    else
      when->tv_sec = device->state_prev_time + device->policy.timeout;
  } else { // likely pending block, just set timer based on policy timeout
    when->tv_sec = now.tv_sec + device->policy.timeout;
  }
}

void *steady_thread_logging(void *x) {
  struct steady_device *device = (struct steady_device *)x;
  pthread_mutex_lock(&device->mutex_logging);

  int timedout = 0, wait_retval;
  struct timespec next_block_time = {0};
    while (1) {
    if (!device->closed_logging) { // wait for new log if we have to
      // we use a timed wait to handle creation of blocks after timeout according to policy
      steady_get_next_block_time(&next_block_time, device);
      wait_retval = pthread_cond_timedwait(&device->cond_logging, &device->mutex_logging,
          &next_block_time);
      if (wait_retval == ETIMEDOUT) {
        timedout = 1;
      } else if (wait_retval != 0) {
        fprintf(stderr, "got abnormal error from pthread_cond_timedwait: %d", wait_retval);
        abort();
      }
    }

    // create a block?
    if (device->mem_active_size >= device->mem_flush_size || // if we hit the flush size,
        device->mem_active_event_num >= steady_device_buffer_num/2 || // if we're out of event slots,
        timedout || // if we hit policy->timeout since the last block,
        device->closed_logging) { // or steady_close() has been called

      // realse logging lock, enabling logging while getting block lock, then get logging lock again
      pthread_mutex_unlock(&device->mutex_logging);
      pthread_mutex_lock(&device->mutex_block); // make sure we don't overwrite something
      pthread_mutex_lock(&device->mutex_logging);
      if (device->mem_block_events == NULL) { // check that block thread is free for work
        // give the block thread the events
        device->mem_block_events = device->mem_active_event;
        device->mem_block_events_num = device->mem_active_event_num;

        /*
         * Below we flip the active memory area for Log to write to. This is always safe because
         * given that the block thread is idle (indicated by device->mem_block_events == NULL)
         * it either has done no work at all (first run) or just finished with one (lock released).
         */
        if (device->mem_active_data == device->mem_event_data) {
          device->mem_active_data = device->mem_event_data+device->mem_active_max;
          device->mem_active_event = &device->mem_event[steady_device_buffer_num/2];
        } else {
          device->mem_active_data = device->mem_event_data;
          device->mem_active_event = device->mem_event;
        }
        device->mem_active_event_num = 0;
        device->mem_active_size = 0;

        if (timedout) // reset the timedout flag if set
          timedout = 0;
      }
      pthread_cond_signal(&device->cond_block);
      pthread_mutex_unlock(&device->mutex_block);
    }
    if (device->closed_logging && device->mem_active_size == 0)
      break;
  }

  pthread_mutex_unlock(&device->mutex_logging);
  pthread_mutex_lock(&device->mutex_block);
  device->closed_block = 1; // signal to thread block to finish
  printf("signaled closed_block\n");
  pthread_cond_signal(&device->cond_block);
  pthread_mutex_unlock(&device->mutex_block);
  pthread_join(device->thread_block, NULL); // join with block thread
  pthread_exit(NULL);
}

/*
 * We need a dedicated thread for creating blocks (instead of being part of the logging logic
 * thread) because making blocks take time and we cannot accurately predict the size of a block
 * with compression, resulting in either wasting space (never making a block before we are sure
 * we have space) or time (by blocking the logging thread until we have space).
 */
void *steady_thread_block(void *x) { // only thread to update state
  struct steady_device *device = (struct steady_device *)x;
  struct timeval now;
  pthread_mutex_lock(&device->mutex_block);

  uint64_t block_size;
  while (1) {
    if (!device->closed_block) // wait to be waken up if we have to
      pthread_cond_wait(&device->cond_block, &device->mutex_block);
    if (device->mem_block_events != NULL) { // do we have any work?
      gettimeofday(&now, NULL);
      block_size = steady_make_block(device->mem_block, device->mem_block_size,
        device->state_next_index, device->state_prev_len, now.tv_sec,
        device->mem_block_events, device->mem_block_events_num, &device->policy,
        device->encrypt, device->compress, device->sk);
      if (block_size == 0) {
        fprintf(stderr, "failed to steady_make_block, this should never happen\n");
        abort();
      }
      device->state_next_index++;
      device->state_prev_len = block_size;
      device->state_prev_time = now.tv_sec;
      pthread_mutex_lock(&device->mutex_send);

      while (1) { // wait until we have room for our new block
        if (block_size + device->allocated_blocks_size <= device->mem_max_block_alloc &&
            device->num_pending_blocks+1 < steady_device_block_ptr_num)
          break;
        pthread_cond_signal(&device->cond_send); // tell send to continue sending...
        pthread_cond_wait(&device->cond_send, &device->mutex_send); // wait for some progress...
      }

      // copy over and track overall allocated memory
      device->pending_blocks[device->num_pending_blocks].len = block_size;
      device->pending_blocks[device->num_pending_blocks].data = steady_mem_alloc(block_size);
      memcpy(device->pending_blocks[device->num_pending_blocks].data, device->mem_block, block_size);
      device->allocated_blocks_size += block_size;
      device->num_pending_blocks++;

      device->mem_block_events = NULL; // signals to logging thread that we're free for more work
      pthread_cond_signal(&device->cond_send); // tell sender to get to work
      pthread_mutex_unlock(&device->mutex_send);
    }
    if (device->closed_block)
      break;
  }

  pthread_mutex_unlock(&device->mutex_block);
  pthread_mutex_lock(&device->mutex_send);
  device->closed_send = 1; // signal to thread send to finish
  printf("signaled closed_send\n");
  pthread_cond_signal(&device->cond_send);
  pthread_mutex_unlock(&device->mutex_send);
  pthread_join(device->thread_send, NULL); // join with send thread
  pthread_exit(NULL);
}

void *steady_thread_send(void *x) {
  struct steady_device *device = (struct steady_device *)x;
  struct steady_block blocks[steady_device_block_ptr_num]; // blocks to send
  uint16_t num_blocks; // the number of blocks to send
  unsigned char reply[8+steady_wire_auth_size], auth[steady_hash_size]; // the reply from the relay
  unsigned char buffer[2+steady_identifier_size+2] = {steady_wire_version,steady_wire_cmd_write};
  memcpy(buffer+2, device->policy.id, steady_identifier_size); // buffer is the steady protocol to send

  pthread_mutex_lock(&device->mutex_send);
  while (1) { // logic: get all blocks to send, copy them (ptrs), then send all of
    if (device->closed_send && device->num_pending_blocks == 0) // quit if no work to do
      break;
    if (!device->closed_send) // wait to be waken up if we have to
      pthread_cond_wait(&device->cond_send, &device->mutex_send);

    num_blocks = device->num_pending_blocks; // copy all pending blocks
    memcpy(blocks, device->pending_blocks, sizeof (struct steady_block) * num_blocks);
    device->num_pending_blocks = 0; // reset the block counter, block thread can write new blocks
    pthread_mutex_unlock(&device->mutex_send);

    // copy num_blocks to buffer
    steady_write16be(buffer+2+steady_identifier_size, num_blocks);

    while (1) { // attempt to send, on fail reconnect / wait / retry
      if (errno == ECONNRESET || errno == EBADF || errno == ENOTCONN || errno == ENOTSOCK ||
          errno == EPIPE || errno == ECONNREFUSED) { // reasons to reconnect
        while (steady_connect(device) < 0) {}
      }

      // send writeN command
      if (steady_really_send(device->socket, &buffer, 4+steady_identifier_size) < 0)
        continue; // errno will be set, triggering re-connect above

      // send all blocks
      for (int i = 0; i < num_blocks; i++) {
        if (steady_really_send(device->socket, blocks[i].data, blocks[i].len) < 0)
          continue; // errno will be set, triggering re-connect above
      }

      // wait for reply
      if (recv(device->socket, &reply, 8+steady_wire_auth_size, 0) < 0)
        continue; // errno will be set, triggering re-connect above

      // check that we got the block index as reply, if not, an error so we try again
      if (strncmp((const char *)reply, (const char *)blocks[num_blocks-1].data, 8) != 0) {
        errno = EPIPE;
        continue;
      }

      // make sure the block index is authenticated by the server
      steady_khash3(auth, device->token, device->token_len,
        (unsigned char *)"writeN", 6, device->policy.id, steady_identifier_size, blocks[num_blocks-1].data, 8);
      if (strncmp((const char *)(reply+8), (const char *)auth, steady_wire_auth_size) != 0) {
        printf("authentication error, this should never happen...we try to reconnect\n");
        errno = EPIPE;
        continue;
      }

      break; // auth OK, all good
    }

    pthread_mutex_lock(&device->mutex_send);
    for (int i = 0; i < num_blocks; i++) {
      steady_mem_free(blocks[i].data); // free memory
      device->allocated_blocks_size -= (uint64_t)blocks[i].len; // and let block thread know
    }

    if (num_blocks > 0)
      pthread_cond_signal(&device->cond_send);
  }

  pthread_mutex_unlock(&device->mutex_send);
  pthread_exit(NULL);
}

size_t steady_really_send(int socket, const void *buf, size_t len) {
  size_t done = 0;
  do {
    ssize_t reply = send(socket, buf+done, len-done, 0);
    if (reply < 0)
      return reply;

    done += reply;
  } while(done < len);

  return done;
}

int steady_fs_device(struct steady_device* device, char *path) {
  char fname[steady_fs_path_max];
  sprintf(fname, steady_fs_device_format, path);
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

int steady_fs_state(struct steady_device* device, char *path) {
  char fname[steady_fs_path_max];
  sprintf(fname, steady_fs_state_format, path);
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

int steady_fs_state_write(struct steady_device* device) {
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

int steady_statusCheckState(struct steady_device* device) {
  unsigned char buffer[2+steady_identifier_size+steady_wire_auth_size] = {steady_wire_version,
    steady_wire_cmd_status};
  memcpy(buffer+2, device->policy.id, steady_identifier_size);
  steady_khash2(buffer+2+steady_identifier_size, device->token, device->token_len,
    (unsigned char *)"status", 6, device->policy.id, steady_identifier_size);

  send(device->socket, &buffer, 2+steady_identifier_size+steady_wire_auth_size, 0);

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
