#ifndef STEADY_DEVICE_HEADER
#define STEADY_DEVICE_HEADER
#include <pthread.h>
#include <netinet/in.h>
#include "steady.h"

#define steady_device_buffer_num (1024*8) // each one takes 10 bytes, allocated per device
#define steady_device_block_ptr_num 1024 // 12 bytes each, on very small flush size relevant

struct steady_block {
  unsigned char *data;
  uint32_t len;
};

// high-level device API below
struct steady_device;
int steady_load_device(struct steady_device* device,
  char *path, char *server, int port, unsigned char *token, int token_len,
  int encrypt, int compress, uint64_t flush_size, uint64_t mem_limit);
int steady_log(struct steady_device* device, char *msg, int len);
int steady_close(struct steady_device* device);

/*
 * All internal details below, peak if you want to better understand how Steady works, but there
 * should be no real need to as a library user.
 */
struct steady_device {
  // generated during setup, read from fs, the policy for the device and its signing key
  struct steady_policy policy;
  unsigned char sk[steady_signing_key_size];

  // steady state, read from fs and persisted on close, can recover if lost
  uint64_t state_next_index, state_prev_time, state_prev_len;

  /*
   * ##### ephemeral below #####
   */

   // encrypt and compress flags
   int encrypt, compress;

   // set at load, how much log data to buffer before making a block
   uint64_t mem_flush_size;

   // derived during load, based on the set memory limit, max dynamic memory for pending blocks
   uint64_t mem_max_block_alloc;

   // a socket for talking to the relay, its access token, and an associated address struct
   int socket, token_len;
   unsigned char *token;
   struct sockaddr_in address;

   // the filesystem path for state
   char* path;

  /*
   * Steady assumes that steady_log() can be called by many different threads where it is vital that
   * the call returns rapdily. To perform logging we spawn three threads:
   * - a _logging_ thread with the core logic of how many events to buffer and when to make blocks,
   * - a _block_ thread that creates blocks out of the events provided the logging thread, and
   * - a _send_ thread that sends blocks to the relay.
   */
  pthread_t thread_logging, thread_block, thread_send;
  pthread_mutex_t mutex_logging, mutex_block, mutex_send;
  pthread_cond_t cond_logging, cond_block, cond_send;
  int closed_logging, closed_block, closed_send; // flags for when the threads should be closed

  // mem_event is the list of events to log, contains only a ptr and len
  struct steady_event mem_event[steady_device_buffer_num];
  // mem_event_data is storage of all data for events in mem_event (size: 2xmem_active_max)
  unsigned char *mem_event_data;

  /*
   * The mem_active_* variables are pointers/counters to the active regions of mem_event and
   * mem_event_data above, where 'active' refers to the regions used by steady_log() to log new events.
   * The logging thread periodically swaps the pointers below when we hit the flush size or timeout,
   * handing off the inactive region with events to the block thread to make a block.
   */
  unsigned char *mem_active_data;
  uint64_t mem_active_size, mem_active_max;
  struct steady_event *mem_active_event;
  uint64_t mem_active_event_num;

  /*
   * The mem_block_* variables are pointers/counters for events that are turned into blocks. The
   * working memory for making blocks is mem_block. If mem_blocks_events is NULL then this is a
   * signal to the logging thread that the block thread is ready to create a new block.
   */
  struct steady_event *mem_block_events;
  uint64_t mem_block_events_num;
  unsigned char *mem_block;
  uint64_t mem_block_size;

  // pending_blocks are the finished blocks pending being sent to the relay
  struct steady_block pending_blocks[steady_device_block_ptr_num];
  uint16_t num_pending_blocks;
  uint64_t allocated_blocks_size;
};

// Internal stuff below
#define steady_fs_device_size (steady_signing_key_size + steady_wire_policy_size)
#define steady_fs_state_size 8*3
#define steady_fs_device_format ((char*) "%s.device")
#define steady_fs_state_format ((char*) "%s.state")
int steady_fs_device(struct steady_device* device, char *path);
int steady_fs_state(struct steady_device* device, char *path);
int steady_fs_state_write(struct steady_device* device);
#define steady_fs_path_max 4096

int steady_statusCheckState(struct steady_device* device);
int steady_make_thread(pthread_t *t, pthread_mutex_t *m, pthread_cond_t *c, int *i,
void *(*start_routine) (void *), void *arg);
int steady_connect(struct steady_device *device);
void *steady_thread_logging(void *x);
void *steady_thread_block(void *x);
void *steady_thread_send(void *x);
size_t steady_really_send(int socket, const void *buf, size_t len);

#endif
