/**
 * Copyright (C) 2022 Carnegie Mellon University
 *
 * This file is part of the TCP in the Wild course project developed for the
 * Computer Networks course (15-441/641) taught at Carnegie Mellon University.
 *
 * No part of the project may be copied and/or distributed without the express
 * permission of the 15-441/641 course staff.
 *
 *
 * This file defines the API for the CMU TCP implementation.
 */

#ifndef PROJECT_2_15_441_INC_CMU_TCP_H_
#define PROJECT_2_15_441_INC_CMU_TCP_H_

#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "cmu_packet.h"
#include "grading.h"

#define EXIT_SUCCESS 0
#define EXIT_ERROR -1
#define EXIT_FAILURE 1

typedef struct {
  uint32_t next_seq_expected;
  uint32_t last_ack_received;
  uint32_t next_seq_to_send;
  // CP2: tracks the farthest byte physically written into received_buf so
  // far (covers the single out-of-order gap between next_seq_expected and
  // this value), and how far the application has consumed via cmu_read().
  uint32_t last_byte_rcvd;
  uint32_t last_byte_read;

  // CP2 congestion control. Initial values are fixed by grading.h:
  // cwnd starts at WINDOW_INITIAL_WINDOW_SIZE, ssthresh at
  // WINDOW_INITIAL_SSTHRESH.
  uint32_t cwnd;
  uint32_t ssthresh;
  // Most recent advertised window reported by the peer. The effective
  // sending window is min(cwnd, peer_adv_window).
  uint16_t peer_adv_window;
  // Consecutive ACKs received carrying the same (non-advancing) ack number.
  uint32_t dup_ack_count;
  // Set while in fast recovery. Slow start vs. congestion avoidance is
  // derived from cwnd < ssthresh, but recovery needs its own marker because
  // cwnd is deliberately inflated above ssthresh while recovering.
  int in_fast_recovery;
  // Raised by the ACK handler when three duplicates have been counted, and
  // consumed by window_send(), which owns the outstanding-packet queue.
  int fast_retransmit_pending;
} window_t;

/**
 * CMU-TCP socket types. (DO NOT CHANGE.)
 */
typedef enum {
  TCP_INITIATOR = 0,
  TCP_LISTENER = 1,
} cmu_socket_type_t;

/**
 * This structure holds the state of a socket. You may modify this structure as
 * you see fit to include any additional state you need for your implementation.
 */
typedef struct {
  int socket;
  pthread_t thread_id;
  uint16_t my_port;
  struct sockaddr_in conn;
  // Fixed-size (MAX_NETWORK_BUFFER) circular buffer. Occupied bytes span
  // [window.last_byte_read, window.last_byte_rcvd); use `% MAX_NETWORK_BUFFER`
  // on sequence numbers to find a byte's position.
  uint8_t* received_buf;
  pthread_mutex_t recv_lock;
  pthread_cond_t wait_cond;
  uint8_t* sending_buf;
  int sending_len;
  cmu_socket_type_t type;
  pthread_mutex_t send_lock;
  int dying;
  pthread_mutex_t death_lock;
  window_t window;
  // Retained so the backend can recognize a retransmitted SYN-ACK.
  uint32_t local_isn;
  uint32_t peer_isn;
  // Teardown state is owned by the backend thread.
  int close_state;
  int peer_fin_received;
  int simultaneous_close;
  uint32_t local_fin_seq;
  uint32_t peer_fin_seq;
  int64_t close_deadline;
} cmu_socket_t;

/*
 * DO NOT CHANGE THE DECLARATIONS BELOW
 */

/**
 * Read mode flags supported by a CMU-TCP socket.
 */
typedef enum {
  NO_FLAG = 0,  // Default behavior: block indefinitely until data is available.
  NO_WAIT,      // Return immediately if no data is available.
  TIMEOUT,      // Block until data is available or the timeout is reached.
} cmu_read_mode_t;

/**
 * Constructs a CMU-TCP socket.
 *
 * An Initiator socket is used to connect to a Listener socket.
 *
 * @param sock The structure with the socket state. It will be initialized by
 *             this function.
 * @param socket_type Indicates the type of socket: Listener or Initiator.
 * @param port Port to either connect to, or bind to. (Based on socket_type.)
 * @param server_ip IP address of the server to connect to. (Only used if the
 *                 socket is an initiator.)
 *
 * @return 0 on success, -1 on error.
 */
int cmu_socket(cmu_socket_t* sock, const cmu_socket_type_t socket_type,
               const int port, const char* server_ip);

/**
 * Closes a CMU-TCP socket.
 *
 * @param sock The socket to close.
 *
 * @return 0 on success, -1 on error.
 */
int cmu_close(cmu_socket_t* sock);

/**
 * Reads data from a CMU-TCP socket.
 *
 * If there is data available in the socket buffer, it is placed in the
 * destination buffer.
 *
 * @param sock The socket to read from.
 * @param buf The buffer to read into.
 * @param length The maximum number of bytes to read.
 * @param flags Flags that determine how the socket should wait for data. Check
 *             `cmu_read_mode_t` for more information. `TIMEOUT` is not
 *             implemented for CMU-TCP.
 *
 * @return The number of bytes read on success, -1 on error.
 */
int cmu_read(cmu_socket_t* sock, void* buf, const int length,
             cmu_read_mode_t flags);

/**
 * Writes data to a CMU-TCP socket.
 *
 * @param sock The socket to write to.
 * @param buf The data to write.
 * @param length The number of bytes to write.
 *
 * @return 0 on success, -1 on error.
 */
int cmu_write(cmu_socket_t* sock, const void* buf, int length);

/*
 * You can declare more functions after this point if you need to.
 */

#endif  // PROJECT_2_15_441_INC_CMU_TCP_H_
