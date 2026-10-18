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
 * This file implements the CMU-TCP backend. The backend runs in a different
 * thread and handles all the socket operations separately from the application.
 *
 * This is where most of your code should go. Feel free to modify any function
 * in this file.
 */

#include "backend.h"

#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

#include "cmu_packet.h"
#include "cmu_tcp.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

static int64_t monotonic_ms(void) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int same_peer(const struct sockaddr_in *a,
                     const struct sockaddr_in *b) {
  return a->sin_addr.s_addr == b->sin_addr.s_addr &&
         a->sin_port == b->sin_port;
}

// CP2 instrumentation: append a cwnd/ssthresh sample for plotting the
// sawtooth. Set CMU_TCP_CWND_LOG to a file path to enable. `stage` is a
// free-form label supplied by the caller.
static void log_cwnd(cmu_socket_t *sock, const char *stage) {
  static FILE *log_file = NULL;
  static int checked = 0;
  if (!checked) {
    checked = 1;
    const char *path = getenv("CMU_TCP_CWND_LOG");
    if (path != NULL) {
      log_file = fopen(path, "w");
      if (log_file != NULL) {
        fprintf(log_file, "time_ms,cwnd,ssthresh,adv_window,stage\n");
      }
    }
  }
  if (log_file == NULL) return;
  fprintf(log_file, "%lld,%u,%u,%u,%s\n", (long long)monotonic_ms(),
          sock->window.cwnd, sock->window.ssthresh,
          sock->window.peer_adv_window, stage);
  fflush(log_file);
}

// CP2 congestion control (TCP Reno), applied on every ACK that either
// advances last_ack_received or repeats it while data is outstanding.
//
//   slow start (cwnd < ssthresh) : new ACK -> cwnd += MSS
//   congestion avoidance         : new ACK -> cwnd += MSS * (MSS / cwnd)
//   third duplicate ACK          : ssthresh = cwnd / 2
//                                  cwnd = ssthresh + 3 * MSS, enter recovery
//   duplicate ACK in recovery    : cwnd += MSS
//   new ACK in recovery          : cwnd = ssthresh, leave recovery
//
// Timeout handling lives in window_send(), which owns the retransmit timer.
static void cc_on_ack(cmu_socket_t *sock, int advanced) {
  if (advanced) {
    sock->window.dup_ack_count = 0;
    if (sock->window.in_fast_recovery) {
      sock->window.in_fast_recovery = 0;
      sock->window.cwnd = sock->window.ssthresh;
      log_cwnd(sock, "recovery_exit");
      return;
    }
    if (sock->window.cwnd < sock->window.ssthresh) {
      sock->window.cwnd += MSS;
      log_cwnd(sock, "slow_start");
    } else {
      // Per-ACK form of "+1 MSS per RTT".
      uint32_t increment = (uint32_t)MSS * (uint32_t)MSS / sock->window.cwnd;
      // Guard against integer truncation stalling growth entirely.
      if (increment == 0) increment = 1;
      sock->window.cwnd += increment;
      log_cwnd(sock, "congestion_avoidance");
    }
    return;
  }

  if (sock->window.in_fast_recovery) {
    // Each duplicate means one more packet has drained out of the network,
    // so one more packet's worth of data may be put in flight.
    sock->window.cwnd += MSS;
    log_cwnd(sock, "recovery_inflate");
    return;
  }

  sock->window.dup_ack_count++;
  if (sock->window.dup_ack_count == 3) {
    sock->window.ssthresh = sock->window.cwnd / 2;
    sock->window.cwnd = sock->window.ssthresh + 3 * MSS;
    sock->window.in_fast_recovery = 1;
    sock->window.fast_retransmit_pending = 1;
    log_cwnd(sock, "fast_retransmit");
  }
}

// CP2 flow control: how much room is left in our fixed-size receive buffer.
// occupied = last_byte_rcvd - last_byte_read covers both the contiguous
// prefix and any buffered out-of-order bytes ahead of the single gap.
static uint16_t advertised_window(cmu_socket_t *sock) {
  uint32_t occupied = sock->window.last_byte_rcvd - sock->window.last_byte_read;
  if (occupied > MAX_NETWORK_BUFFER) return 0;
  uint32_t space = MAX_NETWORK_BUFFER - occupied;
  return space > UINT16_MAX ? UINT16_MAX : (uint16_t)space;
}

static int send_handshake_packet(cmu_socket_t *sock, uint8_t flags,
                                 uint32_t seq, uint32_t ack) {
  uint16_t len = sizeof(cmu_tcp_header_t);
  uint8_t *pkt = create_packet(sock->my_port, ntohs(sock->conn.sin_port),
                               seq, ack, len, len, flags,
                               advertised_window(sock), 0, NULL, NULL, 0);
  if (pkt == NULL) return EXIT_ERROR;
  ssize_t sent = sendto(sock->socket, pkt, len, 0,
                        (struct sockaddr *)&sock->conn, sizeof(sock->conn));
  free(pkt);
  return sent == len ? EXIT_SUCCESS : EXIT_ERROR;
}

// Receive one complete UDP datagram. Malformed packets are ignored without
// changing the retransmission deadline or the socket's saved peer address.
static int receive_handshake_packet(cmu_socket_t *sock, cmu_tcp_header_t *hdr,
                                    struct sockaddr_in *peer, int timeout) {
  struct pollfd fd = {.fd = sock->socket, .events = POLLIN};
  int ready = poll(&fd, 1, timeout);
  if (ready < 0) return errno == EINTR ? 0 : EXIT_ERROR;
  if (ready == 0) return 0;
  uint8_t buf[MAX_LEN + 1];
  socklen_t peer_len = sizeof(*peer);
  ssize_t len = recvfrom(sock->socket, buf, sizeof(buf), MSG_DONTWAIT,
                         (struct sockaddr *)peer, &peer_len);
  if (len < 0) {
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR
               ? 0 : EXIT_ERROR;
  }
  if (len != (ssize_t)sizeof(*hdr)) return 0;
  memcpy(hdr, buf, sizeof(*hdr));
  if (ntohl(hdr->identifier) != IDENTIFIER || get_hlen(hdr) != sizeof(*hdr) ||
      get_plen(hdr) != len || get_extension_length(hdr) != 0) {
    return 0;
  }
  return 1;
}

// Implements the student's SYN / SYN-ACK / ACK exchange before data sending.
static int tcp_handshake(cmu_socket_t *sock) {
  FILE *random = fopen("/dev/urandom", "rb");
  if (random == NULL) return EXIT_ERROR;
  // Get a random sequence number and intitalise it (for each sock client / server)
  size_t count = fread(&sock->local_isn, sizeof(sock->local_isn), 1, random);
  fclose(random);
  if (count != 1) return EXIT_ERROR;


  // The listener's flag will wait for the SYN
  int waiting_for_syn = sock->type == TCP_LISTENER;
  uint8_t outgoing = SYN_FLAG_MASK;
  uint32_t outgoing_ack = 0;
// --- START----
  // Send SYN if you are client/Sender and start the handshake.
  if (!waiting_for_syn &&
      send_handshake_packet(sock, outgoing, sock->local_isn, 0) < 0) {
    return EXIT_ERROR;
  }

  // initialise deadline for sender
  int64_t deadline = monotonic_ms() + DEFAULT_TIMEOUT;

  while (1) {
    int64_t remaining = deadline - monotonic_ms();

    // client  timedout rest timer
    // time out situation would need a slow start here.
    if (!waiting_for_syn && remaining <= 0) {
      if (send_handshake_packet(sock, outgoing, sock->local_isn,
                                outgoing_ack) < 0) return EXIT_ERROR;
      deadline = monotonic_ms() + DEFAULT_TIMEOUT;
      remaining = DEFAULT_TIMEOUT;
    }
    // Short polling intervals also let cmu_close interrupt an unfinished setup.
    int timeout = waiting_for_syn ? 100 : (int)MIN(remaining, 100);
    cmu_tcp_header_t hdr;
    struct sockaddr_in peer;

    // Receive doesnt matter if you are client or server both will receive at some point.
    int received = receive_handshake_packet(sock, &hdr, &peer, timeout);
    if (received < 0) return EXIT_ERROR;
    if (received == 0) continue;

    uint8_t flags = get_flags(&hdr);

    // server
    if (waiting_for_syn) {
        // this is not a start handshake message, wait for it, server will only send SYN-ACK.
      if (flags != SYN_FLAG_MASK) continue;

      sock->conn = peer;
      sock->peer_isn = get_seq(&hdr);
      outgoing = SYN_FLAG_MASK | ACK_FLAG_MASK;
      outgoing_ack = sock->peer_isn + 1;
      if (send_handshake_packet(sock, outgoing, sock->local_isn,
                                outgoing_ack) < 0) return EXIT_ERROR;
    // as a server only will now wait for a ack
      waiting_for_syn = 0;
      deadline = monotonic_ms() + DEFAULT_TIMEOUT;
      continue;
    }
    // if you are not the client that this message is meant for 
    if (!same_peer(&peer, &sock->conn)) continue;

    // Client
    if (sock->type == TCP_INITIATOR) {
        // not syn-ack and not the required ack that it needs
      if (flags != (SYN_FLAG_MASK | ACK_FLAG_MASK) ||
          get_ack(&hdr) != sock->local_isn + 1) continue;
      sock->peer_isn = get_seq(&hdr);

      // ACK the SYN-ACK
      if (send_handshake_packet(sock, ACK_FLAG_MASK, sock->local_isn + 1,
                                sock->peer_isn + 1) < 0) return EXIT_ERROR;
    }
    // Server/ Listener's state when it is not waiting for a syn. 
    else {
    // I sent you my syn-ack but you didnt receive it so you sent a syn again, but now i am not waiting for it.
      if (flags == SYN_FLAG_MASK && get_seq(&hdr) == sock->peer_isn) {
        if (send_handshake_packet(sock, outgoing, sock->local_isn,
                                  outgoing_ack) < 0) return EXIT_ERROR;
        continue;
      }

      // Corrupted packet handling
      if (flags != ACK_FLAG_MASK || get_ack(&hdr) != sock->local_isn + 1 ||
          get_seq(&hdr) != sock->peer_isn + 1) continue;
    }
    sock->window.next_seq_to_send = sock->local_isn + 1;
    sock->window.last_ack_received = sock->local_isn + 1;
    sock->window.next_seq_expected = sock->peer_isn + 1;
    // CP2 receive buffer bookkeeping starts aligned with the SYN-consumed
    // sequence number, same as next_seq_expected.
    sock->window.last_byte_rcvd = sock->peer_isn + 1;
    sock->window.last_byte_read = sock->peer_isn + 1;
    // Seed the peer's advertised window from the handshake so the first
    // send is not gated on having received a data ACK yet.
    if (get_advertised_window(&hdr) > 0) {
      sock->window.peer_adv_window = get_advertised_window(&hdr);
    }
    log_cwnd(sock, "init");
    return EXIT_SUCCESS;
  }
}

enum { CLOSE_OPEN, CLOSE_WAIT_FIN_ACK, CLOSE_WAIT_ACK, CLOSE_LINGER,
       CLOSE_DONE };

static int resend_close_packet(cmu_socket_t *sock) {
  // Every FIN acknowledges the contiguous prefix of the peer's stream.
  return send_handshake_packet(sock, FIN_FLAG_MASK | ACK_FLAG_MASK,
                               sock->local_fin_seq,
                               sock->window.next_seq_expected);
}

// Called only after window_send has received ACKs for all outgoing data.
static int start_teardown(cmu_socket_t *sock) {
  sock->local_fin_seq = sock->window.next_seq_to_send;
  sock->window.next_seq_to_send++;  // FIN consumes one sequence number.
  sock->close_state = sock->peer_fin_received ? CLOSE_WAIT_ACK
                                             : CLOSE_WAIT_FIN_ACK;
  if (resend_close_packet(sock) < 0) return EXIT_ERROR;
  sock->close_deadline = monotonic_ms() + DEFAULT_TIMEOUT;
  return EXIT_SUCCESS;
}

static void handle_close_packet(cmu_socket_t *sock, cmu_tcp_header_t *hdr) {
  if (get_payload_len((uint8_t *)hdr) != 0) return;
  uint8_t flags = get_flags(hdr);
  uint32_t seq = get_seq(hdr);
  if (flags != FIN_FLAG_MASK && flags != (FIN_FLAG_MASK | ACK_FLAG_MASK))
    return;
  if (flags & ACK_FLAG_MASK) {
    uint32_t ack = get_ack(hdr);
    if (after(ack, sock->window.next_seq_to_send)) return;
    if (after(ack, sock->window.last_ack_received))
      sock->window.last_ack_received = ack;
  }
  // FIN+ACK is an initial/crossed FIN unless it acknowledges our own FIN.
  int acknowledges_fin = flags == (FIN_FLAG_MASK | ACK_FLAG_MASK) &&
                         sock->close_state != CLOSE_OPEN &&
                         get_ack(hdr) == sock->local_fin_seq + 1;
  if (!acknowledges_fin) {
    if (sock->peer_fin_received) {
      if (seq == sock->peer_fin_seq && sock->close_state == CLOSE_WAIT_ACK)
        resend_close_packet(sock);
      return;
    }
    if (seq != sock->window.next_seq_expected) return;
    sock->peer_fin_received = 1;
    sock->peer_fin_seq = seq;
    sock->window.next_seq_expected++;
    // If our FIN is already outstanding, reuse its sequence number in FIN-ACK.
    if (sock->close_state == CLOSE_WAIT_FIN_ACK) {
      sock->simultaneous_close = 1;
      sock->close_state = CLOSE_WAIT_ACK;
      resend_close_packet(sock);
      sock->close_deadline = monotonic_ms() + DEFAULT_TIMEOUT;
    }
    // The peer's FIN alone does not request our application's closure.
  } else if (flags == (FIN_FLAG_MASK | ACK_FLAG_MASK)) {
    if (get_ack(hdr) != sock->local_fin_seq + 1) return;
    if (sock->close_state == CLOSE_WAIT_FIN_ACK) {
      if (seq != sock->window.next_seq_expected) return;
      sock->peer_fin_received = 1;
      sock->peer_fin_seq = seq;
      sock->window.next_seq_expected++;
      sock->window.last_ack_received = sock->local_fin_seq + 1;
      sock->close_state = CLOSE_LINGER;
    } else if (sock->close_state == CLOSE_WAIT_ACK &&
               sock->simultaneous_close && seq == sock->peer_fin_seq) {
      // Its FIN was already counted when the crossed FIN arrived.
      sock->window.last_ack_received = sock->local_fin_seq + 1;
      sock->close_state = CLOSE_LINGER;
    } else if (sock->close_state != CLOSE_LINGER ||
               seq != sock->peer_fin_seq) {
      return;
    }
    send_handshake_packet(sock, ACK_FLAG_MASK, sock->local_fin_seq + 1,
                          sock->peer_fin_seq + 1);
    sock->close_deadline = monotonic_ms() + 2LL * DEFAULT_TIMEOUT;
  }
}

/**
 * Tells if a given sequence number has been acknowledged by the socket.
 *
 * @param sock The socket to check for acknowledgements.
 * @param seq Sequence number to check.
 *
 * @return 1 if the sequence number has been acknowledged, 0 otherwise.
 */
int has_been_acked(cmu_socket_t *sock, uint32_t seq) {
  int result;
  result = after(sock->window.last_ack_received, seq);
  return result;
}

/**
 * Updates the socket information to represent the newly received packet.
 *
 * Processes cumulative ACKs and acknowledges only contiguous received data.
 *
 * @param sock The socket used for handling packets received.
 * @param pkt The packet data received by the socket.
 */
void handle_message(cmu_socket_t *sock, uint8_t *pkt) {
  cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;
  uint8_t flags = get_flags(hdr);

  if (flags & SYN_FLAG_MASK) {
    if (sock->type == TCP_INITIATOR &&
        flags == (SYN_FLAG_MASK | ACK_FLAG_MASK) &&
        get_seq(hdr) == sock->peer_isn &&
        get_ack(hdr) == sock->local_isn + 1) {
      send_handshake_packet(sock, ACK_FLAG_MASK, sock->local_isn + 1,
                            sock->peer_isn + 1);
    }
    return;
  }

  if (flags & FIN_FLAG_MASK) {
    handle_close_packet(sock, hdr);
    return;
  }
  if (sock->close_state == CLOSE_WAIT_ACK && flags == ACK_FLAG_MASK &&
      get_payload_len(pkt) == 0 && get_ack(hdr) == sock->local_fin_seq + 1 &&
      get_seq(hdr) == sock->peer_fin_seq + 1) {
    sock->window.last_ack_received = sock->local_fin_seq + 1;
    sock->close_state = sock->simultaneous_close ? CLOSE_LINGER : CLOSE_DONE;
    if (sock->simultaneous_close)
      sock->close_deadline = monotonic_ms() + 2LL * DEFAULT_TIMEOUT;
    return;
  }

  if (flags != 0 && flags != ACK_FLAG_MASK) return;

  if (flags & ACK_FLAG_MASK) {
    uint32_t ack = get_ack(hdr);
    // CP2 flow control: record the peer's current receive capacity.
    sock->window.peer_adv_window = get_advertised_window(hdr);

    int advanced = after(ack, sock->window.last_ack_received) &&
                   !after(ack, sock->window.next_seq_to_send);
    // A repeat only counts as a duplicate ACK if we actually have data in
    // flight; otherwise a pure receiver would count the ACKs piggybacked on
    // incoming data packets and trip fast retransmit with nothing to resend.
    int duplicate = ack == sock->window.last_ack_received &&
                    sock->window.next_seq_to_send !=
                        sock->window.last_ack_received;
    if (advanced) {
      sock->window.last_ack_received = ack;
    }
    if (advanced || duplicate) {
      cc_on_ack(sock, advanced);
    }
  }

  uint16_t payload_len = get_payload_len(pkt);
  if (payload_len == 0 || sock->peer_fin_received) return;

  uint32_t seq = get_seq(hdr);

  // Drop data the receive window has no room for (sender should respect our
  // advertised window, but don't write past the buffer regardless).
  uint32_t occupied = sock->window.last_byte_rcvd - sock->window.last_byte_read;
  if (occupied + payload_len > MAX_NETWORK_BUFFER) return;
  // Already fully delivered to the application — nothing new to store, but
  // still fall through to re-ACK so the peer learns where we are.
  if (!after(seq + payload_len, sock->window.last_byte_read)) {
    send_handshake_packet(sock, ACK_FLAG_MASK, sock->window.next_seq_to_send,
                          sock->window.next_seq_expected);
    return;
  }

  // Place the payload at its position in the circular buffer, regardless of
  // whether it arrived in order. Writes may wrap past MAX_NETWORK_BUFFER.
  uint32_t index = seq % MAX_NETWORK_BUFFER;
  uint8_t *payload = get_payload(pkt);
  uint32_t first_chunk = MAX_NETWORK_BUFFER - index;
  if (payload_len <= first_chunk) {
    memcpy(sock->received_buf + index, payload, payload_len);
  } else {
    memcpy(sock->received_buf + index, payload, first_chunk);
    memcpy(sock->received_buf, payload + first_chunk, payload_len - first_chunk);
  }
  if (after(seq + payload_len, sock->window.last_byte_rcvd)) {
    sock->window.last_byte_rcvd = seq + payload_len;
  }

  if (seq == sock->window.next_seq_expected) {
    // Single-gap design: once the missing piece at the frontier arrives,
    // everything up to last_byte_rcvd is already contiguous in the buffer.
    sock->window.next_seq_expected = sock->window.last_byte_rcvd;
    // Wake the application even while our sender is waiting for its own ACKs.
    pthread_cond_signal(&sock->wait_cond);
  }
  // Out-of-order data (seq != next_seq_expected) is buffered above but does
  // not advance next_seq_expected; the repeated ACK below signals the gap.

  send_handshake_packet(sock, ACK_FLAG_MASK, sock->window.next_seq_to_send,
                        sock->window.next_seq_expected);
}

/**
 * Checks if the socket received any data.
 *
 * Reads and validates one complete UDP datagram from the established peer.
 *
 * @param sock The socket used for receiving data on the connection.
 * @param flags Flags that determine how the socket should wait for data. Check
 *             `cmu_read_mode_t` for more information.
 */
void check_for_data(cmu_socket_t *sock, cmu_read_mode_t flags) {
  uint8_t pkt[MAX_LEN + 1];
  struct sockaddr_in peer;
  socklen_t conn_len = sizeof(peer);
  int recv_flags = MSG_DONTWAIT;

  if (flags == TIMEOUT) {
    struct pollfd fd = {.fd = sock->socket, .events = POLLIN};
    if (poll(&fd, 1, DEFAULT_TIMEOUT) <= 0) return;
  } else if (flags == NO_FLAG) {
    recv_flags = 0;
  } else if (flags != NO_WAIT) {
    fprintf(stderr, "ERROR unknown flag\n");
    return;
  }

  pthread_mutex_lock(&sock->recv_lock);
  ssize_t len = recvfrom(sock->socket, pkt, sizeof(pkt), recv_flags,
                         (struct sockaddr *)&peer, &conn_len);
  if (len >= (ssize_t)sizeof(cmu_tcp_header_t) && len <= MAX_LEN &&
      same_peer(&peer, &sock->conn)) {
    cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;
    uint16_t hlen = get_hlen(hdr);
    if (ntohl(hdr->identifier) == IDENTIFIER && get_plen(hdr) == len &&
        hlen >= sizeof(*hdr) && hlen <= len &&
        get_extension_length(hdr) == hlen - sizeof(*hdr)) {
      handle_message(sock, pkt);
    }
  }
  pthread_mutex_unlock(&(sock->recv_lock));
}

// Retained stop-and-wait alternative; begin_backend uses window_send().
void single_send(cmu_socket_t *sock, uint8_t *data, int buf_len) {
  uint8_t *msg;
  uint8_t *data_offset = data;
  size_t conn_len = sizeof(sock->conn);

  int sockfd = sock->socket;
  if (buf_len > 0) {
    while (buf_len != 0) {
      uint16_t payload_len = MIN((uint32_t)buf_len, (uint32_t)MSS);

      uint16_t src = sock->my_port;
      uint16_t dst = ntohs(sock->conn.sin_port);
      uint32_t seq = sock->window.last_ack_received;
      uint32_t ack = sock->window.next_seq_expected;
      uint16_t hlen = sizeof(cmu_tcp_header_t);
      uint16_t plen = hlen + payload_len;
      uint8_t flags = 0;
      uint16_t adv_window = 1;
      uint16_t ext_len = 0;
      uint8_t *ext_data = NULL;
      uint8_t *payload = data_offset;

      msg = create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                          ext_len, ext_data, payload, payload_len);
      buf_len -= payload_len;
      sock->window.next_seq_to_send = seq + payload_len;

      while (1) {
        // FIXME: This is using stop and wait, can we do better?
        sendto(sockfd, msg, plen, 0, (struct sockaddr *)&(sock->conn),
               conn_len);
        check_for_data(sock, TIMEOUT);
        if (has_been_acked(sock, seq)) {
          break;
        }
      }
      free(msg);

      data_offset += payload_len;
    }
  }
}

// Queue entries retain outstanding payloads in the backend's current data buffer.
// Entries are released (or trimmed) as cumulative ACKs cover their bytes.
typedef struct outstanding_packet {
  uint32_t seq;
  uint16_t len;
  uint8_t *payload;
  struct outstanding_packet *next;
} outstanding_packet_t;

static int send_data_packet(cmu_socket_t *sock, outstanding_packet_t *entry) {
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint16_t plen = hlen + entry->len;
  uint8_t *pkt = create_packet(sock->my_port, ntohs(sock->conn.sin_port),
                               entry->seq, sock->window.next_seq_expected,
                               hlen, plen, ACK_FLAG_MASK,
                               advertised_window(sock), 0, NULL,
                               entry->payload, entry->len);
  if (pkt == NULL) return EXIT_ERROR;
  ssize_t sent = sendto(sock->socket, pkt, plen, 0,
                        (struct sockaddr *)&sock->conn, sizeof(sock->conn));
  free(pkt);
  return sent == plen ? EXIT_SUCCESS : EXIT_ERROR;
}

static int window_send(cmu_socket_t *sock, uint8_t *data, int buf_len) {
  outstanding_packet_t *head = NULL, *tail = NULL;
  int offset = 0;
  int64_t deadline = 0;
  int result = EXIT_SUCCESS;


  // MOVE THROUGH THE DATA IN THE BUFFER.
  while (offset < buf_len || head != NULL) {
    uint32_t ack = sock->window.last_ack_received;

    // Move the head to the data that has not been yet acked 
    // and free the other data from the buffer it has been processed
    while (head != NULL && !after(head->seq + head->len, ack)) {
      outstanding_packet_t *done = head;
      head = head->next;
      free(done);
    }

    // We are starting with a no data buffer.
    if (head == NULL) {
      tail = NULL;
      deadline = 0;
    } 
    else if (after(ack, head->seq)) {
      uint32_t covered = ack - head->seq;
      head->seq = ack;
      head->payload += covered;
      head->len -= covered;
    }

    // CP2 fast retransmit: three duplicate ACKs pinpointed the hole at the
    // head of the queue, so resend that one packet only -- unlike a timeout,
    // which resends the whole queue.
    if (sock->window.fast_retransmit_pending) {
      sock->window.fast_retransmit_pending = 0;
      if (head != NULL) {
        if (send_data_packet(sock, head) < 0) {
          result = EXIT_ERROR;
          goto cleanup;
        }
        deadline = monotonic_ms() + DEFAULT_TIMEOUT;
      }
    }

    // Timeout recovery uses the same outstanding queue, in sequence order.
    // slow start again here 
    if (head != NULL && monotonic_ms() >= deadline) {
      // CP2: a timeout means nothing is getting through. Halve ssthresh from
      // where cwnd had reached and restart at the initial slow-start window,
      // abandoning any fast recovery in progress.
      sock->window.ssthresh = sock->window.cwnd / 2;
      sock->window.cwnd = WINDOW_INITIAL_WINDOW_SIZE;
      sock->window.in_fast_recovery = 0;
      sock->window.dup_ack_count = 0;
      log_cwnd(sock, "timeout");
        // go back N logic
      for (outstanding_packet_t *entry = head; entry; entry = entry->next) {
        if (send_data_packet(sock, entry) < 0) {
          result = EXIT_ERROR;
          goto cleanup;
        }
      }
      deadline = monotonic_ms() + DEFAULT_TIMEOUT;
    }


    while (offset < buf_len) {

      // len is the length of data we can send for a cumulative ack.
      uint16_t len = MIN((uint32_t)(buf_len - offset), (uint32_t)MSS);

      // The effective window size right now
      uint32_t outstanding = sock->window.next_seq_to_send -
                             sock->window.last_ack_received;
      // CP2: bounded by both the peer's receive capacity and the congestion
      // window, per the handout's min(advertised window, cwnd).
      uint32_t send_window = MIN((uint32_t)sock->window.peer_adv_window,
                                 sock->window.cwnd);
      // Preserve the student's rule: do not shrink a packet to fill a gap.
      if (outstanding > send_window || len > send_window - outstanding) break;
      outstanding_packet_t *entry = malloc(sizeof(*entry));
      if (entry == NULL) {
        result = EXIT_ERROR;
        goto cleanup;
      }
      entry->seq = sock->window.next_seq_to_send;
      entry->len = len;
      entry->payload = data + offset;
      entry->next = NULL;
      if (send_data_packet(sock, entry) < 0) {
        free(entry);
        result = EXIT_ERROR;
        goto cleanup;
      }
      if (tail != NULL) tail->next = entry;
      else {
        head = entry;
        deadline = monotonic_ms() + DEFAULT_TIMEOUT;
      }
      tail = entry;
      sock->window.next_seq_to_send += len;
      offset += len;
    }

    // I have to poll for any action on my ques so that I can get acks and do something about my queue.
    if (head != NULL) {
      int64_t remaining = deadline - monotonic_ms();
      struct pollfd fd = {.fd = sock->socket, .events = POLLIN};
      if (remaining > 0) {
        int ready = poll(&fd, 1, (int)remaining);
        if (ready < 0 && errno != EINTR) {
          result = EXIT_ERROR;
          goto cleanup;
        }
        if (ready > 0) check_for_data(sock, NO_WAIT);
      }
    }
  }

cleanup:
  while (head != NULL) {
    outstanding_packet_t *next = head->next;
    free(head);
    head = next;
  }
  return result;
}

void *begin_backend(void *in) {
  cmu_socket_t *sock = (cmu_socket_t *)in;
  int death, buf_len, send_signal;
  uint8_t *data;
  int64_t teardown_giveup_deadline = 0;  // STOPGAP, see below.

  if (tcp_handshake(sock) < 0) {
    fprintf(stderr, "CMU-TCP handshake failed or was interrupted\n");
    return NULL;
  }

  while (1) {
    while (pthread_mutex_lock(&(sock->death_lock)) != 0) {
    }
    death = sock->dying;
    pthread_mutex_unlock(&(sock->death_lock));

    while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
    }
    buf_len = sock->sending_len;

    if (death && buf_len == 0) {
      pthread_mutex_unlock(&sock->send_lock);
      if (sock->close_state == CLOSE_OPEN) {
        if (start_teardown(sock) < 0) {
          perror("CMU-TCP teardown send");
          return NULL;
        }
        // STOPGAP (not part of the original teardown design): bound how long
        // we'll wait for a peer that never responds to our FIN at all, so
        // cmu_close() can't hang forever. Pre-existing CP1 teardown behavior
        // has no such bound; flagged here for the owning student to revisit.
        teardown_giveup_deadline = monotonic_ms() + 5LL * DEFAULT_TIMEOUT;
      }
      if (sock->close_state == CLOSE_DONE) break;
      if (teardown_giveup_deadline != 0 &&
          monotonic_ms() >= teardown_giveup_deadline) {
        fprintf(stderr,
                "CMU-TCP teardown STOPGAP: giving up, peer never "
                "completed the FIN exchange\n");
        break;
      }
      if (monotonic_ms() >= sock->close_deadline) {
        if (sock->close_state == CLOSE_LINGER) break;
        if (resend_close_packet(sock) < 0) {
          perror("CMU-TCP teardown retransmission");
          return NULL;
        }
        sock->close_deadline = monotonic_ms() + DEFAULT_TIMEOUT;
      }
      struct pollfd fd = {.fd = sock->socket, .events = POLLIN};
      int64_t remaining = sock->close_deadline - monotonic_ms();
      if (remaining > 0) poll(&fd, 1, (int)MIN(remaining, 100));
    } else if (buf_len > 0) {
      data = malloc(buf_len);
      memcpy(data, sock->sending_buf, buf_len);
      sock->sending_len = 0;
      free(sock->sending_buf);
      sock->sending_buf = NULL;
      pthread_mutex_unlock(&(sock->send_lock));
      int sent = window_send(sock, data, buf_len);
      free(data);
      if (sent < 0) {
        perror("CMU-TCP window send");
        return NULL;
      }
    } else {
      pthread_mutex_unlock(&(sock->send_lock));
    }

    check_for_data(sock, NO_WAIT);

    while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
    }

    // Readable bytes must be both contiguous and actual payload; see
    // readable_end() in cmu_tcp.c for why the two bounds can differ.
    uint32_t readable =
        before(sock->window.next_seq_expected, sock->window.last_byte_rcvd)
            ? sock->window.next_seq_expected
            : sock->window.last_byte_rcvd;
    send_signal = readable != sock->window.last_byte_read;

    pthread_mutex_unlock(&(sock->recv_lock));

    if (send_signal) {
      pthread_cond_signal(&(sock->wait_cond));
    }
  }

  pthread_exit(NULL);
  return NULL;
}
