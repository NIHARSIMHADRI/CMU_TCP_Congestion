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

static int send_handshake_packet(cmu_socket_t *sock, uint8_t flags,
                                 uint32_t seq, uint32_t ack) {
  uint16_t len = sizeof(cmu_tcp_header_t);
  uint8_t *pkt = create_packet(sock->my_port, ntohs(sock->conn.sin_port),
                               seq, ack, len, len, flags, 1, 0, NULL, NULL, 0);
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
      get_plen(hdr) != len || get_extension_length(hdr) != 0 ||
      get_src(hdr) != ntohs(peer->sin_port) || get_dst(hdr) != sock->my_port) {
    return 0;
  }
  return 1;
}

// Implements the student's SYN / SYN-ACK / ACK exchange before data sending.
static int tcp_handshake(cmu_socket_t *sock) {
  FILE *random = fopen("/dev/urandom", "rb");
  if (random == NULL) return EXIT_ERROR;
  size_t count = fread(&sock->local_isn, sizeof(sock->local_isn), 1, random);
  fclose(random);
  if (count != 1) return EXIT_ERROR;

  int waiting_for_syn = sock->type == TCP_LISTENER;
  uint8_t outgoing = SYN_FLAG_MASK;
  uint32_t outgoing_ack = 0;
  if (!waiting_for_syn &&
      send_handshake_packet(sock, outgoing, sock->local_isn, 0) < 0) {
    return EXIT_ERROR;
  }
  int64_t deadline = monotonic_ms() + DEFAULT_TIMEOUT;

  while (1) {
    int64_t remaining = deadline - monotonic_ms();
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
    int received = receive_handshake_packet(sock, &hdr, &peer, timeout);
    if (received < 0) return EXIT_ERROR;
    if (received == 0) continue;

    uint8_t flags = get_flags(&hdr);
    if (waiting_for_syn) {
      if (flags != SYN_FLAG_MASK) continue;
      sock->conn = peer;
      sock->peer_isn = get_seq(&hdr);
      outgoing = SYN_FLAG_MASK | ACK_FLAG_MASK;
      outgoing_ack = sock->peer_isn + 1;
      if (send_handshake_packet(sock, outgoing, sock->local_isn,
                                outgoing_ack) < 0) return EXIT_ERROR;
      waiting_for_syn = 0;
      deadline = monotonic_ms() + DEFAULT_TIMEOUT;
      continue;
    }
    if (!same_peer(&peer, &sock->conn)) continue;

    if (sock->type == TCP_INITIATOR) {
      if (flags != (SYN_FLAG_MASK | ACK_FLAG_MASK) ||
          get_ack(&hdr) != sock->local_isn + 1) continue;
      sock->peer_isn = get_seq(&hdr);
      if (send_handshake_packet(sock, ACK_FLAG_MASK, sock->local_isn + 1,
                                sock->peer_isn + 1) < 0) return EXIT_ERROR;
    } else {
      if (flags == SYN_FLAG_MASK && get_seq(&hdr) == sock->peer_isn) {
        if (send_handshake_packet(sock, outgoing, sock->local_isn,
                                  outgoing_ack) < 0) return EXIT_ERROR;
        continue;
      }
      if (flags != ACK_FLAG_MASK || get_ack(&hdr) != sock->local_isn + 1 ||
          get_seq(&hdr) != sock->peer_isn + 1) continue;
    }
    sock->window.next_seq_to_send = sock->local_isn + 1;
    sock->window.last_ack_received = sock->local_isn + 1;
    sock->window.next_seq_expected = sock->peer_isn + 1;
    return EXIT_SUCCESS;
  }
}

enum { CLOSE_OPEN, CLOSE_WAIT_FIN_ACK, CLOSE_WAIT_ACK, CLOSE_LINGER,
       CLOSE_DONE };

static int resend_close_packet(cmu_socket_t *sock) {
  uint8_t flags = sock->close_state == CLOSE_WAIT_ACK
                      ? FIN_FLAG_MASK | ACK_FLAG_MASK : FIN_FLAG_MASK;
  uint32_t ack = sock->close_state == CLOSE_WAIT_ACK
                     ? sock->peer_fin_seq + 1 : 0;
  return send_handshake_packet(sock, flags, sock->local_fin_seq, ack);
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
  if (flags == FIN_FLAG_MASK) {
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
    if (after(ack, sock->window.last_ack_received) &&
        !after(ack, sock->window.next_seq_to_send)) {
      sock->window.last_ack_received = ack;
    }
  }

  uint16_t payload_len = get_payload_len(pkt);
  if (payload_len == 0 || sock->peer_fin_received) return;
  if (get_seq(hdr) == sock->window.next_seq_expected) {
    uint8_t *buf = realloc(sock->received_buf,
                            sock->received_len + payload_len);
    if (buf == NULL) {
      perror("CMU-TCP receive allocation");
      return;
    }
    sock->received_buf = buf;
    memcpy(buf + sock->received_len, get_payload(pkt), payload_len);
    sock->received_len += payload_len;
    sock->window.next_seq_expected += payload_len;
    // Wake the application even while our sender is waiting for its own ACKs.
    pthread_cond_signal(&sock->wait_cond);
  }
  // Out-of-order and duplicate data are discarded; ACK the contiguous prefix.
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
        get_extension_length(hdr) == hlen - sizeof(*hdr) &&
        get_src(hdr) == ntohs(peer.sin_port) && get_dst(hdr) == sock->my_port) {
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
                               hlen, plen, ACK_FLAG_MASK, 1, 0, NULL,
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

  while (offset < buf_len || head != NULL) {
    uint32_t ack = sock->window.last_ack_received;
    while (head != NULL && !after(head->seq + head->len, ack)) {
      outstanding_packet_t *done = head;
      head = head->next;
      free(done);
    }
    if (head == NULL) {
      tail = NULL;
      deadline = 0;
    } else if (after(ack, head->seq)) {
      uint32_t covered = ack - head->seq;
      head->seq = ack;
      head->payload += covered;
      head->len -= covered;
    }

    // Timeout recovery uses the same outstanding queue, in sequence order.
    if (head != NULL && monotonic_ms() >= deadline) {
      for (outstanding_packet_t *entry = head; entry; entry = entry->next) {
        if (send_data_packet(sock, entry) < 0) {
          result = EXIT_ERROR;
          goto cleanup;
        }
      }
      deadline = monotonic_ms() + DEFAULT_TIMEOUT;
    }

    while (offset < buf_len) {
      uint16_t len = MIN((uint32_t)(buf_len - offset), (uint32_t)MSS);
      uint32_t outstanding = sock->window.next_seq_to_send -
                             sock->window.last_ack_received;
      // Preserve the student's rule: do not shrink a packet to fill a gap.
      if (outstanding > CP1_WINDOW_SIZE ||
          len > CP1_WINDOW_SIZE - outstanding) break;
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
      if (sock->close_state == CLOSE_OPEN && start_teardown(sock) < 0) {
        perror("CMU-TCP teardown send");
        return NULL;
      }
      if (sock->close_state == CLOSE_DONE) break;
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

    send_signal = sock->received_len > 0;

    pthread_mutex_unlock(&(sock->recv_lock));

    if (send_signal) {
      pthread_cond_signal(&(sock->wait_cond));
    }
  }

  pthread_exit(NULL);
  return NULL;
}
