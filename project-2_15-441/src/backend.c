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
    pthread_mutex_lock(&sock->death_lock);
    int dying = sock->dying;
    pthread_mutex_unlock(&sock->death_lock);
    if (dying) return EXIT_ERROR;

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
    sock->window.last_ack_received = sock->local_isn + 1;
    sock->window.next_seq_expected = sock->peer_isn + 1;
    return EXIT_SUCCESS;
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
 * In the current stop-and-wait implementation, this function also sends an
 * acknowledgement for the packet.
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

  switch (flags) {
    case ACK_FLAG_MASK: {
      uint32_t ack = get_ack(hdr);
      if (after(ack, sock->window.last_ack_received)) {
        sock->window.last_ack_received = ack;
      }
      break;
    }
    default: {
      socklen_t conn_len = sizeof(sock->conn);
      uint32_t seq = sock->window.last_ack_received;

      // No payload.
      uint8_t *payload = NULL;
      uint16_t payload_len = 0;

      // No extension.
      uint16_t ext_len = 0;
      uint8_t *ext_data = NULL;

      uint16_t src = sock->my_port;
      uint16_t dst = ntohs(sock->conn.sin_port);
      uint32_t ack = get_seq(hdr) + get_payload_len(pkt);
      uint16_t hlen = sizeof(cmu_tcp_header_t);
      uint16_t plen = hlen + payload_len;
      uint8_t flags = ACK_FLAG_MASK;
      uint16_t adv_window = 1;
      uint8_t *response_packet =
          create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                        ext_len, ext_data, payload, payload_len);

      sendto(sock->socket, response_packet, plen, 0,
             (struct sockaddr *)&(sock->conn), conn_len);
      free(response_packet);

      seq = get_seq(hdr);

      if (seq == sock->window.next_seq_expected) {
        sock->window.next_seq_expected = seq + get_payload_len(pkt);
        payload_len = get_payload_len(pkt);
        payload = get_payload(pkt);

        // Make sure there is enough space in the buffer to store the payload.
        sock->received_buf =
            realloc(sock->received_buf, sock->received_len + payload_len);
        memcpy(sock->received_buf + sock->received_len, payload, payload_len);
        sock->received_len += payload_len;
      }
    }
  }
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

/**
 * Breaks up the data into packets and sends a single packet at a time.
 *
 * You should most certainly update this function in your implementation.
 *
 * @param sock The socket to use for sending data.
 * @param data The data to be sent.
 * @param buf_len The length of the data being sent.
 */
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
      break;
    }

    if (buf_len > 0) {
      data = malloc(buf_len);
      memcpy(data, sock->sending_buf, buf_len);
      sock->sending_len = 0;
      free(sock->sending_buf);
      sock->sending_buf = NULL;
      pthread_mutex_unlock(&(sock->send_lock));
      single_send(sock, data, buf_len);
      free(data);
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
