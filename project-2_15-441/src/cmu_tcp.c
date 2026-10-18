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
 * This file implements the high-level API for CMU-TCP sockets.
 */

#include "cmu_tcp.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "backend.h"

int cmu_socket(cmu_socket_t *sock, const cmu_socket_type_t socket_type,
               const int port, const char *server_ip) {
  int sockfd, optval;
  socklen_t len;
  struct sockaddr_in conn, my_addr;
  len = sizeof(my_addr);

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    perror("ERROR opening socket");
    return EXIT_ERROR;
  }
  sock->socket = sockfd;
  sock->received_buf = malloc(MAX_NETWORK_BUFFER);
  if (sock->received_buf == NULL) {
    perror("ERROR allocating receive buffer");
    return EXIT_ERROR;
  }
  pthread_mutex_init(&(sock->recv_lock), NULL);

  sock->sending_buf = NULL;
  sock->sending_len = 0;
  pthread_mutex_init(&(sock->send_lock), NULL);

  sock->type = socket_type;
  sock->dying = 0;
  sock->close_state = 0;
  sock->peer_fin_received = 0;
  sock->simultaneous_close = 0;
  sock->local_fin_seq = 0;
  sock->peer_fin_seq = 0;
  sock->close_deadline = 0;
  pthread_mutex_init(&(sock->death_lock), NULL);

  // The backend synchronizes these values during tcp_handshake().
  sock->window.last_ack_received = 0;
  sock->window.next_seq_to_send = 0;
  sock->window.next_seq_expected = 0;
  sock->window.last_byte_rcvd = 0;
  sock->window.last_byte_read = 0;
  sock->window.cwnd = WINDOW_INITIAL_WINDOW_SIZE;
  sock->window.ssthresh = WINDOW_INITIAL_SSTHRESH;
  sock->window.peer_adv_window = MSS;
  sock->window.dup_ack_count = 0;
  sock->window.in_fast_recovery = 0;
  sock->window.fast_retransmit_pending = 0;
  sock->window.last_adv_sent = MAX_NETWORK_BUFFER;
  sock->window.window_update_pending = 0;

  if (pthread_cond_init(&sock->wait_cond, NULL) != 0) {
    perror("ERROR condition variable not set\n");
    return EXIT_ERROR;
  }

  switch (socket_type) {
    case TCP_INITIATOR:
      if (server_ip == NULL) {
        perror("ERROR server_ip NULL");
        return EXIT_ERROR;
      }
      memset(&conn, 0, sizeof(conn));
      conn.sin_family = AF_INET;
      conn.sin_addr.s_addr = inet_addr(server_ip);
      conn.sin_port = htons(port);
      sock->conn = conn;

      my_addr.sin_family = AF_INET;
      my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
      my_addr.sin_port = 0;
      if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(my_addr)) < 0) {
        perror("ERROR on binding");
        return EXIT_ERROR;
      }

      break;

    case TCP_LISTENER:
      memset(&conn, 0, sizeof(conn));
      conn.sin_family = AF_INET;
      conn.sin_addr.s_addr = htonl(INADDR_ANY);
      conn.sin_port = htons((uint16_t)port);

      optval = 1;
      setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval,
                 sizeof(int));
      if (bind(sockfd, (struct sockaddr *)&conn, sizeof(conn)) < 0) {
        perror("ERROR on binding");
        return EXIT_ERROR;
      }
      sock->conn = conn;
      break;

    default:
      perror("Unknown Flag");
      return EXIT_ERROR;
  }
  getsockname(sockfd, (struct sockaddr *)&my_addr, &len);
  sock->my_port = ntohs(my_addr.sin_port);

  pthread_create(&(sock->thread_id), NULL, begin_backend, (void *)sock);
  return EXIT_SUCCESS;
}

int cmu_close(cmu_socket_t *sock) {
  while (pthread_mutex_lock(&(sock->death_lock)) != 0) {
  }
  sock->dying = 1;
  pthread_mutex_unlock(&(sock->death_lock));

  pthread_join(sock->thread_id, NULL);

  if (sock != NULL) {
    if (sock->received_buf != NULL) {
      free(sock->received_buf);
    }
    if (sock->sending_buf != NULL) {
      free(sock->sending_buf);
    }
  } else {
    perror("ERROR null socket\n");
    return EXIT_ERROR;
  }
  return close(sock->socket);
}

// End of the byte range the application is allowed to read. A byte must be
// both contiguous (before next_seq_expected) and actual payload (before
// last_byte_rcvd). The two differ in two situations:
//   - an out-of-order gap leaves next_seq_expected behind last_byte_rcvd, so
//     the buffered bytes past the gap are not readable yet;
//   - a received FIN advances next_seq_expected past last_byte_rcvd, because
//     the FIN consumes a sequence number without carrying a data byte.
static uint32_t readable_end(cmu_socket_t *sock) {
  return before(sock->window.next_seq_expected, sock->window.last_byte_rcvd)
             ? sock->window.next_seq_expected
             : sock->window.last_byte_rcvd;
}

int cmu_read(cmu_socket_t *sock, void *buf, int length, cmu_read_mode_t flags) {
  int read_len = 0;

  if (length < 0) {
    perror("ERROR negative length");
    return EXIT_ERROR;
  }

  while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
  }

  switch (flags) {
    case NO_FLAG:
      while (readable_end(sock) == sock->window.last_byte_read) {
        pthread_cond_wait(&(sock->wait_cond), &(sock->recv_lock));
      }
    // Fall through.
    case NO_WAIT: {
      uint32_t available = readable_end(sock) - sock->window.last_byte_read;
      if (available > 0) {
        read_len = available < (uint32_t)length ? (int)available : length;

        uint32_t start = sock->window.last_byte_read % MAX_NETWORK_BUFFER;
        uint32_t first_chunk = MAX_NETWORK_BUFFER - start;
        if ((uint32_t)read_len <= first_chunk) {
          memcpy(buf, sock->received_buf + start, read_len);
        } else {
          memcpy(buf, sock->received_buf + start, first_chunk);
          memcpy((uint8_t *)buf + first_chunk, sock->received_buf,
                 read_len - first_chunk);
        }
        sock->window.last_byte_read += read_len;

        // CP2 zero-window recovery. The peer only ACKs in response to data,
        // so if we previously advertised a window it cannot send into, it is
        // waiting on us and no amount of waiting will change that. Once at
        // least one MSS has freed up, ask the backend thread to announce the
        // reopened window. The MSS threshold keeps us from announcing every
        // few bytes and provoking a stream of tiny packets.
        uint32_t occupied =
            sock->window.last_byte_rcvd - sock->window.last_byte_read;
        uint32_t space = occupied > MAX_NETWORK_BUFFER
                             ? 0
                             : MAX_NETWORK_BUFFER - occupied;
        if (sock->window.last_adv_sent < MSS && space >= MSS) {
          sock->window.window_update_pending = 1;
        }
      }
      break;
    }
    default:
      perror("ERROR Unknown flag.\n");
      read_len = EXIT_ERROR;
  }
  pthread_mutex_unlock(&(sock->recv_lock));
  return read_len;
}

int cmu_write(cmu_socket_t *sock, const void *buf, int length) {
  while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
  }
  if (sock->sending_buf == NULL)
    sock->sending_buf = malloc(length);
  else
    sock->sending_buf = realloc(sock->sending_buf, length + sock->sending_len);
  memcpy(sock->sending_buf + sock->sending_len, buf, length);
  sock->sending_len += length;

  pthread_mutex_unlock(&(sock->send_lock));
  return EXIT_SUCCESS;
}
