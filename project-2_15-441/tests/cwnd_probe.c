/* Throwaway: push enough data to watch cwnd evolve.
 * Usage: cwnd_probe recv <port> <bytes>
 *        cwnd_probe send <port> <bytes>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmu_tcp.h"

int main(int argc, char **argv) {
  if (argc != 4) return 1;
  int is_send = strcmp(argv[1], "send") == 0;
  int port = atoi(argv[2]);
  int total = atoi(argv[3]);
  cmu_socket_t s;

  if (cmu_socket(&s, is_send ? TCP_INITIATOR : TCP_LISTENER, port,
                 "127.0.0.1") < 0) {
    return 2;
  }

  if (is_send) {
    uint8_t *data = malloc(total);
    for (int i = 0; i < total; i++) data[i] = (uint8_t)(i % 251);
    // CMU_TCP_WRITE_CHUNK mimics an application that writes in pieces (the
    // provided client.c uses 2000-byte freads) rather than one large write.
    const char *chunk_env = getenv("CMU_TCP_WRITE_CHUNK");
    int chunk = chunk_env ? atoi(chunk_env) : 0;
    if (chunk <= 0) {
      cmu_write(&s, data, total);
    } else {
      for (int off = 0; off < total; off += chunk) {
        int n = total - off < chunk ? total - off : chunk;
        cmu_write(&s, data + off, n);
      }
    }
    free(data);
  } else {
    uint8_t *buf = malloc(total);
    int got = 0;
    while (got < total) {
      int n = cmu_read(&s, buf + got, total - got, NO_FLAG);
      if (n <= 0) break;
      got += n;
    }
    int ok = 1;
    for (int i = 0; i < got; i++) {
      if (buf[i] != (uint8_t)(i % 251)) { ok = 0; break; }
    }
    fprintf(stderr, "received %d of %d bytes, payload %s\n", got, total,
            ok ? "CORRECT" : "CORRUPT");
    free(buf);
  }

  cmu_close(&s);
  return 0;
}
