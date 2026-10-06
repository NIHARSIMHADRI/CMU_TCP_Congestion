/* A three-packet transfer followed by FIN / FIN-ACK / ACK teardown. */
#include "cmu_tcp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc < 2 || (strcmp(argv[1], "server") && strcmp(argv[1], "client"))) {
    fprintf(stderr, "Usage: %s server | client [server-ip]\n", argv[0]);
    return 1;
  }
  int client = strcmp(argv[1], "client") == 0;
  const char *ip = argc > 2 ? argv[2] : "10.0.1.1";
  cmu_socket_t sock;
  if (cmu_socket(&sock, client ? TCP_INITIATOR : TCP_LISTENER, 15441,
                 client ? ip : NULL) < 0) return 1;

  unsigned char expected[MSS * 3];
  for (size_t i = 0; i < sizeof(expected); ++i) expected[i] = i % 251;
  if (client) {
    printf("Queueing %zu bytes: three MSS-sized packets.\n", sizeof(expected));
    cmu_write(&sock, expected, sizeof(expected));
    printf("Requesting close; backend waits for data ACKs before FIN.\n");
  } else {
    unsigned char received[sizeof(expected)];
    size_t offset = 0;
    printf("Waiting for %zu bytes on UDP port 15441.\n", sizeof(expected));
    fflush(stdout);
    while (offset < sizeof(received)) {
      int n = cmu_read(&sock, received + offset,
                       sizeof(received) - offset, NO_FLAG);
      if (n <= 0) return 1;
      offset += n;
    }
    if (memcmp(received, expected, sizeof(expected)) != 0) {
      fprintf(stderr, "FAIL: received bytes differ.\n");
      return 1;
    }
    printf("PASS: all %zu bytes match. Closing after one second.\n", offset);
    fflush(stdout);
    sleep(1);
  }
  fflush(stdout);
  if (cmu_close(&sock) < 0) return 1;
  printf("%s: teardown completed.\n", client ? "Client" : "Server");
  return 0;
}
