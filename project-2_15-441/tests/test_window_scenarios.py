"""User-specified five-packet / three-packet-window and Go-Back-N checks.
Run from the project directory: python3 tests/test_window_scenarios.py
Builds an isolated copy with CP1_WINDOW_SIZE=MSS*3; requires gcc and UDP sockets.
"""
import shutil
import socket
import struct
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HEADER = struct.Struct('!IHHIIHHBHH')
MSS = 1400 - HEADER.size


def run_case(binary, loss):
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(('127.0.0.1', 0))
    receiver.settimeout(8)
    proc = subprocess.Popen([str(binary), str(receiver.getsockname()[1])],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True)
    trace = []
    start = time.monotonic()
    try:
        syn, peer = receiver.recvfrom(65535)
        fields = HEADER.unpack(syn[:25])
        assert fields[7] == 8
        client_isn = fields[3]
        base = (client_isn + 1) % 2**32
        server_isn = 5000

        def send(flags, ack, seq=server_isn + 1):
            receiver.sendto(HEADER.pack(15441, receiver.getsockname()[1],
                            peer[1], seq, ack % 2**32, 25, 25, flags, 1, 0), peer)

        send(12, base, server_isn)
        final, _ = receiver.recvfrom(65535)
        f = HEADER.unpack(final[:25])
        assert f[7] == 4 and f[3] == base and f[4] == server_isn + 1
        expected = 0
        received = bytearray()
        dropped = False
        initial = []
        while len(received) < 5 * MSS:
            data, _ = receiver.recvfrom(65535)
            f = HEADER.unpack(data[:25])
            payload = data[f[5]:]
            if not payload:
                continue
            offset = (f[3] - base) % 2**32
            assert len(payload) == MSS
            trace.append((offset // MSS + 1, round(time.monotonic()-start, 3)))
            if len(initial) < 3:
                initial.append(offset)
            if loss and offset == MSS and not dropped:
                dropped = True
            elif offset == expected:
                received.extend(payload)
                expected += len(payload)
            # Hold ACKs until all three initial packets arrive. This checks that
            # transmission fills the window before waiting for a response.
            if len(trace) == 3:
                assert initial == [0, MSS, MSS*2], initial
                receiver.settimeout(.2)
                try:
                    receiver.recvfrom(65535)
                    raise AssertionError('Sender exceeded the three-packet window')
                except socket.timeout:
                    pass
                finally:
                    receiver.settimeout(8)
                if not loss:
                    # Acknowledge just the first two, opening two packet slots.
                    send(4, base + 2*MSS)
                else:
                    send(4, base + expected)
            elif len(trace) > 3:
                send(4, base + expected)
        # In the lossless case, the held third-packet ACK is now included here.
        send(4, base + expected)
        receiver.sendto(HEADER.pack(15441, receiver.getsockname()[1],
                        peer[1], server_isn + 1, (base + expected) % 2**32,
                        25, 26, 4, 1, 0) + b'!', peer)
        out, err = proc.communicate(timeout=8)
        assert proc.returncode == 0, (out, err)
        assert received == bytes(i % 251 for i in range(5*MSS))
        order = [number for number, _ in trace]
        if loss:
            assert order[:6] == [1, 2, 3, 4, 2, 3], order
            retry = next(t for number, t in trace[3:] if number == 2)
            assert retry >= 2.8, trace
            assert order == [1, 2, 3, 4, 2, 3, 4, 5], order
        else:
            assert order == [1, 2, 3, 4, 5], order
        print(('Go-Back-N' if loss else 'Window slides') + ': PASS')
        print('  packet numbers / seconds:', trace)
        print('  all', len(received), 'payload bytes match')
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        receiver.close()


def main():
    with tempfile.TemporaryDirectory(prefix='cmu-window-test-') as tmp:
        tmp = Path(tmp)
        shutil.copytree(ROOT / 'inc', tmp / 'inc')
        grading = tmp / 'inc/grading.h'
        grading.write_text(grading.read_text().replace(
            '#define CP1_WINDOW_SIZE (MSS * 32)',
            '#define CP1_WINDOW_SIZE (MSS * 3)'))
        driver = tmp / 'sender.c'
        driver.write_text('''
#include "cmu_tcp.h"
#include <stdlib.h>
int main(int argc, char **argv) {
  if (argc != 2) return 1;
  cmu_socket_t sock;
  unsigned char data[MSS * 5];
  for (size_t i = 0; i < sizeof(data); ++i) data[i] = i % 251;
  if (cmu_socket(&sock, TCP_INITIATOR, atoi(argv[1]), "127.0.0.1") < 0) return 2;
  cmu_write(&sock, data, sizeof(data));
  unsigned char done;
  if (cmu_read(&sock, &done, 1, NO_FLAG) != 1 || done != '!') return 3;
  return cmu_close(&sock) < 0;
}
''')
        binary = tmp / 'sender'
        subprocess.run(['gcc', '-pthread', '-Wall', '-Wextra', '-pedantic',
                        '-I' + str(tmp / 'inc'),
                        *[str(ROOT / 'src' / f) for f in
                          ('cmu_packet.c', 'cmu_tcp.c', 'backend.c')],
                        str(driver), '-o', str(binary)], check=True)
        run_case(binary, False)
        run_case(binary, True)


if __name__ == '__main__':
    main()
