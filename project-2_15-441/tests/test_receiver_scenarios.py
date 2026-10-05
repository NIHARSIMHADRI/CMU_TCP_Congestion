"""C receiver checks: supplied basic ACK payloads and user's five-packet loss case.
Run: python3 tests/test_receiver_scenarios.py (requires gcc and local UDP sockets).
"""
import socket
import struct
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
H = struct.Struct('!IHHIIHHBHH')
MSS = 1400 - H.size


def case(binary, tmp, payloads, order, name):
    output = tmp / 'received.bin'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', 0))
    sock.settimeout(4)
    total = sum(map(len, payloads))
    proc = subprocess.Popen([str(binary), str(port), str(total), str(output)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        def send(seq, ack, flags, payload=b''):
            sock.sendto(H.pack(15441, sock.getsockname()[1], port, seq, ack,
                              25, 25+len(payload), flags, 1, 0)+payload,
                        ('127.0.0.1', port))
        # Retry startup SYN until the C listener has bound its socket.
        sock.settimeout(.1)
        for _ in range(40):
            send(1000, 0, 8)
            try:
                reply, _ = sock.recvfrom(65535)
                break
            except socket.timeout:
                pass
        else:
            raise AssertionError('No SYN-ACK from C receiver')
        f = H.unpack(reply[:25])
        assert f[7] == 12 and f[4] == 1001
        server_next = (f[3]+1) % 2**32
        send(1001, server_next, 4)
        try:
            sock.recvfrom(65535)
            raise AssertionError('Receiver responded to pure final ACK')
        except socket.timeout:
            pass
        sock.settimeout(4)
        starts=[]
        offset=1001
        for payload in payloads:
            starts.append(offset)
            offset+=len(payload)
        expected_index=0
        ack_trace=[]
        for index in order:
            send(starts[index], server_next, 4, payloads[index])
            reply, _ = sock.recvfrom(65535)
            f=H.unpack(reply[:25])
            if index == expected_index:
                expected_index+=1
            expected_ack=1001+sum(len(p) for p in payloads[:expected_index])
            assert f[7] == 4 and f[4] == expected_ack, (name,index,f,expected_ack)
            assert len(reply)==25
            ack_trace.append(f[4])
        stdout, stderr=proc.communicate(timeout=5)
        assert proc.returncode == 0, (stdout,stderr)
        assert output.read_bytes()==b''.join(payloads), 'Application bytes differ'
        print(name+': PASS; ACKs='+str(ack_trace)+'; exact application bytes verified')
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        sock.close()


def main():
    with tempfile.TemporaryDirectory(prefix='cmu-receiver-test-') as directory:
        tmp=Path(directory)
        driver=tmp/'receiver.c'
        driver.write_text('''
#include "cmu_tcp.h"
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
  if (argc != 4) return 1;
  cmu_socket_t s;
  if (cmu_socket(&s, TCP_LISTENER, atoi(argv[1]), NULL) < 0) return 2;
  int remaining = atoi(argv[2]);
  FILE *out = fopen(argv[3], "wb");
  if (!out) return 3;
  while (remaining > 0) {
    unsigned char buf[997];
    int n = cmu_read(&s, buf, remaining < 997 ? remaining : 997, NO_FLAG);
    if (n <= 0 || fwrite(buf, 1, n, out) != (size_t)n) return 4;
    remaining -= n;
  }
  fclose(out);
  return cmu_close(&s) < 0;
}
''')
        binary=tmp/'receiver'
        subprocess.run(['gcc','-pthread','-Wall','-Wextra','-pedantic',
                        '-I'+str(ROOT/'inc'),
                        *[str(ROOT/'src'/f) for f in
                          ('cmu_packet.c','cmu_tcp.c','backend.c')],
                        str(driver),'-o',str(binary)],check=True)
        for payload in (b'pa',b'pytest 1234567'):
            case(binary,tmp,[payload],[0],'Supplied ACK payload '+repr(payload))
        payloads=[bytes((i*MSS+j)%251 for j in range(MSS)) for i in range(5)]
        case(binary,tmp,payloads,[0,1,2,3,4],'Five in-order packets')
        # Packet 2 lost: 3 and 4 arrive out of order, then sender retries 2-4.
        case(binary,tmp,payloads,[0,2,3,1,2,3,4],'Missing packet 2 and Go-Back-N replay')


if __name__=='__main__':
    main()
