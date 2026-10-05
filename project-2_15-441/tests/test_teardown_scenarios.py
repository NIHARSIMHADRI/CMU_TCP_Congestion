"""Three data packets, then teardown; drop FIN, FIN-ACK, or final ACK.
Run: python3 tests/test_teardown_scenarios.py. Requires gcc and UDP sockets.
"""
import socket
import sys
import struct
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HEADER = struct.Struct('!IHHIIHHBHH')


def run(binary, drop):
    relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    relay.bind(('127.0.0.1', 0))
    relay.settimeout(.1)
    server = subprocess.Popen([str(binary), 'server'], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True)
    port_line = server.stdout.readline()
    assert port_line.startswith('PORT '), port_line
    server_port = int(port_line.split()[1])
    client = subprocess.Popen([str(binary), 'client', str(relay.getsockname()[1])],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    client_addr = None
    packets = []
    dropped = False
    closing = False
    start = time.monotonic()
    try:
        while time.monotonic()-start < 30:
            if client.poll() is not None and server.poll() is not None:
                break
            try:
                data, addr = relay.recvfrom(65535)
            except socket.timeout:
                continue
            from_server = addr[1] == server_port
            if not from_server:
                client_addr = addr
            fields = HEADER.unpack(data[:25])
            flags = fields[7]
            if flags == 2:
                closing = True
            event = dict(sender='server' if from_server else 'client',
                         seq=fields[3], ack=fields[4], flags=flags,
                         payload=len(data)-fields[5],
                         time=round(time.monotonic()-start, 3))
            packets.append(event)
            target = {'fin': 2, 'finack': 6, 'ack': 4}.get(drop)
            if closing and not dropped and flags == target and (
                    drop != 'ack' or not from_server):
                event['dropped'] = True
                dropped = True
                continue
            dst = client_addr if from_server else ('127.0.0.1', server_port)
            data = bytearray(data)
            struct.pack_into('!HH', data, 4, relay.getsockname()[1], dst[1])
            relay.sendto(data, dst)
        else:
            raise AssertionError('Teardown did not finish within 30 seconds')
        co, ce = client.communicate(timeout=1)
        so, se = server.communicate(timeout=1)
        assert client.returncode == server.returncode == 0, (co, ce, so, se)
        data_packets = [p for p in packets if p['sender']=='client' and p['payload']]
        assert len(data_packets) == 3, data_packets
        fin = next(p for p in packets if p['flags']==2)
        end = (data_packets[-1]['seq'] + data_packets[-1]['payload']) % 2**32
        assert fin['seq'] == end
        assert any(p['sender']=='server' and p['flags']==4 and p['ack']==end
                   and p['time']<=fin['time'] for p in packets)
        finack = next(p for p in packets if p['flags']==6)
        peer_fin = next(p for p in packets if p['flags']==2 and
                        p['sender'] != finack['sender'])
        assert finack['ack'] == (peer_fin['seq']+1)%2**32
        acks = [p for p in packets if p['sender'] != finack['sender'] and
                p['flags']==4 and p['ack']==(finack['seq']+1)%2**32]
        assert acks and acks[0]['seq']==(peer_fin['seq']+1)%2**32
        if drop:
            assert dropped
            original = next(p for p in packets if p.get('dropped'))
            repeats = [p for p in packets if p is not original and
                       all(p[k]==original[k] for k in ('sender','seq')) and
                       (p['flags'] in (2,6) if drop == 'fin' else
                        p['flags']==original['flags'] and p['ack']==original['ack'])]
            assert repeats, 'Dropped control packet was not retransmitted'
            if drop == 'ack':
                assert repeats[0]['time']-original['time'] >= 2.8
        assert time.monotonic()-start >= acks[-1]['time']+5.8
        print((drop or 'normal')+': PASS; three payload packets delivered exactly; teardown completed')
        print('  control packets:', [(p['sender'],p['flags'],p['time'],
                                        bool(p.get('dropped'))) for p in packets
                                      if p['flags'] in (2,6) or p in acks])
    finally:
        for proc in (client, server):
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        relay.close()


def main():
    with tempfile.TemporaryDirectory(prefix='cmu-teardown-test-') as directory:
        tmp = Path(directory)
        driver = tmp/'endpoint.c'
        driver.write_text('''
#include "cmu_tcp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
  cmu_socket_t s;
  unsigned char data[MSS * 3];
  for (size_t i=0; i<sizeof(data); i++) data[i]=i%251;
  int client=argc>1 && strcmp(argv[1],"client")==0;
  if (cmu_socket(&s,client?TCP_INITIATOR:TCP_LISTENER,
                 client?atoi(argv[2]):0,"127.0.0.1")<0) return 1;
  if (client) {
    cmu_write(&s,data,sizeof(data));
  } else {
    printf("PORT %u\\n",s.my_port); fflush(stdout);
    unsigned char received[sizeof(data)];
    size_t offset=0;
    while(offset<sizeof(data)) {
      int n=cmu_read(&s,received+offset,sizeof(data)-offset,NO_FLAG);
      if(n<=0) return 2;
      offset+=n;
    }
    if(memcmp(data,received,sizeof(data))) return 3;
    // Let the initiator send FIN first, then request our own closure.
    sleep(1);
  }
  return cmu_close(&s)<0;
}
''')
        binary=tmp/'endpoint'
        subprocess.run(['gcc','-pthread','-Wall','-Wextra','-pedantic',
                        '-I'+str(ROOT/'inc'),
                        *[str(ROOT/'src'/f) for f in
                          ('cmu_packet.c','cmu_tcp.c','backend.c')],
                        str(driver),'-o',str(binary)],check=True)
        failures = []
        for drop in (sys.argv[1:] or (None, 'fin', 'finack', 'ack')):
            try:
                run(binary, drop)
            except AssertionError as error:
                failures.append((drop, str(error)))
                print(str(drop) + ': FAIL; ' + str(error), flush=True)
        if failures:
            raise SystemExit(1)


if __name__=='__main__':
    main()
