"""Diagnostic: measure per-round flight sizes with the receive window held open.

Mimics how an autograder measures slow start: act as the receiver, always
advertise a large window, collect everything the sender puts in flight during
a round (quiet period = end of round), then ACK and repeat.
"""
import socket
import struct
import subprocess
import time

H = struct.Struct('!IHHIIHHBHH')
HDR = H.size
MSS = 1400 - HDR
PROBE = '/tmp/cwnd_probe'
ADV = 65535


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as res:
        res.bind(('127.0.0.1', 0))
        port = res.getsockname()[1]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', port))

    import os
    env = dict(os.environ, CMU_TCP_CWND_LOG='/tmp/flight_cwnd.csv')
    sender = subprocess.Popen([PROBE, 'send', str(port), '400000'],
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, env=env)

    my_isn = 7000

    def send(seq, ack, flags):
        sock.sendto(H.pack(15441, port, 0, seq, ack % 2**32, HDR, HDR,
                            flags, ADV, 0), peer)

    # Handshake.
    sock.settimeout(5)
    syn, peer = sock.recvfrom(65535)
    f = H.unpack(syn[:HDR])
    assert f[7] == 8, 'expected SYN, got flags %d' % f[7]
    client_isn = f[3]
    base = (client_isn + 1) % 2**32
    send(my_isn, base, 12)                       # SYN-ACK
    final, _ = sock.recvfrom(65535)              # final ACK
    assert H.unpack(final[:HDR])[7] == 4

    expected = base          # next contiguous byte we want
    rounds = []
    sock.settimeout(0.35)

    # Withhold ACKs for the duration of a round so the sender drains its
    # window and goes quiet -- that quiet period delimits the round and the
    # bytes collected are the flight size. Then release one ACK per packet,
    # with the ack number advancing a packet at a time, so slow start sees
    # as many ACKs as it sent packets and can double.
    for _ in range(14):
        flight = 0
        seen = set()
        retrans = False
        arrivals = []
        while True:
            try:
                pkt, _ = sock.recvfrom(65535)
            except socket.timeout:
                break
            g = H.unpack(pkt[:HDR])
            seq, hlen, plen = g[3], g[5], g[6]
            payload = plen - hlen
            if payload <= 0:
                continue
            if seq in seen:
                retrans = True
            seen.add(seq)
            flight += payload
            arrivals.append((seq, payload))
        if flight == 0:
            break
        rounds.append((flight, len(seen), retrans))

        # Release the withheld ACKs, in sequence order, one per packet.
        for seq, payload in sorted(arrivals):
            if seq == expected:
                expected = (expected + payload) % 2**32
            send(my_isn + 1, expected, 4)
            time.sleep(0.001)

    sender.kill()
    sender.wait()
    sock.close()

    print('MSS = %d, advertised window held at %d' % (MSS, ADV))
    print()
    print('%-6s %-12s %-8s %-10s %s' % ('round', 'flight', 'packets',
                                        'flight/MSS', 'vs prev'))
    prev = None
    for i, (flight, pkts, retrans) in enumerate(rounds):
        ratio = '%.2f' % (flight / MSS)
        delta = '-' if prev is None else ('%.2fx' % (flight / prev))
        note = '  <-- RETRANSMIT SEEN' if retrans else ''
        aligned = '' if flight % MSS == 0 else '  <-- NOT MSS-ALIGNED'
        print('%-6d %-12d %-8d %-10s %s%s%s'
              % (i, flight, pkts, ratio, delta, note, aligned))
        prev = flight


if __name__ == '__main__':
    main()
