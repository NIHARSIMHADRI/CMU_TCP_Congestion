"""Diagnostic: does the sender return to slow start after a timeout?

Grows cwnd with honest ACKs, then goes completely silent long enough to force
a retransmission timeout, then resumes ACKing and reports the flight sizes
afterwards. A sender that returned to slow start should restart around
WINDOW_INITIAL_WINDOW_SIZE and double from there.
"""
import csv
import os
import socket
import struct
import subprocess
import time

H = struct.Struct('!IHHIIHHBHH')
HDR = H.size
MSS = 1400 - HDR
PROBE = '/tmp/cwnd_probe'
ADV = 65535
LOG = '/tmp/timeout_cwnd.csv'
GROW_ROUNDS = 5
SILENCE = 4.5          # must exceed DEFAULT_TIMEOUT (3000 ms)


def main():
    if os.path.exists(LOG):
        os.remove(LOG)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as res:
        res.bind(('127.0.0.1', 0))
        port = res.getsockname()[1]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', port))

    env = dict(os.environ, CMU_TCP_CWND_LOG=LOG)
    sender = subprocess.Popen([PROBE, 'send', str(port), '400000'],
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, env=env)
    my_isn = 7000

    def send(ack):
        sock.sendto(H.pack(15441, port, 0, my_isn + 1, ack % 2**32, HDR, HDR,
                            4, ADV, 0), peer)

    sock.settimeout(5)
    syn, peer = sock.recvfrom(65535)
    base = (H.unpack(syn[:HDR])[3] + 1) % 2**32
    sock.sendto(H.pack(15441, port, 0, my_isn, base, HDR, HDR, 12, ADV, 0),
                peer)
    sock.recvfrom(65535)

    expected = base
    sock.settimeout(0.35)

    def collect():
        arrivals = []
        while True:
            try:
                pkt, _ = sock.recvfrom(65535)
            except socket.timeout:
                break
            g = H.unpack(pkt[:HDR])
            payload = g[6] - g[5]
            if payload > 0:
                arrivals.append((g[3], payload))
        return arrivals

    def release(arrivals):
        nonlocal expected
        for seq, payload in sorted(arrivals):
            if seq == expected:
                expected = (expected + payload) % 2**32
            send(expected)
            time.sleep(0.001)

    print('--- growing cwnd ---')
    for i in range(GROW_ROUNDS):
        arrivals = collect()
        if not arrivals:
            break
        print('  round %d: flight %d bytes (%d pkts)'
              % (i, sum(p for _, p in arrivals), len(arrivals)))
        release(arrivals)

    print('--- going silent for %.1fs to force a timeout ---' % SILENCE)
    t0 = time.monotonic()
    silent_pkts = 0
    while time.monotonic() - t0 < SILENCE:
        try:
            sock.recvfrom(65535)
            silent_pkts += 1
        except socket.timeout:
            pass
    print('  sender transmitted %d packets during the silence' % silent_pkts)

    print('--- resuming ACKs ---')
    for i in range(6):
        arrivals = collect()
        if not arrivals:
            print('  round %d: nothing sent' % i)
            continue
        flight = sum(p for _, p in arrivals)
        print('  round %d: flight %d bytes (%.2f MSS, %d pkts)'
              % (i, flight, flight / MSS, len(arrivals)))
        release(arrivals)

    sender.kill()
    sender.wait()
    sock.close()

    rows = list(csv.DictReader(open(LOG)))
    print('--- cwnd log around the timeout ---')
    idx = next((i for i, r in enumerate(rows) if r['stage'] == 'timeout'), None)
    if idx is None:
        print('  NO timeout event was logged')
    else:
        for r in rows[max(0, idx - 2):idx + 6]:
            print('  cwnd=%-8s ssthresh=%-8s stage=%s'
                  % (r['cwnd'], r['ssthresh'], r['stage']))


if __name__ == '__main__':
    main()
