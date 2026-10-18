"""Diagnostic: what does cwnd do after N duplicate ACKs?

Grows the sender's cwnd with normal ACKs for a few rounds, then stops
advancing the ack number and sends N duplicate ACKs. Reads the sender's own
cwnd log to report cwnd before loss, at fast retransmit, and after inflation.

Usage: python3 tests/dbg_dupresponse.py [N ...]
"""
import csv
import os
import socket
import struct
import subprocess
import sys
import time

H = struct.Struct('!IHHIIHHBHH')
HDR = H.size
MSS = 1400 - HDR
PROBE = '/tmp/cwnd_probe'
ADV = 65535
LOG = '/tmp/dupresp_cwnd.csv'
GROW_ROUNDS = 5


def run(n_dups):
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
    f = H.unpack(syn[:HDR])
    base = (f[3] + 1) % 2**32
    sock.sendto(H.pack(15441, port, 0, my_isn, base, HDR, HDR, 12, ADV, 0),
                peer)
    sock.recvfrom(65535)                      # final handshake ACK

    expected = base
    sock.settimeout(0.35)

    # Grow cwnd with honest per-packet ACKs.
    for _ in range(GROW_ROUNDS):
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
        if not arrivals:
            break
        for seq, payload in sorted(arrivals):
            if seq == expected:
                expected = (expected + payload) % 2**32
            send(expected)
            time.sleep(0.001)

    # Drain whatever is in flight without advancing the ack number.
    while True:
        try:
            sock.recvfrom(65535)
        except socket.timeout:
            break

    # Now the hole: N duplicate ACKs, all carrying the same ack number.
    for _ in range(n_dups):
        send(expected)
        time.sleep(0.004)
    time.sleep(0.4)

    sender.kill()
    sender.wait()
    sock.close()

    rows = []
    with open(LOG) as fh:
        for r in csv.DictReader(fh):
            rows.append({'cwnd': int(r['cwnd']),
                         'ssthresh': int(r['ssthresh']),
                         'stage': r['stage']})

    fr = next((i for i, r in enumerate(rows) if r['stage'] == 'fast_retransmit'),
              None)
    pre = max((r['cwnd'] for r in rows[:fr]), default=0) if fr else \
        max((r['cwnd'] for r in rows), default=0)
    inflations = sum(1 for r in rows if r['stage'] == 'recovery_inflate')
    final = rows[-1]['cwnd'] if rows else 0
    at_fr = rows[fr]['cwnd'] if fr is not None else None
    ssthresh = rows[fr]['ssthresh'] if fr is not None else None
    return pre, at_fr, ssthresh, inflations, final


def main():
    counts = [int(a) for a in sys.argv[1:]] or [3, 6, 10, 20]
    print('%-7s %-12s %-12s %-12s %-11s %-12s %s'
          % ('dups', 'cwnd before', 'ssthresh', 'cwnd at FR', 'inflations',
             'cwnd after', 'verdict'))
    for n in counts:
        pre, at_fr, ssthresh, infl, final = run(n)
        if at_fr is None:
            print('%-7d %-12d %-12s %-12s %-11d %-12d %s'
                  % (n, pre, '-', 'never fired', infl, final,
                     'no loss detected'))
            continue
        verdict = 'DECREASED' if final < pre else 'NOT decreased'
        print('%-7d %-12d %-12d %-12d %-11d %-12d %s'
              % (n, pre, ssthresh, at_fr, infl, final, verdict))


if __name__ == '__main__':
    main()
