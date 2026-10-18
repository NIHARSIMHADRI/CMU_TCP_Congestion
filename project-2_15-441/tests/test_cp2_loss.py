"""CP2 congestion control under deterministic loss.

A UDP relay sits between sender and receiver and drops chosen data packets,
so we can force specific TCP Reno transitions instead of hoping a lossy link
produces them.

Scenario A -- drop one mid-stream data packet once, with plenty of packets
behind it. Should produce three duplicate ACKs -> fast retransmit -> window
inflation -> recovery exit.

Scenario B -- drop the same data packet repeatedly so duplicates can never
resolve it. Should fall through to the retransmission timeout path.

Run: python3 tests/test_cp2_loss.py
"""
import os
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
H = struct.Struct('!IHHIIHHBHH')
HDR = H.size
MSS = 1400 - HDR
PROBE = '/tmp/cwnd_probe'
TRANSFER = 200000


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def run_scenario(name, targets, log_path):
    """Relay sender<->receiver, dropping chosen data packets.

    `targets` maps "Nth distinct data packet" -> how many times to drop it.
    Multiple entries means multiple simultaneous gaps at the receiver.
    """
    recv_port = free_port()
    relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    relay.bind(('127.0.0.1', 0))
    relay.settimeout(0.2)
    relay_port = relay.getsockname()[1]

    receiver = subprocess.Popen(
        [PROBE, 'recv', str(recv_port), str(TRANSFER)],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    time.sleep(0.4)

    env = dict(os.environ, CMU_TCP_CWND_LOG=log_path)
    sender = subprocess.Popen(
        [PROBE, 'send', str(relay_port), str(TRANSFER)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)

    sender_addr = None
    data_seqs = []          # distinct data sequence numbers, in first-seen order
    target_seqs = {}        # seq -> remaining drops allowed
    dropped = 0
    forwarded = 0
    start = time.monotonic()

    while time.monotonic() - start < 60:
        if sender.poll() is not None and receiver.poll() is not None:
            break
        try:
            pkt, addr = relay.recvfrom(65535)
        except socket.timeout:
            continue
        if len(pkt) < HDR:
            continue

        from_receiver = addr[1] == recv_port
        if not from_receiver:
            sender_addr = addr

        fields = H.unpack(pkt[:HDR])
        seq, hlen, plen = fields[3], fields[5], fields[6]
        payload_len = plen - hlen

        # Pick victims: the Nth distinct data packets from the sender.
        if not from_receiver and payload_len > 0:
            if seq not in data_seqs:
                data_seqs.append(seq)
                if len(data_seqs) in targets:
                    target_seqs[seq] = targets[len(data_seqs)]
            if target_seqs.get(seq, 0) > 0:
                target_seqs[seq] -= 1
                dropped += 1
                continue

        if from_receiver:
            if sender_addr is None:
                continue
            dst = sender_addr
        else:
            dst = ('127.0.0.1', recv_port)

        out = bytearray(pkt)
        struct.pack_into('!HH', out, 4, relay_port, dst[1])
        relay.sendto(bytes(out), dst)
        forwarded += 1

    for proc in (sender, receiver):
        if proc.poll() is None:
            proc.kill()
    sender.wait()
    recv_err = receiver.communicate()[1] or ''
    relay.close()

    return {
        'name': name,
        'dropped': dropped,
        'forwarded': forwarded,
        'data_packets': len(data_seqs),
        'target_seq': sorted(target_seqs),
        'receiver': recv_err.strip(),
        'sender_rc': sender.returncode,
    }


def read_log(path):
    if not os.path.exists(path):
        return [], {}
    rows = []
    with open(path) as fh:
        next(fh, None)
        for line in fh:
            parts = line.strip().split(',')
            if len(parts) == 5:
                rows.append({'t': int(parts[0]), 'cwnd': int(parts[1]),
                             'ssthresh': int(parts[2]),
                             'adv': int(parts[3]), 'stage': parts[4]})
    stages = {}
    for r in rows:
        stages[r['stage']] = stages.get(r['stage'], 0) + 1
    return rows, stages


def report(result, rows, stages, expect_stages):
    print('=== %s ===' % result['name'])
    print('  data packets seen: %d, dropped: %d (seq %s)'
          % (result['data_packets'], result['dropped'], result['target_seq']))
    print('  sender exit: %s' % result['sender_rc'])
    print('  receiver: %s' % (result['receiver'] or '(no output)'))
    print('  cwnd samples: %d' % len(rows))
    print('  stages: %s' % stages)
    if rows:
        print('  cwnd  min/max: %d / %d'
              % (min(r['cwnd'] for r in rows), max(r['cwnd'] for r in rows)))
        seen = sorted({r['ssthresh'] for r in rows})
        print('  ssthresh values: %s' % seen)

    failures = []
    if 'CORRECT' not in result['receiver']:
        failures.append('payload not verified correct')
    if result['sender_rc'] != 0:
        failures.append('sender exited %s' % result['sender_rc'])
    for stage in expect_stages:
        if stage not in stages:
            failures.append('stage %r never fired' % stage)

    if failures:
        print('  RESULT: FAIL')
        for f in failures:
            print('    - %s' % f)
    else:
        print('  RESULT: PASS')
    return not failures


def main():
    ok = True

    res = run_scenario('A: single mid-stream drop', {20: 1}, '/tmp/cp2_a.csv')
    rows, stages = read_log('/tmp/cp2_a.csv')
    ok &= report(res, rows, stages,
                 ['fast_retransmit', 'recovery_inflate', 'recovery_exit'])
    print()

    res = run_scenario('B: repeated drop of one packet', {20: 6},
                       '/tmp/cp2_b.csv')
    rows, stages = read_log('/tmp/cp2_b.csv')
    ok &= report(res, rows, stages, ['timeout'])
    print()

    # Adversarial: two holes open at the receiver at the same time. This is
    # the case the single-gap receiver assumption does not cover -- advancing
    # next_seq_expected straight to last_byte_rcvd would hand the application
    # bytes that never arrived, so watch for CORRUPT rather than a hang.
    res = run_scenario('C: two distinct packets dropped in one window',
                       {20: 1, 23: 1}, '/tmp/cp2_c.csv')
    rows, stages = read_log('/tmp/cp2_c.csv')
    ok &= report(res, rows, stages, [])

    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
