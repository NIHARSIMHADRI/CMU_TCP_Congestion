#!/bin/bash
# Throwaway harness: run a transfer with cwnd logging enabled.
# Results are written to /tmp/cwnd_result.txt so they survive `vagrant ssh -c`.
BYTES=${1:-400000}
PORT=$((20000 + RANDOM % 20000))
OUT=/tmp/cwnd_result.txt

rm -f /tmp/cwnd.csv /tmp/recv.log "$OUT"

/tmp/cwnd_probe recv "$PORT" "$BYTES" >/dev/null 2>/tmp/recv.log &
RECV=$!
sleep 0.5

START=$(date +%s)
CMU_TCP_CWND_LOG=/tmp/cwnd.csv timeout 120 /tmp/cwnd_probe send "$PORT" "$BYTES" \
    >/dev/null 2>&1
SEND_RC=$?
END=$(date +%s)

sleep 1
kill -9 $RECV 2>/dev/null

{
  echo "bytes=$BYTES  sender_exit=$SEND_RC  elapsed=$((END-START))s"
  echo "--- receiver ---"
  cat /tmp/recv.log 2>/dev/null
  if [ -f /tmp/cwnd.csv ]; then
    echo "--- cwnd log: $(($(wc -l < /tmp/cwnd.csv) - 1)) samples ---"
    echo "--- stage counts ---"
    tail -n +2 /tmp/cwnd.csv | cut -d, -f5 | sort | uniq -c
    echo "--- cwnd min / max (bytes) ---"
    tail -n +2 /tmp/cwnd.csv | cut -d, -f2 | sort -n | head -1
    tail -n +2 /tmp/cwnd.csv | cut -d, -f2 | sort -n | tail -1
    echo "--- ssthresh values seen ---"
    tail -n +2 /tmp/cwnd.csv | cut -d, -f3 | sort -n | uniq -c
  else
    echo "no cwnd log produced"
  fi
} > "$OUT" 2>&1
