#!/bin/bash
# Throwaway harness: run a transfer with cwnd logging enabled.
BYTES=${1:-400000}
PORT=$((20000 + RANDOM % 20000))
rm -f /tmp/cwnd.csv

/tmp/cwnd_probe recv "$PORT" "$BYTES" 2>/tmp/recv.log &
RECV=$!
sleep 0.5
CMU_TCP_CWND_LOG=/tmp/cwnd.csv /tmp/cwnd_probe send "$PORT" "$BYTES" \
    2>/tmp/send.log &
SEND=$!

wait $SEND
wait $RECV

echo "--- receiver ---"
cat /tmp/recv.log
echo "--- cwnd log: $(wc -l < /tmp/cwnd.csv) rows ---"
head -3 /tmp/cwnd.csv
echo "..."
echo "--- stage counts ---"
tail -n +2 /tmp/cwnd.csv | cut -d, -f5 | sort | uniq -c
echo "--- cwnd range (bytes) ---"
tail -n +2 /tmp/cwnd.csv | cut -d, -f2 | sort -n | head -1
tail -n +2 /tmp/cwnd.csv | cut -d, -f2 | sort -n | tail -1
