#!/usr/bin/env bash
# Random request generator for the service. Ctrl+C to stop.

set -u

URL="http://127.0.0.1:8091/healthz"
MIN_MS=100
MAX_MS=1000

running=true
trap 'running=false; echo; echo "Stopping."' INT TERM

echo "Sending requests to: ${URL} (Ctrl+C to stop)"
echo "Random sleep between ${MIN_MS}-${MAX_MS} ms"

while $running; do
  # random jitter
  rand_ms=$(( MIN_MS + (RANDOM % (MAX_MS - MIN_MS + 1)) ))
  sleep_secs=$(printf "%d.%03d" "$((rand_ms/1000))" "$((rand_ms%1000))")

  # unique query to avoid any cache
  r=$RANDOM$RANDOM
  out=$(curl -s -o /dev/null -w "%{http_code} %{time_total}" "${URL}?r=${r}") || out="000 0"
  code=${out%% *}
  t=${out#* }
  printf '[%s] %s %ss\n' "$(date +%T)" "$code" "$t"

  sleep "$sleep_secs"
done
