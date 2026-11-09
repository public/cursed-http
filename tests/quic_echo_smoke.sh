#!/usr/bin/env bash
# examples/quic_echo over real UDP on 127.0.0.1: its server, its client, a few stream counts and sizes.
# Usage: tests/quic_echo_smoke.sh build/h2h3/quic_echo
set -euo pipefail
bin=$1
t=$(mktemp -d)
trap 'kill "${srv:-}" 2>/dev/null || true; rm -rf "$t"' EXIT
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$t/k.pem" -out "$t/c.pem" \
  -days 1 -subj /CN=localhost 2>/dev/null
port=$((40000 + RANDOM % 20000))
"$bin" server "$t/c.pem" "$t/k.pem" "$port" 2>"$t/srv.log" &
srv=$!
sleep 0.3
for args in "-n 1 -b 1" "-n 4 -b 100000" "-n 32 -b 1000000"; do
  # shellcheck disable=SC2086
  timeout 30 "$bin" client 127.0.0.1 "$port" -k $args
done
echo "quic_echo smoke: PASS"
