#!/usr/bin/env bash
# real_clients.sh: the example servers against real clients, over real sockets on loopback.
#   HTTP/2 (examples/h2_server.c, h2c with prior knowledge): curl (libnghttp2), GETs on one
#     connection, a 1 MiB GET, a 300 KB POST.
#   HTTP/3 (examples/h3_server.c, QUIC + TLS 1.3): aioquic's client (tests/h3_client.py), 40 GETs,
#     a 1 MiB GET, a 300 KB POST and a key update.
# A functional test: a handful of requests, not a load test. Needs curl with HTTP/2, openssl, python3
# with venv, and the fetched picotls (scripts/fetch-thirdparty.sh picotls). The throwaway TLS key is
# made under build/ at run time and never committed. Exits non-zero on any failure.
set -euo pipefail
cd "$(dirname "$0")/.."
B=build/h2h3
make -s "$B/h2_server" "$B/h3_server"
fail=0
pass() { echo "ok   $*"; }
bad() {
  echo "FAIL $*"
  fail=1
}

# ---------------------------------------- HTTP/2: curl ----------------------------------------
P2=18443
"$B/h2_server" $P2 2>/dev/null &
s2=$!
trap 'kill $s2 ${s3:-} 2>/dev/null || true' EXIT
sleep 0.3
u="http://127.0.0.1:$P2"
out=$(curl -s --http2-prior-knowledge -w '%{http_version} %{response_code}\n' "$u/a" "$u/b" "$u/c" "$u/d" "$u/e")
want=$(printf 'hello, world\n2 200\n%.0s' 1 2 3 4 5)
[ "$out" = "$want" ] && pass "curl: 5 GETs over HTTP/2 on one connection" || bad "curl GETs: $out"
n=$(curl -s --http2-prior-knowledge "$u/big/1048576" | tr -d '\n' | wc -c)
[ "$n" -eq 1048576 ] && pass "curl: GET /big/1048576 ($n bytes)" || bad "curl big GET: $n bytes"
head -c 300000 /dev/zero | tr '\0' 'u' >"$B/post.bin"
r=$(curl -s --http2-prior-knowledge --data-binary @"$B/post.bin" "$u/upload")
[ "$r" = "300000" ] && pass "curl: POST 300000 bytes" || bad "curl POST: '$r'"
v=$(curl -s --http2-prior-knowledge -o /dev/null -w '%{http_version}' "$u/")
[ "$v" = "2" ] && pass "curl negotiated HTTP/2" || bad "curl used HTTP/$v"

# --------------------------------------- HTTP/3: aioquic ---------------------------------------
P3=18444
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 -subj /CN=localhost \
  -keyout "$B/test_key.pem" -out "$B/test_cert.pem" 2>/dev/null
"$B/h3_server" "$B/test_cert.pem" "$B/test_key.pem" $P3 2>/dev/null &
s3=$!
sleep 0.3
V=$B/venv-aioquic
[ -x "$V/bin/python" ] || { python3 -m venv "$V" && "$V/bin/pip" -q install aioquic==1.6.1; }
if "$V/bin/python" tests/h3_client.py 127.0.0.1 $P3; then pass "aioquic: HTTP/3"; else bad "aioquic: HTTP/3"; fi

[ $fail = 0 ] && echo "real clients: PASS" || echo "real clients: FAILED"
exit $fail
