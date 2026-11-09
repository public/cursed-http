#!/bin/bash
# Our HTTP/2 and HTTP/3 clients (examples/h2_client.c, examples/h3_client.c) against real servers, each on
# 127.0.0.1 in turn: small and 1 MiB files, 300 multiplexed requests (past the servers' stream limits), HEAD,
# 404, a 100 kB POST echoed back, 204, and a response with trailers. Prints one line per case and server, and
# exits nonzero if any case failed.
#   SRV=~/opt/httpsrv/root tests/servers/run.sh [server...]
# servers: nginx apache h2o haproxy caddy node (h2c, prior knowledge), caddy-h3 aioquic (HTTP/3).
# SRV: a directory holding the servers' files (usr/sbin/nginx, usr/sbin/apache2, usr/bin/caddy, usr/bin/h2o,
# usr/sbin/haproxy), e.g. Ubuntu 24.04's packages unpacked with dpkg -x; node and openssl from PATH; aioquic
# from AIOQUIC_PY (a python3 that can import aioquic). Build first: make build/h2h3/h2_client build/h2h3/h3_client
set -u
here=$(cd "$(dirname "$0")" && pwd)
B=$(cd "$here/../.." && pwd)/build/h2h3
SRV=${SRV:?set SRV}
export LD_LIBRARY_PATH="$SRV/usr/lib/x86_64-linux-gnu"
PORT=${PORT:-18601} ORIGIN=$((PORT + 1)) PORT3=$((PORT + 2))
run=$(mktemp -d)
docs="$run/docs"
mkdir -p "$docs" "$run/nginx/logs"
python3 -c "
import os
open('$docs/small.txt', 'w').write('small static file\n' * 5)
open('$docs/big.bin', 'wb').write(os.urandom(1 << 20))
"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$run/key.pem" -out "$run/cert.pem" \
  -days 2 -subj /CN=127.0.0.1 -addext subjectAltName=IP:127.0.0.1 2>/dev/null
sub() { sed -e "s|@PORT@|$PORT|g" -e "s|@PORT3@|$PORT3|g" -e "s|@ORIGIN@|$ORIGIN|g" -e "s|@DOCROOT@|$docs|g" \
  -e "s|@RUN@|$run|g" -e "s|@MODS@|$SRV/usr/lib/apache2/modules|g" "$here/$1" >"$run/$1"; }
pids=""
start() {
  "$@" >>"$run/log" 2>&1 &
  pids="$pids $!"
}
stop() {
  for p in $pids; do kill "$p" 2>/dev/null; done
  sleep 0.3
  for p in $pids; do kill -9 "$p" 2>/dev/null; done
  pids=""
}
trap 'stop; rm -rf "$run"' EXIT
fails=0
# one case: name, wanted "status" or "status bytes" on every line, then the client command
check() {
  local name=$1 want=$2
  shift 2
  local out rc bad n tr
  out=$(timeout 60 "$@" 2>"$run/err")
  rc=$?
  n=$(printf '%s\n' "$out" | grep -c .)
  bad=$(printf '%s\n' "$out" | awk -v w="$want" 'NF { g = (w ~ / /) ? $1 " " $2 : $1; if (g != w || $4 != "") b++ } END { print b + 0 }')
  tr=$(printf '%s\n' "$out" | awk '{ if ($3 > m) m = $3 } END { print m + 0 }')
  if [ $rc -eq 0 ] && [ "$bad" -eq 0 ] && [ "$n" -gt 0 ]; then
    printf '  %-9s ok    %4d responses%s\n' "$name" "$n" "$([ "$name" = trailers ] && echo ", $tr trailer fields")"
  else
    fails=$((fails + 1))
    printf '  %-9s FAIL  rc %d, %d of %d responses wrong (want "%s"): %s %s\n' "$name" $rc "$bad" "$n" "$want" \
      "$(printf '%s\n' "$out" | sort | uniq -c | head -3 | tr -s ' \n' ' ')" "$(head -c 200 "$run/err")"
  fi
}
cases() { # $@: the client and its address
  check small "200 90" "$@" /small.txt
  check head "200 0" "$@" -H /small.txt
  check 404 404 "$@" /missing
  check many "200 90" "$@" -n 300 /small.txt
  check big "200 1048576" "$@" -n 8 /big.bin
  check post "200 100000" "$@" -b 100000 /echo
  check 204 "204 0" "$@" /204
  check trailers "200 19" "$@" /trailers
}
wait_port() { # $1: tcp or udp
  for _ in $(seq 50); do
    if [ "$1" = udp ]; then ss -lun | grep -q "127.0.0.1:$PORT3 " && return; else
      ss -ltn | grep -q "127.0.0.1:$PORT " && return
    fi
    sleep 0.1
  done
  echo "  (the server did not start: $(tail -c 300 "$run/log"))"
}
h2() {
  echo "$1 (h2c)"
  wait_port tcp
  cases "$B/h2_client" 127.0.0.1 $PORT
}
h3() {
  echo "$1 (h3)"
  wait_port udp
  sleep 0.3
  cases "$B/h3_client" 127.0.0.1 $PORT3 -k
}
origin() { start python3 "$here/origin.py" $ORIGIN "$docs"; }
[ $# -gt 0 ] || set -- nginx apache h2o haproxy caddy node caddy-h3 aioquic
for s in "$@"; do
  : >"$run/log"
  case $s in
    nginx)
      origin
      sub nginx.conf
      start "$SRV/usr/sbin/nginx" -p "$run/nginx" -c "$run/nginx.conf" -g "daemon off; pid $run/nginx.pid; error_log stderr;"
      h2 "nginx $("$SRV/usr/sbin/nginx" -v 2>&1 | sed 's|.*/||')"
      ;;
    apache)
      origin
      sub httpd.conf
      start "$SRV/usr/sbin/apache2" -d "$run" -f "$run/httpd.conf" -DFOREGROUND
      h2 "Apache httpd $("$SRV/usr/sbin/apache2" -v | sed -n 's|.*Apache/\([^ ]*\).*|\1|p')"
      ;;
    h2o)
      origin
      sub h2o.conf
      start "$SRV/usr/bin/h2o" -c "$run/h2o.conf"
      h2 "h2o $("$SRV/usr/bin/h2o" --version | sed -n 's/h2o version //p')"
      ;;
    haproxy)
      origin
      sub haproxy.cfg
      start "$SRV/usr/sbin/haproxy" -db -f "$run/haproxy.cfg"
      h2 "HAProxy $("$SRV/usr/sbin/haproxy" -v | sed -n 's/HAProxy version \([^ ]*\).*/\1/p')"
      ;;
    caddy | caddy-h3)
      origin
      sub Caddyfile
      HOME="$run" XDG_DATA_HOME="$run" XDG_CONFIG_HOME="$run" start "$SRV/usr/bin/caddy" run --config "$run/Caddyfile" --adapter caddyfile
      v=$("$SRV/usr/bin/caddy" version | cut -d' ' -f1)
      if [ $s = caddy ]; then h2 "Caddy $v"; else h3 "Caddy $v (quic-go)"; fi
      ;;
    node)
      start node "$here/node.js" $PORT "$docs"
      h2 "Node $(node --version) http2"
      ;;
    aioquic)
      py=${AIOQUIC_PY:-python3}
      start "$py" "$here/aioquic_h3.py" $PORT3 "$docs" "$run/cert.pem" "$run/key.pem"
      h3 "aioquic $("$py" -c 'import aioquic; print(aioquic.__version__)')"
      ;;
  esac
  stop
done
[ $fails -eq 0 ] && echo "all cases passed" || echo "$fails cases failed"
exit $((fails != 0))
