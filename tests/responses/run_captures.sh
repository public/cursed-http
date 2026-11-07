#!/bin/sh
# Capture the response corpus (tests/responses/README.md): each server in turn, in the foreground, on 127.0.0.1,
# with capture.py against it; everything the server started is stopped before the next one.
#   SRV=~/opt/httpsrv/root tests/responses/run_captures.sh OUTDIR [server...]
# SRV: a directory holding the servers' files (usr/sbin/nginx, usr/sbin/apache2, usr/bin/caddy, usr/bin/h2o,
# usr/sbin/haproxy, usr/lib/go-1.22), e.g. Ubuntu 24.04's packages unpacked with dpkg -x. node and python3 from PATH.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=$(mkdir -p "$1" && cd "$1" && pwd)
shift
SRV=${SRV:?set SRV}
export LD_LIBRARY_PATH="$SRV/usr/lib/x86_64-linux-gnu"
PORT=18080
ORIGIN=18090
run=$(mktemp -d)
docs="$run/docs"
mkdir -p "$docs/sub"
python3 -c "
import sys
open('$docs/small.txt', 'w').write('small static file\n' * 5)
open('$docs/sub/index.html', 'w').write('<p>sub</p>\n')
open('$docs/big.html', 'w').write(''.join('<p>line %d of a static page, compressible text</p>\n' % i for i in range(1500)))
"
sub() { sed -e "s|@PORT@|$PORT|g" -e "s|@ORIGIN@|$ORIGIN|g" -e "s|@DOCROOT@|$docs|g" -e "s|@RUN@|$run|g" \
  -e "s|@MODS@|$SRV/usr/lib/apache2/modules|g" -e "s|@ETC@|$SRV/etc/nginx|g" "$here/servers/$1" > "$run/$1"; }
pids=""
start() { "$@" > "$run/log" 2>&1 & pids="$pids $!"; }
stop() { for p in $pids; do kill "$p" 2>/dev/null || true; done; sleep 0.3; for p in $pids; do kill -9 "$p" 2>/dev/null || true; done; pids=""; }
trap stop EXIT
origin() { start python3 "$here/servers/origin.py" $ORIGIN "$docs"; }
cap() { python3 "$here/capture.py" "$1" $PORT "$out"; stop; }
for s in ${*:-python node go nginx apache caddy h2o haproxy}; do
  case $s in
  python) start python3 "$here/servers/origin.py" $PORT "$docs"; cap python-http.server ;;
  node) start node "$here/servers/origin.js" $PORT "$docs"; cap node-http ;;
  go)
    GOROOT="$SRV/usr/lib/go-1.22" GOCACHE="$run/gocache" GOFLAGS=-p=1 "$SRV/usr/lib/go-1.22/bin/go" build -o "$run/origin-go" "$here/servers/origin.go"
    start "$run/origin-go" $PORT "$docs"; cap go-net-http ;;
  nginx)
    origin; mkdir -p "$run/nginx/logs"; sub nginx.conf; cp "$SRV/etc/nginx/mime.types" "$run/"
    start "$SRV/usr/sbin/nginx" -p "$run/nginx" -c "$run/nginx.conf" -g "daemon off; pid $run/nginx.pid; error_log stderr;"
    cap nginx ;;
  apache) origin; sub httpd.conf; start "$SRV/usr/sbin/apache2" -d "$run" -f "$run/httpd.conf" -DFOREGROUND; cap apache-httpd ;;
  caddy) origin; sub Caddyfile; HOME="$run" XDG_DATA_HOME="$run" start "$SRV/usr/bin/caddy" run --config "$run/Caddyfile" --adapter caddyfile; cap caddy ;;
  h2o) origin; sub h2o.conf; start "$SRV/usr/bin/h2o" -c "$run/h2o.conf"; cap h2o ;;
  haproxy) origin; sub haproxy.cfg; start "$SRV/usr/sbin/haproxy" -db -f "$run/haproxy.cfg"; cap haproxy ;;
  esac
done
rm -rf "$run"
