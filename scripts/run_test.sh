#!/bin/sh
# run_test.sh LINES BINARY [ARGS...]: run a test binary, keep its full output in build/logs/, print the last
# LINES lines, and exit with the binary's own status (a pipe into tail would hide it).
n=$1
shift
mkdir -p build/logs
log="build/logs/$(basename "$1")${2:+-$2}.log"
echo "== $* "
"$@" >"$log" 2>&1
rc=$?
tail -n "$n" "$log"
[ $rc -eq 0 ] || echo "FAILED (exit $rc): $*, full output in $log"
exit $rc
