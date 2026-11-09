#!/usr/bin/env bash
# real_browsers.sh: cursed-http's HTTP/1.1 parsers against the requests real browsers send (make real-browsers).
#   1. Playwright (pinned, tests/browser/requirements.txt) drives headless Chromium, Firefox and WebKit through
#      tests/browser/page.html, served by build/browser_server on loopback: cookies (one 1.2 KB), JSON / urlencoded /
#      multipart / binary bodies, PUT PATCH DELETE OPTIONS HEAD and an extension method, a 6 KB header, a 7 KB URL,
#      40 and 60 custom headers, tabs and Latin-1 bytes in values, XHR, sendBeacon, keepalive, Range, a WebSocket
#      upgrade, 20 parallel fetches, a form navigation. Each request is checked as it arrives (tests/browser/check.h:
#      fbparse against pico on every prefix, the req_t adapters against testlib's reference).
#   2. The requests saved by that run are replayed under every backend (build/browser_replay_*).
# Env: BROWSERS (default "chromium firefox webkit"), PW_WITH_DEPS=1 (also apt-install the browsers' system libraries:
# CI), BROWSER_SAVE=1 (copy the captures to tests/browser/captures/, the corpus make browser-replay runs).
# Exits non-zero on any mismatch, any failed page step, or a browser that never finishes the page.
set -euo pipefail
cd "$(dirname "$0")/.."
B=build
V=$B/venv-playwright
REQ=tests/browser/requirements.txt
if [ ! -f "$V/.done" ] || ! cmp -s "$REQ" "$V/.done"; then
  python3 -m venv "$V"
  "$V/bin/pip" -q install -r "$REQ"
  cp "$REQ" "$V/.done"
fi
read -ra BR <<<"${BROWSERS:-chromium firefox webkit}"
if [ "${PW_WITH_DEPS:-}" = 1 ]; then "$V/bin/playwright" install --with-deps "${BR[@]}"; else "$V/bin/playwright" install "${BR[@]}"; fi
CAP=$B/browser-captures
rm -rf "$CAP"
mkdir -p "$CAP"
fail=0
BC_VERBOSE=1 "$V/bin/python" tests/browser/drive.py "$B/browser_server" "$CAP" "${BR[@]}" || fail=1
files=$(find "$CAP" -name '*.http' | sort)
[ -n "$files" ] || {
  echo "no requests captured"
  exit 1
}
for t in "$B"/browser_replay_*; do
  # shellcheck disable=SC2086
  "$t" $files || fail=1
done
if [ "${BROWSER_SAVE:-}" = 1 ]; then
  rm -rf tests/browser/captures
  for d in "$CAP"/*/; do
    n=$(basename "$d")
    mkdir -p "tests/browser/captures/$n"
    cp "$d"*.http "tests/browser/captures/$n/"
  done
  echo "saved $(echo "$files" | wc -l) requests to tests/browser/captures/"
fi
[ $fail = 0 ] && echo "real browsers: PASS" || echo "real browsers: FAILED"
exit $fail
