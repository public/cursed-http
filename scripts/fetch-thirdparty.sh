#!/bin/sh
# fetch-thirdparty.sh [name...]: download third-party sources at pinned commits into third_party/ (git-ignored).
# Nothing here is redistributed by this repository; each project keeps its own licence (see THIRD_PARTY.md).
#   uws        uNetworking/uWebSockets v20.80.0     Apache-2.0      comparison benchmark + conformance reference
#   httparse   seanmonstar/httparse v1.10.1         MIT/Apache-2.0  comparison benchmark (needs rustc) + conformance cases
#   hparse     nikneym/hparse                       MIT             comparison benchmark (needs zig 0.15)
#   llhttp-src nodejs/llhttp (sources + tests)      MIT             conformance cases (test/request/*.md)
#   garden     narfindustries/http-garden           GPL-3.0         conformance cases (TROPHIES.md payloads)
#   pico-src   h2o/picohttpparser (with test.c)     MIT/Perl        conformance cases (test.c)
# Default: all of them.
set -e
cd "$(dirname "$0")/.."
mkdir -p third_party
fetch() {   # name owner/repo commit
  [ -f "third_party/$1/.commit" ] && [ "$(cat "third_party/$1/.commit")" = "$3" ] && { echo "$1: have $3"; return; }
  echo "$1: fetching $2 @ $3"
  rm -rf "third_party/$1" "third_party/$1.tmp"; mkdir -p "third_party/$1.tmp"
  curl -fsSL "https://codeload.github.com/$2/tar.gz/$3" | tar -xzf - -C "third_party/$1.tmp" --strip-components=1
  mv "third_party/$1.tmp" "third_party/$1"; echo "$3" > "third_party/$1/.commit"
}
ALL="$*"
for n in uws httparse hparse llhttp-src garden pico-src; do
  if [ -n "$ALL" ] && ! echo " $ALL " | grep -q " $n "; then continue; fi
  case $n in
    uws)        fetch uws uNetworking/uWebSockets 3ffd6f44c9c3c92c96345d9f96bd01ba9c025ab5 ;;
    httparse)   fetch httparse seanmonstar/httparse 9f29e79f9832dbd0ae5220acb17c1866745bdecd ;;
    hparse)     fetch hparse nikneym/hparse 4fb3d836e804eab0469bb128f521ad00b1085731 ;;
    llhttp-src) fetch llhttp-src nodejs/llhttp 69936dbc22922e596a05dfa912fc11d9a7af2136 ;;
    garden)     fetch garden narfindustries/http-garden b417e806c1b15e8ea0b9312f81a91fbdcbc7a83e ;;
    pico-src)   fetch pico-src h2o/picohttpparser 465a7ff09fbd3432fe56c673451f5460154d1f07 ;;
  esac
done
