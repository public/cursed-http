#!/bin/sh
# fetch-thirdparty.sh [name...]: download third-party sources at pinned commits into third_party/ (git-ignored).
# Nothing here is redistributed by this repository; each project keeps its own licence (see THIRD_PARTY.md).
#   uws        uNetworking/uWebSockets v20.80.0     Apache-2.0      comparison benchmark + conformance reference
#   httparse   seanmonstar/httparse v1.10.1         MIT/Apache-2.0  comparison benchmark (needs rustc) + conformance cases
#   hparse     nikneym/hparse                       MIT             comparison benchmark (needs zig 0.15)
#   llhttp-src nodejs/llhttp (sources + tests)      MIT             conformance cases (test/request/*.md)
#   garden     narfindustries/http-garden           GPL-3.0         conformance cases (TROPHIES.md payloads)
#   pico-src   h2o/picohttpparser (with test.c)     MIT/Perl        conformance cases (test.c)
#   lightning  softwaredc/lightning                 Apache-2.0      comparison benchmark (AVX2/SSE4.2 C parser)
#   pico-a64   volyrique/picohttpparser armv8-a     MIT/Perl        comparison benchmark (pico with Armv8-A NEON optimisations)
#   pico-a64tbl volyrique/picohttpparser armv8-a+tbl MIT/Perl       comparison benchmark (the same, TBL-based parse_token)
#   http-parser nodejs/http-parser v2.9.4+         MIT             comparison benchmark (Node.js's parser before llhttp)
# Default: all of them.
set -e
cd "$(dirname "$0")/.."
mkdir -p third_party
fetch() { # name owner/repo commit
  [ -f "third_party/$1/.commit" ] && [ "$(cat "third_party/$1/.commit")" = "$3" ] && {
    echo "$1: have $3"
    return
  }
  echo "$1: fetching $2 @ $3"
  rm -rf "third_party/$1" "third_party/$1.tmp"
  mkdir -p "third_party/$1.tmp"
  curl -fsSL "https://codeload.github.com/$2/tar.gz/$3" | tar -xzf - -C "third_party/$1.tmp" --strip-components=1
  mv "third_party/$1.tmp" "third_party/$1"
  echo "$3" >"third_party/$1/.commit"
}
ALL="$*"
for n in uws httparse hparse llhttp-src garden pico-src lightning pico-a64 pico-a64tbl http-parser; do
  if [ -n "$ALL" ] && ! echo " $ALL " | grep -q " $n "; then continue; fi
  case $n in
    uws) fetch uws uNetworking/uWebSockets 3ffd6f44c9c3c92c96345d9f96bd01ba9c025ab5 ;;
    httparse) fetch httparse seanmonstar/httparse 9f29e79f9832dbd0ae5220acb17c1866745bdecd ;;
    hparse) fetch hparse nikneym/hparse 4fb3d836e804eab0469bb128f521ad00b1085731 ;;
    llhttp-src) fetch llhttp-src nodejs/llhttp 69936dbc22922e596a05dfa912fc11d9a7af2136 ;;
    garden) fetch garden narfindustries/http-garden b417e806c1b15e8ea0b9312f81a91fbdcbc7a83e ;;
    pico-src) fetch pico-src h2o/picohttpparser 465a7ff09fbd3432fe56c673451f5460154d1f07 ;;
    lightning) fetch lightning softwaredc/lightning 7b3b0cb1cb59a1740b2a26e1bb3997d316c4f95a ;;
    pico-a64) fetch pico-a64 volyrique/picohttpparser a47c4d00644f084d5170acdffa73642e81b2f908 ;;
    pico-a64tbl) fetch pico-a64tbl volyrique/picohttpparser b93abc18204cf273829a01197167952c43b5cd6b ;;
    http-parser) fetch http-parser nodejs/http-parser ec8b5ee63f0e51191ea43bb0c6eac7bfbff3141d ;;
  esac
done
