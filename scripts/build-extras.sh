#!/bin/sh
# build-extras.sh: the benchmarks and the conformance harness with the fetched third-party parsers
# (run scripts/fetch-thirdparty.sh first; `make compare-all` / `make conformance` do both).
#   build/compare_all       fastparse vs pico, llhttp, uWebSockets, and httparse (if rustc) / hparse (if zig 0.15)
#   build/bench_fbparse_all fbparse   vs pico, llhttp, and httparse / hparse when available
#   build/conf              conformance harness (references: llhttp, pico, uWebSockets)
# Needs cc and c++. CC, CXX, MARCH, EXTRA (e.g. -DFP_USE_AVX512) as usual; NORUST=1 / NOZIG=1 skip those.
set -e
cd "$(dirname "$0")/.."
B=build
T=third_party
mkdir -p $B
[ -f $T/uws/src/HttpParser.h ] || {
  echo "missing $T/uws: run scripts/fetch-thirdparty.sh" >&2
  exit 1
}
CC=${CC:-cc}
if [ -z "$CXX" ]; then case "$CC" in *clang*) CXX=clang++ ;; *gcc*) CXX=g++ ;; *) CXX=c++ ;; esac fi
case "$(uname -m)" in arm64 | aarch64) MARCH=${MARCH:--mcpu=native} ;; *) MARCH=${MARCH:--march=native} ;; esac
F="-O3 $MARCH -Wall -Wno-unused-function -Wno-deprecated-declarations $EXTRA"
INC="-Iinclude -Itests -Ivendor/pico -Ivendor/llhttp/include -I$B"
make -s $B/fastparse_gen.h $B/fastparse_pgo.h >/dev/null
OBJS=""
for f in llhttp api http; do
  $CC $F -w -Ivendor/llhttp/include -c vendor/llhttp/src/$f.c -o $B/x_llhttp_$f.o
  OBJS="$OBJS $B/x_llhttp_$f.o"
done
$CC $F -c vendor/pico/picohttpparser.c -o $B/x_pico.o
$CC $F $INC -c bench/llhttp_shim.c -o $B/x_lx.o
# uWS's own build.c: -march=native -O3 -std=c++2b (its -flto changes nothing here: the parser is header-only, one TU)
$CXX -std=c++2b -O3 $MARCH -w -I$T/uws/src -Ivendor/pico -c bench/uws_shim.cpp -o $B/x_uw.o
for o in hand:fastparse.h gen:fastparse_gen.h pgo:fastparse_pgo.h; do
  $CC $F $INC "-DOURS_HDR=\"${o#*:}\"" -DOURS=${o%%:*} -c bench/ours.c -o $B/x_ours_${o%%:*}.o
done
$CC $F $INC '-DOURS_HDR="fastparse.h"' -DOURS=hnc -DFP_TM_NOCOST -c bench/ours.c -o $B/x_ours_hnc.o # templates, no cost model
OBJS="$OBJS $B/x_pico.o $B/x_lx.o"
DEFS=""
LIBS=""
XOBJ=""
if [ -z "$NORUST" ] && command -v rustc >/dev/null 2>&1 && [ -f $T/httparse/src/lib.rs ]; then
  RCPU="-C target-cpu=native"
  RCFG='--cfg feature=\"std\" --cfg httparse_simd --cfg httparse_simd_neon_intrinsics'
  FEATS=$(rustc $RCPU --print cfg | grep target_feature || true) # as httparse's build.rs: compile-time SIMD
  echo "$FEATS" | grep -q '"avx2"' && RCFG="$RCFG --cfg httparse_simd_target_feature_avx2"
  echo "$FEATS" | grep -q '"sse4.2"' && RCFG="$RCFG --cfg httparse_simd_target_feature_sse42"
  # as httparse's own bench profile (Cargo.toml [profile.bench]): opt-level 3, codegen-units 1, LTO
  RFL="-C opt-level=3 -C codegen-units=1 $RCPU"
  eval rustc --edition 2018 --crate-type rlib --crate-name httparse $RFL $RCFG $T/httparse/src/lib.rs -o $B/libhttparse.rlib
  rustc --edition 2018 --crate-type staticlib $RFL -C lto=fat -C panic=abort --extern httparse=$B/libhttparse.rlib -L $B bench/httparse_shim.rs -o $B/libhx.a
  DEFS="$DEFS -DHAVE_HTTPARSE"
  LIBS="$LIBS $B/libhx.a -lpthread -ldl -lm"
  echo "httparse: $(rustc --version)"
else echo "httparse: skipped (no rustc or not fetched)"; fi
if [ -z "$NOZIG" ] && command -v zig >/dev/null 2>&1 && [ -f $T/hparse/src/root.zig ]; then
  zig build-obj -O ReleaseFast -mcpu=native # as hparse's bench: zig build -Doptimize=ReleaseFast (-Dcpu=...) -fPIC --dep hparse -Mroot=bench/hparse_shim.zig -Mhparse=$T/hparse/src/root.zig -femit-bin=$B/x_hparse.o
  DEFS="$DEFS -DHAVE_HPARSE"
  XOBJ="$B/x_hparse.o"
  echo "hparse: zig $(zig version)"
else echo "hparse: skipped (no zig or not fetched)"; fi
for n in lightning http-parser pico-a64 pico-a64tbl; do
  [ -d $T/$n ] || {
    echo "$n: skipped (not fetched)"
    continue
  }
  case $n in
    lightning) # its CMake Release build: -O3 -DNDEBUG + -mavx2 (x86); -march=native covers that
      for f in lightning url chunked; do $CC $F -DNDEBUG -w -I$T/lightning/include -I$T/lightning/src -c $T/lightning/src/$f.c -o $B/x_lt_$f.o; done
      $CC $F -I$T/lightning/include -Ivendor/pico -c bench/lightning_shim.c -o $B/x_lt_shim.o
      OBJS="$OBJS $B/x_lt_lightning.o $B/x_lt_url.o $B/x_lt_chunked.o $B/x_lt_shim.o"
      DEFS="$DEFS -DHAVE_LIGHTNING"
      ;;
    http-parser)
      $CC $F -w -I$T/http-parser -c $T/http-parser/http_parser.c -o $B/x_hpn.o
      $CC $F -I$T/http-parser -Ivendor/pico -c bench/http_parser_shim.c -o $B/x_hpn_shim.o
      OBJS="$OBJS $B/x_hpn.o $B/x_hpn_shim.o"
      DEFS="$DEFS -DHAVE_HTTP_PARSER"
      ;;
    pico-a64 | pico-a64tbl) # Armv8-A forks of picohttpparser: only meaningful (and only built) on aarch64
      case "$(uname -m)" in arm64 | aarch64) ;; *) continue ;; esac
      P=pa64
      M=PICO_A64
      [ $n = pico-a64tbl ] && P=pt64 M=PICO_A64TBL
      R=""
      for s in phr_parse_request phr_parse_response phr_parse_headers phr_decode_chunked phr_decode_chunked_is_in_data; do R="$R -D$s=${P}_$s"; done
      $CC $F -w $R -c $T/$n/picohttpparser.c -o $B/x_$P.o
      OBJS="$OBJS $B/x_$P.o"
      DEFS="$DEFS -DHAVE_$M"
      ;;
  esac
  echo "$n: built"
done
$CC $F $INC $DEFS -DHAVE_UWS -c bench/compare.c -o $B/x_compare.o
$CXX $MARCH $B/x_compare.o $B/x_ours_*.o $B/x_uw.o $OBJS $XOBJ $LIBS -o $B/compare_all
$CC $F $INC $DEFS -c bench/bench_fbparse.c -o $B/x_bench_fb.o
$CXX $MARCH $B/x_bench_fb.o $OBJS $XOBJ $LIBS -o $B/bench_fbparse_all
$CC -O2 -g $MARCH -Wall -Wno-unused-function $EXTRA $INC -c conformance/conf.c -o $B/x_conf.o
$CXX $MARCH $B/x_conf.o $B/x_uw.o $OBJS -o $B/conf
echo "built $B/compare_all $B/bench_fbparse_all $B/conf ($($CC --version | head -1); $MARCH $EXTRA)"
