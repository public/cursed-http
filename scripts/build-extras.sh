#!/bin/sh
# build-extras.sh: the benchmarks and the conformance harness with the fetched third-party parsers
# (run scripts/fetch-thirdparty.sh first; `make compare-all` / `make conformance` do both).
#   build/compare_all       fastparse vs pico, llhttp, uWebSockets, and httparse (if rustc) / hparse (if zig 0.15)
#   build/bench_fbparse_all fbparse   vs pico, llhttp, and httparse / hparse when available
#   build/conf              conformance harness (references: llhttp, pico, uWebSockets)
# Needs cc and c++. CC, CXX, MARCH, EXTRA (e.g. -DFP_USE_AVX512) as usual; NORUST=1 / NOZIG=1 skip those.
set -e
cd "$(dirname "$0")/.."
B=build; T=third_party; mkdir -p $B
[ -f $T/uws/src/HttpParser.h ] || { echo "missing $T/uws: run scripts/fetch-thirdparty.sh" >&2; exit 1; }
CC=${CC:-cc}
if [ -z "$CXX" ]; then case "$CC" in *clang*) CXX=clang++ ;; *gcc*) CXX=g++ ;; *) CXX=c++ ;; esac; fi
case "$(uname -m)" in arm64|aarch64) MARCH=${MARCH:--mcpu=native} ;; *) MARCH=${MARCH:--march=native} ;; esac
F="-O3 $MARCH -Wall -Wno-unused-function -Wno-deprecated-declarations $EXTRA"
INC="-Iinclude -Itests -Ivendor/pico -Ivendor/llhttp/include -I$B"
make -s $B/fastparse_gen.h $B/fastparse_pgo.h >/dev/null
OBJS=""
for f in llhttp api http; do $CC $F -w -Ivendor/llhttp/include -c vendor/llhttp/src/$f.c -o $B/x_llhttp_$f.o; OBJS="$OBJS $B/x_llhttp_$f.o"; done
$CC $F -c vendor/pico/picohttpparser.c -o $B/x_pico.o
$CC $F $INC -c bench/llhttp_shim.c -o $B/x_lx.o
$CXX -std=c++20 -O3 $MARCH -w -I$T/uws/src -Ivendor/pico -c bench/uws_shim.cpp -o $B/x_uw.o
for o in hand:fastparse.h gen:fastparse_gen.h pgo:fastparse_pgo.h; do
  $CC $F $INC "-DOURS_HDR=\"${o#*:}\"" -DOURS=${o%%:*} -c bench/ours.c -o $B/x_ours_${o%%:*}.o; done
OBJS="$OBJS $B/x_pico.o $B/x_lx.o"; DEFS=""; LIBS=""; XOBJ=""
if [ -z "$NORUST" ] && command -v rustc >/dev/null 2>&1 && [ -f $T/httparse/src/lib.rs ]; then
  RCPU="-C target-cpu=native"; RCFG='--cfg feature=\"std\" --cfg httparse_simd --cfg httparse_simd_neon_intrinsics'
  FEATS=$(rustc $RCPU --print cfg | grep target_feature || true)   # as httparse's build.rs: compile-time SIMD
  echo "$FEATS" | grep -q '"avx2"' && RCFG="$RCFG --cfg httparse_simd_target_feature_avx2"
  echo "$FEATS" | grep -q '"sse4.2"' && RCFG="$RCFG --cfg httparse_simd_target_feature_sse42"
  eval rustc --edition 2018 --crate-type rlib --crate-name httparse -C opt-level=3 $RCPU $RCFG $T/httparse/src/lib.rs -o $B/libhttparse.rlib
  rustc --edition 2018 --crate-type staticlib -C opt-level=3 $RCPU -C panic=abort --extern httparse=$B/libhttparse.rlib -L $B bench/httparse_shim.rs -o $B/libhx.a
  DEFS="$DEFS -DHAVE_HTTPARSE"; LIBS="$LIBS $B/libhx.a -lpthread -ldl -lm"; echo "httparse: $(rustc --version)"
else echo "httparse: skipped (no rustc or not fetched)"; fi
if [ -z "$NOZIG" ] && command -v zig >/dev/null 2>&1 && [ -f $T/hparse/src/root.zig ]; then
  zig build-obj -O ReleaseFast -mcpu=native -fPIC --dep hparse -Mroot=bench/hparse_shim.zig -Mhparse=$T/hparse/src/root.zig -femit-bin=$B/x_hparse.o
  DEFS="$DEFS -DHAVE_HPARSE"; XOBJ="$B/x_hparse.o"; echo "hparse: zig $(zig version)"
else echo "hparse: skipped (no zig or not fetched)"; fi
$CC $F $INC $DEFS -DHAVE_UWS -c bench/compare.c -o $B/x_compare.o
$CXX $MARCH $B/x_compare.o $B/x_ours_*.o $B/x_uw.o $OBJS $XOBJ $LIBS -o $B/compare_all
$CC $F $INC $DEFS -c bench/bench_fbparse.c -o $B/x_bench_fb.o
$CXX $MARCH $B/x_bench_fb.o $OBJS $XOBJ $LIBS -o $B/bench_fbparse_all
$CC -O2 -g $MARCH -Wall -Wno-unused-function $EXTRA $INC -c conformance/conf.c -o $B/x_conf.o
$CXX $MARCH $B/x_conf.o $B/x_uw.o $OBJS -o $B/conf
echo "built $B/compare_all $B/bench_fbparse_all $B/conf ($($CC --version | head -1); $MARCH $EXTRA)"
