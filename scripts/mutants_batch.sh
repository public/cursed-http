#!/bin/sh
# Planted bugs: each modified copy of include/batchparse.h must FAIL tests/test_batch.c (emulated AVX-512 path
# + lane-C), i.e. print a non-zero "TOTAL FAILURES". The header rules themselves live in fastparse.h and are
# covered by its own tests. Backend-specific mutants only bite on their platform.
cd "$(dirname "$0")/.."; S=$(mktemp -d "${TMPDIR:-/tmp}/bp-mutants.XXXXXX"); mkdir -p $S/include
cp include/fastparse.h $S/include/
case "$(uname -m)" in x86_64|amd64) M=-march=haswell;; *) M=-mcpu=native;; esac
F="-O2 -w -DBP_AVX512_EMU ${MARCH:-$M}"
mut() { sed "$1" include/batchparse.h > $S/include/batchparse.h
  if ! grep -q . $S/include/batchparse.h || cmp -s include/batchparse.h $S/include/batchparse.h; then echo "$2: SED DID NOT APPLY"; return; fi
  ${CC:-cc} $F -I$S/include -Itests -Ivendor/pico tests/test_batch.c vendor/pico/picohttpparser.c -o $S/m && $S/m | grep TOTAL | sed "s|^|$2: |"; }
mut 's/Lk \* (27 + n)/Lk * (26 + n)/' "l0 of like off by one (lane-C)"
mut 's/okn = (n >= 1) \& (n <= 7)/okn = (n >= 0) \& (n <= 7)/' "zero-digit ids canonical (lane-C; NOT a bug: same result)"
mut 's/_mm512_set1_epi16(0x010A)/_mm512_set1_epi16(0x0A01)/' "atoi weights swapped (zmm)"
mut 's/_mm512_set1_epi8(10))/_mm512_set1_epi8(11))/' "':' counted as a digit (zmm)"
mut 's/_mm256_set1_epi8(9)), t)/_mm256_set1_epi8(10)), t)/' "':' counted as a digit (avx2, needs x86)"
mut 's/_mm512_mask_cmpeq_epi64_mask(kLk, t2, ZS(BP_TP11))/kLk/' "like tail word 2 unchecked (zmm)"
mut 's/if (FP_LIKELY(h > 0)) { r->body_off = h; r->body_len = 0;/if (FP_LIKELY(h > 0)) { r->body_off = h; r->body_len = 1;/' "GET: wrong body_len on the quick path"
mut 's/int h = fp_quick_get(b, len, FP_BACKEND != 0);/int h = fp_quick_get(b, len + 64, FP_BACKEND != 0);/' "GET: quick path ignores len (reads the continuation)"
mut 's/post = fp_route_lines((int)rt\[i\]);/post = 0;/' "POST lanes through the GET path (Authorization lost)"
rm -rf $S
