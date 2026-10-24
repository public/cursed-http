#!/bin/sh
# Planted bugs: each modified copy of include/fbparse.h must FAIL tests/test_fbparse.c (quick mode), i.e. print
# a non-zero "TOTAL FAILURES". Run natively; EMU=1 runs the AVX-512 code path on C intrinsics (for the
# AVX-512-only mutants); MUTASAN=1 builds with ASan (for the out-of-bounds mutant). The "SED SELF-CHECK" line
# must say SED DID NOT APPLY; backend-specific mutants only bite on their platform.
cd "$(dirname "$0")/.."; S=$(mktemp -d "${TMPDIR:-/tmp}/fb-mutants.XXXXXX"); mkdir -p $S/include
cp include/fastparse.h $S/include/
case "$(uname -m)" in x86_64|amd64) M=-march=haswell;; *) M=-mcpu=native;; esac
F="-O2 -w ${MARCH:-$M} ${EMU:+-DFP_AVX512_EMU} ${MUTASAN:+-fsanitize=address}"
mut() { sed "$1" include/fbparse.h > $S/include/fbparse.h
  if cmp -s include/fbparse.h $S/include/fbparse.h; then echo "$2: SED DID NOT APPLY"; return; fi
  rm -f $S/m; ${CC:-cc} $F -I$S/include -Itests -Ivendor/pico tests/test_fbparse.c vendor/pico/picohttpparser.c -o $S/m 2>&1 | head -3
  $S/m quick > $S/out.txt 2>&1; r=$(grep TOTAL $S/out.txt); grep -q "ERROR: AddressSanitizer" $S/out.txt && r="caught by ASan ($(grep -m1 -o 'heap-buffer-overflow\|stack-buffer-overflow' $S/out.txt))"
  echo "$2: ${r:-NO RESULT (build failed?)}"; }
mut 's/0x3e, 0x3e, 0x3d, 0x15, 0x34/0x3e, 0x3e, 0x3d, 0x15, 0x30/' "LUT: pipe not a tchar"
mut 's/#define FB_HI_ROW 0, 0, 0x01/#define FB_HI_ROW 0, 0x01, 0x01/' "LUT: hi nibble 1 = hi nibble 2"
mut 's/      if (p >= len) return p;/      if (p > len + 64) return p;/' "classifies a block past len (ASan build: MUTASAN=1)"
mut 's/c |= fb_swar_mm(fb_swar_le(w, 0x20) | fb_swar_eq/c |= fb_swar_mm(fb_swar_le(w, 0x1f) | fb_swar_eq/' "scalar pe: SP not a path end"
mut 's/vorrq_u8(vcleq_u8(x, vdupq_n_u8(0x20)), vceqq_u8(x, vdupq_n_u8(0x7f)))/vcleq_u8(x, vdupq_n_u8(0x20))/' "neon pe: DEL allowed in the path (arm64 only)"
mut 's/fb_FB_PE64/x/' "SED SELF-CHECK (must say SED DID NOT APPLY)"
mut 's/FB_X64(FB_LE(v, 0x20) | FB_EQ(v, 0x7f))/FB_X64(FB_LE(v, 0x20))/' "avx512 pe: DEL allowed in the path (EMU=1)"
mut 's/return fb_mm2(P(_mm256_loadu_si256((const void \*)p)), P(_mm256_loadu_si256((const void \*)(p + 32))))/return fb_mm2(P(_mm256_loadu_si256((const void *)p)), P(_mm256_loadu_si256((const void *)(p + 31))))/' "avx2: second half loaded 1 byte early (x86 only)"
mut 's/if (FB_LIKELY(ce == l - 1 \&\& b\[l - 1\] == .\\r.)) e = l - 1;/if (b[l - 1] == 0x0d) e = l - 1;/' "walk: control byte inside a line ignored"
mut 's/    if (c < 0) c = p + __builtin_ctzll(ct);//' "walk: long line loses its first ct"
mut 's/else if (ce == l \&\& b\[l - 1\] != .\\r.) e = l;/else if (ce == l) e = l - 1;/' "walk: bare LF taken for CR LF"
mut 's/if ((w \& 0xff) != .:. || ne == p) return -1;/if ((w >> 8) != 0x3a \&\& (w \& 0xff) != 0x3a) return -1;/' "walk: colon checked at the wrong byte"
mut 's/    if (FB_LIKELY(!ct)) continue;/    if (FB_LIKELY(!ct)) { ++k; continue; }/' "walk: skips two blocks per empty one"
mut 's/if (len - e < 9) return -2;/if (len - e < 8) return -2;/' "version: 8-byte minimum"
mut 's/(unsigned)(b\[e + 7\] - .0.) > 9/(unsigned)(b[e + 7] - 0x30) > 10/' "version: ':' as a digit"
mut 's/if (b\[e\] != .:. || e == p) return -1;/if (b[e] != 0x3a) return -1;/' "empty header name allowed"
mut 's/if (FB_UNLIKELY(n != 0 \&\& (c ==/if (FB_UNLIKELY((c ==/' "obs-fold allowed on the first header"
mut 's/if (ml == 0) return -1;//' "empty method allowed"
mut 's/if (n == max) return -1;/if (n > max) return -1;/' "one header over capacity"
mut 's/while (vs < len \&\& (b\[vs\] == . . || b\[vs\] == .\\t.)) vs++;/while (vs < len \&\& b[vs] == 0x20) vs++;/' "value: leading HT kept"
mut 's/while (FB_UNLIKELY(ve > vs \&\& (b\[ve - 1\] == . . || b\[ve - 1\] == .\\t.))) ve--;/while (FB_UNLIKELY(ve > vs \&\& b[ve - 1] == 0x20)) ve--;/' "value: trailing HT kept"
mut 's/else if (b\[0\] == .\\n.) p = 1;//' "leading bare LF not skipped"
mut 's/(vl > 1 \&\& v\[0\] == .0.)/(vl > 2 \&\& v[0] == 0x30)/' "adapter: CL 0N accepted"
mut 's/if (!a->have_auth \&\& fb_name_is/if (fb_name_is/' "adapter: last Authorization wins"
mut 's/else if (nl >= 16 \&\& fb_name_is/else if (nl >= 17 \&\& fb_name_is/' "adapter: 16-char transfer-encodin* missed"
mut 's/if (cnt == 2) return 0;/if (cnt == 3) return 0;/' "is_complete: three line ends"
mut 's/_mm256_cmpeq_epi8(_mm256_max_epu8(v, _mm256_set1_epi8(c)), _mm256_set1_epi8(c))/_mm256_cmpeq_epi8(_mm256_max_epu8(v, _mm256_set1_epi8(c)), v)/' "avx2: <= inverted (x86 only)"
mut 's/FB_X64((FB_LE(v, 0x1f) \& ~FB_EQ(v, .\\t.))/FB_X64((FB_LE(v, 0x1f))/' "avx512: HT counted as ctl (EMU=1)"
mut 's/vbicq_u8(vcleq_u8(x, vdupq_n_u8(0x1f)), vceqq_u8(x, vdupq_n_u8(.\\t.)))/vcleq_u8(x, vdupq_n_u8(0x1f))/' "neon: HT counted as ctl (arm64 only)"
mut 's/return vminvq_s8(vminq_s8(m0, m1)) < 0x21;/return vminvq_s8(vminq_s8(m0, m1)) < 0x20;/' "skip windows: 0x1f not seen (neon, arm64 only)"
mut 's/__m256i hit = _mm256_cmpgt_epi8(_mm256_set1_epi8(0x21)/__m256i hit = _mm256_cmpgt_epi8(_mm256_set1_epi8(0x20)/' "skip windows: 0x1f not seen (x86 only)"
mut 's/        a += 64 \* nb; if (nb < 8) nb \*= 2;/        a += 64 * nb + 64; if (nb < 8) nb *= 2;/' "skip windows: 64 unchecked bytes after each window"
mut 's/      for (; a < end; a += 64) {/      for (a += 64; a < end; a += 64) {/' "long-line exit: first window line not scanned"
mut 's/ne = FB_LIKELY(ntm) ? p + __builtin_ctz(ntm) :/ne = FB_LIKELY(ntm) ? p + __builtin_ctz(ntm \& (ntm - 1)) :/' "name scan (x86): second non-token byte taken as the name end (x86 only)"
mut 's/ne = FB_LIKELY(ntm) ? p + (__builtin_ctzll(ntm) >> 2) :/ne = FB_LIKELY(ntm) ? p + (__builtin_ctzll(ntm) >> 3) :/' "name scan (neon): nibble index halved (arm64 only)"
rm -rf $S
