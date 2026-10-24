// TEST ONLY: plain-C stand-ins for the AVX-512BW/VL (+ AVX2) intrinsics fbparse.h's AVX-512 path uses, so that
// path's own logic (lane order, mask widths, combining) runs on any machine with -DFP_AVX512_EMU. Self-contained:
// own vector types and fbemu_-prefixed names (fbparse.h's FB_I() maps to them), so it can't clash with
// tests/avx512_emu.h, which fastparse.h includes in the same build.
// It checks our code, not the CPU: it assumes the real intrinsics do what Intel documents.
#pragma once
#include <stdint.h>
#include <string.h>
typedef struct { uint8_t b[32]; } fbemu256;
typedef struct { uint8_t b[64]; } fbemu512;
#define FBEMU_OPS(W, T, M)                                                                                              \
  static inline T fbemu_mm##W##_set1_epi8(char c) { T r; memset(r.b, (uint8_t)c, sizeof r.b); return r; }          \
  static inline T fbemu_mm##W##_load(const void *p) { T r; memcpy(r.b, p, sizeof r.b); return r; }                 \
  static inline T fbemu_mm##W##_and(T a, T b) { for (unsigned i = 0; i < sizeof a.b; i++) a.b[i] &= b.b[i]; return a; } \
  /* vpshufb: per 128-bit lane, r[i] = x[i] & 0x80 ? 0 : t[lane + (x[i] & 15)] */                                   \
  static inline T fbemu_mm##W##_shuffle_epi8(T t, T x) {                                                           \
    T r; for (unsigned i = 0; i < sizeof r.b; i++) r.b[i] = x.b[i] & 0x80 ? 0 : t.b[(i & ~15u) + (x.b[i] & 15)]; return r; } \
  /* vpsrlw: 16-bit little-endian lanes shifted right */                                                            \
  static inline T fbemu_mm##W##_srli_epi16(T a, int n) {                                                            \
    for (unsigned i = 0; i < sizeof a.b; i += 2) { uint16_t w = (uint16_t)(a.b[i] | a.b[i + 1] << 8); w = (uint16_t)(w >> n); \
      a.b[i] = (uint8_t)w; a.b[i + 1] = (uint8_t)(w >> 8); } return a; }                                            \
  static inline M fbemu_mm##W##_cmpeq_epi8_mask(T a, T b) { M m = 0; for (unsigned i = 0; i < sizeof a.b; i++) m |= (M)(a.b[i] == b.b[i]) << i; return m; } \
  static inline M fbemu_mm##W##_cmple_epu8_mask(T a, T b) { M m = 0; for (unsigned i = 0; i < sizeof a.b; i++) m |= (M)(a.b[i] <= b.b[i]) << i; return m; } \
  /* vptestnmb: bit i = (a[i] & b[i]) == 0 */                                                                       \
  static inline M fbemu_mm##W##_testn_epi8_mask(T a, T b) { M m = 0; for (unsigned i = 0; i < sizeof a.b; i++) m |= (M)((a.b[i] & b.b[i]) == 0) << i; return m; }
FBEMU_OPS(256, fbemu256, uint32_t)
FBEMU_OPS(512, fbemu512, uint64_t)
#undef FBEMU_OPS
