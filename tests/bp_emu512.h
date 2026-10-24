// TEST ONLY: plain-C stand-ins for the AVX-512F/BW/CD intrinsics bp_rl_z() uses, so that code path's
// own logic (lane order, mask chaining, masked gathers, digit count, atoi) runs on any machine with
// -DBP_AVX512_EMU. It checks our code, not the CPU: it assumes the real intrinsics do what Intel
// documents. The real names are #defined onto bpz_* so this works even after <immintrin.h>.
#pragma once
#include <stdint.h>
#include <string.h>
typedef union { uint64_t q[8]; int64_t s[8]; uint32_t d[16]; int32_t sd[16]; uint16_t w[32]; int16_t sw[32]; uint8_t b[64]; int8_t sb[64]; } bpz_v;
typedef uint8_t bpz_m8;
typedef uint64_t bpz_m64;
#define __m512i bpz_v
#define __mmask8 bpz_m8
#define __mmask64 bpz_m64
#define BPZ static inline
#define BPZ_Q(expr) bpz_v r; for (int i = 0; i < 8; i++) r.q[i] = (expr); return r
BPZ bpz_v bpz_loadu(const void *p) { bpz_v r; memcpy(&r, p, 64); return r; }
BPZ void bpz_storeu(void *p, bpz_v a) { memcpy(p, &a, 64); }
BPZ bpz_v bpz_zero(void) { bpz_v r; memset(&r, 0, 64); return r; }
BPZ bpz_v bpz_set1_64(long long x) { BPZ_Q((uint64_t)x); }
BPZ bpz_v bpz_set1_32(int x) { bpz_v r; for (int i = 0; i < 16; i++) r.d[i] = (uint32_t)x; return r; }
BPZ bpz_v bpz_set1_16(short x) { bpz_v r; for (int i = 0; i < 32; i++) r.w[i] = (uint16_t)x; return r; }
BPZ bpz_v bpz_set1_8(char x) { bpz_v r; memset(r.b, (uint8_t)x, 64); return r; }
BPZ bpz_v bpz_add64(bpz_v a, bpz_v b) { BPZ_Q(a.q[i] + b.q[i]); }
BPZ bpz_v bpz_sub64(bpz_v a, bpz_v b) { BPZ_Q(a.q[i] - b.q[i]); }
BPZ bpz_v bpz_and(bpz_v a, bpz_v b) { BPZ_Q(a.q[i] & b.q[i]); }
BPZ bpz_v bpz_or(bpz_v a, bpz_v b) { BPZ_Q(a.q[i] | b.q[i]); }
BPZ bpz_v bpz_srli64(bpz_v a, unsigned c) { BPZ_Q(c > 63 ? 0 : a.q[i] >> c); }
BPZ bpz_v bpz_slli64(bpz_v a, unsigned c) { BPZ_Q(c > 63 ? 0 : a.q[i] << c); }
BPZ bpz_v bpz_srai64(bpz_v a, unsigned c) { BPZ_Q((uint64_t)(a.s[i] >> (c > 63 ? 63 : c))); }
BPZ bpz_v bpz_sllv64(bpz_v a, bpz_v c) { BPZ_Q(c.q[i] > 63 ? 0 : a.q[i] << c.q[i]); }
BPZ bpz_v bpz_lzcnt64(bpz_v a) { BPZ_Q(a.q[i] ? (uint64_t)__builtin_clzll(a.q[i]) : 64); }
BPZ bpz_v bpz_mul_epu32(bpz_v a, bpz_v b) { BPZ_Q((a.q[i] & 0xFFFFFFFFu) * (b.q[i] & 0xFFFFFFFFu)); }
BPZ bpz_v bpz_sub8(bpz_v a, bpz_v b) { for (int i = 0; i < 64; i++) a.b[i] = (uint8_t)(a.b[i] - b.b[i]); return a; }
BPZ bpz_v bpz_maddubs(bpz_v a, bpz_v b) {   // u8 x s8 pairs -> saturated s16
  bpz_v r; for (int i = 0; i < 32; i++) { int x = a.b[2 * i] * b.sb[2 * i] + a.b[2 * i + 1] * b.sb[2 * i + 1];
    r.sw[i] = (int16_t)(x > 32767 ? 32767 : x < -32768 ? -32768 : x); } return r; }
BPZ bpz_v bpz_madd16(bpz_v a, bpz_v b) {
  bpz_v r; for (int i = 0; i < 16; i++) r.sd[i] = a.sw[2 * i] * b.sw[2 * i] + a.sw[2 * i + 1] * b.sw[2 * i + 1]; return r; }
BPZ bpz_m8 bpz_cmpeq64(bpz_v a, bpz_v b) { bpz_m8 m = 0; for (int i = 0; i < 8; i++) m |= (bpz_m8)((a.q[i] == b.q[i]) << i); return m; }
BPZ bpz_m8 bpz_mcmpeq64(bpz_m8 k, bpz_v a, bpz_v b) { return k & bpz_cmpeq64(a, b); }
BPZ bpz_m8 bpz_mcmpgt64(bpz_m8 k, bpz_v a, bpz_v b) { bpz_m8 m = 0; for (int i = 0; i < 8; i++) m |= (bpz_m8)((a.s[i] > b.s[i]) << i); return k & m; }
BPZ bpz_m64 bpz_cmplt_epu8(bpz_v a, bpz_v b) { bpz_m64 m = 0; for (int i = 0; i < 64; i++) m |= (bpz_m64)(a.b[i] < b.b[i]) << i; return m; }
BPZ bpz_v bpz_movm8(bpz_m64 k) { bpz_v r; for (int i = 0; i < 64; i++) r.b[i] = (k >> i & 1) ? 0xFF : 0; return r; }
BPZ bpz_v bpz_blend64(bpz_m8 k, bpz_v a, bpz_v b) { BPZ_Q((k >> i & 1) ? b.q[i] : a.q[i]); }
BPZ bpz_v bpz_maskz_mov64(bpz_m8 k, bpz_v a) { BPZ_Q((k >> i & 1) ? a.q[i] : 0); }
BPZ bpz_v bpz_mask_mov64(bpz_v s, bpz_m8 k, bpz_v a) { BPZ_Q((k >> i & 1) ? a.q[i] : s.q[i]); }
BPZ bpz_v bpz_mask_add64(bpz_v s, bpz_m8 k, bpz_v a, bpz_v b) { BPZ_Q((k >> i & 1) ? a.q[i] + b.q[i] : s.q[i]); }
BPZ bpz_v bpz_gather(bpz_v idx, const void *base, int scale) {
  BPZ_Q(({ uint64_t x; memcpy(&x, (const void *)((uintptr_t)base + idx.q[i] * (uint64_t)scale), 8); x; })); }
BPZ bpz_v bpz_mgather(bpz_v src, bpz_m8 k, bpz_v idx, const void *base, int scale) {
  BPZ_Q((k >> i & 1) ? ({ uint64_t x; memcpy(&x, (const void *)((uintptr_t)base + idx.q[i] * (uint64_t)scale), 8); x; }) : src.q[i]); }
#define _mm512_loadu_si512 bpz_loadu
#define _mm512_storeu_si512 bpz_storeu
#define _mm512_setzero_si512 bpz_zero
#define _mm512_set1_epi64 bpz_set1_64
#define _mm512_set1_epi32 bpz_set1_32
#define _mm512_set1_epi16 bpz_set1_16
#define _mm512_set1_epi8 bpz_set1_8
#define _mm512_add_epi64 bpz_add64
#define _mm512_sub_epi64 bpz_sub64
#define _mm512_and_si512 bpz_and
#define _mm512_or_si512 bpz_or
#define _mm512_srli_epi64 bpz_srli64
#define _mm512_slli_epi64 bpz_slli64
#define _mm512_srai_epi64 bpz_srai64
#define _mm512_sllv_epi64 bpz_sllv64
#define _mm512_lzcnt_epi64 bpz_lzcnt64
#define _mm512_mul_epu32 bpz_mul_epu32
#define _mm512_sub_epi8 bpz_sub8
#define _mm512_maddubs_epi16 bpz_maddubs
#define _mm512_madd_epi16 bpz_madd16
#define _mm512_cmpeq_epi64_mask bpz_cmpeq64
#define _mm512_mask_cmpeq_epi64_mask bpz_mcmpeq64
#define _mm512_mask_cmpgt_epi64_mask bpz_mcmpgt64
#define _mm512_cmplt_epu8_mask bpz_cmplt_epu8
#define _mm512_movm_epi8 bpz_movm8
#define _mm512_mask_blend_epi64 bpz_blend64
#define _mm512_maskz_mov_epi64 bpz_maskz_mov64
#define _mm512_mask_mov_epi64 bpz_mask_mov64
#define _mm512_mask_add_epi64 bpz_mask_add64
#define _mm512_i64gather_epi64 bpz_gather
#define _mm512_mask_i64gather_epi64 bpz_mgather
