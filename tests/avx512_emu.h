// TEST ONLY: plain-C stand-ins for the AVX-512BW/VL intrinsics fastparse.h's AVX-512 path uses, so that
// path's own logic (lane order, mask widths, combining) runs on any machine with -DFP_AVX512_EMU.
// This checks our code, not the CPU: it assumes the real intrinsics do what Intel documents.
#pragma once
#include <stdint.h>
#include <string.h>
typedef struct {
  uint8_t b[32];
} __m256i;
typedef struct {
  uint8_t b[64];
} __m512i;
typedef uint32_t __mmask32;
typedef uint64_t __mmask64;
static inline __m256i _mm256_set1_epi8(char c) {
  __m256i r;
  memset(r.b, (uint8_t)c, 32);
  return r;
}
static inline __m512i _mm512_set1_epi8(char c) {
  __m512i r;
  memset(r.b, (uint8_t)c, 64);
  return r;
}
static inline __m256i _mm256_loadu_si256(const void *p) {
  __m256i r;
  memcpy(r.b, p, 32);
  return r;
}
static inline __m512i _mm512_loadu_si512(const void *p) {
  __m512i r;
  memcpy(r.b, p, 64);
  return r;
}
static inline __m256i _mm256_or_si256(__m256i a, __m256i b) {
  for (int i = 0; i < 32; i++) a.b[i] |= b.b[i];
  return a;
}
static inline __m512i _mm512_or_si512(__m512i a, __m512i b) {
  for (int i = 0; i < 64; i++) a.b[i] |= b.b[i];
  return a;
}
static inline __mmask32 _mm256_cmpeq_epi8_mask(__m256i a, __m256i b) {
  __mmask32 m = 0;
  for (int i = 0; i < 32; i++) m |= (__mmask32)(a.b[i] == b.b[i]) << i;
  return m;
}
static inline __mmask64 _mm512_cmpeq_epi8_mask(__m512i a, __m512i b) {
  __mmask64 m = 0;
  for (int i = 0; i < 64; i++) m |= (__mmask64)(a.b[i] == b.b[i]) << i;
  return m;
}
static inline __mmask32 _mm256_cmple_epu8_mask(__m256i a, __m256i b) {
  __mmask32 m = 0;
  for (int i = 0; i < 32; i++) m |= (__mmask32)(a.b[i] <= b.b[i]) << i;
  return m;
}
static inline __mmask64 _mm512_cmple_epu8_mask(__m512i a, __m512i b) {
  __mmask64 m = 0;
  for (int i = 0; i < 64; i++) m |= (__mmask64)(a.b[i] <= b.b[i]) << i;
  return m;
}
// plain AVX2 vector ops (the bare-CR accumulator uses them on every x86 backend)
static inline __m256i _mm256_setzero_si256(void) {
  __m256i r;
  memset(r.b, 0, 32);
  return r;
}
static inline __m256i _mm256_cmpeq_epi8(__m256i a, __m256i b) {
  for (int i = 0; i < 32; i++) a.b[i] = a.b[i] == b.b[i] ? 0xFF : 0;
  return a;
}
static inline __m256i _mm256_cmpgt_epi8(__m256i a, __m256i b) {
  for (int i = 0; i < 32; i++) a.b[i] = (int8_t)a.b[i] > (int8_t)b.b[i] ? 0xFF : 0;
  return a;
}
static inline __m256i _mm256_and_si256(__m256i a, __m256i b) {
  for (int i = 0; i < 32; i++) a.b[i] &= b.b[i];
  return a;
}
static inline __m256i _mm256_andnot_si256(__m256i a, __m256i b) {
  for (int i = 0; i < 32; i++) a.b[i] = (uint8_t)(~a.b[i] & b.b[i]);
  return a;
}
static inline int _mm256_testz_si256(__m256i a, __m256i b) {
  for (int i = 0; i < 32; i++)
    if (a.b[i] & b.b[i]) return 0;
  return 1;
}
