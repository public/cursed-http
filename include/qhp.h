/* qhp.h: QUIC header protection masks in batches (RFC 9001 §5.4). From cursed-http explore/simd-h2-h3.
 *
 * The receive path has to remove header protection before it can decrypt (the packet number
 * feeds the AEAD nonce), so it cannot be folded into that packet's AEAD the way picotls fusion
 * folds it on the send path. It can be batched across the packets of one recvmmsg/GRO batch:
 * every mask is one independent AES block (or one ChaCha20 block), so 8 of them pipeline.
 *
 *   qhp_aes_init(&k, key, 16 | 32)                 AES-128 / AES-256 header-protection key
 *   qhp_aes_masks(&k, samples, masks, n)           masks[i*16 .. +16) = AES-ECB(k, samples[i])
 *   qhp_aes_masks_keys(keys, samples, masks, n)    same with a key per packet (several connections)
 *   qhp_chacha_masks(key32, samples, masks, n)     masks[i*16 .. +5)  = ChaCha20(key, ctr = LE32(
 *                                                  sample[0..4)), nonce = sample[4..16)) ^ 0 (5 B)
 *   qhp_apply(pkt, pn_off, mask)                   unmask first byte and the packet number in place;
 *                                                  returns the packet number length
 *
 * samples[i] points at the 16-byte sample of packet i (inside the packet). Backends: AES-NI
 * (-maes), ARMv8 AES (+crypto), and a portable table AES; ChaCha20 8-wide AVX2, 4-wide NEON,
 * else scalar. This is crypto code: it is tested against FIPS-197, RFC 9001 Appendix A and
 * RFC 8439 vectors and differentially against OpenSSL (tests/test_qhp.c).
 */
#ifndef QHP_H
#define QHP_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(__AES__) && defined(__SSE2__) && !defined(QHP_FORCE_SCALAR)
#define QHP_AESNI 1
#include <immintrin.h>
#elif defined(__ARM_FEATURE_CRYPTO) || defined(__ARM_FEATURE_AES)
#if !defined(QHP_FORCE_SCALAR)
#define QHP_ARMAES 1
#include <arm_neon.h>
#endif
#endif
#if defined(__AVX2__) && !defined(QHP_FORCE_SCALAR)
#define QHP_CHACHA_AVX2 1
#include <immintrin.h>
#elif (defined(__ARM_NEON) || defined(__aarch64__)) && !defined(QHP_FORCE_SCALAR)
#define QHP_CHACHA_NEON 1
#include <arm_neon.h>
#endif

#if defined(__clang__)
#define QHP_UNROLL _Pragma("clang loop unroll(full)")
#else
#define QHP_UNROLL _Pragma("GCC unroll 8")
#endif

typedef struct {
  int nr; /* 10 or 14 */
  uint8_t rk[15][16] __attribute__((aligned(16)));
} qhp_aes_key;

static const uint8_t qhp_sbox[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};

/* FIPS-197 §5.2 key expansion (once per key, not hot). */
static inline void qhp_aes_init(qhp_aes_key *k, const uint8_t *key, int keylen) {
  int nk = keylen / 4, nr = nk + 6, total = 4 * (nr + 1);
  uint8_t w[60][4];
  uint8_t rcon = 1;
  memcpy(w, key, (size_t)keylen);
  for (int i = nk; i < total; i++) {
    uint8_t t[4];
    memcpy(t, w[i - 1], 4);
    if (i % nk == 0) {
      uint8_t t0 = t[0];
      t[0] = qhp_sbox[t[1]] ^ rcon, t[1] = qhp_sbox[t[2]], t[2] = qhp_sbox[t[3]], t[3] = qhp_sbox[t0];
      rcon = (uint8_t)(rcon << 1 ^ (rcon & 0x80 ? 0x1b : 0));
    } else if (nk > 6 && i % nk == 4) {
      for (int j = 0; j < 4; j++) t[j] = qhp_sbox[t[j]];
    }
    for (int j = 0; j < 4; j++) w[i][j] = w[i - nk][j] ^ t[j];
  }
  k->nr = nr;
  memcpy(k->rk, w, (size_t)total * 4);
}

/* portable single-block AES (reference and fallback; byte-oriented, not constant time) */
static inline uint8_t qhp__xt(uint8_t x) { return (uint8_t)(x << 1 ^ (x & 0x80 ? 0x1b : 0)); }
static inline void qhp_aes_block_ref(const qhp_aes_key *k, const uint8_t in[16], uint8_t out[16]) {
  uint8_t s[16], t[16];
  for (int i = 0; i < 16; i++) s[i] = in[i] ^ k->rk[0][i];
  for (int r = 1; r <= k->nr; r++) {
    for (int c = 0; c < 4; c++) /* SubBytes + ShiftRows */
      for (int row = 0; row < 4; row++) t[4 * c + row] = qhp_sbox[s[4 * ((c + row) & 3) + row]];
    if (r != k->nr)
      for (int c = 0; c < 4; c++) { /* MixColumns */
        uint8_t *a = t + 4 * c, a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], x = a0 ^ a1 ^ a2 ^ a3;
        a[0] ^= x ^ qhp__xt(a0 ^ a1), a[1] ^= x ^ qhp__xt(a1 ^ a2);
        a[2] ^= x ^ qhp__xt(a2 ^ a3), a[3] ^= x ^ qhp__xt(a3 ^ a0);
      }
    for (int i = 0; i < 16; i++) s[i] = t[i] ^ k->rk[r][i];
  }
  memcpy(out, s, 16);
}

static inline void qhp_aes_masks(const qhp_aes_key *k, const uint8_t *const *samples, uint8_t *masks, size_t n) {
  size_t i = 0;
#if QHP_AESNI
  __m128i rk[15];
  for (int r = 0; r <= k->nr; r++) rk[r] = _mm_load_si128((const __m128i *)k->rk[r]);
  for (; i + 8 <= n; i += 8) {
    __m128i b[8];
    for (int j = 0; j < 8; j++) b[j] = _mm_xor_si128(_mm_loadu_si128((const __m128i *)samples[i + j]), rk[0]);
    for (int r = 1; r < k->nr; r++)
      QHP_UNROLL for (int j = 0; j < 8; j++) b[j] = _mm_aesenc_si128(b[j], rk[r]);
    for (int j = 0; j < 8; j++) _mm_storeu_si128((__m128i *)(masks + 16 * (i + j)), _mm_aesenclast_si128(b[j], rk[k->nr]));
  }
  for (; i < n; i++) {
    __m128i b = _mm_xor_si128(_mm_loadu_si128((const __m128i *)samples[i]), rk[0]);
    for (int r = 1; r < k->nr; r++) b = _mm_aesenc_si128(b, rk[r]);
    _mm_storeu_si128((__m128i *)(masks + 16 * i), _mm_aesenclast_si128(b, rk[k->nr]));
  }
#elif QHP_ARMAES
  uint8x16_t rk[15];
  for (int r = 0; r <= k->nr; r++) rk[r] = vld1q_u8(k->rk[r]);
  for (; i + 8 <= n; i += 8) {
    uint8x16_t b[8];
    for (int j = 0; j < 8; j++) b[j] = vld1q_u8(samples[i + j]);
    for (int r = 0; r < k->nr - 1; r++)
      QHP_UNROLL for (int j = 0; j < 8; j++) b[j] = vaesmcq_u8(vaeseq_u8(b[j], rk[r]));
    for (int j = 0; j < 8; j++) vst1q_u8(masks + 16 * (i + j), veorq_u8(vaeseq_u8(b[j], rk[k->nr - 1]), rk[k->nr]));
  }
  for (; i < n; i++) {
    uint8x16_t b = vld1q_u8(samples[i]);
    for (int r = 0; r < k->nr - 1; r++) b = vaesmcq_u8(vaeseq_u8(b, rk[r]));
    vst1q_u8(masks + 16 * i, veorq_u8(vaeseq_u8(b, rk[k->nr - 1]), rk[k->nr]));
  }
#else
  for (; i < n; i++) qhp_aes_block_ref(k, samples[i], masks + 16 * i);
#endif
}

/* Cross-connection batch: packet i uses keys[i] (packets of one recvmmsg/GRO burst belong to
 * different connections). Same 8-wide pipeline, each lane with its own key schedule; the round
 * keys come from memory operands, so no extra register pressure. All keys must have the same nr
 * (AES-128 and AES-256 suites go in separate batches). */
static inline void qhp_aes_masks_keys(const qhp_aes_key *const *keys, const uint8_t *const *samples, uint8_t *masks, size_t n) {
  size_t i = 0;
#if QHP_AESNI
  for (; i + 8 <= n; i += 8) {
    const qhp_aes_key *k[8];
    __m128i b[8];
    for (int j = 0; j < 8; j++)
      k[j] = keys[i + j], b[j] = _mm_xor_si128(_mm_loadu_si128((const __m128i *)samples[i + j]), _mm_load_si128((const __m128i *)k[j]->rk[0]));
    int nr = k[0]->nr;
    for (int r = 1; r < nr; r++)
      QHP_UNROLL for (int j = 0; j < 8; j++) b[j] = _mm_aesenc_si128(b[j], _mm_load_si128((const __m128i *)k[j]->rk[r]));
    for (int j = 0; j < 8; j++)
      _mm_storeu_si128((__m128i *)(masks + 16 * (i + j)), _mm_aesenclast_si128(b[j], _mm_load_si128((const __m128i *)k[j]->rk[nr])));
  }
#elif QHP_ARMAES
  for (; i + 8 <= n; i += 8) {
    const qhp_aes_key *k[8];
    uint8x16_t b[8];
    for (int j = 0; j < 8; j++) k[j] = keys[i + j], b[j] = vld1q_u8(samples[i + j]);
    int nr = k[0]->nr;
    for (int r = 0; r < nr - 1; r++)
      QHP_UNROLL for (int j = 0; j < 8; j++) b[j] = vaesmcq_u8(vaeseq_u8(b[j], vld1q_u8(k[j]->rk[r])));
    for (int j = 0; j < 8; j++)
      vst1q_u8(masks + 16 * (i + j), veorq_u8(vaeseq_u8(b[j], vld1q_u8(k[j]->rk[nr - 1])), vld1q_u8(k[j]->rk[nr])));
  }
#endif
  for (; i < n; i++) qhp_aes_masks(keys[i], samples + i, masks + 16 * i, 1);
}

/* ------------------------------------------ ChaCha20 ------------------------------------------ */
static inline uint32_t qhp__le32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
#define QHP_ROTL(x, n) ((x) << (n) | (x) >> (32 - (n)))
#define QHP_QR(a, b, c, d) \
  a += b, d ^= a, d = QHP_ROTL(d, 16), c += d, b ^= c, b = QHP_ROTL(b, 12), \
  a += b, d ^= a, d = QHP_ROTL(d, 8), c += d, b ^= c, b = QHP_ROTL(b, 7)

/* RFC 8439 §2.3 block function; writes the first 8 keystream bytes (the mask uses 5) */
static inline void qhp_chacha_block_ref(const uint8_t key[32], const uint8_t sample[16], uint8_t out[8]) {
  uint32_t in[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
  for (int i = 0; i < 8; i++) in[4 + i] = qhp__le32(key + 4 * i);
  for (int i = 0; i < 4; i++) in[12 + i] = qhp__le32(sample + 4 * i);
  uint32_t x[16];
  memcpy(x, in, sizeof x);
  for (int r = 0; r < 10; r++) {
    QHP_QR(x[0], x[4], x[8], x[12]); QHP_QR(x[1], x[5], x[9], x[13]);
    QHP_QR(x[2], x[6], x[10], x[14]); QHP_QR(x[3], x[7], x[11], x[15]);
    QHP_QR(x[0], x[5], x[10], x[15]); QHP_QR(x[1], x[6], x[11], x[12]);
    QHP_QR(x[2], x[7], x[8], x[13]); QHP_QR(x[3], x[4], x[9], x[14]);
  }
  for (int w = 0; w < 2; w++) {
    uint32_t v = x[w] + in[w];
    for (int j = 0; j < 4; j++) out[4 * w + j] = (uint8_t)(v >> 8 * j);
  }
}

#if QHP_CHACHA_AVX2
#define QHP_VW 8
typedef __m256i qhp_cv;
#define QV_ADD _mm256_add_epi32
#define QV_XOR _mm256_xor_si256
#define QV_SET1(x) _mm256_set1_epi32((int)(x))
static inline __m256i qhp__rot(__m256i x, int n) {
  if (n == 16)
    return _mm256_shuffle_epi8(x, _mm256_set_epi8(13,12,15,14,9,8,11,10,5,4,7,6,1,0,3,2,13,12,15,14,9,8,11,10,5,4,7,6,1,0,3,2));
  if (n == 8)
    return _mm256_shuffle_epi8(x, _mm256_set_epi8(14,13,12,15,10,9,8,11,6,5,4,7,2,1,0,3,14,13,12,15,10,9,8,11,6,5,4,7,2,1,0,3));
  return _mm256_or_si256(_mm256_slli_epi32(x, n), _mm256_srli_epi32(x, 32 - n));
}
#elif QHP_CHACHA_NEON
#define QHP_VW 4
typedef uint32x4_t qhp_cv;
#define QV_ADD vaddq_u32
#define QV_XOR veorq_u32
#define QV_SET1(x) vdupq_n_u32(x)
static inline uint32x4_t qhp__rot(uint32x4_t x, int n) {
  if (n == 16) return vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(x)));
  if (n == 8) {
    static const uint8_t r8[16] = {3,0,1,2,7,4,5,6,11,8,9,10,15,12,13,14};
    return vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(x), vld1q_u8(r8)));
  }
  if (n == 12) return vsriq_n_u32(vshlq_n_u32(x, 12), x, 20);
  return vsriq_n_u32(vshlq_n_u32(x, 7), x, 25);
}
#endif

#ifdef QHP_VW
#define QHP_VQR(a, b, c, d) \
  a = QV_ADD(a, b), d = qhp__rot(QV_XOR(d, a), 16), c = QV_ADD(c, d), b = qhp__rot(QV_XOR(b, c), 12), \
  a = QV_ADD(a, b), d = qhp__rot(QV_XOR(d, a), 8), c = QV_ADD(c, d), b = qhp__rot(QV_XOR(b, c), 7)
/* QHP_VW independent blocks, one per lane: state word i of every block lives in x[i] */
static inline void qhp__chacha_vec(const uint8_t key[32], const uint8_t *const *s, uint8_t *masks) {
  uint32_t lanes[4][QHP_VW] __attribute__((aligned(32)));
  for (int j = 0; j < QHP_VW; j++)
    for (int w = 0; w < 4; w++) lanes[w][j] = qhp__le32(s[j] + 4 * w);
  qhp_cv x[16], in0, in1;
  x[0] = QV_SET1(0x61707865), x[1] = QV_SET1(0x3320646e), x[2] = QV_SET1(0x79622d32), x[3] = QV_SET1(0x6b206574);
  for (int i = 0; i < 8; i++) x[4 + i] = QV_SET1(qhp__le32(key + 4 * i));
  for (int w = 0; w < 4; w++) memcpy(&x[12 + w], lanes[w], sizeof(qhp_cv));
  in0 = x[0], in1 = x[1];
  for (int r = 0; r < 10; r++) {
    QHP_VQR(x[0], x[4], x[8], x[12]); QHP_VQR(x[1], x[5], x[9], x[13]);
    QHP_VQR(x[2], x[6], x[10], x[14]); QHP_VQR(x[3], x[7], x[11], x[15]);
    QHP_VQR(x[0], x[5], x[10], x[15]); QHP_VQR(x[1], x[6], x[11], x[12]);
    QHP_VQR(x[2], x[7], x[8], x[13]); QHP_VQR(x[3], x[4], x[9], x[14]);
  }
  uint32_t w0[QHP_VW] __attribute__((aligned(32))), w1[QHP_VW] __attribute__((aligned(32)));
  x[0] = QV_ADD(x[0], in0), x[1] = QV_ADD(x[1], in1);
  memcpy(w0, &x[0], sizeof w0), memcpy(w1, &x[1], sizeof w1);
  for (int j = 0; j < QHP_VW; j++) { /* little-endian hosts only (x86-64, aarch64) */
    memcpy(masks + 16 * j, &w0[j], 4);
    memcpy(masks + 16 * j + 4, &w1[j], 4);
  }
}
#endif

static inline void qhp_chacha_masks(const uint8_t key[32], const uint8_t *const *samples, uint8_t *masks, size_t n) {
  size_t i = 0;
#ifdef QHP_VW
  for (; i + QHP_VW <= n; i += QHP_VW) qhp__chacha_vec(key, samples + i, masks + 16 * i);
#endif
  for (; i < n; i++) qhp_chacha_block_ref(key, samples[i], masks + 16 * i);
}

/* Remove header protection in place (RFC 9001 §5.4.1). pn_off: offset of the packet number. */
static inline int qhp_apply(uint8_t *pkt, size_t pn_off, const uint8_t *mask) {
  pkt[0] ^= mask[0] & (pkt[0] & 0x80 ? 0x0f : 0x1f);
  int pnlen = (pkt[0] & 3) + 1;
  for (int i = 0; i < pnlen; i++) pkt[pn_off + i] ^= mask[1 + i];
  return pnlen;
}
#endif
