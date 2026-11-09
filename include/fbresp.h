// fbresp.h - HTTP/1.x response parser for clients: picohttpparser-exact head, RFC 9112 body framing. SIMD.
// Part of cursed-http. MIT licence, see LICENSE. The head's validation rules and -1/-2 decisions follow
// picohttpparser's phr_parse_response (MIT; credited in THIRD_PARTY.md); tests/test_resp.c checks every one.
//
// Layer 1, the head (picohttpparser's API, same arguments and results):
//   int fb_parse_response(buf, len, &minor, &status, &msg, &msg_len, headers, &num_headers, last_len);
//     > 0 bytes of the response head consumed, -1 invalid, -2 incomplete. num_headers: in = capacity, out = count.
//     "HTTP/1.<digit>" SP+ 3DIGIT, then an empty reason or SP+ reason, then CRLF or LF; the status is any 000-999
//     (as pico; fbr_parse below checks the range). Headers exactly as fb_parse_request's (obs-fold: name == NULL).
//   int fb_parse_headers(buf, len, headers, &num_headers, last_len): phr_parse_headers (trailer sections).
//   Both are stateless: a client with a partial head calls again with more bytes (last_len = the previous len, so
//   the slowloris check only looks at the new bytes, as pico).
//
// Layer 2, the client (fbr_parse): the head, then the body's framing by RFC 9112 section 6.3, in its order:
//   1. a response to HEAD, 1xx, 204, 304: no body (FBR_NONE), whatever the headers say;
//   2. 101, and any 2xx to CONNECT (a 204 too, RFC 9110 9.3.6): FBR_TUNNEL (the bytes after the head are not HTTP);
//      other 1xx are interim (FBR_INTERIM): the final response follows at buf + head_len (fbr_parse again);
//   3. Transfer-Encoding: chunked as the final coding -> FBR_CHUNKED (it beats Content-Length; FBR_TECL is set and the
//      connection must not be reused); any other final coding -> FBR_CLOSE. In an HTTP/1.0 response the framing is
//      faulty (RFC 9112 6.1): -1, FBR_E_TE10;
//   4. Content-Length: exactly one field, 1*DIGIT, < 2^63 -> FBR_LENGTH; anything else (a list, a second field even
//      with the same value, a sign, junk) -> -1, FBR_E_CL;
//   5. otherwise FBR_CLOSE: the body ends when the server closes.
//   Status outside 100..599 -> -1, FBR_E_STATUS. An obs-fold continuation of Content-Length, Transfer-Encoding or
//   Connection -> -1, FBR_E_FOLD. Keep-alive (FBR_KEEPALIVE): HTTP/1.1 unless "Connection: close", HTTP/1.0 only with
//   "keep-alive"; never after FBR_CLOSE, FBR_TUNNEL or FBR_TECL.
//
// Layer 3, chunked bodies: fbr_chunked() = fb_decode_chunked's rules (fbparse.h), stopping at the trailer section
// (parse it with fb_parse_headers), and it can stream: on FB_CHUNK_NEED_MORE it says how much input the complete chunks used and
// how much data they decoded, so a client drops those bytes and never re-decodes them.
//
// Contract (as fbparse.h): >= 64 readable bytes after buf[len] for layers 1 and 2, any contents. Layer 3 reads
// b[0..len) only. Nothing here is on the request parser's path: fbparse.h is used as it is, unchanged.
#pragma once
#include "fbparse.h"
#if defined(__SSE2__)
#include <emmintrin.h> // the chunk-extension scan (every x86-64 backend, the forced-scalar one too)
#endif

// ---------------- layer 1: the head ----------------
// The ct mask (a byte that ends a value) is classified ahead in batches of FBR_CTB blocks into an array, so the search
// for a line's end reads two cached words (a 64-byte window from any position) instead of branching where lines cross
// 64-byte blocks: that branch is data-dependent, and it mispredicted ~20 times per 1.3 KB head. Blocks at or after len
// are all ones, so a search always stops, at a position >= len (the caller's -2). Heads past FBR_CTMAX blocks go on with
// fbr_next, fbparse.h's per-block cache, which also serves the (rare) names of 32+ bytes.
#ifndef FBR_CTB
#define FBR_CTB 4 // blocks per batch (c002: 4 and 8 tie; growing batches lose on short heads)
#endif
#ifndef FBR_CTMAX
#define FBR_CTMAX 128 // 8 KB of head with the array (1 KB of stack: no stack-clash probes); longer heads use fbr_next
#endif
typedef struct {
  int k[2];
  uint64_t m[2]; // fbr_next's cache: [0] = nt, [1] = ct
  int done;      // blocks classified into ct[]
  uint64_t ct[FBR_CTMAX + FBR_CTB];
} fbr_scan_t;
FB_INLINE int fbr_next(const char *b, int len, int p, fbr_scan_t *s, const int which, const int simd) {
  const int i = which == FB_NT ? 0 : 1;
  for (;;) {
    int k = p >> 6;
    if (FB_UNLIKELY(k != s->k[i])) {
      if (p >= len) return p;
      s->m[i] = fb_cls64(simd, which, b + 64 * k);
      s->k[i] = k;
    }
    uint64_t m = s->m[i] >> (p & 63);
    if (FB_LIKELY(m)) return p + __builtin_ctzll(m);
    p = (k + 1) << 6;
  }
}
FB_INLINE void fbr_fill(const char *b, int len, fbr_scan_t *s, int upto, const int simd) {
  while (s->done <= upto) {
    int j = s->done;
    for (int i = 0; i < FBR_CTB; i++, j++) s->ct[j] = 64 * j < len ? fb_cls64(simd, FB_CT, b + 64 * j) : ~0ull;
    s->done = j;
  }
}
// the first ct at or after p (or some position >= len)
FB_INLINE int fbr_ct(const char *b, int len, int p, fbr_scan_t *s, const int simd) {
  int k = p >> 6, sh = p & 63;
  if (FB_UNLIKELY(k + 1 >= s->done)) {
    if (k + 1 >= FBR_CTMAX) return fbr_next(b, len, p, s, FB_CT, simd);
    fbr_fill(b, len, s, k + 1, simd);
  }
  // the 64 bytes from p from words k and k + 1 (aligned loads: they forward from the fill's stores)
  uint64_t m = (s->ct[k] >> sh) | ((s->ct[k + 1] << 1) << (63 - sh));
  if (FB_LIKELY(m)) return p + __builtin_ctzll(m);
  k++; // positions p .. p + 63 had no ct: on from p + 64, in word k + 1
  // a long value: the rest of word k, then whole words
  uint64_t w = s->ct[k] & (~0ull << sh);
  for (;;) {
    if (w) return (k << 6) + __builtin_ctzll(w);
    if (++k >= s->done) {
      if (k >= FBR_CTMAX) return fbr_next(b, len, k << 6, s, FB_CT, simd);
      fbr_fill(b, len, s, k, simd);
    }
    w = s->ct[k];
  }
}

// fbr_parse's view of the fields, noted during the parse (fx != NULL): the fields whose name has a framing-field
// length (10 Connection, 14 Content-Length, 17 Transfer-Encoding), and which of them an obs-fold line continues.
// More than FBR_FX candidates: fbr_parse looks at every field instead.
#define FBR_FX 8
typedef struct {
  int n, last;              // candidates noted; the field index of the last one (or of a fold line continuing it)
  unsigned fold;            // bit j: candidate j is continued by an obs-fold line
  unsigned idx[FBR_FX + 1]; // + a spare slot for the branch-free store
} fbr_fx_t;
#define FBR_FRAMING_LEN(nl) ((nl) <= 17 && ((1u << 10 | 1u << 14 | 1u << 17) >> (nl) & 1))

// the header section from p (pico's parse_headers): returns the end of the head, -1 or -2
// (*num_headers: out only, the count so far even on an error, as pico)
FB_INLINE int fbr_headers(const char *b, int len, int p, fbr_scan_t *sc, struct fb_header *h, size_t max,
                          size_t *num_headers, const int simd, fbr_fx_t *fx) {
  size_t n = 0;
#define FBR_RET(x)                                                                                                     \
  do {                                                                                                                 \
    *num_headers = n;                                                                                                  \
    return (x);                                                                                                        \
  } while (0)
  for (;; n++) {
    if (FB_UNLIKELY(p >= len)) FBR_RET(-2);
    unsigned char c = (unsigned char)b[p];
    const char *name;
    int nl, vs, e;
    // the line's first ct, from its start: a name, its ':' and the whitespace after it hold no ct, so this is the
    // value's end too. Searching from the line start keeps the line-to-line chain (p -> e -> p) off the name scan,
    // so lines overlap in the CPU; the name is still checked first below, so every result is pico's.
    e = fbr_ct(b, len, p, sc, simd);
    if (FB_UNLIKELY(c <= ' ')) { // the end of the head, obs-fold, or an error
      if (c == '\r') {
        if (p + 1 >= len) FBR_RET(-2);
        if (b[p + 1] != '\n') FBR_RET(-1);
        p += 2;
        break;
      }
      if (c == '\n') {
        p++;
        break;
      }
      // obs-fold continues the field before it (the value keeps its leading whitespace); on the first line, and for a
      // control byte, pico's name scan stops at once: -1 (as it is for n == max)
      if (n == max || n == 0 || (c != ' ' && c != '\t')) FBR_RET(-1);
      name = NULL;
      nl = 0;
      vs = p;
      if (fx && fx->last == (int)n - 1) { // continues a candidate (or a fold line that did)
        if (fx->n <= FBR_FX) fx->fold |= 1u << (fx->n - 1);
        fx->last = (int)n;
      }
    } else {
      if (n == max) FBR_RET(-1);
      int ne;
#if (FB_BACKEND == 2 || FB_BACKEND == 3) && !defined(FP_AVX512_EMU)
      // the 32 bytes at the line start (p < len: readable with the padding), as fb_core's walk
      if (simd) {
        uint32_t ntm = fb_nt32_at(b + p);
        ne = FB_LIKELY(ntm) ? p + __builtin_ctz(ntm) : fbr_next(b, len, p + 32, sc, FB_NT, simd);
      } else
#elif FB_BACKEND == 1
      if (simd) {
        uint64_t ntm = fb_nt16_nib(b + p);
        ne = FB_LIKELY(ntm) ? p + (__builtin_ctzll(ntm) >> 2) : fbr_next(b, len, p + 16, sc, FB_NT, simd);
      } else
#endif
        ne = fbr_next(b, len, p, sc, FB_NT, simd);
      // a ':' at ne >= len (in the padding) goes on: the value's end is then >= len too, so it is -2 below, as it
      // must be; any other byte at ne >= len is -2, below len -1
      if (FB_UNLIKELY(b[ne] != ':' || ne == p)) FBR_RET(ne >= len ? -2 : -1);
      name = b + p;
      nl = ne - p;
      vs = ne + 1;
      if (fx) { // without a branch: name lengths are data (a branch here mispredicted ~10 times per top-1k head)
        unsigned un = (unsigned)nl, cand = ((1u << 10 | 1u << 14 | 1u << 17) >> (un & 31) & 1) & (un <= 17);
        unsigned slot = (unsigned)fx->n < FBR_FX ? (unsigned)fx->n : FBR_FX; // idx[FBR_FX]: a spare slot
        fx->idx[slot] = (unsigned)n;
        fx->n += (int)cand;
        fx->last ^= (fx->last ^ (int)n) & -(int)cand;
      }
    }
    // e is the value's end: SP and HT are not ct either, so it is the first ct after the colon too, as pico's (it
    // skips the whitespace, then looks for the first ct); whitespace running into len is -2 there as here
    if (FB_LIKELY(e + 1 < len && (unsigned char)b[e] == '\r' && (unsigned char)b[e + 1] == '\n')) p = e + 2;
    else { // pico's order: incomplete before the line end, then a bare LF ends it, anything else is invalid
      if (e >= len) FBR_RET(-2);
      if (b[e] == '\n') p = e + 1;
      else if (b[e] != '\r') FBR_RET(-1);
      else if (e + 1 >= len) FBR_RET(-2);
      else FBR_RET(-1); // CR, then not LF
    }
    if (name) { // the whitespace after the colon: before e, a byte <= ' ' can only be SP or HT (the rest are ct)
      vs += b[vs] == ' ';
      if (FB_UNLIKELY(vs < e && (unsigned char)b[vs] <= ' '))
        while (vs < e && (unsigned char)b[vs] <= ' ') vs++;
    }
    int ve = e;
    while (FB_UNLIKELY(ve > vs && (unsigned char)b[ve - 1] <= ' ')) ve--; // SP or HT (as above)
    h[n].name = name;
    h[n].name_len = (size_t)nl;
    h[n].value = b + vs;
    h[n].value_len = (size_t)(ve - vs);
  }
  FBR_RET(p);
#undef FBR_RET
}

FB_INLINE int fbr_core(const char *b, int len, int *minor, int *status, const char **msg, size_t *msg_len,
                       struct fb_header *h, size_t *num_headers, size_t last_len, const int simd, fbr_fx_t *fx) {
  size_t max = *num_headers;
  *minor = -1;
  *status = 0;
  *msg = NULL;
  *msg_len = 0;
  *num_headers = 0;
  if (last_len != 0) {
    int c = fb_is_complete(b, len, last_len);
    if (c) return c;
  }
  // "HTTP/1.<digit>": pico wants 9 bytes before looking at any of them
  if (len < 9) return -2;
  if (fb_ld64(b) << 8 != (fb_ld64("HTTP/1.0") << 8) || (unsigned)(b[7] - '0') > 9) return -1;
  int mv = b[7] - '0';
  *minor = mv;
  if (b[8] != ' ') return -1;
  int p = 8;
  do {
    if (++p >= len) return -2;
  } while (b[p] == ' ');
  // three digits and one more byte before looking at them
  if (len - p < 4) return -2;
  unsigned d0 = (unsigned char)b[p] - '0', d1 = (unsigned char)b[p + 1] - '0', d2 = (unsigned char)b[p + 2] - '0';
  if (d0 > 9 || d1 > 9 || d2 > 9) return -1;
  *status = (int)(d0 * 100 + d1 * 10 + d2);
  // the reason phrase, with its leading spaces, up to the first ct (pico's get_token_to_eol)
  fbr_scan_t sc;
  sc.k[0] = sc.k[1] = -1;
  sc.m[0] = sc.m[1] = 0; // never read before a fill (k = -1); set for -Wmaybe-uninitialized
  sc.done = 0;
  int rs = p + 3, e = fbr_ct(b, len, rs, &sc, simd);
  if (e >= len) return -2;
  int q;
  if (FB_LIKELY(b[e] == '\r')) {
    if (e + 1 >= len) return -2;
    if (b[e + 1] != '\n') return -1;
    q = e + 2;
  } else if (b[e] == '\n') q = e + 1;
  else return -1;
  if (e != rs) {
    if (b[rs] != ' ') return -1; // garbage after the status code
    while (b[rs] == ' ') rs++;   // stops at the CR or LF at the latest
  }
  *msg = b + rs;
  *msg_len = (size_t)(e - rs);
  return fbr_headers(b, len, q, &sc, h, max, num_headers, simd, fx);
}

static inline int fb_parse_response(const char *buf, size_t len, int *minor_version, int *status, const char **msg,
                                    size_t *msg_len, struct fb_header *headers, size_t *num_headers, size_t last_len) {
  return fbr_core(buf, (int)len, minor_version, status, msg, msg_len, headers, num_headers, last_len, 1, NULL);
}
static inline int fb_parse_response_scalar(const char *buf, size_t len, int *minor_version, int *status,
                                           const char **msg, size_t *msg_len, struct fb_header *headers,
                                           size_t *num_headers, size_t last_len) {
  return fbr_core(buf, (int)len, minor_version, status, msg, msg_len, headers, num_headers, last_len, 0, NULL);
}

FB_INLINE int fbr_headers_core(const char *b, int len, struct fb_header *h, size_t *num_headers, size_t last_len,
                               const int simd) {
  size_t max = *num_headers;
  *num_headers = 0;
  if (last_len != 0) {
    int c = fb_is_complete(b, len, last_len);
    if (c) return c;
  }
  fbr_scan_t sc;
  sc.k[0] = sc.k[1] = -1;
  sc.m[0] = sc.m[1] = 0; // never read before a fill (k = -1); set for -Wmaybe-uninitialized
  sc.done = 0;
  return fbr_headers(b, len, 0, &sc, h, max, num_headers, simd, NULL);
}
// phr_parse_headers: a header section on its own (chunked trailers)
static inline int fb_parse_headers(const char *buf, size_t len, struct fb_header *headers, size_t *num_headers,
                                   size_t last_len) {
  return fbr_headers_core(buf, (int)len, headers, num_headers, last_len, 1);
}
static inline int fb_parse_headers_scalar(const char *buf, size_t len, struct fb_header *headers, size_t *num_headers,
                                          size_t last_len) {
  return fbr_headers_core(buf, (int)len, headers, num_headers, last_len, 0);
}

// ---------------- layer 2: the client's view (RFC 9112 section 6.3) ----------------
enum { FBR_REQ_OTHER = 0, FBR_REQ_HEAD = 1, FBR_REQ_CONNECT = 2 };     // the request this response answers
enum { FBR_NONE = 0, FBR_LENGTH, FBR_CHUNKED, FBR_CLOSE, FBR_TUNNEL }; // fbr_resp_t.body
enum {
  FBR_KEEPALIVE = 1,
  FBR_INTERIM = 2,
  FBR_TECL = 4,
  FBR_UPGRADE = 8
}; // fbr_resp_t.flags (UPGRADE: Connection has it)
enum { FBR_E_HEAD = 1, FBR_E_STATUS, FBR_E_CL, FBR_E_TE10, FBR_E_FOLD }; // fbr_resp_t.err, when fbr_parse says -1
typedef struct {
  int minor, status;
  const char *reason;
  size_t reason_len;
  struct fb_header *headers; // set by the caller, with num_headers = its capacity
  size_t num_headers;
  int body;       // FBR_NONE ... FBR_TUNNEL
  int64_t length; // FBR_LENGTH: the body's length; -1 otherwise
  unsigned flags; // FBR_KEEPALIVE | FBR_INTERIM | FBR_TECL | FBR_UPGRADE
  int err;        // why -1: FBR_E_*
} fbr_resp_t;

FB_INLINE int fbr_lc_eq(const char *s, size_t n, const char *lc, size_t k) { // ASCII case-insensitive, lc lowercase
  if (n != k) return 0;
  for (size_t i = 0; i < k; i++)
    if (((unsigned char)s[i] | ((unsigned)(s[i] - 'A') < 26u ? 0x20 : 0)) != (unsigned char)lc[i]) return 0;
  return 1;
}
// a field name (k >= 8 bytes, validated as tchars) vs a lowercase name of letters and '-': two overlapping 8-byte loads
// (with one more 8-byte load for k > 16). x | 0x20 maps exactly the two cases of a letter onto it, and '-' only from
// '-' or CR (not a tchar), so the compare is exact for these names.
FB_INLINE int fbr_name_is(const char *n, const char *lc, size_t k) {
  uint64_t a = fb_ld64(n) | 0x2020202020202020ull, z = fb_ld64(n + k - 8) | 0x2020202020202020ull;
  int ok = a == fb_ld64(lc) && z == fb_ld64(lc + k - 8);
  if (k > 16) ok &= (fb_ld64(n + 8) | 0x2020202020202020ull) == fb_ld64(lc + 8);
  return ok;
}
// the elements of a comma list (RFC 9110 5.6.1): calls back with each non-empty element, OWS trimmed
#define FBR_EACH(v, vl, EL, ELN, BODY)                                                                                 \
  for (size_t i_ = 0; i_ <= (vl);) {                                                                                   \
    size_t s_ = i_;                                                                                                    \
    while (i_ < (vl) && (v)[i_] != ',') i_++;                                                                          \
    size_t e_ = i_++;                                                                                                  \
    while (s_ < e_ && ((v)[s_] == ' ' || (v)[s_] == '\t')) s_++;                                                       \
    while (e_ > s_ && ((v)[e_ - 1] == ' ' || (v)[e_ - 1] == '\t')) e_--;                                               \
    if (e_ == s_) continue;                                                                                            \
    const char *EL = (v) + s_;                                                                                         \
    size_t ELN = e_ - s_;                                                                                              \
    BODY                                                                                                               \
  }

// one candidate field: a framing field updates fs; an obs-fold continuation of one is an error (1)
typedef struct {
  int ncl, te, te_chunked, conn_close, conn_ka;
  const char *clv;
  size_t cll;
} fbr_fs_t;
FB_INLINE int fbr_field(const struct fb_header *f, int fold, fbr_fs_t *fs, fbr_resp_t *r) {
  size_t nl = f->name_len;
  if (nl == 14 && fbr_name_is(f->name, "content-length", 14)) {
    fs->ncl++;
    fs->clv = f->value;
    fs->cll = f->value_len;
  } else if (nl == 17 && fbr_name_is(f->name, "transfer-encoding", 17)) {
    fs->te = 1;
    // the final coding of the last field decides; "chunked" alone first (nearly every response)
    if (f->value_len == 7 && fbr_lc_eq(f->value, 7, "chunked", 7)) fs->te_chunked = 1;
    else {
      fs->te_chunked = 0;
      FBR_EACH(f->value, f->value_len, el, eln, { fs->te_chunked = fbr_lc_eq(el, eln, "chunked", 7); })
    }
  } else if (nl == 10 && fbr_name_is(f->name, "connection", 10)) {
    if (f->value_len == 10 && fbr_name_is(f->value, "keep-alive", 10)) fs->conn_ka = 1; // the usual values first
    else if (f->value_len == 5 && fbr_lc_eq(f->value, 5, "close", 5)) fs->conn_close = 1;
    else
      FBR_EACH(f->value, f->value_len, el, eln, {
        if (fbr_lc_eq(el, eln, "close", 5)) fs->conn_close = 1;
        else if (fbr_lc_eq(el, eln, "keep-alive", 10)) fs->conn_ka = 1;
        else if (fbr_lc_eq(el, eln, "upgrade", 7)) r->flags |= FBR_UPGRADE;
      })
  } else return 0; // a name of the same length
  if (FB_UNLIKELY(fold)) {
    r->err = FBR_E_FOLD;
    return 1;
  }
  return 0;
}

FB_INLINE int fbr_core2(const char *b, size_t len, int req, fbr_resp_t *r, size_t last_len, const int simd) {
  r->body = FBR_NONE;
  r->length = -1;
  r->flags = 0;
  r->err = 0;
  fbr_fx_t fx;
  fx.n = 0;
  fx.last = -2;
  fx.fold = 0;
  int n = fbr_core(b, (int)len, &r->minor, &r->status, &r->reason, &r->reason_len, r->headers, &r->num_headers,
                   last_len, simd, &fx);
  if (n < 0) {
    if (n == -1) r->err = FBR_E_HEAD;
    return n;
  }
  int st = r->status;
  if (st < 100 || st > 599) {
    r->err = FBR_E_STATUS;
    return -1;
  }
  // the framing fields: the candidates noted during the parse (a framing-field name length), else every field
  fbr_fs_t fs = { 0, 0, 0, 0, 0, NULL, 0 };
  if (FB_LIKELY(fx.n <= FBR_FX)) {
    for (int j = 0; j < fx.n; j++)
      if (FB_UNLIKELY(fbr_field(&r->headers[fx.idx[j]], fx.fold >> j & 1, &fs, r))) return -1;
  } else {
    for (size_t i = 0; i < r->num_headers; i++) {
      const struct fb_header *f = &r->headers[i];
      if (!f->name || !FBR_FRAMING_LEN(f->name_len)) continue;
      int fold = i + 1 < r->num_headers && !r->headers[i + 1].name;
      if (FB_UNLIKELY(fbr_field(f, fold, &fs, r))) return -1;
    }
  }
  int ncl = fs.ncl, te = fs.te, te_chunked = fs.te_chunked, conn_close = fs.conn_close, conn_ka = fs.conn_ka;
  const char *clv = fs.clv;
  size_t cll = fs.cll;
  int ka = r->minor >= 1 ? !conn_close : conn_ka && !conn_close;
  if (req == FBR_REQ_CONNECT && st >= 200 &&
      st < 300) { // 2. (before 1: a 204 to CONNECT is a tunnel too, RFC 9110 9.3.6)
    r->body = FBR_TUNNEL;
    ka = 0;
  } else if (req == FBR_REQ_HEAD || st < 200 || st == 204 || st == 304) { // 1.
    if (st == 101) r->body = FBR_TUNNEL, ka = 0;
    else if (st < 200) r->flags |= FBR_INTERIM;
  } else if (te) { // 3.
    if (r->minor == 0) {
      r->err = FBR_E_TE10;
      return -1;
    }
    r->body = te_chunked ? FBR_CHUNKED : FBR_CLOSE;
    if (!te_chunked) ka = 0;
    if (ncl) r->flags |= FBR_TECL, ka = 0;
  } else if (ncl) { // 4.
    int64_t v = 0;
    if (ncl != 1 || cll == 0 || cll > 18) {
      r->err = FBR_E_CL;
      return -1;
    }
    if (FB_LIKELY(cll <= 8)) {
      // up to 8 digits at once (the value is inside the head, which the 64-byte padding follows): left-pad with
      // '0' to 8 bytes, check every byte is a digit, then the usual SWAR conversion of 8 ASCII digits
      uint64_t x = fb_ld64(clv) << (8 * (8 - cll)), t;
      if (cll < 8) x |= 0x3030303030303030ull >> (8 * cll);
      t = x - 0x3030303030303030ull;
      if ((t | (t + 0x7676767676767676ull)) & 0x8080808080808080ull) {
        r->err = FBR_E_CL;
        return -1;
      }
      t = t * 10 + (t >> 8); // pairs
      v = (int64_t)(((t & 0x000000FF000000FFull) * (100 + (1000000ull << 32)) +
                     ((t >> 16) & 0x000000FF000000FFull) * (1 + (10000ull << 32))) >>
                    32);
    } else
      for (size_t i = 0; i < cll; i++) {
        unsigned d = (unsigned char)clv[i] - '0';
        if (d > 9) {
          r->err = FBR_E_CL;
          return -1;
        }
        v = v * 10 + d; // 18 digits < 2^63
      }
    r->body = FBR_LENGTH;
    r->length = v;
  } else { // 5.
    r->body = FBR_CLOSE;
    ka = 0;
  }
  if (ka) r->flags |= FBR_KEEPALIVE;
  return n;
}
// > 0 head length, -1 invalid (r->err), -2 incomplete. r->headers / r->num_headers: the caller's array and capacity.
static inline int fbr_parse(const char *buf, size_t len, int req, fbr_resp_t *r, size_t last_len) {
  return fbr_core2(buf, len, req, r, last_len, 1);
}
static inline int fbr_parse_scalar(const char *buf, size_t len, int req, fbr_resp_t *r, size_t last_len) {
  return fbr_core2(buf, len, req, r, last_len, 0);
}

// ---------------- layer 3: chunked bodies ----------------
// hex digit values; 16 = not a hex digit
static const uint8_t
    FBR_HEX[256] = {
#define FBR_X16 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16
      FBR_X16, FBR_X16, FBR_X16, 0,       1,       2,       3,       4,       5,      6,
      7,       8,       9,       16,      16,      16,      16,      16,      16, // '0'-'9'
      16,      10,      11,      12,      13,      14,      15,      16,      16,     16,
      16,      16,      16,      16,      16,      16, // 'A'-'F'
      FBR_X16, 16,      10,      11,      12,      13,      14,      15,      16,     16,
      16,      16,      16,      16,      16,      16,      16,                       // 'a'-'f'
      FBR_X16, FBR_X16, FBR_X16, FBR_X16, FBR_X16, FBR_X16, FBR_X16, FBR_X16, FBR_X16 // 0x70-0xff
#undef FBR_X16
    };
// fbparse.h's fb_chunked_pass with two additions, kept here so the request decoder's code stays as it is:
// tr = 1: stop after the last-chunk line and return the position of the trailer section; prog != NULL: on NEED_MORE,
// prog[0] = the input bytes of the complete chunks before the incomplete one, prog[1] = their data bytes. The rules
// are fb_decode_chunked's, byte for byte (tests/test_resp.c checks fbr_chunked against it).
static inline int fbr_chunked_pass(const char *b, int len, char *out, int max_body, int *body_len, const int write,
                                   fb_chunk_span_t *sp, int *nsp, const int tr, int *prog) {
  int p = 0, total = 0, c0 = 0;
#define FBR_MORE()                                                                                                     \
  do {                                                                                                                 \
    if (prog) prog[0] = c0, prog[1] = total;                                                                           \
    return FB_CHUNK_NEED_MORE;                                                                                         \
  } while (0)
  for (;;) {
    c0 = p; // this chunk's start
    // the size: fb_decode_chunked checks the limit at every digit, but appending a digit never makes the value
    // smaller, so "over the limit at some digit" is "over it after the last one scanned" (16 at most, no overflow in
    // 64 bits): the same TOO_LARGE, before the 17th digit's INVALID and before NEED_MORE, as there
    uint64_t v = 0;
    int nd = 0, h;
    while (p < len && (h = FBR_HEX[(unsigned char)b[p]]) < 16) {
      if (++nd > 16) break;
      v = v * 16 + (unsigned)h;
      p++;
    }
    if (v > (uint64_t)((int64_t)max_body - total)) return FB_CHUNK_TOO_LARGE;
    if (nd > 16) return FB_CHUNK_INVALID;
    int64_t size = (int64_t)v;
    if (p >= len) FBR_MORE();
    if (nd == 0) return FB_CHUNK_INVALID;
    int q = p;
    if (FB_LIKELY(b[q] == '\r')) goto crlf; // the usual size line: no whitespace, no extension
    while (q < len && (b[q] == ' ' || b[q] == '\t')) q++;
    if (q >= len) FBR_MORE();
    if (b[q] == ';') {
      q++;
#if defined(__SSE2__)
      for (; q + 16 <= len; q += 16) { // 16 bytes at a time: the first ct must be the CR that ends the extension
        __m128i x = _mm_loadu_si128((const __m128i *)(b + q));
        __m128i ct = _mm_or_si128(_mm_andnot_si128(_mm_cmpeq_epi8(x, _mm_set1_epi8('\t')),
                                                   _mm_cmpeq_epi8(_mm_min_epu8(x, _mm_set1_epi8(0x1f)), x)),
                                  _mm_cmpeq_epi8(x, _mm_set1_epi8(0x7f)));
        unsigned m = (unsigned)_mm_movemask_epi8(ct);
        if (m) {
          q += __builtin_ctz(m);
          if (b[q] != '\r') return FB_CHUNK_INVALID;
          goto ext_end;
        }
      }
#endif
      for (; q + 8 <= len; q += 8) {
        uint64_t w = fb_ld64(b + q),
                 m = (fb_swar_le(w, 0x1f) & ~fb_swar_eq(w, '\t' * FB_ONES)) | fb_swar_eq(w, 0x7f * FB_ONES);
        if (m) {
          q += __builtin_ctzll(m) >> 3;
          if (b[q] != '\r') return FB_CHUNK_INVALID;
          break;
        }
      }
      for (; q < len && b[q] != '\r'; q++) {
        unsigned char c = (unsigned char)b[q];
        if ((c < 0x20 && c != '\t') || c == 0x7f) return FB_CHUNK_INVALID;
      }
#if defined(__SSE2__)
    ext_end:;
#endif
    } else if (q != p) return FB_CHUNK_INVALID;
    if (q >= len) FBR_MORE();
    if (b[q] != '\r') return FB_CHUNK_INVALID;
  crlf:
    if (q + 1 >= len) FBR_MORE();
    if (b[q + 1] != '\n') return FB_CHUNK_INVALID;
    p = q + 2;
    if (size == 0) {
      if (tr) {
        *body_len = total;
        return p;
      }
      if (p >= len) FBR_MORE();
      if (b[p] != '\r') return FB_CHUNK_INVALID;
      if (p + 1 >= len) FBR_MORE();
      if (b[p + 1] != '\n') return FB_CHUNK_INVALID;
      *body_len = total;
      return p + 2;
    }
    if ((int64_t)len - p < size + 2) {
      if ((int64_t)len - p >= size + 1 && b[p + size] != '\r') return FB_CHUNK_INVALID;
      FBR_MORE();
    }
    if (b[p + size] != '\r' || b[p + size + 1] != '\n') return FB_CHUNK_INVALID;
    if (write) fb_chunk_copy(out + total, b + p, (int)size);
    else if (*nsp < FB_CHUNK_SPANS) {
      sp[*nsp].off = p;
      sp[*nsp].size = (int)size;
      ++*nsp;
    } else *nsp = FB_CHUNK_SPANS + 1;
    total += (int)size;
    p += (int)size + 2;
  }
#undef FBR_MORE
}
// The chunks of b[0..len) into out (out == b: in place), up to max_body data bytes. Returns:
//   > 0: the last-chunk line ends there; *body_len = the data. The trailer section starts there: fb_parse_headers
//        (b + r, len - r, ...) ends it (> 0: the response ends at r + that; an empty section is just CRLF).
//   FB_CHUNK_NEED_MORE (0): incomplete. prog (may be NULL): prog[0] = input bytes of the complete chunks, prog[1] =
//        their data, already in out[0..prog[1]). A streaming client keeps that data, drops b[0..prog[0]) and calls
//        again on the rest with more bytes; nothing is decoded twice. In place, b[prog[0]..len) is untouched (and with
//        prog the decode is one pass; without it, two: a retry on the same bytes must find them as they were).
//   FB_CHUNK_INVALID (-2), FB_CHUNK_TOO_LARGE (-3): as fb_decode_chunked.
static inline int fbr_chunked(const char *b, int len, char *out, int max_body, int *body_len, int *prog) {
  int n = 0, ns = 0, r;
  fb_chunk_span_t sp[FB_CHUNK_SPANS];
  if (max_body < 0) max_body = 0;
  if (out != b) {
    r = fbr_chunked_pass(b, len, out, max_body, &n, 1, sp, &ns, 1, prog);
    if (r > 0) *body_len = n;
    return r;
  }
  // in place, streaming (prog): one pass, compacting as it goes. The caller resumes at prog[0], and nothing at or after
  // it is written (the data moves down to out[0..prog[1]) only)
  if (prog) {
    r = fbr_chunked_pass(b, len, out, max_body, &n, 1, sp, &ns, 1, prog);
    if (r > 0) *body_len = n;
    return r;
  }
  // in place without prog: validate first (a NEED_MORE retry must see the original bytes), then compact the chunks
  r = fbr_chunked_pass(b, len, out, max_body, &n, 0, sp, &ns, 1, prog);
  if (r < 0 || (r == 0 && !prog)) return r;
  if (ns <= FB_CHUNK_SPANS) {
    int t = 0;
    for (int i = 0; i < ns; i++) {
      fb_chunk_copy(out + t, b + sp[i].off, sp[i].size);
      t += sp[i].size;
    }
  } else fbr_chunked_pass(b, len, out, max_body, &n, 1, sp, &ns, 1, prog);
  if (r > 0) *body_len = n;
  return r;
}
