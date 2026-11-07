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
// Layer 3, chunked bodies: fbr_chunked() = fb_decode_chunked (fbparse.h) that stops at the trailer section (parse it
// with fb_parse_headers) and can stream: on FB_CHUNK_NEED_MORE it says how much input the complete chunks used and
// how much data they decoded, so a client drops those bytes and never re-decodes them.
//
// Contract (as fbparse.h): >= 64 readable bytes after buf[len] for layers 1 and 2, any contents. Layer 3 reads
// b[0..len) only. Nothing here is on the request parser's path: fbparse.h's request code is untouched.
#pragma once
#include "fbparse.h"

// ---------------- layer 1: the head ----------------
// Per predicate (nt, ct) one cached 64-byte block mask, as fbparse.h's scan; searches only move forward.
typedef struct {
  int k[2];
  uint64_t m[2]; // [0] = nt, [1] = ct
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

// the header section from p (pico's parse_headers): returns the end of the head, -1 or -2
// (*num_headers: out only, the count so far even on an error, as pico)
FB_INLINE int fbr_headers(const char *b, int len, int p, fbr_scan_t *sc, struct fb_header *h, size_t max,
                          size_t *num_headers, const int simd) {
  size_t n = 0;
  for (;; n++) {
    if (p >= len) return -2;
    unsigned char c = (unsigned char)b[p];
    if (c == '\r') {
      if (p + 1 >= len) return -2;
      if (b[p + 1] != '\n') return -1;
      p += 2;
      break;
    }
    if (c == '\n') {
      p++;
      break;
    }
    if (n == max) return -1;
    const char *name;
    int nl, vs, e;
    if (FB_UNLIKELY(n != 0 && (c == ' ' || c == '\t'))) { // obs-fold: the value keeps its leading whitespace
      name = NULL;
      nl = 0;
      vs = p;
    } else {
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
      if (ne >= len) return -2;
      if (b[ne] != ':' || ne == p) return -1;
      name = b + p;
      nl = ne - p;
      vs = ne + 1;
      while (vs < len && (b[vs] == ' ' || b[vs] == '\t')) vs++;
      if (vs >= len) return -2;
    }
    e = fbr_next(b, len, vs, sc, FB_CT, simd);
    if (e >= len) return -2;
    if (FB_LIKELY(b[e] == '\r')) {
      if (e + 1 >= len) return -2;
      if (b[e + 1] != '\n') return -1;
      p = e + 2;
    } else if (b[e] == '\n') p = e + 1;
    else return -1;
    int ve = e;
    while (FB_UNLIKELY(ve > vs && (b[ve - 1] == ' ' || b[ve - 1] == '\t'))) ve--;
    h[n].name = name;
    h[n].name_len = (size_t)nl;
    h[n].value = b + vs;
    h[n].value_len = (size_t)(ve - vs);
    *num_headers = n + 1;
  }
  *num_headers = n;
  return p;
}

FB_INLINE int fbr_core(const char *b, int len, int *minor, int *status, const char **msg, size_t *msg_len,
                       struct fb_header *h, size_t *num_headers, size_t last_len, const int simd) {
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
  fbr_scan_t sc = { { 0, 0 }, { 0, 0 } };
  fb_ntct64(simd, b, &sc.m[0], &sc.m[1]); // block 0: the status line and the first headers
  int rs = p + 3, e = fbr_next(b, len, rs, &sc, FB_CT, simd);
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
  return fbr_headers(b, len, q, &sc, h, max, num_headers, simd);
}

static inline int fb_parse_response(const char *buf, size_t len, int *minor_version, int *status, const char **msg,
                                    size_t *msg_len, struct fb_header *headers, size_t *num_headers, size_t last_len) {
  return fbr_core(buf, (int)len, minor_version, status, msg, msg_len, headers, num_headers, last_len, 1);
}
static inline int fb_parse_response_scalar(const char *buf, size_t len, int *minor_version, int *status,
                                           const char **msg, size_t *msg_len, struct fb_header *headers,
                                           size_t *num_headers, size_t last_len) {
  return fbr_core(buf, (int)len, minor_version, status, msg, msg_len, headers, num_headers, last_len, 0);
}

FB_INLINE int fbr_headers_core(const char *b, int len, struct fb_header *h, size_t *num_headers, size_t last_len,
                               const int simd) {
  size_t max = *num_headers;
  *num_headers = 0;
  if (last_len != 0) {
    int c = fb_is_complete(b, len, last_len);
    if (c) return c;
  }
  fbr_scan_t sc = { { -1, -1 }, { 0, 0 } };
  return fbr_headers(b, len, 0, &sc, h, max, num_headers, simd);
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
enum { FBR_REQ_OTHER = 0, FBR_REQ_HEAD = 1, FBR_REQ_CONNECT = 2 }; // the request this response answers
enum { FBR_NONE = 0, FBR_LENGTH, FBR_CHUNKED, FBR_CLOSE, FBR_TUNNEL }; // fbr_resp_t.body
enum { FBR_KEEPALIVE = 1, FBR_INTERIM = 2, FBR_TECL = 4, FBR_UPGRADE = 8 }; // fbr_resp_t.flags (UPGRADE: Connection has it)
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

FB_INLINE int fbr_core2(const char *b, size_t len, int req, fbr_resp_t *r, size_t last_len, const int simd) {
  r->body = FBR_NONE;
  r->length = -1;
  r->flags = 0;
  r->err = 0;
  int n = fbr_core(b, (int)len, &r->minor, &r->status, &r->reason, &r->reason_len, r->headers, &r->num_headers,
                   last_len, simd);
  if (n < 0) {
    if (n == -1) r->err = FBR_E_HEAD;
    return n;
  }
  int st = r->status;
  if (st < 100 || st > 599) {
    r->err = FBR_E_STATUS;
    return -1;
  }
  // the framing fields: names by length first (cheap), then the case-insensitive compare
  int ncl = 0, te = 0, te_chunked = 0, conn_close = 0, conn_ka = 0, last = 0; // last: 1 CL, 2 TE, 3 Connection
  const char *clv = NULL;
  size_t cll = 0;
  for (size_t i = 0; i < r->num_headers; i++) {
    const struct fb_header *f = &r->headers[i];
    if (!f->name) { // obs-fold: a continuation of the field before it
      if (last) {
        r->err = FBR_E_FOLD;
        return -1;
      }
      continue;
    }
    last = 0;
    size_t nl = f->name_len;
    if (nl == 14 && fbr_lc_eq(f->name, nl, "content-length", 14)) {
      ncl++;
      clv = f->value;
      cll = f->value_len;
      last = 1;
    } else if (nl == 17 && fbr_lc_eq(f->name, nl, "transfer-encoding", 17)) {
      te = 1;
      last = 2;
      te_chunked = 0; // the final coding of the last field decides
      FBR_EACH(f->value, f->value_len, el, eln, { te_chunked = fbr_lc_eq(el, eln, "chunked", 7); })
    } else if (nl == 10 && fbr_lc_eq(f->name, nl, "connection", 10)) {
      last = 3;
      FBR_EACH(f->value, f->value_len, el, eln, {
        if (fbr_lc_eq(el, eln, "close", 5)) conn_close = 1;
        else if (fbr_lc_eq(el, eln, "keep-alive", 10)) conn_ka = 1;
        else if (fbr_lc_eq(el, eln, "upgrade", 7)) r->flags |= FBR_UPGRADE;
      })
    }
  }
  int ka = r->minor >= 1 ? !conn_close : conn_ka && !conn_close;
  if (req == FBR_REQ_CONNECT && st >= 200 && st < 300) { // 2. (before 1: a 204 to CONNECT is a tunnel too, RFC 9110 9.3.6)
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
// The chunks of b[0..len) into out (out == b: in place), up to max_body data bytes. Returns:
//   > 0: the last-chunk line ends there; *body_len = the data. The trailer section starts there: fb_parse_headers
//        (b + r, len - r, ...) ends it (> 0: the response ends at r + that; an empty section is just CRLF).
//   FB_CHUNK_NEED_MORE (0): incomplete. prog (may be NULL): prog[0] = input bytes of the complete chunks, prog[1] =
//        their data, already in out[0..prog[1]). A streaming client keeps that data, drops b[0..prog[0]) and calls
//        again on the rest with more bytes; nothing is decoded twice. In place, b[prog[0]..len) is untouched.
//   FB_CHUNK_INVALID (-2), FB_CHUNK_TOO_LARGE (-3): as fb_decode_chunked.
static inline int fbr_chunked(const char *b, int len, char *out, int max_body, int *body_len, int *prog) {
  return fb_decode_chunked_ex(b, len, out, max_body, body_len, 1, prog);
}
