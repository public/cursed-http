// Differential test for fbresp.h (the response parser) against picohttpparser (vendor/pico, pinned commit 465a7ff).
//   make test-resp   (mk/resp.mk; also the scalar, SSE2 and emulated AVX-512 builds)
//   ./test_resp [quick]
// 1. The head: every input is parsed by phr_parse_response and by fb_parse_response with the best backend and the
//    scalar classify, with two different 64-byte paddings, and at every prefix length; the return code must be
//    identical (including -1 vs -2), and on success every output (minor, status, reason pointer and length, header
//    count, every name/value pointer and length). Also smaller header capacities and the last_len check.
//    The same for phr_parse_headers vs fb_parse_headers (trailer sections).
// 2. The framing (fbr_parse): a table of RFC 9112 section 6.3 cases with the expected body kind, length, flags and
//    errors; and on every generated response, fbr_parse's head must be fb_parse_response's.
// 3. Chunked bodies (fbr_chunked): every case of a trailer table, and generated bodies with trailers fed in random
//    pieces through the streaming interface, in place and not: the data must be the one-shot decode's, and the
//    one-shot decode must be phr_decode_chunked's (consume_trailer = 1) wherever fbr_chunked accepts.
// There is no list of tolerated differences: any difference is a failure.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "picohttpparser.h"
#include "fbresp.h"
#include "resp_gen.h"

_Static_assert(sizeof(struct fb_header) == sizeof(struct phr_header), "fb_header must match phr_header");

static int fails = 0;
#define FAIL(...)                                                                                                      \
  do {                                                                                                                 \
    if (fails++ < 25) printf(__VA_ARGS__);                                                                             \
  } while (0)
static void show(const char *b, int len) {
  if (fails > 25) return;
  printf("    \"");
  for (int i = 0; i < len && i < 200; i++) {
    unsigned char c = (unsigned char)b[i];
    if (c == '\r') printf("\\r");
    else if (c == '\n') printf("\\n");
    else if (c < 32 || c > 126) printf("\\x%02x", c);
    else putchar(c);
  }
  printf("%s\" (len %d)\n", len > 200 ? "..." : "", len);
}

static char *bufA, *bufB;
static void load(const char *src, int len) {
  free(bufA);
  free(bufB);
  bufA = malloc(len + PAD);
  bufB = malloc(len + PAD);
  memcpy(bufA, src, len);
  memcpy(bufB, src, len);
  memset(bufA + len, 'Z', PAD);
  for (int i = 0; i < PAD; i++) bufB[len + i] = "\r\n: \t\x00\xff\x7f"[rnd() % 8];
}

typedef int (*frfn)(const char *, size_t, int *, int *, const char **, size_t *, struct fb_header *, size_t *, size_t);
__attribute__((noinline)) static int FR_simd(const char *b, size_t l, int *mv, int *st, const char **m, size_t *ml,
                                             struct fb_header *h, size_t *nh, size_t ll) {
  return fb_parse_response(b, l, mv, st, m, ml, h, nh, ll);
}
__attribute__((noinline)) static int FR_scalar(const char *b, size_t l, int *mv, int *st, const char **m, size_t *ml,
                                               struct fb_header *h, size_t *nh, size_t ll) {
  return fb_parse_response_scalar(b, l, mv, st, m, ml, h, nh, ll);
}

#define MAXH 64
static long st_ok, st_inval, st_part, st_hdr_ok;
static int same_hdrs(const struct phr_header *H, const char *A, const struct fb_header *G, const char *B, size_t n) {
  for (size_t i = 0; i < n; i++)
    if ((G[i].name == NULL) != (H[i].name == NULL) || (H[i].name && G[i].name - B != H[i].name - A) ||
        G[i].name_len != H[i].name_len || G[i].value - B != H[i].value - A || G[i].value_len != H[i].value_len)
      return 0;
  return 1;
}
static void check_resp(int len, size_t max, size_t last_len, const char *what) {
  int mv, st;
  const char *m;
  size_t ml, nh = max;
  struct phr_header H[MAXH];
  int rp = phr_parse_response(bufA, len, &mv, &st, &m, &ml, H, &nh, last_len);
  if (rp > 0) st_ok++;
  else if (rp == -1) st_inval++;
  else st_part++;
  struct {
    frfn f;
    const char *base, *name;
  } V[] = { { FR_simd, bufA, "simd/A" }, { FR_simd, bufB, "simd/B" }, { FR_scalar, bufB, "scalar/B" } };
  for (int v = 0; v < 3; v++) {
    int mv2, st2;
    const char *m2;
    size_t ml2, nh2 = max;
    struct fb_header G[MAXH];
    const char *B = V[v].base;
    int rf = V[v].f(B, len, &mv2, &st2, &m2, &ml2, G, &nh2, last_len);
    int bad = rf != rp;
    if (!bad && rp > 0)
      bad = mv2 != mv || st2 != st || m2 - B != m - bufA || ml2 != ml || nh2 != nh || !same_hdrs(H, bufA, G, B, nh);
    if (bad) {
      FAIL("RESP MISMATCH (%s, %s) max=%zu last_len=%zu: pico=%d fb=%d\n", what, V[v].name, max, last_len, rp, rf);
      show(bufA, len);
    }
  }
  // fbr_parse's head is fb_parse_response's (its own -1s come after a successful head)
  struct fb_header G[MAXH];
  fbr_resp_t r = { .headers = G, .num_headers = max };
  int rr = fbr_parse(bufB, len, FBR_REQ_OTHER, &r, last_len);
  int ok = rp > 0 ? (rr == rp || (rr == -1 && r.err > FBR_E_HEAD)) : rr == rp && (rp != -1 || r.err == FBR_E_HEAD);
  if (ok && rr > 0)
    ok = r.minor == mv && r.status == st && r.reason - bufB == m - bufA && r.reason_len == ml && r.num_headers == nh;
  if (!ok) {
    FAIL("FBR HEAD MISMATCH (%s): pico=%d fbr=%d err=%d\n", what, rp, rr, r.err);
    show(bufA, len);
  }
}
static void check_hdrs(int len, size_t max, size_t last_len, const char *what) {
  size_t nh = max, nh2 = max, nh3 = max;
  struct phr_header H[MAXH];
  struct fb_header G[MAXH], S[MAXH];
  int rp = phr_parse_headers(bufA, len, H, &nh, last_len);
  int rf = fb_parse_headers(bufB, len, G, &nh2, last_len), rs2 = fb_parse_headers_scalar(bufA, len, S, &nh3, last_len);
  if (rp > 0) st_hdr_ok++;
  int bad = rf != rp || rs2 != rp;
  if (!bad && rp > 0) bad = nh2 != nh || nh3 != nh || !same_hdrs(H, bufA, G, bufB, nh) || !same_hdrs(H, bufA, S, bufA, nh);
  if (bad) {
    FAIL("HEADERS MISMATCH (%s) max=%zu: pico=%d fb=%d scalar=%d\n", what, max, rp, rf, rs2);
    show(bufA, len);
  }
}
static const size_t MAXES[] = { MAXH, 48, 0, 1, 2, 3, 5, 16 };
static void check(const char *src, int len, const char *what) {
  load(src, len);
  check_resp(len, MAXH, 0, what);
  if (rnd() % 4 == 0) check_resp(len, MAXES[rnd() % 8], 0, what);
  if (rnd() % 8 == 0 && len) check_resp(len, MAXH, 1 + rnd() % len, what);
}
static void check_truncs(const char *src, int len, const char *what) {
  for (int t = 0; t <= len; t++) check(src, t, what);
}
// a header section on its own: the response's, after the status line
static void check_hdr_truncs(const char *src, int len, const char *what) {
  const char *nl = memchr(src, '\n', len);
  if (!nl) return;
  int off = (int)(nl + 1 - src);
  for (int t = 0; t <= len - off; t++) {
    load(src + off, t);
    check_hdrs(t, MAXH, 0, what);
    if (rnd() % 4 == 0) check_hdrs(t, MAXES[rnd() % 8], 0, what);
    if (rnd() % 8 == 0 && t) check_hdrs(t, MAXH, 1 + rnd() % t, what);
  }
}

// ---------------- 2. framing ----------------
typedef struct {
  const char *in;
  int req, want; // want: 1 = a head, -1 / -2
  int body, err;
  int64_t length;
  unsigned flags;
} fcase_t;
#define K FBR_KEEPALIVE
static const fcase_t FC[] = {
  { "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", 0, 1, FBR_LENGTH, 0, 5, K },
  { "HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n", 0, 1, FBR_LENGTH, 0, 0, K },
  { "HTTP/1.1 200 OK\r\nContent-Length: 000123\r\n\r\n", 0, 1, FBR_LENGTH, 0, 123, K },
  { "HTTP/1.1 200 OK\r\nContent-Length: 999999999999999999\r\n\r\n", 0, 1, FBR_LENGTH, 0, 999999999999999999ll, K },
  { "HTTP/1.1 200 OK\r\nContent-Length: 1000000000000000000\r\n\r\n", 0, -1, 0, FBR_E_CL, -1, 0 },
  { "HTTP/1.1 200 OK\r\nContent-Length: 5, 5\r\n\r\n", 0, -1, 0, FBR_E_CL, -1, 0 },
  { "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n", 0, -1, 0, FBR_E_CL, -1, 0 },
  { "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n", 0, -1, 0, FBR_E_CL, -1, 0 },
  { "HTTP/1.1 200 OK\r\nContent-Length: +5\r\n\r\n", 0, -1, 0, FBR_E_CL, -1, 0 },
  { "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n", 0, -1, 0, FBR_E_CL, -1, 0 },
  { "HTTP/1.1 200 OK\r\nContent-Length: 0x10\r\n\r\n", 0, -1, 0, FBR_E_CL, -1, 0 },
  { "HTTP/1.1 200 OK\r\nContent-Length: 1 2\r\n\r\n", 0, -1, 0, FBR_E_CL, -1, 0 },
  { "HTTP/1.1 200 OK\r\nContent-Length:\r\n\r\n", 0, -1, 0, FBR_E_CL, -1, 0 },
  { "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n 6\r\n\r\n", 0, -1, 0, FBR_E_FOLD, -1, 0 },
  { "HTTP/1.1 200 OK\r\nX-A: 5\r\n 6\r\nContent-Length: 1\r\n\r\n", 0, 1, FBR_LENGTH, 0, 1, K },
  { "HTTP/1.1 200 OK\r\nContent-Length : 5\r\n\r\n", 0, -1, 0, FBR_E_HEAD, -1, 0 },
  { "HTTP/1.1 200 OK\r\nContent-Lengthx: 5\r\n\r\n", 0, 1, FBR_CLOSE, 0, -1, 0 },
  // Transfer-Encoding
  { "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", 0, 1, FBR_CHUNKED, 0, -1, K },
  { "HTTP/1.1 200 OK\r\nTransfer-Encoding: CHUNKED\r\n\r\n", 0, 1, FBR_CHUNKED, 0, -1, K },
  { "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", 0, 1, FBR_CHUNKED, 0, -1, K },
  { "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n", 0, 1, FBR_CHUNKED, 0, -1, K },
  { "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n", 0, 1, FBR_CLOSE, 0, -1, 0 },
  { "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n\r\n", 0, 1, FBR_CLOSE, 0, -1, 0 },
  { "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n", 0, 1, FBR_CLOSE, 0, -1, 0 },
  { "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked , \r\n\r\n", 0, 1, FBR_CHUNKED, 0, -1, K },
  { "HTTP/1.1 200 OK\r\nTransfer-Encoding: xchunked\r\n\r\n", 0, 1, FBR_CLOSE, 0, -1, 0 },
  { "HTTP/1.1 200 OK\r\nTransfer-Encoding:\r\n\r\n", 0, 1, FBR_CLOSE, 0, -1, 0 },
  { "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n", 0, 1, FBR_CHUNKED, 0, -1, FBR_TECL },
  { "HTTP/1.1 200 OK\r\nContent-Length: x\r\nTransfer-Encoding: chunked\r\n\r\n", 0, 1, FBR_CHUNKED, 0, -1, FBR_TECL },
  { "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", 0, -1, 0, FBR_E_TE10, -1, 0 },
  { "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\tgzip\r\n\r\n", 0, -1, 0, FBR_E_FOLD, -1, 0 },
  // no body: HEAD, 1xx, 204, 304
  { "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", FBR_REQ_HEAD, 1, FBR_NONE, 0, -1, K },
  { "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", FBR_REQ_HEAD, 1, FBR_NONE, 0, -1, K },
  { "HTTP/1.1 200 OK\r\nContent-Length: 5, 6\r\n\r\n", FBR_REQ_HEAD, 1, FBR_NONE, 0, -1, K },
  { "HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n", 0, 1, FBR_NONE, 0, -1, K },
  { "HTTP/1.1 304 Not Modified\r\nContent-Length: 500\r\n\r\n", 0, 1, FBR_NONE, 0, -1, K },
  { "HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n", 0, 1, FBR_NONE, 0, -1, K },
  { "HTTP/1.1 100 Continue\r\n\r\n", 0, 1, FBR_NONE, 0, -1, K | FBR_INTERIM },
  { "HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\n", 0, 1, FBR_NONE, 0, -1, K | FBR_INTERIM },
  { "HTTP/1.1 199 Whatever\r\n\r\n", 0, 1, FBR_NONE, 0, -1, K | FBR_INTERIM },
  // tunnels
  { "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", 0, 1, FBR_TUNNEL, 0, -1,
    FBR_UPGRADE },
  { "HTTP/1.1 200 Connection established\r\n\r\n", FBR_REQ_CONNECT, 1, FBR_TUNNEL, 0, -1, 0 },
  { "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", FBR_REQ_CONNECT, 1, FBR_TUNNEL, 0, -1, 0 },
  { "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 3\r\n\r\n", FBR_REQ_CONNECT, 1, FBR_LENGTH, 0, 3, K },
  { "HTTP/1.1 204 No Content\r\n\r\n", FBR_REQ_CONNECT, 1, FBR_TUNNEL, 0, -1, 0 },
  { "HTTP/1.1 304 Not Modified\r\n\r\n", FBR_REQ_CONNECT, 1, FBR_NONE, 0, -1, K },
  { "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", FBR_REQ_HEAD | 0, 1, FBR_NONE, 0, -1, K },
  // close-delimited, keep-alive
  { "HTTP/1.1 200 OK\r\n\r\n", 0, 1, FBR_CLOSE, 0, -1, 0 },
  { "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n", 0, 1, FBR_LENGTH, 0, 2, 0 },
  { "HTTP/1.0 200 OK\r\nConnection: keep-alive\r\nContent-Length: 2\r\n\r\n", 0, 1, FBR_LENGTH, 0, 2, K },
  { "HTTP/1.0 200 OK\r\nConnection: Keep-Alive, close\r\nContent-Length: 2\r\n\r\n", 0, 1, FBR_LENGTH, 0, 2, 0 },
  { "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\n", 0, 1, FBR_LENGTH, 0, 2, 0 },
  { "HTTP/1.1 200 OK\r\nConnection: x, CLOSE\r\nContent-Length: 2\r\n\r\n", 0, 1, FBR_LENGTH, 0, 2, 0 },
  { "HTTP/1.1 200 OK\r\nConnection: closed\r\nContent-Length: 2\r\n\r\n", 0, 1, FBR_LENGTH, 0, 2, K },
  { "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n", 0, 1, FBR_CLOSE, 0, -1, 0 },
  { "HTTP/1.2 200 OK\r\nContent-Length: 2\r\n\r\n", 0, 1, FBR_LENGTH, 0, 2, K },
  // status range
  { "HTTP/1.1 099 Low\r\nContent-Length: 2\r\n\r\n", 0, -1, 0, FBR_E_STATUS, -1, 0 },
  { "HTTP/1.1 000 Zero\r\n\r\n", 0, -1, 0, FBR_E_STATUS, -1, 0 },
  { "HTTP/1.1 600 High\r\nContent-Length: 2\r\n\r\n", 0, -1, 0, FBR_E_STATUS, -1, 0 },
  { "HTTP/1.1 599 Highest\r\nContent-Length: 2\r\n\r\n", 0, 1, FBR_LENGTH, 0, 2, K },
  { "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n", 0, -2, 0, 0, -1, 0 },
};

// ---------------- 3. chunked bodies ----------------
typedef struct {
  const char *in;
  int want; // 1 ok, else the FB_CHUNK_* code
  const char *body, *trailer; // trailer: the first trailer field's name, or NULL
} tcase_t;
static const tcase_t TC[] = {
  { "5\r\nhello\r\n0\r\n\r\n", 1, "hello", NULL },
  { "5\r\nhello\r\n0\r\nX-Checksum: abc\r\n\r\n", 1, "hello", "X-Checksum" },
  { "5\r\nhello\r\n0\r\nA: 1\r\nB: 2\r\n\r\n", 1, "hello", "A" },
  { "0\r\nServer-Timing: total;dur=12\r\n\r\n", 1, "", "Server-Timing" },
  { "5\r\nhello\r\n0;ext=1\r\nA: 1\r\n\r\n", 1, "hello", "A" },
  { "5\r\nhello\r\n0\r\nA: 1\n\n", 1, "hello", "A" },     // trailers: bare LF as headers allow
  { "5\r\nhello\r\n0\r\n\n", 1, "hello", NULL },          // the empty trailer section: LF, as fb_parse_headers
  { "5\r\nhello\r\n0\r\nA 1\r\n\r\n", -1, "hello", NULL }, // a bad trailer field: fb_parse_headers says -1
  { "5\r\nhello\r\n0\r\n", 0, NULL, NULL },               // incomplete trailer section (fb_parse_headers: -2)
  { "5\r\nhelloX\r\n0\r\n\r\n", FB_CHUNK_INVALID, NULL, NULL },
};
static char tbuf[1 << 16], tout[1 << 16];
// fbr_chunked + fb_parse_headers on the whole input: 1 / 0 (incomplete) / FB_CHUNK_* / -1 (bad trailer)
static int whole(const char *in, int len, char *out, int *bl, int *end, const char **tr) {
  int r = fbr_chunked(in, len, out, 1 << 20, bl, NULL);
  if (r <= 0) return r;
  struct fb_header T[16];
  size_t nt = 16;
  memcpy(tbuf, in + r, len - r);
  memset(tbuf + len - r, 'Z', PAD);
  int t = fb_parse_headers(tbuf, len - r, T, &nt, 0);
  if (t == -2) return 0;
  if (t < 0) return -1;
  *end = r + t;
  *tr = nt ? T[0].name : NULL;
  if (tr && nt) *tr = in + r + (T[0].name - tbuf);
  return 1;
}
// the same input in random pieces through prog: returns the data length (or < 0), the data in out
static int streamed(const char *in, int len, char *out, int inplace) {
  static char w[1 << 16];
  int have = 0, fed = 0, data = 0;
  for (;;) {
    int add = len - fed < 1 ? 0 : 1 + rnd() % (rnd() % 4 == 0 ? 64 : 7);
    if (add > len - fed) add = len - fed;
    memcpy(w + have, in + fed, add);
    have += add;
    fed += add;
    int bl = -1, prog[2] = { -1, -1 };
    char *o = inplace ? w : out + data;
    int r = fbr_chunked(w, have, o, (1 << 20) - data, &bl, prog);
    if (r > 0) {
      if (inplace) memcpy(out + data, w, bl);
      return data + bl;
    }
    if (r < 0) return r;
    if (prog[0] < 0 || prog[1] < 0 || prog[1] > prog[0] || prog[0] > have) return -100;
    if (inplace) memcpy(out + data, w, prog[1]);
    data += prog[1];
    memmove(w, w + prog[0], have - prog[0]);
    have -= prog[0];
    if (fed == len && add == 0) return -101; // never completed
  }
}
static int gen_chunked(char *s, char *body, int *blen) {
  int n = 0, b = 0, nc = rnd() % 12;
  for (int i = 0; i < nc; i++) {
    int sz = 1 + rnd() % (rnd() % 4 ? 40 : 3000);
    n += sprintf(s + n, rnd() % 5 ? "%x" : "%04X", sz);
    if (rnd() % 8 == 0) n += sprintf(s + n, ";ext=%d", i);
    n += sprintf(s + n, "\r\n");
    for (int j = 0; j < sz; j++) s[n + j] = body[b + j] = (char)rnd();
    n += sz;
    b += sz;
    n += sprintf(s + n, "\r\n");
  }
  n += sprintf(s + n, "0\r\n");
  int nt = rnd() % 3 ? 0 : 1 + rnd() % 3;
  for (int i = 0; i < nt; i++) n += sprintf(s + n, "X-T%d: v%u\r\n", i, rnd());
  n += sprintf(s + n, "\r\n");
  *blen = b;
  return n;
}

int main(int argc, char **argv) {
  int quick = argc > 1 && !strcmp(argv[1], "quick"), NGEN = quick ? 3000 : 30000;
  printf("fbresp backend: %s\n", FB_BACKEND_NAME);
  static char s[1 << 16];
  // 1. the head: edges, generated, mutated; every prefix
  for (size_t i = 0; i < sizeof EDGES / sizeof *EDGES; i++) {
    int l = (int)strlen(EDGES[i]);
    check_truncs(EDGES[i], l, "edge");
    check_hdr_truncs(EDGES[i], l, "edge");
  }
  for (size_t i = 0; i < sizeof FC / sizeof *FC; i++) check_truncs(FC[i].in, (int)strlen(FC[i].in), "framing case");
  for (int i = 0; i < NGEN; i++) {
    int n = gen(s);
    if (i % 3 == 0) mutate(s, &n);
    if (i % 8 == 0 || n > 600) { // every prefix of some, the complete input and random prefixes of the rest
      check_truncs(s, n, i % 3 == 0 ? "mutated" : "generated");
      check_hdr_truncs(s, n, "generated headers");
    } else {
      check(s, n, "generated");
      for (int k = 0; k < 8; k++) check(s, rnd() % (n + 1), "generated prefix");
      load(s, n);
      check_hdrs(n, MAXH, 0, "generated");
    }
  }
  // long heads: header counts at and around the capacity, values across many blocks
  for (int nh = 60; nh <= 70; nh++) {
    int n = sprintf(s, "HTTP/1.1 200 OK\r\n");
    for (int i = 0; i < nh; i++) n += sprintf(s + n, "X-H%d: %d\r\n", i, i);
    n += sprintf(s + n, "\r\n");
    check_truncs(s, n, "header count");
  }
  printf("head: pico ok %ld, invalid %ld, incomplete %ld; headers ok %ld\n", st_ok, st_inval, st_part, st_hdr_ok);

  // 2. framing
  int nf = 0;
  for (size_t i = 0; i < sizeof FC / sizeof *FC; i++) {
    const fcase_t *c = &FC[i];
    int l = (int)strlen(c->in);
    for (int simd = 0; simd < 2; simd++) {
      load(c->in, l);
      struct fb_header G[MAXH];
      fbr_resp_t r = { .headers = G, .num_headers = MAXH };
      int x = simd ? fbr_parse(bufA, l, c->req, &r, 0) : fbr_parse_scalar(bufB, l, c->req, &r, 0);
      int ok = c->want == 1 ? x == l && r.body == c->body && r.length == c->length && r.flags == c->flags
               : c->want == -1 ? x == -1 && r.err == c->err
                               : x == c->want;
      if (!ok) {
        FAIL("FRAMING case %zu (%s, req %d): got %d body %d length %lld flags %u err %d; want %d body %d length %lld "
             "flags %u err %d\n",
             i, simd ? "simd" : "scalar", c->req, x, r.body, (long long)r.length, r.flags, r.err, c->want, c->body,
             (long long)c->length, c->flags, c->err);
        show(c->in, l);
      }
      nf++;
    }
  }
  // an interim response, then the final one, from the same buffer
  {
    const char *in = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: <a>\r\n\r\n"
                     "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
    int l = (int)strlen(in), off = 0, steps = 0;
    load(in, l);
    struct fb_header G[MAXH];
    fbr_resp_t r;
    for (;;) {
      r.headers = G;
      r.num_headers = MAXH;
      int x = fbr_parse(bufA + off, l - off, 0, &r, 0);
      if (x <= 0) break;
      off += x;
      steps++;
      if (!(r.flags & FBR_INTERIM)) break;
    }
    if (steps != 3 || r.status != 200 || r.body != FBR_LENGTH || r.length != 2 || l - off != 2)
      FAIL("INTERIM: steps %d status %d body %d at %d of %d\n", steps, r.status, r.body, off, l);
  }
  printf("framing: %d checks\n", nf);

  // 3. chunked: the trailer table, then generated bodies streamed in pieces vs one shot vs pico
  for (size_t i = 0; i < sizeof TC / sizeof *TC; i++) {
    const tcase_t *c = &TC[i];
    int l = (int)strlen(c->in), bl = -1, end = -1;
    const char *tr = NULL;
    int x = whole(c->in, l, tout, &bl, &end, &tr);
    int ok = x == c->want;
    if (ok && x == 1)
      ok = end == l && bl == (int)strlen(c->body) && !memcmp(tout, c->body, bl) &&
           (c->trailer ? tr && !memcmp(tr, c->trailer, strlen(c->trailer)) : tr == NULL);
    // every truncation is incomplete (or already invalid for the invalid ones)
    for (int t = 0; ok && t < l; t++) {
      int y = whole(c->in, t, tout, &bl, &end, &tr);
      ok = y == 0 || (c->want < 0 && y == c->want);
    }
    if (!ok) {
      FAIL("TRAILER case %zu: got %d (body %d, end %d) want %d\n", i, x, bl, end, c->want);
      show(c->in, l);
    }
  }
  static char body[1 << 16], o1[1 << 16], o2[1 << 16], pc[1 << 16];
  long nck = 0, npico = 0;
  for (int i = 0; i < NGEN / 3; i++) {
    int blen, n = gen_chunked(s, body, &blen);
    if (n > (1 << 15)) continue;
    int mut = i % 4 == 0;
    if (mut) mutate(s, &n);
    int bl = -1, end = -1;
    const char *tr;
    int x = whole(s, n, o1, &bl, &end, &tr);
    if (!mut && (x != 1 || bl != blen || memcmp(o1, body, blen) || end != n)) {
      FAIL("CHUNKED generated: got %d (body %d of %d, end %d of %d)\n", x, bl, blen, end, n);
      show(s, n);
      continue;
    }
    // the streamed decode equals the one-shot decode (data only: the trailer section is the caller's)
    int r1 = fbr_chunked(s, n, o1, 1 << 20, &bl, NULL);
    for (int inplace = 0; inplace < 2; inplace++) {
      int sl = streamed(s, n, o2, inplace);
      int ok = r1 > 0 ? sl == bl && !memcmp(o1, o2, bl) : r1 == 0 ? sl == -101 : sl == r1;
      if (!ok) {
        FAIL("CHUNKED streamed (%s): one-shot %d (body %d), streamed %d\n", inplace ? "in place" : "out", r1, bl, sl);
        show(s, n);
      }
    }
    // pico: where fbr_chunked + fb_parse_headers accept, phr_decode_chunked (consume_trailer) agrees
    if (x == 1) {
      struct phr_chunked_decoder d = { 0 };
      d.consume_trailer = 1;
      memcpy(pc, s, n);
      size_t sz = n;
      ssize_t pr = phr_decode_chunked(&d, pc, &sz);
      if (pr != 0 || (int)sz != bl || memcmp(pc, o1, bl)) {
        FAIL("CHUNKED vs pico: pico %zd (body %zu), fbr body %d\n", pr, sz, bl);
        show(s, n);
      }
      npico++;
    }
    nck++;
  }
  printf("chunked: %ld bodies, %ld agreed with pico\n", nck, npico);
  if (fails) {
    printf("FAILED: %d mismatches\n", fails);
    return 1;
  }
  printf("ALL RESPONSE TESTS PASSED\n");
  return 0;
}
