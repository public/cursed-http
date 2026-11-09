// libFuzzer target: fbresp.h vs picohttpparser. The input is a response (head, body, anything after):
//   - fb_parse_response (SIMD and scalar) == phr_parse_response: result code, and on success every output; also on
//     a prefix of the input (incomplete vs invalid) and with a small header capacity;
//   - fb_parse_headers == phr_parse_headers on the same bytes;
//   - fbr_parse's head == fb_parse_response's, and its framing obeys RFC 9112 6.3 (checked from the fields);
//   - fbr_chunked on the bytes after the head: streamed in pieces == one shot, and where it and fb_parse_headers
//     accept, phr_decode_chunked (consume_trailer) decodes the same data.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fuzz.h"
#include "fbresp.h"

#define FPAD  64
#define FMAXH 32
static char *dup_pad(const uint8_t *d, size_t n, char fill) {
  char *b = malloc(n + FPAD);
  memcpy(b, d, n);
  memset(b + n, fill, FPAD);
  return b;
}
static int same_h(const struct phr_header *H, const char *A, const struct fb_header *G, const char *B, size_t n) {
  for (size_t i = 0; i < n; i++)
    if ((G[i].name == NULL) != (H[i].name == NULL) || (H[i].name && G[i].name - B != H[i].name - A) ||
        G[i].name_len != H[i].name_len || G[i].value - B != H[i].value - A || G[i].value_len != H[i].value_len)
      return 0;
  return 1;
}
static void head(const uint8_t *d, size_t n, size_t max, const char *what) {
  char *A = dup_pad(d, n, 'Z'), *B = dup_pad(d, n, '\n'), err[256];
  int mv, st, mv2, st2;
  const char *m, *m2;
  size_t ml, ml2, nh = max, nh2;
  struct phr_header H[FMAXH];
  struct fb_header G[FMAXH];
  int rp = phr_parse_response(A, n, &mv, &st, &m, &ml, H, &nh, 0);
  for (int v = 0; v < 2; v++) {
    nh2 = max;
    int rf = v ? fb_parse_response_scalar(B, n, &mv2, &st2, &m2, &ml2, G, &nh2, 0)
               : fb_parse_response(B, n, &mv2, &st2, &m2, &ml2, G, &nh2, 0);
    if (rf != rp ||
        (rp > 0 && (mv2 != mv || st2 != st || m2 - B != m - A || ml2 != ml || nh2 != nh || !same_h(H, A, G, B, nh)))) {
      snprintf(err, sizeof err, "%s (%s, max %zu): pico %d, fb %d", what, v ? "scalar" : "simd", max, rp, rf);
      fz_report("resp", err, d, n);
    }
  }
  nh = max;
  nh2 = max;
  int hp = phr_parse_headers(A, n, H, &nh, 0), hf = fb_parse_headers(B, n, G, &nh2, 0);
  if (hp != hf || (hp > 0 && (nh != nh2 || !same_h(H, A, G, B, nh)))) {
    snprintf(err, sizeof err, "headers (%s, max %zu): pico %d, fb %d", what, max, hp, hf);
    fz_report("resp", err, d, n);
  }
  free(A);
  free(B);
}

static int lc_is(const struct fb_header *h, const char *lc) {
  size_t k = strlen(lc);
  if (!h->name || h->name_len != k) return 0;
  for (size_t i = 0; i < k; i++) {
    char c = h->name[i];
    if (c >= 'A' && c <= 'Z') c += 32;
    if (c != lc[i]) return 0;
  }
  return 1;
}
static void framing(const uint8_t *d, size_t n, int req) {
  char *A = dup_pad(d, n, 'Z'), err[256];
  struct fb_header G[FMAXH];
  fbr_resp_t r = { .headers = G, .num_headers = FMAXH };
  int x = fbr_parse(A, n, req, &r, 0);
  int mv, st;
  const char *m;
  size_t ml, nh = FMAXH;
  struct fb_header G2[FMAXH];
  int y = fb_parse_response(A, n, &mv, &st, &m, &ml, G2, &nh, 0);
  int bad = 0;
  if (y <= 0) bad = !(x == y && (y == -2 || r.err == FBR_E_HEAD));
  else if (x == -1) {
    // an error after a good head must be one of the framing errors, and must be right
    int ncl = 0, te = 0;
    for (size_t i = 0; i < nh; i++) ncl += lc_is(&G2[i], "content-length"), te |= lc_is(&G2[i], "transfer-encoding");
    bad = r.err == FBR_E_STATUS ? !(st < 100 || st > 599)
          : r.err == FBR_E_TE10 ? !(te && mv == 0)
          : r.err == FBR_E_CL   ? !(ncl && !te)
                                : r.err != FBR_E_FOLD;
  } else if (x != y) bad = 1;
  else {
    int nobody = req == FBR_REQ_HEAD || st < 200 || st == 204 || st == 304;
    int tunnel = (req == FBR_REQ_CONNECT && st / 100 == 2) || st == 101;
    if (tunnel) bad = r.body != FBR_TUNNEL || (r.flags & FBR_KEEPALIVE);
    else if (nobody) bad = r.body != FBR_NONE;
    else
      bad = r.body == FBR_NONE || r.body == FBR_TUNNEL || (r.body == FBR_LENGTH) != (r.length >= 0) ||
            (r.body == FBR_CLOSE && (r.flags & FBR_KEEPALIVE));
  }
  if (bad) {
    snprintf(err, sizeof err, "fbr_parse req %d: %d (err %d body %d flags %u), fb_parse_response %d status %d", req, x,
             r.err, r.body, r.flags, y, st);
    fz_report("resp", err, d, n);
  }
  free(A);
}

static void chunked(const uint8_t *d, size_t n) {
  char err[256];
  char *in = dup_pad(d, n, 'Z'), *o1 = malloc(n + 1), *o2 = malloc(n + 1), *w = malloc(n + FPAD);
  int bl = -1, r1 = fbr_chunked(in, (int)n, o1, 1 << 30, &bl, NULL);
  // streamed: pieces of a size taken from the input itself
  int have = 0, fed = 0, data = 0, rs = 0, step = 1 + (n ? d[0] % 13 : 0);
  for (;;) {
    int add = (int)n - fed < step ? (int)n - fed : step;
    memcpy(w + have, in + fed, add);
    have += add;
    fed += add;
    int b2 = -1, prog[2];
    rs = fbr_chunked(w, have, o2 + data, 1 << 30, &b2, prog);
    if (rs > 0) {
      data += b2;
      break;
    }
    if (rs < 0) break;
    data += prog[1];
    memmove(w, w + prog[0], have - prog[0]);
    have -= prog[0];
    if (add == 0) break;
  }
  int ok = r1 > 0 ? rs > 0 && data == bl && !memcmp(o1, o2, bl) : r1 == 0 ? rs == 0 : rs == r1;
  if (!ok) {
    snprintf(err, sizeof err, "fbr_chunked streamed %d (data %d) vs one shot %d (data %d)", rs, data, r1, bl);
    fz_report("resp", err, d, n);
  }
  if (r1 > 0) {
    struct fb_header T[FMAXH];
    size_t nt = FMAXH;
    char *t = dup_pad((const uint8_t *)in + r1, n - r1, 'Z');
    int tr = fb_parse_headers(t, n - r1, T, &nt, 0);
    if (tr > 0) {
      struct phr_chunked_decoder dec = { 0 };
      dec.consume_trailer = 1;
      char *pc = malloc(n + 1);
      memcpy(pc, in, n);
      size_t sz = n;
      ssize_t pr = phr_decode_chunked(&dec, pc, &sz);
      if (pr < 0 || (int)sz != bl || memcmp(pc, o1, bl)) {
        snprintf(err, sizeof err, "fbr_chunked + trailers accept (data %d), pico %zd (data %zu)", bl, pr, sz);
        fz_report("resp", err, d, n);
      }
      free(pc);
    }
    free(t);
  }
  free(in);
  free(o1);
  free(o2);
  free(w);
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
  head(d, n, FMAXH, "whole");
  if (n) head(d, n - 1 - (n > 1 ? d[n / 2] % (n - 1) : 0), FMAXH, "prefix");
  head(d, n, n ? d[0] % 4 : 0, "small capacity");
  for (int req = 0; req < 3; req++) framing(d, n, req);
  // the body after the head (or the whole input) as a chunked body
  char *A = dup_pad(d, n, 'Z');
  struct fb_header G[FMAXH];
  fbr_resp_t r = { .headers = G, .num_headers = FMAXH };
  int x = fbr_parse(A, n, 0, &r, 0);
  free(A);
  if (x > 0) chunked(d + x, n - x);
  else chunked(d, n);
  return 0;
}
