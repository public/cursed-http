// bench_resp.c - ns per response head: fbresp.h's fb_parse_response (SIMD, scalar) and fbr_parse (head + framing)
// against picohttpparser's phr_parse_response, llhttp in response mode and (with HAVE_HTTPARSE) Rust httparse's
// Response, all through phr_parse_response's signature, on the same heads.
//   ./bench_resp [rounds] [DIR...]   DIR: a corpus of u32-length-prefixed records (responses.dat): the captured
//                                    connections of tests/responses/corpus (heads cut out with fbr_parse), or heads
// Built-in corpora (deterministic): nginx-like static 200s, CDN responses with many and long fields, small API
// responses, and 304s. Each corpus is a set of heads, each in its own buffer with 64 bytes of padding; a pass parses
// every head once; the parsers run interleaved in a rotated order, best pass of each kept.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "picohttpparser.h"
#include "fbresp.h"
#include "resp_shapes.h"

#define PAD  64
#define MAXH 100
static double now(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return t.tv_sec * 1e9 + t.tv_nsec;
}
typedef int (*rfn)(const char *, size_t, int *, int *, const char **, size_t *, struct phr_header *, size_t *, size_t);
int lx_parse_response(const char *, size_t, int *, int *, const char **, size_t *, struct phr_header *, size_t *,
                      size_t);
#ifdef HAVE_HTTPARSE
int hx_parse_response(const char *, size_t, int *, int *, const char **, size_t *, struct phr_header *, size_t *,
                      size_t);
#endif
__attribute__((noinline)) static int fb_r(const char *b, size_t l, int *mv, int *st, const char **m, size_t *ml,
                                          struct phr_header *h, size_t *nh, size_t ll) {
  return fb_parse_response(b, l, mv, st, m, ml, (struct fb_header *)h, nh, ll);
}
__attribute__((noinline)) static int fbs_r(const char *b, size_t l, int *mv, int *st, const char **m, size_t *ml,
                                           struct phr_header *h, size_t *nh, size_t ll) {
  return fb_parse_response_scalar(b, l, mv, st, m, ml, (struct fb_header *)h, nh, ll);
}
__attribute__((noinline)) static int fbr_r(const char *b, size_t l, int *mv, int *st, const char **m, size_t *ml,
                                           struct phr_header *h, size_t *nh, size_t ll) {
  fbr_resp_t r = { .headers = (struct fb_header *)h, .num_headers = *nh };
  int x = fbr_parse(b, l, FBR_REQ_OTHER, &r, ll);
  *mv = r.minor;
  *st = r.status + r.body; // keep the framing live
  *m = r.reason;
  *ml = r.reason_len;
  *nh = r.num_headers;
  return x;
}
static const struct {
  const char *name;
  rfn f;
} P[] = {
  { "fbresp", fb_r },
  { "fbresp-scalar", fbs_r },
  { "fbr_parse", fbr_r },
  { "pico", phr_parse_response },
  { "llhttp", lx_parse_response },
#ifdef HAVE_HTTPARSE
  { "httparse", hx_parse_response },
#endif
};
enum { NP = sizeof P / sizeof *P };

typedef struct {
  char name[64];
  int n;
  char **b;
  int *len;
  long bytes;
} corpus_t;
static void add(corpus_t *c, const char *s, int n) {
  c->b = realloc(c->b, sizeof(char *) * (c->n + 1));
  c->len = realloc(c->len, sizeof(int) * (c->n + 1));
  char *b = aligned_alloc(64, (n + PAD + 63) / 64 * 64);
  memcpy(b, s, n);
  memset(b + n, 0, PAD);
  c->b[c->n] = b;
  c->len[c->n++] = n;
  c->bytes += n;
}

// ---------------- corpora from files ----------------
// records of a responses.dat: whole connections (cut every head out with fbr_parse) or heads
static void load_dir(corpus_t *c, const char *dir) {
  char path[600];
  snprintf(path, sizeof path, "%s/responses.dat", dir);
  FILE *f = fopen(path, "rb");
  if (!f) {
    fprintf(stderr, "%s: no responses.dat\n", dir);
    exit(2);
  }
  snprintf(c->name, sizeof c->name, "%s", strrchr(dir, '/') ? strrchr(dir, '/') + 1 : dir);
  unsigned char lb[4];
  while (fread(lb, 1, 4, f) == 4) {
    int n = lb[0] | lb[1] << 8 | lb[2] << 16 | lb[3] << 24;
    char *r = malloc(n + PAD);
    if (fread(r, 1, n, f) != (size_t)n) break;
    memset(r + n, 0, PAD);
    for (int off = 0; off < n;) {
      struct fb_header H[MAXH];
      fbr_resp_t x = { .headers = H, .num_headers = MAXH };
      int h = fbr_parse(r + off, n - off, FBR_REQ_OTHER, &x, 0);
      if (h <= 0) break;
      add(c, r + off, h);
      if (x.body == FBR_LENGTH) off += h + (int)x.length;
      else if (x.body == FBR_NONE) off += h;
      else if (x.body == FBR_CHUNKED) {
        static char tmp[1 << 20];
        int bl, k = fbr_chunked(r + off + h, n - off - h, tmp, sizeof tmp, &bl, NULL);
        if (k <= 0) break;
        struct fb_header T[MAXH];
        size_t nt = MAXH;
        int t = fb_parse_headers(r + off + h + k, n - off - h - k, T, &nt, 0);
        if (t <= 0) break;
        off += h + k + t;
      } else break;
    }
    free(r);
  }
  fclose(f);
}

static volatile long sink;
static double pass(const corpus_t *c, rfn f) {
  double t0 = now();
  long s = 0;
  for (int i = 0; i < c->n; i++) {
    int mv, st;
    const char *m;
    size_t ml, nh = MAXH;
    struct phr_header h[MAXH];
    s += f(c->b[i], c->len[i], &mv, &st, &m, &ml, h, &nh, 0) + (long)nh;
  }
  sink += s;
  return now() - t0;
}
static void bench(const corpus_t *c, int rounds) {
  double best[NP];
  // all parsers must accept every head (else the comparison is unfair): report, and skip a parser that does not
  for (int p = 0; p < NP; p++) {
    best[p] = 1e30;
    int bad = 0;
    for (int i = 0; i < c->n; i++) {
      int mv, st;
      const char *m;
      size_t ml, nh = MAXH;
      struct phr_header h[MAXH];
      if (P[p].f(c->b[i], c->len[i], &mv, &st, &m, &ml, h, &nh, 0) != c->len[i]) bad++;
    }
    if (bad) {
      printf("  (%s rejects %d of %d heads: not timed)\n", P[p].name, bad, c->n);
      best[p] = -1;
    }
  }
  for (int r = 0; r < rounds; r++)
    for (int k = 0; k < NP; k++) {
      int p = (k + r) % NP;
      if (best[p] < 0) continue;
      double t = pass(c, P[p].f);
      if (t < best[p]) best[p] = t;
    }
  printf("%-14s %6d heads, %5.0f B/head:", c->name, c->n, (double)c->bytes / c->n);
  double pico = best[3];
  for (int p = 0; p < NP; p++)
    if (best[p] < 0) printf("  %s -", P[p].name);
    else printf("  %s %.1f ns (%.2fx)", P[p].name, best[p] / c->n, pico / best[p]);
  printf("\n");
}

// ---------------- chunked bodies: fbr_chunked vs phr_decode_chunked ----------------
// ns per body, decode only: each round decodes a fresh copy of every body (pico and in-place decoding rewrite their
// input), and the copy, timed alone, is subtracted. Shapes as bench/bench_chunked.c, plus a trailer section.
static int ck_build(char *b, int chunks, int size, int ext, int trailer) {
  int n = 0;
  for (int c = 0; c < chunks; c++) {
    n += sprintf(b + n, ext ? "%x;name=value\r\n" : "%x\r\n", size);
    for (int i = 0; i < size; i++) b[n++] = (char)('a' + (i + c) % 26);
    n += sprintf(b + n, "\r\n");
  }
  return n + sprintf(b + n, trailer ? "0\r\nServer-Timing: app;dur=3\r\n\r\n" : "0\r\n\r\n");
}
enum { CKN = 128 };
static double ck_round(char **src, char **w, int *len, char *out, int which) {
  double t0 = now();
  long s = 0;
  for (int i = 0; i < CKN; i++) {
    memcpy(w[i], src[i], len[i]);
    int bl = 0;
    if (which == 0) s += fbr_chunked(w[i], len[i], out, 1 << 30, &bl, NULL) + bl;
    else if (which == 1) { // in place, resumable (prog): pico's decoder is in place and resumable too
      int prog[2];
      s += fbr_chunked(w[i], len[i], w[i], 1 << 30, &bl, prog) + bl;
    } else if (which == 2) {
      struct phr_chunked_decoder d = { 0 };
      d.consume_trailer = 1;
      size_t sz = len[i];
      s += phr_decode_chunked(&d, w[i], &sz) + (long)sz;
    } else s += w[i][0];
  }
  sink += s;
  return now() - t0;
}
static void bench_chunked(int rounds) {
  static const struct {
    const char *name;
    int chunks, size, ext, trailer;
  } S[] = { { "1 x 17 B", 1, 17, 0, 0 },        { "1 x 500 B", 1, 500, 0, 0 },         { "4 x 128 B", 4, 128, 0, 0 },
            { "16 x 32 B", 16, 32, 0, 0 },      { "64 x 8 B", 64, 8, 0, 0 },           { "1 x 4 KB", 1, 4096, 0, 0 },
            { "8 x 500 B, ext", 8, 500, 1, 0 }, { "4 x 128 B, trailer", 4, 128, 0, 1 } };
  printf(
      "chunked bodies, ns per body (decode only), best of %d rounds: fbr_chunked out / in place (with prog), pico in place\n",
      rounds);
  for (size_t k = 0; k < sizeof S / sizeof *S; k++) {
    static char *src[CKN], *w[CKN];
    static int len[CKN];
    static char out[1 << 16];
    for (int i = 0; i < CKN; i++) {
      src[i] = malloc(1 << 16);
      w[i] = malloc(1 << 16);
      len[i] = ck_build(src[i], S[k].chunks, S[k].size, S[k].ext, S[k].trailer);
    }
    double best[4] = { 1e30, 1e30, 1e30, 1e30 };
    for (int r = 0; r < rounds; r++)
      for (int j = 0; j < 4; j++) {
        int x = (j + r) % 4;
        double t = ck_round(src, w, len, out, x);
        if (t < best[x]) best[x] = t;
      }
    double fo = (best[0] - best[3]) / CKN, fi = (best[1] - best[3]) / CKN, pc = (best[2] - best[3]) / CKN;
    printf("  %-20s fbr-out %7.1f (%.2fx)  fbr-in %7.1f (%.2fx)  pico %7.1f\n", S[k].name, fo, pc / fo, fi, pc / fi,
           pc);
    for (int i = 0; i < CKN; i++) {
      free(src[i]);
      free(w[i]);
    }
  }
}

int main(int argc, char **argv) {
  int rounds = argc > 1 && atoi(argv[1]) > 0 ? atoi(argv[1]) : 200;
  printf("bench_resp: fbresp backend %s; ns per head, best of %d interleaved passes; (x) = pico's time / this\n",
         FB_BACKEND_NAME, rounds);
  static char s[1 << 14];
  for (int k = 0; k < RS_N; k++) {
    corpus_t c = { 0 };
    snprintf(c.name, sizeof c.name, "%s", RS_NAME[k]);
    rs_seed();
    for (int i = 0; i < 256; i++) add(&c, s, rs_shape(k, s));
    bench(&c, rounds);
  }
  for (int a = 2; a < argc; a++) {
    corpus_t c = { 0 };
    load_dir(&c, argv[a]);
    if (c.n) bench(&c, rounds);
  }
  bench_chunked(rounds > 50 ? rounds / 10 : 5);
  return 0;
}
