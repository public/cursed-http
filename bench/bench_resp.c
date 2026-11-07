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

#define PAD 64
#define MAXH 100
static double now(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return t.tv_sec * 1e9 + t.tv_nsec;
}
static uint64_t rs = 0x9E3779B97F4A7C15ull;
static uint32_t rnd(void) {
  rs ^= rs << 13;
  rs ^= rs >> 7;
  rs ^= rs << 17;
  return (uint32_t)rs;
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
} P[] = { { "fbresp", fb_r },     { "fbresp-scalar", fbs_r }, { "fbr_parse", fbr_r },
          { "pico", phr_parse_response }, { "llhttp", lx_parse_response },
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

// ---------------- built-in shapes ----------------
static const char *DAYS[] = { "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun" };
static int date(char *s) {
  return sprintf(s, "%s, %02u Nov 2026 %02u:%02u:%02u GMT", DAYS[rnd() % 7], 1 + rnd() % 28, rnd() % 24, rnd() % 60,
                 rnd() % 60);
}
static void hex(char *s, int n) {
  for (int i = 0; i < n; i++) s[i] = "0123456789abcdef"[rnd() % 16];
  s[n] = 0;
}
static int shape_nginx(char *s) {
  char d[64], e[16];
  date(d);
  hex(e, 8);
  return sprintf(s,
                 "HTTP/1.1 200 OK\r\nServer: nginx/1.26.%u\r\nDate: %s\r\nContent-Type: text/html\r\n"
                 "Content-Length: %u\r\nLast-Modified: %s\r\nConnection: keep-alive\r\nETag: \"%s-%x\"\r\n"
                 "Accept-Ranges: bytes\r\n\r\n",
                 rnd() % 3, d, 100 + rnd() % 90000, d, e, rnd() % 99999);
}
static int shape_cdn(char *s) {
  char d[64], id[64], ck[200], csp[600];
  date(d);
  hex(id, 40);
  hex(ck, 120);
  int n = sprintf(csp, "default-src 'self'; script-src 'self' 'nonce-%.16s'", ck);
  for (int i = 0; i < 6 + (int)(rnd() % 6); i++) n += sprintf(csp + n, " https://cdn%u.example-cdn.net", rnd() % 100);
  return sprintf(s,
                 "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nTransfer-Encoding: chunked\r\n"
                 "Connection: keep-alive\r\nDate: %s\r\nCache-Control: private, max-age=0, must-revalidate\r\n"
                 "Content-Security-Policy: %s\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; "
                 "preload\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n"
                 "Referrer-Policy: strict-origin-when-cross-origin\r\nSet-Cookie: session=%s; Path=/; Secure; "
                 "HttpOnly; SameSite=Lax\r\nSet-Cookie: _ga=GA1.1.%u.%u; Path=/; Max-Age=63072000\r\n"
                 "Vary: Accept-Encoding\r\nContent-Encoding: gzip\r\nX-Cache: Hit from cloudfront\r\n"
                 "Via: 1.1 %.32s.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Pop: LHR61-P%u\r\nX-Amz-Cf-Id: %s==\r\n"
                 "Age: %u\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nServer-Timing: cdn-cache; desc=HIT, edge; dur=%u\r\n"
                 "\r\n",
                 d, csp, ck, rnd(), rnd(), id, 1 + rnd() % 9, id, rnd() % 5000, rnd() % 40);
}
static int shape_api(char *s) {
  char d[64], rid[40];
  date(d);
  hex(rid, 32);
  return sprintf(s,
                 "HTTP/1.1 %s\r\nContent-Type: application/json\r\nContent-Length: %u\r\nDate: %s\r\n"
                 "X-Request-Id: %s\r\nConnection: keep-alive\r\n\r\n",
                 rnd() % 8 ? "200 OK" : "404 Not Found", 2 + rnd() % 4000, d, rid);
}
static int shape_304(char *s) {
  char d[64], e[24];
  date(d);
  hex(e, 16);
  return sprintf(s, "HTTP/1.1 304 Not Modified\r\nDate: %s\r\nETag: W/\"%s\"\r\nCache-Control: max-age=%u\r\n\r\n", d,
                 e, rnd() % 86400);
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

int main(int argc, char **argv) {
  int rounds = argc > 1 && atoi(argv[1]) > 0 ? atoi(argv[1]) : 200;
  printf("bench_resp: fbresp backend %s; ns per head, best of %d interleaved passes; (x) = pico's time / this\n",
         FB_BACKEND_NAME, rounds);
  static char s[1 << 14];
  int (*SH[])(char *) = { shape_nginx, shape_cdn, shape_api, shape_304 };
  const char *SN[] = { "nginx-static", "cdn", "api", "304" };
  for (int k = 0; k < 4; k++) {
    corpus_t c = { 0 };
    snprintf(c.name, sizeof c.name, "%s", SN[k]);
    for (int i = 0; i < 256; i++) add(&c, s, SH[k](s));
    bench(&c, rounds);
  }
  for (int a = 2; a < argc; a++) {
    corpus_t c = { 0 };
    load_dir(&c, argv[a]);
    if (c.n) bench(&c, rounds);
  }
  return 0;
}
