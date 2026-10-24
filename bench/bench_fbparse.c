// ns/request: fbparse.h vs picohttpparser and llhttp on fallback-shaped traffic and on the k6 / gocli corpora.
// make bench (see Makefile).
//   bench [REPS=200] [corpora: a substring filter, e.g. "curl,chrome"; "" = all] [parsers: substring filter on names]
// Per corpus and parser: raw = the phr_parse_request-style parse alone; +logic = the parse plus testlib's
// routing / Authorization / Content-Length logic (ref_parse_with), or fb_parse_req for us. "gate" counts
// requests where the +logic result differs from pico's ref_parse (a parser that disagrees is still timed,
// and the count says on how many requests; ours must be 0). "server path" = fast_parse, and on
// FP_FALLBACK the slow parser: what a request costs in the server.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fastparse.h"
#include "picohttpparser.h"
#include "fbparse.h"
#include "testlib.h"
#include "shapes.h"

int lx_parse_request(const char *, size_t, const char **, size_t *, const char **, size_t *, int *, struct phr_header *, size_t *, size_t);
#ifdef HAVE_HTTPARSE
int hx_parse_request(const char *, size_t, const char **, size_t *, const char **, size_t *, int *, struct phr_header *, size_t *, size_t);
#endif
#ifdef HAVE_HPARSE
int hp_parse_request(const char *, size_t, const char **, size_t *, const char **, size_t *, int *, struct phr_header *, size_t *, size_t);
#endif
// noinline like pico's external call: otherwise the raw parse inlines into the wrapper and the compiler drops
// the header-array stores nobody reads (and the work feeding them), which flatters "raw"
__attribute__((noinline)) static int fb_phr(const char *b, size_t l, const char **m, size_t *ml, const char **p, size_t *pl, int *mv, struct phr_header *h, size_t *nh, size_t ll) {
  return fb_parse_request(b, l, m, ml, p, pl, mv, (struct fb_header *)h, nh, ll); }
__attribute__((noinline)) static int fb_phr_scalar(const char *b, size_t l, const char **m, size_t *ml, const char **p, size_t *pl, int *mv, struct phr_header *h, size_t *nh, size_t ll) {
  return fb_parse_request_scalar(b, l, m, ml, p, pl, mv, (struct fb_header *)h, nh, ll); }

#define RAW(name, fn) __attribute__((noinline)) static int raw_##name(const char *b, int l, req_t *r) { \
  const char *m, *p; size_t ml, pl, nh = 48; int minor; struct phr_header h[48]; \
  int ret = fn(b, l, &m, &ml, &p, &pl, &minor, h, &nh, 0); r->route = (int)nh; r->body_off = (int)pl; return ret; }
#define LOGIC(name, fn) __attribute__((noinline)) static int logic_##name(const char *b, int l, req_t *r) { return ref_parse_with(fn, b, l, r); }
RAW(pico, phr_parse_request) LOGIC(pico, phr_parse_request)
RAW(fb, fb_phr) RAW(fbs, fb_phr_scalar)
RAW(llhttp, lx_parse_request) LOGIC(llhttp, lx_parse_request)
#ifdef HAVE_HTTPARSE
RAW(httparse, hx_parse_request) LOGIC(httparse, hx_parse_request)
#endif
#ifdef HAVE_HPARSE
RAW(hparse, hp_parse_request) LOGIC(hparse, hp_parse_request)
#endif
__attribute__((noinline)) static int logic_fb(const char *b, int l, req_t *r) { return fb_parse_req(b, l, r); }
__attribute__((noinline)) static int fb_phr_seq(const char *b, size_t l, const char **m, size_t *ml, const char **p, size_t *pl, int *mv, struct phr_header *h, size_t *nh, size_t ll) {
  return fb_parse_request_loop(0, b, l, m, ml, p, pl, mv, (struct fb_header *)h, nh, ll); }
RAW(fbq, fb_phr_seq)
__attribute__((noinline)) static int logic_fbq(const char *b, int l, req_t *r) { return fb_parse_req_loop(0, b, l, r); }
__attribute__((noinline)) static int logic_fbs(const char *b, int l, req_t *r) { return fb_parse_req_scalar(b, l, r); }
// the server path: fast_parse first, the slow parser only on FP_FALLBACK
__attribute__((noinline)) static int srv_fb(const char *b, int l, req_t *r) { int c = fast_parse(b, l, r); return c == FP_FALLBACK ? fb_parse_req(b, l, r) : c; }
__attribute__((noinline)) static int srv_pico(const char *b, int l, req_t *r) { int c = fast_parse(b, l, r); return c == FP_FALLBACK ? ref_parse(b, l, r) : c; }

typedef int (*req_fn)(const char *, int, req_t *);
typedef struct { const char *name; req_fn raw, logic; } entry_t;
static const entry_t E[] = {
  {"picohttpparser", raw_pico, logic_pico},
  {"fbparse " FB_BACKEND_NAME, raw_fb, logic_fb},
  {"fbparse scalar", raw_fbs, logic_fbs},
  {"fbparse seq loop", raw_fbq, logic_fbq},
  {"llhttp 9.4.3", raw_llhttp, logic_llhttp},
#ifdef HAVE_HTTPARSE
  {"httparse 1.10.1", raw_httparse, logic_httparse},
#endif
#ifdef HAVE_HPARSE
  {"hparse 4fb3d83", raw_hparse, logic_hparse},
#endif
};
#define NE ((int)(sizeof E / sizeof *E))

static volatile long sink;
static int REPS = 200;
static double best(req_fn fn, const char *mem, const long *off, const int *len, int n) {
  double b = 1e18; req_t out; int reps = (4096 + n - 1) / n;
  for (int rep = 0; rep < REPS; rep++) { double t0 = now();
    for (int r = 0; r < reps; r++) for (int i = 0; i < n; i++) { int a = fn(mem + off[i], len[i], &out); sink += a + out.route + out.body_off; }
    double dt = now() - t0; if (dt < b) b = dt; }
  return b / ((double)n * reps);
}

int main(int argc, char **argv) {
  if (argc > 1) REPS = atoi(argv[1]);
  const char *filter = argc > 2 ? argv[2] : "", *pfilter = argc > 3 ? argv[3] : "";
  double T0 = now();
  mk_tokens();
  printf("fbparse backend %s, fastparse.h backend %s, REPS %d\n", FB_BACKEND_NAME, FP_BACKEND_NAME, REPS);
  // corpora: the fallback shapes, then k6 / gocli (gen shapes 0..2)
  const char *CN[] = {"curl", "chrome", "firefox", "http/1.0", "long headers", "chunked POST", "odd", "k6", "gocli -gzip", "gocli"};
  int gate_total = 0;
  printf("\nns/request, raw / +logic (gate = requests where +logic differs from pico's ref_parse)\n");
  printf("%-14s %6s", "corpus", "avg B");
  for (int e = 0; e < NE; e++) if (!*pfilter || strstr(E[e].name, pfilter) || e <= 1) printf(" %22s", E[e].name);
  printf(" %18s %18s\n", "srv: fast+fb", "srv: fast+pico");
  for (int c = 0; c < 10; c++) {
    if (*filter && !strstr(filter, CN[c])) continue;
    int n = c == 4 ? 256 : 2048; long tot = 0;
    char *mem = malloc((size_t)n * (32768 + PAD)); long *off = malloc(n * sizeof(long)); int *len = malloc(n * sizeof(int));
    char *tmp = malloc(32768); long o = 0;
    for (int i = 0; i < n; i++) {
      int l = c < 7 ? gen_fb(tmp, c) : gen(tmp, c - 7);
      off[i] = o; len[i] = l; memcpy(mem + o, tmp, l); memset(mem + o + l, 0x5a, PAD); o += (l + PAD + 63) & ~63; tot += l;
    }
    printf("%-14s %6ld", CN[c], tot / n);
    int fbfail = 0, fallbacks = 0;
    for (int e = 0; e < NE; e++) {
      if (*pfilter && !strstr(E[e].name, pfilter) && e != 0 && e != 1) continue;   // pico and the default fbparse always run
      int gate = 0;
      for (int i = 0; i < n; i++) { req_t x, y; memset(&x, 0, sizeof x); memset(&y, 0, sizeof y);
        int a = ref_parse(mem + off[i], len[i], &x), b = E[e].logic(mem + off[i], len[i], &y);
        if (!same(a, &x, b, &y) || (a > 0 && x.id_ok && x.id != y.id)) gate++; }
      if (e >= 1 && e <= 3) fbfail += gate;
      double r = best(E[e].raw, mem, off, len, n), l = best(E[e].logic, mem, off, len, n);
      char cell[64]; snprintf(cell, sizeof cell, "%.1f / %.1f%s", r, l, gate ? "" : "");
      if (gate) snprintf(cell, sizeof cell, "%.1f / %.1f [%d]", r, l, gate);
      printf(" %22s", cell); fflush(stdout);
    }
    for (int i = 0; i < n; i++) { req_t t; if (fast_parse(mem + off[i], len[i], &t) == FP_FALLBACK) fallbacks++; }
    printf(" %18.1f %18.1f   (fast_parse falls back on %d%%)\n", best(srv_fb, mem, off, len, n), best(srv_pico, mem, off, len, n), 100 * fallbacks / n);
    gate_total += fbfail;
    free(mem); free(off); free(len); free(tmp);
  }
  printf("\nfbparse gate failures (must be 0): %d   (%.1f s)\n", gate_total, (now() - T0) / 1e9);
  return gate_total != 0;
}
