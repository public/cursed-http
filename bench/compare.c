// Single-request parser comparison: general parsers (picohttpparser, llhttp, httparse, hparse) vs ours
// (hand-written fastparse.h, spec-generated, spec+profile-generated; plain, learned layout, learned templates).
//   cmp [bench|gate] [SHAPES=01234] [REPS=200] [ours]
//     bench: correctness gate + benchmark (default); gate: correctness gate only
//     SHAPES: corpus shapes to run (0 k6, 1 gocli -gzip, 2 gocli, 3 browser, 4 proxy: tests/testlib.h); ours: skip
//     the general parsers
// Columns: single calls per route (API shapes), and "pipelined x8": the corpus back to back, each parser called
// request after request on the remaining buffer (len > request), 8 requests per buffer. Shapes 3/4 have no API:
// requests fast_parse falls back on (a Connection other than keep-alive) are regenerated, so every parser parses every one.
// For the general parsers two costs are measured:
//   raw    the parser alone (request line + headers into arrays; llhttp: spans via callbacks)
//   +logic the same parser + exactly the routing / id / Bearer / Content-Length logic of the reference,
//          i.e. the work fast_parse does. This is the apples-to-apples number.
// Every parser+logic must agree with fast_parse on every corpus request (route, id, token, body) first.
#include "fastparse.h"
#include "fbparse.h"
#include "picohttpparser.h"
#include "testlib.h"

typedef int (*req_fn)(const char *, int, req_t *);
#define DECL_OURS(n)                                                                                                   \
  int n##_parse(const char *, int, req_t *);                                                                           \
  int n##_learn(const char *, int, req_t *);                                                                           \
  int n##_scalar(const char *, int, req_t *);                                                                          \
  int n##_tmpl(const char *, int, req_t *);                                                                            \
  void n##_tmpl_stats(uint64_t *, uint64_t *);                                                                         \
  extern const char *n##_name;
DECL_OURS(hand)
DECL_OURS(gen)
DECL_OURS(pgo)
DECL_OURS(hnc)

int lx_parse_request(const char *, size_t, const char **, size_t *, const char **, size_t *, int *, struct phr_header *,
                     size_t *, size_t);
#ifdef HAVE_HTTPARSE
int hx_parse_request(const char *, size_t, const char **, size_t *, const char **, size_t *, int *, struct phr_header *,
                     size_t *, size_t);
#endif
#ifdef HAVE_UWS
int uw_parse_request(const char *, size_t, const char **, size_t *, const char **, size_t *, int *, struct phr_header *,
                     size_t *, size_t);
int uw_parse_request_prefenced(const char *, size_t, const char **, size_t *, const char **, size_t *, int *,
                               struct phr_header *, size_t *, size_t);
#endif
#ifdef HAVE_LIGHTNING
int lt_parse_request(const char *, size_t, const char **, size_t *, const char **, size_t *, int *, struct phr_header *,
                     size_t *, size_t);
#endif
#ifdef HAVE_PICO_A64
int pa64_phr_parse_request(const char *, size_t, const char **, size_t *, const char **, size_t *, int *,
                           struct phr_header *, size_t *, size_t);
#endif
#ifdef HAVE_PICO_A64TBL
int pt64_phr_parse_request(const char *, size_t, const char **, size_t *, const char **, size_t *, int *,
                           struct phr_header *, size_t *, size_t);
#endif
#ifdef HAVE_HTTP_PARSER
int hpn_parse_request(const char *, size_t, const char **, size_t *, const char **, size_t *, int *,
                      struct phr_header *, size_t *, size_t);
#endif
#ifdef HAVE_HPARSE
int hp_parse_request(const char *, size_t, const char **, size_t *, const char **, size_t *, int *, struct phr_header *,
                     size_t *, size_t);
#endif

#define RAW(name, fn)                                                                                                  \
  __attribute__((noinline)) static int raw_##name(const char *b, int l, req_t *r) {                                    \
    const char *m, *p;                                                                                                 \
    size_t ml, pl, nh = 48;                                                                                            \
    int minor;                                                                                                         \
    struct phr_header h[48];                                                                                           \
    int ret = fn(b, l, &m, &ml, &p, &pl, &minor, h, &nh, 0);                                                           \
    r->route = (int)nh;                                                                                                \
    r->body_off = (int)pl;                                                                                             \
    return ret;                                                                                                        \
  }
#define LOGIC(name, fn)                                                                                                \
  __attribute__((noinline)) static int logic_##name(const char *b, int l, req_t *r) {                                  \
    return ref_parse_with(fn, b, l, r);                                                                                \
  }
// fbparse.h: picohttpparser's signature with struct fb_header (the same layout as struct phr_header)
_Static_assert(sizeof(struct fb_header) == sizeof(struct phr_header), "fb_header layout");
static int fbx_parse_request(const char *b, size_t l, const char **m, size_t *ml, const char **p, size_t *pl,
                             int *minor, struct phr_header *h, size_t *nh, size_t last) {
  return fb_parse_request(b, l, m, ml, p, pl, minor, (struct fb_header *)h, nh, last);
}
RAW(fbparse, fbx_parse_request)
LOGIC(fbparse, fbx_parse_request)
RAW(pico, phr_parse_request)
LOGIC(pico, phr_parse_request)
RAW(llhttp, lx_parse_request)
LOGIC(llhttp, lx_parse_request)
#ifdef HAVE_UWS
RAW(uws, uw_parse_request)
LOGIC(uws, uw_parse_request)
RAW(uwsf, uw_parse_request_prefenced)
LOGIC(uwsf, uw_parse_request_prefenced)
#endif
#ifdef HAVE_HTTPARSE
RAW(httparse, hx_parse_request)
LOGIC(httparse, hx_parse_request)
#endif
#ifdef HAVE_HPARSE
RAW(hparse, hp_parse_request)
LOGIC(hparse, hp_parse_request)
#endif
#ifdef HAVE_LIGHTNING
RAW(lightning, lt_parse_request)
LOGIC(lightning, lt_parse_request)
#endif
#ifdef HAVE_PICO_A64
RAW(pico_a64, pa64_phr_parse_request)
LOGIC(pico_a64, pa64_phr_parse_request)
#endif
#ifdef HAVE_PICO_A64TBL
RAW(pico_a64tbl, pt64_phr_parse_request)
LOGIC(pico_a64tbl, pt64_phr_parse_request)
#endif
#ifdef HAVE_HTTP_PARSER
RAW(http_parser, hpn_parse_request)
LOGIC(http_parser, hpn_parse_request)
#endif

typedef struct {
  const char *name;
  req_fn raw, full;
  int mutates;
} entry_t; // mutates: writes into the request buffer
static entry_t E[] = {
  { "fbparse.h (ours, general)", raw_fbparse, logic_fbparse },
  { "picohttpparser 465a7ff", raw_pico, logic_pico },
  { "llhttp 9.4.3", raw_llhttp, logic_llhttp },
#ifdef HAVE_UWS
  { "uWebSockets 20.80.0 (C++)", raw_uws, logic_uws, 1 },
  { "uWebSockets, fence pre-written", raw_uwsf, logic_uwsf, 2 },
#endif
#ifdef HAVE_HTTPARSE
  { "httparse 1.10.1 (Rust)", raw_httparse, logic_httparse },
#endif
#ifdef HAVE_HPARSE
  { "hparse 4fb3d83 (Zig)", raw_hparse, logic_hparse },
#endif
#ifdef HAVE_LIGHTNING
  { "lightning 7b3b0cb (C, AVX2/SSE4.2)", raw_lightning, logic_lightning },
#endif
#ifdef HAVE_PICO_A64
  { "pico, Armv8-A NEON fork", raw_pico_a64, logic_pico_a64 },
#endif
#ifdef HAVE_PICO_A64TBL
  { "pico, Armv8-A TBL fork", raw_pico_a64tbl, logic_pico_a64tbl },
#endif
#ifdef HAVE_HTTP_PARSER
  { "http-parser 2.9.4 (Node.js)", raw_http_parser, logic_http_parser },
#endif
  { "ours: fastparse.h hand-written", 0, hand_parse },
  { "ours: generated (spec)", 0, gen_parse },
  { "ours: generated (spec+profile)", 0, pgo_parse },
  { "ours: hand, learned layout", 0, hand_learn },
  { "ours: spec+profile, learned", 0, pgo_learn },
  { "ours: learned templates (no spec)", 0, hand_tmpl },
  { "ours: templates, cost model off", 0, hnc_tmpl },
  { "ours: hand, scalar backend", 0, hand_scalar },
};
#define NE ((int)(sizeof E / sizeof *E))

enum { N = 4096, STRIDE = 2048 + PAD };
static volatile long sink;
static int REPS = 200;
static double best(req_fn fn, char *mem, const int *len, const int *idx, int n) {
  double b = 1e18;
  req_t out;
  int reps = (N + n - 1) / n;
  for (int rep = 0; rep < REPS; rep++) {
    double t0 = now();
    for (int r = 0; r < reps; r++)
      for (int j = 0; j < n; j++) {
        int i = idx[j];
        int a = fn(mem + (size_t)i * STRIDE, len[i], &out);
        sink += a + out.route + out.body_off;
      }
    double dt = now() - t0;
    if (dt < b) b = dt;
  }
  return b / ((double)n * reps);
}
// pipelined: pk = the corpus back to back, st[i] = start of request i; groups of 8 requests per buffer
static double bestp(req_fn fn, const char *pk, const int *st) {
  double b = 1e18;
  req_t out;
  for (int rep = 0; rep < REPS; rep++) {
    double t0 = now();
    for (int i = 0; i < N; i += 8) {
      const char *g = pk + st[i];
      int l = st[i + 8] - st[i], u = 0;
      for (int j = 0; j < 8; j++) {
        int a = fn(g + u, l - u, &out);
        if (a <= 0) break;
        u += a;
        sink += out.route + out.body_off;
      }
    }
    double dt = now() - t0;
    if (dt < b) b = dt;
  }
  return b / N;
}

int main(int argc, char **argv) {
  int gate_only = argc > 1 && !strcmp(argv[1], "gate"), ours_only = argc > 4 && !strcmp(argv[4], "ours");
  const char *shapes = argc > 2 ? argv[2] : "01234";
  if (argc > 3) REPS = atoi(argv[3]);
  mk_tokens();
  printf("ours: %s | %s | %s\n", hand_name, gen_name, pgo_name);
  int fails = 0;
  for (int shape = 0; shape < CORPUS_N; shape++) {
    if (!strchr(shapes, '0' + shape)) continue;
    char *mem = calloc(N, STRIDE), *mem2 = calloc(N, STRIDE);
    int len[N]; // mem2: copy for parsers that write into it
    for (int i = 0; i < N; i++) {
      req_t t;
      char *b = mem + (size_t)i * STRIDE;
      do len[i] = gen(b, shape);
      while (shape >= 3 && hand_parse(b, len[i], &t) != len[i]);
    }
    memcpy(mem2, mem, (size_t)N * STRIDE);
    char *mem3 = calloc(N, STRIDE);
    memcpy(mem3, mem, (size_t)N * STRIDE); // mem3: + uWS fence written once
    for (int i = 0; i < N; i++) {
      mem3[(size_t)i * STRIDE + len[i]] = '\r';
      mem3[(size_t)i * STRIDE + len[i] + 1] = 'a';
    }
    // correctness gate: everything vs fast_parse (hand), every request
    for (int e = 0; e < NE; e++)
      for (int i = 0; i < N; i++) {
        const char *b = mem + (size_t)i * STRIDE, *b2 = (E[e].mutates == 2 ? mem3
                                                         : E[e].mutates    ? mem2
                                                                           : mem) +
                                                        (size_t)i * STRIDE;
        req_t x, y;
        int a = hand_parse(b, len[i], &x), c = E[e].full(b2, len[i], &y);
        if (E[e].mutates && c > 0) { y.tok = y.tok ? b + (y.tok - b2) : 0; } // same token, other copy
        if (!same(a, &x, c, &y) || (a > 0 && x.id != y.id) || a != len[i]) {
          if (fails++ < 10) printf("GATE FAIL %s shape %d req %d: %d vs %d\n", E[e].name, shape, i, a, c);
        }
      }
    if (gate_only) {
      free(mem);
      free(mem2);
      free(mem3);
      continue;
    }
    long tot = 0;
    for (int i = 0; i < N; i++) tot += len[i];
    printf("\n[%s corpus, avg %ld B] ns/request; general parsers: raw / +same logic\n", CORPUS_NAME[shape], tot / N);
    const int api = shape < 3, nk = api ? 4 : 1;
    if (api)
      printf("  %-32s %15s %15s %15s %15s %15s\n", "", "load-test mix", "GET /feed", "GET /posts/:id", "POST like",
             "pipelined x8");
    else printf("  %-32s %15s %15s\n", "", "mix", "pipelined x8");
    char *pk = malloc((size_t)N * STRIDE);
    int st[N + 1];
    long o = 0;
    for (int i = 0; i < N; i++) {
      st[i] = (int)o;
      memcpy(pk + o, mem + (size_t)i * STRIDE, len[i]);
      o += len[i];
    }
    st[N] = (int)o;
    memset(pk + o, 0x5a, PAD);
    int sel[4][N], ns[4] = { N, 0, 0, 0 };
    const int want[4] = { -1, R_FEED, R_GETPOST, R_LIKE };
    for (int i = 0; i < N; i++) {
      sel[0][i] = i;
      req_t t;
      hand_parse(mem + (size_t)i * STRIDE, len[i], &t);
      for (int k = 1; k < 4; k++)
        if (t.route == want[k]) sel[k][ns[k]++] = i;
    }
    for (int e = 0; e < NE; e++) {
      if (ours_only && E[e].raw) continue;
      printf("  %-32s", E[e].name);
      for (int k = 0; k < nk; k++) {
        char *m = E[e].mutates == 2 ? mem3 : E[e].mutates ? mem2 : mem;
        double f = best(E[e].full, m, len, sel[k], ns[k]);
        if (E[e].raw) printf("    %5.1f / %5.1f", best(E[e].raw, m, len, sel[k], ns[k]), f);
        else printf("    %13.1f", f);
      }
      if (E[e].mutates) printf("    %15s", "-"); // uWS writes a fence after the request: not inside a pipelined buffer
      else if (E[e].raw) printf("    %5.1f / %5.1f", bestp(E[e].raw, pk, st), bestp(E[e].full, pk, st));
      else printf("    %13.1f", bestp(E[e].full, pk, st));
      if (E[e].full == hand_tmpl || E[e].full == hnc_tmpl) {
        uint64_t h, m;
        (E[e].full == hand_tmpl ? hand_tmpl_stats : hnc_tmpl_stats)(&h, &m);
        printf("   (templates: %.1f%% of all calls hit)", 100.0 * h / (h + m + 1e-9));
      }
      printf("\n");
    }
    free(mem);
    free(mem2);
    free(mem3);
    free(pk);
  }
  printf("\nGATE FAILURES: %d\n", fails);
  return fails != 0;
}
