// Single-request parser comparison: general parsers (picohttpparser, llhttp) vs ours
// (hand-written fastparse.h, spec-generated, spec+profile-generated; plain and learned-layout).
//   cmp [bench|gate] [SHAPES=012] [REPS=200] [ours]
//     bench: correctness gate + benchmark (default); gate: correctness gate only
//     SHAPES: corpus shapes to run (0 k6, 1 gocli -gzip, 2 gocli); ours: skip the general parsers
// For the general parsers two costs are measured:
//   raw    the parser alone (request line + headers into arrays; llhttp: spans via callbacks)
//   +logic the same parser + exactly the routing / id / Bearer / Content-Length logic of the reference,
//          i.e. the work fast_parse does. This is the apples-to-apples number.
// Every parser+logic must agree with fast_parse on every corpus request (route, id, token, body) first.
#include "fastparse.h"
#include "picohttpparser.h"
#include "testlib.h"

typedef int (*req_fn)(const char *, int, req_t *);
#define DECL_OURS(n) int n##_parse(const char *, int, req_t *); int n##_learn(const char *, int, req_t *); \
                     int n##_scalar(const char *, int, req_t *); extern const char *n##_name;
DECL_OURS(hand) DECL_OURS(gen) DECL_OURS(pgo)

int lx_parse_request(const char *, size_t, const char **, size_t *, const char **, size_t *, int *, struct phr_header *, size_t *, size_t);

#define RAW(name, fn) __attribute__((noinline)) static int raw_##name(const char *b, int l, req_t *r) { \
  const char *m, *p; size_t ml, pl, nh = 48; int minor; struct phr_header h[48]; \
  int ret = fn(b, l, &m, &ml, &p, &pl, &minor, h, &nh, 0); r->route = (int)nh; r->body_off = (int)pl; return ret; }
#define LOGIC(name, fn) __attribute__((noinline)) static int logic_##name(const char *b, int l, req_t *r) { return ref_parse_with(fn, b, l, r); }
RAW(pico, phr_parse_request) LOGIC(pico, phr_parse_request)
RAW(llhttp, lx_parse_request) LOGIC(llhttp, lx_parse_request)

typedef struct { const char *name; req_fn raw, full; } entry_t;
static entry_t E[] = {
  {"picohttpparser 465a7ff", raw_pico, logic_pico},
  {"llhttp 9.4.3", raw_llhttp, logic_llhttp},
  {"ours: fastparse.h hand-written", 0, hand_parse},
  {"ours: generated (spec)", 0, gen_parse},
  {"ours: generated (spec+profile)", 0, pgo_parse},
  {"ours: hand, learned layout", 0, hand_learn},
  {"ours: spec+profile, learned", 0, pgo_learn},
  {"ours: hand, scalar backend", 0, hand_scalar},
};
#define NE ((int)(sizeof E / sizeof *E))

enum { N = 4096, STRIDE = 1024 + PAD };
static volatile long sink;
static int REPS = 200;
static double best(req_fn fn, char *mem, const int *len, const int *idx, int n) {
  double b = 1e18; req_t out; int reps = (N + n - 1) / n;
  for (int rep = 0; rep < REPS; rep++) { double t0 = now();
    for (int r = 0; r < reps; r++) for (int j = 0; j < n; j++) { int i = idx[j]; int a = fn(mem + (size_t)i * STRIDE, len[i], &out); sink += a + out.route + out.body_off; }
    double dt = now() - t0; if (dt < b) b = dt; }
  return b / ((double)n * reps);
}

int main(int argc, char **argv) {
  int gate_only = argc > 1 && !strcmp(argv[1], "gate"), ours_only = argc > 4 && !strcmp(argv[4], "ours");
  const char *shapes = argc > 2 ? argv[2] : "012";
  if (argc > 3) REPS = atoi(argv[3]);
  mk_tokens();
  printf("ours: %s | %s | %s\n", hand_name, gen_name, pgo_name);
  int fails = 0;
  static const char *SN[] = {"k6", "gocli -gzip", "gocli"};
  for (int shape = 0; shape < 3; shape++) {
    if (!strchr(shapes, '0' + shape)) continue;
    char *mem = calloc(N, STRIDE); int len[N];
    for (int i = 0; i < N; i++) { len[i] = gen(mem + (size_t)i * STRIDE, shape); }
    // correctness gate: everything vs fast_parse (hand), every request
    for (int e = 0; e < NE; e++) for (int i = 0; i < N; i++) {
      const char *b = mem + (size_t)i * STRIDE, *b2 = b; req_t x, y;
      int a = hand_parse(b, len[i], &x), c = E[e].full(b2, len[i], &y);
      if (!same(a, &x, c, &y) || (a > 0 && x.id != y.id) || a != len[i]) { if (fails++ < 10) printf("GATE FAIL %s shape %d req %d: %d vs %d\n", E[e].name, shape, i, a, c); }
    }
    if (gate_only) { free(mem); continue; }
    long tot = 0; for (int i = 0; i < N; i++) tot += len[i];
    printf("\n[%s corpus, avg %ld B] ns/request; general parsers: raw / +same logic\n", SN[shape], tot / N);
    printf("  %-32s %15s %15s %15s %15s\n", "", "load-test mix", "GET /feed", "GET /posts/:id", "POST like");
    int sel[4][N], ns[4] = {N, 0, 0, 0}; const int want[4] = {-1, R_FEED, R_GETPOST, R_LIKE};
    for (int i = 0; i < N; i++) { sel[0][i] = i; req_t t; hand_parse(mem + (size_t)i * STRIDE, len[i], &t);
      for (int k = 1; k < 4; k++) if (t.route == want[k]) sel[k][ns[k]++] = i; }
    for (int e = 0; e < NE; e++) {
      if (ours_only && E[e].raw) continue;
      printf("  %-32s", E[e].name);
      for (int k = 0; k < 4; k++) {
        char *m = mem;
        double f = best(E[e].full, m, len, sel[k], ns[k]);
        if (E[e].raw) printf("    %5.1f / %5.1f", best(E[e].raw, m, len, sel[k], ns[k]), f); else printf("    %13.1f", f);
      }
      printf("\n");
    }
    free(mem);
  }
  printf("\nGATE FAILURES: %d\n", fails);
  return fails != 0;
}
