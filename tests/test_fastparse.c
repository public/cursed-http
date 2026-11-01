// Differential test + benchmark for fastparse.h against picohttpparser (vendor/pico, pinned commit).
//   make test   (see Makefile); ./test_fastparse [nobench | benchonly | dumpcorpus FILE SHAPE N]
// Checks fast_parse (best backend) AND fast_parse_scalar against pico, and against each other.
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <time.h>
#ifdef HTTP_HEADER // e.g. -DHTTP_HEADER='"gen/http_gen.h"' to test a generated parser
#include HTTP_HEADER
#else
#include "fastparse.h"
#endif
#include "picohttpparser.h"

#include "testlib.h"
#include "edges.h"

static char *padded(const char *src, int len) {
  char *b = malloc(len + PAD);
  memcpy(b, src, len);
  memset(b + len, 0x5a, PAD);
  return b;
}
static int fails = 0, Q = 1; // Q: fuzz counts divided by Q ("quick" while iterating)
#define FAIL(...)                                                                                                      \
  do {                                                                                                                 \
    if (fails++ < 20) printf(__VA_ARGS__);                                                                             \
  } while (0)

// learned-layout tables: T_simd / T_scalar learn from every input the checks below see
static fp_learn_t T_simd, T_scalar, T_bench;
__attribute__((noinline)) static int P_learn(const char *b, int l, req_t *r) {
  return fast_parse_learn(b, l, r, &T_simd);
}
__attribute__((noinline)) static int P_learn_scalar(const char *b, int l, req_t *r) {
  return fast_parse_learn_scalar(b, l, r, &T_scalar);
}
__attribute__((noinline)) static int P_learn_bench(const char *b, int l, req_t *r) {
  return fast_parse_learn(b, l, r, &T_bench);
}
__attribute__((noinline)) static fp_batch_t P_many_learn(const char *b, int l, req_t *o, int m) {
  return fast_parse_many_learn(b, l, o, m, &T_simd);
}

// Up to 16 distinct layouts per route, built from the clean corpus: every input is also run through
// fp_try_layout against each of them (SIMD and scalar classify), ignoring the votes, and any layout
// that claims the input must give exactly fast_parse's result.
#define NLAY 16
static fp_layout_t LAYS[FP_NROUTES][NLAY];
static int nlays[FP_NROUTES];
static long lay_hits, lay_tries;
static void add_layout(const char *b, int len) {
  req_t r;
  int l0 = fp_reqline_canon(b, &r), c = fast_parse(b, len, &r);
  if (!l0 || c <= 0 || nlays[r.route] == NLAY) return;
  fp_layout_t L;
  memset(&L, 0, sizeof L);
  if (!fp_layout_build(b, l0, r.body_off, r.route, &L)) return;
  for (int i = 0; i < nlays[r.route]; i++) {
    fp_layout_t *o = &LAYS[r.route][i];
    if (o->hrel == L.hrel && o->n == L.n && !memcmp(o->rel, L.rel, sizeof L.rel) && !memcmp(o->k0, L.k0, sizeof L.k0) &&
        !memcmp(o->k1, L.k1, sizeof L.k1))
      return;
  }
  LAYS[r.route][nlays[r.route]++] = L;
}
static void check_layouts(const char *b, int len, int a, const req_t *f) {
  req_t r0;
  int l0 = fp_reqline_canon(b, &r0);
  if (!l0) return;
  for (int i = 0; i < nlays[r0.route]; i++)
    for (int simd = 0; simd < 2; simd++) {
      req_t r = r0;
      lay_tries++;
      int c = simd ? fp_try_layout(b, len, &r, l0, &LAYS[r0.route][i], 1)
                   : fp_try_layout(b, len, &r, l0, &LAYS[r0.route][i], 0);
      if (c == -2) continue;
      lay_hits++;
      if (!same(a, f, c, &r) || (a > 0 && f->id != r.id))
        FAIL("LAYOUT MISMATCH route %d layout %d simd %d len=%d: fast=%d layout=%d\n", r0.route, i, simd, len, a, c);
    }
}

// learned-template tables: X_simd / X_scalar learn from every input the checks below see
static fp_tmpl_t X_simd, X_scalar, X_bench, X_quick, X_quick_scalar; // X_quick*: fp_tmpl_quick on
__attribute__((noinline)) static int P_tmpl(const char *b, int l, req_t *r) {
  return fast_parse_tmpl(b, l, r, &X_simd);
}
__attribute__((noinline)) static int P_tmpl_scalar(const char *b, int l, req_t *r) {
  return fast_parse_tmpl_scalar(b, l, r, &X_scalar);
}
__attribute__((noinline)) static int P_tmpl_quick(const char *b, int l, req_t *r) {
  X_quick.quick = 128;
  return fast_parse_tmpl(b, l, r, &X_quick);
}
__attribute__((noinline)) static int P_tmpl_quick_scalar(const char *b, int l, req_t *r) {
  X_quick_scalar.quick = 64;
  return fast_parse_tmpl_scalar(b, l, r, &X_quick_scalar);
}
__attribute__((noinline)) static int P_tmpl_bench(const char *b, int l, req_t *r) {
  return fast_parse_tmpl(b, l, r, &X_bench);
}
__attribute__((noinline)) static fp_batch_t P_many_tmpl(const char *b, int l, req_t *o, int m) {
  return fast_parse_many_tmpl(b, l, o, m, &X_simd);
}

// Templates learned from every corpus shape (the learner's own output): every input is also run through
// fp_tm_try against each of them (SIMD and scalar scans/compares), ignoring order, windows and bypass, and
// any template that claims the input must give exactly fast_parse's result.
#define NTM 64
static fp_tm_t TMS[NTM];
static int ntms;
static long tm_hits, tm_tries;
static void collect_templates(const fp_tmpl_t *X) {
  for (int i = 0; i < X->n && ntms < NTM; i++) TMS[ntms++] = X->t[X->ord[i]];
  for (int i = 0; i < X->npend && ntms < NTM; i++) TMS[ntms++] = X->pend[i]; // pending: constant templates
}
static void check_templates(const char *b, int len, int a, const req_t *f) {
  int lim = len < FP_MAXHDR ? len : FP_MAXHDR;
  for (int simd = 0; simd < 2; simd++) {
    int me, pe, ok = simd ? fp_tm_rl(1, b, lim, &me, &pe) : fp_tm_rl(0, b, lim, &me, &pe);
    if (!ok) continue;
    for (int i = 0; i < ntms; i++) {
      req_t r;
      memset(&r, 0, sizeof r);
      tm_tries++;
      int c = simd ? fp_tm_try(b, len, &r, &TMS[i], 1, lim, me, pe) : fp_tm_try(b, len, &r, &TMS[i], 0, lim, me, pe);
      if (c == -2) continue;
      tm_hits++;
      if (!same(a, f, c, &r) || (a > 0 && f->id != r.id))
        FAIL("TEMPLATE MISMATCH template %d simd %d len=%d: fast=%d template=%d\n", i, simd, len, a, c);
    }
  }
}

// every core x classify combination, the learned-layout and the learned-template paths, must agree on everything,
// every input
static long quick_claims;
static void check_backends(const char *b, int len, const char *what) {
  int (*fn[])(const char *, int, req_t *) = { P_scalar,     P_cand_scalar,      P_walk_simd, P_cand_simd,
                                              P_learn,      P_learn_scalar,     P_tmpl,      P_tmpl_scalar,
                                              P_tmpl_quick, P_tmpl_quick_scalar };
  req_t f;
  memset(&f, 0, sizeof f);
  int a = P_fast(b, len, &f);
  for (int i = 0; i < 10; i++) {
    req_t s;
    memset(&s, 0, sizeof s);
    int c = fn[i](b, len, &s);
    if (!same(a, &f, c, &s) || (a > 0 && (f.id != s.id)))
      FAIL("BACKEND MISMATCH %d (%s) len=%d: fast=%d other=%d\n", i, what, len, a, c);
  }
  check_layouts(b, len, a, &f);
  check_templates(b, len, a, &f);
  // fp_quick_get (the entry batchparse.h uses): whenever it claims a canonical non-auth request,
  // fast_parse must return exactly that, with no body; both SIMD and scalar classify
  req_t q;
  int l0 = fp_reqline_canon(b, &q);
  if (l0 && !fp_route_lines(q.route))
    for (int simd = 0; simd < 2; simd++) {
      for (int cap = 0; cap < 2; cap++) { // cap: the length capped at 128, as fp_tm_quick passes it
        int lq = cap && len > 128 ? 128 : len, h = simd ? fp_quick_get(b, lq, 1) : fp_quick_get(b, lq, 0);
        if (h > 0) {
          quick_claims++;
          if (a != h || f.body_len != 0 || f.route != q.route)
            FAIL("QUICK-GET MISMATCH simd %d cap %d len=%d: quick=%d fast=%d\n", simd, cap, len, h, a);
        }
      }
    }
}

// many(): result must equal repeated single calls
static void check_many(const char *b, int len, int max) {
  req_t o1[16], o2[16];
  fp_batch_t x = P_many(b, len, o1, max), y = P_many_scalar(b, len, o2, max);
  int used = 0, n = 0, st = FP_FULL;
  while (n < max) {
    req_t t;
    int c = P_fast(b + used, len - used, &t);
    if (c <= 0) {
      st = c;
      break;
    }
    t.body_off += used;
    if (n >= x.n || !same(c, &t, c, &o1[n])) {
      FAIL("MANY FAIL req %d\n", n);
      return;
    }
    used += c;
    n++;
  }
  if (n == max && used == len) st = FP_NEED_MORE;
  if (x.n != n || x.used != used || x.status != st)
    FAIL("MANY FAIL n=%d/%d used=%d/%d st=%d/%d\n", x.n, n, x.used, used, x.status, st);
  if (y.n != x.n || y.used != x.used || y.status != x.status) FAIL("MANY SCALAR MISMATCH\n");
  req_t o3[16];
  fp_batch_t z = P_many_learn(b, len, o3, max);
  if (z.n != x.n || z.used != x.used || z.status != x.status) FAIL("MANY LEARN MISMATCH\n");
  for (int i = 0; i < x.n && i < z.n; i++)
    if (!same(1, &o1[i], 1, &o3[i]) || o1[i].id != o3[i].id) FAIL("MANY LEARN MISMATCH req %d\n", i);
  for (int i = 0; i < x.n && i < y.n; i++)
    if (!same(1, &o1[i], 1, &o2[i])) FAIL("MANY SCALAR MISMATCH req %d\n", i);
  req_t o5[16];
  X_quick.quick = 128;
  fp_batch_t v = fast_parse_many_tmpl(b, len, o5, max, &X_quick);
  if (v.n != x.n || v.used != x.used || v.status != x.status) FAIL("MANY TMPL QUICK MISMATCH\n");
  for (int i = 0; i < x.n && i < v.n; i++)
    if (!same(1, &o1[i], 1, &o5[i]) || o1[i].id != o5[i].id) FAIL("MANY TMPL QUICK MISMATCH req %d\n", i);
  req_t o4[16];
  fp_batch_t w = P_many_tmpl(b, len, o4, max);
  if (w.n != x.n || w.used != x.used || w.status != x.status) FAIL("MANY TMPL MISMATCH\n");
  for (int i = 0; i < x.n && i < w.n; i++)
    if (!same(1, &o1[i], 1, &o4[i]) || o1[i].id != o4[i].id) FAIL("MANY TMPL MISMATCH req %d\n", i);
}

static volatile long sink_g;
static double best_of(int (*fn)(const char *, int, req_t *), char *mem, size_t stride, const int *len, const int *idx,
                      int n) {
  double best = 1e18;
  req_t out;
  int reps = (4096 + n - 1) / n; // >= 4096 calls per timed run (macOS clock ~1 us)
  for (int rep = 0; rep < 300; rep++) {
    double t0 = now();
    for (int r = 0; r < reps; r++)
      for (int j = 0; j < n; j++) {
        int i = idx[j];
        int a = fn(mem + (size_t)i * stride, len[i], &out);
        sink_g += a + out.route + out.id;
      }
    double dt = now() - t0;
    if (dt < best) best = dt;
  }
  return best / ((double)n * reps);
}
static void bench_corpus(int shape) {
  enum { N = 4096, STRIDE = 1024 + PAD };
  static const char *SN[] = { "k6", "gocli -gzip", "gocli" };
  char *mem = calloc(N, STRIDE);
  int *len = malloc(N * sizeof(int)), *idx = malloc(N * sizeof(int));
  long tot = 0;
  for (int i = 0; i < N; i++) {
    len[i] = gen(mem + (size_t)i * STRIDE, shape);
    tot += len[i];
    idx[i] = i;
  }
  memset(&T_bench, 0, sizeof T_bench);
  for (int i = 0; i < N; i++) {
    req_t t;
    P_learn_bench(mem + (size_t)i * STRIDE, len[i], &t);
  } // warm-up: learn
  const char *cn[] = { "pico", "scalar", "simd", "walk+simd", "learned" };
  int (*fns[])(const char *, int, req_t *) = { ref_parse, P_scalar, P_fast, P_walk_simd, P_learn_bench };
  printf("\n[%s corpus, avg %ld B] ns/req   ", SN[shape], tot / N);
  for (int w = 0; w < 5; w++) printf("%10s", cn[w]);
  printf("\n");
  uint64_t h0 = T_bench.hits, m0 = T_bench.misses;
  printf("  %-24s", "load-test mix");
  for (int w = 0; w < 5; w++) printf("%10.1f", best_of(fns[w], mem, STRIDE, len, idx, N));
  printf("     (learned: %.0f%% fast-path hits)\n",
         100.0 * (T_bench.hits - h0) / (double)(T_bench.hits - h0 + T_bench.misses - m0 + 1e-9));
  const char *tn[] = { "", "GET /feed", "", "GET /posts/:id", "POST /posts", "POST like" };
  int rt[] = { 1, 3, 5, 4 };
  for (int k = 0; k < 4; k++) {
    int n = 0;
    long bytes = 0;
    for (int i = 0; i < N; i++) {
      req_t t;
      ref_parse(mem + (size_t)i * STRIDE, len[i], &t);
      if (t.route == rt[k]) {
        idx[n++] = i;
        bytes += len[i];
      }
    }
    if (!n) continue;
    h0 = T_bench.hits;
    m0 = T_bench.misses;
    printf("  %-15s (%3ld B)", tn[rt[k]], bytes / n);
    for (int w = 0; w < 5; w++) printf("%10.1f", best_of(fns[w], mem, STRIDE, len, idx, n));
    printf("     (learned: %.0f%% hits)\n",
           100.0 * (T_bench.hits - h0) / (double)(T_bench.hits - h0 + T_bench.misses - m0 + 1e-9));
    for (int i = 0; i < N; i++) idx[i] = i;
  }
  // pipelined: the corpus back to back, 8 requests per call
  char *pk = malloc(tot + PAD);
  int *st = malloc((N + 1) * sizeof(int));
  long o = 0;
  for (int i = 0; i < N; i++) {
    st[i] = (int)o;
    memcpy(pk + o, mem + (size_t)i * STRIDE, len[i]);
    o += len[i];
  }
  st[N] = (int)o;
  memset(pk + o, 0x5a, PAD);
  printf("  %-24s", "pipelined x8 (many)");
  for (int w = 0; w < 5; w++) {
    double best = 1e18;
    req_t ob[8];
    for (int rep = 0; rep < 300; rep++) {
      double t0 = now();
      for (int i = 0; i < N; i += 8) {
        const char *b = pk + st[i];
        int l = st[i + 8 > N ? N : i + 8] - st[i];
        fp_batch_t x = { 0, 0, 0 };
        if (w == 0) {
          int u = 0;
          for (int j = 0; j < 8; j++) {
            int a = ref_parse(b + u, l - u, &ob[j]);
            if (a <= 0) break;
            u += a;
          }
          x.used = u;
        } else if (w == 1) x = P_many_scalar(b, l, ob, 8);
        else if (w == 2) x = P_many(b, l, ob, 8);
        else if (w == 3) {
          int u = 0;
          for (int j = 0; j < 8; j++) {
            int a = P_walk_simd(b + u, l - u, &ob[j]);
            if (a <= 0) break;
            u += a;
          }
          x.used = u;
        } else x = fast_parse_many_learn(b, l, ob, 8, &T_bench);
        sink_g += x.n + x.used + ob[0].route;
      }
      double dt = now() - t0;
      if (dt < best) best = dt;
    }
    printf("%10.1f", best / N);
  }
  printf("\n");
  free(pk);
  free(st);
  free(mem);
  free(len);
  free(idx);
}

int main(int argc, char **argv) {
  int bench = !(argc > 1 && (!strcmp(argv[1], "nobench") || !strcmp(argv[1], "quick")));
  if (argc > 1 && !strcmp(argv[1], "quick")) Q = 10;
  printf("backend: %s\n", FP_BACKEND_NAME);
  mk_tokens();
  if (argc > 4 && !strcmp(argv[1], "dumpcorpus")) { // dumpcorpus FILE SHAPE N: a capture for gen/httpgen.py profile
    FILE *f = fopen(argv[2], "wb");
    char buf[1100];
    for (int i = 0, n = atoi(argv[4]); i < n; i++) fwrite(buf, 1, gen(buf, atoi(argv[3])), f);
    fclose(f);
    return 0;
  }
  printf("parser: %s\n", FP_SPEC_NAME);
  if (argc > 1 && !strcmp(argv[1], "benchonly")) {
    for (int shape = 0; shape < 3; shape++) bench_corpus(shape);
    return 0;
  }
  { // templates for the direct check: what the learner makes of each corpus shape, plus pending ones
    static fp_tmpl_t X;
    static char rq[2048 + PAD];
    for (int shape = 0; shape < CORPUS_N; shape++) {
      memset(&X, 0, sizeof X);
      for (int i = 0; i < 4096; i++) {
        req_t t;
        int l = gen(rq, shape);
        fast_parse_tmpl(rq, l, &t, &X);
      }
      collect_templates(&X);
    }
    int k[4] = { 0 };
    for (int i = 0; i < ntms; i++) {
      k[0] += TMS[i].mslot;
      k[1] += TMS[i].cl_kind == 1;
      k[2] += TMS[i].cl_kind == 2;
      k[3] += TMS[i].au_kind;
    }
    printf("templates for the direct check: %d (method slot %d, constant CL %d, CL slot %d, Authorization %d)\n", ntms,
           k[0], k[1], k[2], k[3]);
  }


  // 0. mask primitive vs a byte loop, random bytes biased to CR/LF
  for (int it = 0; it < 200000 / Q; it++) {
    char blk[128 + PAD];
    for (int i = 0; i < 128 + PAD; i++) {
      uint32_t x = rnd();
      blk[i] = (x & 3) == 0 ? '\r' : (x & 3) == 1 ? '\n' : (char)(x >> 8);
    }
    if (it & 1)
      for (int i = 0; i < 64; i++)
        if (rnd() % 3 == 0)
          blk[i] = "aAcCtT\x01\x03\x14\x41\x43\x54\xe1\xe3\xf4 \t\x20\x21\x00\x1f\x80\xa0"[rnd() % 23];
    if (it & 2)
      for (int i = 0; i < 64; i++)
        if (blk[i] == '\r' && rnd() % 4) blk[i + 1] = '\n'; // mostly CRLF
    uint64_t lf = 0, ct = 0, l1, c1, l2, c2;
    for (int i = 0; i < 64; i++) {
      unsigned char x = (unsigned char)blk[i];
      int f = x | 0x20;
      lf |= (uint64_t)(x == '\n') << i;
      ct |= (uint64_t)(f == 'c' || f == 't' || x <= 0x20) << i;
    }
    fp_cls64(1, blk, &l1, &c1);
    fp_cls64(0, blk, &l2, &c2);
    if ((l1 ^ lf) | (l2 ^ lf) | (fp_lf64(1, blk) ^ lf) | (fp_lf64(0, blk) ^ lf) | (c1 ^ ct) | (c2 ^ ct)) {
      FAIL("MASK FAIL it %d\n", it);
      break;
    }
    // bare-CR accumulator: bytes [0, n) of one or two blocks, vs a byte loop (the byte after n is read)
    int n = 1 + rnd() % 64, two = rnd() & 1, want = 0;
    for (int i = 0; i < (two ? 64 + n : n); i++) want |= blk[i] == '\r' && blk[i + 1] != '\n';
    for (int simd = 0; simd < 2; simd++) {
      fp_cracc_t a;
      fp_cr_init(simd, &a);
      if (two) {
        fp_cr_add(simd, &a, blk, 64);
        fp_cr_add(simd, &a, blk + 64, n);
      } else fp_cr_add(simd, &a, blk, n);
      if (fp_cr_any(simd, &a) != want) {
        FAIL("BARE-CR FAIL it %d simd %d n %d\n", it, simd, n);
        break;
      }
    }
  }
  // digits vs plain loop
  for (int it = 0; it < 200000 / Q; it++) {
    char d[32];
    int n = rnd() % 19;
    for (int i = 0; i < 32; i++) d[i] = (rnd() % 23 == 0) ? "/:a.-/ 0"[rnd() % 8] : (char)('0' + rnd() % 10);
    if (rnd() % 5 == 0)
      for (int i = 0; i < n && i < 10; i++) d[i] = '0';
    int o1, o2;
    int64_t v1 = fp_digits(d, n, &o1), v2 = ref_digits(d, n, &o2);
    if (o1 != o2 || (o1 && v1 != v2)) {
      FAIL("DIGITS FAIL n=%d %.*s: %d/%lld vs %d/%lld\n", n, n, d, o1, (long long)v1, o2, (long long)v2);
      break;
    }
  }
  printf("primitives: failures %d\n", fails);

  // 1. edge cases: expected semantics + agreement with reference
  for (size_t i = 0; i < sizeof EDGES / sizeof *EDGES; i++) {
    const edge_t *e = &EDGES[i];
    int len = strlen(e->req);
    char *b = padded(e->req, len);
    req_t f = { 0 }, g = { 0 };
    int a = P_fast(b, len, &f), c = ref_parse(b, len, &g);
    int want = e->ret >= 1 ? len : e->ret, ok;
    if (want > 0)
      ok = a == len &&
           (e->ret == 2   ? c == FP_FALLBACK
            : e->ret == 3 ? c == -2
                          : same(a, &f, c, &g)) &&
           f.route == e->route && f.id_ok == e->id_ok && (!e->id_ok || f.id == e->id) && f.auth == e->auth &&
           (!e->tok || (f.tok_len == (int)strlen(e->tok) && !memcmp(f.tok, e->tok, f.tok_len)));
    else ok = a == want;
    if (!ok)
      FAIL("EDGE FAIL %zu: fast=%d ref=%d route=%d id_ok=%d id=%lld auth=%d\n  %s\n", i, a, c, f.route, f.id_ok,
           (long long)f.id, f.auth, e->req);
    check_backends(b, len, "edge");
    // every truncation must be NEED_MORE in both
    for (int t = 0; t < len; t++) {
      req_t x, y;
      int p = P_fast(b, t, &x), q = ref_parse(b, t, &y);
      check_backends(b, t, "edge-trunc");
      if (want <= 0 && p == want) continue; // e.g. duplicate CL is detected before the body is complete
      if (p != FP_NEED_MORE || (q != FP_NEED_MORE && q != -2 && !(e->ret == 2 && q == FP_FALLBACK))) {
        FAIL("TRUNC FAIL edge %zu at %d: fast=%d ref=%d\n", i, t, p, q);
        break;
      }
    }
    free(b);
  }
  // block-boundary sweep: every alignment of line starts, header names and "\r\n\r\n" vs 64-byte blocks
  for (int pad = 0; pad < 200; pad++)
    for (int v = 0; v < 4; v++) {
      char req[600];
      int n = sprintf(
          req, "%s HTTP/1.1\r\nX: %.*s\r\n%s", v & 1 ? "POST /posts" : "POST /posts/12/like", pad,
          "pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp"
          "pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp",
          v & 2 ? "Content-Length: 2\r\nAuthorization: Bearer tk\r\n\r\nhi"
                : "authorization: Bearer tk\r\ncontent-length: 2\r\n\r\nhi");
      char *b = padded(req, n);
      req_t f, g;
      int a = P_fast(b, n, &f), c = ref_parse(b, n, &g);
      if (a != n || !same(a, &f, c, &g) || !f.auth || f.tok_len != 2 || f.body_len != 2)
        FAIL("SWEEP FAIL pad %d v %d: %d %d\n", pad, v, a, c);
      check_backends(b, n, "sweep");
      for (int t = 0; t < n; t++) {
        if (P_fast(b, t, &f) != FP_NEED_MORE) {
          FAIL("SWEEP TRUNC FAIL pad %d at %d\n", pad, t);
          break;
        }
        check_backends(b, t, "sweep-trunc");
      }
      free(b);
    }
  printf("edge cases: %zu + 800 boundary sweeps, failures so far: %d\n", sizeof EDGES / sizeof *EDGES, fails);

  // 2. corpus: agreement, every truncation, and pipelined pairs
  enum { N = 4096, STRIDE = 2048 + PAD };
  char *mem = calloc(N, STRIDE);
  int *len = malloc(N * sizeof(int)), *shp = malloc(N * sizeof(int));
  long tot = 0;
  // correctness corpus: k6 3/8, gocli -gzip 1/8, gocli 1/8, browser 1/4, proxy 1/8
  static const int SHMIX[8] = { 0, 1, 0, 2, 3, 0, 4, 3 };
  for (int i = 0; i < N; i++) {
    shp[i] = SHMIX[i & 7];
    len[i] = gen(mem + (size_t)i * STRIDE, shp[i]);
    tot += len[i];
  }
  for (int i = 0; i < N; i++) add_layout(mem + (size_t)i * STRIDE, len[i]);
  printf("layouts for the direct check: feed %d, getpost %d, create %d, like %d\n", nlays[R_FEED], nlays[R_GETPOST],
         nlays[R_CREATE], nlays[R_LIKE]);
  int fb = 0;
  for (int i = 0; i < N; i++) {
    char *b = mem + (size_t)i * STRIDE;
    req_t f, g;
    int a = P_fast(b, len[i], &f), c = ref_parse(b, len[i], &g);
    if (a == FP_FALLBACK) fb++;
    // no-spec shapes: "GET / HTTP/1.1" falls back (l0 < 16, see fp_reqline), and so does a Connection other
    // than keep-alive
    if ((!same(a, &f, c, &g) || a != len[i]) && !(shp[i] >= 3 && a == FP_FALLBACK))
      FAIL("CORPUS FAIL %d: fast=%d ref=%d len=%d\n", i, a, c, len[i]);
    check_backends(b, len[i], "corpus");
    if (i < 300)
      for (int t = 0; t < len[i]; t++) {
        int p = P_fast(b, t, &f);
        check_backends(b, t, "corpus-trunc");
        if (p != FP_NEED_MORE) {
          FAIL("TRUNC FAIL corpus %d at %d -> %d\n", i, t, p);
          break;
        }
      }
  }
  char *pbuf = malloc(32 * 1024 + PAD);
  for (int i = 0; i + 1 < 600; i += 2) { // pipelined: second request directly after the first
    int l1 = len[i], l2 = len[i + 1];
    {
      req_t t;
      if (P_fast(mem + (size_t)i * STRIDE, l1, &t) != l1 || P_fast(mem + (size_t)(i + 1) * STRIDE, l2, &t) != l2)
        continue;
    }
    memcpy(pbuf, mem + (size_t)i * STRIDE, l1);
    memcpy(pbuf + l1, mem + (size_t)(i + 1) * STRIDE, l2);
    memset(pbuf + l1 + l2, 0x5a, PAD);
    req_t f, g;
    int a = P_fast(pbuf, l1 + l2, &f), c = ref_parse(pbuf, l1 + l2, &g);
    if (a != l1 || c != l1 || !same(a, &f, c, &g)) {
      FAIL("PIPELINE FAIL %d: %d %d\n", i, a, c);
      break;
    }
    req_t f2, g2;
    int a2 = P_fast(pbuf + a, l1 + l2 - a, &f2), c2 = ref_parse(pbuf + a, l1 + l2 - a, &g2);
    if (a2 != l2 || !same(a2, &f2, c2, &g2)) {
      FAIL("PIPELINE FAIL (2nd) %d: %d %d\n", i, a2, c2);
      break;
    }
    req_t o[2];
    fp_batch_t x = P_many(pbuf, l1 + l2, o, 2);
    if (x.n != 2 || x.used != l1 + l2 || x.status != FP_NEED_MORE || o[1].body_off != l1 + f2.body_off) {
      FAIL("PIPELINE many FAIL %d\n", i);
      break;
    }
    check_many(pbuf, l1 + l2, 2);
    for (int t = 0; t < l1 + l2; t++) check_many(pbuf, t, 2); // every truncation of the pair
  }
  // pipelined batches of 1..12 random requests, random truncation of the tail, random max
  for (int it = 0; it < 30000 / Q; it++) {
    int k = 1 + rnd() % 12, l = 0;
    for (int j = 0; j < k; j++) {
      int i = rnd() % N;
      memcpy(pbuf + l, mem + (size_t)i * STRIDE, len[i]);
      l += len[i];
    }
    if (rnd() & 1) l -= rnd() % (l + 1);
    if (rnd() % 8 == 0 && l > 0) pbuf[rnd() % l] = " \r\n:/0aT"[rnd() % 8]; // occasional damage
    memset(pbuf + l, 0x5a, PAD);
    check_many(pbuf, l, 1 + rnd() % 16);
  }
  printf("corpus: %d requests, avg %.0f bytes, fallbacks %d, total failures %d\n", N, (double)tot / N, fb, fails);

  // 3. fuzz: mutate + truncate; must never disagree when pico accepts and fast doesn't fall back
  const char *alpha = " \r\n:/\tabcABC0123456789-.Bearer";
  long agree = 0, skip_inval = 0, skip_fb = 0, dis = 0;
  uint64_t h0 = T_simd.hits, m0 = T_simd.misses, hs0 = T_scalar.hits;
  for (int it = 0; it < 300000 / Q; it++) {
    int i = rnd() % N;
    char tmp[2048];
    int l = len[i];
    memcpy(tmp, mem + (size_t)i * STRIDE, l);
    int k = 1 + rnd() % 3;
    for (int j = 0; j < k; j++) tmp[rnd() % l] = alpha[rnd() % strlen(alpha)];
    if (rnd() & 1) l = rnd() % (l + 1);
    char *b = padded(tmp, l);
    req_t f, g;
    int a = P_fast(b, l, &f), c = ref_parse(b, l, &g);
    check_backends(b, l, "fuzz");
    if (c == -2) skip_inval++;
    else if (a == FP_FALLBACK || c == FP_FALLBACK) skip_fb++;
    else if (same(a, &f, c, &g)) agree++;
    else {
      {
        dis++;
        FAIL("FUZZ DISAGREE fast=%d ref=%d id_ok %d/%d id %lld/%lld line: ", a, c, f.id_ok, g.id_ok, (long long)f.id,
             (long long)g.id);
        if (fails <= 20) {
          for (int t = 0; t < 60 && t < l && b[t] != '\n'; t++)
            printf(b[t] < 32 ? "\\x%02x" : "%c", (unsigned char)b[t]);
          printf("\n");
        }
      }
    }
    free(b);
  }
  printf("fuzz 300k: agree %ld, pico-invalid (relaxed accept) %ld, fallback %ld, disagree %ld\n", agree, skip_inval,
         skip_fb, dis);
  printf(
      "learned layout during fuzz: %llu fast-path results (scalar table %llu), %llu misses on complete requests; whole run: %llu hits, %llu relearns\n",
      (unsigned long long)(T_simd.hits - h0), (unsigned long long)(T_scalar.hits - hs0),
      (unsigned long long)(T_simd.misses - m0), (unsigned long long)T_simd.hits, (unsigned long long)T_simd.learned);
  // 3b. layout-preserving fuzz: never touches CR/LF, keeps the length: mostly lands on a learned
  // layout, so header names/values, CL digits, tokens and ids are mutated under the fast path
  long h_before = lay_hits, agree2 = 0;
  for (int it = 0; it < 300000 / Q; it++) {
    int i = rnd() % N;
    char tmp[2048];
    int l = len[i];
    memcpy(tmp, mem + (size_t)i * STRIDE, l);
    int k = 1 + rnd() % 3;
    for (int j = 0; j < k; j++) {
      int p = rnd() % l;
      if (tmp[p] == '\r' || tmp[p] == '\n') continue;
      tmp[p] = (rnd() & 3) ? " :/\tabcABC0123456789-.BearerxX"[rnd() % 31] : (char)(tmp[p] ^ 0x20);
    }
    if (rnd() % 4 == 0) l = rnd() % (l + 1);
    char *b = padded(tmp, l);
    req_t f, g;
    int a = P_fast(b, l, &f), c = ref_parse(b, l, &g);
    check_backends(b, l, "layout-fuzz");
    if (c != -2 && a != FP_FALLBACK && c != FP_FALLBACK) {
      if (same(a, &f, c, &g)) agree2++;
      else FAIL("LAYOUT-FUZZ DISAGREE vs pico: fast=%d ref=%d\n", a, c);
    }
    free(b);
  }
  // 3c. header swap: rewrite one header line into another (relevant) name, same line length, so the
  // LF layout is unchanged but what the line *is* changes (catches too-short line keys)
  static const char *NAMES[] = { "Content-Length",
                                 "content-length",
                                 "CONTENT-LENGTH",
                                 "Content-Lengtx",
                                 "Transfer-Encoding",
                                 "transfer-encodinX",
                                 "Authorization",
                                 "authorization",
                                 "Authorizatio",
                                 "Accept",
                                 "Cookie",
                                 "Content-Type",
                                 "TE",
                                 "a",
                                 "c",
                                 "t",
                                 "Host" };
  long swaps = 0, h_sw = lay_hits;
  for (int it = 0; it < 200000 / Q; it++) {
    int i = rnd() % N;
    char tmp[2048];
    int l = len[i];
    memcpy(tmp, mem + (size_t)i * STRIDE, l);
    int nl = 0, st[64];
    for (int p = 0; p < l && nl < 64; p++)
      if (tmp[p] == '\n') st[nl++] = p + 1;
    if (nl < 3) continue;
    int li = rnd() % (nl - 2), s = st[li], e = st[li + 1] - 2; // header line [s, e) + CRLF
    if (e <= s || tmp[e] != '\r') continue;
    const char *nm = NAMES[rnd() % (sizeof NAMES / sizeof *NAMES)];
    int n = strlen(nm), L = e - s;
    if (n + 2 > L) continue;
    memcpy(tmp + s, nm, n);
    tmp[s + n] = ':';
    tmp[s + n + 1] = ' ';
    for (int p = s + n + 2; p < e; p++) tmp[p] = (rnd() % 4) ? '0' + rnd() % 10 : "Bearer x "[rnd() % 9];
    if (rnd() % 3 == 0) {
      int p = s + n + 2;
      if (p + 7 <= e) memcpy(tmp + p, "Bearer ", 7);
    }
    char *b = padded(tmp, l);
    swaps++;
    check_backends(b, l, "swap");
    free(b);
  }
  printf("header-swap fuzz: %ld requests, %ld matched a layout\n", swaps, lay_hits - h_sw);
  printf(
      "layout-preserving fuzz 300k: %ld agree with pico; direct layout check: %ld of %ld tries matched a layout in this phase (%ld in the whole run), all identical to fast_parse\n",
      agree2, lay_hits - h_before, lay_tries, lay_hits);
  printf(
      "fp_quick_get claimed %ld inputs, all identical to fast_parse; fp_tmpl_quick tables: %llu quick, %llu template hits\n",
      quick_claims, (unsigned long long)(X_quick.quicks + X_quick_scalar.quicks),
      (unsigned long long)(X_quick.hits + X_quick_scalar.hits));
  // 3d. slot fuzz: mutate what templates leave variable (the method, the path, header values after the
  // colon): insert / delete / replace bytes, including CR, LF, SP, HT, ':', NUL and high bytes, so line
  // lengths change and slots end early or late; then everything above, and every template directly
  long tm_h0 = tm_hits, agree3 = 0, xh0 = (long)X_simd.hits;
  static const char SLOTB[] = "abcXYZ019/._-=;,\"Bearer  ::\t\r\n\r\n\x00\x7f\x80\xff+%?&";
  for (int it = 0; it < 300000 / Q; it++) {
    int i = rnd() % N;
    char tmp[2048 + 64];
    int l = len[i];
    memcpy(tmp, mem + (size_t)i * STRIDE, l);
    for (int k = 1 + rnd() % 3; k > 0; k--) {
      int nl = 0, st[64];
      st[nl++] = 0;
      for (int p = 0; p < l && nl < 64; p++)
        if (tmp[p] == '\n') st[nl++] = p + 1;
      int li = rnd() % (nl > 1 ? nl - 1 : 1), s0 = st[li], e0 = li + 1 < nl ? st[li + 1] - 1 : l, a0,
          a1;        // line [s0, e0)
      if (li == 0) { // request line: the method or the path
        const char *sp = memchr(tmp, ' ', e0);
        if (!sp) continue;
        int me = (int)(sp - tmp);
        const char *sp2 = memchr(tmp + me + 1, ' ', e0 - me - 1);
        int pe = sp2 ? (int)(sp2 - tmp) : e0;
        if (rnd() & 1) {
          a0 = 0;
          a1 = me;
        } else {
          a0 = me + 1;
          a1 = pe;
        }
      } else {
        const char *c = memchr(tmp + s0, ':', e0 - s0);
        if (!c) continue;
        a0 = (int)(c - tmp) + 1;
        a1 = e0 > a0 && tmp[e0 - 1] == '\r' ? e0 - 1 : e0;
      }
      int at = a0 + (a1 > a0 ? (int)(rnd() % (a1 - a0 + 1)) : 0), op = rnd() % 3,
          n = 1 + (rnd() % 4 == 0 ? rnd() % 40 : rnd() % 3);
      if (op == 0 && l + n < 2048) { // insert n bytes
        memmove(tmp + at + n, tmp + at, l - at);
        for (int j = 0; j < n; j++)
          tmp[at + j] = (rnd() % 6) ? "abcdefXYZ0123456789-._~/"[rnd() % 24] : SLOTB[rnd() % (sizeof SLOTB - 1)];
        l += n;
      } else if (op == 1) { // delete up to n bytes of the slot
        if (n > a1 - at) n = a1 - at;
        if (n > 0) {
          memmove(tmp + at, tmp + at + n, l - at - n);
          l -= n;
        }
      } else if (at < a1) tmp[at] = SLOTB[rnd() % (sizeof SLOTB - 1)];
    }
    if (rnd() % 4 == 0) l = rnd() % (l + 1);
    char *b = padded(tmp, l);
    req_t f, g;
    int a = P_fast(b, l, &f), c = ref_parse(b, l, &g);
    check_backends(b, l, "slot-fuzz");
    if (c != -2 && a != FP_FALLBACK && c != FP_FALLBACK) {
      if (same(a, &f, c, &g)) agree3++;
      else FAIL("SLOT-FUZZ DISAGREE vs pico: fast=%d ref=%d\n", a, c);
    }
    free(b);
  }
  printf(
      "slot fuzz %d: %ld agree with pico; %ld direct template matches, %ld learned-table hits, all identical to fast_parse\n",
      300000 / Q, agree3, tm_hits - tm_h0, (long)X_simd.hits - xh0);
  // 3e. traffic shifts: one table sees mload -gzip, then browser, proxy, k6, mload -gzip again; every result
  // checked (SIMD and scalar tables); per phase the hit rate and the requests until 90% of a window hits
  {
    static fp_tmpl_t XS, XS0;
    static char rq[2048 + PAD];
    static const int PH[] = { 1, 3, 4, 0, 1 };
    memset(&XS, 0, sizeof XS);
    memset(&XS0, 0, sizeof XS0);
    for (int ph = 0; ph < 5; ph++) {
      long h0 = (long)XS.hits, warm = -1, wh = 0;
      int nreq = 6000;
      for (int i = 0; i < nreq; i++) {
        int l = gen(rq, PH[ph]);
        memset(rq + l, 0x5a, PAD);
        req_t f, x, y;
        int a = P_fast(rq, l, &f), hb = (int)XS.hits, c = fast_parse_tmpl(rq, l, &x, &XS),
            d = fast_parse_tmpl_scalar(rq, l, &y, &XS0);
        if (!same(a, &f, c, &x) || !same(a, &f, d, &y) || (a > 0 && (f.id != x.id || f.id != y.id)))
          FAIL("SHIFT MISMATCH phase %d req %d: fast=%d tmpl=%d scalar=%d\n", ph, i, a, c, d);
        wh += (int)XS.hits - hb;
        if (i % 256 == 255) {
          if (warm < 0 && wh >= 230) warm = i - 255;
          wh = 0;
        }
      }
      printf(
          "shift phase %d (%s): %.1f%% template hits, 90%% of a 256-request window after %ld requests; table: %d templates, %llu learned, %llu evicted, bypass %d\n",
          ph, CORPUS_NAME[PH[ph]], 100.0 * ((long)XS.hits - h0) / nreq, warm, XS.n, (unsigned long long)XS.learned,
          (unsigned long long)XS.evicted, XS.bypass);
    }
  }
  printf(
      "learned templates: %ld of %ld direct tries matched over the whole run, all identical to fast_parse; tables: %llu hits / %llu misses, %llu learned, %llu generalized, %llu evicted\n",
      tm_hits, tm_tries, (unsigned long long)X_simd.hits, (unsigned long long)X_simd.misses,
      (unsigned long long)X_simd.learned, (unsigned long long)X_simd.generalized, (unsigned long long)X_simd.evicted);
  // 3f. Connection (RFC 9112 9.6): templates keep a Connection line constant, since fast_parse's verdict reads its
  // whole value. Learn from keep-alive requests, then the same skeleton with other values: every result ==
  // fast_parse, nothing but keep-alive ever completes, and no template ever makes a Connection value a slot
  {
    static fp_tmpl_t XC;
    static const char *CV[] = { "keep-alive", "Keep-Alive",        "close",       "keep-alive, Upgrade",
                                "upgrade",    "keep-alivf",        " keep-alive", "keep-alive\t",
                                "",           "keep-alive, close", "KEEP-ALIVE",  "Close" };
    memset(&XC, 0, sizeof XC);
    long claimed = 0;
    for (int it = 0; it < 4000 / (Q > 1 ? 4 : 1); it++) {
      char rq[512 + PAD];
      const char *v = it < 64 ? "keep-alive" : CV[rnd() % 12];
      int pos = rnd() % 3,
          l = sprintf(rq, "GET /item/%u HTTP/1.1\r\nHost: shop.example.com\r\nUser-Agent: t/1\r\nAccept: */*\r\n\r\n",
                      rnd() % 100000);
      char hd[160]; // "Connection: v" goes in as header line 1, 2 or 3
      sprintf(hd, "Connection: %s\r\n", v);
      char *ins = strstr(rq, pos == 0 ? "Host:" : pos == 1 ? "User-Agent:" : "Accept:");
      int off = (int)(ins - rq), hl = (int)strlen(hd);
      memmove(rq + off + hl, rq + off, l - off);
      memcpy(rq + off, hd, hl);
      l += hl;
      memset(rq + l, 0x5a, PAD);
      req_t f, x;
      int a = P_fast(rq, l, &f), h0 = (int)XC.hits, c = fast_parse_tmpl(rq, l, &x, &XC);
      if (!same(a, &f, c, &x) || (a > 0 && f.id != x.id)) FAIL("CONNECTION MISMATCH %s: fast=%d tmpl=%d\n", v, a, c);
      if (c > 0 && strcmp(v, "keep-alive") && strcmp(v, "Keep-Alive") && strcmp(v, "KEEP-ALIVE") &&
          strcmp(v, " keep-alive") && strcmp(v, "keep-alive\t"))
        FAIL("CONNECTION %s completed (%d)\n", v, c);
      claimed += (int)XC.hits != h0;
      check_backends(rq, l, "connection");
    }
    for (int i = 0; i < XC.n; i++)
      for (int k = 0; k < XC.t[i].nl; k++)
        if (XC.t[i].lj[k] >= 0 && fp_tm_is_conn(XC.t[i].rep, XC.t[i].ls[k], XC.t[i].le[k]))
          FAIL("CONNECTION line became a slot (template %d line %d)\n", i, k);
    printf("Connection variants: %ld template results, all identical to fast_parse; %d templates\n", claimed, XC.n);
  }
  // 3g. caller hints: fp_tmpl_mode (OFF never hits, ALWAYS never bypasses) and fp_tmpl_seed (templates before
  // any traffic; pinned ones survive other traffic); every result checked against fast_parse
  {
    static fp_tmpl_t XM[3], XP;
    static char rq[2048 + PAD], sb[512 * 1100 + PAD];
    long hits[3] = { 0 }, bypassed = 0;
    for (int m = 0; m < 3; m++) {
      memset(&XM[m], 0, sizeof XM[m]);
      fp_tmpl_mode(&XM[m], m);
    }
    for (int i = 0; i < 20000 / Q; i++) {
      int l = gen(rq, 4);
      memset(rq + l, 0x5a, PAD);
      req_t f, x;
      int a = P_fast(rq, l, &f);
      for (int m = 0; m < 3; m++) {
        long h = (long)XM[m].hits;
        int c = fast_parse_tmpl(rq, l, &x, &XM[m]);
        hits[m] += (long)XM[m].hits - h;
        if (!same(a, &f, c, &x) || (a > 0 && f.id != x.id))
          FAIL("MODE MISMATCH mode %d req %d: fast=%d tmpl=%d\n", m, i, a, c);
      }
      bypassed += XM[FP_TM_ALWAYS].bypass;
    }
    if (hits[FP_TM_OFF] || bypassed || !hits[FP_TM_ALWAYS])
      FAIL("MODES: off hit %ld times, always bypassed %ld times, always hit %ld\n", hits[FP_TM_OFF], bypassed,
           hits[FP_TM_ALWAYS]);
    printf("modes on proxy traffic: auto %ld hits (bypass %d), always %ld, off %ld\n", hits[0], XM[0].bypass, hits[1],
           hits[2]);
    int u = 0;
    for (int i = 0; i < 512; i++) u += gen(sb + u, 1); // 512 mload -gzip requests, back to back
    memset(sb + u, 0x5a, PAD);
    memset(&XP, 0, sizeof XP);
    fp_tmpl_quick(&XP, -1); // templates only
    int nt = fp_tmpl_seed(&XP, sb, u, 1), npin = 0;
    for (int i = 0; i < XP.n; i++) npin += XP.t[i].pin;
    long h0 = (long)XP.hits;
    int first = -1;
    for (int ph = 0; ph < 2; ph++)
      for (int i = 0; i < 6000; i++) { // mload -gzip (seeded), then proxy (can't evict the pins)
        int l = gen(rq, ph ? 4 : 1);
        memset(rq + l, 0x5a, PAD);
        req_t f, x;
        int a = P_fast(rq, l, &f), c = fast_parse_tmpl(rq, l, &x, &XP);
        if (!same(a, &f, c, &x) || (a > 0 && f.id != x.id))
          FAIL("SEED MISMATCH phase %d req %d: fast=%d tmpl=%d\n", ph, i, a, c);
        if (ph == 0 && first < 0 && XP.hits > (uint64_t)h0) first = i;
      }
    int still = 0;
    for (int i = 0; i < XP.n; i++) still += XP.t[i].pin;
    if (!nt || npin != nt || still != npin || first != 0)
      FAIL("SEED: %d templates, %d pinned, %d pinned after proxy traffic, first hit at request %d\n", nt, npin, still,
           first);
    printf(
        "seeded from 512 requests: %d templates, all pinned; first request hit; %d still pinned after 6000 proxy requests\n",
        nt, still);
  }
  printf("TOTAL FAILURES: %d\n", fails);
  if (!bench) return fails != 0;

  // 4. benchmark: one corpus per request shape, best of 300 passes, load-test mix in random order
  free(mem);
  free(len);
  for (int shape = 0; shape < 3; shape++) bench_corpus(shape);
  (void)sink_g;
  return fails != 0;
}
