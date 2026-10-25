// ns/request of bp_parse at batch sizes 1/4/8/16/32 vs (a) fast_parse called N times and (b)
// picohttpparser (+ the same routing/header logic) called N times. Corpus as test_fastparse.c: 4096
// requests, each in its own 1088-byte-stride buffer ("different connections"), load-test mix
// (46% feed, 46% post-by-id, 7% like, 1% create) in random order. Best of R passes over the corpus.
//   ./bench [passes [corpus requests]]   BP_ONLY=<method name> runs one method, BP_N=<batch> one batch size
//   (for perf stat); the corpus size picks the cache level the buffers live in (256: L2, 4096: L3, 65536: DRAM)
#include "batchparse.h"
#include "picohttpparser.h"
#include "testlib.h"
#include "edges.h"

typedef void (*bfn)(int, const char *const *, const int *, req_t *, int *);
__attribute__((noinline)) static void B_fast(int n, const char *const *b, const int *l, req_t *o, int *r) { for (int i = 0; i < n; i++) r[i] = P_fast(b[i], l[i], &o[i]); }
__attribute__((noinline)) static void B_pico(int n, const char *const *b, const int *l, req_t *o, int *r) { for (int i = 0; i < n; i++) r[i] = ref_parse(b[i], l[i], &o[i]); }
__attribute__((noinline)) static void B_c(int n, const char *const *b, const int *l, req_t *o, int *r) { bp_parse_rl(n, b, l, o, r, BP_RL_C); }
__attribute__((noinline)) static void B_canon(int n, const char *const *b, const int *l, req_t *o, int *r) { bp_parse_rl(n, b, l, o, r, BP_RL_CANON); }
#ifdef BP_HAVE_AVX2
__attribute__((noinline)) static void B_avx2(int n, const char *const *b, const int *l, req_t *o, int *r) { bp_parse_rl(n, b, l, o, r, BP_RL_AVX2); }
__attribute__((noinline)) static void B_avx2i(int n, const char *const *b, const int *l, req_t *o, int *r) { bp_parse_rl(n, b, l, o, r, BP_RL_AVX2I); }
#endif
#ifdef BP_HAVE_Z
__attribute__((noinline)) static void B_z(int n, const char *const *b, const int *l, req_t *o, int *r) { bp_parse_rl(n, b, l, o, r, BP_RL_Z); }
#endif
static const struct { const char *name; bfn f; } M[] = {
  {"pico xN", B_pico}, {"fast xN", B_fast}, {"bp lane-C", B_c}, {"bp canon", B_canon},
#ifdef BP_HAVE_AVX2
  {"bp avx2-g", B_avx2}, {"bp avx2-i", B_avx2i},
#endif
#ifdef BP_HAVE_Z
  {"bp zmm", B_z},
#endif
};
#define NM ((int)(sizeof M / sizeof *M))

static volatile long sink;
static int PASSES = 300;

static double run(bfn f, const char **P, const int *L, int n, int B) {
  static req_t out[64]; static int ret[64]; double best = 1e18;
  int reps = n >= 4096 ? 1 : (4096 + n - 1) / n;
  for (int p = 0; p < PASSES; p++) {
    double t0 = now();
    for (int r = 0; r < reps; r++) for (int i = 0; i + B <= n; i += B) { f(B, P + i, L + i, out, ret); sink += ret[0] + out[B - 1].route; }
    double dt = now() - t0; if (dt < best) best = dt;
  }
  return best / ((double)(n / B * B) * reps);
}

int main(int argc, char **argv) {
  if (argc > 1) PASSES = atoi(argv[1]);
  int N = argc > 2 ? atoi(argv[2]) : 4096; enum { STRIDE = 1024 + 64 };
  static const char *SN[] = {"k6", "gocli -gzip", "gocli"};
  static const int BS[] = {1, 4, 8, 16, 32};
  printf("fastparse.h backend: %s; ns/request, best of %d passes over %d requests\n", FP_BACKEND_NAME, PASSES, N);
  mk_tokens();
  char *mem = calloc(N, STRIDE); int *len = malloc(N * sizeof(int));
  const char **P = malloc(N * sizeof(char *)); int *L = malloc(N * sizeof(int));
  for (int shape = 0; shape < 3; shape++) {
    for (int i = 0; i < N; i++) { len[i] = gen(mem + (size_t)i * STRIDE, shape); memset(mem + (size_t)i * STRIDE + len[i], 0x5a, 64); }
    // self-check: the batch agrees with fast_parse on this corpus
    for (int m = getenv("BP_NOCHECK") ? NM : 2; m < NM; m++) for (int i = 0; i < N; i += 32) {
      const char *bb[32]; int ll[32], rr[32]; req_t oo[32];
      for (int j = 0; j < 32; j++) { bb[j] = mem + (size_t)(i + j) * STRIDE; ll[j] = len[i + j]; }
      M[m].f(32, bb, ll, oo, rr);
      for (int j = 0; j < 32; j++) { req_t t; if (P_fast(bb[j], ll[j], &t) != rr[j] || rr[j] <= 0 || t.id != oo[j].id || t.tok_len != oo[j].tok_len) { printf("SELF-CHECK FAIL %s\n", M[m].name); return 1; } }
    }
    printf("\n[%s corpus, load-test mix]\n  %-12s", SN[shape], "batch");
    for (int m = 0; m < NM; m++) printf("%11s", M[m].name);
    printf("   bp best vs fast\n");
    for (int i = 0; i < N; i++) { P[i] = mem + (size_t)i * STRIDE; L[i] = len[i]; }
    const char *only = getenv("BP_ONLY"); int bn = getenv("BP_N") ? atoi(getenv("BP_N")) : 0;
    for (size_t b = 0; b < sizeof BS / sizeof *BS; b++) {
      if (bn && BS[b] != bn) continue;
      printf("  N=%-10d", BS[b]); double fast = 0, best = 1e18;
      for (int m = 0; m < NM; m++) { if (only && strcmp(only, M[m].name)) { printf("%11s", "-"); continue; }
        double t = run(M[m].f, P, L, N, BS[b]); printf("%11.1f", t); if (m == 1) fast = t; if (m >= 2 && t < best) best = t; }
      if (fast > 0 && best < 1e18) printf("   %+.0f%%\n", 100.0 * (best - fast) / fast); else printf("\n");
    }
    if (only || bn) continue;
    // per request type, N=16: GET-only and POST-only streams
    for (int kind = 0; kind < 2; kind++) {
      int n = 0; for (int i = 0; i < N; i++) { int post = mem[(size_t)i * STRIDE] == 'P'; if (post == kind) { P[n] = mem + (size_t)i * STRIDE; L[n++] = len[i]; } }
      printf("  %-12s", kind ? "POST N=16" : "GET N=16");
      double fast = 0, best = 1e18;
      for (int m = 0; m < NM; m++) { double t = run(M[m].f, P, L, n, 16); printf("%11.1f", t); if (m == 1) fast = t; if (m >= 2 && t < best) best = t; }
      printf("   %+.0f%%\n", 100.0 * (best - fast) / fast);
    }
  }
  return 0;
}
