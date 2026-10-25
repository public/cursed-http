// bench_chp.c - ns/request of every include/chp.h backend this CPU supports, and of the inline headers built
// with this file's own flags ("inline", e.g. -march=native), on the API mix (fast_parse), the fallback shapes
// (fb_parse_request) and batches of 16 (bp_parse). Rounds are interleaved; the best of each is kept.
//   ./bench_chp [rounds]
#include "chp.h"
#include "batchparse.h"
#include "picohttpparser.h"
#include "testlib.h"
#include "shapes.h"

enum { N = 2048, STRIDE = 24576 + 64 };
static char *mem; static int len_[N]; static const char *P[N];
static volatile long sink;
typedef int (*phr_t)(const char *, size_t, const char **, size_t *, const char **, size_t *, int *, struct fb_header *, size_t *, size_t);
static int inl_fast(const char *b, int l, req_t *r) { return fast_parse(b, l, r); }
static int inl_fb(const char *b, size_t l, const char **m, size_t *ml, const char **p, size_t *pl, int *mv, struct fb_header *h, size_t *nh, size_t ll) {
  return fb_parse_request(b, l, m, ml, p, pl, mv, h, nh, ll); }
static void inl_bp(int n, const char *const *b, const int *l, req_t *o, int *r) { bp_parse(n, b, l, o, r); }

static double t_fast(int (*f)(const char *, int, req_t *), int n) {
  double best = 1e18;
  for (int pass = 0; pass < 20; pass++) { double t0 = now(); req_t r;
    for (int i = 0; i < n; i++) sink += f(P[i], len_[i], &r) + r.route;
    double dt = now() - t0; if (dt < best) best = dt; }
  return best / n;
}
static double t_fb(phr_t f, int n) {
  double best = 1e18;
  for (int pass = 0; pass < 20; pass++) { double t0 = now();
    for (int i = 0; i < n; i++) { const char *m, *p; size_t ml, pl, nh = 64; int mv; struct fb_header h[64];
      sink += f(P[i], len_[i], &m, &ml, &p, &pl, &mv, h, &nh, 0) + (long)nh; }
    double dt = now() - t0; if (dt < best) best = dt; }
  return best / n;
}
static double t_bp(void (*f)(int, const char *const *, const int *, req_t *, int *), int n) {
  double best = 1e18;
  for (int pass = 0; pass < 20; pass++) { double t0 = now(); req_t o[16]; int r[16];
    for (int i = 0; i + 16 <= n; i += 16) { f(16, P + i, len_ + i, o, r); sink += r[0] + o[15].route; }
    double dt = now() - t0; if (dt < best) best = dt; }
  return best / (n / 16 * 16);
}

int main(int argc, char **argv) {
  int rounds = argc > 1 ? atoi(argv[1]) : 5;
  const char *const *bk = chp_backends(); int nb = 0; while (bk[nb]) nb++;
  printf("chp default: %s; inline headers: fastparse %s, fbparse %s; ns/request, best of %d rounds x 20 passes\n",
         chp_backend(), FP_BACKEND_NAME, FB_BACKEND_NAME, rounds);
  mk_tokens();
  mem = calloc(N, STRIDE);
  static const char *CN[] = {"API mix (fast_parse)", "bp_parse N=16", "curl (fb)", "chrome (fb)", "firefox (fb)", "long headers (fb)"};
  printf("%-22s %9s", "", "inline"); for (int k = 0; k < nb; k++) printf(" %9s", bk[k]); printf("\n");
  for (int c = 0; c < 6; c++) {
    for (int i = 0; i < N; i++) {
      char *b = mem + (size_t)i * STRIDE;
      len_[i] = c < 2 ? gen(b, i % 3) : gen_fb(b, c == 2 ? S_CURL : c == 3 ? S_CHROME : c == 4 ? S_FIREFOX : S_LONG);
      memset(b + len_[i], 0x5a, 64); P[i] = b;
    }
    int n = c == 5 ? 256 : N;
    double best[9]; for (int k = 0; k <= nb; k++) best[k] = 1e18;
    for (int r = 0; r < rounds; r++) for (int k = 0; k <= nb; k++) {   // k == nb: inline
      if (k < nb) chp_select(bk[k]);
      double t = c == 0 ? t_fast(k < nb ? chp_fast_parse : inl_fast, n) : c == 1 ? t_bp(k < nb ? chp_bp_parse : inl_bp, n)
                        : t_fb(k < nb ? chp_fb_parse_request : inl_fb, n);
      if (t < best[k]) best[k] = t;
    }
    printf("%-22s %9.1f", CN[c], best[nb]); for (int k = 0; k < nb; k++) printf(" %9.1f", best[k]); printf("\n");
  }
  return 0;
}
