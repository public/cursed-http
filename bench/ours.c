// One of our parsers in its own translation unit (fastparse.h and the generated headers define the same
// symbols). Built several times with -DOURS_HDR='"..."' -DOURS=name.
#include OURS_HDR
#include <stdio.h>
#define CAT2(a, b) a##_##b
#define CAT(a, b)  CAT2(a, b)
static fp_learn_t T;
static fp_tmpl_t X;
__attribute__((noinline)) int CAT(OURS, parse)(const char *b, int l, req_t *r) { return fast_parse(b, l, r); }
__attribute__((noinline)) int CAT(OURS, learn)(const char *b, int l, req_t *r) { return fast_parse_learn(b, l, r, &T); }
__attribute__((noinline)) int CAT(OURS, tmpl)(const char *b, int l, req_t *r) { return fast_parse_tmpl(b, l, r, &X); }
void CAT(OURS, tmpl_stats)(uint64_t *h, uint64_t *m) { // hits / misses, and what the cost model decided
  *h = X.hits;
  *m = X.misses;
  int slow = 0;
  for (int i = 0; i < X.n; i++) slow += X.t[i].slow;
  printf("   [%d templates, %d off, bypass %d, saving %.1f cycles/request over %d samples]", X.n, slow, X.bypass,
         X.nsave ? (double)X.save / X.nsave : 0.0, X.nsave);
}
__attribute__((noinline)) int CAT(OURS, scalar)(const char *b, int l, req_t *r) { return fast_parse_scalar(b, l, r); }
const char *CAT(OURS, name) = FP_SPEC_NAME " / " FP_BACKEND_NAME;
