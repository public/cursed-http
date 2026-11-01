// Differential test for include/chp.h (build/libchp.a): every backend this CPU supports must return exactly
// what the scalar backend returns, for every entry point (return codes, every field, every pointer).
// Inputs: the client corpus, the fallback shapes, the edge cases, their truncations, mutations and pipelined
// pairs, each in an exact-size allocation with 64 bytes of padding.   make test (x86: also under qemu/Docker)
//   ./test_chp [quick]
#include "chp.h"
#include "picohttpparser.h"
#include "testlib.h"
#include "shapes.h"
#include "edges.h"

static int fails;
#define FAIL(...)                                                                                                      \
  do {                                                                                                                 \
    if (fails++ < 20) printf(__VA_ARGS__);                                                                             \
  } while (0)
static const char *const *BK; // supported backends, best first; the last one is always scalar
static int NB;

static int same_req(int a, const req_t *x, const char *bx, int b, const req_t *y, const char *by) {
  if (a != b) return 0;
  if (a <= 0) return 1;
  return x->route == y->route && x->id_ok == y->id_ok && (!x->id_ok || x->id == y->id) && x->auth == y->auth &&
         x->tok_len == y->tok_len && (!x->auth || x->tok - bx == y->tok - by) && x->body_off == y->body_off &&
         x->body_len == y->body_len;
}
// one input against every backend; ref = scalar
static void check(const char *src, int len, const char *what) {
  char *b = malloc(len + PAD);
  memcpy(b, src, len);
  memset(b + len, 0x5a, PAD);
  struct {
    int fp, fl, fr, fx, ph;
    req_t rp, rl, rr, rx;
    fb_info_t ix;
    fp_batch_t many;
    req_t mo[8];
    const char *m, *p;
    size_t ml, pl, nh;
    int mv;
    struct fb_header h[48];
    int bret[3];
    req_t bout[3];
  } R[8];
  for (int k = 0; k < NB; k++) {
    if (chp_select(BK[k])) {
      FAIL("chp_select(%s) failed\n", BK[k]);
      break;
    }
    memset(&R[k], 0, sizeof R[k]);
    fp_learn_t *T = calloc(1, sizeof *T);
    R[k].fp = chp_fast_parse(b, len, &R[k].rp);
    chp_fast_parse_learn(b, len, &R[k].rl, T);
    R[k].fl = chp_fast_parse_learn(b, len, &R[k].rl, T); // learn, then use
    free(T);
    R[k].fr = chp_fb_parse_req(b, len, &R[k].rr);
    R[k].fx = chp_fb_parse_req_ex(b, len, &R[k].rx, &R[k].ix);
    R[k].many = chp_fast_parse_many(b, len, R[k].mo, 8);
    R[k].nh = 48;
    R[k].ph = chp_fb_parse_request(b, len, &R[k].m, &R[k].ml, &R[k].p, &R[k].pl, &R[k].mv, R[k].h, &R[k].nh, 0);
    const char *bb[3] = { b, b, b };
    int ll[3] = { len, len / 2, len ? len - 1 : 0 };
    chp_bp_parse(3, bb, ll, R[k].bout, R[k].bret);
  }
  int s = NB - 1;
  for (int k = 0; k < s; k++) {
    const char *n = BK[k];
    if (!same_req(R[s].fp, &R[s].rp, b, R[k].fp, &R[k].rp, b))
      FAIL("%s fast_parse %d, scalar %d (%s, len %d)\n", n, R[k].fp, R[s].fp, what, len);
    if (!same_req(R[s].fl, &R[s].rl, b, R[k].fl, &R[k].rl, b))
      FAIL("%s fast_parse_learn %d, scalar %d (%s)\n", n, R[k].fl, R[s].fl, what);
    if (!same_req(R[s].fr, &R[s].rr, b, R[k].fr, &R[k].rr, b))
      FAIL("%s fb_parse_req %d, scalar %d (%s)\n", n, R[k].fr, R[s].fr, what);
    if (!same_req(R[s].fx, &R[s].rx, b, R[k].fx, &R[k].rx, b) || R[s].ix.flags != R[k].ix.flags ||
        R[s].ix.minor != R[k].ix.minor || R[s].ix.total != R[k].ix.total)
      FAIL("%s fb_parse_req_ex %d, scalar %d (%s)\n", n, R[k].fx, R[s].fx, what);
    if (R[s].many.n != R[k].many.n || R[s].many.used != R[k].many.used || R[s].many.status != R[k].many.status)
      FAIL("%s fast_parse_many differs (%s)\n", n, what);
    for (int i = 0; i < R[s].many.n && i < R[k].many.n; i++)
      if (!same_req(1, &R[s].mo[i], b, 1, &R[k].mo[i], b))
        FAIL("%s fast_parse_many request %d differs (%s)\n", n, i, what);
    int bad = R[s].ph != R[k].ph;
    if (!bad && R[s].ph > 0) {
      bad = R[s].m != R[k].m || R[s].ml != R[k].ml || R[s].p != R[k].p || R[s].pl != R[k].pl || R[s].mv != R[k].mv ||
            R[s].nh != R[k].nh;
      for (size_t i = 0; !bad && i < R[s].nh; i++)
        bad = R[s].h[i].name != R[k].h[i].name || R[s].h[i].name_len != R[k].h[i].name_len ||
              R[s].h[i].value != R[k].h[i].value || R[s].h[i].value_len != R[k].h[i].value_len;
    }
    if (bad) FAIL("%s fb_parse_request %d, scalar %d (%s, len %d)\n", n, R[k].ph, R[s].ph, what, len);
    for (int i = 0; i < 3; i++)
      if (!same_req(R[s].bret[i], &R[s].bout[i], b, R[k].bret[i], &R[k].bout[i], b))
        FAIL("%s bp_parse lane %d differs (%s)\n", n, i, what);
  }
  free(b);
}

int main(int argc, char **argv) {
  int quick = argc > 1 && !strcmp(argv[1], "quick"), MUT = quick ? 20000 : 200000;
  BK = chp_backends();
  for (NB = 0; BK[NB]; NB++);
  printf("chp: default backend %s; checking", chp_backend());
  for (int k = 0; k < NB; k++) printf(" %s", BK[k]);
  printf(" (vs scalar)\n");
  if (NB < 1 || NB > 8 || strcmp(BK[NB - 1], "scalar")) {
    printf("unexpected backend list\nTOTAL FAILURES: 1\n");
    return 1;
  }
  mk_tokens();
  static char a[32768], c[65536];
  long n = 0;
  for (size_t i = 0; i < sizeof EDGES / sizeof *EDGES; i++) {
    int l = (int)strlen(EDGES[i].req);
    for (int t = 0; t <= l; t++) {
      check(EDGES[i].req, t, "edge");
      n++;
    }
  }
  for (int shape = 0; shape < 3; shape++)
    for (int i = 0; i < 300; i++) {
      int l = gen(a, shape);
      check(a, l, "corpus");
      n++;
      if (i < 20)
        for (int t = 0; t < l; t++) {
          check(a, t, "corpus-trunc");
          n++;
        }
    }
  for (int shape = 0; shape < S_NSHAPES; shape++)
    for (int i = 0; i < 100; i++) {
      int l = gen_fb(a, shape);
      check(a, l, SHAPE_NAME[shape]);
      n++;
      if (i < 3)
        for (int t = 0; t < l; t += 1 + l / 400) {
          check(a, t, "shape-trunc");
          n++;
        }
    }
  const char *alpha = " \r\n:/\tabcABC0123456789-.Bearer\x7f\x00\x1f\x80";
  for (int it = 0; it < MUT; it++) {
    int l = (it & 1) ? gen_fb(a, it % S_NSHAPES) : gen(a, it % 3);
    for (int j = 1 + rnd() % 3; j--;) a[rnd() % l] = alpha[rnd() % 34];
    if (rnd() & 1) l = rnd() % (l + 1);
    check(a, l, "mutation");
    n++;
  }
  for (int i = 0; i < 2000; i++) { // pipelined pairs
    int l = gen(a, i % 3), m = gen_fb(c, i % S_NSHAPES);
    if (l + m < (int)sizeof c) {
      memmove(c + l, c, m);
      memcpy(c, a, l);
      check(c, l + m, "pipelined");
      n++;
    }
  }
  printf("%ld inputs x %d backends\nTOTAL FAILURES: %d\n", n, NB, fails);
  return fails != 0;
}
