// Self-check of gen/httpgen.py on any spec (see Makefile target gencheck):
//  1. the generated fp_route equals httpgen's Python router model on random vectors (stdin);
//  2. for every vector, the request line "M P HTTP/1.1\r\n\r\n" gives the same result through the
//     canonical templates (fp_reqline_canon) and through the general path (fp_reqline), and the
//     full fast_parse agrees with the general route.
#include <stdio.h>
#include <stdlib.h>
#include HTTP_HEADER
static int unhex(const char *h, char *out) {
  int n = 0;
  for (; h[0] && h[1]; h += 2) {
    unsigned x;
    sscanf(h, "%2x", &x);
    out[n++] = (char)x;
  }
  return n;
}
int main(void) {
  char mh[64], ph[512], m[32], p[256];
  int want, wok;
  long long wid;
  long n = 0, canon = 0, fails = 0;
  while (scanf("%63s %511s %d %d %lld", mh, ph, &want, &wok, &wid) == 5) {
    int ml = unhex(mh, m), pl = unhex(ph, p);
    n++;
    req_t r;
    memset(&r, 0, sizeof r);
    fp_route(m, ml, p, pl, &r);
    if (r.route != want || r.id_ok != wok || (wok && r.id != wid)) {
      if (fails++ < 10)
        printf("ROUTE MISMATCH %.*s %.*s: %d/%d/%lld want %d/%d/%lld\n", ml, m, pl, p, r.route, r.id_ok,
               (long long)r.id, want, wok, wid);
    }
    char buf[512 + 64];
    int len = sprintf(buf, "%.*s %.*s HTTP/1.1\r\n\r\n", ml, m, pl, p);
    memset(buf + len, 0x5a, 64);
    req_t c, g;
    memset(&c, 0, sizeof c);
    memset(&g, 0, sizeof g);
    int l0c = fp_reqline_canon(buf, &c), l0 = (int)(strchr(buf, '\n') - buf), gr = fp_reqline(buf, l0, &g);
    if (l0c) {
      canon++;
      if (l0c != l0 || gr != 0 || c.route != g.route || c.id_ok != g.id_ok || (c.id_ok && c.id != g.id)) {
        if (fails++ < 10) printf("CANON MISMATCH %.*s %.*s\n", ml, m, pl, p);
      }
    }
    req_t f;
    int a = fast_parse(buf, len, &f);
    if (gr == 0 && (a != len || f.route != g.route || f.id_ok != g.id_ok || (f.id_ok && f.id != g.id))) {
      if (fails++ < 10) printf("PARSE MISMATCH %.*s %.*s\n", ml, m, pl, p);
    }
  }
  printf("%s: %ld vectors, %ld via canonical templates, failures %ld\n", FP_SPEC_NAME, n, canon, fails);
  return fails != 0;
}
