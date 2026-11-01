// batchparse.h on a generated parser for a different spec (gen/toy_spec.json), built with -DBP_CANON_ONLY:
// every lane must equal fast_parse on the same buffer. Inputs: canonical and near-canonical requests of the
// toy spec's routes, mutated, truncated, in random mixed batches of 1..100 lanes.
//   cc -Ibuild -Iinclude -DBP_CANON_ONLY '-DBP_HTTP_H="check_toy_spec.h"' tests/test_batch_spec.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "batchparse.h"

static uint64_t rs = 0x9E3779B97F4A7C15ull;
static uint32_t rnd(void) {
  rs ^= rs << 13;
  rs ^= rs >> 7;
  rs ^= rs << 17;
  return (uint32_t)rs;
}

static int same(int a, const req_t *x, int b, const req_t *y) {
  if (a != b) return 0;
  if (a <= 0) return 1;
  return x->route == y->route && x->id_ok == y->id_ok && (!x->id_ok || x->id == y->id) && x->auth == y->auth &&
         x->tok_len == y->tok_len && (!x->auth || x->tok == y->tok) && x->body_off == y->body_off &&
         x->body_len == y->body_len;
}

static int gen(char *s) {
  static const char *lines[] = { "GET /a",
                                 "GET /items/new",
                                 "GET /items/%u",
                                 "GET /items/7",
                                 "GET /items/%u/sub",
                                 "PUT /items/%u",
                                 "DELETE /items/%u/x",
                                 "POST /very/long/literal/path/for/chunking",
                                 "GET /n/%u2",
                                 "GET /nope",
                                 "PATCH /items/%u",
                                 "GET /items/%u/",
                                 "GET  /a" };
  char line[96];
  snprintf(line, sizeof line, lines[rnd() % 13], rnd() % 7 ? 1 + rnd() % 99999999u : 0u);
  int n = sprintf(s, "%s HTTP/1.1\r\nHost: example.test\r\n", line);
  if (rnd() % 2) n += sprintf(s + n, "Authorization: Bearer tok%u.x.y\r\n", rnd());
  if (rnd() % 3 == 0) {
    int bl = rnd() % 40;
    n += sprintf(s + n, "Content-Length: %d\r\n\r\n", bl);
    memset(s + n, 'b', bl);
    return n + bl;
  }
  return n + sprintf(s + n, "\r\n");
}

int main(void) {
  enum { MAXL = 100, CAP = 600 };
  static char mem[MAXL][CAP + 64];
  const char *buf[MAXL];
  int len[MAXL], ret[MAXL];
  req_t out[MAXL];
  long lanes = 0, ok = 0;
  int fails = 0;
  for (int it = 0; it < 200000; it++) {
    int n = 1 + (rnd() % 16 == 0 ? rnd() % MAXL : rnd() % 32);
    for (int i = 0; i < n; i++) {
      char *s = mem[i];
      int l = gen(s);
      for (int m = rnd() % 4 == 0 ? 1 + rnd() % 3 : 0; m--;) s[rnd() % l] = " \r\n:/0123456789aZ"[rnd() % 17];
      if (rnd() % 4 == 0) l = rnd() % (l + 1);
      memset(s + l, rnd() % 2 ? 0x5a : (int)(rnd() & 0xff), 64);
      buf[i] = s;
      len[i] = l;
    }
    bp_parse(n, buf, len, out, ret);
    for (int i = 0; i < n; i++) {
      req_t r;
      int c = fast_parse(buf[i], len[i], &r);
      lanes++;
      ok += c > 0;
      if (!same(c, &r, ret[i], &out[i]) && fails++ < 10)
        printf("LANE MISMATCH: fast_parse %d, bp_parse %d, len %d\n", c, ret[i], len[i]);
    }
  }
  printf("spec: %s, %ld lanes (%ld complete requests) vs fast_parse\n", FP_SPEC_NAME, lanes, ok);
  printf("TOTAL FAILURES: %d\n", fails);
  return fails != 0;
}
