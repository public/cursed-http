// test_hdrspec.c - headers asked for by name in the spec (a route's "headers"), on a generated parser
// (gen/headers_spec.json -> build/fastparse_hdr.h, included through -DBP_HTTP_H). Random requests on every route
// carry the spec's headers (any case, OWS, empty and long values, duplicates: the first wins), lookalike
// distractors ("X-Request-Idz", "X-Request-Id :", the -Extra variant) and the usual other headers.
//   1. the reference (pico + logic, tests/testlib.h) gives exactly what the request was built with
//   2. fb_parse_req == the reference, exactly (every field, every pointer)
//   3. fast_parse == the reference or FP_FALLBACK, and never falls back on a clean request (no distractors)
//   4. batchparse == fast_parse lane by lane; every request and some truncations through fuzz/oracle.h
//   ./test_hdrspec [quick]
#include "oracle.h"
#if FP_NHDR == 0
#error "build against the generated header: -Ibuild -DBP_HTTP_H='\"fastparse_hdr.h\"' (gen/headers_spec.json)"
#endif

static int fails;
#define FAIL(...)                                                                                                      \
  do {                                                                                                                 \
    if (fails++ < 30) printf(__VA_ARGS__);                                                                             \
  } while (0)

// the spec's headers in their spec spelling (index = FP_H_*), for building requests
static const char *const HN[FP_NHDR] = { "If-None-Match",
                                         "Accept-Language",
                                         "X-Request-Id",
                                         "X-Request-Id-Extra",
                                         "Cookie",
                                         "Idempotency-Key",
                                         "X-A-Very-Long-Custom-Header-Name-For-Chunked-Compares" };
static const struct {
  const char *m, *p;
  int route;
  long long id;
} RT[] = { { "GET", "/feed", R_FEED, 0 },
           { "GET", "/health", R_HEALTH, 0 },
           { "GET", "/posts/42", R_GETPOST, 42 },
           { "POST", "/posts", R_CREATE, 0 },
           { "POST", "/posts/7/like", R_LIKE, 7 } };

static void recase(char *d, const char *s) {
  for (; *s; s++, d++) {
    int c = (unsigned char)*s;
    *d = (char)((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ? ((rnd() & 1) ? c ^ 0x20 : c) : c);
  }
  *d = 0;
}

int main(int argc, char **argv) {
  int quick = argc > 1 && !strcmp(argv[1], "quick"), N = quick ? 20000 : 200000;
  for (int i = 0; i < FP_NHDR; i++) { // the generated table and this file agree
    char lc[64];
    int n = (int)strlen(HN[i]);
    for (int k = 0; k <= n; k++) lc[k] = (char)(HN[i][k] | (HN[i][k] >= 'A' && HN[i][k] <= 'Z' ? 0x20 : 0));
    if (fp_hdr_names[i].len != n || memcmp(fp_hdr_names[i].lc, lc, n)) {
      printf("header table differs at %d\nTOTAL FAILURES: 1\n", i);
      return 1;
    }
  }
  static char src[16384], err[256], name[128], val[2048];
  long clean = 0, fast_hits = 0, fb_ok = 0, extracted = 0;
  for (int it = 0; it < N; it++) {
    int ri = rnd() % 5, n = 0, dirty = 0;
    unsigned want = fp_route_hdrs(RT[ri].route), seen = 0;
    const char *expv[FP_NHDR];
    int expl[FP_NHDR], expoff[FP_NHDR];
    for (int j = 0; j < FP_NHDR; j++) {
      expv[j] = NULL;
      expl[j] = 0;
      expoff[j] = -1;
    }
    n += sprintf(src + n, "%s %s HTTP/1.1\r\n", RT[ri].m, RT[ri].p);
    int lines = 1 + rnd() % 12, post = RT[ri].m[0] == 'P';
    const char *body = post ? "{\"body\":\"hello\"}" : NULL;
    for (int k = 0; k < lines; k++) {
      int kind = rnd() % 10;
      if (kind < 5) { // one of the spec's headers
        int j = rnd() % FP_NHDR, vl = rnd() % 4 == 0 ? 0 : rnd() % 8 == 0 ? 60 + rnd() % 300 : 1 + rnd() % 30;
        for (int q = 0; q < vl; q++) val[q] = "abcdefgXYZ0123456789-_.;=, \"/"[rnd() % 29];
        if (vl) {
          if (val[0] == ' ') val[0] = 'v';
          if (val[vl - 1] == ' ') val[vl - 1] = 'v';
        } // the value proper: no edge OWS
        val[vl] = 0;
        recase(name, HN[j]);
        const char *pre = (const char *[]){ "", " ", "  ", "\t" }[rnd() % 4],
                   *post_ws = (const char *[]){ "", "", " ", "\t " }[rnd() % 4];
        int off = n + (int)strlen(name) + 1 + (int)strlen(pre);
        n += sprintf(src + n, "%s:%s%s%s\r\n", name, pre, val, post_ws);
        if ((want >> j & 1) && !(seen >> j & 1)) {
          seen |= 1u << j;
          expoff[j] = off;
          expl[j] = vl;
        }
      } else if (kind == 5) { // a distractor: a lookalike name; on a route that asks for headers it may fall back
        const char *d =
            (const char *[]){ "X-Request-Idz: 1", "x-request-ide: 2",     "Cookies: c=1",
                              "If-None-Matc: x",  "Accept-Languages: en", "Idempotency-Keys: k" }[rnd() % 6];
        n += sprintf(src + n, "%s\r\n", d);
        if (!dirty) dirty = 1;
      } else if (kind == 6 && (rnd() & 3) == 0) { // "name :" - pico rejects the request
        recase(name, HN[rnd() % FP_NHDR]);
        n += sprintf(src + n, "%s : x\r\n", name);
        dirty = 2;
      } else {
        n += sprintf(src + n, "%s\r\n",
                     (const char *[]){ "Host: localhost:8080", "User-Agent: test/1.0", "Accept: */*",
                                       "Accept-Encoding: gzip", "X-Other: 1" }[kind % 5]);
      }
    }
    if (post) n += sprintf(src + n, "Authorization: Bearer abc.def.ghi\r\nContent-Length: %d\r\n", (int)strlen(body));
    n += sprintf(src + n, "\r\n");
    int head = n;
    if (body) n += sprintf(src + n, "%s", body);
    char *b = fz_copy(src, n, 0);
    for (int j = 0; j < FP_NHDR; j++)
      if (expoff[j] >= 0) expv[j] = b + expoff[j];
    req_t g, f, x;
    memset(&g, 0, sizeof g);
    memset(&f, 0, sizeof f);
    memset(&x, 0, sizeof x);
    int c = ref_parse(b, n, &g), a = fast_parse(b, n, &f), y = fb_parse_req(b, n, &x);
    // 1. the reference against the construction
    if (dirty == 2) {
      if (c != -2) FAIL("it %d: \"name :\" but ref_parse %d\n", it, c);
    } else if (c != n) {
      FAIL("it %d: ref_parse %d, want %d\n", it, c, n);
      static int shown;
      if (!shown++) {
        for (int q = 0; q < n; q++) putchar(src[q] == 0x0d ? 0x7c : src[q]);
        putchar(10);
      }
    } else {
      for (int j = 0; j < FP_NHDR; j++)
        if ((g.hdr[j] != NULL) != (expv[j] != NULL) ||
            (expv[j] && (g.hdr_len[j] != expl[j] || (expl[j] && g.hdr[j] != expv[j])))) {
          FAIL("it %d: ref header %d: %p/%d, built %p/%d\n", it, j, (void *)g.hdr[j], g.hdr_len[j], (void *)expv[j],
               expl[j]);
          break;
        }
      if (g.route != RT[ri].route || g.body_off != head)
        FAIL("it %d: ref route %d body_off %d\n", it, g.route, g.body_off);
      for (int j = 0; j < FP_NHDR; j++) extracted += expv[j] != NULL;
    }
    // 2. fb_parse_req == ref
    if (!same(c, &g, y, &x)) FAIL("it %d: fb_parse_req %d, ref_parse %d\n", it, y, c);
    else fb_ok++;
    // 3. fast_parse == ref or a fallback; never a fallback on a clean request
    if (a != FP_FALLBACK && c != -2 && !same(c, &g, a, &f)) FAIL("it %d: fast_parse %d, ref_parse %d\n", it, a, c);
    if (!dirty) {
      clean++;
      if (a == FP_FALLBACK) FAIL("it %d: fast_parse fell back on a clean request (route %d)\n", it, RT[ri].route);
    }
    if (a > 0) fast_hits++;
    // 4. batch + the oracles (every 16th: also every truncation)
    if (fz_check_fast(b, n, err, sizeof err) || fz_check_fb(b, n, 64, 0, err, sizeof err) ||
        fz_check_batch(b, n, err, sizeof err))
      FAIL("it %d: %s\n", it, err);
    if (it % 16 == 0)
      for (int t = 0; t < n; t++)
        if (fz_check_fast(b, t, err, sizeof err) || fz_check_fb(b, t, 64, 0, err, sizeof err) ||
            fz_check_batch(b, t, err, sizeof err)) {
          FAIL("it %d at %d: %s\n", it, t, err);
          break;
        }
    free(b);
  }
  printf(
      "spec headers (%s): %d requests, %ld clean, %ld on the fast path, %ld fbparse == ref, %ld values extracted\nTOTAL FAILURES: %d\n",
      FP_SPEC_NAME, N, clean, fast_hits, fb_ok, extracted, fails);
  return fails != 0;
}
