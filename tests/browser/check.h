// tests/browser/check.h - differential checks of one raw request, as a real client sent it, through every
// HTTP/1.1 entry point against picohttpparser. Used by tests/browser/server.c (live, while a browser drives it) and
// tests/browser/replay.c (the saved requests, under every backend). Include after fastparse.h, fbparse.h,
// picohttpparser.h and testlib.h.
//
// Each request is checked in a copy padded with 64 bytes (zeros, then 0xff: the contract allows any contents), at
// every length from 0 to 64 bytes past the head, then every 61st and the last 64 of a body, so the -1 / -2 decisions
// on partial reads are covered as well as the complete request:
//   - fb_parse_request and fb_parse_request_scalar: exactly pico's result and outputs (header arrays of 128 and 48),
//     and again with last_len = k - 1 (pico's slowloris check);
//   - fb_parse_req: exactly ref_parse (testlib.h: pico + fastparse.h's routing and header rules, 48 headers max);
//   - fast_parse, fast_parse_scalar, and fast_parse_tmpl (templates learned across the whole session): ref_parse's
//     result, or FP_FALLBACK. Where ref_parse says invalid (-2), the fast path may still say FP_NEED_MORE on a
//     partial request or accept the complete one: its documented relaxed acceptance (README, tests/edges.h ret 3).
//     Those are counted, not failed (BC_VERBOSE=1 lists the requests).
#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BC_NH 128 // header array for pico / fbparse (browsers send up to ~75 here); also checked with 48
typedef struct {
  long reqs, lengths, bad, relaxed_more, relaxed_accept;
  size_t max_head, max_headers;
} bc_stats_t;
static bc_stats_t BC;
static FILE *BC_LOG; // where mismatches go (stderr if NULL)

typedef struct {
  int ret, minor;
  const char *m, *p;
  size_t ml, pl, nh;
  struct phr_header h[BC_NH];
} bc_res_t;
enum { BC_PICO, BC_FB, BC_FB_SCALAR };
static void bc_run(int which, const char *b, size_t len, size_t cap, size_t last, bc_res_t *r) {
  memset(r, 0, sizeof *r);
  r->nh = cap;
  if (which == BC_PICO) r->ret = phr_parse_request(b, len, &r->m, &r->ml, &r->p, &r->pl, &r->minor, r->h, &r->nh, last);
  else if (which == BC_FB)
    r->ret = fb_parse_request(b, len, &r->m, &r->ml, &r->p, &r->pl, &r->minor, (struct fb_header *)r->h, &r->nh, last);
  else
    r->ret = fb_parse_request_scalar(b, len, &r->m, &r->ml, &r->p, &r->pl, &r->minor, (struct fb_header *)r->h, &r->nh,
                                     last);
}
static int bc_same(const bc_res_t *a, const bc_res_t *b) {
  if (a->ret != b->ret) return 0;
  if (a->ret <= 0) return 1;
  if (a->m != b->m || a->ml != b->ml || a->p != b->p || a->pl != b->pl || a->minor != b->minor || a->nh != b->nh)
    return 0;
  for (size_t i = 0; i < a->nh; i++)
    if (a->h[i].name != b->h[i].name || a->h[i].name_len != b->h[i].name_len || a->h[i].value != b->h[i].value ||
        a->h[i].value_len != b->h[i].value_len)
      return 0;
  return 1;
}
static void bc_fail(const char *what, const char *tag, size_t k, size_t n, long want, long got) {
  BC.bad++;
  if (BC.bad <= 200)
    fprintf(BC_LOG ? BC_LOG : stderr, "MISMATCH %s [%s] at length %zu of %zu: want %ld, got %ld\n", what, tag, k, n,
            want, got);
}
// a fast-path result b against ref_parse's a (same request, same length k of n)
static void bc_fast(const char *what, const char *tag, size_t k, size_t n, int a, const req_t *ra, int b,
                    const req_t *rb) {
  if (b == FP_FALLBACK || same(a, ra, b, rb)) return;
  if (a == -2 && b == FP_NEED_MORE && k < n) BC.relaxed_more++;
  else if (a == -2 && b > 0) {
    static char last[1024]; // one line per request
    BC.relaxed_accept++;
    if (strcmp(tag, last) && getenv("BC_VERBOSE"))
      fprintf(BC_LOG ? BC_LOG : stdout, "relaxed accept [%s]: %s accepts the %zu-byte request pico rejects\n", tag,
              what, n);
    snprintf(last, sizeof last, "%s", tag);
  } else bc_fail(what, tag, k, n, a, b);
}

static fp_tmpl_t BC_X; // learned templates across the whole session, as one server thread would keep them
// returns the number of new mismatches
static long bc_check(const char *raw, size_t n, const char *tag) {
  long bad0 = BC.bad;
  BC.reqs++;
  char *buf = malloc(n + 64);
  size_t hl = n; // the head's length (pico's, on the whole request), or n
  {
    const char *m, *p;
    size_t ml, pl, nh = BC_NH;
    int mv;
    struct phr_header h[BC_NH];
    int r = phr_parse_request(raw, n, &m, &ml, &p, &pl, &mv, h, &nh, 0);
    if (r > 0) hl = (size_t)r;
  }
  for (int pad = 0; pad < 2; pad++) {
    memcpy(buf, raw, n);
    memset(buf + n, pad ? 0xff : 0, 64);
    for (size_t k = 0; k <= n; k++) {
      static bc_res_t A, B;
      // inside a body nothing is decided until it is complete: there, every 61st length and the last 64 only
      if (k > hl + 64 && k + 64 < n && k % 61) continue;
      BC.lengths++;
      const size_t caps[2] = { BC_NH, 48 };
      for (int ci = 0; ci < 2; ci++) {
        bc_run(BC_PICO, buf, k, caps[ci], 0, &A);
        bc_run(BC_FB, buf, k, caps[ci], 0, &B);
        if (!bc_same(&A, &B)) bc_fail("fb_parse_request", tag, k, n, A.ret, B.ret);
        bc_run(BC_FB_SCALAR, buf, k, caps[ci], 0, &B);
        if (!bc_same(&A, &B)) bc_fail("fb_parse_request_scalar", tag, k, n, A.ret, B.ret);
        if (ci == 0 && A.ret > 0 && k == n) {
          if ((size_t)A.ret > BC.max_head) BC.max_head = (size_t)A.ret;
          if (A.nh > BC.max_headers) BC.max_headers = A.nh;
        }
      }
      if (k > 0) {
        bc_run(BC_PICO, buf, k, BC_NH, k - 1, &A);
        bc_run(BC_FB, buf, k, BC_NH, k - 1, &B);
        if (!bc_same(&A, &B)) bc_fail("fb_parse_request (last_len)", tag, k, n, A.ret, B.ret);
      }
      req_t ra, rb;
      memset(&ra, 0, sizeof ra);
      memset(&rb, 0, sizeof rb);
      int a = ref_parse(buf, (int)k, &ra), b = fb_parse_req(buf, (int)k, &rb);
      if (!same(a, &ra, b, &rb)) bc_fail("fb_parse_req", tag, k, n, a, b);
      memset(&rb, 0, sizeof rb);
      b = fast_parse(buf, (int)k, &rb);
      bc_fast("fast_parse", tag, k, n, a, &ra, b, &rb);
      memset(&rb, 0, sizeof rb);
      b = fast_parse_scalar(buf, (int)k, &rb);
      bc_fast("fast_parse_scalar", tag, k, n, a, &ra, b, &rb);
    }
    req_t ra, rb;
    memset(&ra, 0, sizeof ra);
    int a = ref_parse(buf, (int)n, &ra);
    for (int rep = 0; rep < 3; rep++) { // a skeleton seen twice becomes a template: later tries take that path
      memset(&rb, 0, sizeof rb);
      int b = fast_parse_tmpl(buf, (int)n, &rb, &BC_X);
      bc_fast("fast_parse_tmpl", tag, n, n, a, &ra, b, &rb);
    }
  }
  free(buf);
  return BC.bad - bad0;
}
static void bc_summary(const char *who) {
  printf("%s, backend %s: %ld requests, %ld lengths checked, %ld mismatches; relaxed (documented): %ld NEED_MORE "
         "on invalid partials, %ld accepts of pico-invalid requests; largest head %zu B, most headers %zu\n",
         who, FB_BACKEND_NAME, BC.reqs, BC.lengths, BC.bad, BC.relaxed_more, BC.relaxed_accept, BC.max_head,
         BC.max_headers);
}
