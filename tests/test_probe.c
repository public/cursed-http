// test_probe.c - the transport-level request shapes of an HTTP/1.1 conformance probe (tests/probe_cases.h), each
// with its exact expected result:
//   fb_parse_req / fb_parse_req_ex   the class (complete, HTTP/1.0, Transfer-Encoding, invalid, incomplete), route,
//                                    id, Bearer token, body framing; HTTP/1.0 requests are filled with their size
//   fast_parse                       the same answer, or FP_FALLBACK (never on HTTP/1.1 API requests)
//   fb_parse_request (pico API)      the head length on every request with a complete head; -1 on a non-request
//   chunked bodies                   the head from fbparse, the body decoded by picohttpparser's phr_decode_chunked
//   pipelined pairs                  fast_parse_many returns both, fbparse parses the second at its offset
// and every case and every truncation through fuzz/oracle.h (pico, all backends, batchparse). Any difference fails.
//   make test   ./test_probe
#include "oracle.h"
#include "probe_cases.h"

static int fails;
#define FAIL(...) do { if (fails++ < 30) printf(__VA_ARGS__); } while (0)

static const char *exp_tok(const probe_case_t *c) {   // the Bearer token the parser must hand over, or NULL
  if (c->raw || !c->auth || strncmp(c->auth, "Bearer ", 7) || (c->route != R_CREATE && c->route != R_LIKE)) return NULL;
  return c->auth + 7;
}
static int fields_ok(const probe_case_t *c, const req_t *r, const char *b) {
  const char *t = exp_tok(c);
  if (r->route != c->route || r->id_ok != c->id_ok || (c->id_ok && r->id != c->id)) return 0;
  if (!t) return r->auth == 0;
  return r->auth == 1 && r->tok_len == (int)strlen(t) && !memcmp(r->tok, t, r->tok_len) && r->tok >= b;
}

static void check_case(const probe_case_t *c) {
  static char src[8192]; int head, body, len = pc_build(c, src, sizeof src, &head, &body);
  char *b = fz_copy(src, len, 0), err[256];
  // fb_parse_req / fb_parse_req_ex: the exact class and fields
  req_t r; memset(&r, 0, sizeof r); fb_info_t in; memset(&in, 0, sizeof in);
  int x = fb_parse_req_ex(b, len, &r, &in), y; req_t r2; y = fb_parse_req(b, len, &r2);
  int want = c->cls == PC_OK ? head + body : c->cls == PC_NEED_MORE ? FP_NEED_MORE : c->cls == PC_INVALID ? -2 : FP_FALLBACK;
  if (x != want || y != want) FAIL("%s: fb_parse_req_ex %d, fb_parse_req %d, want %d\n", c->name, x, y, want);
  else if (c->cls == PC_OK && (!fields_ok(c, &r, b) || r.body_off != head || r.body_len != body))
    FAIL("%s: fields route %d id_ok %d id %lld auth %d tok_len %d body %d+%d\n", c->name, r.route, r.id_ok, (long long)r.id, r.auth, r.tok_len, r.body_off, r.body_len);
  else if (c->cls == PC_MINOR && (in.flags != FB_MINOR || in.total != head + body || !fields_ok(c, &r, b) || r.body_len != body))
    FAIL("%s: HTTP/1.0 flags %d total %d (want %d) route %d body_len %d\n", c->name, in.flags, in.total, head + body, r.route, r.body_len);
  else if (c->cls == PC_TE && !(in.flags & FB_TE)) FAIL("%s: Transfer-Encoding not reported (flags %d)\n", c->name, in.flags);
  // fast_parse: the same answer, or a fallback; HTTP/1.1 API requests stay on the fast path
  req_t f; memset(&f, 0, sizeof f); int a = fast_parse(b, len, &f);
  if (c->cls == PC_OK && (a != want || !fields_ok(c, &f, b) || f.body_off != head || f.body_len != body))
    FAIL("%s: fast_parse %d (want %d, no fallback)\n", c->name, a, want);
  if (c->cls == PC_NEED_MORE && a != FP_NEED_MORE) FAIL("%s: fast_parse %d on an incomplete body, want NEED_MORE\n", c->name, a);
  if ((c->cls == PC_MINOR || c->cls == PC_TE || c->cls == PC_INVALID) && a != FP_FALLBACK) FAIL("%s: fast_parse %d, want FP_FALLBACK\n", c->name, a);
  // fb_parse_request (pico's API): the head, or -1 for a non-request
  const char *m, *p; size_t ml, pl, nh = 64; int mv; struct fb_header h[64];
  int ph = fb_parse_request(b, len, &m, &ml, &p, &pl, &mv, h, &nh, 0);
  if (c->cls == PC_INVALID ? ph != -1 : ph != head) FAIL("%s: fb_parse_request %d, want %d\n", c->name, ph, c->cls == PC_INVALID ? -1 : head);
  // a chunked body: the caller decodes it after the head (phr_decode_chunked works in place)
  if (c->cls == PC_TE && c->decoded) {
    char *body2 = malloc(len - head + 1); memcpy(body2, b + head, len - head);
    struct phr_chunked_decoder d; memset(&d, 0, sizeof d); d.consume_trailer = 1; size_t sz = len - head;
    ssize_t rest = phr_decode_chunked(&d, body2, &sz);
    size_t dl = strlen(c->decoded);
    if (rest < 0 || sz != dl || memcmp(body2, c->decoded, dl)) FAIL("%s: chunked body decoded to %zd / %zu bytes, want %zu\n", c->name, rest, sz, dl);
    free(body2);
  }
  // every truncation, and the whole request, through the oracles (pico, every backend, batchparse)
  for (int t = 0; t <= len; t++) {
    if (fz_check_fb(b, t, 64, 0, err, sizeof err) || fz_check_fast(b, t, err, sizeof err) || fz_check_batch(b, t, err, sizeof err)) {
      FAIL("%s: at %d of %d bytes: %s\n", c->name, t, len, err); break; }
    if (t < head && c->cls != PC_INVALID) {   // a prefix of a valid head is never complete or invalid
      req_t q; int z = fb_parse_req(b, t, &q);
      if (z != FP_NEED_MORE) { FAIL("%s: fb_parse_req %d on the %d-byte prefix, want NEED_MORE\n", c->name, z, t); break; }
    }
  }
  free(b);
}

static void check_pipeline(const char *t1, const char *t2) {
  static char src[1024];
  int n1 = snprintf(src, sizeof src, "GET %s HTTP/1.1\r\nHost: localhost:8080\r\n\r\n", t1);
  int n = n1 + snprintf(src + n1, sizeof src - n1, "GET %s HTTP/1.1\r\nHost: localhost:8080\r\n\r\n", t2);
  char *b = fz_copy(src, n, 0), err[256];
  req_t o[4]; fp_batch_t x = fast_parse_many(b, n, o, 4);
  if (x.n != 2 || x.used != n || x.status != FP_NEED_MORE) FAIL("pipeline %s + %s: fast_parse_many n %d used %d/%d status %d\n", t1, t2, x.n, x.used, n, x.status);
  req_t r; int a = fb_parse_req(b, n, &r), c = fb_parse_req(b + n1, n - n1, &r);
  if (a != n1 || c != n - n1) FAIL("pipeline %s + %s: fb_parse_req %d and %d, want %d and %d\n", t1, t2, a, c, n1, n - n1);
  if (fz_check_fast(b, n, err, sizeof err) || fz_check_fb(b, n, 64, 0, err, sizeof err) || fz_check_batch(b, n, err, sizeof err))
    FAIL("pipeline %s + %s: %s\n", t1, t2, err);
  free(b);
}

int main(void) {
  printf("probe cases: fastparse.h %s, fbparse.h %s\n", FP_BACKEND_NAME, FB_BACKEND_NAME);
  for (int i = 0; i < N_PROBE_CASES; i++) check_case(&PROBE_CASES[i]);
  for (size_t i = 0; i < sizeof PROBE_PIPELINES / sizeof *PROBE_PIPELINES; i++) check_pipeline(PROBE_PIPELINES[i][0], PROBE_PIPELINES[i][1]);
  check_pipeline("/posts/1/like", "/posts/1");   // the probe's like pair, as GETs (the like route then is NOTFOUND)
  printf("%d cases, %zu pipelined pairs + 1, every truncation\nTOTAL FAILURES: %d\n", N_PROBE_CASES,
         sizeof PROBE_PIPELINES / sizeof *PROBE_PIPELINES, fails);
  return fails != 0;
}
