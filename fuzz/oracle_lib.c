// oracle_lib.c - oracle.h as a shared library for the Hypothesis properties (fuzz/hyp/props.py, via ctypes).
//   fz_fb / fz_fast / fz_batch   the differential checks (0 = all agree, else 1 and a message in err)
//   fz_fb_prefixes               fz_fb on every prefix
//   fz_fbparse                   fb_parse_request's raw result, so a property can check it against its own model
//   fz_req                       fast_parse (which 0) or fb_parse_req (which 1) as integers
#include "oracle.h"
#define FZ_API __attribute__((visibility("default")))

FZ_API int fz_fb(const char *d, size_t n, size_t max, size_t last_len, char *err, size_t en) { return fz_check_fb(d, n, max, last_len, err, en); }
FZ_API int fz_fast(const char *d, size_t n, char *err, size_t en) { return fz_check_fast(d, n, err, en); }
// fz_fb on every prefix of the input (every 4th past 2 KB): truncation is where line and version ends move
FZ_API int fz_fb_prefixes(const char *d, size_t n, char *err, size_t en) {
  for (size_t t = 0; t <= n; t += t < 2048 ? 1 : 4) if (fz_check_fb(d, t, FZ_MAXH, 0, err, en)) return 1;
  return 0;
}
FZ_API int fz_batch(const char *d, size_t n, char *err, size_t en) { return fz_check_batch(d, n, err, en); }

// out: method off, len; path off, len; minor; header count; then per header name off (-1: continuation), len,
// value off, len. Room for 6 + 4 * 64 ints.
FZ_API int fz_fbparse(const char *d, size_t n, int *out) {
  char *b = fz_copy(d, n, 1);
  const char *m, *p; size_t ml, pl, nh = FZ_MAXH; int mv; struct fb_header H[FZ_MAXH];
  int r = fb_parse_request(b, n, &m, &ml, &p, &pl, &mv, H, &nh, 0);
  if (r > 0) {
    out[0] = (int)(m - b); out[1] = (int)ml; out[2] = (int)(p - b); out[3] = (int)pl; out[4] = mv; out[5] = (int)nh;
    for (size_t i = 0; i < nh; i++) { int *o = out + 6 + 4 * i;
      o[0] = H[i].name ? (int)(H[i].name - b) : -1; o[1] = (int)H[i].name_len; o[2] = (int)(H[i].value - b); o[3] = (int)H[i].value_len; }
  }
  free(b);
  return r;
}
// out: route, id_ok, id, auth, token off, token len, body off, body len
FZ_API int fz_req(const char *d, size_t n, int which, long long *out) {
  char *b = fz_copy(d, n, 0); req_t r; memset(&r, 0, sizeof r);
  int x = which ? fb_parse_req(b, (int)n, &r) : fast_parse(b, (int)n, &r);
  out[0] = r.route; out[1] = r.id_ok; out[2] = r.id; out[3] = r.auth; out[4] = r.auth ? (long long)(r.tok - b) : -1; out[5] = r.tok_len;
  out[6] = r.body_off; out[7] = r.body_len;
  free(b);
  return x;
}
