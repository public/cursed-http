// oracle.h - the differential checks behind the fuzzers: the libFuzzer targets (fuzz/fuzz_*.c) and the
// Hypothesis properties (fuzz/hyp/, through build/libfuzzoracle). The same rules as the unit tests:
//   fz_check_fb     fbparse.h (SIMD, scalar, both header loops, two paddings) == picohttpparser, exactly;
//                   the req_t adapter == testlib's ref_parse (pico + the routing logic)
//   fz_check_fast   fastparse.h: every core/classify/learned path (layouts and templates) agrees; vs ref_parse it may only fall back
//                   (or meet pico's -2 with a relaxed accept); no prefix of a complete request completes or
//                   errors; fast_parse_many == repeated fast_parse
//   fz_check_batch  batchparse.h: every lane of every phase-A variant == fast_parse on that lane
// Each returns 0 when everything agrees, else writes what differed into err and returns 1. Inputs are
// copied into exact-size allocations with 64 bytes of padding, so ASan sees any read past the contract.
// The padding contents are derived from the input, so every result is reproducible.
#pragma once
#include <stdarg.h>
#include <stdio.h>
#include "batchparse.h"
#include "fbparse.h"
#include "picohttpparser.h"
#include "testlib.h"

#define FZ_MAXH 64
static int fz_err(char *err, size_t n, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  if (err && n) vsnprintf(err, n, fmt, ap);
  va_end(ap);
  return 1;
}
static uint64_t fz_hash(const char *d, size_t n) {
  uint64_t h = 0xcbf29ce484222325ull;
  for (size_t i = 0; i < n; i++) h = (h ^ (unsigned char)d[i]) * 0x100000001b3ull;
  return h;
}
// pad 0: 'Z' padding; pad 1: padding that looks like structure (CR, LF, ':', SP, HT, NUL, 0xff, DEL)
static char *fz_copy(const char *d, size_t n, int pad) {
  char *b = malloc(n + PAD);
  if (n) memcpy(b, d, n);
  uint64_t h = fz_hash(d, n) | 1;
  for (int i = 0; i < PAD; i++) {
    h ^= h << 13;
    h ^= h >> 7;
    h ^= h << 17;
    b[n + i] = pad ? "\r\n: \t\x00\xff\x7f"[h % 8] : 'Z';
  }
  return b;
}

// ---- Connection headers, read straight off the raw head (no parser involved) ----
// over the header lines of b[0..hend): kind 0 = any line whose name starts with "connection" (case-insensitive) is
// "connection:" + exactly keep-alive (OWS trimmed); kind 1 = some "connection:" line lists the "close" token
static int fz_ci(const char *a, const char *lc, int n) {
  for (int i = 0; i < n; i++)
    if ((a[i] | (lc[i] >= 'a' ? 0x20 : 0)) != lc[i]) return 0;
  return 1;
}
static int fz_conn(const char *b, int hend, int kind) {
  const char *e = b + hend, *l = memchr(b, '\n', hend);
  for (l = l ? l + 1 : e; l < e;) {
    const char *nl = memchr(l, '\n', e - l);
    if (!nl) nl = e;
    int n = (int)(nl - l);
    if (n && l[n - 1] == '\r') n--;
    if (n >= 10 && fz_ci(l, "connection", 10)) {
      int named = n >= 11 && l[10] == ':';
      const char *v = l + 11, *ve = l + n;
      if (named) {
        while (v < ve && (*v == ' ' || *v == '\t')) v++;
        while (ve > v && (ve[-1] == ' ' || ve[-1] == '\t')) ve--;
      }
      if (kind == 0 && !(named && ve - v == 10 && fz_ci(v, "keep-alive", 10))) return 0;
      if (kind == 1 && named)
        for (const char *t = v; t < ve;) {
          while (t < ve && (*t == ' ' || *t == '\t' || *t == ',')) t++;
          const char *u = t;
          while (u < ve && *u != ',' && *u != ' ' && *u != '\t') u++;
          if (u - t == 5 && fz_ci(t, "close", 5)) return 1;
          t = u;
        }
    }
    l = nl + 1;
  }
  return kind == 0;
}

// ---- fbparse.h vs picohttpparser ----
typedef int (*fz_fbfn)(const char *, size_t, const char **, size_t *, const char **, size_t *, int *,
                       struct fb_header *, size_t *, size_t);
static int fz_fb_simd(const char *b, size_t l, const char **m, size_t *ml, const char **p, size_t *pl, int *mv,
                      struct fb_header *h, size_t *nh, size_t ll) {
  return fb_parse_request(b, l, m, ml, p, pl, mv, h, nh, ll);
}
static int fz_fb_scalar(const char *b, size_t l, const char **m, size_t *ml, const char **p, size_t *pl, int *mv,
                        struct fb_header *h, size_t *nh, size_t ll) {
  return fb_parse_request_scalar(b, l, m, ml, p, pl, mv, h, nh, ll);
}
static int fz_fb_seq(const char *b, size_t l, const char **m, size_t *ml, const char **p, size_t *pl, int *mv,
                     struct fb_header *h, size_t *nh, size_t ll) {
  return fb_parse_request_loop(0, b, l, m, ml, p, pl, mv, h, nh, ll);
}
static int fz_fb_walk(const char *b, size_t l, const char **m, size_t *ml, const char **p, size_t *pl, int *mv,
                      struct fb_header *h, size_t *nh, size_t ll) {
  return fb_parse_request_loop(1, b, l, m, ml, p, pl, mv, h, nh, ll);
}

static int fz_phr(const char *A, const char *Bp, size_t len, size_t max, size_t last_len, char *err, size_t en) {
  const char *m, *p;
  size_t ml, pl, nh = max;
  int mv;
  struct phr_header H[FZ_MAXH];
  int rp = phr_parse_request(A, len, &m, &ml, &p, &pl, &mv, H, &nh, last_len);
  struct {
    fz_fbfn f;
    const char *base;
    const char *name;
  } V[] = { { fz_fb_simd, A, "simd/Z-pad" },
            { fz_fb_simd, Bp, "simd/struct-pad" },
            { fz_fb_scalar, Bp, "scalar" },
            { fz_fb_seq, Bp, "seq loop" },
            { fz_fb_walk, A, "walk loop" } };
  for (int v = 0; v < 5; v++) {
    const char *m2, *p2;
    size_t ml2, pl2, nh2 = max;
    int mv2;
    struct fb_header G[FZ_MAXH];
    const char *B = V[v].base;
    int rf = V[v].f(B, len, &m2, &ml2, &p2, &pl2, &mv2, G, &nh2, last_len);
    if (rf != rp)
      return fz_err(err, en, "fbparse %s returned %d, pico %d (max_headers %zu, last_len %zu)", V[v].name, rf, rp, max,
                    last_len);
    if (rp <= 0) continue;
    if (m2 - B != m - A || ml2 != ml) return fz_err(err, en, "fbparse %s: method differs", V[v].name);
    if (p2 - B != p - A || pl2 != pl) return fz_err(err, en, "fbparse %s: path differs", V[v].name);
    if (mv2 != mv || nh2 != nh)
      return fz_err(err, en, "fbparse %s: minor %d/%d or header count %zu/%zu differs", V[v].name, mv2, mv, nh2, nh);
    for (size_t i = 0; i < nh; i++)
      if ((G[i].name == NULL) != (H[i].name == NULL) || (H[i].name && G[i].name - B != H[i].name - A) ||
          G[i].name_len != H[i].name_len || G[i].value - B != H[i].value - A || G[i].value_len != H[i].value_len)
        return fz_err(err, en, "fbparse %s: header %zu differs", V[v].name, i);
  }
  return 0;
}
static int fz_adapter(const char *A, const char *Bp, int len, char *err, size_t en) {
  req_t g, f, s;
  memset(&g, 0, sizeof g);
  memset(&f, 0, sizeof f);
  memset(&s, 0, sizeof s);
  int c = ref_parse(A, len, &g), a = fb_parse_req(Bp, len, &f), b = fb_parse_req_scalar(A, len, &s);
  if (a > 0) req_rebase(&f, Bp, A); // same() compares pointers: rebase onto A
  if (!same(c, &g, a, &f) || (c > 0 && g.id_ok && g.id != f.id))
    return fz_err(err, en, "fb_parse_req (simd) %d, ref_parse %d", a, c);
  if (!same(c, &g, b, &s) || (c > 0 && g.id_ok && g.id != s.id))
    return fz_err(err, en, "fb_parse_req (scalar) %d, ref_parse %d", b, c);
  for (int w = 0; w < 2; w++) {
    req_t q;
    memset(&q, 0, sizeof q);
    int x = fb_parse_req_loop(w, A, len, &q);
    if (!same(c, &g, x, &q) || (c > 0 && g.id_ok && g.id != q.id))
      return fz_err(err, en, "fb_parse_req_loop(%d) %d, ref_parse %d", w, x, c);
  }
  fb_info_t in;
  req_t e;
  memset(&e, 0, sizeof e);
  int x = fb_parse_req_ex(A, len, &e, &in);
  if (x != c || (x == FP_FALLBACK && !in.flags) || (x > 0 && in.flags))
    return fz_err(err, en, "fb_parse_req_ex %d (flags %d), ref_parse %d", x, in.flags, c);
  if (x != -2 && x != FP_NEED_MORE && in.close != fz_conn(A, e.body_off, 1))
    return fz_err(err, en, "fb_parse_req_ex close %d, the head's Connection says %d", in.close,
                  fz_conn(A, e.body_off, 1));
  // HTTP/1.x with x != 1 and nothing else odd: ex fills r like a success of the same request as HTTP/1.1
  if (x == FP_FALLBACK && in.flags == FB_MINOR) {
    int vp = -1;
    for (int i = 0; i + 8 <= len; i++)
      if (!memcmp(A + i, "HTTP/1.", 7) && A[i + 7] != '1' && (A[i + 8] == '\r' || A[i + 8] == '\n')) {
        vp = i + 7;
        break;
      }
    if (vp >= 0) {
      char *t = malloc(len + PAD);
      memcpy(t, A, len + PAD);
      t[vp] = '1';
      req_t g1;
      memset(&g1, 0, sizeof g1);
      int c1 = ref_parse(t, len, &g1), bad = 0;
      if (c1 > 0 || c1 == FP_NEED_MORE) {
        if (!e.auth) e.tok = 0;
        req_rebase(&e, A, t);
        bad = (c1 > 0 ? !same(c1, &g1, in.total, &e) : in.total <= len) || (g1.id_ok && g1.id != e.id);
      }
      free(t);
      if (bad)
        return fz_err(err, en, "fb_parse_req_ex on HTTP/1.%c: total %d, ref_parse as HTTP/1.1 %d", A[vp], in.total, c1);
    }
  }
  return 0;
}
// max_headers 0..64 (larger is clamped), last_len 0..len (larger is clamped)
static int fz_check_fb(const char *d, size_t len, size_t max, size_t last_len, char *err, size_t en) {
  if (max > FZ_MAXH) max = FZ_MAXH;
  if (last_len > len) last_len = len;
  char *A = fz_copy(d, len, 0), *Bp = fz_copy(d, len, 1);
  int r = fz_phr(A, Bp, len, FZ_MAXH, 0, err, en);
  if (!r && max != FZ_MAXH) r = fz_phr(A, Bp, len, max, 0, err, en);
  if (!r && last_len) r = fz_phr(A, Bp, len, FZ_MAXH, last_len, err, en);
  if (!r && len < (1u << 30)) r = fz_adapter(A, Bp, (int)len, err, en);
  free(A);
  free(Bp);
  return r;
}

// ---- fastparse.h: its cores against each other, and against ref_parse ----
static int fz_fast_backends(const char *b, int len, int a, const req_t *f, char *err, size_t en) {
  static const char *NAME[] = { "scalar",         "cand core/scalar", "walk core/simd",
                                "cand core/simd", "learned/simd",     "learned/scalar" };
  fp_learn_t *T = calloc(2, sizeof *T); // fresh tables per input: learn on the first call, use on the second
  int r = 0;
  for (int i = 0; i < 8 && !r; i++) {
    req_t s;
    memset(&s, 0, sizeof s);
    int c;
    switch (i) {
      case 0: c = fast_parse_scalar(b, len, &s); break;
      case 1: c = fp_core_cand(b, len, &s, 0); break;
      case 2: c = fp_core_walk(b, len, &s, 1); break;
      case 3: c = fp_core_cand(b, len, &s, 1); break;
      case 4:
      case 6: c = fast_parse_learn(b, len, &s, &T[0]); break;
      default: c = fast_parse_learn_scalar(b, len, &s, &T[1]); break;
    }
    if (!same(a, f, c, &s) || (a > 0 && f->id != s.id))
      r = fz_err(err, en, "fast_parse %d, %s %d", a, NAME[i < 6 ? i : i - 2], c);
  }
  free(T);
  if (r) return r;
  // learned templates, fresh tables per input: the first call leaves it pending, the second makes a template
  // of it, the third goes through that template; every call == fast_parse (SIMD and scalar tables)
  fp_tmpl_t *X = calloc(2, sizeof *X);
  for (int i = 0; i < 6 && !r; i++) {
    req_t s;
    memset(&s, 0, sizeof s);
    int c = i & 1 ? fast_parse_tmpl_scalar(b, len, &s, &X[1]) : fast_parse_tmpl(b, len, &s, &X[0]);
    if (!same(a, f, c, &s) || (a > 0 && f->id != s.id))
      r = fz_err(err, en, "fast_parse %d, learned template/%s %d (call %d)", a, i & 1 ? "scalar" : "simd", c, i / 2);
  }
  free(X);
  if (r) return r;
  // a template made of this request alone must reproduce fast_parse's result on it
  if (a > 0) {
    fp_tm_t *S = calloc(1, sizeof *S);
    if (fp_tm_shape(b, f->body_off, S) && fp_tm_compile(S))
      for (int simd = 0; simd < 2 && !r; simd++) {
        req_t s;
        memset(&s, 0, sizeof s);
        int lim = len < FP_MAXHDR ? len : FP_MAXHDR, me, pe, c = -2;
        if (simd ? fp_tm_rl(1, b, lim, &me, &pe) : fp_tm_rl(0, b, lim, &me, &pe))
          c = simd ? fp_tm_try(b, len, &s, S, 1, lim, me, pe) : fp_tm_try(b, len, &s, S, 0, lim, me, pe);
        if (c != -2 && (!same(a, f, c, &s) || f->id != s.id))
          r = fz_err(err, en, "fast_parse %d, its own template/%s %d", a, simd ? "simd" : "scalar", c);
      }
    free(S);
    if (r) return r;
  }
  // a layout built from this request must reproduce fast_parse's result on it
  req_t q;
  int l0 = fp_reqline_canon(b, &q);
  if (l0 && a > 0) {
    fp_layout_t L;
    memset(&L, 0, sizeof L);
    if (fp_layout_build(b, l0, f->body_off, f->route, &L))
      for (int simd = 0; simd < 2; simd++) {
        req_t t = q;
        int c = simd ? fp_try_layout(b, len, &t, l0, &L, 1) : fp_try_layout(b, len, &t, l0, &L, 0);
        if (c != -2 && (!same(a, f, c, &t) || f->id != t.id))
          return fz_err(err, en, "fast_parse %d, own layout (simd %d) %d", a, simd, c);
      }
  }
  // fp_quick_get (batchparse.h's GET entry): a claim must be exactly fast_parse's result, with no body
  if (l0 && !fp_route_lines(q.route))
    for (int simd = 0; simd < 2; simd++) {
      int h = simd ? fp_quick_get(b, len, 1) : fp_quick_get(b, len, 0);
      if (h > 0 && (a != h || f->body_len != 0 || f->route != q.route))
        return fz_err(err, en, "fp_quick_get (simd %d) %d, fast_parse %d", simd, h, a);
    }
  return 0;
}
static int fz_fast_one(const char *b, const char *b2, int len, int prefixes, char *err, size_t en) {
  req_t f, f2, g;
  memset(&f, 0, sizeof f);
  memset(&f2, 0, sizeof f2);
  memset(&g, 0, sizeof g);
  int a = fast_parse(b, len, &f), a2 = fast_parse(b2, len, &f2), c = ref_parse(b, len, &g);
  if (a2 > 0) req_rebase(&f2, b2, b);
  if (!same(a, &f, a2, &f2) || (a > 0 && f.id != f2.id))
    return fz_err(err, en, "fast_parse depends on the padding: %d vs %d", a, a2);
  if (fz_fast_backends(b, len, a, &f, err, en)) return 1;
  if (a > 0 && !fz_conn(b, f.body_off, 0)) // RFC 9112 9.6: a close (or anything but keep-alive) must reach the caller
    return fz_err(err, en, "fast_parse completes a request whose Connection header is not keep-alive");
  if (c != -2 && a != FP_FALLBACK && c != FP_FALLBACK && !same(a, &f, c, &g))
    return fz_err(err, en, "fast_parse %d (route %d id %lld body %d+%d), ref_parse %d (route %d id %lld body %d+%d)", a,
                  f.route, (long long)f.id, f.body_off, f.body_len, c, g.route, (long long)g.id, g.body_off,
                  g.body_len);
  if (prefixes && a > 0) { // every prefix of a complete request: NEED_MORE or FALLBACK, never complete or invalid
    int step = a <= 4096 ? 1 : a / 1024;
    for (int t = 0; t < a; t += step) {
      req_t p;
      int x = fast_parse(b, t, &p);
      if (x != FP_NEED_MORE && x != FP_FALLBACK)
        return fz_err(err, en, "fast_parse completes at %d bytes, %d on the %d-byte prefix", a, x, t);
    }
  }
  return 0;
}
static int fz_check_fast(const char *d, size_t len, char *err, size_t en) {
  if (len >= (1u << 30)) return 0;
  char *b = fz_copy(d, len, 0), *b2 = fz_copy(d, len, 1);
  int r = fz_fast_one(b, b2, (int)len, 1, err, en);
  // the input as a pipelined stream: fast_parse_many (SIMD, scalar, learned) == repeated fast_parse
  for (int max = 1; !r && max <= 16; max *= 4) {
    req_t o1[16], o2[16], o3[16];
    fp_learn_t *T = calloc(1, sizeof *T);
    fp_batch_t x = fast_parse_many(b, (int)len, o1, max), y = fast_parse_many_scalar(b, (int)len, o2, max),
               z = fast_parse_many_learn(b, (int)len, o3, max, T);
    free(T);
    int used = 0, n = 0, st = FP_FULL;
    while (n < max) {
      req_t t;
      int c = fast_parse(b + used, (int)len - used, &t);
      if (c <= 0) {
        st = c;
        break;
      }
      t.body_off += used;
      if (n >= x.n || !same(c, &t, c, &o1[n])) {
        r = fz_err(err, en, "fast_parse_many request %d differs from fast_parse", n);
        break;
      }
      used += c;
      n++;
    }
    if (r) break;
    if (n == max && used == (int)len) st = FP_NEED_MORE;
    if (x.n != n || x.used != used || x.status != st)
      r = fz_err(err, en, "fast_parse_many(max %d): n %d/%d used %d/%d status %d/%d", max, x.n, n, x.used, used,
                 x.status, st);
    else if (y.n != x.n || y.used != x.used || y.status != x.status)
      r = fz_err(err, en, "fast_parse_many_scalar(max %d) differs", max);
    else if (z.n != x.n || z.used != x.used || z.status != x.status)
      r = fz_err(err, en, "fast_parse_many_learn(max %d) differs", max);
    for (int i = 0; !r && i < x.n; i++)
      if (!same(1, &o1[i], 1, &o2[i]) || !same(1, &o1[i], 1, &o3[i]) || o1[i].id != o3[i].id)
        r = fz_err(err, en, "fast_parse_many(max %d) request %d: variants differ", max, i);
  }
  // and each request of the stream on its own (the second and later ones start mid-buffer)
  for (int used = 0, k = 0; !r && k < 16; k++) {
    req_t t;
    int c = fast_parse(b + used, (int)len - used, &t);
    if (c <= 0) break;
    used += c;
    if (used < (int)len) r = fz_fast_one(b + used, b2 + used, (int)len - used, 0, err, en);
  }
  free(b);
  free(b2);
  return r;
}

// ---- batchparse.h: every lane == fast_parse ----
typedef void (*fz_bfn)(int, const char *const *, const int *, req_t *, int *);
static void fz_b_c(int n, const char *const *b, const int *l, req_t *o, int *r) { bp_parse_rl(n, b, l, o, r, BP_RL_C); }
static void fz_b_canon(int n, const char *const *b, const int *l, req_t *o, int *r) {
  bp_parse_rl(n, b, l, o, r, BP_RL_CANON);
}
#ifdef BP_HAVE_AVX2
static void fz_b_avx2(int n, const char *const *b, const int *l, req_t *o, int *r) {
  bp_parse_rl(n, b, l, o, r, BP_RL_AVX2);
}
static void fz_b_avx2i(int n, const char *const *b, const int *l, req_t *o, int *r) {
  bp_parse_rl(n, b, l, o, r, BP_RL_AVX2I);
}
#endif
#ifdef BP_HAVE_Z
static void fz_b_z(int n, const char *const *b, const int *l, req_t *o, int *r) { bp_parse_rl(n, b, l, o, r, BP_RL_Z); }
#endif
static const struct {
  const char *name;
  fz_bfn f;
} FZ_BVAR[] = {
  { "lane-C", fz_b_c },         { "lane-canon", fz_b_canon },
#ifdef BP_HAVE_AVX2
  { "avx2-gather", fz_b_avx2 }, { "avx2-insert", fz_b_avx2i },
#endif
#ifdef BP_HAVE_Z
  { "avx512-zmm", fz_b_z },
#endif
};
// Lanes: each request start of the input read as a pipelined stream (up to 32), each at its full remaining
// length and at a truncation derived from the input; all lanes alias the one buffer.
static int fz_check_batch(const char *d, size_t len, char *err, size_t en) {
  if (len >= (1u << 30)) return 0;
  enum { NL = 64 };
  char *b = fz_copy(d, len, 1);
  const char *bufs[NL];
  int lens[NL], want[NL], n = 0, r = 0;
  req_t ref[NL];
  uint64_t h = fz_hash(d, len) | 1;
  for (int used = 0, k = 0; k < 32 && used <= (int)len; k++) {
    int rest = (int)len - used;
    bufs[n] = b + used;
    lens[n++] = rest;
    h ^= h << 13;
    h ^= h >> 7;
    h ^= h << 17;
    bufs[n] = b + used;
    lens[n++] = rest ? (int)(h % (uint64_t)(rest + 1)) : 0;
    req_t t;
    int c = fast_parse(b + used, rest, &t);
    if (c <= 0) break;
    used += c;
  }
  for (int i = 0; i < n; i++) {
    memset(&ref[i], 0, sizeof ref[i]);
    want[i] = fast_parse(bufs[i], lens[i], &ref[i]);
  }
  for (size_t v = 0; v < sizeof FZ_BVAR / sizeof *FZ_BVAR && !r; v++) {
    req_t out[NL];
    int ret[NL];
    memset(out, 0xA5, sizeof out);
    for (int i = 0; i < n; i++) ret[i] = 0x7777;
    FZ_BVAR[v].f(n, bufs, lens, out, ret);
    for (int i = 0; i < n && !r; i++)
      if (!same(want[i], &ref[i], ret[i], &out[i]) || (want[i] > 0 && ref[i].id != out[i].id))
        r = fz_err(err, en, "batchparse %s lane %d/%d (offset %d, len %d): %d, fast_parse %d", FZ_BVAR[v].name, i, n,
                   (int)(bufs[i] - b), lens[i], ret[i], want[i]);
  }
  free(b);
  return r;
}

// ---- fbparse.h's chunked decoder vs picohttpparser's phr_decode_chunked (consume_trailer = 1) ----
// fb_decode_chunked is the stricter of the two, so: whatever it accepts, pico accepts with the same body and the
// same length; whatever pico rejects, it rejects; when it waits for more, so does pico. It also must not depend
// on bytes past len, decode in place to the same bytes, and stop at max_body exactly.
static int fz_check_chunked(const char *d, size_t n, char *err, size_t en) {
  if (n >= (1u << 24)) return 0;
  int len = (int)n, bl = -1, bl2 = -1, bl3 = -1;
  // out of place: a buffer of max_body bytes; a body is never longer than its encoding, so max_body = n + 1
  char *b = fz_copy(d, n, 1), *out = malloc(n + 1), *in = fz_copy(d, n, 0), *pc = malloc(n + 1);
  int r = fb_decode_chunked(b, len, out, len + 1, &bl), r2 = fb_decode_chunked(in, len, in, len + 1, &bl2), res = 0;
  memcpy(pc, d, n);
  struct phr_chunked_decoder dec;
  memset(&dec, 0, sizeof dec);
  dec.consume_trailer = 1;
  size_t sz = n;
  ssize_t pr = phr_decode_chunked(&dec, pc, &sz);
  if (r != r2 || (r > 0 && (bl != bl2 || memcmp(out, in, bl))))
    res = fz_err(err, en, "fb_decode_chunked: in place %d (%d bytes), out of place %d (%d bytes)", r2, bl2, r, bl);
  else if (r > 0 && (pr < 0 || (int)(n - pr) != r || (int)sz != bl || memcmp(pc, out, bl)))
    res = fz_err(err, en, "fb_decode_chunked accepts %d bytes (body %d), pico %zd (body %zu)", r, bl, pr, sz);
  else if (pr == -1 && r != FB_CHUNK_INVALID && r != FB_CHUNK_TOO_LARGE) // both refuse (a size over the limit
    res = fz_err(err, en, "pico rejects, fb_decode_chunked %d", r);      // can come before pico's bad byte)
  else if (r == FB_CHUNK_NEED_MORE && pr != -2) res = fz_err(err, en, "fb_decode_chunked waits for more, pico %zd", pr);
  else if (r > 0) { // max_body: exactly the body fits; one byte less is too large (unless the body is empty)
    int t = fb_decode_chunked(b, len, out, bl, &bl3);
    if (t != r || bl3 != bl) res = fz_err(err, en, "max_body = body (%d): %d", bl, t);
    else if (bl > 0 && fb_decode_chunked(b, len, out, bl - 1, &bl3) != FB_CHUNK_TOO_LARGE)
      res = fz_err(err, en, "max_body = body - 1 is not too large");
  }
  free(b);
  free(out);
  free(in);
  free(pc);
  return res;
}
