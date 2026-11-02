// Shared by the tests and benchmarks: timer, PRNG, the reference semantics on top of a pico-style parser, and the
// request corpus generator (k6 and gocli shapes). Include after the parser header and picohttpparser.h.
#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#define PAD 64
static double now(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return t.tv_sec * 1e9 + t.tv_nsec;
}
static uint64_t rs = 0x9E3779B97F4A7C15ull;
static uint32_t rnd(void) {
  rs ^= rs << 13;
  rs ^= rs >> 7;
  rs ^= rs << 17;
  return (uint32_t)rs;
}

// out-of-line entry points, so the benchmark compares calls with calls (pico is a real call too)
__attribute__((noinline)) static int P_fast(const char *b, int l, req_t *r) { return fast_parse(b, l, r); }
__attribute__((noinline)) static int P_scalar(const char *b, int l, req_t *r) { return fast_parse_scalar(b, l, r); }
__attribute__((noinline)) static int P_cand_scalar(const char *b, int l, req_t *r) { return fp_core_cand(b, l, r, 0); }
__attribute__((noinline)) static int P_cand_simd(const char *b, int l, req_t *r) { return fp_core_cand(b, l, r, 1); }
__attribute__((noinline)) static int P_walk_simd(const char *b, int l, req_t *r) { return fp_core_walk(b, l, r, 1); }
__attribute__((noinline)) static fp_batch_t P_many(const char *b, int l, req_t *o, int m) {
  return fast_parse_many(b, l, o, m);
}
__attribute__((noinline)) static fp_batch_t P_many_scalar(const char *b, int l, req_t *o, int m) {
  return fast_parse_many_scalar(b, l, o, m);
}

// ---- reference: picohttpparser + identical semantics, with its own plain routing/digits ----
static int64_t ref_digits(const char *p, int n, int *ok) {
  *ok = 0;
  if (n < 1 || n > 16) return 0;
  int64_t v = 0;
  for (int i = 0; i < n; i++) {
    unsigned d = (unsigned char)p[i] - '0';
    if (d > 9) return 0;
    v = v * 10 + d;
  }
  *ok = v > 0;
  return v;
}
static void ref_route(const char *m, int ml, const char *p, int pl, req_t *r) { // fastparse.h fp_route, verbatim logic
  r->route = R_NOTFOUND;
  r->id_ok = 0;
  r->id = 0;
  if (ml == 3 && !memcmp(m, "GET", 3)) {
    if (pl == 5 && !memcmp(p, "/feed", 5)) r->route = R_FEED;
    else if (pl == 7 && !memcmp(p, "/health", 7)) r->route = R_HEALTH;
    else if (pl >= 7 && !memcmp(p, "/posts/", 7)) {
      r->id = ref_digits(p + 7, pl - 7, &r->id_ok);
      r->route = (r->id_ok || !memchr(p + 7, '/', pl - 7)) ? R_GETPOST : R_NOTFOUND;
    }
  } else if (ml == 4 && !memcmp(m, "POST", 4)) {
    if (pl == 6 && !memcmp(p, "/posts", 6)) r->route = R_CREATE;
    else if (pl >= 12 && !memcmp(p, "/posts/", 7) && !memcmp(p + pl - 5, "/like", 5)) {
      r->id = ref_digits(p + 7, pl - 12, &r->id_ok);
      r->route = (r->id_ok || !memchr(p + 7, '/', pl - 12)) ? R_LIKE : R_NOTFOUND;
    }
  }
}
// any parser with picohttpparser's phr_parse_request signature (pico itself, and the llhttp
// adapter in bench/) + the same routing/header logic = a reference with fast_parse's semantics
typedef int (*phr_fn)(const char *, size_t, const char **, size_t *, const char **, size_t *, int *,
                      struct phr_header *, size_t *, size_t);
static inline __attribute__((always_inline)) int ref_parse_with(phr_fn parse, const char *b, int len, req_t *r) {
  const char *m, *p;
  size_t ml, pl, nh = 48;
  int minor;
  struct phr_header h[48];
  int ret = parse(b, len, &m, &ml, &p, &pl, &minor, h, &nh, 0);
  if (ret == -2) return FP_NEED_MORE;
  if (ret < 0) return -2; // pico says invalid
  if (minor != 1) return FP_FALLBACK;
  ref_route(m, (int)ml, p, (int)pl, r);
  int cl = 0, have_auth = 0, have_cl = 0;
  r->auth = 0;
  r->tok = 0;
  r->tok_len = 0;
#if FP_NHDR > 0
  unsigned want = fp_route_hdrs(r->route); // the spec's headers: first line of each name, pico's trimmed value
  for (int j = 0; j < FP_NHDR; j++) {
    r->hdr[j] = 0;
    r->hdr_len[j] = 0;
  }
#endif
  for (size_t i = 0; i < nh; i++) {
    if (!h[i].name) continue;
#if FP_NHDR > 0
    for (int j = 0; j < FP_NHDR; j++)
      if ((want >> j & 1) && h[i].name_len == (size_t)fp_hdr_names[j].len &&
          !strncasecmp(h[i].name, fp_hdr_names[j].lc, h[i].name_len)) {
        r->hdr[j] = h[i].value;
        r->hdr_len[j] = (int)h[i].value_len;
        want &= ~(1u << j);
      }
#endif
    if (h[i].name_len == 13 && !strncasecmp(h[i].name, "authorization", 13) && !have_auth) {
      have_auth = 1;
      if (h[i].value_len >= 7 && !memcmp(h[i].value, "Bearer ", 7)) {
        r->auth = 1;
        r->tok = h[i].value + 7;
        r->tok_len = (int)h[i].value_len - 7;
      }
    } else if (h[i].name_len == 14 && !strncasecmp(h[i].name, "content-length", 14)) {
      if (have_cl || h[i].value_len < 1 || h[i].value_len > 9) return FP_FALLBACK;
      int x = 0;
      for (size_t k = 0; k < h[i].value_len; k++) {
        unsigned d = h[i].value[k] - '0';
        if (d > 9) return FP_FALLBACK;
        x = x * 10 + d;
      }
      if (h[i].value_len > 1 && h[i].value[0] == '0') return FP_FALLBACK;
      cl = x;
      have_cl = 1;
    } else if (h[i].name_len >= 16 && !strncasecmp(h[i].name, "transfer-encodin", 16)) return FP_FALLBACK;
  }
  if (r->route != R_CREATE && r->route != R_LIKE) {
    r->auth = 0;
    r->tok = 0;
    r->tok_len = 0;
  }
  if (ret + cl > len) return FP_NEED_MORE;
  r->body_off = ret;
  r->body_len = cl;
  return ret + cl;
}
static int ref_parse(const char *b, int len, req_t *r) { return ref_parse_with(phr_parse_request, b, len, r); }

static int same(int a, const req_t *x, int b, const req_t *y) {
  if (a != b) return 0;
  if (a <= 0) return 1;
#if FP_NHDR > 0
  for (int j = 0; j < FP_NHDR; j++)
    if (x->hdr[j] != y->hdr[j] || (x->hdr[j] && x->hdr_len[j] != y->hdr_len[j])) return 0;
#endif
  return x->route == y->route && x->id_ok == y->id_ok && (!x->id_ok || x->id == y->id) && x->auth == y->auth &&
         x->tok_len == y->tok_len && (!x->auth || x->tok == y->tok) && x->body_off == y->body_off &&
         x->body_len == y->body_len;
}
// a result parsed from a copy of the buffer at `from`, re-pointed at the original `to` (same() compares pointers)
static void req_rebase(req_t *r, const char *from, const char *to) {
  if (r->auth) r->tok = to + (r->tok - from);
#if FP_NHDR > 0
  for (int j = 0; j < FP_NHDR; j++)
    if (r->hdr[j]) r->hdr[j] = to + (r->hdr[j] - from);
#endif
  (void)from;
  (void)to;
}

// ---- corpus in k6 (Go net/http) request format ----
static char TOKS[64][256];
static void mk_tokens(void) {
  const char *a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  for (int t = 0; t < 64; t++) {
    int n = sprintf(TOKS[t], "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.");
    for (int i = 0; i < 96 + (int)(rnd() % 20); i++) TOKS[t][n++] = a[rnd() % 64];
    TOKS[t][n++] = '.';
    for (int i = 0; i < 43; i++) TOKS[t][n++] = a[rnd() % 64];
    TOKS[t][n] = 0;
  }
}
// shape 0: k6 (Go net/http header order); 1/2: "gocli", a minimal Go load generator's request writer,
// with / without -gzip. These bytes live only in the test, never in the parser.
static int gen_gocli(char *s, int gz) {
  uint32_t r = rnd() % 1000;
  unsigned id = 1 + rnd() % 500000;
  const char *tok = TOKS[rnd() % 64];
  int n = 0;
  if (r < 460) n = sprintf(s, "GET /feed HTTP/1.1\r\n");
  else if (r < 920) n = sprintf(s, "GET /posts/%u HTTP/1.1\r\n", id);
  else if (r < 990) n = sprintf(s, "POST /posts/%u/like HTTP/1.1\r\n", id);
  else n = sprintf(s, "POST /posts HTTP/1.1\r\n");
  n += sprintf(s + n, "Host: 10.0.0.5\r\nUser-Agent: gocli\r\n%s", gz ? "Accept-Encoding: gzip\r\n" : "");
  if (r >= 920) n += sprintf(s + n, "Authorization: Bearer %s\r\n", tok);
  if (r >= 990) {
    char body[200];
    int bl = sprintf(body, "{\"body\":\"post %u from gocli\"}", id);
    return n + sprintf(s + n, "Content-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", bl, body);
  }
  if (r >= 920) return n + sprintf(s + n, "Content-Length: 0\r\n\r\n");
  return n + sprintf(s + n, "\r\n");
}
// shapes 3/4: traffic with no API spec, where only learning can help (the API routes never appear).
// 3 "browser": one site, Chrome and Firefox header orders per resource type (document, script, style,
// image, fetch GET/POST), per-user cookies of varying length, referers, asset paths with hashes.
// 4 "proxy": a reverse proxy's mix: curl, python-requests, Go, okhttp, k6 and browser clients, 6 vhosts,
// arbitrary REST paths and methods, X-Forwarded-For / X-Request-Id / Authorization with varying values.
static const char *HEX = "0123456789abcdef";
__attribute__((unused)) static int rhex(char *s, int n) {
  for (int i = 0; i < n; i++) s[i] = HEX[rnd() % 16];
  return n;
}
__attribute__((unused)) static int gen_path(char *s) {
  static const char *P[] = { "/static/js/app.%x.js",
                             "/static/css/main.%x.css",
                             "/img/p/%u/%u.webp",
                             "/product/%u",
                             "/api/v2/cart/%u/items",
                             "/search?q=red+shoes&page=%u",
                             "/",
                             "/account/orders/%u",
                             "/fonts/inter-%u.woff2",
                             "/api/v2/reco?user=%u&n=%u" };
  return sprintf(s, P[rnd() % 10], rnd() % 100000, rnd() % 1000, rnd() % 50);
}
__attribute__((unused)) static int gen_browser(char *s) {
  static const char *CH_UA = "\"Chromium\";v=\"130\", \"Google Chrome\";v=\"130\", \"Not?A_Brand\";v=\"99\"";
  static const char *UA_C =
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";
  static const char *UA_F = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0";
  static const char *ACC[] = {
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "*/*",
    "text/css,*/*;q=0.1",
    "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
    "application/json",
    "application/json"
  };
  static const char *DEST[] = { "document", "script", "style", "image", "empty", "empty" },
                    *MODE[] = { "navigate", "no-cors", "no-cors", "no-cors", "cors", "cors" };
  uint32_t k = rnd() % 100;
  int kind = k < 10 ? 0 : k < 25 ? 1 : k < 35 ? 2 : k < 80 ? 3 : k < 95 ? 4 : 5, ff = rnd() % 10 < 3;
  unsigned user = rnd() % 2000;
  char path[96], ref[128], ck[400];
  gen_path(path);
  int rl = sprintf(ref, "https://shop.example.com/product/%u", rnd() % 100000);
  int cl = sprintf(ck, "sid=%08x%08x%08x%08x", user * 2654435761u, user * 40503u, user ^ 0x5bd1e995u, user * 97u);
  if (user % 3) cl += sprintf(ck + cl, "; _ga=GA1.1.%u.%u", user * 7919u, 1700000000u + user);
  if (user % 5 == 0) {
    cl += sprintf(ck + cl, "; cart=");
    cl += rhex(ck + cl, 8 + user % 120);
    ck[cl] = 0;
  }
  if (user % 7 == 0) cl += sprintf(ck + cl, "; consent=1");
  const char *m = kind == 5 ? "POST" : "GET";
  char body[160];
  int bl = kind == 5 ? sprintf(body, "{\"sku\":%u,\"qty\":%u}", rnd() % 100000, 1 + rnd() % 9) : 0;
  int n = sprintf(s, "%s %s HTTP/1.1\r\nHost: shop.example.com\r\n", m, kind == 5 ? "/api/v2/cart/items" : path);
  if (!ff) {
    n += sprintf(s + n, "Connection: keep-alive\r\n");
    if (bl) n += sprintf(s + n, "Content-Length: %d\r\n", bl);
    n += sprintf(s + n, "sec-ch-ua-platform: \"macOS\"\r\n");
    if (kind == 0)
      n += sprintf(s + n, "sec-ch-ua: %s\r\nsec-ch-ua-mobile: ?0\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: %s\r\n",
                   CH_UA, UA_C);
    else n += sprintf(s + n, "User-Agent: %s\r\nsec-ch-ua: %s\r\nsec-ch-ua-mobile: ?0\r\n", UA_C, CH_UA);
    n += sprintf(s + n, "Accept: %s\r\n", ACC[kind]);
    if (bl) n += sprintf(s + n, "Content-Type: application/json\r\nOrigin: https://shop.example.com\r\n");
    n += sprintf(s + n, "Sec-Fetch-Site: same-origin\r\nSec-Fetch-Mode: %s\r\n%sSec-Fetch-Dest: %s\r\n", MODE[kind],
                 kind == 0 ? "Sec-Fetch-User: ?1\r\n" : "", DEST[kind]);
    n += sprintf(
        s + n,
        "Referer: %.*s\r\nAccept-Encoding: gzip, deflate, br, zstd\r\nAccept-Language: en-GB,en;q=0.9\r\nCookie: %s\r\n\r\n",
        rl, ref, ck);
  } else {
    n += sprintf(
        s + n,
        "User-Agent: %s\r\nAccept: %s\r\nAccept-Language: en-GB,en;q=0.5\r\nAccept-Encoding: gzip, deflate, br, zstd\r\n",
        UA_F, ACC[kind]);
    if (bl)
      n += sprintf(s + n,
                   "Content-Type: application/json\r\nContent-Length: %d\r\nOrigin: https://shop.example.com\r\n", bl);
    n += sprintf(s + n, "Connection: keep-alive\r\nReferer: %.*s\r\nCookie: %s\r\n", rl, ref, ck);
    if (kind == 0) n += sprintf(s + n, "Upgrade-Insecure-Requests: 1\r\n");
    n += sprintf(
        s + n, "Sec-Fetch-Dest: %s\r\nSec-Fetch-Mode: %s\r\nSec-Fetch-Site: same-origin\r\n%sPriority: u=%d, i\r\n\r\n",
        DEST[kind], MODE[kind], kind == 0 ? "Sec-Fetch-User: ?1\r\n" : "", kind == 0 ? 0 : 4);
  }
  return n + sprintf(s + n, "%.*s", bl, body);
}
__attribute__((unused)) static int gen_proxy(char *s) {
  static const char *HOSTS[] = { "api.example.com", "shop.example.com",      "auth.example.com",
                                 "img.example.net", "internal-billing:8080", "10.1.4.7:9000" };
  static const char *M[] = { "GET", "GET", "GET", "GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS" };
  static const char *RES[] = { "users", "orders", "invoices", "sessions", "items", "events" };
  uint32_t c = rnd() % 100;
  const char *h = HOSTS[rnd() % 6], *m = M[rnd() % 10];
  char path[128];
  int pl = sprintf(path, "/v%u/%s/%u", 1 + rnd() % 3, RES[rnd() % 6], rnd() % 1000000);
  if (rnd() % 3 == 0) pl += sprintf(path + pl, "/%s", RES[rnd() % 6]);
  if (rnd() % 4 == 0)
    pl += sprintf(path + pl, "?limit=%u&cursor=", 10 * (1 + rnd() % 10)), pl += rhex(path + pl, 12), path[pl] = 0;
  char xff[64];
  sprintf(xff, "X-Forwarded-For: %u.%u.%u.%u\r\nX-Request-Id: ", 1 + rnd() % 223, rnd() % 256, rnd() % 256,
          1 + rnd() % 254);
  char rid[40];
  rhex(rid, 32);
  rid[32] = 0;
  int body = (!strcmp(m, "POST") || !strcmp(m, "PUT") || !strcmp(m, "PATCH")) ? 10 + rnd() % 120 : 0, n;
  if (c < 25)
    n = sprintf(s, "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: curl/8.%u.0\r\nAccept: */*\r\n%s%s\r\n", m, path, h,
                5 + rnd() % 6, xff, rid);
  else if (c < 45)
    n = sprintf(
        s,
        "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: python-requests/2.32.3\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\n%s%s\r\n",
        m, path, h, xff, rid);
  else if (c < 70) {
    n = sprintf(s, "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Go-http-client/1.1\r\n", m, path, h);
    if (rnd() % 2) { n += sprintf(s + n, "Authorization: Bearer %s\r\n", TOKS[rnd() % 64]); }
    n += sprintf(s + n, "%s%s\r\nAccept-Encoding: gzip\r\n", xff, rid);
  } else if (c < 85)
    n = sprintf(
        s,
        "%s %s HTTP/1.1\r\nHost: %s\r\nAccept: application/json\r\nAuthorization: Bearer %s\r\n%s%s\r\nConnection: Keep-Alive\r\nAccept-Encoding: gzip\r\nUser-Agent: okhttp/4.12.0\r\n",
        m, path, h, TOKS[rnd() % 64], xff, rid);
  else if (c < 93)
    n = sprintf(
        s, "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: k6/0.54.0 (https://k6.io/)\r\nAccept-Encoding: gzip\r\n%s%s\r\n",
        m, path, h, xff, rid);
  else
    n = sprintf(
        s,
        "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0\r\nAccept: */*\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate, br, zstd\r\n%s%s\r\nConnection: keep-alive\r\n",
        m, path, h, xff, rid);
  if (body) {
    n += sprintf(s + n, "Content-Type: application/json\r\nContent-Length: %d\r\n\r\n", body);
    memset(s + n, 'x', body);
    return n + body;
  }
  return n + sprintf(s + n, "\r\n");
}
#define CORPUS_N 5
__attribute__((unused)) static const char *CORPUS_NAME[CORPUS_N] = { "k6", "gocli -gzip", "gocli", "browser (no spec)",
                                                                     "proxy (no spec)" };
static int gen(char *s, int shape) {
  if (shape == 3) return gen_browser(s);
  if (shape == 4) return gen_proxy(s);
  if (shape) return gen_gocli(s, shape == 1);
  const char *H = "Host: 203.0.113.10\r\nUser-Agent: k6/0.54.0 (https://k6.io/)\r\n";
  uint32_t r = rnd() % 1000;
  unsigned id = 1 + rnd() % 500000;
  if (r < 460) return sprintf(s, "GET /feed HTTP/1.1\r\n%sAccept-Encoding: gzip\r\n\r\n", H);
  if (r < 920) return sprintf(s, "GET /posts/%u HTTP/1.1\r\n%sAccept-Encoding: gzip\r\n\r\n", id, H);
  const char *tok = TOKS[rnd() % 64];
  if (r < 990)
    return sprintf(
        s,
        "POST /posts/%u/like HTTP/1.1\r\n%sContent-Length: 0\r\nAccept-Encoding: gzip\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\n\r\n",
        id, H, tok);
  char body[200];
  int bl = sprintf(body, "{\"body\":\"silver_comet_%u says hi at 2026-10-24T08:00:00.000Z (VU %u, iter %u)\"}",
                   id % 20000, id % 9000, id % 50);
  return sprintf(
      s,
      "POST /posts HTTP/1.1\r\n%sContent-Length: %d\r\nAccept-Encoding: gzip\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\n\r\n%s",
      H, bl, tok, body);
}
