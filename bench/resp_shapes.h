// resp_shapes.h - deterministic response heads for the benchmarks (bench/bench_resp.c, bench/codspeed): nginx-like
// static 200s, CDN responses with many and long fields (CSP, cookies, cache headers), small API responses, and 304s.
// rs_shape(k, buf) writes one head of shape k (RS_NGINX .. RS_304) and returns its length; the PRNG is rs_seed()'s.
#pragma once
#include <stdint.h>
#include <stdio.h>

static uint64_t rs_state = 0x9E3779B97F4A7C15ull;
static uint32_t rnd(void) {
  rs_state ^= rs_state << 13;
  rs_state ^= rs_state >> 7;
  rs_state ^= rs_state << 17;
  return (uint32_t)rs_state;
}
static void rs_seed(void) { rs_state = 0x9E3779B97F4A7C15ull; }

static const char *DAYS[] = { "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun" };
static int date(char *s) {
  return sprintf(s, "%s, %02u Nov 2026 %02u:%02u:%02u GMT", DAYS[rnd() % 7], 1 + rnd() % 28, rnd() % 24, rnd() % 60,
                 rnd() % 60);
}
static void hex(char *s, int n) {
  for (int i = 0; i < n; i++) s[i] = "0123456789abcdef"[rnd() % 16];
  s[n] = 0;
}
static int shape_nginx(char *s) {
  char d[64], e[16];
  date(d);
  hex(e, 8);
  return sprintf(s,
                 "HTTP/1.1 200 OK\r\nServer: nginx/1.26.%u\r\nDate: %s\r\nContent-Type: text/html\r\n"
                 "Content-Length: %u\r\nLast-Modified: %s\r\nConnection: keep-alive\r\nETag: \"%s-%x\"\r\n"
                 "Accept-Ranges: bytes\r\n\r\n",
                 rnd() % 3, d, 100 + rnd() % 90000, d, e, rnd() % 99999);
}
static int shape_cdn(char *s) {
  char d[64], id[64], ck[200], csp[600];
  date(d);
  hex(id, 40);
  hex(ck, 120);
  int n = sprintf(csp, "default-src 'self'; script-src 'self' 'nonce-%.16s'", ck);
  for (int i = 0; i < 6 + (int)(rnd() % 6); i++) n += sprintf(csp + n, " https://cdn%u.example-cdn.net", rnd() % 100);
  return sprintf(s,
                 "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nTransfer-Encoding: chunked\r\n"
                 "Connection: keep-alive\r\nDate: %s\r\nCache-Control: private, max-age=0, must-revalidate\r\n"
                 "Content-Security-Policy: %s\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains; "
                 "preload\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n"
                 "Referrer-Policy: strict-origin-when-cross-origin\r\nSet-Cookie: session=%s; Path=/; Secure; "
                 "HttpOnly; SameSite=Lax\r\nSet-Cookie: _ga=GA1.1.%u.%u; Path=/; Max-Age=63072000\r\n"
                 "Vary: Accept-Encoding\r\nContent-Encoding: gzip\r\nX-Cache: Hit from cloudfront\r\n"
                 "Via: 1.1 %.32s.cloudfront.net (CloudFront)\r\nX-Amz-Cf-Pop: LHR61-P%u\r\nX-Amz-Cf-Id: %s==\r\n"
                 "Age: %u\r\nAlt-Svc: h3=\":443\"; ma=86400\r\nServer-Timing: cdn-cache; desc=HIT, edge; dur=%u\r\n"
                 "\r\n",
                 d, csp, ck, rnd(), rnd(), id, 1 + rnd() % 9, id, rnd() % 5000, rnd() % 40);
}
static int shape_api(char *s) {
  char d[64], rid[40];
  date(d);
  hex(rid, 32);
  return sprintf(s,
                 "HTTP/1.1 %s\r\nContent-Type: application/json\r\nContent-Length: %u\r\nDate: %s\r\n"
                 "X-Request-Id: %s\r\nConnection: keep-alive\r\n\r\n",
                 rnd() % 8 ? "200 OK" : "404 Not Found", 2 + rnd() % 4000, d, rid);
}
static int shape_304(char *s) {
  char d[64], e[24];
  date(d);
  hex(e, 16);
  return sprintf(s, "HTTP/1.1 304 Not Modified\r\nDate: %s\r\nETag: W/\"%s\"\r\nCache-Control: max-age=%u\r\n\r\n", d,
                 e, rnd() % 86400);
}

enum { RS_NGINX, RS_CDN, RS_API, RS_304, RS_N };
static const char *const RS_NAME[RS_N] = { "nginx-static", "cdn", "api", "304" };
static int rs_shape(int k, char *s) {
  return k == RS_NGINX ? shape_nginx(s) : k == RS_CDN ? shape_cdn(s) : k == RS_API ? shape_api(s) : shape_304(s);
}
