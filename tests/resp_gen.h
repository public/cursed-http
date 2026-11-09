// resp_gen.h - generated HTTP/1.x responses for the response-parser tests and benchmarks (tests/test_resp.c,
// tests/test_resp_httparse.c, bench/bench_resp.c): realistic status lines and header fields, the grey areas
// (obs-fold, bare LF, whitespace before the colon, odd status codes, long names and values), and byte mutations.
#pragma once
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PAD 64
static uint64_t rs = 0x9E3779B97F4A7C15ull;
static uint32_t rnd(void) {
  rs ^= rs << 13;
  rs ^= rs >> 7;
  rs ^= rs << 17;
  return (uint32_t)rs;
}
static const char *REASONS[] = { "OK",
                                 "Not Found",
                                 "",
                                 "Moved Permanently",
                                 "No Content",
                                 "Not Modified",
                                 "Switching Protocols",
                                 "Continue",
                                 "Internal Server Error",
                                 "I'm a teapot",
                                 "Gateway Time-out",
                                 "OK\tTAB",
                                 "R\xc3\xa9ponse",
                                 "  spaced  ",
                                 "Partial Content" };
static const char *STATUSES[] = { "200", "404", "301", "204", "304", "101", "100", "500",
                                  "418", "504", "103", "206", "000", "999", "600", "099" };
static const char *HNAMES[] = { "Date",
                                "Server",
                                "Content-Type",
                                "Content-Length",
                                "Transfer-Encoding",
                                "Connection",
                                "Cache-Control",
                                "Set-Cookie",
                                "ETag",
                                "Last-Modified",
                                "Vary",
                                "X-Frame-Options",
                                "Strict-Transport-Security",
                                "Content-Encoding",
                                "Location",
                                "Accept-Ranges",
                                "Keep-Alive",
                                "Alt-Svc",
                                "x-amz-cf-id",
                                "Content-Security-Policy" };
static const char *HVALS[] = { "Sat, 07 Nov 2026 12:00:00 GMT",
                               "nginx/1.26.0",
                               "text/html; charset=utf-8",
                               "1234",
                               "chunked",
                               "keep-alive",
                               "max-age=0, private, must-revalidate",
                               "sid=abc123; Path=/; HttpOnly; Secure",
                               "\"5f3e-1a2b\"",
                               "",
                               "Accept-Encoding",
                               "SAMEORIGIN",
                               "max-age=31536000; includeSubDomains",
                               "gzip",
                               "https://example.com/a/b?c=d",
                               "bytes",
                               "timeout=5, max=100",
                               "h3=\":443\"; ma=86400",
                               "Zx9fK2_abc-QWERTY==",
                               "default-src 'self'; script-src 'self' https://cdn.example.com" };
static int gen(char *s) {
  int n = 0;
  uint32_t k = rnd() % 100;
  n += sprintf(s + n, "HTTP/1.%c", k < 70 ? '1' : k < 90 ? '0' : "0123456789x"[rnd() % 11]);
  n += sprintf(s + n, "%s", rnd() % 20 ? " " : rnd() % 2 ? "  " : "\t");
  if (rnd() % 30 == 0) n += sprintf(s + n, "%c%c%c", '0' + rnd() % 10, "0123456789a "[rnd() % 12], '0' + rnd() % 10);
  else n += sprintf(s + n, "%s", STATUSES[rnd() % 16]);
  uint32_t rm = rnd() % 20;
  if (rm == 0) {
  } // no reason, no space
  else if (rm == 1)
    n += sprintf(s + n, " ");
  else if (rm == 2) n += sprintf(s + n, "X"); // garbage after the code
  else n += sprintf(s + n, "%s%s", rnd() % 10 ? " " : "   ", REASONS[rnd() % 15]);
  const char *eol = rnd() % 15 ? "\r\n" : "\n";
  n += sprintf(s + n, "%s", eol);
  int nh = rnd() % 4 == 0 ? rnd() % 40 : rnd() % 12;
  for (int i = 0; i < nh; i++) {
    uint32_t sh = rnd() % 60;
    if (sh == 0 && i) n += sprintf(s + n, " folded continuation%s", eol);
    else if (sh == 1) n += sprintf(s + n, "%s : %s%s", HNAMES[rnd() % 20], HVALS[rnd() % 20], eol); // SP before :
    else if (sh == 2) { // a long value (cookies, CSP)
      n += sprintf(s + n, "%s: ", HNAMES[rnd() % 20]);
      int l = 50 + rnd() % 3000;
      for (int j = 0; j < l; j++) s[n++] = "abcdefghijklmnopqrstuvwxyz0123456789=;, -_/"[rnd() % 43];
      n += sprintf(s + n, "%s", eol);
    } else if (sh == 3) { // a long name
      int l = 20 + rnd() % 120;
      for (int j = 0; j < l; j++) s[n++] = "abcdefghij-XYZ_!#$%&'*+.^`|~0123456789"[rnd() % 38];
      n += sprintf(s + n, ":v%s", eol);
    } else
      n += sprintf(s + n, "%s:%s%s%s%s", HNAMES[rnd() % 20],
                   rnd() % 10  ? " "
                   : rnd() % 2 ? ""
                               : " \t ",
                   HVALS[rnd() % 20], rnd() % 15 ? "" : " \t", rnd() % 30 ? eol : "\r\n");
  }
  n += sprintf(s + n, "%s", eol);
  if (rnd() % 3 == 0) n += sprintf(s + n, "body bytes HTTP/1.1 200 OK\r\n"); // what follows the head
  return n;
}
static void mutate(char *s, int *n) {
  int m = 1 + rnd() % 3;
  for (int i = 0; i < m && *n > 0; i++) {
    int p = rnd() % *n;
    uint32_t op = rnd() % 4;
    char c = "\r\n: \t\x00\x7f\x80\xff\x01\x1f\"(),/;=?@[]{}aZ09"[rnd() % 28];
    if (op == 0) s[p] = c;
    else if (op == 1) {
      memmove(s + p + 1, s + p, *n - p);
      s[p] = c;
      ++*n;
    } else if (op == 2) {
      memmove(s + p, s + p + 1, *n - p - 1);
      --*n;
    } else s[p] = (char)rnd();
  }
}

static const char *EDGES[] = {
  "HTTP/1.1 200 OK\r\n\r\n",
  "HTTP/1.1 200\r\n\r\n",
  "HTTP/1.1 200 \r\n\r\n",
  "HTTP/1.1 200    \r\n\r\n",
  "HTTP/1.1 200OK\r\n\r\n",
  "HTTP/1.1  200 OK\r\n\r\n",
  "HTTP/1.1\t200 OK\r\n\r\n",
  "HTTP/1.0 200 OK\n\n",
  "HTTP/1.1 200 OK\n\r\n",
  "HTTP/1.1 200 OK\r\r\n\r\n",
  "HTTP/1.1 999 Weird\r\n\r\n",
  "HTTP/1.1 600 Beyond\r\n\r\n",
  "HTTP/1.1 099 Low\r\n\r\n",
  "HTTP/1.1 20 OK\r\n\r\n",
  "HTTP/1.1 2000 OK\r\n\r\n",
  "HTTP/1.1 -20 OK\r\n\r\n",
  "HTTP/2 200 OK\r\n\r\n",
  "HTTP/2.0 200 OK\r\n\r\n",
  "HTTP/1.10 200 OK\r\n\r\n",
  "http/1.1 200 OK\r\n\r\n",
  "\r\nHTTP/1.1 200 OK\r\n\r\n",
  "HTTP/1.1 200 OK\x01\r\n\r\n",
  "HTTP/1.1 200 O\x7fK\r\n\r\n",
  "HTTP/1.1 200 \xe2\x9c\x93\r\n\r\n",
  "HTTP/1.1 200 OK\r\nA: b\r\n c\r\n\r\n",
  "HTTP/1.1 200 OK\r\n c\r\n\r\n",
  "HTTP/1.1 200 OK\r\nA : b\r\n\r\n",
  "HTTP/1.1 200 OK\r\nA:b\r\n\r\n",
  "HTTP/1.1 200 OK\r\nA:\r\n\r\n",
  "HTTP/1.1 200 OK\r\n:b\r\n\r\n",
  "HTTP/1.1 200 OK\r\nA\r\n\r\n",
  "HTTP/1.1 200 OK\r\nA: b\rc\r\n\r\n",
  "HTTP/1.1 200 OK\r\nA: b\x00\r\n\r\n",
  "HTTP/1.1 200 OK\r\nA: b \t \r\n\r\n",
  "HTTP/1.1 200 OK\r\nA: \t b\r\n\r\n",
  "HTTP/1.1 200 OK\r\nA: b\nB: c\n\n",
  "HTTP/1.1 200 OK\r\nA\x80: b\r\n\r\n",
  "HTTP/1.1 200 OK\r\nA: b\x80\xff\r\n\r\n",
  "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
};
