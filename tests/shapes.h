// shapes.h - "fallback-shaped" requests: what reaches the slow path behind fast_parse in real life.
// Include after ref_corpus.h (rnd(), TOKS). gen_fb(s, shape) writes one request into s (>= 24 KB) and
// returns its length. Header orders/values are modelled on real clients (curl 8.x, Chrome 130, Firefox 131,
// ApacheBench, wget) but are not captures; nothing here is in fbparse.h.
#pragma once
enum { S_CURL, S_CHROME, S_FIREFOX, S_HTTP10, S_LONG, S_CHUNKED, S_ODD, S_NSHAPES };
__attribute__((unused)) static const char *SHAPE_NAME[] = { "curl",         "chrome",       "firefox", "http/1.0",
                                                            "long headers", "chunked POST", "odd" };

static const char *rpath(char *tmp) {
  switch (rnd() % 6) {
    case 0: return "/feed";
    case 1: return "/health";
    case 2: sprintf(tmp, "/posts/%u", 1 + rnd() % 500000); return tmp;
    case 3: sprintf(tmp, "/posts/%u/like", 1 + rnd() % 500000); return tmp;
    case 4: sprintf(tmp, "/feed?limit=%u&before=%u", rnd() % 50, rnd() % 100000); return tmp;
    default: return "/posts";
  }
}
static int rcookie(char *s, int n) { // "name=value; ..." of about n bytes
  static const char *A = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_%.";
  int o = 0;
  while (o < n) {
    o += sprintf(s + o, "%s%c%c%c%u=", o ? "; " : "", 'a' + rnd() % 26, 'a' + rnd() % 26, '_', rnd() % 100);
    for (int k = 8 + rnd() % 40; k-- && o < n;) s[o++] = A[rnd() % 66];
  }
  s[o] = 0;
  return o;
}
static int gen_fb(char *s, int shape) {
  char p[64], ck[20000];
  const char *tok = TOKS[rnd() % 64];
  int n = 0;
  switch (shape) {
    case S_CURL:
      if (rnd() % 3)
        return sprintf(s, "GET %s HTTP/1.1\r\nHost: localhost:3000\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n",
                       rpath(p));
      {
        char body[200];
        int bl = sprintf(body, "{\"body\":\"hello from curl %u\"}", rnd() % 100000);
        return sprintf(s,
                       "POST /posts HTTP/1.1\r\nHost: localhost:3000\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n"
                       "Authorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
                       tok, bl, body);
      }
    case S_CHROME:
      rcookie(ck, 40 + rnd() % 600);
      return sprintf(
          s,
          "GET %s HTTP/1.1\r\nHost: localhost:3000\r\nConnection: keep-alive\r\n"
          "sec-ch-ua: \"Chromium\";v=\"130\", \"Google Chrome\";v=\"130\", \"Not?A_Brand\";v=\"99\"\r\nsec-ch-ua-mobile: ?0\r\n"
          "sec-ch-ua-platform: \"macOS\"\r\nUpgrade-Insecure-Requests: 1\r\n"
          "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36\r\n"
          "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n"
          "Sec-Fetch-Site: none\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-User: ?1\r\nSec-Fetch-Dest: document\r\n"
          "Accept-Encoding: gzip, deflate, br, zstd\r\nAccept-Language: en-GB,en-US;q=0.9,en;q=0.8\r\nCookie: %s\r\n\r\n",
          rpath(p), ck);
    case S_FIREFOX:
      rcookie(ck, 40 + rnd() % 400);
      n = sprintf(
          s,
          "GET %s HTTP/1.1\r\nHost: localhost:3000\r\n"
          "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:131.0) Gecko/20100101 Firefox/131.0\r\n"
          "Accept: application/json, text/plain, */*\r\nAccept-Language: en-GB,en;q=0.5\r\nAccept-Encoding: gzip, deflate, br, zstd\r\n"
          "Referer: http://localhost:3000/\r\n",
          rpath(p));
      if (rnd() & 1) n += sprintf(s + n, "Authorization: Bearer %s\r\n", tok);
      return n +
             sprintf(
                 s + n,
                 "Connection: keep-alive\r\nCookie: %s\r\nSec-Fetch-Dest: empty\r\nSec-Fetch-Mode: cors\r\n"
                 "Sec-Fetch-Site: same-origin\r\nPriority: u=0\r\nPragma: no-cache\r\nCache-Control: no-cache\r\n\r\n",
                 ck);
    case S_HTTP10:
      switch (rnd() % 3) {
        case 0:
          return sprintf(
              s, "GET %s HTTP/1.0\r\nHost: localhost:3000\r\nUser-Agent: ApacheBench/2.3\r\nAccept: */*\r\n\r\n",
              rpath(p));
        case 1:
          return sprintf(
              s,
              "GET %s HTTP/1.0\r\nUser-Agent: Wget/1.21.4\r\nAccept: */*\r\nAccept-Encoding: identity\r\nHost: localhost:3000\r\nConnection: Keep-Alive\r\n\r\n",
              rpath(p));
        default:
          return sprintf(
              s,
              "POST /posts/%u/like HTTP/1.0\r\nHost: localhost\r\nAuthorization: Bearer %s\r\nContent-Length: 0\r\n\r\n",
              1 + rnd() % 9999, tok);
      }
    case S_LONG: // big cookies / long custom headers, 2-20 KB heads (over fastparse.h's 8 KB limit half the time)
      rcookie(ck, 2000 + rnd() % 17000);
      n = sprintf(
          s,
          "GET %s HTTP/1.1\r\nHost: app.example.test\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64)\r\nAccept: */*\r\n",
          rpath(p));
      if (rnd() & 1) {
        n += sprintf(s + n, "X-Trace: ");
        for (int k = 200 + rnd() % 2000; k--;) s[n++] = "0123456789abcdef"[rnd() % 16];
        n += sprintf(s + n, "\r\n");
      }
      return n + sprintf(s + n, "Cookie: %s\r\nAuthorization: Bearer %s\r\n\r\n", ck, tok);
    case S_CHUNKED:
      return sprintf(
          s,
          "POST /posts HTTP/1.1\r\nHost: localhost:3000\r\nUser-Agent: python-requests/2.32.3\r\nAccept-Encoding: gzip, deflate\r\n"
          "Accept: */*\r\nConnection: keep-alive\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
          "1c\r\n{\"body\":\"chunked hello %04u\"}\r\n0\r\n\r\n",
          tok, rnd() % 10000);
    default: { // S_ODD: shapes pico accepts that fast_parse hands over
      const char *eol = (rnd() % 3) ? "\r\n" : "\n";
      n = sprintf(s, "%s%s %s%s HTTP/1.%c%s", rnd() % 8 ? "" : "\r\n",
                  (const char *[]){ "GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD", "M-SEARCH" }[rnd() % 8],
                  rnd() % 4 ? "" : "http://localhost:3000", rpath(p), "0119"[rnd() % 4], eol);
      for (int k = rnd() % 12; k--;) {
        switch (rnd() % 12) {
          case 0: n += sprintf(s + n, "host:localhost%s", eol); break;
          case 1: n += sprintf(s + n, "X-Empty:%s", eol); break;
          case 2: n += sprintf(s + n, "X-Tabs:\t\tv a l\t \t%s", eol); break;
          case 3: n += sprintf(s + n, "X-Fold: first%s  continued%s\tagain%s", eol, eol, eol); break;
          case 4: n += sprintf(s + n, "X-High: caf\xc3\xa9 \xff\x80%s", eol); break;
          case 5: n += sprintf(s + n, "content-length: %u%s", rnd() % 3 ? rnd() % 20 : rnd(), eol); break;
          case 6: n += sprintf(s + n, "Content-Length: 0%u%s", rnd() % 10, eol); break;
          case 7:
            n += sprintf(s + n, "%s: gzip, chunked%s",
                         (const char *[]){ "TRANSFER-ENCODING", "Transfer-Encodin", "transfer-encodinG2",
                                           "Transfer-Encodi" }[rnd() % 4],
                         eol);
            break;
          case 8: n += sprintf(s + n, "x-!#$%%&'*+-.^_`|~09AZaz: odd-name%s", eol); break;
          case 9: n += sprintf(s + n, "Authorization: Bearer %s   %s", tok, eol); break;
          case 10: n += sprintf(s + n, "Expect: 100-continue%s", eol); break;
          default: n += sprintf(s + n, "Connection: close%s", eol); break;
        }
      }
      return n + sprintf(s + n, "%s", eol);
    }
  }
}
