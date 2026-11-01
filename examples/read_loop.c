// read_loop.c - the README's usage example: read a request from a socket (here: a pipe or file on stdin),
// parse it with fast_parse, and fall back to fbparse for anything unusual.
//   printf 'GET /posts/42 HTTP/1.1\r\nHost: x\r\n\r\n' | build/read_loop
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include "fastparse.h"
#include "fbparse.h"

int main(void) {
  static char buf[8192 + 64]; // + 64: the padding contract (any contents, never parsed)
  int sock = 0, buflen = 0, ret;
  req_t req;
  for (;;) {
    ssize_t n;
    while ((n = read(sock, buf + buflen, sizeof buf - 64 - buflen)) == -1 && errno == EINTR);
    if (n <= 0) {
      fprintf(stderr, "connection closed mid-request\n");
      return 1;
    }
    buflen += (int)n;
    ret = fast_parse(buf, buflen, &req); // the API's canonical requests
    if (ret == FP_FALLBACK) {            // everything else, pico-exact
      fb_info_t info;
      ret = fb_parse_req_ex(buf, buflen, &req, &info);
      if (ret == FP_FALLBACK && info.flags == FB_MINOR) ret = info.total; // HTTP/1.0: serve it too
    }
    if (ret > 0) break; // complete: head + body
    if (ret == -2 || ret == FP_FALLBACK) {
      fprintf(stderr, "400 Bad Request\n");
      return 1;
    } // or 501 for chunked
    if (buflen == (int)sizeof buf - 64) {
      fprintf(stderr, "431 Request Header Fields Too Large\n");
      return 1;
    }
    // FP_NEED_MORE: read more
  }
  static const char *names[] = { "NOTFOUND", "FEED", "HEALTH", "GETPOST", "CREATE", "LIKE" };
  printf("request is %d bytes, route %s", ret, names[req.route]);
  if (req.id_ok) printf(", id %lld", (long long)req.id);
  if (req.auth) printf(", bearer token %.*s", req.tok_len, req.tok);
  printf(", body %d bytes at offset %d\n", req.body_len, req.body_off);
  return 0;
}
