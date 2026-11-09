// Framing differential for fbresp.h against llhttp (vendor/llhttp v9.4.3, Node.js's parser) in response mode.
//   make test-resp   (mk/resp.mk)
//   ./test_resp_llhttp [quick]
// On generated responses with every combination of the framing fields (Content-Length right, wrong, repeated, listed,
// signed; Transfer-Encoding chunked or not, with Content-Length, in HTTP/1.0; Connection; 1xx/204/304; HEAD and
// CONNECT requests; trailers; a second response pipelined behind), both parsers say where the message ends (or that
// it is incomplete, or invalid) and whether the connection can be reused. llhttp runs strict (no lenient flags).
// Where they differ, the difference must be one of the classes below, each a rule where llhttp and RFC 9112 / this
// parser's documented choice part ways; any other difference is a failure. Each class is counted and printed.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "llhttp.h"
#include "fbresp.h"

#define PAD 64
static uint64_t rs = 0x2545F4914F6CDD1Dull;
static uint32_t rnd(void) {
  rs ^= rs << 13;
  rs ^= rs >> 7;
  rs ^= rs << 17;
  return (uint32_t)rs;
}
static int fails;
static void show(const char *b, int len) {
  printf("    \"");
  for (int i = 0; i < len && i < 300; i++) {
    unsigned char c = (unsigned char)b[i];
    if (c == '\r') printf("\\r");
    else if (c == '\n') printf("\\n");
    else if (c < 32 || c > 126) printf("\\x%02x", c);
    else putchar(c);
  }
  printf("%s\" (len %d)\n", len > 300 ? "..." : "", len);
}

enum { R_INCOMPLETE = -2, R_INVALID = -1 }; // else the message end (>= 0)
// ---------------- llhttp: where the first message ends ----------------
typedef struct {
  llhttp_t p;
  int req, done, ka, tunnel;
} lh_t;
static int lh_headers(llhttp_t *p) {
  lh_t *s = (lh_t *)p;
  if (s->req == FBR_REQ_HEAD) return 1;                         // no body
  if (s->req == FBR_REQ_CONNECT && p->status_code / 100 == 2) { // a tunnel: llhttp ends the message at the head
    s->tunnel = 1;
    return 2;
  }
  return 0;
}
static int lh_complete(llhttp_t *p) {
  lh_t *s = (lh_t *)p;
  s->done = 1;
  s->ka = llhttp_should_keep_alive(p);
  return HPE_PAUSED;
}
static llhttp_settings_t LS;
static int lh_end(const char *b, int len, int req, int *ka, int *tunnel) {
  lh_t s = { .req = req };
  llhttp_init(&s.p, HTTP_RESPONSE, &LS);
  *tunnel = 0;
  llhttp_errno_t e = llhttp_execute(&s.p, b, len);
  if (e == HPE_PAUSED && s.done) {
    *ka = s.tunnel ? 0 : s.ka;
    *tunnel = s.tunnel;
    return (int)(llhttp_get_error_pos(&s.p) - b);
  }
  if (e == HPE_PAUSED_UPGRADE) {
    *tunnel = 1;
    *ka = 0;
    return (int)(llhttp_get_error_pos(&s.p) - b);
  }
  if (e != HPE_OK) return R_INVALID;
  // all bytes used, no message end: the end of the input may end it (a close-delimited body)
  e = llhttp_finish(&s.p);
  if (e == HPE_PAUSED && s.done) {
    *ka = s.ka;
    return len;
  }
  return e == HPE_OK || e == HPE_INVALID_EOF_STATE ? R_INCOMPLETE : R_INVALID;
}

// ---------------- fbresp: the same ----------------
static char tb[1 << 17];
static int fb_end(const char *b, int len, int req, int *ka, int *tunnel, fbr_resp_t *r) {
  static struct fb_header H[100], T[100];
  r->headers = H;
  r->num_headers = 100;
  *tunnel = 0;
  int n = fbr_parse(b, len, req, r, 0);
  if (n < 0) return n == -2 ? R_INCOMPLETE : R_INVALID;
  *ka = !!(r->flags & FBR_KEEPALIVE);
  switch (r->body) {
    case FBR_NONE: return n;
    case FBR_TUNNEL: *tunnel = 1; return n;
    case FBR_LENGTH: return len - n >= r->length ? n + (int)r->length : R_INCOMPLETE;
    case FBR_CLOSE: return len; // the input ends here: the connection closed
    default: break;
  }
  int bl, c = fbr_chunked(b + n, len - n, tb, 1 << 30, &bl, NULL);
  if (c == FB_CHUNK_NEED_MORE) return R_INCOMPLETE;
  if (c < 0) return R_INVALID;
  int off = n + c;
  memcpy(tb, b + off, len - off); // fb_parse_headers wants padding after the section
  memset(tb + len - off, 'Z', PAD);
  size_t nt = 100;
  int t = fb_parse_headers(tb, len - off, T, &nt, 0);
  return t == -2 ? R_INCOMPLETE : t < 0 ? R_INVALID : off + t;
}

// ---------------- generated responses ----------------
static int gen(char *s, int *req) {
  static const char *ST[] = { "200 OK",          "200 OK",           "200 OK",       "404 Not Found",
                              "204 No Content",  "304 Not Modified", "100 Continue", "101 Switching Protocols",
                              "103 Early Hints", "301 Moved",        "500 Oops",     "206 Partial Content",
                              "407 Proxy Auth" };
  int n = 0;
  *req = rnd() % 8 == 0 ? FBR_REQ_HEAD : rnd() % 12 == 0 ? FBR_REQ_CONNECT : FBR_REQ_OTHER;
  int minor = rnd() % 6 == 0 ? 0 : 1;
  const char *st = ST[rnd() % 13];
  n += sprintf(s + n, "HTTP/1.%d %s\r\nServer: gen\r\n", minor, st);
  int body = rnd() % 200, chunked = 0;
  uint32_t te = rnd() % 10;
  if (te < 3) {
    chunked = 1;
    n += sprintf(s + n, "Transfer-Encoding: chunked\r\n");
  } else if (te == 3) {
    chunked = 1;
    n += sprintf(s + n, "Transfer-Encoding: gzip, chunked\r\n");
  } else if (te == 4) n += sprintf(s + n, "Transfer-Encoding: gzip\r\n");
  uint32_t cl = rnd() % 14;
  if (cl < 5) n += sprintf(s + n, "Content-Length: %d\r\n", body);
  else if (cl == 5) n += sprintf(s + n, "Content-Length: %d\r\nContent-Length: %d\r\n", body, body);
  else if (cl == 6) n += sprintf(s + n, "Content-Length: %d, %d\r\n", body, body);
  else if (cl == 7) n += sprintf(s + n, "Content-Length: %d\r\nContent-Length: %d\r\n", body, body + 1);
  else if (cl == 8) n += sprintf(s + n, "Content-Length: +%d\r\n", body);
  else if (cl == 9) n += sprintf(s + n, "Content-Length: %d\r\n", body + (int)(rnd() % 3) - 1);
  uint32_t co = rnd() % 8;
  if (co == 0) n += sprintf(s + n, "Connection: close\r\n");
  else if (co == 1) n += sprintf(s + n, "Connection: keep-alive\r\n");
  else if (co == 2) n += sprintf(s + n, "Connection: Upgrade\r\nUpgrade: websocket\r\n");
  n += sprintf(s + n, "\r\n");
  if (chunked && rnd() % 6) {
    int left = body;
    while (left > 0) {
      int c = 1 + rnd() % (left < 50 ? left : 50);
      n += sprintf(s + n, "%x\r\n", c);
      for (int i = 0; i < c; i++) s[n++] = 'a' + i % 26;
      n += sprintf(s + n, "\r\n");
      left -= c;
    }
    n += sprintf(s + n, "0\r\n%s\r\n", rnd() % 4 ? "" : "X-Trailer: t\r\n");
  } else
    for (int i = 0; i < body; i++) s[n++] = 'A' + i % 26;
  if (rnd() % 3 == 0) n += sprintf(s + n, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"); // pipelined
  return n;
}

// the classes of known differences (see the README of each in main)
enum { D_TECL, D_TE10, D_101, D_CLTE_HEAD, D_EARLY, D_N };
static const char *DN[] = {
  "TE + CL: llhttp rejects, fbr uses chunked and closes", "TE in HTTP/1.0: fbr rejects (RFC 9112 6.1), llhttp uses it",
  "101 without Upgrade fields: llhttp parses on as HTTP, fbr tunnels",
  "framing fields of a no-body response: llhttp validates them, fbr ignores them (6.3 rule 1)",
  "a prefix of an input llhttp rejects: llhttp rejects at the field, fbr waits for the head"
};
static long dc[D_N];

static char *buf;
int main(int argc, char **argv) {
  int quick = argc > 1 && !strcmp(argv[1], "quick"), N = quick ? 20000 : 200000;
  llhttp_settings_init(&LS);
  LS.on_headers_complete = lh_headers;
  LS.on_message_complete = lh_complete;
  static char s[1 << 16];
  buf = malloc((1 << 16) + PAD);
  long agree = 0, prefixes = 0;
  for (int i = 0; i < N; i++) {
    int req, n = gen(s, &req), full_le = 0;
    // the whole input, and a few prefixes (incomplete vs complete must agree too)
    for (int k = 0; k < 4; k++) {
      int len = k == 0 ? n : (int)(rnd() % (n + 1));
      memcpy(buf, s, len);
      memset(buf + len, 'Z', PAD);
      int lka = 0, fka = 0, lt, ft;
      fbr_resp_t r;
      int le = lh_end(buf, len, req, &lka, &lt), fe = fb_end(buf, len, req, &fka, &ft, &r);
      prefixes++;
      if (k == 0) full_le = le;
      if (le == fe && lt == ft && (le < 0 || lka == fka)) {
        agree++;
        continue;
      }
      // classify
      int cls = -1, has_te = strstr(s, "Transfer-Encoding") != NULL, has_cl = strstr(s, "Content-Length") != NULL;
      int st = r.status, nobody = req == FBR_REQ_HEAD || st / 100 == 1 || st == 204 || st == 304 ||
                                  (req == FBR_REQ_CONNECT && st / 100 == 2);
      if (k && le == R_INVALID && fe == R_INCOMPLETE && full_le == R_INVALID) cls = D_EARLY;
      else if (le == R_INVALID && fe != R_INVALID && nobody && (has_te || has_cl)) cls = D_CLTE_HEAD;
      else if (le == R_INVALID && fe != R_INVALID && has_te && has_cl && (r.flags & FBR_TECL)) cls = D_TECL;
      else if (fe == R_INVALID && r.err == FBR_E_TE10) cls = D_TE10;
      else if (st == 101 && ft && !lt) cls = D_101;
      if (cls >= 0) {
        dc[cls]++;
        continue;
      }
      if (fails++ < 20) {
        printf("MISMATCH req %d: llhttp end %d tunnel %d ka %d; fbr end %d tunnel %d ka %d (body %d err %d)\n", req, le,
               lt, lka, fe, ft, fka, r.body, r.err);
        show(buf, len);
      }
    }
  }
  printf("llhttp vs fbr: %ld inputs, %ld agree\n", prefixes, agree);
  for (int c = 0; c < D_N; c++) printf("  %7ld  %s\n", dc[c], DN[c]);
  if (fails) {
    printf("FAILED: %d unexplained differences\n", fails);
    return 1;
  }
  printf("RESPONSE FRAMING vs LLHTTP: no unexplained difference\n");
  return 0;
}
