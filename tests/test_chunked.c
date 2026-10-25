// test_chunked.c - fbparse.h's chunked-body decoder (fb_decode_chunked):
//   1. exact cases: every strictness rule (sizes, CRLF, data framing, extensions, trailers, limits), with the
//      expected result and decoded body, and every truncation of each (incomplete until the bad byte or the end)
//   2. generated chunked bodies (1-40 chunks, sizes 0-300, extensions, mixed-case hex, leading zeros, a pipelined
//      request behind them) and mutations of them, through fz_check_chunked (fuzz/oracle.h): never more lenient
//      than picohttpparser's phr_decode_chunked, the same body and length when it accepts, in place == out of
//      place, max_body exact
//   ./test_chunked [quick]
#include "oracle.h"

static int fails;
#define FAIL(...) do { if (fails++ < 30) printf(__VA_ARGS__); } while (0)

// valid: want = 1 and the decoded body (body_len bytes); invalid: the expected code. len 0 = strlen(in)
typedef struct { const char *name, *in; int len, want; const char *body; int body_len; } ccase_t;
#define OKC(name, in, body) {name, in, (int)(sizeof(in) - 1), 1, body, (int)(sizeof(body) - 1)}
static const ccase_t CC[] = {
  OKC("single chunk", "11\r\n{\"body\":\"chunky\"}\r\n0\r\n\r\n", "{\"body\":\"chunky\"}"),
  OKC("empty body", "0\r\n\r\n", ""),
  OKC("two chunks", "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n", "hello world"),
  OKC("uppercase and lowercase hex", "A\r\n0123456789\r\na\r\nabcdefghij\r\n0\r\n\r\n", "0123456789abcdefghij"),
  OKC("leading zeros", "0005\r\nhello\r\n000\r\n\r\n", "hello"),
  OKC("16 hex digits", "0000000000000005\r\nhello\r\n0\r\n\r\n", "hello"),
  OKC("extension ignored", "5;name=value\r\nhello\r\n0;last\r\n\r\n", "hello"),
  OKC("extension after BWS", "5 ;x\r\nhello\r\n0\t;y=\"q s\"\r\n\r\n", "hello"),
  OKC("CRLF inside the data", "4\r\n\r\n\r\n\r\n0\r\n\r\n", "\r\n\r\n"),
  OKC("binary data", "3\r\n\x00\xff\x7f\r\n0\r\n\r\n", "\x00\xff\x7f"),
  {"17 hex digits", "00000000000000005\r\nhello\r\n0\r\n\r\n", 0, FB_CHUNK_INVALID, NULL, 0},
  {"no size", "\r\nhello\r\n0\r\n\r\n", 0, FB_CHUNK_INVALID, NULL, 0},
  {"0x prefix", "0x5\r\nhello\r\n0\r\n\r\n", 0, FB_CHUNK_INVALID, NULL, 0},
  {"plus sign", "+5\r\nhello\r\n0\r\n\r\n", 0, FB_CHUNK_INVALID, NULL, 0},
  {"minus sign", "-5\r\nhello\r\n0\r\n\r\n", 0, FB_CHUNK_INVALID, NULL, 0},
  {"space before the size", " 5\r\nhello\r\n0\r\n\r\n", 0, FB_CHUNK_INVALID, NULL, 0},
  {"space after the size, no ;", "5 \r\nhello\r\n0\r\n\r\n", 0, FB_CHUNK_INVALID, NULL, 0},
  {"junk after the size", "5x\r\nhello\r\n0\r\n\r\n", 0, FB_CHUNK_INVALID, NULL, 0},
  {"bare LF after the size", "5\nhello\r\n0\r\n\r\n", 0, FB_CHUNK_INVALID, NULL, 0},
  {"CR without LF after the size", "5\rhello\r\n0\r\n\r\n", 0, FB_CHUNK_INVALID, NULL, 0},
  {"data longer than its size", "5\r\nhello!\r\n0\r\n\r\n", 0, FB_CHUNK_INVALID, NULL, 0},
  {"data shorter than its size", "6\r\nhello\r\n0\r\n\r\n", 0, FB_CHUNK_INVALID, NULL, 0},
  {"bare LF after the data", "5\r\nhello\n0\r\n\r\n", 0, FB_CHUNK_INVALID, NULL, 0},
  {"control byte in an extension", "5;a\x01\r\nhello\r\n0\r\n\r\n", 0, FB_CHUNK_INVALID, NULL, 0},
  {"DEL in an extension", "5;a\x7f\r\nhello\r\n0\r\n\r\n", 0, FB_CHUNK_INVALID, NULL, 0},
  {"LF in an extension", "5;a\nb\r\nhello\r\n0\r\n\r\n", 0, FB_CHUNK_INVALID, NULL, 0},
  {"trailer field", "5\r\nhello\r\n0\r\nX-Trailer: 1\r\n\r\n", 0, FB_CHUNK_INVALID, NULL, 0},
  {"bare LF ending", "5\r\nhello\r\n0\r\n\n", 0, FB_CHUNK_INVALID, NULL, 0},
  {"no last chunk", "5\r\nhello\r\n\r\n", 0, FB_CHUNK_INVALID, NULL, 0},
  {"size over max_body", "7fffffff\r\n", 0, FB_CHUNK_TOO_LARGE, NULL, 0},
  {"sum over max_body", "800\r\n", 0, FB_CHUNK_NEED_MORE, NULL, 0},   // 2048 bytes fit; checked with a 1000-byte limit below
};
#define NCC ((int)(sizeof CC / sizeof *CC))

static int first_bad(const ccase_t *c, int len) {   // the shortest prefix that is already invalid (or len + 1)
  for (int t = 0; t <= len; t++) { int bl; if (fb_decode_chunked(c->in, t, (char[1]){0}, 1 << 20, &bl) == FB_CHUNK_INVALID) return t; }
  return len + 1;
}

int main(int argc, char **argv) {
  int quick = argc > 1 && !strcmp(argv[1], "quick"), N = quick ? 20000 : 200000;
  char err[256];
  // 1. exact cases
  for (int i = 0; i < NCC; i++) {
    const ccase_t *c = &CC[i]; int len = c->len ? c->len : (int)strlen(c->in), bl = -1;
    char *out = malloc(len + 1);
    int r = fb_decode_chunked(c->in, len, out, 1 << 20, &bl);
    if (c->body ? (r != len || bl != c->body_len || memcmp(out, c->body, bl)) : r != c->want)
      FAIL("%s: fb_decode_chunked %d (body %d), want %d (body %d)\n", c->name, r, bl, c->body ? len : c->want, c->body_len);
    if (c->body) {   // every truncation is incomplete
      for (int t = 0; t < len; t++) if (fb_decode_chunked(c->in, t, out, 1 << 20, &bl) != FB_CHUNK_NEED_MORE) { FAIL("%s: prefix %d not NEED_MORE\n", c->name, t); break; }
      if (fz_check_chunked(c->in, len, err, sizeof err)) FAIL("%s: %s\n", c->name, err);
    } else if (c->want == FB_CHUNK_INVALID) {   // incomplete until the bad byte, invalid from then on
      int fb = first_bad(c, len);
      for (int t = 0; t <= len; t++) { int x = fb_decode_chunked(c->in, t, out, 1 << 20, &bl);
        if (x != (t < fb ? FB_CHUNK_NEED_MORE : FB_CHUNK_INVALID)) { FAIL("%s: prefix %d gives %d\n", c->name, t, x); break; } }
      if (fz_check_chunked(c->in, len, err, sizeof err)) FAIL("%s: %s\n", c->name, err);
    }
    free(out);
  }
  { int bl; if (fb_decode_chunked("800\r\n", 5, (char[1]){0}, 1000, &bl) != FB_CHUNK_TOO_LARGE) FAIL("2048-byte chunk under a 1000-byte limit not too large\n");
    if (fb_decode_chunked("3e8\r\n", 5, (char[1]){0}, 1000, &bl) != FB_CHUNK_NEED_MORE) FAIL("1000-byte chunk under a 1000-byte limit not accepted\n"); }
  // a pipelined request right behind the body: the returned length is where it starts
  { const char *s = "5\r\nhello\r\n0\r\n\r\nGET / HTTP/1.1\r\n\r\n"; int bl; char out[64];
    if (fb_decode_chunked(s, (int)strlen(s), out, 100, &bl) != 15 || bl != 5) FAIL("pipelined: consumed length wrong\n"); }
  // 2. generated bodies and their mutations against pico
  static char buf[32768]; long accepted = 0, rejected = 0;
  for (int it = 0; it < N; it++) {
    int n = 0, chunks = 1 + rnd() % 40;
    for (int k = 0; k < chunks && n < 24000; k++) {
      int sz = rnd() % 4 ? rnd() % 64 : rnd() % 300;
      if (sz == 0) sz = 1;
      n += sprintf(buf + n, rnd() % 2 ? "%x" : rnd() % 2 ? "%X" : "%04x", sz);
      if (rnd() % 6 == 0) n += sprintf(buf + n, "%s", (const char *[]){";a", ";a=b", " ;x=\"y z\"", "\t;\x80"}[rnd() % 4]);
      n += sprintf(buf + n, "\r\n");
      for (int j = 0; j < sz; j++) buf[n++] = (char)rnd();
      n += sprintf(buf + n, "\r\n");
    }
    n += sprintf(buf + n, rnd() % 4 ? "0\r\n\r\n" : "000;end\r\n\r\n");
    if (rnd() % 4 == 0) n += sprintf(buf + n, "GET / HTTP/1.1\r\n\r\n");
    int m = 1 + rnd() % 3;
    if (it & 1) for (int j = 0; j < m; j++) buf[rnd() % n] = "\r\n ;0aAgG\t\x00\x7f-+x"[rnd() % 15];
    if (rnd() % 4 == 0) n = rnd() % (n + 1);
    if (fz_check_chunked(buf, n, err, sizeof err)) { FAIL("generated %d (%d bytes): %s\n", it, n, err); continue; }
    static char out[32768]; int bl; if (fb_decode_chunked(buf, n, out, 1 << 20, &bl) > 0) accepted++; else rejected++;
  }
  printf("chunked: %d exact cases, %d generated bodies (%ld complete, %ld incomplete or rejected)\nTOTAL FAILURES: %d\n", NCC, N, accepted, rejected, fails);
  return fails != 0;
}
