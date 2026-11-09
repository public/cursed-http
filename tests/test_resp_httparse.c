// Head differential for fbresp.h against Rust httparse's Response (v1.10.1; needs rustc, scripts/fetch-thirdparty.sh
// httparse).   make test-resp-httparse   ./test_resp_httparse [quick]
// Generated and mutated heads (tests/resp_gen.h), every prefix of some: fb_parse_response vs httparse with its
// defaults and with its response leniencies on. Where they differ, the difference must be one of the classes below
// (each a rule where httparse departs from picohttpparser, whose rules fbresp.h keeps); anything else fails.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fbresp.h"
#include "resp_gen.h"

typedef int (*hxfn)(const char *, size_t, int *, int *, const char **, size_t *, struct fb_header *, size_t *, size_t);
int hx_parse_response(const char *, size_t, int *, int *, const char **, size_t *, struct fb_header *, size_t *,
                      size_t);
int hx_parse_response_lenient(const char *, size_t, int *, int *, const char **, size_t *, struct fb_header *, size_t *,
                              size_t);
#define MAXH 64
static int fails, discover;
static long agree, total, cls[16];
static char *buf;
static void show(const char *b, int len) {
  printf("    \"");
  for (int i = 0; i < len && i < 220; i++) {
    unsigned char c = (unsigned char)b[i];
    if (c == '\r') printf("\\r");
    else if (c == '\n') printf("\\n");
    else if (c < 32 || c > 126) printf("\\x%02x", c);
    else putchar(c);
  }
  printf("%s\" (len %d)\n", len > 220 ? "..." : "", len);
}
// features of a head where httparse's rules are not pico's (found by this test's discover mode)
enum {
  F_VERSION = 1,
  F_MULTISP = 2,
  F_FOLD = 4,
  F_SPCOLON = 8,
  F_REASONWS = 16,
  F_STATUS = 32,
  F_OBSREASON = 64,
  F_SHORT = 128,
  F_EARLY = 256,
  F_N = 9
};
static const char *FN[] = { "version other than 1.0 / 1.1: httparse rejects",
                            "more than one SP/HT in the status line: httparse rejects (default)",
                            "obs-fold: httparse rejects (default) or joins it to the previous field (lenient)",
                            "whitespace before a header's colon: pico rejects, httparse (lenient) accepts",
                            "whitespace around the reason phrase: pico strips leading SP, httparse keeps it",
                            "status code: httparse's own rules",
                            "obs-text in the reason phrase: httparse accepts it, returns an empty reason",
                            "under 9 bytes that cannot start HTTP/1.x: pico waits for 9 (-2), httparse rejects (-1)",
                            "a prefix: one says incomplete, the other invalid, and that one rejects the whole input" };
static unsigned features(const char *b, int len) {
  unsigned f = 0;
  if (len < 9)
    for (int i = 0; i < len; i++)
      if (i < 7 ? b[i] != "HTTP/1."[i] : (unsigned)(b[i] - '0') > 9) f |= F_SHORT;
  if (len >= 8 && !memcmp(b, "HTTP/1.", 7) && b[7] != '0' && b[7] != '1') f |= F_VERSION;
  int e = 0;
  while (e < len && b[e] != '\n') e++; // the status line
  if (len > 9 && (b[9] == ' ' || b[9] == '\t' || b[8] == '\t')) f |= F_MULTISP;
  for (int i = 9; i + 1 < e; i++)
    if ((b[i] == ' ' || b[i] == '\t') && i > 12 && (b[i + 1] == ' ' || b[i + 1] == '\t' || b[i + 1] == '\r'))
      f |= F_REASONWS;
  if (len > 12 && (b[12] == ' ' || b[12] == '\t') && 13 < len && (b[13] == ' ' || b[13] == '\t'))
    f |= F_MULTISP | F_REASONWS;
  if (len > 9 && (b[9] == '0' || (len > 12 && b[12] != ' ' && b[12] != '\r' && b[12] != '\n'))) f |= F_STATUS;
  for (int i = 9; i < e; i++)
    if ((unsigned char)b[i] >= 0x80) f |= F_OBSREASON;
  // header lines
  for (int p = e + 1; p < len;) {
    if (b[p] == '\r' || b[p] == '\n') break;
    if (b[p] == ' ' || b[p] == '\t') f |= F_FOLD;
    int q = p;
    while (q < len && b[q] != ':' && b[q] != '\n') q++;
    if (q < len && b[q] == ':' && q > p && (b[q - 1] == ' ' || b[q - 1] == '\t')) f |= F_SPCOLON;
    while (q < len && b[q] != '\n') q++;
    p = q + 1;
  }
  return f;
}
static const unsigned MODE_F[2] = { F_VERSION | F_MULTISP | F_FOLD | F_REASONWS | F_STATUS | F_OBSREASON | F_SHORT,
                                    F_VERSION | F_FOLD | F_SPCOLON | F_REASONWS | F_STATUS | F_OBSREASON | F_SHORT };
static int full_fb, full_hx[2]; // the whole input's results, for prefixes
static void check(const char *s, int len) {
  memcpy(buf, s, len);
  memset(buf + len, 'Z', PAD);
  int mv, st, mv2, st2;
  const char *m, *m2;
  size_t ml, ml2, nh = MAXH, nh2;
  struct fb_header F[MAXH], X[MAXH];
  int rf = fb_parse_response(buf, len, &mv, &st, &m, &ml, F, &nh, 0);
  for (int v = 0; v < 2; v++) {
    nh2 = MAXH;
    int rx = (v ? hx_parse_response_lenient : hx_parse_response)(buf, len, &mv2, &st2, &m2, &ml2, X, &nh2, 0);
    total++;
    int same = rf == rx;
    if (same && rf > 0) {
      same = mv == mv2 && st == st2 && ml == ml2 && (ml == 0 || m == m2) && nh == nh2;
      for (size_t i = 0; same && i < nh; i++)
        same = F[i].name == X[i].name && F[i].name_len == X[i].name_len && F[i].value == X[i].value &&
               F[i].value_len == X[i].value_len;
    }
    if (same) {
      agree++;
      continue;
    }
    unsigned f = features(s, len) & MODE_F[v];
    if ((rf == -2 && rx == -1 && full_hx[v] == -1) || (rf == -1 && rx == -2 && full_fb == -1)) f |= F_EARLY;
    if (f) {
      for (int k = 0; k < F_N; k++)
        if (f & 1u << k) {
          cls[k]++;
          break;
        }
      continue;
    }
    if (discover || fails < 20) {
      printf("DIFF (%s): fb %d, httparse %d\n", v ? "lenient" : "default", rf, rx);
      show(s, len);
    }
    fails++;
  }
}
int main(int argc, char **argv) {
  int quick = argc > 1 && !strcmp(argv[1], "quick"), N = quick ? 3000 : 30000;
  discover = argc > 1 && !strcmp(argv[1], "discover");
  if (discover) N = 300;
  buf = malloc((1 << 16) + PAD);
  static char s[1 << 16];
  if (argc > 1 && strcmp(argv[1], "quick") && strcmp(argv[1], "discover")) { // a responses.dat of heads
    FILE *f = fopen(argv[1], "rb");
    unsigned char lb[4];
    long heads = 0;
    while (f && fread(lb, 1, 4, f) == 4) {
      int n = lb[0] | lb[1] << 8 | lb[2] << 16 | lb[3] << 24;
      if (n > (1 << 16) || fread(s, 1, n, f) != (size_t)n) break;
      full_fb = full_hx[0] = full_hx[1] = 0;
      check(s, n);
      heads++;
    }
    printf("%ld heads from %s\n", heads, argv[1]);
    N = 0;
  }
  for (int i = 0; i < N; i++) {
    int n = gen(s);
    if (i % 3 == 0) mutate(s, &n);
    full_fb = full_hx[0] = full_hx[1] = 0;
    check(s, n);
    {
      int mv, st;
      const char *m;
      size_t ml, nh = MAXH;
      struct fb_header X[MAXH];
      memcpy(buf, s, n);
      memset(buf + n, 'Z', PAD);
      full_fb = fb_parse_response(buf, n, &mv, &st, &m, &ml, X, &nh, 0);
      nh = MAXH;
      full_hx[0] = hx_parse_response(buf, n, &mv, &st, &m, &ml, X, &nh, 0);
      nh = MAXH;
      full_hx[1] = hx_parse_response_lenient(buf, n, &mv, &st, &m, &ml, X, &nh, 0);
    }
    for (int k = 0; k < 4; k++) check(s, rnd() % (n + 1));
  }
  printf("fb vs httparse: %ld comparisons, %ld agree\n", total, agree);
  for (int k = 0; k < F_N; k++) printf("  %7ld  %s\n", cls[k], FN[k]);
  if (fails) {
    printf("FAILED: %d unexplained differences\n", fails);
    return 1;
  }
  printf("RESPONSE HEADS vs HTTPARSE: no unexplained difference\n");
  return 0;
}
