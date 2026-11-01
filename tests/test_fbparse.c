// Differential test for fbparse.h against picohttpparser (vendor/pico, pinned commit 465a7ff).
//   make test   (see Makefile; -DFP_AVX512_EMU for the AVX-512 code path on C intrinsics, -DFP_FORCE_SCALAR)
//   ./test [quick]
// Every input is parsed by pico and by fb_parse_request with the best backend AND the scalar classify, with
// both header loops (sequential / LF walk), and with two different 64-byte paddings; the return code must be identical (including -1 vs -2), and on
// success every output (method, path, minor version, header count, every name/value pointer and length).
// The req_t adapter (fb_parse_req, both backends) must equal testlib's ref_parse exactly (return code,
// route, id, token, body). There is no list of tolerated differences: any difference is a failure.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fastparse.h"
#include "picohttpparser.h"
#include "fbparse.h"
#include "testlib.h"
#include "shapes.h"
#include "edges.h"

_Static_assert(sizeof(struct fb_header) == sizeof(struct phr_header), "fb_header must match phr_header");

static int fails = 0;
#define FAIL(...)                                                                                                      \
  do {                                                                                                                 \
    if (fails++ < 25) printf(__VA_ARGS__);                                                                             \
  } while (0)
static void show(const char *b, int len) {
  if (fails > 25) return;
  printf("    \"");
  for (int i = 0; i < len && i < 160; i++) {
    unsigned char c = (unsigned char)b[i];
    if (c == '\r') printf("\\r");
    else if (c == '\n') printf("\\n");
    else if (c < 32 || c > 126) printf("\\x%02x", c);
    else putchar(c);
  }
  printf("%s\" (len %d)\n", len > 160 ? "..." : "", len);
}

// pico's token_char_map, copied from vendor/pico/picohttpparser.c (static there)
static const char *pico_tok = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                              "\0\1\0\1\1\1\1\1\0\0\1\1\0\1\1\0\1\1\1\1\1\1\1\1\1\1\0\0\0\0\0\0"
                              "\0\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\0\0\0\1\1"
                              "\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\0\1\0\1\0"
                              "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                              "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                              "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                              "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

// two copies of the input, each with exactly 64 bytes of padding (ASan catches anything further)
static char *bufA, *bufB;
static void load(const char *src, int len) {
  free(bufA);
  free(bufB);
  bufA = malloc(len + PAD);
  bufB = malloc(len + PAD);
  memcpy(bufA, src, len);
  memcpy(bufB, src, len);
  memset(bufA + len, 'Z', PAD);
  for (int i = 0; i < PAD; i++) bufB[len + i] = "\r\n: \t\x00\xff\x7f"[rnd() % 8]; // padding that looks like structure
}

typedef int (*fbfn)(const char *, size_t, const char **, size_t *, const char **, size_t *, int *, struct fb_header *,
                    size_t *, size_t);
__attribute__((noinline)) static int FB_simd(const char *b, size_t l, const char **m, size_t *ml, const char **p,
                                             size_t *pl, int *mv, struct fb_header *h, size_t *nh, size_t ll) {
  return fb_parse_request(b, l, m, ml, p, pl, mv, h, nh, ll);
}
__attribute__((noinline)) static int FB_scalar(const char *b, size_t l, const char **m, size_t *ml, const char **p,
                                               size_t *pl, int *mv, struct fb_header *h, size_t *nh, size_t ll) {
  return fb_parse_request_scalar(b, l, m, ml, p, pl, mv, h, nh, ll);
}
__attribute__((noinline)) static int FB_seq(const char *b, size_t l, const char **m, size_t *ml, const char **p,
                                            size_t *pl, int *mv, struct fb_header *h, size_t *nh, size_t ll) {
  return fb_parse_request_loop(0, b, l, m, ml, p, pl, mv, h, nh, ll);
}
__attribute__((noinline)) static int FB_walk(const char *b, size_t l, const char **m, size_t *ml, const char **p,
                                             size_t *pl, int *mv, struct fb_header *h, size_t *nh, size_t ll) {
  return fb_parse_request_loop(1, b, l, m, ml, p, pl, mv, h, nh, ll);
}
__attribute__((noinline)) static int AX_simd(const char *b, int l, req_t *r) { return fb_parse_req(b, l, r); }
__attribute__((noinline)) static int AX_scalar(const char *b, int l, req_t *r) { return fb_parse_req_scalar(b, l, r); }

static long st_ok, st_inval, st_part, st_ax[4], ex10; // pico results seen; adapter: >0, NEED_MORE, FALLBACK, -2
#define MAXH 64
// the phr API: pico vs fb (simd on A and B, scalar on B)
static void check_phr(int len, size_t max, size_t last_len, const char *what) {
  const char *m, *p;
  size_t ml, pl, nh = max;
  int mv;
  struct phr_header H[MAXH];
  int rp = phr_parse_request(bufA, len, &m, &ml, &p, &pl, &mv, H, &nh, last_len);
  if (rp > 0) st_ok++;
  else if (rp == -1) st_inval++;
  else st_part++;
  struct {
    fbfn f;
    const char *base;
    const char *name;
  } V[] = { { FB_simd, bufA, "simd/A" },
            { FB_simd, bufB, "simd/B" },
            { FB_scalar, bufB, "scalar/B" },
            { FB_seq, bufB, "seq loop/B" },
            { FB_walk, bufA, "walk loop/A" } };
  for (int v = 0; v < 5; v++) {
    const char *m2, *p2;
    size_t ml2, pl2, nh2 = max;
    int mv2;
    struct fb_header G[MAXH];
    const char *B = V[v].base;
    int rf = V[v].f(B, len, &m2, &ml2, &p2, &pl2, &mv2, G, &nh2, last_len);
    int bad = rf != rp;
    if (!bad && rp > 0) {
      bad = m2 - B != m - bufA || ml2 != ml || p2 - B != p - bufA || pl2 != pl || mv2 != mv || nh2 != nh;
      for (size_t i = 0; !bad && i < nh; i++)
        bad = (G[i].name == NULL) != (H[i].name == NULL) || (H[i].name && G[i].name - B != H[i].name - bufA) ||
              G[i].name_len != H[i].name_len || G[i].value - B != H[i].value - bufA || G[i].value_len != H[i].value_len;
    }
    if (bad) {
      FAIL("PHR MISMATCH (%s, %s) max=%zu last_len=%zu: pico=%d fb=%d\n", what, V[v].name, max, last_len, rp, rf);
      show(bufA, len);
    }
  }
}
// the req_t adapter vs ref_parse (pico + logic)
static void check_ax(int len, const char *what) {
  req_t g, f, s;
  memset(&g, 0, sizeof g);
  memset(&f, 0, sizeof f);
  memset(&s, 0, sizeof s);
  int c = ref_parse(bufA, len, &g), a = AX_simd(bufB, len, &f), b = AX_scalar(bufA, len, &s);
  for (int w = 0; w < 2; w++) {
    req_t q;
    memset(&q, 0, sizeof q);
    int x = fb_parse_req_loop(w, bufA, len, &q);
    if (!same(c, &g, x, &q) || (c > 0 && g.id_ok && g.id != q.id)) {
      FAIL("ADAPTER MISMATCH (%s, loop %d): ref=%d fb=%d\n", what, w, c, x);
      show(bufA, len);
    }
  }
  st_ax[c > 0 ? 0 : c == FP_NEED_MORE ? 1 : c == FP_FALLBACK ? 2 : 3]++;
  // same() compares tok pointers: rebase the B-buffer result onto A
  if (a > 0 && f.auth) f.tok = bufA + (f.tok - bufB);
  if (!same(c, &g, a, &f) || (c > 0 && g.id_ok && g.id != f.id)) {
    FAIL("ADAPTER MISMATCH (%s, simd): ref=%d fb=%d\n", what, c, a);
    show(bufA, len);
  }
  if (!same(c, &g, b, &s) || (c > 0 && g.id_ok && g.id != s.id)) {
    FAIL("ADAPTER MISMATCH (%s, scalar): ref=%d fb=%d\n", what, c, b);
    show(bufA, len);
  }
  fb_info_t in;
  req_t e;
  int x = fb_parse_req_ex(bufA, len, &e, &in);
  if (x != c || (x == FP_FALLBACK && !in.flags) || (x > 0 && in.flags)) {
    FAIL("ADAPTER EX MISMATCH (%s): ref=%d ex=%d flags=%d\n", what, c, x, in.flags);
    show(bufA, len);
  }
  // HTTP/1.x with x != 1 and nothing else odd: ex fills r like a success of the same request as HTTP/1.1
  if (x == FP_FALLBACK && in.flags == FB_MINOR) {
    char *t = malloc(len + PAD);
    memcpy(t, bufA, len + PAD);
    int vp = -1;
    for (int i = 0; i + 8 <= len; i++)
      if (!memcmp(t + i, "HTTP/1.", 7) && t[i + 7] != '1' && (t[i + 8] == '\r' || t[i + 8] == '\n')) {
        vp = i + 7;
        break;
      }
    if (vp >= 0) {
      t[vp] = '1';
      req_t g1;
      int c1 = ref_parse(t, len, &g1);
      if (c1 > 0 || c1 == FP_NEED_MORE) {
        e.tok = e.auth ? t + (e.tok - bufA) : 0;
        if ((c1 > 0 ? !same(c1, &g1, in.total, &e) : in.total <= len) || (g1.id_ok && g1.id != e.id)) {
          FAIL("ADAPTER EX/1.0 MISMATCH (%s): ref(1.1)=%d total=%d\n", what, c1, in.total);
          show(bufA, len);
        }
      }
      ex10++;
    }
    free(t);
  }
}
static const size_t MAXES[] = { MAXH, 48, 0, 1, 2, 3, 5, 16 };
static void check(const char *src, int len, const char *what) {
  load(src, len);
  check_phr(len, MAXH, 0, what);
  check_ax(len, what);
  if (rnd() % 4 == 0) check_phr(len, MAXES[rnd() % 8], 0, what);
  if (rnd() % 8 == 0 && len) check_phr(len, MAXH, 1 + rnd() % len, what); // slowloris check (last_len <= len)
}
static void check_truncs(const char *src, int len, const char *what) {
  for (int t = 0; t <= len; t++) check(src, t, what);
}

int main(int argc, char **argv) {
  int quick = argc > 1 && !strcmp(argv[1], "quick"), FUZZ = quick ? 200000 : 2000000;
  printf("fbparse backend: %s (fastparse.h backend %s)\n", FB_BACKEND_NAME, FP_BACKEND_NAME);
  mk_tokens();
  // 0. classify primitive vs pico's token map and the byte definitions, SIMD and scalar
  for (int c = 0; c < 256; c++)
    if (fb_tchar((unsigned char)c) != (pico_tok[c] != 0)) FAIL("TCHAR LUT FAIL 0x%02x\n", c);
  for (int it = 0; it < 300000; it++) {
    char blk[64 + PAD];
    for (int i = 0; i < 64 + PAD; i++)
      blk[i] = (it & 1) ? (char)rnd()
                        : " \t\r\n:\"(),/;<=>?@[\\]{}\x7f\x80\xff\x00\x08\x09\x0a\x1f\x20"
                          "aZ0~|^_`"[rnd() % 36];
    uint64_t ref[4] = { 0, 0, 0, 0 };
    for (int i = 0; i < 64; i++) {
      unsigned char x = (unsigned char)blk[i];
      ref[FB_NT] |= (uint64_t)!pico_tok[x] << i;
      ref[FB_CT] |= (uint64_t)((x < 32 && x != 9) || x == 127) << i;
      ref[FB_PE] |= (uint64_t)(x <= 32 || x == 127) << i;
      ref[FB_LF] |= (uint64_t)(x == '\n') << i;
    }
    uint64_t got[8] = { fb_cls64(1, FB_NT, blk), fb_cls64(1, FB_CT, blk), fb_cls64(1, FB_PE, blk),
                        fb_cls64(1, FB_LF, blk), fb_cls64(0, FB_NT, blk), fb_cls64(0, FB_CT, blk),
                        fb_cls64(0, FB_PE, blk), fb_cls64(0, FB_LF, blk) };
    uint64_t all1[4], all0[4], nc1[2], nc0[2], lc1[2], lc0[2];
    fb_all64(1, blk, all1);
    fb_all64(0, blk, all0);
    fb_ntct64(1, blk, &nc1[0], &nc1[1]);
    fb_ntct64(0, blk, &nc0[0], &nc0[1]);
    fb_lfct64(1, blk, &lc1[0], &lc1[1]);
    fb_lfct64(0, blk, &lc0[0], &lc0[1]);
    int bad = 0;
    for (int j = 0; j < 8; j++)
      bad |= (got[j] != ref[j % 4]) | (all1[j % 4] != ref[j % 4]) | (all0[j % 4] != ref[j % 4]);
    bad |= (nc1[0] != ref[FB_NT]) | (nc1[1] != ref[FB_CT]) | (nc0[0] != ref[FB_NT]) | (nc0[1] != ref[FB_CT]);
    bad |= (lc1[0] != ref[FB_LF]) | (lc1[1] != ref[FB_CT]) | (lc0[0] != ref[FB_LF]) | (lc0[1] != ref[FB_CT]);
    if (bad) {
      FAIL("CLASSIFY FAIL it %d\n", it);
      break;
    }
  }
  printf("primitives: failures %d\n", fails);

  // 1. the shared edge cases (tests/edges.h), every truncation
  for (size_t i = 0; i < sizeof EDGES / sizeof *EDGES; i++)
    check_truncs(EDGES[i].req, (int)strlen(EDGES[i].req), "edge");
  printf("edge cases: %zu x every truncation, failures %d\n", sizeof EDGES / sizeof *EDGES, fails);

  // 2. optional: third-party conformance cases, every truncation. FB_CASES=file of records
  //    name\0 source\0 verdict\0 <u32 little-endian length> <bytes>   (not shipped: build it from the suites you trust)
  const char *cases = getenv("FB_CASES");
  FILE *fi = cases ? fopen(cases, "rb") : NULL;
  long ncase = 0;
  if (fi) {
    fseek(fi, 0, SEEK_END);
    long sz = ftell(fi);
    fseek(fi, 0, SEEK_SET);
    char *all = malloc(sz);
    if (fread(all, 1, sz, fi) != (size_t)sz) return 2;
    fclose(fi);
    for (long i = 0; i < sz; ncase++) {
      for (int f = 0; f < 3; f++) i += strlen(all + i) + 1; // name, source, verdict
      uint32_t n;
      memcpy(&n, all + i, 4);
      i += 4;
      check_truncs(all + i, (int)n, "conf");
      i += n;
    }
    free(all);
    printf("conformance cases: %ld x every truncation, failures %d\n", ncase, fails);
  } else printf("conformance cases: FB_CASES not set, skipped\n");

  // 3. corpora: k6 / gocli (the parser corpus) and every fallback shape; truncations for a subset
  enum { NC = 4096 };
  static char *seed[NC + 8 * 512];
  static int slen[NC + 8 * 512];
  int ns = 0;
  char *tmp = malloc(32768);
  for (int i = 0; i < NC; i++) {
    int l = gen(tmp, i % 3);
    seed[ns] = malloc(l + 1);
    memcpy(seed[ns], tmp, l);
    slen[ns++] = l;
  }
  for (int sh = 0; sh < S_NSHAPES; sh++)
    for (int i = 0; i < 512; i++) {
      int l = gen_fb(tmp, sh);
      seed[ns] = malloc(l + 1);
      memcpy(seed[ns], tmp, l);
      slen[ns++] = l;
    }
  long big = 0;
  for (int i = 0; i < ns; i++) {
    check(seed[i], slen[i], "corpus");
    if (slen[i] > 8192) big++;
    if (i % 64 == 0 && slen[i] < 4096) check_truncs(seed[i], slen[i], "corpus-trunc");
  }
  for (int sh = 0; sh < S_NSHAPES; sh++) {
    int i = NC + sh * 512;
    check_truncs(seed[i], slen[i], "shape-trunc");
  }
  printf("corpus: %d requests (k6/gocli %d, %d per fallback shape, %ld heads > 8 KB), failures %d\n", ns, NC, 512, big,
         fails);
  // pipelined: two requests back to back (pico parses only the first head)
  for (int it = 0; it < 20000; it++) {
    int i = rnd() % ns, j = rnd() % ns, l = slen[i] + slen[j];
    if (l > 32000) continue;
    memcpy(tmp, seed[i], slen[i]);
    memcpy(tmp + slen[i], seed[j], slen[j]);
    check(tmp, l, "pipelined");
  }

  // 4. block-boundary sweep: put every structural byte at every offset relative to the 64-byte blocks
  for (int pad = 0; pad < 140; pad++)
    for (int v = 0; v < 12; v++) {
      static const char *tail[] = { "\r\n\r\n",        "\n\n",           "\r\n\n",         "\r\r\n",
                                    "\r\nX:y\r\n\r\n", "\r\n y\r\n\r\n", "\r\n:y\r\n\r\n", "\r\nX y\r\n\r\n",
                                    "\x7f\r\n\r\n",    "\t\r\n\r\n",     " \r\n\r\n",      "\x01\r\n\r\n" };
      int n = sprintf(tmp, "%s /%.*s HTTP/1.1\r\nHost: x\r\nAbc: ", v & 1 ? "GET" : "M-SEARCH", pad % 70,
                      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
      for (int k = 0; k < pad; k++) tmp[n++] = "vv vv\tv"[k % 7];
      n += sprintf(tmp + n, "%s", tail[v]);
      check_truncs(tmp, n, "sweep");
    }
  printf("block-boundary sweeps: 1680 x every truncation, failures %d\n", fails);

  // 5. fuzz: mutate / insert / delete / splice / truncate seeds (corpus + edges), compare everything
  const char *alpha = " \t\r\n:/\"(),;<=>?@[\\]{}\x7f\x80\xff\x00\x01\x1fHTTP/1.0GETPOSTabcAZ09-_~|^`'!#$%&*+.";
  int nalpha = (int)strlen(alpha) + 1; // + the NUL
  int nedge = (int)(sizeof EDGES / sizeof *EDGES);
  for (int it = 0; it < FUZZ; it++) {
    int l;
    int k = rnd() % (ns + nedge);
    if (k < ns) {
      l = slen[k];
      if (l > 16000) {
        k = rnd() % NC;
        l = slen[k];
      }
      memcpy(tmp, seed[k], l);
    } else {
      l = (int)strlen(EDGES[k - ns].req);
      memcpy(tmp, EDGES[k - ns].req, l);
    }
    for (int nm = 1 + rnd() % 4; nm--;) {
      int op = rnd() % 10, at = l ? rnd() % l : 0;
      if (op < 5 && l) tmp[at] = (rnd() % 4) ? alpha[rnd() % nalpha] : (char)rnd();
      else if (op < 7 && l < 30000) {
        memmove(tmp + at + 1, tmp + at, l - at);
        tmp[at] = alpha[rnd() % nalpha];
        l++;
      } else if (op < 8 && l) {
        int d = 1 + rnd() % 8;
        if (at + d > l) d = l - at;
        memmove(tmp + at, tmp + at + d, l - at - d);
        l -= d;
      } else if (op < 9 && l) {
        int j = rnd() % l, d = 1 + rnd() % 40;
        if (j + d > l) d = l - j;
        if (l + d < 30000) {
          memmove(tmp + at + d, tmp + at, l - at);
          memmove(tmp + at, tmp + (j < at ? j : j + d), d);
          l += d;
        }
      } else if (l) {
        int s = rnd() % 4;
        const char *e[] = { "\r\n", "\n", "\r", " " };
        int d = (int)strlen(e[s]);
        if (l + d < 30000) {
          memmove(tmp + at + d, tmp + at, l - at);
          memcpy(tmp + at, e[s], d);
          l += d;
        }
      }
    }
    if (rnd() % 3 == 0) l = rnd() % (l + 1);
    check(tmp, l, "fuzz");
  }
  printf("fuzz: %d mutated inputs, failures %d\n", FUZZ, fails);
  // 6. random short strings from a structural alphabet (dense coverage of request-line states)
  for (int it = 0; it < FUZZ / 4; it++) {
    static const char *pieces[] = { "GET",  "POST", " ",    "  ",   "/",    "/a",      "HTTP/1.", "1",
                                    "0",    "9",    "x",    "\r\n", "\n",   "\r",      ":",       "A",
                                    "a: b", "\t",   "\x7f", "\x80", "\x00", "\r\n\r\n" };
    int l = 0;
    for (int k = 1 + rnd() % 14; k--;) {
      const char *pc = pieces[rnd() % 22];
      int d = pc[0] ? (int)strlen(pc) : 1;
      memcpy(tmp + l, pc, d);
      l += d;
    }
    check(tmp, l, "pieces");
  }
  printf("piece strings: %d, failures %d\n", FUZZ / 4, fails);
  printf(
      "pico results seen: ok %ld, invalid %ld, incomplete %ld; ref_parse results: >0 %ld, NEED_MORE %ld, FALLBACK %ld, invalid %ld\n",
      st_ok, st_inval, st_part, st_ax[0], st_ax[1], st_ax[2], st_ax[3]);
  printf("HTTP/1.x (x != 1) requests checked against the same request as 1.1 through fb_parse_req_ex: %ld\n", ex10);
  printf("TOTAL FAILURES: %d\n", fails);
  for (int i = 0; i < ns; i++) free(seed[i]);
  free(tmp);
  free(bufA);
  free(bufB);
  return fails != 0;
}
