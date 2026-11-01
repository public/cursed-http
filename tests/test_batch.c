// Differential test: every lane of bp_parse (every phase-A backend compiled in) must return exactly what
// fastparse.h's fast_parse returns for that buffer: same ret, and for ret > 0 the same route, id_ok, id,
// auth, tok (pointer), tok_len, body_off, body_len. Inputs are streamed into random mixed batches of
// 1..32 lanes (sometimes up to 100, to cross BP_CHUNK), each lane its own malloc of exactly
// alloc + 64 bytes (ASan sees any read past the padding).
//   make test   (see Makefile)
#define BP_STATS
#include "batchparse.h"
#include "picohttpparser.h"
#include "testlib.h"
#include "edges.h"

__attribute__((noinline)) static void B_c(int n, const char *const *b, const int *l, req_t *o, int *r) {
  bp_parse_rl(n, b, l, o, r, BP_RL_C);
}
__attribute__((noinline)) static void B_canon(int n, const char *const *b, const int *l, req_t *o, int *r) {
  bp_parse_rl(n, b, l, o, r, BP_RL_CANON);
}
#ifdef BP_HAVE_AVX2
__attribute__((noinline)) static void B_avx2(int n, const char *const *b, const int *l, req_t *o, int *r) {
  bp_parse_rl(n, b, l, o, r, BP_RL_AVX2);
}
__attribute__((noinline)) static void B_avx2i(int n, const char *const *b, const int *l, req_t *o, int *r) {
  bp_parse_rl(n, b, l, o, r, BP_RL_AVX2I);
}
#endif
#ifdef BP_HAVE_Z
__attribute__((noinline)) static void B_z(int n, const char *const *b, const int *l, req_t *o, int *r) {
  bp_parse_rl(n, b, l, o, r, BP_RL_Z);
}
#endif
typedef void (*bfn)(int, const char *const *, const int *, req_t *, int *);
static const struct {
  const char *name;
  bfn f;
} VAR[] = {
  { "lane-C", B_c },
  { "lane-canon", B_canon },
#ifdef BP_HAVE_AVX2
  { "avx2-gather", B_avx2 },
  { "avx2-insert", B_avx2i },
#endif
#ifdef BP_HAVE_Z
  { "avx512-zmm" BP_ZTAG, B_z },
#endif
};
#define NVAR ((int)(sizeof VAR / sizeof *VAR))

static int fails = 0;
static long lanes_checked = 0, batches = 0, by_ret[3];
#define FAIL(...)                                                                                                      \
  do {                                                                                                                 \
    if (fails++ < 20) printf(__VA_ARGS__);                                                                             \
  } while (0)

// ---- the batcher ----
#define QMAX 128
static struct {
  char *b;
  int len, own;
  const char *what;
} Q[QMAX];
static int nq = 0, target = 1;
static void new_target(void) { target = (rnd() % 16 == 0) ? 33 + rnd() % 68 : 1 + rnd() % 32; }

static void flush(void) {
  if (!nq) return;
  const char *bufs[QMAX];
  int lens[QMAX], want[QMAX];
  req_t ref[QMAX];
  for (int i = 0; i < nq; i++) {
    bufs[i] = Q[i].b;
    lens[i] = Q[i].len;
    memset(&ref[i], 0, sizeof ref[i]);
    want[i] = P_fast(bufs[i], lens[i], &ref[i]);
  }
  for (int v = 0; v < NVAR; v++) {
    req_t out[QMAX];
    int ret[QMAX];
    memset(out, 0xA5, sizeof out);
    for (int i = 0; i < nq; i++) ret[i] = 0x7777;
    VAR[v].f(nq, bufs, lens, out, ret);
    for (int i = 0; i < nq; i++) {
      if (!same(want[i], &ref[i], ret[i], &out[i]) || (want[i] > 0 && ref[i].id != out[i].id)) {
        FAIL(
            "MISMATCH %s lane %d/%d (%s) len=%d: fast=%d batch=%d route %d/%d id %lld/%lld auth %d/%d tl %d/%d bo %d/%d bl %d/%d\n",
            VAR[v].name, i, nq, Q[i].what, lens[i], want[i], ret[i], ref[i].route, out[i].route, (long long)ref[i].id,
            (long long)out[i].id, ref[i].auth, out[i].auth, ref[i].tok_len, out[i].tok_len, ref[i].body_off,
            out[i].body_off, ref[i].body_len, out[i].body_len);
        if (fails <= 20) {
          printf("  ");
          for (int t = 0; t < 70 && t < lens[i]; t++)
            printf(bufs[i][t] < 32 || bufs[i][t] > 126 ? "\\x%02x" : "%c", (unsigned char)bufs[i][t]);
          printf("\n");
        }
      }
    }
  }
  for (int i = 0; i < nq; i++) {
    lanes_checked++;
    by_ret[want[i] > 0 ? 0 : want[i] == 0 ? 1 : 2]++;
    if (Q[i].own) free(Q[i].b);
  }
  batches++;
  nq = 0;
  new_target();
}
// one lane: buffer of exactly alloc + 64 bytes (src[0..alloc) then padding), parsed with len <= alloc
static void push_raw(const char *src, int alloc, int len, const char *what) {
  char *b = malloc(alloc + 64);
  memcpy(b, src, alloc);
  for (int i = 0; i < 64; i++) b[alloc + i] = (rnd() & 1) ? 0x5a : (char)rnd();
  Q[nq].b = b;
  Q[nq].len = len;
  Q[nq].own = 1;
  Q[nq].what = what;
  if (nq > 0 && rnd() % 64 == 0) { // alias: a second lane on the same buffer
    if (++nq >= QMAX) {
      flush();
      return;
    }
    Q[nq] = Q[nq - 1];
    Q[nq].own = 0;
  }
  if (++nq >= target) flush();
}

// mixers: the corpus and fuzz streams get interleaved with whatever category is being enumerated
enum { N = 4096, STRIDE = 1024 + 64 };
static char *mem;
static int *len_;
static void push_corpus(void) {
  int i = rnd() % N;
  push_raw(mem + (size_t)i * STRIDE, len_[i], len_[i], "corpus");
}
static void push_fuzz(void) {
  static const char *alpha = " \r\n:/\tabcABC0123456789-.Bearer";
  int i = rnd() % N;
  char tmp[1024];
  int l = len_[i];
  memcpy(tmp, mem + (size_t)i * STRIDE, l);
  int k = 1 + rnd() % 3;
  for (int j = 0; j < k; j++) tmp[rnd() % l] = alpha[rnd() % strlen(alpha)];
  push_raw(tmp, l, (rnd() & 1) ? (int)(rnd() % (l + 1)) : l, "fuzz");
}
static void push(const char *src, int alloc, int len, const char *what) {
  uint32_t m = rnd() % 4;
  if (m == 0) push_corpus();
  else if (m == 1) push_fuzz();
  push_raw(src, alloc, len, what);
}

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;
  printf("fastparse.h backend: %s; batch variants:", FP_BACKEND_NAME);
  for (int v = 0; v < NVAR; v++) printf(" %s", VAR[v].name);
  printf("\n");
  mk_tokens();
  new_target();
  mem = calloc(N, STRIDE);
  len_ = malloc(N * sizeof(int));
  for (int i = 0; i < N; i++) len_[i] = gen(mem + (size_t)i * STRIDE, (i & 1) ? 0 : 1 + ((i >> 1) & 1));

  // 1. edge cases, each at every truncation (the full bytes stay in the buffer past len)
  for (size_t e = 0; e < sizeof EDGES / sizeof *EDGES; e++) {
    int l = strlen(EDGES[e].req);
    for (int t = 0; t <= l; t++) push(EDGES[e].req, l, t, "edge");
  }
  flush();
  printf("edge cases x every truncation: lanes %ld, failures %d\n", lanes_checked, fails);
  // 2. block-boundary sweep (as test_fastparse.c), every truncation
  for (int pad = 0; pad < 200; pad++)
    for (int v = 0; v < 4; v++) {
      char req[600];
      int n = sprintf(
          req, "%s HTTP/1.1\r\nX: %.*s\r\n%s", v & 1 ? "POST /posts" : "POST /posts/12/like", pad,
          "pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp"
          "pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp",
          v & 2 ? "Content-Length: 2\r\nAuthorization: Bearer tk\r\n\r\nhi"
                : "authorization: Bearer tk\r\ncontent-length: 2\r\n\r\nhi");
      for (int t = 0; t <= n; t++) push(req, n, t, "sweep");
    }
  // GET-shaped sweep too (c/t candidate path, 1..3 blocks)
  for (int pad = 0; pad < 200; pad++)
    for (int v = 0; v < 4; v++) {
      char req[600];
      int n = sprintf(
          req, "%s HTTP/1.1\r\nX: %.*s\r\n%s\r\n", v & 1 ? "GET /feed" : "GET /posts/4242", pad,
          "pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp"
          "pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp",
          v & 2 ? "Content-Length: 0\r\nTE: x" : "Accept: */*");
      for (int t = 0; t <= n; t++) push(req, n, t, "sweep-get");
    }
  flush();
  printf("+ 1600 boundary sweeps x every truncation: lanes %ld, failures %d\n", lanes_checked, fails);
  // 3. corpus: all, plus every truncation of 300
  for (int i = 0; i < N; i++) push_raw(mem + (size_t)i * STRIDE, len_[i], len_[i], "corpus");
  for (int i = 0; i < 300; i++)
    for (int t = 0; t < len_[i]; t++) push(mem + (size_t)i * STRIDE, len_[i], t, "corpus-trunc");
  // pipelined pairs: the batch parses the first request of each lane
  for (int i = 0; i + 1 < 2000; i += 2) {
    char pb[2200];
    int l1 = len_[i], l2 = len_[i + 1];
    memcpy(pb, mem + (size_t)i * STRIDE, l1);
    memcpy(pb + l1, mem + (size_t)(i + 1) * STRIDE, l2);
    push(pb, l1 + l2, l1 + l2, "pipelined");
    push(pb, l1 + l2, (int)(rnd() % (l1 + l2 + 1)), "pipelined-trunc");
  }
  flush();
  printf("corpus %d + 300 x every truncation + 1000 pipelined pairs: lanes %ld, failures %d\n", N, lanes_checked,
         fails);
  // 4. fuzz (as test_fastparse.c): mutate + maybe truncate
  for (int it = 0; it < 300000; it++) push_fuzz();
  // 5. layout-preserving fuzz: never touches CR/LF
  for (int it = 0; it < 300000; it++) {
    int i = rnd() % N;
    char tmp[1024];
    int l = len_[i];
    memcpy(tmp, mem + (size_t)i * STRIDE, l);
    int k = 1 + rnd() % 3;
    for (int j = 0; j < k; j++) {
      int p = rnd() % l;
      if (tmp[p] == '\r' || tmp[p] == '\n') continue;
      tmp[p] = (rnd() & 3) ? " :/\tabcABC0123456789-.BearerxX"[rnd() % 31] : (char)(tmp[p] ^ 0x20);
    }
    push(tmp, l, (rnd() % 4 == 0) ? (int)(rnd() % (l + 1)) : l, "layout-fuzz");
  }
  // 5b. request-line fuzz: mutate only the first 40 bytes (the lane-parallel phase), incl. digits
  for (int it = 0; it < 300000; it++) {
    int i = rnd() % N;
    char tmp[1100];
    int l = len_[i];
    memcpy(tmp, mem + (size_t)i * STRIDE, l);
    int k = 1 + rnd() % 2;
    for (int j = 0; j < k; j++) {
      int p = rnd() % 40;
      if (p >= l) continue;
      uint32_t c = rnd() % 8;
      tmp[p] = c < 4   ? "0123456789 /:\r\n\x00\xff\x2f\x3a.HTPSGE"[rnd() % 23]
               : c < 6 ? (char)(tmp[p] ^ (1 << (rnd() % 8)))
                       : (char)rnd();
    }
    if (rnd() % 8 == 0) { // insert / delete a byte in the request line (shifts the tail)
      int p = 5 + rnd() % 20;
      if (rnd() & 1) {
        memmove(tmp + p + 1, tmp + p, l - p);
        tmp[p] = '0' + rnd() % 10;
        l++;
      } else {
        memmove(tmp + p, tmp + p + 1, l - p - 1);
        l--;
      }
    }
    push(tmp, l, (rnd() % 6 == 0) ? (int)(rnd() % (l + 1)) : l, "line-fuzz");
  }
  // 5c. ids: every digit count 0..18 on both id routes, leading zeros, all-zero
  for (int it = 0; it < 50000; it++) {
    char tmp[600], digs[24];
    int nd = rnd() % 19;
    for (int d = 0; d < nd; d++) digs[d] = (rnd() % 5 == 0) ? '0' : '0' + rnd() % 10;
    if (rnd() % 7 == 0 && nd) digs[rnd() % nd] = "/:a. "[rnd() % 5];
    digs[nd] = 0;
    int l = (rnd() & 1) ? sprintf(tmp, "GET /posts/%s HTTP/1.1\r\nHost: x\r\n\r\n", digs)
            : (rnd() & 1)
                ? sprintf(tmp, "POST /posts/%s/like HTTP/1.1\r\nAuthorization: Bearer %s\r\nContent-Length: 0\r\n\r\n",
                          digs, TOKS[rnd() % 64])
                : sprintf(tmp, "POST /posts%s%s%s HTTP/1.1\r\nAuthorization: Bearer %.*s\r\n\r\n", // short, no CL
                          nd ? "/" : "", nd ? digs : "", nd ? "/like" : "", (int)(rnd() % 40), TOKS[rnd() % 64]);
    push(tmp, l, (rnd() % 5 == 0) ? (int)(rnd() % (l + 1)) : l, "ids");
  }
  printf("fuzz 300k + layout fuzz 300k + request-line fuzz 300k + ids 50k: lanes %ld, failures %d\n", lanes_checked,
         fails);
  // 6. header swap (as test_fastparse.c)
  static const char *NAMES[] = { "Content-Length",
                                 "content-length",
                                 "CONTENT-LENGTH",
                                 "Content-Lengtx",
                                 "Transfer-Encoding",
                                 "transfer-encodinX",
                                 "Authorization",
                                 "authorization",
                                 "Authorizatio",
                                 "Accept",
                                 "Cookie",
                                 "Content-Type",
                                 "TE",
                                 "a",
                                 "c",
                                 "t",
                                 "Host" };
  for (int it = 0; it < 200000; it++) {
    int i = rnd() % N;
    char tmp[1100];
    int l = len_[i];
    memcpy(tmp, mem + (size_t)i * STRIDE, l);
    int nl = 0, st[32];
    for (int p = 0; p < l && nl < 32; p++)
      if (tmp[p] == '\n') st[nl++] = p + 1;
    if (nl < 3) continue;
    int li = rnd() % (nl - 2), s = st[li], e = st[li + 1] - 2;
    if (e <= s || tmp[e] != '\r') continue;
    const char *nm = NAMES[rnd() % (sizeof NAMES / sizeof *NAMES)];
    int n = strlen(nm), L = e - s;
    if (n + 2 > L) continue;
    memcpy(tmp + s, nm, n);
    tmp[s + n] = ':';
    tmp[s + n + 1] = ' ';
    for (int p = s + n + 2; p < e; p++) tmp[p] = (rnd() % 4) ? '0' + rnd() % 10 : "Bearer x "[rnd() % 9];
    if (rnd() % 3 == 0) {
      int p = s + n + 2;
      if (p + 7 <= e) memcpy(tmp + p, "Bearer ", 7);
    }
    push(tmp, l, l, "swap");
  }
  // 7. envelope busters: an extra header of 0..9000 bytes at a random line, so the end of headers lands
  //    in every block 1..140 (BP_NB and FP_MAXHDR edges included), some truncated, some >= 8 KB long
  static char big[20000];
  for (int it = 0; it < 30000; it++) {
    int i = rnd() % N;
    const char *src = mem + (size_t)i * STRIDE;
    int l = len_[i];
    int nl = 0, st[32];
    for (int p = 0; p < l && nl < 32; p++)
      if (src[p] == '\n') st[nl++] = p + 1;
    int at = st[rnd() % (nl - 1)]; // after some LF before the empty line
    int pl = (it & 3) == 0 ? (int)(rnd() % 9000) : (it & 3) == 1 ? 8000 + (int)(rnd() % 400) : (int)(rnd() % 600);
    memcpy(big, src, at);
    int o = at;
    o += sprintf(big + o, "X-Pad: ");
    for (int p = 0; p < pl; p++) big[o++] = 'a' + (char)(rnd() % 26);
    if (rnd() % 4 == 0)
      for (int p = 0; p < pl / 50; p++) big[o - 1 - (int)(rnd() % (pl + 1))] = "\r\nct:"[rnd() % 5];
    big[o++] = '\r';
    big[o++] = '\n';
    memcpy(big + o, src + at, l - at);
    o += l - at;
    int tl = (rnd() % 4 == 0) ? (int)(rnd() % (o + 1)) : o;
    push(big, o, tl, "envelope");
  }
  // 8. trailing bytes after the end of headers that look like header lines (body / next request / junk):
  //    "\r\nContent-Length: 1x", "transfer-encoding", LFs, in the same 64-byte block as the end
  static const char *JUNK[] = { "content-length: 1x\r\n",
                                "Transfer-Encoding: chunked\r\n",
                                "\n\n",
                                "c\r\nt\r\n",
                                "\r\n\r\n",
                                "Content-Length: 5\r\n\r\nhello",
                                "a\nAuthorization: Bearer zz\r\n",
                                "\nContent-Length: 7\r\n" };
  for (int it = 0; it < 100000; it++) {
    int i = rnd() % N;
    char tmp[1400];
    int l = len_[i];
    memcpy(tmp, mem + (size_t)i * STRIDE, l);
    for (int j = 0, k = 1 + rnd() % 4; j < k; j++) {
      const char *J = JUNK[rnd() % 8];
      int n = strlen(J);
      memcpy(tmp + l, J, n);
      l += n;
    }
    push(tmp, l, (rnd() % 3 == 0) ? (int)(rnd() % (l + 1)) : l, "junk-after");
  }
  // 9. CR / control-byte injection (fastparse.h's bare-CR and "line starts <= 0x20" rules): bare CRs,
  //    obs-fold (SP/HT after LF), control bytes, ':'-less c/t lines, CR at block edges; GETs mostly
  //    (the 2-block fast path), every position incl. right after an LF
  for (int it = 0; it < 200000; it++) {
    int i = rnd() % N;
    char tmp[1100];
    int l = len_[i];
    memcpy(tmp, mem + (size_t)i * STRIDE, l);
    if (tmp[0] == 'P' && rnd() % 4) continue;
    for (int j = 0, k = 1 + rnd() % 2; j < k; j++) {
      int p;
      if (rnd() & 1) {
        int nl = 0, st[32];
        for (int q = 0; q < l && nl < 32; q++)
          if (tmp[q] == '\n') st[nl++] = q + 1;
        p = st[rnd() % nl];
      } else p = rnd() % l;
      if (p >= l) p = l - 1;
      char c = "\r\r \t\x01\x1f\x7f:cT\n"[rnd() % 11];
      if (rnd() % 3 == 0) {
        memmove(tmp + p + 1, tmp + p, l - p);
        l++;
      }
      tmp[p] = c;
    }
    push(tmp, l, (rnd() % 5 == 0) ? (int)(rnd() % (l + 1)) : l, "cr-ctl");
  }
  flush();
  printf("header-swap 200k + envelope busters 30k + trailing junk 100k + CR/control 200k: lanes %ld, failures %d\n",
         lanes_checked, fails);
  printf("lanes checked %ld in %ld batches (x %d variants): parsed %ld, NEED_MORE %ld, FALLBACK %ld\n", lanes_checked,
         batches, NVAR, by_ret[0], by_ret[1], by_ret[2]);
  printf("lane paths (all variants): canonical GET %llu, canonical POST %llu, handed to fast_parse %llu of %llu\n",
         (unsigned long long)bp_stats.canon_get, (unsigned long long)bp_stats.canon_post,
         (unsigned long long)bp_stats.slow, (unsigned long long)bp_stats.lanes);
  printf("TOTAL FAILURES: %d\n", fails);
  return fails != 0;
}
