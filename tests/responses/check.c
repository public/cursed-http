// check.c - fbresp.h over the captured response corpus (tests/responses/README.md).
//   build/check_resp_corpus tests/responses/corpus
// Each record is every byte one server sent on one connection; the index says which requests went out on it.
// The connection is walked as a client would: per request, fbr_parse the heads (interim 1xx first), then the body by
// its framing (fbr_chunked + fb_parse_headers for chunked bodies and trailers). Checks:
//   - every head, and every prefix of it, parses exactly as phr_parse_response (result code, every output), SIMD and
//     scalar, with two paddings;
//   - the walk ends exactly at the end of the record (or in a tunnel / a close-delimited body), with one final
//     response per request;
//   - chunked bodies: streamed in pieces == one shot == phr_decode_chunked;
//   - llhttp (response mode, HEAD from the index) finds the same message boundaries.
// Prints a table per server: responses, body kinds, interim responses, trailers.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "picohttpparser.h"
#include "llhttp.h"
#include "fbresp.h"

#define PAD 64
#define MAXH 100
static int fails;
#define FAIL(...)                                                                                                      \
  do {                                                                                                                 \
    if (fails++ < 30) printf(__VA_ARGS__);                                                                             \
  } while (0)

static char *padded(const char *s, int n, char fill) {
  char *b = malloc(n + PAD);
  memcpy(b, s, n);
  memset(b + n, fill, PAD);
  return b;
}
// the head at s[0..n) and every prefix of it: fb == pico
static long heads_checked;
static void check_head(const char *s, int n, const char *where) {
  for (int t = 0; t <= n; t++) {
    char *A = padded(s, t, 'Z'), *B = padded(s, t, '\n');
    int mv, st, mv2, st2;
    const char *m, *m2;
    size_t ml, ml2, nh = MAXH, nh2;
    struct phr_header H[MAXH];
    struct fb_header G[MAXH];
    int rp = phr_parse_response(A, t, &mv, &st, &m, &ml, H, &nh, 0);
    for (int v = 0; v < 2; v++) {
      nh2 = MAXH;
      int rf = v ? fb_parse_response_scalar(A, t, &mv2, &st2, &m2, &ml2, G, &nh2, 0)
                 : fb_parse_response(B, t, &mv2, &st2, &m2, &ml2, G, &nh2, 0);
      const char *base = v ? A : B;
      int bad = rf != rp;
      if (!bad && rp > 0) {
        bad = mv2 != mv || st2 != st || m2 - base != m - A || ml2 != ml || nh2 != nh;
        for (size_t i = 0; !bad && i < nh; i++)
          bad = (G[i].name == NULL) != (H[i].name == NULL) || (H[i].name && G[i].name - base != H[i].name - A) ||
                G[i].name_len != H[i].name_len || G[i].value - base != H[i].value - A ||
                G[i].value_len != H[i].value_len;
      }
      if (bad) FAIL("HEAD MISMATCH %s, prefix %d of %d (%s): pico %d fb %d\n", where, t, n, v ? "scalar" : "simd", rp, rf);
    }
    free(A);
    free(B);
  }
  heads_checked++;
}

// llhttp's message ends on the whole connection
typedef struct {
  llhttp_t p;
  const char **reqs;
  int nreq, k, nend, ends[64];
  const char *base;
} lh_t;
static int lh_headers(llhttp_t *p) {
  lh_t *s = (lh_t *)p;
  return s->k < s->nreq && !strcmp(s->reqs[s->k], "HEAD") ? 1 : 0;
}
static int lh_complete(llhttp_t *p) {
  lh_t *s = (lh_t *)p;
  if (p->status_code / 100 != 1 || p->status_code == 101) s->k++; // a final response answers the next request
  return HPE_PAUSED;
}
static int lh_ends(const char *b, int n, const char **reqs, int nreq, int *ends) {
  static llhttp_settings_t S;
  llhttp_settings_init(&S);
  S.on_headers_complete = lh_headers;
  S.on_message_complete = lh_complete;
  lh_t s = { .reqs = reqs, .nreq = nreq };
  llhttp_init(&s.p, HTTP_RESPONSE, &S);
  int off = 0, ne = 0;
  for (;;) {
    llhttp_errno_t e = llhttp_execute(&s.p, b + off, n - off);
    if (e == HPE_PAUSED) {
      off = (int)(llhttp_get_error_pos(&s.p) - b);
      ends[ne++] = off;
      llhttp_resume(&s.p);
      if (off == n) return ne;
      continue;
    }
    if (e == HPE_PAUSED_UPGRADE) { // after the message's own end (on_message_complete), at the same place
      int at = (int)(llhttp_get_error_pos(&s.p) - b);
      if (!ne || ends[ne - 1] != at) ends[ne++] = at;
      return ne;
    }
    if (e != HPE_OK) return -1 - ne;
    if (llhttp_finish(&s.p) == HPE_PAUSED) ends[ne++] = n;
    return ne;
  }
}

enum { K_NONE, K_LENGTH, K_CHUNKED, K_CLOSE, K_TUNNEL, K_INTERIM, K_TRAILERS, K_N };
static const char *KN[] = { "none", "length", "chunked", "close", "tunnel", "1xx", "trailers" };
typedef struct {
  char name[64];
  long conns, resp, k[K_N];
} srv_t;
static srv_t SV[32];
static int nsv;
static srv_t *srv(const char *name) {
  for (int i = 0; i < nsv; i++)
    if (!strcmp(SV[i].name, name)) return &SV[i];
  snprintf(SV[nsv].name, sizeof SV[nsv].name, "%s", name);
  return &SV[nsv++];
}

static void walk(const char *rec, int n, const char *server, const char *cas, char *reqlist) {
  const char *reqs[64];
  int nreq = 0;
  for (char *t = strtok(reqlist, ","); t && nreq < 64; t = strtok(NULL, ",")) reqs[nreq++] = t;
  srv_t *S = srv(server);
  S->conns++;
  char where[160];
  int off = 0, k = 0, ends[64], ne = 0, open_end = 0;
  char *buf = padded(rec, n, 'Z');
  while (off < n && k < nreq) {
    snprintf(where, sizeof where, "%s/%s response %d", server, cas, ne);
    struct fb_header H[MAXH];
    fbr_resp_t r = { .headers = H, .num_headers = MAXH };
    int req = !strcmp(reqs[k], "HEAD") ? FBR_REQ_HEAD : !strcmp(reqs[k], "CONNECT") ? FBR_REQ_CONNECT : FBR_REQ_OTHER;
    int x = fbr_parse(buf + off, n - off, req, &r, 0);
    if (x <= 0) {
      FAIL("%s: fbr_parse %d (err %d) at %d of %d\n", where, x, r.err, off, n);
      break;
    }
    check_head(rec + off, x, where);
    S->resp++;
    int end = off + x;
    if (r.flags & FBR_INTERIM) S->k[K_INTERIM]++;
    else S->k[r.body]++, k++;
    if (r.body == FBR_LENGTH) end += (int)r.length;
    else if (r.body == FBR_CLOSE) end = n, open_end = 1;
    else if (r.body == FBR_TUNNEL) open_end = 1;
    else if (r.body == FBR_CHUNKED) {
      char *data = malloc(n);
      int bl = -1, c = fbr_chunked(buf + end, n - end, data, 1 << 30, &bl, NULL);
      free(data);
      if (c <= 0) {
        FAIL("%s: fbr_chunked %d\n", where, c);
        break;
      }
      // pico on the same body (it decodes in place: a copy)
      char *pc = malloc(n - end + 1);
      memcpy(pc, rec + end, n - end);
      struct phr_chunked_decoder d = { 0 };
      d.consume_trailer = 1;
      size_t sz = n - end;
      ssize_t left = phr_decode_chunked(&d, pc, &sz);
      struct fb_header T[MAXH];
      size_t nt = MAXH;
      char *tb = padded(rec + end + c, n - end - c, 'Z');
      int t = fb_parse_headers(tb, n - end - c, T, &nt, 0);
      free(tb);
      if (t <= 0) {
        FAIL("%s: trailer section %d\n", where, t);
        break;
      }
      if (nt) S->k[K_TRAILERS]++;
      if (left < 0 || (int)sz != bl || (int)(n - end - left) != c + t)
        FAIL("%s: chunked body: fbr %d bytes (data %d), pico left %zd (data %zu)\n", where, c + t, bl, left, sz);
      free(pc);
      end += c + t;
    }
    if (end > n) {
      FAIL("%s: body runs past the record (%d > %d)\n", where, end, n);
      break;
    }
    ends[ne++] = end;
    off = end;
    if (open_end) break;
  }
  if (off != n && !open_end) FAIL("%s/%s: walk stopped at %d of %d\n", server, cas, off, n);
  int le[64], nl = lh_ends(rec, n, reqs, nreq, le);
  int same = nl == ne;
  for (int i = 0; same && i < ne; i++) same = le[i] == ends[i];
  if (!same) {
    FAIL("%s/%s: message ends differ: fbr", server, cas);
    for (int i = 0; i < ne && fails <= 30; i++) printf(" %d", ends[i]);
    if (fails <= 30) printf("; llhttp (%d)", nl);
    for (int i = 0; i < (nl < 0 ? -1 - nl : nl) && fails <= 30; i++) printf(" %d", le[i]);
    if (fails <= 30) printf("\n");
  }
  free(buf);
}

// a corpus of heads alone (no index.tsv: tests/top1k's responses.dat): every head and every prefix vs pico, and
// fbr_parse's verdict on each, tallied
static int heads_only(FILE *dat) {
  long n_ok = 0, n_err[8] = { 0 }, empty_reason = 0, maxh = 0, st[6] = { 0 }, kinds[5] = { 0 };
  unsigned char lb[4];
  while (fread(lb, 1, 4, dat) == 4) {
    int n = lb[0] | lb[1] << 8 | lb[2] << 16 | lb[3] << 24;
    char *rec = malloc(n);
    if (fread(rec, 1, n, dat) != (size_t)n) return 2;
    check_head(rec, n, "head");
    char *b = padded(rec, n, 'Z');
    struct fb_header H[MAXH];
    fbr_resp_t r = { .headers = H, .num_headers = MAXH };
    int x = fbr_parse(b, n, FBR_REQ_OTHER, &r, 0);
    if (x == n) {
      n_ok++;
      kinds[r.body]++;
      if (!r.reason_len) empty_reason++;
      if ((long)r.num_headers > maxh) maxh = (long)r.num_headers;
      st[r.status / 100]++;
    } else if (x == -1) n_err[r.err]++;
    else FAIL("head of %d bytes: fbr_parse %d\n", n, x);
    free(b);
    free(rec);
  }
  printf("%ld heads: %ld parsed (1xx %ld, 2xx %ld, 3xx %ld, 4xx %ld, 5xx %ld; empty reason %ld; up to %ld fields)\n",
         heads_checked, n_ok, st[1], st[2], st[3], st[4], st[5], empty_reason, maxh);
  printf("framing: none %ld, length %ld, chunked %ld, close %ld, tunnel %ld; rejected: head %ld, status %ld, "
         "content-length %ld, TE in 1.0 %ld, folded framing field %ld\n",
         kinds[0], kinds[1], kinds[2], kinds[3], kinds[4], n_err[FBR_E_HEAD], n_err[FBR_E_STATUS], n_err[FBR_E_CL],
         n_err[FBR_E_TE10], n_err[FBR_E_FOLD]);
  if (fails) {
    printf("FAILED: %d\n", fails);
    return 1;
  }
  printf("RESPONSE HEADS OK (every prefix of each identical to pico)\n");
  return 0;
}

int main(int argc, char **argv) {
  const char *dir = argc > 1 ? argv[1] : "tests/responses/corpus";
  char path[512];
  snprintf(path, sizeof path, "%s/responses.dat", dir);
  FILE *dat = fopen(path, "rb");
  snprintf(path, sizeof path, "%s/index.tsv", dir);
  FILE *idx = fopen(path, "r");
  if (dat && !idx) return heads_only(dat);
  if (!dat || !idx) {
    fprintf(stderr, "%s: no responses.dat / index.tsv\n", dir);
    return 2;
  }
  char line[1024];
  long recs = 0;
  while (fgets(line, sizeof line, idx)) {
    char server[64], cas[64], reqlist[512];
    int len;
    if (sscanf(line, "%63[^\t]\t%63[^\t]\t%511[^\t]\t%d", server, cas, reqlist, &len) != 4) continue;
    unsigned char lb[4];
    if (fread(lb, 1, 4, dat) != 4) break;
    int n = lb[0] | lb[1] << 8 | lb[2] << 16 | lb[3] << 24;
    if (n != len) {
      fprintf(stderr, "index and data disagree at record %ld\n", recs);
      return 2;
    }
    char *rec = malloc(n);
    if (fread(rec, 1, n, dat) != (size_t)n) return 2;
    walk(rec, n, server, cas, reqlist);
    free(rec);
    recs++;
  }
  printf("%-20s %5s %5s", "server", "conns", "resp");
  for (int k = 0; k < K_N; k++) printf(" %8s", KN[k]);
  printf("\n");
  for (int i = 0; i < nsv; i++) {
    printf("%-20s %5ld %5ld", SV[i].name, SV[i].conns, SV[i].resp);
    for (int k = 0; k < K_N; k++) printf(" %8ld", SV[i].k[k]);
    printf("\n");
  }
  printf("%ld connections, %ld heads (every prefix of each checked against pico)\n", recs, heads_checked);
  if (fails) {
    printf("FAILED: %d\n", fails);
    return 1;
  }
  printf("RESPONSE CORPUS OK\n");
  return 0;
}
