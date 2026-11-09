// fixtures.c - inputs and timed loops of the CodSpeed benchmarks (see fixtures.h). Built by
// bench/codspeed/CMakeLists.txt with -O3 and the Makefile's -march, so the parsers get their native backend.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "fastparse.h"
#include "fbparse.h"
#include "batchparse.h"
#include "hpack.h"
#include "picohttpparser.h"
#include "testlib.h"
#include "shapes.h"
#include "h2_headers.h"
#include "fixtures.h"

struct cb_corpus {
  int n;
  long bytes;
  char *mem;        // n slots of 64-byte aligned requests, each followed by PAD bytes of 0x5a
  const char **ptr; // ptr[i] = start of request i
  int *len;         // len[i] = its length
  char *pipe;       // the same requests back to back (+ PAD), for fast_parse_many
  int pipe_len;
  char *out; // scratch for fb_decode_chunked
};

static int seeded;
static void seed(void) {
  // the same corpus on every run, whichever benchmark builds it first
  if (!seeded) mk_tokens(), seeded = 1;
  rs = 0x9E3779B97F4A7C15ull;
}

typedef int (*gen_fn)(char *, int);
static int gen_chunked_body(char *b, int chunks, int size, int ext) {
  int n = 0;
  for (int c = 0; c < chunks; c++) {
    n += sprintf(b + n, ext ? "%x;name=value\r\n" : "%x\r\n", size);
    for (int i = 0; i < size; i++) b[n++] = (char)('a' + (i + c) % 26);
    n += sprintf(b + n, "\r\n");
  }
  return n + sprintf(b + n, "0\r\n\r\n");
}

static cb_corpus *build_seeded(int n, gen_fn g, int shape, int chunks, int size, int ext);
static cb_corpus *build(int n, gen_fn g, int shape, int chunks, int size, int ext) {
  seed();
  return build_seeded(n, g, shape, chunks, size, ext);
}
static cb_corpus *build_seeded(int n, gen_fn g, int shape, int chunks, int size, int ext) {
  enum { MAXREQ = 1 << 16 };
  cb_corpus *c = calloc(1, sizeof *c);
  char *tmp = malloc(MAXREQ);
  c->n = n;
  c->ptr = malloc(n * sizeof *c->ptr);
  c->len = malloc(n * sizeof *c->len);
  long cap = 0, o = 0;
  int *lens = malloc(n * sizeof *lens);
  char **reqs = malloc(n * sizeof *reqs);
  for (int i = 0; i < n; i++) {
    int l = g ? g(tmp, shape) : gen_chunked_body(tmp, chunks, size, ext);
    reqs[i] = malloc(l);
    memcpy(reqs[i], tmp, l);
    lens[i] = l;
    cap += (l + PAD + 63) & ~63;
    c->bytes += l;
  }
  if (posix_memalign((void **)&c->mem, 64, cap)) abort();
  c->pipe = malloc(c->bytes + PAD);
  for (int i = 0; i < n; i++) {
    memcpy(c->mem + o, reqs[i], lens[i]);
    memset(c->mem + o + lens[i], 0x5a, PAD);
    c->ptr[i] = c->mem + o;
    c->len[i] = lens[i];
    memcpy(c->pipe + c->pipe_len, reqs[i], lens[i]);
    c->pipe_len += lens[i];
    o += (lens[i] + PAD + 63) & ~63;
    free(reqs[i]);
  }
  memset(c->pipe + c->pipe_len, 0x5a, PAD);
  c->out = malloc(MAXREQ);
  free(reqs);
  free(lens);
  free(tmp);
  return c;
}

cb_corpus *cb_corpus_fast(int shape, int n) { return build(n, gen, shape, 0, 0, 0); }
cb_corpus *cb_corpus_fb(int shape, int n) { return build(n, gen_fb, shape, 0, 0, 0); }
cb_corpus *cb_corpus_perf(int shape, int n) {
  rs = 0x9E3779B97F4A7C15ull; // as dump_corpus: the PRNG fresh, then the tokens, then the requests (the tokens come
  mk_tokens(), seeded = 1;    // out the same as seed()'s, which also draws them from the fresh PRNG)
  return build_seeded(n, gen, shape, 0, 0, 0);
}
cb_corpus *cb_corpus_chunked(int chunks, int size, int ext, int n) { return build(n, NULL, 0, chunks, size, ext); }
int cb_corpus_len(const cb_corpus *c) { return c->n; }
long cb_corpus_bytes(const cb_corpus *c) { return c->bytes; }
void cb_corpus_free(cb_corpus *c) {
  free(c->mem);
  free(c->ptr);
  free(c->len);
  free(c->pipe);
  free(c->out);
  free(c);
}

#define SUM(r, out) ((long)(r) + (out).route + (out).body_off + (out).body_len)

long cb_fast_parse(const cb_corpus *c) {
  long s = 0;
  req_t out;
  for (int i = 0; i < c->n; i++) {
    int r = fast_parse(c->ptr[i], c->len[i], &out);
    s += SUM(r, out);
  }
  return s;
}
long cb_fast_parse_scalar(const cb_corpus *c) {
  long s = 0;
  req_t out;
  for (int i = 0; i < c->n; i++) {
    int r = fast_parse_scalar(c->ptr[i], c->len[i], &out);
    s += SUM(r, out);
  }
  return s;
}
long cb_fast_parse_learn(const cb_corpus *c, void *state) {
  long s = 0;
  req_t out;
  for (int i = 0; i < c->n; i++) {
    int r = fast_parse_learn(c->ptr[i], c->len[i], &out, (fp_learn_t *)state);
    s += SUM(r, out);
  }
  return s;
}
long cb_fast_parse_tmpl(const cb_corpus *c, void *state) {
  long s = 0;
  req_t out;
  for (int i = 0; i < c->n; i++) {
    int r = fast_parse_tmpl(c->ptr[i], c->len[i], &out, (fp_tmpl_t *)state);
    s += SUM(r, out);
  }
  return s;
}
long cb_fast_parse_many(const cb_corpus *c) {
  long s = 0;
  req_t out[64];
  int used = 0;
  while (used < c->pipe_len) {
    fp_batch_t b = fast_parse_many(c->pipe + used, c->pipe_len - used, out, 64);
    s += b.n + b.status + (b.n ? out[b.n - 1].route : 0);
    if (!b.used) break; // FP_FALLBACK: not on this corpus
    used += b.used;
  }
  return s + used;
}
long cb_fb_parse_request(const cb_corpus *c) {
  long s = 0;
  for (int i = 0; i < c->n; i++) {
    const char *m, *p;
    size_t ml, pl, nh = 64;
    int minor;
    struct fb_header h[64];
    int r = fb_parse_request(c->ptr[i], c->len[i], &m, &ml, &p, &pl, &minor, h, &nh, 0);
    s += r + (long)nh + (long)pl + (nh ? (long)h[nh - 1].value_len : 0);
  }
  return s;
}
long cb_fb_parse_request_scalar(const cb_corpus *c) {
  long s = 0;
  for (int i = 0; i < c->n; i++) {
    const char *m, *p;
    size_t ml, pl, nh = 64;
    int minor;
    struct fb_header h[64];
    int r = fb_parse_request_scalar(c->ptr[i], c->len[i], &m, &ml, &p, &pl, &minor, h, &nh, 0);
    s += r + (long)nh + (long)pl + (nh ? (long)h[nh - 1].value_len : 0);
  }
  return s;
}
long cb_fb_parse_req(const cb_corpus *c) {
  long s = 0;
  req_t out;
  for (int i = 0; i < c->n; i++) {
    int r = fb_parse_req(c->ptr[i], c->len[i], &out);
    s += SUM(r, out);
  }
  return s;
}
__attribute__((noinline)) static int fb_call(const char *b, int l, const char **m, size_t *ml, const char **p,
                                             size_t *pl, int *minor, struct fb_header *h, size_t *nh) {
  return fb_parse_request(b, l, m, ml, p, pl, minor, h, nh, 0);
}
__attribute__((noinline)) static int fb_call_scalar(const char *b, int l, const char **m, size_t *ml, const char **p,
                                                    size_t *pl, int *minor, struct fb_header *h, size_t *nh) {
  return fb_parse_request_scalar(b, l, m, ml, p, pl, minor, h, nh, 0);
}
__attribute__((noinline)) static int fb_req_call(const char *b, int l, req_t *out) { return fb_parse_req(b, l, out); }
long cb_fb_parse_request_call(const cb_corpus *c) {
  long s = 0;
  for (int i = 0; i < c->n; i++) {
    const char *m, *p;
    size_t ml, pl, nh = 64;
    int minor;
    struct fb_header h[64];
    int r = fb_call(c->ptr[i], c->len[i], &m, &ml, &p, &pl, &minor, h, &nh);
    s += r + (long)nh + (long)pl + (nh ? (long)h[nh - 1].value_len : 0);
  }
  return s;
}
long cb_fb_parse_request_scalar_call(const cb_corpus *c) {
  long s = 0;
  for (int i = 0; i < c->n; i++) {
    const char *m, *p;
    size_t ml, pl, nh = 64;
    int minor;
    struct fb_header h[64];
    int r = fb_call_scalar(c->ptr[i], c->len[i], &m, &ml, &p, &pl, &minor, h, &nh);
    s += r + (long)nh + (long)pl + (nh ? (long)h[nh - 1].value_len : 0);
  }
  return s;
}
long cb_fb_parse_req_call(const cb_corpus *c) {
  long s = 0;
  req_t out;
  for (int i = 0; i < c->n; i++) {
    int r = fb_req_call(c->ptr[i], c->len[i], &out);
    s += SUM(r, out);
  }
  return s;
}
long cb_server_path(const cb_corpus *c) {
  long s = 0;
  req_t out;
  for (int i = 0; i < c->n; i++) {
    int r = fast_parse(c->ptr[i], c->len[i], &out);
    if (r == FP_FALLBACK) r = fb_parse_req(c->ptr[i], c->len[i], &out);
    s += SUM(r, out);
  }
  return s;
}
long cb_bp_parse(const cb_corpus *c, int batch) {
  long s = 0;
  req_t out[64];
  int ret[64];
  for (int i = 0; i + batch <= c->n; i += batch) {
    bp_parse(batch, c->ptr + i, c->len + i, out, ret);
    s += ret[0] + out[batch - 1].route + out[batch - 1].body_off;
  }
  return s;
}
long cb_fb_decode_chunked(const cb_corpus *c) {
  long s = 0;
  for (int i = 0; i < c->n; i++) {
    int bl = 0;
    s += fb_decode_chunked(c->ptr[i], c->len[i], c->out, 1 << 16, &bl) + bl;
  }
  return s;
}

void *cb_learn_new(void) { return calloc(1, sizeof(fp_learn_t)); }
void *cb_tmpl_new(void) { return calloc(1, sizeof(fp_tmpl_t)); }
void cb_state_free(void *state) { free(state); }

// ---------------- HPACK ----------------
typedef struct {
  uint8_t *p;
  size_t n;
} cb_blk;
struct cb_hpack {
  int n, nv;
  cb_blk *blk;  // one encoded header block per request
  cb_blk *huff; // Huffman-coded header values
  size_t *hlen; // their decoded lengths
  hp_dec *dec;
  hp_field *fields;
  uint8_t *arena, *scratch;
};
enum { CB_ARENA = 1 << 17, CB_MAXF = 64 };

cb_hpack *cb_hpack_new(int set, int n) {
  cb_hpack *h = calloc(1, sizeof *h);
  h->n = n;
  h->blk = calloc(n, sizeof *h->blk);
  h->huff = calloc((size_t)n * 24, sizeof *h->huff);
  h->hlen = calloc((size_t)n * 24, sizeof *h->hlen);
  hs_set base;
  hs_init(&base, set);
  for (int i = 0; i < n; i++) {
    hs_set s = base;
    hs_fill(&s, (unsigned long)i);
    size_t cap = 0;
    for (int k = 0; k < s.n; k++) cap += hp_enc_bound(strlen(s.f[k].name), strlen(s.f[k].value));
    uint8_t *p = malloc(cap);
    size_t o = 0;
    for (int k = 0; k < s.n; k++) {
      const char *nm = s.f[k].name, *v = s.f[k].value;
      o += hp_enc_field(p + o, (const uint8_t *)nm, strlen(nm), (const uint8_t *)v, strlen(v), 0);
      size_t vl = strlen(v);
      if (!vl) continue;
      cb_blk *hb = &h->huff[h->nv];
      hb->p = malloc(hh_encode_len((const uint8_t *)v, vl) + 8);
      hb->n = hh_encode(hb->p, (const uint8_t *)v, vl);
      h->hlen[h->nv++] = vl;
    }
    h->blk[i].p = p;
    h->blk[i].n = o;
  }
  h->dec = malloc(sizeof *h->dec);
  h->fields = malloc(CB_MAXF * sizeof *h->fields);
  h->arena = malloc(CB_ARENA);
  h->scratch = malloc(4096);
  return h;
}
long cb_hpack_decode(cb_hpack *h) {
  long s = 0;
  hp_dec_init(h->dec, 4096);
  for (int i = 0; i < h->n; i++) {
    int fl, n = hp_decode_block(h->dec, h->blk[i].p, h->blk[i].n, h->fields, CB_MAXF, h->arena, CB_ARENA, 1 << 20, &fl);
    if (n <= 0) abort();
    s += n + h->fields[n - 1].vlen;
  }
  return s;
}
long cb_huffman_decode(cb_hpack *h) {
  long s = 0;
  for (int i = 0; i < h->nv; i++) {
    ssize_t r = hh_decode(h->scratch, h->huff[i].p, h->huff[i].n);
    if (r != (ssize_t)h->hlen[i]) abort();
    s += r + h->scratch[0];
  }
  return s;
}
void cb_hpack_free(cb_hpack *h) {
  for (int i = 0; i < h->n; i++) free(h->blk[i].p);
  for (int i = 0; i < h->nv; i++) free(h->huff[i].p);
  free(h->blk);
  free(h->huff);
  free(h->hlen);
  free(h->dec);
  free(h->fields);
  free(h->arena);
  free(h->scratch);
  free(h);
}

const char *cb_backend_name(void) { return FP_BACKEND_NAME; }
