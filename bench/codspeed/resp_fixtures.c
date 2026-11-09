// resp_fixtures.c - inputs and calls for the response-parser CodSpeed benchmarks (resp_fixtures.h)
#include <stdlib.h>
#include <string.h>
#include "fbresp.h"
#include "resp_shapes.h"
#include "resp_fixtures.h"

#define RPAD 64
struct cb_resp {
  int n;
  long bytes;
  char **b;
  int *len;
  char *out, *win; // scratch: decoded data, the streaming window
};
static cb_resp *alloc_resp(int n) {
  cb_resp *c = calloc(1, sizeof *c);
  c->n = n;
  c->b = calloc(n, sizeof *c->b);
  c->len = calloc(n, sizeof *c->len);
  return c;
}
static void put(cb_resp *c, int i, const char *s, int n) {
  c->b[i] = aligned_alloc(64, (n + RPAD + 63) / 64 * 64);
  memcpy(c->b[i], s, n);
  memset(c->b[i] + n, 0x5a, RPAD);
  c->len[i] = n;
  c->bytes += n;
}
cb_resp *cb_resp_new(int shape, int n) {
  static char s[1 << 14];
  cb_resp *c = alloc_resp(n);
  rs_seed();
  for (int i = 0; i < n; i++) put(c, i, s, rs_shape(shape, s));
  return c;
}
cb_resp *cb_resp_chunked(int chunks, int size, int n) {
  cb_resp *c = alloc_resp(n);
  int max = chunks * (size + 16) + 64;
  char *s = malloc(max);
  int big = 0;
  for (int i = 0; i < n; i++) {
    int k = 0;
    for (int j = 0; j < chunks; j++) {
      k += sprintf(s + k, "%x\r\n", size);
      for (int q = 0; q < size; q++) s[k++] = (char)('a' + (q + i + j) % 26);
      k += sprintf(s + k, "\r\n");
    }
    k += sprintf(s + k, "0\r\nServer-Timing: app;dur=%d\r\n\r\n", i);
    put(c, i, s, k);
    if (k > big) big = k;
  }
  free(s);
  c->out = malloc(big + RPAD);
  c->win = malloc(big + RPAD);
  return c;
}
int cb_resp_len(const cb_resp *c) { return c->n; }
long cb_resp_bytes(const cb_resp *c) { return c->bytes; }
void cb_resp_free(cb_resp *c) {
  for (int i = 0; i < c->n; i++) free(c->b[i]);
  free(c->b);
  free(c->len);
  free(c->out);
  free(c->win);
  free(c);
}

#define MAXH 64
__attribute__((noinline)) static int resp_call(const char *b, int l, int *mv, int *st, const char **m, size_t *ml,
                                               struct fb_header *h, size_t *nh) {
  return fb_parse_response(b, l, mv, st, m, ml, h, nh, 0);
}
__attribute__((noinline)) static int resp_call_scalar(const char *b, int l, int *mv, int *st, const char **m,
                                                      size_t *ml, struct fb_header *h, size_t *nh) {
  return fb_parse_response_scalar(b, l, mv, st, m, ml, h, nh, 0);
}
__attribute__((noinline)) static int fbr_call(const char *b, int l, fbr_resp_t *r) {
  return fbr_parse(b, l, FBR_REQ_OTHER, r, 0);
}
static long heads(const cb_resp *c, int scalar) {
  long s = 0;
  for (int i = 0; i < c->n; i++) {
    int mv, st;
    const char *m;
    size_t ml, nh = MAXH;
    struct fb_header h[MAXH];
    int r = scalar ? resp_call_scalar(c->b[i], c->len[i], &mv, &st, &m, &ml, h, &nh)
                   : resp_call(c->b[i], c->len[i], &mv, &st, &m, &ml, h, &nh);
    s += r + st + (long)nh + (nh ? (long)h[nh - 1].value_len : 0);
  }
  return s;
}
long cb_fb_parse_response_call(const cb_resp *c) { return heads(c, 0); }
long cb_fb_parse_response_scalar_call(const cb_resp *c) { return heads(c, 1); }
long cb_fbr_parse_call(const cb_resp *c) {
  long s = 0;
  for (int i = 0; i < c->n; i++) {
    struct fb_header h[MAXH];
    fbr_resp_t r = { .headers = h, .num_headers = MAXH };
    s += fbr_call(c->b[i], c->len[i], &r) + r.body + r.length + r.flags;
  }
  return s;
}
static long trailers(const char *b, int n) {
  struct fb_header t[8];
  size_t nt = 8;
  return fb_parse_headers(b, n, t, &nt, 0) + (long)nt;
}
long cb_fbr_chunked(const cb_resp *c) {
  long s = 0;
  for (int i = 0; i < c->n; i++) {
    int bl = 0, r = fbr_chunked(c->b[i], c->len[i], c->out, 1 << 30, &bl, NULL);
    s += r + bl + (r > 0 ? trailers(c->b[i] + r, c->len[i] - r) : 0);
  }
  return s;
}
long cb_fbr_chunked_stream(const cb_resp *c) {
  long s = 0;
  for (int i = 0; i < c->n; i++) {
    int have = 0, fed = 0, data = 0, r = 0;
    while (fed < c->len[i] || have) {
      int add = c->len[i] - fed < 512 ? c->len[i] - fed : 512;
      memcpy(c->win + have, c->b[i] + fed, add);
      have += add;
      fed += add;
      int bl = 0, prog[2] = { 0, 0 };
      r = fbr_chunked(c->win, have, c->out + data, 1 << 30, &bl, prog);
      if (r != 0) {
        data += bl;
        break;
      }
      data += prog[1];
      memmove(c->win, c->win + prog[0], have - prog[0]);
      have -= prog[0];
      if (!add) break;
    }
    s += r + data;
  }
  return s;
}
