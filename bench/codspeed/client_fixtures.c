// client_fixtures.c - the HTTP/2 and HTTP/3 client benchmarks of bench/codspeed: one client connection's work for
// 256 requests of a bench/h2_headers.h set, against server bytes recorded once from this repo's own server
// (responses of bench/h2_client_inputs.h). Built with H2_MAX_STREAMS=1000, so the HTTP/2 server's SETTINGS let all
// 256 go out at once; the HTTP/3 client keeps 64 open, as the recording did, opening each request stream just
// before its first response bytes.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "h2.h"
#include "h3.h"
#include "h2_headers.h"
#include "h2_client_inputs.h"
#include "fixtures.h"

enum { CR = 256 };
typedef struct {
  uint8_t *p;
  size_t n, cap;
} cb_bytes;
static void cb_put(cb_bytes *b, const uint8_t *d, size_t n) {
  if (b->n + n > b->cap) b->cap = (b->n + n) * 2 + 4096, b->p = realloc(b->p, b->cap);
  memcpy(b->p + b->n, d, n), b->n += n;
}
typedef struct {
  hs_set hs[CR];
  h_request rq[CR];
  hp_field rqf[CR][24];
  rs_set rs[CR];
} cb_inputs;
static void cb_inputs_build(cb_inputs *in, int set) {
  hs_set b;
  hs_init(&b, set);
  for (int i = 0; i < CR; i++) {
    in->hs[i] = b, hs_fill(&in->hs[i], (unsigned long)i);
    rq_build(&in->hs[i], &in->rq[i], in->rqf[i]);
    rs_build(&in->rs[i], set, i);
  }
}
typedef struct {
  long done, body, fields;
} cb_count;

// ---------------- HTTP/2 ----------------
struct cb_h2c {
  cb_inputs in;
  cb_bytes srv; // the server's bytes; its first frames (SETTINGS, WINDOW_UPDATE) are fed before the requests
  size_t first;
  h2_conn c, s;
  h2_scratch sc;
  uint8_t buf[1 << 17], out[1 << 16];
  cb_count n;
  hp_enc enc;
  uint8_t blk[1 << 16];
};
static int h2s_req(h2_conn *c, uint32_t sid, const h2_request *rq, int end, void *u) {
  (void)rq;
  cb_h2c *x = (cb_h2c *)u;
  const rs_set *r = &x->in.rs[(sid - 1) / 2];
  hp_field f[16];
  int n = rs_fields(r, 0, f);
  (void)end; /* GETs: answered at once */
  if (h2_respond(c, sid, 200, f, n, (const uint8_t *)CI_BODY, 13, !r->nt) < 0) return 1;
  return r->nt && h2_trailers(c, sid, f, rs_fields(r, 1, f)) < 0;
}
static int h2c_resp(h2_conn *c, uint32_t sid, const h2_response *rs, int end, void *u) {
  (void)c, (void)sid, (void)end;
  cb_count *k = &((cb_h2c *)u)->n;
  k->fields += rs->nfields + 1;
  return 0;
}
static int h2c_data(h2_conn *c, uint32_t sid, const uint8_t *d, size_t n, int end, void *u) {
  (void)c, (void)sid, (void)d, (void)end;
  ((cb_h2c *)u)->n.body += (long)n;
  return 0;
}
static int h2c_tr(h2_conn *c, uint32_t sid, const hp_field *f, int n, void *u) {
  (void)c, (void)sid, (void)f;
  ((cb_h2c *)u)->n.fields += n;
  return 0;
}
static void h2c_close(h2_conn *c, uint32_t sid, uint32_t err, void *u) {
  (void)c, (void)sid;
  if (!err) ((cb_h2c *)u)->n.done++;
}
static const h2_callbacks H2C_CB = { NULL, h2c_data, h2c_tr, NULL, h2c_close, h2c_resp };
static const h2_callbacks H2S_CB = { h2s_req, NULL, NULL, NULL, NULL, NULL };
// bytes in to conn: everything it takes, its output drained to `to` (NULL: dropped)
static void h2_feed(cb_h2c *x, h2_conn *c, cb_bytes *in, cb_bytes *to) {
  size_t off = 0;
  for (;;) {
    int r = h2_recv(c, &x->sc, in->p + off, in->n - off);
    if (r < 0) abort();
    off += (size_t)r;
    size_t w;
    while ((w = h2_send(c, x->out, sizeof x->out)) > 0)
      if (to) cb_put(to, x->out, w);
    if (!r || off == in->n) break;
  }
  memmove(in->p, in->p + off, in->n - off), in->n -= off;
}
static void h2_submit_all(cb_h2c *x, cb_bytes *to) {
  for (int i = 0; i < CR; i++)
    for (int r; (r = h2_submit(&x->c, &x->in.rq[i], NULL, 0, 1)) != 2 * i + 1;) {
      size_t w = h2_send(&x->c, x->out, sizeof x->out);
      if (r != H2_E_AGAIN || !w) abort();
      if (to) cb_put(to, x->out, w);
    }
}
cb_h2c *cb_h2c_new(int set) {
  cb_h2c *x = (cb_h2c *)calloc(1, sizeof *x);
  cb_inputs_build(&x->in, set);
  cb_bytes c2s = { 0 }, s2c = { 0 };
  h2_init(&x->s, &H2S_CB, x);
  h2_init_client(&x->c, &H2C_CB, x);
  size_t w;
  while ((w = h2_send(&x->s, x->out, sizeof x->out)) > 0) cb_put(&x->srv, x->out, w), cb_put(&s2c, x->out, w);
  x->first = x->srv.n;
  h2_feed(x, &x->c, &s2c, &c2s);
  h2_submit_all(x, &c2s);
  while ((w = h2_send(&x->c, x->out, sizeof x->out)) > 0) cb_put(&c2s, x->out, w);
  for (int round = 0; round < 1000 && (c2s.n || s2c.n); round++) {
    size_t from = x->srv.n;
    cb_bytes srv_out = { 0 };
    h2_feed(x, &x->s, &c2s, &srv_out);
    if (srv_out.n) cb_put(&x->srv, srv_out.p, srv_out.n), cb_put(&s2c, srv_out.p, srv_out.n);
    free(srv_out.p);
    (void)from;
    h2_feed(x, &x->c, &s2c, &c2s);
  }
  free(c2s.p), free(s2c.p);
  memset(&x->n, 0, sizeof x->n);
  if (cb_h2c_run(x) != CR) abort(); // the gate: every response
  return x;
}
long cb_h2c_run(cb_h2c *x) {
  memset(&x->n, 0, sizeof x->n);
  h2_init_client(&x->c, &H2C_CB, x);
  cb_bytes in = { x->buf, 0, sizeof x->buf };
  memcpy(in.p, x->srv.p, x->first), in.n = x->first;
  h2_feed(x, &x->c, &in, NULL);
  h2_submit_all(x, NULL);
  size_t w;
  while ((w = h2_send(&x->c, x->out, sizeof x->out)) > 0) {}
  for (size_t off = x->first; off < x->srv.n;) { // 16 KiB reads
    size_t m = x->srv.n - off < 16384 ? x->srv.n - off : 16384;
    memcpy(in.p + in.n, x->srv.p + off, m), in.n += m, off += m;
    h2_feed(x, &x->c, &in, NULL);
  }
  if (x->n.body != 13L * CR) abort();
  return x->n.done;
}
long cb_hpack_encode(cb_h2c *x) {
  long s = 0;
  hp_enc_init(&x->enc, 4096);
  for (int i = 0; i < CR; i++) {
    const h_request *q = &x->in.rq[i];
    uint8_t *p = x->blk;
    p += hp_enc_begin(&x->enc, p);
    p += hp_enc_ifield(&x->enc, p, (const uint8_t *)":authority", 10, q->authority, q->authority_len, 0);
    p += hp_enc_ifield(&x->enc, p, (const uint8_t *)":path", 5, q->path, q->path_len, 0);
    for (int k = 0; k < q->nfields; k++)
      p += hp_enc_ifield(&x->enc, p, q->fields[k].name, q->fields[k].nlen, q->fields[k].value, q->fields[k].vlen, 0);
    s += p - x->blk;
  }
  return s;
}
void cb_h2c_free(cb_h2c *x) {
  free(x->srv.p);
  free(x);
}

// ---------------- HTTP/3 (above QUIC) ----------------
typedef struct {
  int64_t sid;
  uint8_t *p;
  size_t n;
  int fin;
} cb_chunk;
typedef struct {
  uint8_t *p;
  size_t n, cap;
  uint64_t off;
  int fin;
  int64_t gen;
} cb_sbuf;
enum { CB_NSB = 2 * CR + 8 };
struct cb_h3c {
  cb_inputs in;
  cb_chunk *log; // the server's writes, in order
  int nlog, caplog;
  h3_conn c, s;
  h3_scratch sc;
  cb_sbuf sb[2][CB_NSB]; // [side: 0 client in, 1 server in][stream]
  int64_t gen;
  uint8_t out[1 << 16];
  cb_count n;
};
static cb_sbuf *sb_of(cb_h3c *x, int side, int64_t sid) {
  size_t i = (size_t)(sid >> 2) * 2 + ((sid & 2) != 0);
  if (i >= CB_NSB) abort();
  cb_sbuf *b = &x->sb[side][i];
  if (b->gen != x->gen) b->gen = x->gen, b->n = 0, b->off = 0, b->fin = 0;
  return b;
}
static void h3_in(cb_h3c *x, h3_conn *c, int side, int64_t sid, const uint8_t *d, size_t n, int fin) {
  cb_sbuf *b = sb_of(x, side, sid);
  if (b->n + n > b->cap) b->cap = (b->n + n) * 2 + 4096, b->p = (uint8_t *)realloc(b->p, b->cap);
  memcpy(b->p + b->n, d, n), b->n += n;
  if (fin) b->fin = 1;
  while (b->n || b->fin == 1) {
    int r = h3_recv(c, &x->sc, (uint64_t)sid, b->off, b->p, b->n, b->fin == 1);
    if (r < 0) abort();
    memmove(b->p, b->p + r, b->n - (size_t)r), b->n -= (size_t)r, b->off += (uint64_t)r;
    if (b->fin == 1 && !b->n) b->fin = 2;
    if (!r) break;
  }
}
// conn's output: to the peer (side), logged when log
static void h3_out(cb_h3c *x, h3_conn *c, h3_conn *peer, int side, int log) {
  uint64_t pend[256];
  for (int np; (np = h3_pending(c, pend, 256)) > 0;) {
    int progress = 0;
    for (int i = 0; i < np; i++) {
      int fin;
      size_t w = h3_stream_send(c, pend[i], x->out, sizeof x->out, &fin);
      if (!w && !fin) continue;
      progress = 1;
      if (log) {
        if (x->nlog == x->caplog)
          x->caplog = x->caplog ? 2 * x->caplog : 4096,
          x->log = (cb_chunk *)realloc(x->log, sizeof *x->log * (size_t)x->caplog);
        cb_chunk *k = &x->log[x->nlog++];
        k->sid = (int64_t)pend[i], k->n = w, k->fin = fin, k->p = (uint8_t *)malloc(w + 1), memcpy(k->p, x->out, w);
      }
      if (peer) h3_in(x, peer, side, (int64_t)pend[i], x->out, w, fin);
    }
    if (!progress) break;
  }
}
static int h3s_req(h3_conn *c, uint64_t sid, const h_request *rq, int end, void *u) {
  (void)rq;
  cb_h3c *x = (cb_h3c *)u;
  const rs_set *r = &x->in.rs[sid / 4];
  hp_field f[16];
  int n = rs_fields(r, 0, f);
  (void)end; /* GETs: answered at once (the fin may come later) */
  if (h3_respond(c, sid, 200, f, n, (const uint8_t *)CI_BODY, 13, !r->nt) < 0) return 1;
  return r->nt && h3_trailers(c, sid, f, rs_fields(r, 1, f)) < 0;
}
static int h3c_resp(h3_conn *c, uint64_t sid, const h_response *rs, int end, void *u) {
  (void)c, (void)sid, (void)end;
  ((cb_h3c *)u)->n.fields += rs->nfields + 1;
  return 0;
}
static int h3c_data(h3_conn *c, uint64_t sid, const uint8_t *d, size_t n, int end, void *u) {
  (void)c, (void)sid, (void)d, (void)end;
  ((cb_h3c *)u)->n.body += (long)n;
  return 0;
}
static int h3c_tr(h3_conn *c, uint64_t sid, const hp_field *f, int n, void *u) {
  (void)c, (void)sid, (void)f;
  ((cb_h3c *)u)->n.fields += n;
  return 0;
}
static void h3c_close(h3_conn *c, uint64_t sid, uint64_t err, void *u) {
  (void)c, (void)sid;
  if (!err) ((cb_h3c *)u)->n.done++;
}
static const h3_callbacks H3C_CB = { NULL, h3c_data, h3c_tr, NULL, h3c_close, NULL, h3c_resp };
static const h3_callbacks H3S_CB = { h3s_req, NULL, NULL, NULL, NULL, NULL, NULL };
static void h3_submit_one(cb_h3c *x, int i, h3_conn *peer) {
  for (int r; (r = h3_submit(&x->c, 4 * (uint64_t)i, &x->in.rq[i], NULL, 0, 1));) {
    if (r != H3_E_AGAIN) abort();
    h3_out(x, &x->c, peer, 1, 0); // the spill area is full of unsent request headers
  }
}
cb_h3c *cb_h3c_new(int set) {
  cb_h3c *x = (cb_h3c *)calloc(1, sizeof *x);
  cb_inputs_build(&x->in, set);
  x->gen = 1;
  h3_init(&x->s, &H3S_CB, x, 3, 7, 11);
  h3_init_client(&x->c, &H3C_CB, x, 2, 6, 10);
  int sent = 0;
  for (int guard = 0; x->n.done < CR && guard < 100000; guard++) {
    while (sent < CR && sent - x->n.done < 64) h3_submit_one(x, sent++, &x->s);
    h3_out(x, &x->c, &x->s, 1, 0);
    h3_out(x, &x->s, &x->c, 0, 1);
  }
  if (x->n.done != CR) abort();
  if (cb_h3c_run(x) != CR) abort(); // the gate: every response, replayed
  return x;
}
long cb_h3c_run(cb_h3c *x) {
  memset(&x->n, 0, sizeof x->n);
  x->gen++;
  h3_init_client(&x->c, &H3C_CB, x, 2, 6, 10);
  int opened = 0;
  for (int i = 0; i < x->nlog; i++) {
    const cb_chunk *k = &x->log[i];
    if ((k->sid & 3) == 0 && k->sid / 4 >= opened) {
      for (; opened <= k->sid / 4; opened++) h3_submit_one(x, opened, NULL);
      h3_out(x, &x->c, NULL, 1, 0);
    }
    h3_in(x, &x->c, 0, k->sid, k->p, k->n, k->fin);
    h3_out(x, &x->c, NULL, 1, 0);
  }
  if (x->n.body != 13L * CR) abort();
  return x->n.done;
}
void cb_h3c_free(cb_h3c *x) {
  for (int i = 0; i < x->nlog; i++) free(x->log[i].p);
  for (int s = 0; s < 2; s++)
    for (int i = 0; i < CB_NSB; i++) free(x->sb[s][i].p);
  free(x->log);
  free(x);
}
