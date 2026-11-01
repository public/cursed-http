/* bench_h2h3: this repo's HTTP/2 / HPACK / QPACK against nghttp2 / nghttp3, in memory. Built with
 * -DRIVALS (make bench-h2h3-rivals) it also times LiteSpeed's ls-hpack / ls-qpack and h2o's HPACK /
 * QPACK decoders, and `--dump DIR` writes the same inputs for the Go and Rust harnesses
 * (bench/go-h2h3, bench/rust-h2). Every decoder's output is checked field by field against the
 * request it encodes before it is timed.
 *   1. HPACK decode per request (warm table, one connection's worth of requests)
 *   2. HTTP/2 server CPU per request: the same nghttp2 client bytes into h2.h and into an nghttp2
 *      server session; both answer 200 + 13-byte body; only the server's work is timed
 *   3. QPACK decode per request, static-only (what a client sees when the server advertises no
 *      table) and with nghttp3's encoder using a 4096-byte dynamic table
 *   4. HTTP/3 server CPU per request above QUIC: an nghttp3 client's stream bytes (its QPACK
 *      encoder with a 4096-byte dynamic table) replayed into h3.h and into an nghttp3 server; both
 *      answer 200 + 13-byte body; only the server's work is timed
 * ns per request, best of PASSES. Header sets: bench/h2_headers.h (browser, gRPC, h2load).
 *   ./bench_h2h3 [passes] */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "h2.h"
#include "qpack.h"
#include "h3.h"
#include "h2_headers.h"
#include <nghttp2/nghttp2.h>
#include <nghttp3/nghttp3.h>
#ifdef RIVALS
#include "lshpack.h"
#include "lsqpack.h"
#include "h2o.h"
#include "h2o/hpack.h"
#include "h2o/qpack.h"
#endif

#define R 256
static int PASSES = 100;
static volatile long sink;
static double now_ns(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return t.tv_sec * 1e9 + t.tv_nsec;
}

/* ------------------------------------------- inputs ------------------------------------------- */
static hs_set SETS[3][R];
static void build_sets(void) {
  for (int s = 0; s < 3; s++) {
    hs_set b;
    hs_init(&b, s);
    for (int i = 0; i < R; i++) SETS[s][i] = b, hs_fill(&SETS[s][i], (unsigned long)i);
  }
}
static int nv2(const hs_set *h, nghttp2_nv *nv) {
  for (int k = 0; k < h->n; k++)
    nv[k] = (nghttp2_nv){ (uint8_t *)h->f[k].name, (uint8_t *)h->f[k].value, strlen(h->f[k].name),
                          strlen(h->f[k].value), 0 };
  return h->n;
}

/* the correctness gate: on its first pass every decoder reports each field it decoded */
static const char *GATE_WHO;
static long GATE_BAD;
static void gate(int s, int i, int k, const void *n, size_t nl, const void *v, size_t vl) {
  const hs_set *h = &SETS[s][i];
  if (k < h->n && strlen(h->f[k].name) == nl && !memcmp(h->f[k].name, n, nl) && strlen(h->f[k].value) == vl &&
      !memcmp(h->f[k].value, v, vl))
    return;
  if (GATE_BAD++ < 5)
    fprintf(stderr, "%s: set %d request %d field %d: got %.*s: %.*s\n", GATE_WHO, s, i, k, (int)nl, (const char *)n,
            (int)vl, (const char *)v);
}
static void gate_n(int s, int i, int k) {
  if (k != SETS[s][i].n && GATE_BAD++ < 5)
    fprintf(stderr, "%s: set %d request %d: %d fields, want %d\n", GATE_WHO, s, i, k, SETS[s][i].n);
}

/* ----------------------------------------- 1. HPACK ----------------------------------------- */
typedef struct {
  uint8_t *p;
  size_t n;
} blk;
static blk HB[3][R];
static void build_hpack(void) {
  for (int s = 0; s < 3; s++) {
    nghttp2_hd_deflater *d;
    nghttp2_hd_deflate_new(&d, 4096);
    for (int i = 0; i < R; i++) {
      nghttp2_nv nv[24];
      int n = nv2(&SETS[s][i], nv);
      size_t bound = nghttp2_hd_deflate_bound(d, nv, (size_t)n);
      HB[s][i].p = malloc(bound);
      HB[s][i].n = (size_t)nghttp2_hd_deflate_hd(d, HB[s][i].p, bound, nv, (size_t)n);
    }
    nghttp2_hd_deflate_del(d);
  }
}
static double hpack_n2(int s) {
  double best = 1e18;
  GATE_WHO = "nghttp2 HPACK";
  for (int p = 0; p < PASSES; p++) {
    double t0 = now_ns();
    nghttp2_hd_inflater *inf;
    nghttp2_hd_inflate_new(&inf);
    for (int i = 0; i < R; i++) {
      const uint8_t *in = HB[s][i].p;
      size_t n = HB[s][i].n;
      int k = 0;
      for (;;) {
        nghttp2_nv nv;
        int fl = 0;
        nghttp2_ssize r = nghttp2_hd_inflate_hd3(inf, &nv, &fl, in, n, 1);
        if (r < 0) exit(1);
        in += r, n -= (size_t)r;
        if (fl & NGHTTP2_HD_INFLATE_EMIT) {
          sink += (long)nv.valuelen;
          if (!p) gate(s, i, k++, nv.name, nv.namelen, nv.value, nv.valuelen);
        }
        if (fl & NGHTTP2_HD_INFLATE_FINAL) {
          nghttp2_hd_inflate_end_headers(inf);
          break;
        }
        if (!n && !(fl & NGHTTP2_HD_INFLATE_EMIT)) break;
      }
      if (!p) gate_n(s, i, k);
    }
    nghttp2_hd_inflate_del(inf);
    double t = (now_ns() - t0) / R;
    if (t < best) best = t;
  }
  return best;
}
static hp_dec HD;
static uint8_t ARENA[1 << 17];
static hp_field F[256];
static double hpack_ours(int s) {
  double best = 1e18;
  GATE_WHO = "hpack.h";
  for (int p = 0; p < PASSES; p++) {
    double t0 = now_ns();
    hp_dec_init(&HD, 4096);
    for (int i = 0; i < R; i++) {
      int fl, n = hp_decode_block(&HD, HB[s][i].p, HB[s][i].n, F, 256, ARENA, sizeof ARENA, 1 << 20, &fl);
      if (n < 0) exit(2);
      sink += F[n - 1].vlen;
      if (!p) {
        for (int k = 0; k < n; k++) gate(s, i, k, F[k].name, F[k].nlen, F[k].value, F[k].vlen);
        gate_n(s, i, n);
      }
    }
    double t = (now_ns() - t0) / R;
    if (t < best) best = t;
  }
  return best;
}

#ifdef RIVALS
/* LiteSpeed ls-hpack: each field decoded into a caller buffer (no validation of the bytes) */
static char XBUF[1 << 16];
static double hpack_ls(int s) {
  double best = 1e18;
  GATE_WHO = "ls-hpack";
  for (int p = 0; p < PASSES; p++) {
    double t0 = now_ns();
    struct lshpack_dec d;
    lshpack_dec_init(&d);
    for (int i = 0; i < R; i++) {
      const unsigned char *in = HB[s][i].p, *end = in + HB[s][i].n;
      int k = 0;
      while (in < end) {
        lsxpack_header_t x;
        lsxpack_header_prepare_decode(&x, XBUF, 0, sizeof XBUF);
        if (lshpack_dec_decode(&d, &in, end, &x) != LSHPACK_OK) exit(10);
        sink += x.val_len;
        if (!p) gate(s, i, k, XBUF + x.name_offset, x.name_len, XBUF + x.val_offset, x.val_len);
        k++;
      }
      if (!p) gate_n(s, i, k);
    }
    lshpack_dec_cleanup(&d);
    double t = (now_ns() - t0) / R;
    if (t < best) best = t;
  }
  return best;
}
/* h2o: h2o_hpack_decode_header, the per-field decoder its request parser calls (it validates the
 * bytes), strings in a memory pool cleared per request as h2o does per stream */
static double hpack_h2o(int s) {
  double best = 1e18;
  GATE_WHO = "h2o HPACK";
  h2o_mem_pool_t pool;
  h2o_mem_init_pool(&pool);
  for (int p = 0; p < PASSES; p++) {
    double t0 = now_ns();
    h2o_hpack_header_table_t tbl;
    memset(&tbl, 0, sizeof tbl);
    tbl.hpack_capacity = tbl.hpack_max_capacity = 4096;
    for (int i = 0; i < R; i++) {
      const uint8_t *in = HB[s][i].p, *end = in + HB[s][i].n;
      int k = 0;
      while (in < end) {
        h2o_iovec_t *name, value;
        const char *err = NULL;
        int r = h2o_hpack_decode_header(&pool, &tbl, &name, &value, &in, end, &err);
        if (r != 0 && r != H2O_HTTP2_ERROR_INVALID_HEADER_CHAR) exit(11);
        sink += (long)value.len;
        if (!p) gate(s, i, k, name->base, name->len, value.base, value.len);
        k++;
      }
      if (!p) gate_n(s, i, k);
      h2o_mem_clear_pool(&pool);
    }
    h2o_hpack_dispose_header_table(&tbl);
    double t = (now_ns() - t0) / R;
    if (t < best) best = t;
  }
  return best;
}
#endif

/* ------------------------------------- 2. HTTP/2 server ------------------------------------- */
typedef struct {
  uint8_t *p;
  size_t n, cap;
} bytes;
static void put(bytes *b, const uint8_t *d, size_t n) {
  if (b->n + n > b->cap) b->cap = (b->n + n) * 2 + 4096, b->p = realloc(b->p, b->cap);
  memcpy(b->p + b->n, d, n), b->n += n;
}
/* the client byte stream for one connection: preface + SETTINGS + nreq requests, each answered by
 * a recorded server reply (so the client's state, e.g. WINDOW_UPDATE, is realistic) */
static bytes CLI[3];
static const char BODY[] = "hello, world\n";
static int n2s_frame(nghttp2_session *s, const nghttp2_frame *f, void *u) {
  (void)u;
  if (f->hd.type == NGHTTP2_HEADERS && (f->hd.flags & NGHTTP2_FLAG_END_STREAM)) {
    nghttp2_nv nv[] = { { (uint8_t *)":status", (uint8_t *)"200", 7, 3, 0 },
                        { (uint8_t *)"content-type", (uint8_t *)"text/plain", 12, 10, 0 } };
    nghttp2_submit_response2(s, f->hd.stream_id, nv, 2, NULL);
  }
  return 0;
}
static void record_client(int s) {
  nghttp2_session_callbacks *cb;
  nghttp2_session *cli;
  nghttp2_session_callbacks_new(&cb);
  nghttp2_session_client_new(&cli, cb, NULL);
  nghttp2_session_callbacks_del(cb);
  nghttp2_submit_settings(cli, NGHTTP2_FLAG_NONE, NULL, 0);
  /* the server's SETTINGS (MAX_CONCURRENT_STREAMS 1000), so all R requests go out at once */
  static const uint8_t srv_settings[] = { 0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0x03, 0xe8 };
  nghttp2_session_mem_recv2(cli, srv_settings, sizeof srv_settings);
  for (int i = 0; i < R; i++) {
    nghttp2_nv nv[24];
    int n = nv2(&SETS[s][i], nv);
    nghttp2_submit_request2(cli, NULL, nv, (size_t)n, NULL, NULL);
  }
  const uint8_t *d;
  nghttp2_ssize n;
  while ((n = nghttp2_session_mem_send2(cli, &d)) > 0) put(&CLI[s], d, (size_t)n);
  nghttp2_session_del(cli);
}
/* nghttp2 as the server */
static nghttp2_ssize n2_body(nghttp2_session *s, int32_t id, uint8_t *buf, size_t len, uint32_t *fl,
                             nghttp2_data_source *src, void *u) {
  (void)s, (void)id, (void)len, (void)src, (void)u;
  memcpy(buf, BODY, 13);
  *fl |= NGHTTP2_DATA_FLAG_EOF;
  return 13;
}
static int n2_on_frame(nghttp2_session *s, const nghttp2_frame *f, void *u) {
  (void)u;
  if (f->hd.type == NGHTTP2_HEADERS && (f->hd.flags & NGHTTP2_FLAG_END_STREAM)) {
    nghttp2_nv nv[] = { { (uint8_t *)":status", (uint8_t *)"200", 7, 3, 0 },
                        { (uint8_t *)"content-type", (uint8_t *)"text/plain", 12, 10, 0 } };
    nghttp2_data_provider2 dp = { { 0 }, n2_body };
    nghttp2_submit_response2(s, f->hd.stream_id, nv, 2, &dp);
  }
  return 0;
}
static int n2_on_header(nghttp2_session *s, const nghttp2_frame *f, nghttp2_rcbuf *n, nghttp2_rcbuf *v, uint8_t fl,
                        void *u) {
  (void)s, (void)f, (void)n, (void)v, (void)fl, (void)u;
  return 0; /* a server reads its headers: the callback costs what a real one does */
}
static double h2_n2(int s) {
  double best = 1e18;
  static uint8_t sinkbuf[1 << 16];
  for (int p = 0; p < PASSES / 4 + 1; p++) {
    nghttp2_session_callbacks *cb;
    nghttp2_session *srv;
    nghttp2_session_callbacks_new(&cb);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cb, n2_on_frame);
    nghttp2_session_callbacks_set_on_header_callback2(cb, n2_on_header);
    double t0 = now_ns();
    nghttp2_session_server_new(&srv, cb, NULL);
    nghttp2_settings_entry st[] = { { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 1000 } };
    nghttp2_submit_settings(srv, NGHTTP2_FLAG_NONE, st, 1);
    /* in 16 KiB reads, draining output after each, as a server would */
    for (size_t off = 0; off < CLI[s].n;) {
      size_t m = CLI[s].n - off < 16384 ? CLI[s].n - off : 16384;
      if (nghttp2_session_mem_recv2(srv, CLI[s].p + off, m) < 0) exit(3);
      off += m;
      const uint8_t *d;
      nghttp2_ssize n;
      while ((n = nghttp2_session_mem_send2(srv, &d)) > 0)
        memcpy(sinkbuf, d, (size_t)n < sizeof sinkbuf ? (size_t)n : sizeof sinkbuf);
    }
    nghttp2_session_del(srv);
    double t = (now_ns() - t0) / R;
    nghttp2_session_callbacks_del(cb);
    if (t < best) best = t;
  }
  return best;
}
/* h2.h as the server */
static long OUR_DONE;
static int o_req(h2_conn *c, uint32_t sid, const h2_request *rq, int end, void *u) {
  (void)rq, (void)u;
  static const hp_field ct = { (const uint8_t *)"content-type", (const uint8_t *)"text/plain", 12, 10, 0, 0, 0, 0 };
  OUR_DONE++;
  return end ? h2_respond(c, sid, 200, &ct, 1, (const uint8_t *)BODY, 13, 1) < 0 : 0;
}
static const h2_callbacks OCB = { o_req, NULL, NULL, NULL, NULL };
static h2_conn OC;
static h2_scratch OSC;
static double h2_ours(int s) {
  double best = 1e18;
  static uint8_t out[1 << 16], in[1 << 16];
  for (int p = 0; p < PASSES / 4 + 1; p++) {
    OUR_DONE = 0;
    double t0 = now_ns();
    h2_init(&OC, &OCB, NULL);
    size_t have = 0;
    for (size_t off = 0; off < CLI[s].n || have;) {
      size_t m = CLI[s].n - off < 16384 ? CLI[s].n - off : 16384;
      memcpy(in + have, CLI[s].p + off, m), have += m, off += m;
      for (;;) {
        int r = h2_recv(&OC, &OSC, in, have);
        if (r < 0) exit(4);
        size_t w;
        while ((w = h2_send(&OC, out, sizeof out)) > 0) sink += out[0];
        memmove(in, in + r, have - (size_t)r), have -= (size_t)r;
        if (!r || !have) break;
      }
      if (off == CLI[s].n && have) break;
    }
    double t = (now_ns() - t0) / R;
    if (OUR_DONE != R) {
      printf("h2.h answered %ld of %d\n", OUR_DONE, R);
      exit(5);
    }
    if (t < best) best = t;
  }
  return best;
}

/* ------------------------------------------ 3. QPACK ------------------------------------------ */
static blk QB[2][3][R]; /* [dynamic?][set][request]: field sections */
static blk QE[3][R];    /* encoder stream bytes produced with each section (dynamic case) */
static void build_qpack(void) {
  const nghttp3_mem *mem = nghttp3_mem_default();
  for (int dyn = 0; dyn < 2; dyn++)
    for (int s = 0; s < 3; s++) {
      nghttp3_qpack_encoder *e;
      nghttp3_qpack_encoder_new(&e, dyn ? 4096 : 0, mem);
      if (dyn)
        nghttp3_qpack_encoder_set_max_dtable_capacity(e, 4096), nghttp3_qpack_encoder_set_max_blocked_streams(e, 0);
      qp_dec d;
      qp_dec_init(&d, 4096);
      for (int i = 0; i < R; i++) {
        nghttp3_nv nv[24];
        hs_set *h = &SETS[s][i];
        for (int k = 0; k < h->n; k++)
          nv[k] = (nghttp3_nv){ (uint8_t *)h->f[k].name, (uint8_t *)h->f[k].value, strlen(h->f[k].name),
                                strlen(h->f[k].value), 0 };
        nghttp3_buf pb, rb, eb;
        nghttp3_buf_init(&pb), nghttp3_buf_init(&rb), nghttp3_buf_init(&eb);
        nghttp3_qpack_encoder_encode(e, &pb, &rb, &eb, 4 * i, nv, (size_t)h->n);
        size_t pl = (size_t)(pb.last - pb.pos), rl = (size_t)(rb.last - rb.pos), el = (size_t)(eb.last - eb.pos);
        QB[dyn][s][i].p = malloc(pl + rl + 1), QB[dyn][s][i].n = pl + rl;
        memcpy(QB[dyn][s][i].p, pb.pos, pl), memcpy(QB[dyn][s][i].p + pl, rb.pos, rl);
        if (dyn) {
          QE[s][i].p = malloc(el + 1), QE[s][i].n = el, memcpy(QE[s][i].p, eb.pos, el);
          /* acknowledge through our decoder so the encoder keeps referencing its table */
          qp_dec_encoder(&d, eb.pos, el);
          int fl;
          qp_decode_section(&d, (uint64_t)(4 * i), QB[dyn][s][i].p, QB[dyn][s][i].n, F, 256, ARENA, sizeof ARENA,
                            1 << 20, &fl);
          uint8_t fb[256];
          size_t fn;
          while ((fn = qp_dec_feedback(&d, fb, sizeof fb)) > 0) nghttp3_qpack_encoder_read_decoder(e, fb, fn);
        }
        nghttp3_buf_free(&pb, mem), nghttp3_buf_free(&rb, mem), nghttp3_buf_free(&eb, mem);
      }
      nghttp3_qpack_encoder_del(e);
    }
}
static double qpack_n3(int dyn, int s) {
  const nghttp3_mem *mem = nghttp3_mem_default();
  double best = 1e18;
  GATE_WHO = "nghttp3 QPACK";
  for (int p = 0; p < PASSES / 2 + 1; p++) {
    double t0 = now_ns();
    nghttp3_qpack_decoder *d;
    nghttp3_qpack_decoder_new(&d, 4096, 0, mem);
    for (int i = 0; i < R; i++) {
      if (dyn && QE[s][i].n) nghttp3_qpack_decoder_read_encoder(d, QE[s][i].p, QE[s][i].n);
      nghttp3_qpack_stream_context *sc;
      nghttp3_qpack_stream_context_new(&sc, 4 * i, mem);
      const uint8_t *in = QB[dyn][s][i].p;
      size_t n = QB[dyn][s][i].n;
      int k = 0;
      for (;;) {
        nghttp3_qpack_nv nv;
        uint8_t fl = 0;
        nghttp3_ssize r = nghttp3_qpack_decoder_read_request(d, sc, &nv, &fl, in, n, 1);
        if (r < 0) exit(6);
        in += r, n -= (size_t)r;
        if (fl & NGHTTP3_QPACK_DECODE_FLAG_EMIT) {
          sink += (long)nghttp3_rcbuf_get_buf(nv.value).len;
          if (!p) {
            nghttp3_vec a = nghttp3_rcbuf_get_buf(nv.name), b = nghttp3_rcbuf_get_buf(nv.value);
            gate(s, i, k, a.base, a.len, b.base, b.len);
          }
          k++;
          nghttp3_rcbuf_decref(nv.name), nghttp3_rcbuf_decref(nv.value);
        }
        if (fl & NGHTTP3_QPACK_DECODE_FLAG_FINAL) break;
        if (!n && !(fl & NGHTTP3_QPACK_DECODE_FLAG_EMIT)) break;
      }
      if (!p) gate_n(s, i, k);
      nghttp3_qpack_stream_context_del(sc);
    }
    nghttp3_qpack_decoder_del(d);
    double t = (now_ns() - t0) / R;
    if (t < best) best = t;
  }
  return best;
}
static qp_dec QD;
static double qpack_ours(int dyn, int s) {
  double best = 1e18;
  GATE_WHO = "qpack.h";
  uint8_t fb[512];
  for (int p = 0; p < PASSES / 2 + 1; p++) {
    double t0 = now_ns();
    qp_dec_init(&QD, 4096);
    for (int i = 0; i < R; i++) {
      if (dyn && QE[s][i].n) qp_dec_encoder(&QD, QE[s][i].p, QE[s][i].n);
      int fl, n = qp_decode_section(&QD, (uint64_t)(4 * i), QB[dyn][s][i].p, QB[dyn][s][i].n, F, 256, ARENA,
                                    sizeof ARENA, 1 << 20, &fl);
      if (n < 0) exit(7);
      while (qp_dec_feedback(&QD, fb, sizeof fb)) {}
      sink += F[n - 1].vlen;
      if (!p) {
        for (int k = 0; k < n; k++) gate(s, i, k, F[k].name, F[k].nlen, F[k].value, F[k].vlen);
        gate_n(s, i, n);
      }
    }
    double t = (now_ns() - t0) / R;
    if (t < best) best = t;
  }
  return best;
}

#ifdef RIVALS
/* LiteSpeed ls-qpack: fields decoded into a caller buffer through its header-set callbacks */
typedef struct {
  int s, i, k, chk;
  lsxpack_header_t x;
} lsq_ctx;
static struct lsxpack_header *lsq_prepare(void *u, struct lsxpack_header *x, size_t space) {
  lsq_ctx *c = u;
  (void)space;
  if (!x) x = &c->x, lsxpack_header_prepare_decode(x, XBUF, 0, sizeof XBUF);
  else x->val_len = (lsxpack_strlen_t)(sizeof XBUF - x->val_offset);
  return x;
}
static int lsq_process(void *u, struct lsxpack_header *x) {
  lsq_ctx *c = u;
  sink += x->val_len;
#ifdef LSVAL /* -DLSVAL: the same per-field checks qpack.h does (name class, RFC 9113 value rules) */
  sink += hp__nclass((const uint8_t *)x->buf + x->name_offset, x->name_len) +
          hv_check_value_rfc9113((const uint8_t *)x->buf + x->val_offset, x->val_len);
#endif
  if (c->chk) gate(c->s, c->i, c->k, x->buf + x->name_offset, x->name_len, x->buf + x->val_offset, x->val_len);
  c->k++;
  return 0;
}
static void lsq_unblocked(void *u) { (void)u; }
static const struct lsqpack_dec_hset_if LSQ_IF = { lsq_unblocked, lsq_prepare, lsq_process };
static double qpack_ls(int dyn, int s) {
  double best = 1e18;
  GATE_WHO = "ls-qpack";
  for (int p = 0; p < PASSES / 2 + 1; p++) {
    double t0 = now_ns();
    struct lsqpack_dec d;
    lsqpack_dec_init(&d, NULL, 4096, 0, &LSQ_IF, 0);
    for (int i = 0; i < R; i++) {
      if (dyn && QE[s][i].n && lsqpack_dec_enc_in(&d, QE[s][i].p, QE[s][i].n) != 0) exit(12);
      lsq_ctx c = { s, i, 0, !p, { 0 } };
      const unsigned char *in = QB[dyn][s][i].p;
      unsigned char ack[64];
      size_t acklen = sizeof ack;
      if (lsqpack_dec_header_in(&d, &c, (uint64_t)(4 * i), QB[dyn][s][i].n, &in, QB[dyn][s][i].n, ack, &acklen) !=
          LQRHS_DONE)
        exit(13);
      if (!p) gate_n(s, i, c.k);
    }
    lsqpack_dec_cleanup(&d);
    double t = (now_ns() - t0) / R;
    if (t < best) best = t;
  }
  return best;
}
/* h2o: h2o_qpack_parse_request is its only public section decoder, so it also does h2o's request
 * checks (pseudo-headers, content-length) and builds its header vector: a little more work than
 * the others' decode-only loops */
static double qpack_h2o(int dyn, int s) {
  double best = 1e18;
  GATE_WHO = "h2o QPACK";
  h2o_mem_pool_t pool;
  h2o_mem_init_pool(&pool);
  for (int p = 0; p < PASSES / 2 + 1; p++) {
    double t0 = now_ns();
    h2o_qpack_decoder_t *q = h2o_qpack_create_decoder(4096, 0);
    for (int i = 0; i < R; i++) {
      const char *err = NULL;
      if (dyn && QE[s][i].n) {
        const uint8_t *e = QE[s][i].p;
        uint64_t inserted;
        if (h2o_qpack_decoder_handle_input(q, &inserted, &e, e + QE[s][i].n, &err) != 0) exit(14);
      }
      h2o_iovec_t method = { 0 }, authority = { 0 }, path = { 0 }, protocol = { 0 }, expect = { 0 }, dfid = { 0 };
      const h2o_url_scheme_t *scheme = NULL;
      h2o_headers_t hs = { 0 };
      int pm = 0;
      size_t cl;
      uint8_t ack[64];
      size_t acklen = sizeof ack;
      uint64_t blocked_ref = 0;
      h2o_qpack_section_stats_t stats = { 0 };
      if (h2o_qpack_parse_request(&pool, q, 4 * i, &method, &scheme, &authority, &path, &protocol, &hs, &pm, &cl,
                                  &expect, &dfid, 0, &blocked_ref, &stats, ack, &acklen, QB[dyn][s][i].p,
                                  QB[dyn][s][i].n, &err) != 0)
        exit(15);
      sink += (long)path.len + (long)hs.size;
      if (!p) { /* pseudo-headers come back in their own outputs, the rest in order */
        const hs_set *h = &SETS[s][i];
        size_t r = 0;
        for (int k = 0; k < h->n; k++) {
          const char *n = h->f[k].name;
          h2o_iovec_t nm = { (char *)n, strlen(n) }, v = { NULL, 0 };
          if (!strcmp(n, ":method")) v = method;
          else if (!strcmp(n, ":authority")) v = authority;
          else if (!strcmp(n, ":path")) v = path;
          else if (!strcmp(n, ":scheme")) v = scheme->name;
          else if (r < hs.size) nm = *hs.entries[r].name, v = hs.entries[r++].value;
          gate(s, i, k, nm.base, nm.len, v.base, v.len);
        }
        if (r != hs.size) gate_n(s, i, h->n + (int)(hs.size - r));
      }
      h2o_mem_clear_pool(&pool);
    }
    h2o_qpack_destroy_decoder(q);
    double t = (now_ns() - t0) / R;
    if (t < best) best = t;
  }
  return best;
}
#endif

/* ------------------------------------- 4. HTTP/3 server ------------------------------------- */
/* the client side, recorded once against h3.h (so the client's QPACK encoder sees our decoder's
 * acknowledgements and uses its dynamic table): every chunk it writes, in order */
typedef struct {
  int64_t sid;
  uint8_t *p;
  size_t n;
  int fin;
} chunk;
static chunk *H3LOG[3];
static int H3N[3];
typedef struct {
  int64_t id;
  uint8_t *p;
  size_t n, cap;
  uint64_t off;
  int fin;
} sbuf;
static sbuf SB[600];
static int NSB;
static sbuf *sb_get(int64_t id) {
  for (int i = 0; i < NSB; i++)
    if (SB[i].id == id) return &SB[i];
  SB[NSB] = (sbuf){ id, SB[NSB].p, 0, SB[NSB].cap, 0, 0 }; /* keep the buffer across connections */
  return &SB[NSB++];
}
static void sb_put(sbuf *b, const uint8_t *d, size_t n) {
  if (b->n + n > b->cap) b->cap = (b->n + n) * 2 + 4096, b->p = realloc(b->p, b->cap);
  memcpy(b->p + b->n, d, n), b->n += n;
}
static h3_scratch H3SC;
static long H3_DONE;
static int h3o_req(h3_conn *c, uint64_t sid, const h_request *rq, int end, void *u) {
  (void)rq, (void)end, (void)u;
  static const hp_field ct = { (const uint8_t *)"content-type", (const uint8_t *)"text/plain", 12, 10, 0, 0, 0, 0 };
  return h3_respond(c, sid, 200, &ct, 1, (const uint8_t *)BODY, 13, 1) < 0;
}
static void h3o_close(h3_conn *c, uint64_t sid, uint64_t err, void *u) {
  (void)c, (void)sid, (void)u;
  if (!err) H3_DONE++;
}
static const h3_callbacks H3CB = { h3o_req, NULL, NULL, NULL, h3o_close, NULL };
/* our server: per-stream bytes in, as a transport would deliver them; returns 0 or -1 */
static int h3o_feed(h3_conn *c, sbuf *b) {
  while (b->n || b->fin == 1) {
    int r = h3_recv(c, &H3SC, (uint64_t)b->id, b->off, b->p, b->n, b->fin == 1);
    if (r < 0) return -1;
    memmove(b->p, b->p + r, b->n - (size_t)r), b->n -= (size_t)r, b->off += (uint64_t)r;
    if (b->fin == 1 && !b->n) b->fin = 2;
    if (!r) break;
  }
  return 0;
}
static size_t h3o_drain(h3_conn *c, nghttp3_conn *cli) {
  static uint8_t out[1 << 16];
  uint64_t pend[256];
  size_t tot = 0;
  for (int np; (np = h3_pending(c, pend, 256)) > 0;) {
    int progress = 0;
    for (int i = 0; i < np; i++) {
      int fin;
      size_t w = h3_stream_send(c, pend[i], out, sizeof out, &fin);
      if (!w && !fin) continue;
      progress = 1, tot += w, sink += out[0];
      if (cli && nghttp3_conn_read_stream(cli, (int64_t)pend[i], out, w, fin) < 0) exit(30);
    }
    if (!progress) break;
  }
  return tot;
}
static long REC_ENDED;
static int rec_end(nghttp3_conn *c, int64_t sid, void *u, void *su) {
  (void)c, (void)sid, (void)u, (void)su;
  REC_ENDED++;
  return 0;
}
static int rec_data(nghttp3_conn *c, int64_t sid, const uint8_t *d, size_t n, void *u, void *su) {
  (void)d, (void)u, (void)su;
  nghttp3_conn_add_ack_offset(c, sid, n);
  return 0;
}
static void record_h3(int s) {
  static h3_conn S;
  h3_init(&S, &H3CB, NULL, 3, 7, 11);
  NSB = 0, REC_ENDED = 0;
  nghttp3_callbacks cb = { 0 };
  cb.end_stream = rec_end, cb.recv_data = rec_data;
  nghttp3_settings st;
  nghttp3_settings_default(&st);
  st.qpack_max_dtable_capacity = 4096, st.qpack_blocked_streams = 0;
  nghttp3_conn *cli;
  nghttp3_conn_client_new(&cli, &cb, &st, nghttp3_mem_default(), NULL);
  nghttp3_conn_bind_control_stream(cli, 2);
  nghttp3_conn_bind_qpack_streams(cli, 6, 10);
  int cap = 4096;
  H3LOG[s] = malloc(sizeof(chunk) * (size_t)cap);
  int sent = 0;
  for (int guard = 0; REC_ENDED < R && guard < 100000; guard++) {
    while (sent < R && sent - REC_ENDED < 64) { /* within H3_MAX_STREAMS, as a transport's MAX_STREAMS would keep it */
      nghttp3_nv nv[24];
      hs_set *h = &SETS[s][sent];
      for (int k = 0; k < h->n; k++)
        nv[k] = (nghttp3_nv){ (uint8_t *)h->f[k].name, (uint8_t *)h->f[k].value, strlen(h->f[k].name),
                              strlen(h->f[k].value), 0 };
      if (nghttp3_conn_submit_request(cli, 4 * (int64_t)sent, nv, (size_t)h->n, NULL, NULL)) exit(31);
      sent++;
    }
    for (;;) {
      int64_t sid;
      int fin;
      nghttp3_vec vec[16];
      nghttp3_ssize nv = nghttp3_conn_writev_stream(cli, &sid, &fin, vec, 16);
      if (nv < 0) exit(32);
      if (sid < 0) break;
      size_t tot = 0;
      for (int i = 0; i < nv; i++) tot += vec[i].len;
      chunk *ch = &H3LOG[s][H3N[s]++];
      if (H3N[s] == cap)
        cap *= 2, H3LOG[s] = realloc(H3LOG[s], sizeof(chunk) * (size_t)cap), ch = &H3LOG[s][H3N[s] - 1];
      ch->sid = sid, ch->fin = fin, ch->n = tot, ch->p = malloc(tot + 1);
      for (size_t i = 0, o = 0; i < (size_t)nv; o += vec[i].len, i++) memcpy(ch->p + o, vec[i].base, vec[i].len);
      sbuf *b = sb_get(sid);
      sb_put(b, ch->p, tot);
      if (fin) b->fin = 1;
      if (h3o_feed(&S, b)) exit(33);
      nghttp3_conn_add_write_offset(cli, sid, tot);
      nghttp3_conn_add_ack_offset(cli, sid, tot);
      if (!tot && !fin) break;
    }
    h3o_drain(&S, cli);
  }
  if (REC_ENDED != R) printf("h3 recording: %ld of %d answered\n", REC_ENDED, R), exit(34);
  nghttp3_conn_del(cli);
}
static double h3_ours(int s) {
  static h3_conn S;
  double best = 1e18;
  for (int p = 0; p < PASSES / 4 + 1; p++) {
    H3_DONE = 0, NSB = 0;
    double t0 = now_ns();
    h3_init(&S, &H3CB, NULL, 3, 7, 11);
    for (int i = 0; i < H3N[s]; i++) {
      chunk *ch = &H3LOG[s][i];
      sbuf *b = sb_get(ch->sid);
      sb_put(b, ch->p, ch->n);
      if (ch->fin) b->fin = 1;
      if (h3o_feed(&S, b)) exit(35);
      h3o_drain(&S, NULL);
    }
    double t = (now_ns() - t0) / R;
    if (H3_DONE != R) printf("h3.h finished %ld of %d\n", H3_DONE, R), exit(36);
    if (t < best) best = t;
  }
  return best;
}
static long N3_DONE;
static nghttp3_ssize n3_body(nghttp3_conn *c, int64_t sid, nghttp3_vec *vec, size_t veccnt, uint32_t *fl, void *u,
                             void *su) {
  (void)c, (void)sid, (void)veccnt, (void)u, (void)su;
  vec[0].base = (uint8_t *)BODY, vec[0].len = 13;
  *fl |= NGHTTP3_DATA_FLAG_EOF;
  return 1;
}
static int n3_end(nghttp3_conn *c, int64_t sid, void *u, void *su) {
  (void)u, (void)su;
  nghttp3_nv nv[] = { { (uint8_t *)":status", (uint8_t *)"200", 7, 3, 0 },
                      { (uint8_t *)"content-type", (uint8_t *)"text/plain", 12, 10, 0 } };
  nghttp3_data_reader dr = { n3_body };
  return nghttp3_conn_submit_response(c, sid, nv, 2, &dr);
}
static int n3_header(nghttp3_conn *c, int64_t sid, int32_t tok, nghttp3_rcbuf *n, nghttp3_rcbuf *v, uint8_t fl, void *u,
                     void *su) {
  (void)c, (void)sid, (void)tok, (void)n, (void)v, (void)fl, (void)u, (void)su;
  return 0; /* a server reads its headers: the callback costs what a real one does */
}
static double h3_n3(int s) {
  double best = 1e18;
  static uint8_t sinkbuf[1 << 16];
  for (int p = 0; p < PASSES / 4 + 1; p++) {
    nghttp3_callbacks cb = { 0 };
    cb.recv_header = n3_header, cb.end_stream = n3_end;
    nghttp3_settings st;
    nghttp3_settings_default(&st);
    st.qpack_max_dtable_capacity = 4096, st.qpack_blocked_streams = 0;
    N3_DONE = 0;
    double t0 = now_ns();
    nghttp3_conn *srv;
    nghttp3_conn_server_new(&srv, &cb, &st, nghttp3_mem_default(), NULL);
    nghttp3_conn_bind_control_stream(srv, 3);
    nghttp3_conn_bind_qpack_streams(srv, 7, 11);
    for (int i = 0; i < H3N[s]; i++) {
      chunk *ch = &H3LOG[s][i];
      if (nghttp3_conn_read_stream(srv, ch->sid, ch->p, ch->n, ch->fin) < 0) exit(37);
      for (;;) { /* drain, acknowledging at once, and close finished request streams as a transport would */
        int64_t sid;
        int fin;
        nghttp3_vec vec[16];
        nghttp3_ssize nv = nghttp3_conn_writev_stream(srv, &sid, &fin, vec, 16);
        if (nv < 0) exit(38);
        if (sid < 0) break;
        size_t tot = 0;
        for (int k = 0; k < nv; k++) {
          size_t m = vec[k].len < sizeof sinkbuf ? vec[k].len : sizeof sinkbuf;
          memcpy(sinkbuf, vec[k].base, m), tot += vec[k].len;
        }
        nghttp3_conn_add_write_offset(srv, sid, tot);
        nghttp3_conn_add_ack_offset(srv, sid, tot);
        if (fin && (sid & 3) == 0) nghttp3_conn_close_stream(srv, sid, 0), N3_DONE++;
        if (!tot && !fin) break;
      }
    }
    nghttp3_conn_del(srv);
    double t = (now_ns() - t0) / R;
    if (N3_DONE != R) printf("nghttp3 finished %ld of %d\n", N3_DONE, R), exit(39);
    if (t < best) best = t;
  }
  return best;
}

/* --dump DIR: the same inputs for the Go and Rust harnesses. Each file is a sequence of records,
 * each a u32 little-endian length and that many bytes */
static void wr(FILE *f, const void *p, size_t n) {
  uint32_t l = (uint32_t)n;
  fwrite(&l, 4, 1, f), fwrite(p, 1, n, f);
}
static FILE *dopen(const char *dir, const char *what, const char *set) {
  char path[512];
  snprintf(path, sizeof path, "%s/%s_%s.bin", dir, what, set);
  FILE *f = fopen(path, "wb");
  if (!f) perror(path), exit(20);
  return f;
}
static void dump(const char *dir, const char *const *L) {
  for (int s = 0; s < 3; s++) {
    FILE *f = dopen(dir, "fields", L[s]); /* per request: a record of the field count, then name, value, ... */
    for (int i = 0; i < R; i++) {
      char n[8];
      snprintf(n, sizeof n, "%d", SETS[s][i].n);
      wr(f, n, strlen(n));
      for (int k = 0; k < SETS[s][i].n; k++)
        wr(f, SETS[s][i].f[k].name, strlen(SETS[s][i].f[k].name)),
            wr(f, SETS[s][i].f[k].value, strlen(SETS[s][i].f[k].value));
    }
    fclose(f);
    f = dopen(dir, "hpack", L[s]);
    for (int i = 0; i < R; i++) wr(f, HB[s][i].p, HB[s][i].n);
    fclose(f);
    for (int dyn = 0; dyn < 2; dyn++) { /* per request: encoder-stream bytes, then the field section */
      f = dopen(dir, dyn ? "qpack_dynamic" : "qpack_static", L[s]);
      for (int i = 0; i < R; i++)
        wr(f, dyn ? QE[s][i].p : (const uint8_t *)"", dyn ? QE[s][i].n : 0), wr(f, QB[dyn][s][i].p, QB[dyn][s][i].n);
      fclose(f);
    }
    f = dopen(dir, "h2client", L[s]);
    wr(f, CLI[s].p, CLI[s].n);
    fclose(f);
  }
}

/* one result: a table row for people and an "= bench set impl ns" line for bench/chart_h2h3.py */
static void res(const char *bench, const char *set, const char *impl, double ns, double ours) {
  printf("= %s %s %s %.1f\n", bench, set, impl, ns);
  printf("  %-14s %-8s %-16s %8.1f ns  %5.2fx ours\n", bench, set, impl, ns, ns / ours);
}

int main(int argc, char **argv) {
  static const char *L[3] = { "browser", "gRPC", "h2load" };
  if (argc > 2 && !strcmp(argv[1], "--dump")) {
    build_sets(), build_hpack(), build_qpack();
    for (int s = 0; s < 3; s++) record_client(s);
    dump(argv[2], L);
    return 0;
  }
  if (argc > 1) PASSES = atoi(argv[1]);
  if (argc > 2) { /* profile one piece: ./bench_h2h3 passes h2|n2 */
    build_sets(), record_client(0);
    printf("%s: %.0f ns/request\n", argv[2], !strcmp(argv[2], "h2") ? h2_ours(0) : h2_n2(0));
    return 0;
  }
  build_sets();
  build_hpack();
  build_qpack();
  for (int s = 0; s < 3; s++) record_client(s), record_h3(s);
  printf("ns per request, best of %d passes over %d requests; hv backend %s\n\n", PASSES, R, hv_backend());
  for (int s = 0; s < 3; s++) {
    double o = hpack_ours(s);
    res("hpack", L[s], "hpack.h", o, o);
    res("hpack", L[s], "nghttp2", hpack_n2(s), o);
#ifdef RIVALS
    res("hpack", L[s], "ls-hpack", hpack_ls(s), o);
    res("hpack", L[s], "h2o", hpack_h2o(s), o);
#endif
  }
  for (int s = 0; s < 3; s++) {
    double o = h2_ours(s);
    res("h2server", L[s], "h2.h", o, o);
    res("h2server", L[s], "nghttp2", h2_n2(s), o);
  }
  for (int s = 0; s < 3; s++) {
    double o = h3_ours(s);
    res("h3server", L[s], "h3.h", o, o);
    res("h3server", L[s], "nghttp3", h3_n3(s), o);
  }
  for (int dyn = 0; dyn < 2; dyn++)
    for (int s = 0; s < 3; s++) {
      const char *b = dyn ? "qpack-dynamic" : "qpack-static";
      double o = qpack_ours(dyn, s);
      res(b, L[s], "qpack.h", o, o);
      res(b, L[s], "nghttp3", qpack_n3(dyn, s), o);
#ifdef RIVALS
      res(b, L[s], "ls-qpack", qpack_ls(dyn, s), o);
      res(b, L[s], "h2o", qpack_h2o(dyn, s), o);
#endif
    }
  if (GATE_BAD) {
    printf("GATE FAILED: %ld fields differ from the requests they encode\n", GATE_BAD);
    return 1;
  }
  printf("gate: every decoder returned every request's fields exactly\n");
  return 0;
}
