/* bench_h2h3: this repo's HTTP/2 / HPACK / QPACK against nghttp2 / nghttp3, in memory.
 *   1. HPACK decode per request (warm table, one connection's worth of requests)
 *   2. HTTP/2 server CPU per request: the same nghttp2 client bytes into h2.h and into an nghttp2
 *      server session; both answer 200 + 13-byte body; only the server's work is timed
 *   3. QPACK decode per request, static-only (what a client sees when the server advertises no
 *      table) and with nghttp3's encoder using a 4096-byte dynamic table
 * ns per request, best of PASSES. Header sets: bench/h2_headers.h (browser, gRPC, h2load).
 *   ./bench_h2h3 [passes] */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "h2.h"
#include "qpack.h"
#include "h2_headers.h"
#include <nghttp2/nghttp2.h>
#include <nghttp3/nghttp3.h>

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
  for (int p = 0; p < PASSES; p++) {
    double t0 = now_ns();
    nghttp2_hd_inflater *inf;
    nghttp2_hd_inflate_new(&inf);
    for (int i = 0; i < R; i++) {
      const uint8_t *in = HB[s][i].p;
      size_t n = HB[s][i].n;
      for (;;) {
        nghttp2_nv nv;
        int fl = 0;
        nghttp2_ssize r = nghttp2_hd_inflate_hd3(inf, &nv, &fl, in, n, 1);
        if (r < 0) exit(1);
        in += r, n -= (size_t)r;
        if (fl & NGHTTP2_HD_INFLATE_EMIT) sink += (long)nv.valuelen;
        if (fl & NGHTTP2_HD_INFLATE_FINAL) {
          nghttp2_hd_inflate_end_headers(inf);
          break;
        }
        if (!n && !(fl & NGHTTP2_HD_INFLATE_EMIT)) break;
      }
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
  for (int p = 0; p < PASSES; p++) {
    double t0 = now_ns();
    hp_dec_init(&HD, 4096);
    for (int i = 0; i < R; i++) {
      int fl, n = hp_decode_block(&HD, HB[s][i].p, HB[s][i].n, F, 256, ARENA, sizeof ARENA, 1 << 20, &fl);
      if (n < 0) exit(2);
      sink += F[n - 1].vlen;
    }
    double t = (now_ns() - t0) / R;
    if (t < best) best = t;
  }
  return best;
}

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
      for (;;) {
        nghttp3_qpack_nv nv;
        uint8_t fl = 0;
        nghttp3_ssize r = nghttp3_qpack_decoder_read_request(d, sc, &nv, &fl, in, n, 1);
        if (r < 0) exit(6);
        in += r, n -= (size_t)r;
        if (fl & NGHTTP3_QPACK_DECODE_FLAG_EMIT) {
          sink += (long)nghttp3_rcbuf_get_buf(nv.value).len;
          nghttp3_rcbuf_decref(nv.name), nghttp3_rcbuf_decref(nv.value);
        }
        if (fl & NGHTTP3_QPACK_DECODE_FLAG_FINAL) break;
        if (!n && !(fl & NGHTTP3_QPACK_DECODE_FLAG_EMIT)) break;
      }
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
    }
    double t = (now_ns() - t0) / R;
    if (t < best) best = t;
  }
  return best;
}

int main(int argc, char **argv) {
  if (argc > 1) PASSES = atoi(argv[1]);
  if (argc > 2) { /* profile one piece: ./bench_h2h3 passes h2|n2 */
    build_sets(), record_client(0);
    printf("%s: %.0f ns/request\n", argv[2], !strcmp(argv[2], "h2") ? h2_ours(0) : h2_n2(0));
    return 0;
  }
  build_sets();
  build_hpack();
  build_qpack();
  for (int s = 0; s < 3; s++) record_client(s);
  static const char *L[3] = { "browser", "gRPC", "h2load" };
  printf("ns per request, best of %d passes over %d requests; hv backend %s\n\n", PASSES, R, hv_backend());
  printf(
      "| set | HPACK decode nghttp2 | hpack.h | x | HTTP/2 server nghttp2 | h2.h | x | QPACK static nghttp3 | qpack.h | x | QPACK dynamic nghttp3 | qpack.h | x |\n");
  printf("|---|---|---|---|---|---|---|---|---|---|---|---|---|\n");
  for (int s = 0; s < 3; s++) {
    double a = hpack_n2(s), b = hpack_ours(s), c = h2_n2(s), d = h2_ours(s);
    double e = qpack_n3(0, s), f = qpack_ours(0, s), g = qpack_n3(1, s), h = qpack_ours(1, s);
    printf("| %s | %.0f | %.0f | %.2f | %.0f | %.0f | %.2f | %.0f | %.0f | %.2f | %.0f | %.0f | %.2f |\n", L[s], a, b,
           a / b, c, d, c / d, e, f, e / f, g, h, g / h);
  }
  return 0;
}
