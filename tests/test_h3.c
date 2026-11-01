/* include/h3.h against nghttp3's client over an emulated QUIC (reliable, in-order streams, in memory).
 *   - traffic: GETs, gRPC-style POSTs (body + trailers), large responses; the client uses its QPACK
 *     dynamic table; input to h3_recv is cut at random points (unconsumed tails kept, offsets
 *     tracked) and h3_stream_send is drained with random sizes.
 *   - hand-built bad input: the connection and stream errors RFC 9114 / RFC 9204 ask for.
 * FUZZ=N scales the counts. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "h3.h"
#include <nghttp3/nghttp3.h>

static long fails, checks;
#define CHECK(c, ...) do { checks++; if (!(c)) { if (fails++ < 25) { printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } } while (0)
static uint64_t rs = 0xda942042e4dd58b5ull;
static uint64_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }
static long scale(void) { const char *e = getenv("FUZZ"); return e ? atol(e) : 1; }

static h3_scratch SC;
static uint8_t BIG[1 << 20];

/* -------------------------------------- server application -------------------------------------- */
typedef struct { long requests, closes, close_err, resets; uint64_t last_reset; } srv_stats;
static srv_stats SS;
static int s_request(h3_conn *c, uint64_t sid, const h_request *rq, int end, void *u) {
  (void)u;
  SS.requests++;
  static const hp_field ct = {(const uint8_t *)"content-type", (const uint8_t *)"text/plain", 12, 10, 0, 0, 0, 0};
  if (rq->path_len >= 5 && !memcmp(rq->path, "/big/", 5)) return h3_respond(c, sid, 200, &ct, 1, BIG, (size_t)atoi((const char *)rq->path + 5), 1) < 0;
  if (rq->method_len == 4 && !memcmp(rq->method, "POST", 4)) return end ? h3_respond(c, sid, 200, &ct, 1, (const uint8_t *)"empty", 5, 1) < 0 : 0;
  return h3_respond(c, sid, 200, &ct, 1, (const uint8_t *)"hello, world\n", 13, 1) < 0;
}
static int s_data(h3_conn *c, uint64_t sid, const uint8_t *d, size_t n, int end, void *u) {
  (void)d, (void)n, (void)u;
  if (!end) return 0;
  h3_stream *st = h3__find(c, sid);
  if (st && (st->flags & H3_ST_RESPONDED)) return 0; /* a GET whose fin came after its HEADERS frame */
  static const hp_field ct = {(const uint8_t *)"content-type", (const uint8_t *)"application/grpc", 12, 16, 0, 0, 0, 0};
  static const hp_field tr[2] = {{(const uint8_t *)"grpc-status", (const uint8_t *)"0", 11, 1, 0, 0, 0, 0},
                                 {(const uint8_t *)"grpc-message", (const uint8_t *)"OK", 12, 2, 0, 0, 0, 0}};
  if (h3_respond(c, sid, 200, &ct, 1, (const uint8_t *)"\0\0\0\0\x05hello", 10, 0) < 0) return 1;
  return h3_trailers(c, sid, tr, 2) < 0;
}
static void s_close(h3_conn *c, uint64_t sid, uint64_t err, void *u) {
  (void)c, (void)sid, (void)u;
  SS.closes++;
  if (err) SS.close_err++;
}
static void s_reset(h3_conn *c, uint64_t sid, uint64_t code, void *u) {
  (void)c, (void)sid, (void)u;
  SS.resets++, SS.last_reset = code;
}
static const h3_callbacks SCB = {s_request, s_data, NULL, NULL, s_close, s_reset};

/* -------------------------------------- the nghttp3 client -------------------------------------- */
typedef struct { long ok, body, trailers, ended; } cli_stats;
static cli_stats CS;
static int c_header(nghttp3_conn *c, int64_t sid, int32_t tok, nghttp3_rcbuf *n, nghttp3_rcbuf *v, uint8_t fl, void *u, void *su) {
  (void)c, (void)sid, (void)tok, (void)fl, (void)u, (void)su;
  nghttp3_vec nn = nghttp3_rcbuf_get_buf(n), vv = nghttp3_rcbuf_get_buf(v);
  if (nn.len == 7 && !memcmp(nn.base, ":status", 7) && vv.len == 3 && !memcmp(vv.base, "200", 3)) CS.ok++;
  return 0;
}
static int c_trailer(nghttp3_conn *c, int64_t sid, int32_t tok, nghttp3_rcbuf *n, nghttp3_rcbuf *v, uint8_t fl, void *u, void *su) {
  (void)c, (void)sid, (void)tok, (void)v, (void)fl, (void)u, (void)su;
  nghttp3_vec nn = nghttp3_rcbuf_get_buf(n);
  if (nn.len == 11 && !memcmp(nn.base, "grpc-status", 11)) CS.trailers++;
  return 0;
}
static int c_data(nghttp3_conn *c, int64_t sid, const uint8_t *d, size_t n, void *u, void *su) {
  (void)d, (void)u, (void)su;
  CS.body += (long)n;
  nghttp3_conn_add_ack_offset(c, sid, 0);
  return 0;
}
static int c_end(nghttp3_conn *c, int64_t sid, void *u, void *su) {
  (void)c, (void)sid, (void)u, (void)su;
  CS.ended++;
  return 0;
}
static size_t UPLOAD[4096];
static nghttp3_ssize c_body(nghttp3_conn *c, int64_t sid, nghttp3_vec *vec, size_t veccnt, uint32_t *fl, void *u, void *su) {
  (void)c, (void)veccnt, (void)u, (void)su;
  static uint8_t chunk[4096];
  size_t *left = &UPLOAD[(sid / 4) % 4096], m = *left < sizeof chunk ? *left : sizeof chunk;
  memset(chunk, 'b', m);
  vec[0].base = chunk, vec[0].len = m;
  *left -= m;
  if (!*left) *fl |= NGHTTP3_DATA_FLAG_EOF;
  return 1;
}

/* emulated QUIC: per stream, bytes not yet consumed by the server */
typedef struct { int64_t id; uint8_t *p; size_t n, cap; uint64_t off; int fin; } sbuf;
static sbuf IN[512];
static int nin;
static sbuf *inbuf(int64_t id) {
  for (int i = 0; i < nin; i++)
    if (IN[i].id == id) return &IN[i];
  IN[nin] = (sbuf){id, NULL, 0, 0, 0, 0};
  return &IN[nin++];
}
static int deliver(h3_conn *s, sbuf *b) {
  for (;;) {
    size_t lim = b->n;
    int fin = b->fin;
    if (lim > 1 && rnd() % 3 == 0) lim = 1 + rnd() % lim, fin = 0;
    int r = h3_recv(s, &SC, (uint64_t)b->id, b->off, b->p, lim, fin && lim == b->n);
    if (r < 0) return r;
    memmove(b->p, b->p + r, b->n - (size_t)r), b->n -= (size_t)r, b->off += (uint64_t)r;
    if (fin && !b->n) b->fin = 2; /* fin delivered */
    if (!r && lim == b->n) return 0;
    if (!b->n) return 0;
  }
}

static void run_conn(int kind, int nreq) {
  static h3_conn S;
  h3_init(&S, &SCB, NULL, 3, 7, 11);
  nin = 0;
  memset(&SS, 0, sizeof SS), memset(&CS, 0, sizeof CS);
  nghttp3_callbacks cb = {0};
  cb.recv_header = c_header, cb.recv_trailer = c_trailer, cb.recv_data = c_data, cb.end_stream = c_end;
  nghttp3_settings st;
  nghttp3_settings_default(&st);
  st.qpack_max_dtable_capacity = 4096, st.qpack_blocked_streams = 0;
  nghttp3_conn *cli;
  nghttp3_conn_client_new(&cli, &cb, &st, nghttp3_mem_default(), NULL);
  nghttp3_conn_bind_control_stream(cli, 2);
  nghttp3_conn_bind_qpack_streams(cli, 6, 10);
  long expect_body = 0;
  int sent = 0;
  for (int guard = 0, tail = 0; guard < 100000 && tail < 3; guard++) {
    if (CS.ended >= nreq) tail++; /* a few more rounds so the server sees the last fins */
    while (sent < nreq && sent - CS.ended < 90) {
      int k = kind == 3 ? (int)(rnd() % 3) : kind;
      char path[64];
      size_t big = 1000 + rnd() % 200000;
      if (k == 2) snprintf(path, sizeof path, "/big/%zu", big), expect_body += (long)big;
      else snprintf(path, sizeof path, "/assets/%d-%llx.js", sent % 7, (unsigned long long)(rnd() % 3));
      nghttp3_nv nv[8] = {
        {(uint8_t *)":method", (uint8_t *)(k == 1 ? "POST" : "GET"), 7, k == 1 ? 4u : 3u, 0},
        {(uint8_t *)":scheme", (uint8_t *)"https", 7, 5, 0},
        {(uint8_t *)":authority", (uint8_t *)"example.com", 10, 11, 0},
        {(uint8_t *)":path", (uint8_t *)path, 5, strlen(path), 0},
        {(uint8_t *)"user-agent", (uint8_t *)"Mozilla/5.0 (test) Chrome/130", 10, 29, 0},
        {(uint8_t *)"cookie", (uint8_t *)"session=abcdef0123456789; theme=dark", 6, 36, 0},
        {(uint8_t *)"content-type", (uint8_t *)"application/grpc", 12, 16, 0},
        {(uint8_t *)"te", (uint8_t *)"trailers", 2, 8, 0}};
      int64_t sid = 4 * (int64_t)sent;
      UPLOAD[(sid / 4) % 4096] = 1 + rnd() % 20000;
      nghttp3_data_reader dr = {c_body};
      if (nghttp3_conn_submit_request(cli, sid, nv, k == 1 ? 8 : 6, k == 1 ? &dr : NULL, NULL)) { printf("submit\n"); exit(1); }
      expect_body += k == 1 ? 10 : k == 0 ? 13 : 0;
      sent++;
    }
    /* client -> server */
    for (;;) {
      int64_t sid;
      int fin;
      nghttp3_vec vec[16];
      nghttp3_ssize nv = nghttp3_conn_writev_stream(cli, &sid, &fin, vec, 16);
      if (nv < 0) { CHECK(0, "client writev %d", (int)nv); goto out; }
      if (sid < 0) break;
      sbuf *b = inbuf(sid);
      size_t tot = 0;
      for (int i = 0; i < nv; i++) {
        if (b->n + vec[i].len > b->cap) b->cap = (b->n + vec[i].len) * 2 + 4096, b->p = realloc(b->p, b->cap);
        memcpy(b->p + b->n, vec[i].base, vec[i].len), b->n += vec[i].len, tot += vec[i].len;
      }
      if (fin) b->fin = 1;
      nghttp3_conn_add_write_offset(cli, sid, tot);
      nghttp3_conn_add_ack_offset(cli, sid, tot);
      if (!tot && !fin) break;
    }
    for (int i = 0; i < nin; i++)
      if ((IN[i].n || IN[i].fin == 1) && deliver(&S, &IN[i]) < 0) { CHECK(0, "server failed: error 0x%llx (kind %d)", (unsigned long long)h3_error(&S), kind); goto out; }
    /* server -> client */
    uint64_t pend[256];
    int np = h3_pending(&S, pend, 256);
    for (int i = 0; i < np; i++) {
      static uint8_t out[70000];
      int fin;
      size_t w = h3_stream_send(&S, pend[i], out, 1 + rnd() % sizeof out, &fin);
      if (!w && !fin) continue;
      nghttp3_ssize r = nghttp3_conn_read_stream(cli, (int64_t)pend[i], out, w, fin);
      if (r < 0) { CHECK(0, "client rejected stream %llu: %s", (unsigned long long)pend[i], nghttp3_strerror((int)r)); goto out; }
    }
  }
out:
  CHECK(CS.ended == nreq && CS.ok == nreq, "kind %d: %ld/%d ended, %ld x 200", kind, CS.ended, nreq, CS.ok);
  CHECK(CS.body == expect_body, "kind %d: body %ld want %ld", kind, CS.body, expect_body);
  CHECK(SS.resets == 0 && SS.close_err == 0 && SS.closes == nreq, "kind %d: resets %ld (0x%llx), closes %ld", kind, SS.resets,
        (unsigned long long)SS.last_reset, SS.closes);
  if (kind == 1) CHECK(CS.trailers == nreq, "kind 1: trailers %ld", CS.trailers);
  nghttp3_conn_del(cli);
  for (int i = 0; i < nin; i++) free(IN[i].p);
}

static void test_traffic(void) {
  long before = fails;
  for (int r = 0; r < 4 * scale(); r++) {
    run_conn(0, 400);
    run_conn(1, 200);
    run_conn(2, 30);
    run_conn(3, 300);
  }
  printf("traffic vs nghttp3 client: %s\n", fails == before ? "ok" : "FAILED");
}

/* ---------------------------------------- bad input ---------------------------------------- */
static uint64_t raw(const uint8_t *ctrl, size_t cl, int ctrl_fin, uint64_t sid2, const uint8_t *s2, size_t l2, int fin2) {
  static h3_conn S;
  h3_init(&S, &SCB, NULL, 3, 7, 11);
  memset(&SS, 0, sizeof SS);
  if (cl) h3_recv(&S, &SC, 2, 0, ctrl, cl, ctrl_fin);
  if (l2 || fin2) h3_recv(&S, &SC, sid2, 0, s2, l2, fin2);
  return h3_error(&S) ? h3_error(&S) : SS.resets ? 0x10000 | SS.last_reset : 0;
}
#define CTRL_OK "\x00\x04\x00" /* control stream type + empty SETTINGS */
static void test_bad(void) {
  long before = fails;
  /* a request: HEADERS with QPACK prefix 0000 and literal fields, from raw bytes */
  uint8_t req[256], *p = req;
  p = h3__put_vi(p, H3F_HEADERS);
  uint8_t sec[200], *q = sec;
  q += qp_enc_prefix(q);
  q += qp_enc_field(q, (const uint8_t *)":method", 7, (const uint8_t *)"GET", 3, 0);
  q += qp_enc_field(q, (const uint8_t *)":scheme", 7, (const uint8_t *)"https", 5, 0);
  q += qp_enc_field(q, (const uint8_t *)":path", 5, (const uint8_t *)"/", 1, 0);
  size_t good_len = (size_t)(q - sec);
  p = h3__put_vi(p, good_len);
  memcpy(p, sec, good_len), p += good_len;
  size_t reql = (size_t)(p - req);
  CHECK(raw((const uint8_t *)CTRL_OK, 3, 0, 0, req, reql, 1) == 0 && SS.requests == 1, "good request");
  struct { const char *what; const char *ctrl; size_t cl; int cfin; uint64_t want; } cc[] = {
    {"control without SETTINGS first", "\x00\x07\x01\x00", 4, 0, H3_MISSING_SETTINGS},
    {"second SETTINGS", "\x00\x04\x00\x04\x00", 5, 0, H3_FRAME_UNEXPECTED},
    {"DATA on control", "\x00\x04\x00\x00\x01x", 6, 0, H3_FRAME_UNEXPECTED},
    {"HTTP/2 setting id", "\x00\x04\x02\x02\x00", 5, 0, H3_SETTINGS_ERROR},
    {"duplicate setting", "\x00\x04\x04\x06\x01\x06\x02", 7, 0, H3_SETTINGS_ERROR},
    {"control stream fin", CTRL_OK, 3, 1, H3_CLOSED_CRITICAL_STREAM},
    {"reserved frame type 0x2 on control", "\x00\x04\x00\x02\x00", 5, 0, H3_FRAME_UNEXPECTED},
    {"push stream from client", "\x01\x00", 2, 0, H3_STREAM_CREATION_ERROR},
  };
  for (size_t i = 0; i < sizeof cc / sizeof cc[0]; i++)
    CHECK(raw((const uint8_t *)cc[i].ctrl, cc[i].cl, cc[i].cfin, 0, NULL, 0, 0) == cc[i].want, "%s: got 0x%llx", cc[i].what,
          (unsigned long long)raw((const uint8_t *)cc[i].ctrl, cc[i].cl, cc[i].cfin, 0, NULL, 0, 0));
  /* a second control stream */
  {
    static h3_conn S;
    h3_init(&S, &SCB, NULL, 3, 7, 11);
    h3_recv(&S, &SC, 2, 0, (const uint8_t *)CTRL_OK, 3, 0);
    h3_recv(&S, &SC, 6, 0, (const uint8_t *)CTRL_OK, 3, 0);
    CHECK(h3_error(&S) == H3_STREAM_CREATION_ERROR, "two control streams");
    h3_init(&S, &SCB, NULL, 3, 7, 11);
    h3_recv(&S, &SC, 6, 0, (const uint8_t *)"\x03\x80", 2, 0); /* decoder stream: Section Ack for stream 0 */
    CHECK(h3_error(&S) == QPACK_DECODER_STREAM_ERROR, "Section Ack to an encoder that never inserts");
    h3_init(&S, &SCB, NULL, 3, 7, 11);
    h3_recv(&S, &SC, 6, 0, (const uint8_t *)"\x02\x3f\xe2\x1f", 4, 0); /* encoder stream: Set Dynamic Table Capacity 4097 */
    CHECK(h3_error(&S) == QPACK_ENCODER_STREAM_ERROR, "capacity above our limit");
    h3_init(&S, &SCB, NULL, 3, 7, 11);
    CHECK(h3_recv(&S, &SC, 6, 0, (const uint8_t *)"\x21\x41\x42", 3, 0) == 3 && !h3_error(&S), "unknown uni stream type ignored");
    CHECK(h3_recv(&S, &SC, 6, 3, (const uint8_t *)"\x00\x01", 2, 0) == 2 && !h3_error(&S), "... and its later bytes too");
  }
  /* request streams */
  uint8_t r2[512];
  memcpy(r2, "\x00\x01x", 3), memcpy(r2 + 3, req, reql);
  CHECK(raw((const uint8_t *)CTRL_OK, 3, 0, 0, r2, reql + 3, 1) == H3_FRAME_UNEXPECTED, "DATA before HEADERS");
  CHECK(raw((const uint8_t *)CTRL_OK, 3, 0, 0, req, reql - 2, 1) == H3_FRAME_ERROR, "HEADERS cut by fin");
  CHECK(raw((const uint8_t *)CTRL_OK, 3, 0, 0, (const uint8_t *)"\x21\x00", 2, 1) == (0x10000 | H3_REQUEST_INCOMPLETE), "fin with no HEADERS");
  memcpy(r2, req, reql), memcpy(r2 + reql, "\x02\x00", 2);
  CHECK(raw((const uint8_t *)CTRL_OK, 3, 0, 0, r2, reql + 2, 1) == H3_FRAME_UNEXPECTED, "reserved type 0x2 on a request");
  memcpy(r2, req, reql), memcpy(r2 + reql, "\x04\x00", 2);
  CHECK(raw((const uint8_t *)CTRL_OK, 3, 0, 0, r2, reql + 2, 1) == H3_FRAME_UNEXPECTED, "SETTINGS on a request");
  memcpy(r2, "\x21\x02zz", 4), memcpy(r2 + 4, req, reql);
  CHECK(raw((const uint8_t *)CTRL_OK, 3, 0, 0, r2, reql + 4, 1) == 0 && SS.requests == 1, "unknown frame before HEADERS skipped");
  /* malformed requests: H3_MESSAGE_ERROR */
  const char *bad[][8] = {
    {":method", "GET", ":scheme", "https", ":path", "/", "Upper", "x"},
    {":method", "GET", ":scheme", "https", ":path", "/", "connection", "close"},
    {":method", "GET", ":scheme", "https", ":path", "/", ":status", "200"},
    {":method", "GET", ":scheme", "https", "x", "y", ":path", "/"},
  };
  for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
    q = sec + qp_enc_prefix(sec);
    for (int k = 0; k < 4; k++)
      q += qp_enc_field(q, (const uint8_t *)bad[i][2 * k], strlen(bad[i][2 * k]), (const uint8_t *)bad[i][2 * k + 1], strlen(bad[i][2 * k + 1]), 0);
    p = h3__put_vi(h3__put_vi(r2, H3F_HEADERS), (uint64_t)(q - sec));
    memcpy(p, sec, (size_t)(q - sec)), p += q - sec;
    CHECK(raw((const uint8_t *)CTRL_OK, 3, 0, 0, r2, (size_t)(p - r2), 1) == (0x10000 | H3_MESSAGE_ERROR) && SS.requests == 0, "malformed %zu", i);
  }
  /* content-length disagreeing with DATA */
  q = sec + qp_enc_prefix(sec);
  q += qp_enc_field(q, (const uint8_t *)":method", 7, (const uint8_t *)"POST", 4, 0);
  q += qp_enc_field(q, (const uint8_t *)":scheme", 7, (const uint8_t *)"https", 5, 0);
  q += qp_enc_field(q, (const uint8_t *)":path", 5, (const uint8_t *)"/", 1, 0);
  q += qp_enc_field(q, (const uint8_t *)"content-length", 14, (const uint8_t *)"5", 1, 0);
  p = h3__put_vi(h3__put_vi(r2, H3F_HEADERS), (uint64_t)(q - sec));
  memcpy(p, sec, (size_t)(q - sec)), p += q - sec;
  memcpy(p, "\x00\x03" "abc", 5), p += 5;
  CHECK(raw((const uint8_t *)CTRL_OK, 3, 0, 0, r2, (size_t)(p - r2), 1) == (0x10000 | H3_MESSAGE_ERROR), "content-length mismatch");
  p[-4] = 6; /* DATA of 6 bytes ("abc" + 3 more) against content-length 5, before any fin */
  memcpy(p - 3, "abcdef", 6), p += 3;
  CHECK(raw((const uint8_t *)CTRL_OK, 3, 0, 0, r2, (size_t)(p - r2), 0) == (0x10000 | H3_MESSAGE_ERROR), "content-length exceeded mid-stream");
  printf("bad input: %s\n", fails == before ? "ok" : "FAILED");
}

int main(void) {
  printf("sizeof(h3_conn) = %zu, sizeof(h3_scratch) = %zu\n", sizeof(h3_conn), sizeof(h3_scratch));
  for (int i = 0; i < 1000; i++) BIG[i] = (uint8_t)i;
  test_bad();
  test_traffic();
  printf("%s: %ld failures / %ld checks\n", fails ? "FAILED" : "PASS", fails, checks);
  return fails != 0;
}
