/* include/h2.h against nghttp2's client, in memory.
 *   - traffic: browser-like GETs, gRPC POSTs (request body, response trailers), large responses
 *     through a small client window, more streams than MAX_CONCURRENT_STREAMS; input to h2_recv is
 *     cut at random points and output from h2_send drained in random sizes.
 *   - malformed requests and frames (hand-built) get the RST_STREAM / GOAWAY codes RFC 9113 asks for.
 * FUZZ=N scales the counts. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef H2_STAGE
#define H2_STAGE 65536 /* room for a response header block larger than one frame */
#endif
#include "h2.h"
#include <nghttp2/nghttp2.h>

static long fails, checks;
#define CHECK(c, ...)                                                                                                  \
  do {                                                                                                                 \
    checks++;                                                                                                          \
    if (!(c)) {                                                                                                        \
      if (fails++ < 25) {                                                                                              \
        printf("FAIL %s:%d: ", __FILE__, __LINE__);                                                                    \
        printf(__VA_ARGS__);                                                                                           \
        printf("\n");                                                                                                  \
      }                                                                                                                \
    }                                                                                                                  \
  } while (0)
static uint64_t rs = 0x9e3779b97f4a7c15ull;
static uint64_t rnd(void) {
  rs ^= rs << 13;
  rs ^= rs >> 7;
  rs ^= rs << 17;
  return rs;
}
static long scale(void) {
  const char *e = getenv("FUZZ");
  return e ? atol(e) : 1;
}

static h2_scratch SC;
static uint8_t BIG[1 << 20];

/* ------------------------------------- server application ------------------------------------- */
typedef struct {
  long requests, data_bytes, trailers, closes, close_errors;
  uint32_t last_reset;
} srv_stats;
static srv_stats SS;
static int srv_on_request(h2_conn *c, uint32_t sid, const h2_request *rq, int end, void *u) {
  (void)u;
  SS.requests++;
  static const char ct[] = "text/plain";
  hp_field hd[2] = { { (const uint8_t *)"content-type", (const uint8_t *)ct, 12, sizeof ct - 1, 0, 0, 0, 0 },
                     { (const uint8_t *)"x-path", rq->path, 6, rq->path_len > 200 ? 200 : rq->path_len, 0, 0, 0, 0 } };
  if (rq->path_len >= 7 && !memcmp(rq->path, "/hdrs/", 6)) { /* a header block that needs CONTINUATION */
    static char hv[20000];
    memset(hv, '"', sizeof hv); /* a 10-bit code: sent raw, so the block exceeds one frame */
    hp_field big = {
      (const uint8_t *)"x-big", (const uint8_t *)hv, 5, (uint32_t)atoi((const char *)rq->path + 6), 0, 0, 0, 0
    };
    return h2_respond(c, sid, 200, &big, 1, (const uint8_t *)"hello, world\n", 13, 1) < 0;
  }
  if (rq->path_len >= 5 && !memcmp(rq->path, "/big/", 5)) {
    size_t n = (size_t)atoi((const char *)rq->path + 5);
    return h2_respond(c, sid, 200, hd, 2, BIG, n, 1) < 0;
  }
  if (rq->method_len == 4 && !memcmp(rq->method, "POST", 4)) {
    if (end) return h2_respond(c, sid, 200, hd, 1, (const uint8_t *)"empty", 5, 1) < 0;
    return 0; /* answered when the body ends */
  }
  return h2_respond(c, sid, 200, hd, 2, (const uint8_t *)"hello, world\n", 13, 1) < 0;
}
static int srv_on_data(h2_conn *c, uint32_t sid, const uint8_t *d, size_t n, int end, void *u) {
  (void)d, (void)u;
  SS.data_bytes += (long)n;
  if (end) {
    static const hp_field ct = {
      (const uint8_t *)"content-type", (const uint8_t *)"application/grpc", 12, 16, 0, 0, 0, 0
    };
    static const hp_field tr[2] = { { (const uint8_t *)"grpc-status", (const uint8_t *)"0", 11, 1, 0, 0, 0, 0 },
                                    { (const uint8_t *)"grpc-message", (const uint8_t *)"OK", 12, 2, 0, 0, 0, 0 } };
    if (h2_respond(c, sid, 200, &ct, 1, (const uint8_t *)"\0\0\0\0\x05hello", 10, 0) < 0) return 1;
    return h2_trailers(c, sid, tr, 2) < 0;
  }
  return 0;
}
static void srv_on_close(h2_conn *c, uint32_t sid, uint32_t err, void *u) {
  (void)c, (void)sid, (void)u;
  SS.closes++;
  if (err) SS.close_errors++, SS.last_reset = err;
}
static const h2_callbacks SRV_CB = { srv_on_request, srv_on_data, NULL, NULL, srv_on_close, NULL };

/* -------------------------------------- nghttp2 client -------------------------------------- */
typedef struct {
  long done, ok, body, trailers_ok, rst;
  uint32_t rst_code;
} cli_stats;
static cli_stats CS;
static int cli_on_header(nghttp2_session *s, const nghttp2_frame *f, nghttp2_rcbuf *n, nghttp2_rcbuf *v, uint8_t fl,
                         void *u) {
  (void)s, (void)fl, (void)u;
  nghttp2_vec nn = nghttp2_rcbuf_get_buf(n), vv = nghttp2_rcbuf_get_buf(v);
  if (nn.len == 7 && !memcmp(nn.base, ":status", 7) && vv.len == 3 && !memcmp(vv.base, "200", 3)) CS.ok++;
  if (f->headers.cat == NGHTTP2_HCAT_HEADERS && nn.len == 11 && !memcmp(nn.base, "grpc-status", 11)) CS.trailers_ok++;
  return 0;
}
static int cli_on_chunk(nghttp2_session *s, uint8_t fl, int32_t id, const uint8_t *d, size_t n, void *u) {
  (void)s, (void)fl, (void)id, (void)d, (void)u;
  CS.body += (long)n;
  return 0;
}
static int cli_on_close(nghttp2_session *s, int32_t id, uint32_t err, void *u) {
  (void)s, (void)id, (void)u;
  CS.done++;
  if (err) CS.rst++, CS.rst_code = err;
  return 0;
}
static nghttp2_ssize cli_body(nghttp2_session *s, int32_t id, uint8_t *buf, size_t len, uint32_t *fl,
                              nghttp2_data_source *src, void *u) {
  (void)s, (void)id, (void)u;
  size_t *left = (size_t *)src->ptr, m = *left < len ? *left : len;
  memset(buf, 'b', m);
  *left -= m;
  if (!*left) *fl |= NGHTTP2_DATA_FLAG_EOF;
  return (nghttp2_ssize)m;
}

typedef struct {
  uint8_t *p;
  size_t n, cap;
} bytes;
static void put(bytes *b, const uint8_t *d, size_t n) {
  if (b->n + n > b->cap) b->cap = (b->n + n) * 2 + 4096, b->p = realloc(b->p, b->cap);
  memcpy(b->p + b->n, d, n), b->n += n;
}

/* push client bytes into the server in random cuts, keeping the unconsumed tail */
static bytes INQ;
static int feed(h2_conn *c, const uint8_t *d, size_t n) {
  if (n) put(&INQ, d, n);
  size_t off = 0;
  while (off < INQ.n) {
    size_t lim = INQ.n - off;
    if (rnd() % 3 == 0) lim = 1 + rnd() % lim; /* expose a prefix only */
    int r = h2_recv(c, &SC, INQ.p + off, lim);
    if (r < 0) return r;
    if (r == 0 && lim == INQ.n - off) break; /* needs more than we have */
    off += (size_t)r;
  }
  if (off) memmove(INQ.p, INQ.p + off, INQ.n - off), INQ.n -= off;
  return 0;
}

static void run_conn(int kind, int nreq, uint32_t cli_window) {
  static h2_conn C;
  h2_init(&C, &SRV_CB, NULL);
  INQ.n = 0;
  nghttp2_session_callbacks *cb;
  nghttp2_session *cli;
  nghttp2_session_callbacks_new(&cb);
  nghttp2_session_callbacks_set_on_header_callback2(cb, cli_on_header);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cb, cli_on_chunk);
  nghttp2_session_callbacks_set_on_stream_close_callback(cb, cli_on_close);
  nghttp2_session_client_new(&cli, cb, NULL);
  nghttp2_session_callbacks_del(cb);
  nghttp2_settings_entry st[] = { { NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, cli_window },
                                  { NGHTTP2_SETTINGS_HEADER_TABLE_SIZE, rnd() % 2 ? 4096 : 0 } };
  nghttp2_submit_settings(cli, NGHTTP2_FLAG_NONE, st, 2);
  memset(&CS, 0, sizeof CS), memset(&SS, 0, sizeof SS);
  long expect_body = 0;
  static size_t left[4096];
  int sent = 0;
  uint8_t out[70000];
  for (int guard = 0; guard < 200000 && CS.done < nreq; guard++) {
    while (sent < nreq && sent - CS.done < 150) { /* more than our 100 concurrent */
      char path[64];
      int k = kind == 3 ? (int)(rnd() % 3) : kind;
      size_t big = 1000 + rnd() % 300000;
      if (k == 2) snprintf(path, sizeof path, "/big/%zu", big), expect_body += (long)big;
      else if (k == 4) snprintf(path, sizeof path, "/hdrs/%d", 16500 + (int)(rnd() % 3000)), expect_body += 13;
      else snprintf(path, sizeof path, "/assets/%d-%llx.js", sent, (unsigned long long)rnd());
      nghttp2_nv nv[8] = { { (uint8_t *)":method", (uint8_t *)(k == 1 ? "POST" : "GET"), 7, k == 1 ? 4u : 3u, 0 },
                           { (uint8_t *)":scheme", (uint8_t *)"https", 7, 5, 0 },
                           { (uint8_t *)":authority", (uint8_t *)"example.com", 10, 11, 0 },
                           { (uint8_t *)":path", (uint8_t *)path, 5, strlen(path), 0 },
                           { (uint8_t *)"user-agent", (uint8_t *)"Mozilla/5.0 (test) Chrome/130", 10, 29, 0 },
                           { (uint8_t *)"cookie", (uint8_t *)"session=abcdef0123456789; theme=dark", 6, 36, 0 },
                           { (uint8_t *)"content-type", (uint8_t *)"application/grpc", 12, 16, 0 },
                           { (uint8_t *)"te", (uint8_t *)"trailers", 2, 8, 0 } };
      int nnv = k == 1 || k == 5 ? 8 : 6;
      if (k == 5) nv[0].value = (uint8_t *)"POST", nv[0].valuelen = 4;
      left[sent % 4096] = k == 5 ? 400000 + rnd() % 200000 : 1 + rnd() % 5000; /* kind 5: uploads beyond every window */
      nghttp2_data_provider2 dp = { { .ptr = &left[sent % 4096] }, cli_body };
      if (nghttp2_submit_request2(cli, NULL, nv, (size_t)nnv, k == 1 || k == 5 ? &dp : NULL, NULL) < 0) {
        printf("submit failed\n");
        exit(1);
      }
      if (k == 1 || k == 5) expect_body += 10;
      else if (k == 0) expect_body += 13;
      if (kind == 2 && sent == nreq / 2) { /* the client changes its window mid-connection (§6.9.2) */
        nghttp2_settings_entry ws = { NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, cli_window / 2 + 100 };
        nghttp2_submit_settings(cli, NGHTTP2_FLAG_NONE, &ws, 1);
      }
      sent++;
    }
    const uint8_t *d;
    nghttp2_ssize n;
    /* backpressured tail */
    if (feed(&C, NULL, 0) < 0) {
      CHECK(0, "server failed the connection (kind %d)", kind);
      goto out;
    }
    while ((n = nghttp2_session_mem_send2(cli, &d)) > 0)
      if (feed(&C, d, (size_t)n) < 0) {
        CHECK(0, "server failed the connection (kind %d)", kind);
        goto out;
      }
    size_t w;
    while ((w = h2_send(&C, out, 1 + rnd() % sizeof out)) > 0)
      if (nghttp2_session_mem_recv2(cli, out, w) < 0) {
        CHECK(0, "client rejected server output");
        goto out;
      }
    if (n < 0) {
      CHECK(0, "client mem_send");
      goto out;
    }
  }
out:
  CHECK(CS.done == nreq && CS.rst == 0, "kind %d: %ld/%d done, %ld reset (code %u)", kind, CS.done, nreq, CS.rst,
        CS.rst_code);
  CHECK(CS.ok == nreq, "kind %d: %ld x 200", kind, CS.ok);
  CHECK(CS.body == expect_body, "kind %d: body %ld want %ld", kind, CS.body, expect_body);
  CHECK(SS.closes == nreq && SS.close_errors == 0, "kind %d: server closes %ld errors %ld", kind, SS.closes,
        SS.close_errors);
  nghttp2_session_del(cli);
}

static void test_traffic(void) {
  long before = fails;
  for (int i = 0; i < 1000; i++) BIG[i] = (uint8_t)i;
  for (long r = 0; r < 4 * scale(); r++) {
    run_conn(0, 500, 65535);                           /* browser GETs */
    run_conn(1, 300, 65535);                           /* gRPC: body + trailers */
    run_conn(2, 20, 1000 + (uint32_t)(rnd() % 20000)); /* big bodies through small windows */
    run_conn(3, 300, 16384);                           /* mixed */
    run_conn(4, 30, 65535);                            /* response header blocks > one frame */
    run_conn(5, 40, 65535);                            /* 16-24 MB of uploads: stream and connection WINDOW_UPDATEs */
  }
  printf("traffic vs nghttp2 client: %s\n", fails == before ? "ok" : "FAILED");
}

/* ---------------------------------- hand-built bad input ---------------------------------- */
static const uint8_t PREFACE[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
static size_t frame(uint8_t *p, uint32_t len, uint8_t type, uint8_t fl, uint32_t sid, const void *pl) {
  h2__hdr(p, len, type, fl, sid);
  if (len) memcpy(p + 9, pl, len);
  return 9 + len;
}
/* run a raw client byte string; report what the server sent back: last RST code for sid, or GOAWAY code */
typedef struct {
  int goaway;
  uint32_t goaway_code;
  int rst;
  uint32_t rst_code;
  int responded;
} verdict;
static verdict run_raw(const uint8_t *in, size_t n) {
  static h2_conn C;
  h2_init(&C, &SRV_CB, NULL);
  memset(&SS, 0, sizeof SS);
  verdict v = { 0 };
  h2_recv(&C, &SC, in, n);
  static uint8_t out[1 << 17];
  size_t w = h2_send(&C, out, sizeof out);
  for (size_t o = 0; o + 9 <= w;) {
    uint32_t len = h2__be24(out + o);
    uint8_t t = out[o + 3];
    if (t == H2F_GOAWAY) v.goaway = 1, v.goaway_code = h2__be32(out + o + 13);
    if (t == H2F_RST_STREAM) v.rst = 1, v.rst_code = h2__be32(out + o + 9);
    if (t == H2F_HEADERS) v.responded = 1;
    o += 9 + len;
  }
  return v;
}
static size_t hdrblock(uint8_t *b, const char *const *kv, int n) { /* literal fields, no Huffman, no indexing */
  size_t o = 0;
  for (int i = 0; i < n; i++) {
    size_t nl = strlen(kv[2 * i]), vl = strlen(kv[2 * i + 1]);
    b[o++] = 0x00, b[o++] = (uint8_t)nl, memcpy(b + o, kv[2 * i], nl), o += nl;
    b[o++] = (uint8_t)vl, memcpy(b + o, kv[2 * i + 1], vl), o += vl;
  }
  return o;
}
static void test_bad(void) {
  long before = fails;
  static uint8_t in[40000], blk[1024];
  size_t o;
#define START() (o = 0, memcpy(in, PREFACE, 24), o += 24, o += frame(in + o, 0, H2F_SETTINGS, 0, 0, NULL))
#define REQ(sid, fl, ...)                                                                                              \
  do {                                                                                                                 \
    const char *kv_[] = { __VA_ARGS__ };                                                                               \
    size_t bl_ = hdrblock(blk, kv_, (int)(sizeof kv_ / sizeof kv_[0] / 2));                                            \
    o += frame(in + o, (uint32_t)bl_, H2F_HEADERS, (uint8_t)(H2_FL_END_HEADERS | (fl)), sid, blk);                     \
  } while (0)
#define GOOD ":method", "GET", ":scheme", "https", ":path", "/", ":authority", "a"
  verdict v;
  START();
  REQ(1, H2_FL_END_STREAM, GOOD);
  v = run_raw(in, o);
  CHECK(v.responded && !v.rst && !v.goaway, "good request");
  /* malformed requests: stream error PROTOCOL_ERROR (§8.1.1) */
  const char *bad[][12] = {
    { ":method", "GET", ":scheme", "https", ":path", "/", "Upper", "x" },           /* uppercase name */
    { ":method", "GET", ":scheme", "https", ":path", "/", "connection", "close" },  /* connection-specific */
    { ":method", "GET", ":scheme", "https", ":path", "/", "te", "gzip" },           /* te other than trailers */
    { ":method", "GET", ":scheme", "https", "x", "1", ":path", "/" },               /* pseudo after regular */
    { ":method", "GET", ":scheme", "https", ":path", "/", ":path", "/" },           /* duplicate pseudo */
    { ":method", "GET", ":scheme", "https", ":path", "/", ":status", "200" },       /* response pseudo */
    { ":method", "GET", ":scheme", "https" },                                       /* no :path */
    { ":method", "GET", ":scheme", "https", ":path", "" },                          /* empty :path */
    { ":method", "GET", ":scheme", "https", ":path", "/", "x", " lead" },           /* leading space */
    { ":method", "GET", ":scheme", "https", ":path", "/", "content-length", "1x" }, /* bad content-length */
    { ":method", "GET", ":scheme", "https", ":path", "/", "transfer-encoding", "chunked" },
    { ":method", "CONNECT", ":scheme", "https", ":path", "/", ":authority", "a" }, /* CONNECT with :path */
  };
  for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
    int n = 0;
    while (n < 6 && bad[i][2 * n]) n++;
    START();
    size_t bl = hdrblock(blk, bad[i], n);
    o += frame(in + o, (uint32_t)bl, H2F_HEADERS, H2_FL_END_HEADERS | H2_FL_END_STREAM, 1, blk);
    v = run_raw(in, o);
    CHECK(v.rst && v.rst_code == H2_PROTOCOL_ERROR && !v.responded && !v.goaway, "malformed %zu: rst %d code %u", i,
          v.rst, v.rst_code);
  }
  /* content-length mismatch with the DATA received */
  START();
  REQ(1, 0, ":method", "POST", ":scheme", "https", ":path", "/", "content-length", "5");
  o += frame(in + o, 3, H2F_DATA, H2_FL_END_STREAM, 1, "abc");
  v = run_raw(in, o);
  CHECK(v.rst && v.rst_code == H2_PROTOCOL_ERROR, "content-length mismatch");
  /* connection errors */
  struct {
    const char *what;
    uint32_t code;
  } ce[] = {
    { "DATA on stream 0", H2_PROTOCOL_ERROR },
    { "HEADERS on even stream", H2_PROTOCOL_ERROR },
    { "CONTINUATION alone", H2_PROTOCOL_ERROR },
    { "PING with stream id", H2_PROTOCOL_ERROR },
    { "PING length 7", H2_FRAME_SIZE_ERROR },
    { "SETTINGS length 5", H2_FRAME_SIZE_ERROR },
    { "SETTINGS ack with payload", H2_FRAME_SIZE_ERROR },
    { "ENABLE_PUSH 2", H2_PROTOCOL_ERROR },
    { "INITIAL_WINDOW_SIZE 2^31", H2_FLOW_CONTROL_ERROR },
    { "MAX_FRAME_SIZE 100", H2_PROTOCOL_ERROR },
    { "WINDOW_UPDATE 0 on connection", H2_PROTOCOL_ERROR },
    { "connection window overflow", H2_FLOW_CONTROL_ERROR },
    { "PUSH_PROMISE from client", H2_PROTOCOL_ERROR },
    { "frame larger than 16384", H2_FRAME_SIZE_ERROR },
    { "bad HPACK", H2_COMPRESSION_ERROR },
    { "HEADERS on closed stream", H2_STREAM_CLOSED },
    { "DATA on idle stream", H2_PROTOCOL_ERROR },
    { "interleaved frame in header block", H2_PROTOCOL_ERROR },
    { "first frame not SETTINGS", H2_PROTOCOL_ERROR },
    { "RST_STREAM on idle stream", H2_PROTOCOL_ERROR },
  };
  for (size_t i = 0; i < sizeof ce / sizeof ce[0]; i++) {
    uint8_t s6[6] = { 0 }, w4[4], z[20000] = { 0 };
    START();
    switch (i) {
      case 0: o += frame(in + o, 1, H2F_DATA, 0, 0, "x"); break;
      case 1: REQ(2, H2_FL_END_STREAM, GOOD); break;
      case 2: o += frame(in + o, 1, H2F_CONTINUATION, H2_FL_END_HEADERS, 1, "\x82"); break;
      case 3: o += frame(in + o, 8, H2F_PING, 0, 1, "12345678"); break;
      case 4: o += frame(in + o, 7, H2F_PING, 0, 0, "1234567"); break;
      case 5: o += frame(in + o, 5, H2F_SETTINGS, 0, 0, "12345"); break;
      case 6: o += frame(in + o, 6, H2F_SETTINGS, H2_FL_ACK, 0, s6); break;
      case 7:
        s6[1] = 2, s6[5] = 2;
        o += frame(in + o, 6, H2F_SETTINGS, 0, 0, s6);
        break;
      case 8:
        s6[1] = 4, s6[2] = 0x80;
        o += frame(in + o, 6, H2F_SETTINGS, 0, 0, s6);
        break;
      case 9:
        s6[1] = 5, s6[5] = 100;
        o += frame(in + o, 6, H2F_SETTINGS, 0, 0, s6);
        break;
      case 10:
        h2__put32(w4, 0);
        o += frame(in + o, 4, H2F_WINDOW_UPDATE, 0, 0, w4);
        break;
      case 11:
        h2__put32(w4, 0x7fffffff);
        o += frame(in + o, 4, H2F_WINDOW_UPDATE, 0, 0, w4);
        break;
      case 12: o += frame(in + o, 4, H2F_PUSH_PROMISE, H2_FL_END_HEADERS, 1, "\0\0\0\2"); break;
      case 13: o += frame(in + o, 16385, 0xfa, 0, 0, z); break;
      case 14: o += frame(in + o, 1, H2F_HEADERS, H2_FL_END_HEADERS, 1, "\x80"); break; /* index 0 */
      case 15:
        REQ(3, H2_FL_END_STREAM, GOOD);
        REQ(1, H2_FL_END_STREAM, GOOD);
        break;
      case 16: o += frame(in + o, 1, H2F_DATA, 0, 5, "x"); break;
      case 17: {
        const char *kv[] = { GOOD };
        size_t bl = hdrblock(blk, kv, 4);
        o += frame(in + o, (uint32_t)(bl / 2), H2F_HEADERS, 0, 1, blk);
        o += frame(in + o, 8, H2F_PING, 0, 0, "12345678");
        o += frame(in + o, (uint32_t)(bl - bl / 2), H2F_CONTINUATION, H2_FL_END_HEADERS, 1, blk + bl / 2);
      } break;
      case 18:
        o = 24;
        o += frame(in + o, 8, H2F_PING, 0, 0, "12345678");
        break;
      case 19: o += frame(in + o, 4, H2F_RST_STREAM, 0, 7, "\0\0\0\0"); break;
    }
    v = run_raw(in, o);
    CHECK(v.goaway && v.goaway_code == ce[i].code, "%s: goaway %d code %u want %u", ce[i].what, v.goaway, v.goaway_code,
          ce[i].code);
  }
  {
    START();
    o += frame(in + o, 8, H2F_PING, 0, 0, "12345678");
    static h2_conn C;
    h2_init(&C, &SRV_CB, NULL);
    h2_recv(&C, &SC, in, o);
    uint8_t out[512];
    size_t w = h2_send(&C, out, sizeof out), off = 0;
    int acked = 0;
    while (off + 9 <= w) {
      uint32_t len = h2__be24(out + off);
      if (out[off + 3] == H2F_PING && (out[off + 4] & H2_FL_ACK) && len == 8 && !memcmp(out + off + 9, "12345678", 8))
        acked = 1;
      off += 9 + len;
    }
    CHECK(acked, "PING is acked with the same payload");
    const char *kv[] = { GOOD };
    size_t bl = hdrblock(blk, kv, 4);
    START();
    o += frame(in + o, (uint32_t)(bl / 2), H2F_HEADERS, 0, 1, blk);
    o += frame(in + o, (uint32_t)(bl - bl / 2), H2F_CONTINUATION, H2_FL_END_HEADERS, 3, blk + bl / 2);
    v = run_raw(in, o);
    CHECK(v.goaway && v.goaway_code == H2_PROTOCOL_ERROR, "CONTINUATION on another stream");
    /* INITIAL_WINDOW_SIZE lowered after a stream opened: its window shrinks by the delta (§6.9.2) */
    START();
    REQ(1, H2_FL_END_STREAM, ":method", "GET", ":scheme", "https", ":path", "/big/100000");
    uint8_t s6[6] = { 0, 4, 0, 0, 0, 100 };
    o += frame(in + o, 6, H2F_SETTINGS, 0, 0, s6);
    h2_init(&C, &SRV_CB, NULL);
    h2_recv(&C, &SC, in, o);
    static uint8_t big[1 << 18];
    w = h2_send(&C, big, sizeof big), off = 0;
    size_t data = 0;
    while (off + 9 <= w) {
      uint32_t len = h2__be24(big + off);
      if (big[off + 3] == H2F_DATA) data += len;
      off += 9 + len;
    }
    CHECK(data == 100, "DATA after INITIAL_WINDOW_SIZE 100: %zu bytes", data);
  }
  /* stream errors that keep the connection */
  START();
  REQ(1, H2_FL_PRIORITY | 0, GOOD); /* placeholder replaced below */
  {
    uint8_t pr[5] = { 0, 0, 0, 1, 16 }; /* depends on itself */
    START();
    o += frame(in + o, 5, H2F_PRIORITY, 0, 1, pr);
    v = run_raw(in, o);
    CHECK(v.rst && v.rst_code == H2_PROTOCOL_ERROR && !v.goaway, "PRIORITY self-dependency");
    START();
    o += frame(in + o, 4, H2F_PRIORITY, 0, 1, pr);
    v = run_raw(in, o);
    CHECK(v.rst && v.rst_code == H2_FRAME_SIZE_ERROR && !v.goaway, "PRIORITY length 4");
    START();
    REQ(1, 0, ":method", "POST", ":scheme", "https", ":path", "/");
    o += frame(in + o, 1, H2F_DATA, H2_FL_END_STREAM, 1, "x");
    o += frame(in + o, 1, H2F_DATA, 0, 1, "y"); /* after END_STREAM */
    v = run_raw(in, o);
    CHECK(v.rst && v.rst_code == H2_STREAM_CLOSED && !v.goaway, "DATA after END_STREAM: rst %d code %u", v.rst,
          v.rst_code);
    START();
    REQ(1, 0, ":method", "POST", ":scheme", "https", ":path", "/");
    uint8_t w4[4];
    h2__put32(w4, 0);
    o += frame(in + o, 4, H2F_WINDOW_UPDATE, 0, 1, w4);
    v = run_raw(in, o);
    CHECK(v.rst && v.rst_code == H2_PROTOCOL_ERROR && !v.goaway, "stream WINDOW_UPDATE 0");
  }
  printf("bad input: %s\n", fails == before ? "ok" : "FAILED");
}

int main(void) {
  printf("sizeof(h2_conn) = %zu, sizeof(h2_scratch) = %zu\n", sizeof(h2_conn), sizeof(h2_scratch));
  test_bad();
  test_traffic();
  printf("%s: %ld failures / %ld checks\n", fails ? "FAILED" : "PASS", fails, checks);
  return fails != 0;
}
