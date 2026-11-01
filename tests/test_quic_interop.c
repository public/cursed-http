/* include/quic.h + include/h3.h serving HTTP/3 to ngtcp2 + nghttp3 (picotls on both sides), in memory.
 *   - a simulated network carries datagrams both ways with a configurable loss rate and
 *     reordering; a simulated clock drives both stacks' timers.
 *   - each run: handshake, then N requests (GETs, POSTs with bodies, large responses); the client
 *     checks every status and body length; both sides must finish without errors.
 *   - the server certificate is a throwaway self-signed P-256 key made in memory here.
 * Usage: test_quic_interop [loss_percent] (default: a sweep of 0, 2, 10). FUZZ=N scales runs.
 * Debugging: NGLOG=1 prints ngtcp2's log, DUMP=1 the packets of every server datagram; a stalled run
 * prints the server's transport and HTTP/3 state. */
#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/ec.h>
#include "quic.h"
#include "h3.h"
#include <picotls/openssl.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_picotls.h>
#include <nghttp3/nghttp3.h>

static long fails, checks;
#define CHECK(c, ...) do { checks++; if (!(c)) { if (fails++ < 25) { printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } } while (0)
static uint64_t rs = 0x243f6a8885a308d3ull;
static uint64_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }
static long scale(void) { const char *e = getenv("FUZZ"); return e ? atol(e) : 1; }

/* ------------------------------------------- clock / net ------------------------------------------- */
static uint64_t NOW_NS = 1000000000ull;
static int64_t now_ms(void) { return (int64_t)(NOW_NS / 1000000); }
typedef struct { uint8_t d[1500]; size_t n; uint64_t at, seq; } dgram;
static uint64_t SEQ;
typedef struct { dgram q[4096]; int n; } wire;
static wire TO_SRV, TO_CLI;
static int LOSS, REORDER, BLACKHOLE; /* BLACKHOLE: drop client->server after its first datagram, for 3 s */
static uint64_t BLACKHOLE_UNTIL;
static long SENT_DGRAMS, LOST_DGRAMS;
static uint64_t TO_SRV_BYTES, TO_CLI_BYTES; /* before the server validated the client's address */
static void put(wire *w, const uint8_t *d, size_t n) {
  SENT_DGRAMS++;
  if (BLACKHOLE && w == &TO_SRV) {
    if (!BLACKHOLE_UNTIL) BLACKHOLE_UNTIL = NOW_NS + 3000000000ull; /* the first datagram goes through */
    else if (NOW_NS < BLACKHOLE_UNTIL) { LOST_DGRAMS++; return; }
  }
  if ((int)(rnd() % 100) < LOSS) { LOST_DGRAMS++; return; }
  if (REORDER && rnd() % 100 == 0 && w->n < 4095) { /* a duplicate */
    dgram *g = &w->q[w->n++];
    memcpy(g->d, d, n), g->n = n, g->at = NOW_NS + 10000000ull + (rnd() % 8) * 3000000ull, g->seq = SEQ++;
  }
  if (w->n == 4096 || n > 1500) return;
  dgram *g = &w->q[w->n++];
  memcpy(g->d, d, n), g->n = n;
  g->at = NOW_NS + 10000000ull + (REORDER ? (rnd() % 8) * 3000000ull : 0); /* 10 ms one way, +0..21 ms jitter */
  g->seq = SEQ++;
}
/* the next datagram due by now: earliest arrival, then send order (no reordering unless jittered) */
static int take(wire *w, dgram *out) {
  int best = -1;
  for (int i = 0; i < w->n; i++)
    if (w->q[i].at <= NOW_NS && (best < 0 || w->q[i].at < w->q[best].at || (w->q[i].at == w->q[best].at && w->q[i].seq < w->q[best].seq)))
      best = i;
  if (best < 0) return 0;
  *out = w->q[best];
  w->q[best] = w->q[--w->n];
  return 1;
}
static uint64_t next_arrival(void) {
  uint64_t t = UINT64_MAX;
  for (int i = 0; i < TO_SRV.n; i++) if (TO_SRV.q[i].at < t) t = TO_SRV.q[i].at;
  for (int i = 0; i < TO_CLI.n; i++) if (TO_CLI.q[i].at < t) t = TO_CLI.q[i].at;
  return t;
}

/* --------------------------------------------- server --------------------------------------------- */
static ptls_context_t SRV_TLS;
static ptls_openssl_sign_certificate_t SRV_SIGN;
static ptls_iovec_t SRV_CERT;
static quic_ctx QX;
typedef struct { quic_conn q; h3_conn h; int h3_ready; long requests, closes, errors; } server;
static server *SRV;
static h3_scratch H3S;
static uint8_t BIG[1 << 20];

static int s_request(h3_conn *h, uint64_t sid, const h_request *rq, int end, void *u) {
  server *s = u;
  s->requests++;
  static const hp_field ct = {(const uint8_t *)"content-type", (const uint8_t *)"text/plain", 12, 10, 0, 0, 0, 0};
  if (rq->path_len > 5 && !memcmp(rq->path, "/big/", 5)) return h3_respond(h, sid, 200, &ct, 1, BIG, (size_t)atoi((const char *)rq->path + 5), 1) < 0;
  if (!end) return 0; /* POST: answered at the end of the body */
  return h3_respond(h, sid, 200, &ct, 1, (const uint8_t *)"hello, world\n", 13, 1) < 0;
}
static int s_data(h3_conn *h, uint64_t sid, const uint8_t *d, size_t n, int end, void *u) {
  (void)d, (void)n, (void)u;
  h3_stream *st = h3__find(h, sid);
  if (!end || !st || (st->flags & H3_ST_RESPONDED)) return 0;
  static const hp_field ct = {(const uint8_t *)"content-type", (const uint8_t *)"text/plain", 12, 10, 0, 0, 0, 0};
  return h3_respond(h, sid, 200, &ct, 1, (const uint8_t *)"posted\n", 7, 1) < 0;
}
static void s_close(h3_conn *h, uint64_t sid, uint64_t err, void *u) {
  (void)h, (void)sid;
  server *s = u;
  s->closes++;
  if (err) s->errors++;
}
static void s_reset(h3_conn *h, uint64_t sid, uint64_t code, void *u) {
  (void)h;
  server *s = u;
  quic_reset_stream(&s->q, sid, code);
}
static const h3_callbacks H3CB = {s_request, s_data, NULL, NULL, s_close, s_reset};

static int64_t q_on_stream(quic_conn *q, uint64_t sid, uint64_t off, const uint8_t *d, size_t len, int fin, void *u) {
  (void)q;
  server *s = u;
  if (!s->h3_ready) return 0;
  int r = h3_recv(&s->h, &H3S, sid, off, d, len, fin);
  if (r < 0) return -(int64_t)h3_error(&s->h);
  return r;
}
static size_t q_send(quic_conn *q, uint64_t sid, uint8_t *out, size_t cap, int *fin, void *u) {
  (void)q;
  server *s = u;
  return h3_stream_send(&s->h, sid, out, cap, fin);
}
static int q_wants(quic_conn *q, uint64_t sid, void *u) {
  (void)q;
  return h3_stream_wants(&((server *)u)->h, sid);
}
static void q_reset(quic_conn *q, uint64_t sid, uint64_t code, void *u) {
  (void)q;
  server *s = u;
  h3_peer_reset(&s->h, sid, code);
}
static void q_established(quic_conn *q, void *u) {
  server *s = u;
  int64_t a = quic_open_uni(q), b = quic_open_uni(q), c = quic_open_uni(q);
  CHECK(a >= 0 && b >= 0 && c >= 0, "open uni streams");
  h3_init(&s->h, &H3CB, s, (uint64_t)a, (uint64_t)b, (uint64_t)c);
  s->h3_ready = 1;
}
static const quic_callbacks QCB = {q_on_stream, q_send, q_wants, q_reset, q_established};

static void make_cert(void) {
  EVP_PKEY *pk = EVP_EC_gen("P-256");
  X509 *x = X509_new();
  X509_set_version(x, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
  X509_gmtime_adj(X509_getm_notBefore(x), -3600);
  X509_gmtime_adj(X509_getm_notAfter(x), 3600);
  X509_set_pubkey(x, pk);
  X509_NAME *nm = X509_get_subject_name(x);
  X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC, (const unsigned char *)"localhost", -1, -1, 0);
  X509_set_issuer_name(x, nm);
  X509_sign(x, pk, EVP_sha256());
  unsigned char *der = NULL;
  int dl = i2d_X509(x, &der);
  SRV_CERT = ptls_iovec_init(der, (size_t)dl);
  ptls_openssl_init_sign_certificate(&SRV_SIGN, pk);
  X509_free(x), EVP_PKEY_free(pk);
}
static void server_init(void) {
  make_cert();
  memset(&SRV_TLS, 0, sizeof SRV_TLS);
  SRV_TLS.random_bytes = ptls_openssl_random_bytes;
  SRV_TLS.get_time = &ptls_get_time;
  SRV_TLS.key_exchanges = ptls_openssl_key_exchanges;
  SRV_TLS.cipher_suites = ptls_openssl_cipher_suites;
  SRV_TLS.certificates.list = &SRV_CERT, SRV_TLS.certificates.count = 1;
  SRV_TLS.sign_certificate = &SRV_SIGN.super;
  quic_ctx_init(&QX, &SRV_TLS);
}

/* --------------------------------------------- client --------------------------------------------- */
static ptls_context_t CLI_TLS;
typedef struct {
  ngtcp2_conn *conn;
  ngtcp2_crypto_conn_ref ref;
  ngtcp2_crypto_picotls_ctx cptls;
  nghttp3_conn *h3;
  int ready, nreq, submitted, done, ok, failed, key_updates;
  long body, want_body;
  size_t upload[512];
  ngtcp2_path_storage ps;
} client;
static client *CLI;

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *r) { return ((client *)r->user_data)->conn; }
static void c_rand(uint8_t *dest, size_t n, const ngtcp2_rand_ctx *rc) { (void)rc; for (size_t i = 0; i < n; i++) dest[i] = (uint8_t)rnd(); }
static int c_new_cid(ngtcp2_conn *c, ngtcp2_cid *cid, ngtcp2_stateless_reset_token *tok, size_t len, void *u) {
  (void)c, (void)u;
  c_rand(cid->data, len, NULL), cid->datalen = len;
  c_rand(tok->data, sizeof tok->data, NULL);
  return 0;
}
static int h_header(nghttp3_conn *c, int64_t sid, int32_t tok, nghttp3_rcbuf *n, nghttp3_rcbuf *v, uint8_t fl, void *u, void *su) {
  (void)c, (void)sid, (void)tok, (void)fl, (void)su;
  client *cl = u;
  nghttp3_vec nn = nghttp3_rcbuf_get_buf(n), vv = nghttp3_rcbuf_get_buf(v);
  if (nn.len == 7 && !memcmp(nn.base, ":status", 7) && vv.len == 3 && !memcmp(vv.base, "200", 3)) cl->ok++;
  return 0;
}
static int h_data(nghttp3_conn *c, int64_t sid, const uint8_t *d, size_t n, void *u, void *su) {
  (void)c, (void)d, (void)su;
  client *cl = u;
  cl->body += (long)n;
  ngtcp2_conn_extend_max_stream_offset(cl->conn, sid, n);
  ngtcp2_conn_extend_max_offset(cl->conn, n);
  return 0;
}
static int h_deferred(nghttp3_conn *c, int64_t sid, size_t n, void *u, void *su) {
  (void)c, (void)su;
  client *cl = u;
  ngtcp2_conn_extend_max_stream_offset(cl->conn, sid, n);
  ngtcp2_conn_extend_max_offset(cl->conn, n);
  return 0;
}
static int h_end(nghttp3_conn *c, int64_t sid, void *u, void *su) {
  (void)c, (void)sid, (void)su;
  client *cl = u;
  cl->done++;
  return 0;
}
static int h_acked(nghttp3_conn *c, int64_t sid, uint64_t n, void *u, void *su) { (void)c, (void)sid, (void)n, (void)u, (void)su; return 0; }
static nghttp3_ssize h_body(nghttp3_conn *c, int64_t sid, nghttp3_vec *vec, size_t veccnt, uint32_t *fl, void *u, void *su) {
  (void)c, (void)veccnt, (void)su;
  client *cl = u;
  static uint8_t chunk[16384];
  size_t *left = &cl->upload[(sid / 4) % 512], m = *left < sizeof chunk ? *left : sizeof chunk;
  memset(chunk, 'u', m);
  vec[0].base = chunk, vec[0].len = m;
  *left -= m;
  if (!*left) *fl |= NGHTTP3_DATA_FLAG_EOF;
  return 1;
}
static void submit_more(client *cl) {
  while (cl->submitted < cl->nreq && cl->submitted - cl->done < 50) {
    int64_t sid;
    if (ngtcp2_conn_open_bidi_stream(cl->conn, &sid, NULL)) return;
    int k = (int)(rnd() % 3);
    char path[64];
    if (k == 2) {
      size_t big = 1000 + rnd() % 200000;
      snprintf(path, sizeof path, "/big/%zu", big), cl->want_body += (long)big;
    } else snprintf(path, sizeof path, "/p/%d", cl->submitted), cl->want_body += k == 1 ? 7 : 13;
    nghttp3_nv nv[5] = {{(uint8_t *)":method", (uint8_t *)(k == 1 ? "POST" : "GET"), 7, k == 1 ? 4u : 3u, 0},
                        {(uint8_t *)":scheme", (uint8_t *)"https", 7, 5, 0},
                        {(uint8_t *)":authority", (uint8_t *)"localhost", 10, 9, 0},
                        {(uint8_t *)":path", (uint8_t *)path, 5, strlen(path), 0},
                        {(uint8_t *)"user-agent", (uint8_t *)"ngtcp2-test", 10, 11, 0}};
    cl->upload[(sid / 4) % 512] = 1 + rnd() % 30000;
    nghttp3_data_reader dr = {h_body};
    if (nghttp3_conn_submit_request(cl->h3, sid, nv, 5, k == 1 ? &dr : NULL, NULL)) { cl->failed = 1; return; }
    cl->submitted++;
  }
}
static int c_handshake_done(ngtcp2_conn *c, void *u) {
  client *cl = u;
  nghttp3_callbacks cb = {0};
  cb.recv_header = h_header, cb.recv_data = h_data, cb.deferred_consume = h_deferred, cb.end_stream = h_end, cb.acked_stream_data = h_acked;
  nghttp3_settings st;
  nghttp3_settings_default(&st);
  st.qpack_max_dtable_capacity = 4096, st.qpack_blocked_streams = 0;
  if (nghttp3_conn_client_new(&cl->h3, &cb, &st, nghttp3_mem_default(), cl)) return NGTCP2_ERR_CALLBACK_FAILURE;
  int64_t ctrl, enc, dec;
  if (ngtcp2_conn_open_uni_stream(c, &ctrl, NULL) || ngtcp2_conn_open_uni_stream(c, &enc, NULL) || ngtcp2_conn_open_uni_stream(c, &dec, NULL))
    return NGTCP2_ERR_CALLBACK_FAILURE;
  nghttp3_conn_bind_control_stream(cl->h3, ctrl);
  nghttp3_conn_bind_qpack_streams(cl->h3, enc, dec);
  cl->ready = 1;
  submit_more(cl);
  return 0;
}
static int c_recv_stream(ngtcp2_conn *c, uint32_t fl, int64_t sid, uint64_t off, const uint8_t *d, size_t n, void *u, void *su) {
  (void)c, (void)off, (void)su;
  client *cl = u;
  if (!cl->h3) return 0;
  nghttp3_ssize r = nghttp3_conn_read_stream(cl->h3, sid, d, n, fl & NGTCP2_STREAM_DATA_FLAG_FIN);
  if (r < 0) { printf("client h3 read: %s\n", nghttp3_strerror((int)r)); return NGTCP2_ERR_CALLBACK_FAILURE; }
  ngtcp2_conn_extend_max_stream_offset(cl->conn, sid, (uint64_t)r);
  ngtcp2_conn_extend_max_offset(cl->conn, (uint64_t)r);
  return 0;
}
static int c_acked(ngtcp2_conn *c, int64_t sid, uint64_t off, uint64_t n, void *u, void *su) {
  (void)c, (void)off, (void)su;
  client *cl = u;
  return cl->h3 && nghttp3_conn_add_ack_offset(cl->h3, sid, n) ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}
static int c_stream_close(ngtcp2_conn *c, uint32_t fl, int64_t sid, uint64_t code, void *u, void *su) {
  (void)c, (void)su;
  client *cl = u;
  if (!(fl & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET)) code = NGHTTP3_H3_NO_ERROR;
  if (cl->h3) nghttp3_conn_close_stream(cl->h3, sid, code);
  return 0;
}
static int c_extend_bidi(ngtcp2_conn *c, uint64_t max, void *u) { (void)c, (void)max; client *cl = u; if (cl->ready) submit_more(cl); return 0; }
static int c_stream_reset(ngtcp2_conn *c, int64_t sid, uint64_t fs, uint64_t code, void *u, void *su) {
  (void)c, (void)sid, (void)fs, (void)su;
  client *cl = u;
  printf("client: stream %lld reset by server, code 0x%llx\n", (long long)sid, (unsigned long long)code);
  cl->failed = 1;
  return 0;
}

static void ng_log(void *u, const char *fmt, ...) {
  (void)u;
  va_list ap;
  va_start(ap, fmt);
  vprintf(fmt, ap);
  va_end(ap);
  printf("\n");
}
static void client_init(client *cl) {
  memset(cl, 0, sizeof *cl);
  memset(&CLI_TLS, 0, sizeof CLI_TLS);
  CLI_TLS.random_bytes = ptls_openssl_random_bytes;
  CLI_TLS.get_time = &ptls_get_time;
  CLI_TLS.key_exchanges = ptls_openssl_key_exchanges;
  CLI_TLS.cipher_suites = ptls_openssl_cipher_suites;
  ngtcp2_crypto_picotls_configure_client_context(&CLI_TLS);
  ngtcp2_callbacks cb = {0};
  cb.client_initial = ngtcp2_crypto_client_initial_cb, cb.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
  cb.encrypt = ngtcp2_crypto_encrypt_cb, cb.decrypt = ngtcp2_crypto_decrypt_cb, cb.hp_mask = ngtcp2_crypto_hp_mask_cb;
  cb.recv_retry = ngtcp2_crypto_recv_retry_cb, cb.update_key = ngtcp2_crypto_update_key_cb;
  cb.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb, cb.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
  cb.version_negotiation = ngtcp2_crypto_version_negotiation_cb, cb.get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb;
  cb.rand = c_rand, cb.get_new_connection_id2 = c_new_cid, cb.handshake_completed = c_handshake_done;
  cb.recv_stream_data = c_recv_stream, cb.acked_stream_data_offset = c_acked, cb.stream_close = c_stream_close;
  cb.extend_max_local_streams_bidi = c_extend_bidi, cb.stream_reset = c_stream_reset;
  ngtcp2_cid dcid, scid;
  dcid.datalen = 18, scid.datalen = 8;
  c_rand(dcid.data, dcid.datalen, NULL), c_rand(scid.data, scid.datalen, NULL);
  ngtcp2_settings st;
  ngtcp2_settings_default(&st);
  st.initial_ts = NOW_NS;
  if (getenv("NGLOG")) st.log_printf = ng_log;
  ngtcp2_transport_params tp;
  ngtcp2_transport_params_default(&tp);
  tp.initial_max_streams_uni = 3, tp.initial_max_stream_data_bidi_local = 256 * 1024, tp.initial_max_stream_data_uni = 256 * 1024;
  tp.initial_max_data = 4 * 1024 * 1024;
  static struct sockaddr_in la, ra;
  la.sin_family = ra.sin_family = AF_INET, la.sin_port = htons(5555), ra.sin_port = htons(443);
  ngtcp2_path path = {{(struct sockaddr *)&la, sizeof la}, {(struct sockaddr *)&ra, sizeof ra}, NULL};
  if (ngtcp2_conn_client_new(&cl->conn, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1, &cb, &st, &tp, NULL, cl)) { printf("client_new\n"); exit(1); }
  ngtcp2_path_storage_init(&cl->ps, path.local.addr, path.local.addrlen, path.remote.addr, path.remote.addrlen, NULL);
  cl->ref.get_conn = get_conn, cl->ref.user_data = cl;
  ngtcp2_crypto_picotls_ctx_init(&cl->cptls);
  cl->cptls.ptls = ptls_client_new(&CLI_TLS);
  *ptls_get_data_ptr(cl->cptls.ptls) = &cl->ref;
  static ptls_raw_extension_t exts[2];
  exts[0] = (ptls_raw_extension_t){0, {NULL, 0}}, exts[1] = (ptls_raw_extension_t){UINT16_MAX, {NULL, 0}};
  cl->cptls.handshake_properties.additional_extensions = exts; /* ngtcp2 fills exts[0] with its transport parameters */
  ngtcp2_crypto_picotls_configure_client_session(&cl->cptls, cl->conn);
  static ptls_iovec_t alpn = {(uint8_t *)"h3", 2};
  cl->cptls.handshake_properties.client.negotiated_protocols.list = &alpn;
  cl->cptls.handshake_properties.client.negotiated_protocols.count = 1;
  ptls_set_server_name(cl->cptls.ptls, "localhost", 9);
  ngtcp2_conn_set_tls_native_handle(cl->conn, &cl->cptls);
}

/* everything the client wants to send now */
static int client_write(client *cl) {
  uint8_t buf[1500];
  for (int guard = 0; guard < 10000; guard++) {
    int64_t sid = -1;
    int fin = 0;
    nghttp3_vec vec[16];
    nghttp3_ssize nv = 0;
    if (cl->h3) {
      nv = nghttp3_conn_writev_stream(cl->h3, &sid, &fin, vec, 16);
      if (nv < 0) { printf("client writev_stream: %s\n", nghttp3_strerror((int)nv)); return -1; }
    }
    ngtcp2_ssize ndata = -1;
    ngtcp2_pkt_info pi;
    uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE | (fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0);
    ngtcp2_ssize w = ngtcp2_conn_writev_stream(cl->conn, &cl->ps.path, &pi, buf, 1252, &ndata, flags, sid, (ngtcp2_vec *)vec, (size_t)nv, NOW_NS);
    if (w < 0) {
      if (w == NGTCP2_ERR_STREAM_DATA_BLOCKED) { nghttp3_conn_block_stream(cl->h3, sid); continue; }
      if (w == NGTCP2_ERR_STREAM_SHUT_WR) { nghttp3_conn_shutdown_stream_write(cl->h3, sid); continue; }
      if (w == NGTCP2_ERR_WRITE_MORE) { nghttp3_conn_add_write_offset(cl->h3, sid, (size_t)ndata); continue; }
      printf("client write: %s\n", ngtcp2_strerror((int)w));
      return -1;
    }
    if (ndata >= 0 && cl->h3) nghttp3_conn_add_write_offset(cl->h3, sid, (size_t)ndata);
    if (!w) return 0;
    put(&TO_SRV, buf, (size_t)w);
  }
  return 0;
}

/* --------------------------------------------- one run --------------------------------------------- */
static int run(int nreq, int loss, int reorder) {
  LOSS = loss, REORDER = reorder, BLACKHOLE_UNTIL = 0;
  TO_SRV.n = TO_CLI.n = 0;
  static client cl;
  static server sv;
  CLI = &cl, SRV = &sv;
  client_init(&cl);
  cl.nreq = nreq;
  memset(&sv, 0, sizeof sv);
  int accepted = 0;
  long before = fails;
  uint8_t out[1500];
  uint64_t start = NOW_NS;
  TO_SRV_BYTES = TO_CLI_BYTES = 0;
  int amp_ok = 1;
  for (int guard = 0; guard < 2000000; guard++) {
    if (cl.ready) submit_more(&cl); /* keep up to 50 requests in flight */
    if (cl.ready && cl.done >= cl.nreq / 3 && cl.key_updates == 0 && !ngtcp2_conn_initiate_key_update(cl.conn, NOW_NS)) cl.key_updates++;
    if (client_write(&cl)) { CHECK(0, "client write failed"); break; }
    dgram g;
    while (take(&TO_SRV, &g)) {
      if (!accepted || !sv.q.addr_validated) TO_SRV_BYTES += g.n;
      if (!accepted) {
        int r = quic_accept(&sv.q, &QX, g.d, g.n, now_ms(), &QCB, &sv);
        if (r == 0) accepted = 1;
        continue;
      }
      quic_recv(&sv.q, g.d, g.n, now_ms());
    }
    if (accepted) {
      size_t n;
      while ((n = quic_send(&sv.q, out, sizeof out, now_ms())) > 0) {
        if (getenv("DUMP")) {
          printf("srv dgram %zu:", n);
          for (size_t o = 0; o < n;) {
            printf(" [%02x", out[o]);
            if (!(out[o] & 0x80)) { printf(" short %zu]", n - o); break; }
            size_t q = o + 5, dl = out[q++]; q += dl; size_t sl = out[q++]; q += sl;
            if (((out[o] >> 4) & 3) == 0) q++;
            size_t len = ((out[q] & 0x3f) << 8) | out[q + 1]; q += 2;
            printf(" long type %d len %zu]", (out[o] >> 4) & 3, len);
            o = q + len;
          }
          printf("\n");
        }
        if (!sv.q.addr_validated) {
          TO_CLI_BYTES += n;
          if (TO_CLI_BYTES > 3 * TO_SRV_BYTES) amp_ok = 0; /* RFC 9000 §8.1 */
        }
        put(&TO_CLI, out, n);
      }
    }
    while (take(&TO_CLI, &g)) {
      ngtcp2_pkt_info pi = {0};
      int r = ngtcp2_conn_read_pkt(cl.conn, &cl.ps.path, &pi, g.d, g.n, NOW_NS);
      if (r) { printf("client read_pkt: %s\n", ngtcp2_strerror(r)); cl.failed = 1; break; }
    }
    if (cl.failed || (accepted && (sv.q.closing || sv.q.draining))) break;
    if (cl.done == nreq && cl.submitted == nreq) break;
    /* advance time to the next event if nothing is ready now */
    if ((!TO_SRV.n && !TO_CLI.n) || next_arrival() > NOW_NS) {
      uint64_t t = next_arrival();
      ngtcp2_tstamp ce = ngtcp2_conn_get_expiry2(cl.conn);
      if (ce < t) t = ce;
      if (accepted) {
        int64_t se = quic_timeout(&sv.q);
        if (se != INT64_MAX && (uint64_t)se * 1000000ull < t) t = (uint64_t)se * 1000000ull;
      }
      if (t == UINT64_MAX || t <= NOW_NS) t = NOW_NS + 1000000;
      NOW_NS = t;
      if (ngtcp2_conn_get_expiry2(cl.conn) <= NOW_NS) ngtcp2_conn_handle_expiry(cl.conn, NOW_NS);
      if (accepted && quic_timeout(&sv.q) <= now_ms()) quic_on_timeout(&sv.q, now_ms());
    }
    if (NOW_NS - start > 120ull * 1000000000ull) { CHECK(0, "run took > 120 simulated seconds"); break; }
  }
  if (cl.done != nreq && accepted) { /* what is stuck */
    quic_conn *q = &sv.q;
    printf("  stuck: in_flight %llu cwnd %llu pto_count %u probes %u | max_data_peer %llu data_sent %llu | nsent %u %u %u\n",
           (unsigned long long)q->bytes_in_flight, (unsigned long long)q->cwnd, q->pto_count, q->probes_due,
           (unsigned long long)q->max_data_peer, (unsigned long long)q->data_sent, q->sp[0].nsent, q->sp[1].nsent, q->sp[2].nsent);
    int shown = 0;
    for (int i = 0; i < QUIC_MAX_STREAMS && shown < 8; i++) {
      quic_stream *st = &q->s[i];
      if (!st->used) continue;
      shown++;
      printf("    sid %llu: out base %llu len %zu sent %llu max_send %llu fin %d/%d/%d lost %d | in base %llu contig %llu fin %llu done %d/%d\n",
             (unsigned long long)st->id, (unsigned long long)st->out.base, st->out.len, (unsigned long long)st->out.sent,
             (unsigned long long)st->max_send, st->out.fin, st->out.fin_sent, st->out.fin_acked, st->out.lost.n,
             (unsigned long long)st->in.base, (unsigned long long)st->in.contig, (unsigned long long)st->in.fin, st->recv_done, st->send_done);
      h3_stream *hs = h3__find(&sv.h, st->id);
      if (!(st->id & 3)) printf("      h3: %s flags 0x%x data_left %llu skip %llu\n", hs ? "active" : "none", hs ? hs->flags : 0,
                                 hs ? (unsigned long long)hs->data_left : 0ull, hs ? (unsigned long long)hs->skip_left : 0ull);
    }
    uint64_t ids[64];
    int np = h3_pending(&sv.h, ids, 64);
    printf("    h3 pending %d, h3 requests %ld closes %ld | client submitted %d done %d bidi_left %llu, server max_streams_bidi %llu opened %llu send_flag %d\n",
           np, sv.requests, sv.closes, cl.submitted, cl.done, (unsigned long long)ngtcp2_conn_get_streams_bidi_left(cl.conn),
           (unsigned long long)q->max_streams_bidi_local, (unsigned long long)q->opened_bidi, q->send_max_streams_bidi);
  }
  CHECK(accepted && sv.h3_ready, "handshake (loss %d%%)", loss);
  CHECK(amp_ok, "anti-amplification: %llu bytes sent for %llu received before validation", (unsigned long long)TO_CLI_BYTES,
        (unsigned long long)TO_SRV_BYTES);
  CHECK(cl.key_updates == 1 && sv.q.key_phase == 1, "client key update seen by the server (phase %d)", sv.q.key_phase);
  CHECK(sv.q.undecryptable == 0, "%llu packets failed to decrypt (nothing on this network corrupts them)", (unsigned long long)sv.q.undecryptable);
  CHECK(!cl.failed && cl.done == nreq && cl.ok == nreq, "loss %d%%: %d/%d done, %d x 200", loss, cl.done, nreq, cl.ok);
  CHECK(cl.body == cl.want_body, "loss %d%%: body %ld want %ld", loss, cl.body, cl.want_body);
  CHECK(!sv.q.closing && !sv.q.draining, "server closed the connection: code 0x%llx frame 0x%llx", (unsigned long long)sv.q.close_code,
        (unsigned long long)sv.q.close_frame);
  CHECK(sv.errors == 0, "server stream errors %ld", sv.errors);
  printf("  loss %2d%% reorder %d: %d requests, %.1f simulated s, %ld datagrams (%ld lost), cwnd %llu, srtt %lld ms\n", loss, reorder, nreq,
         (NOW_NS - start) / 1e9, SENT_DGRAMS, LOST_DGRAMS, (unsigned long long)sv.q.cwnd, (long long)sv.q.smoothed_rtt);
  SENT_DGRAMS = LOST_DGRAMS = 0;
  if (cl.h3) nghttp3_conn_del(cl.h3);
  ngtcp2_conn_del(cl.conn);
  ngtcp2_crypto_picotls_deconfigure_session(&cl.cptls);
  ptls_free(cl.cptls.ptls);
  if (accepted) quic_free(&sv.q);
  return fails == before;
}

int main(int argc, char **argv) {
  for (int i = 0; i < 1000; i++) BIG[i] = (uint8_t)i;
  server_init();
  printf("sizeof(quic_conn) = %zu\n", sizeof(quic_conn));
  if (argc > 1) { run(100, atoi(argv[1]), 1); }
  else
    for (long r = 0; r < scale(); r++) {
      run(50, 0, 0);
      run(150, 0, 0); /* beyond the initial 100 streams: MAX_STREAMS credit */
      run(100, 0, 1);
      run(100, 2, 1);
      run(60, 10, 1);
      BLACKHOLE = 1; /* the server retransmits its first flight while the client is silent: 3x limit */
      run(20, 0, 0);
      BLACKHOLE = 0;
    }
  printf("%s: %ld failures / %ld checks\n", fails ? "FAILED" : "PASS", fails, checks);
  return fails != 0;
}
