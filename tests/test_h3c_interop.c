/* The client side of include/quic.h + include/h3.h against ngtcp2 + nghttp3's server (picotls on both sides), in
 * memory, over test_quic_interop.c's simulated network (latency, loss, reordering, duplicates, a simulated clock).
 *   - each run: handshake, then N requests (GETs, POSTs with bodies, large responses, HEAD, 204) from our client;
 *     every status, body length and stream end is checked; neither side may fail the connection, and our client
 *     must confirm the handshake (HANDSHAKE_DONE from ngtcp2).
 * Usage: test_h3c_interop [loss_percent]. FUZZ=N scales the runs. NGLOG=1 prints ngtcp2's log. */
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
#include <arpa/inet.h>
#include <netinet/in.h>

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
static uint64_t rs = 0xa4093822299f31d0ull;
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

/* ------------------------------------------- clock / net ------------------------------------------- */
static uint64_t NOW_NS = 1000000000ull;
static int64_t now_ms(void) { return (int64_t)(NOW_NS / 1000000); }
typedef struct {
  uint8_t d[1500];
  size_t n;
  uint64_t at, seq;
} dgram;
static uint64_t SEQ;
typedef struct {
  dgram q[4096];
  int n;
} wire;
static wire TO_SRV, TO_CLI;
static int LOSS, REORDER, BLACKHOLE; /* BLACKHOLE: drop client->server after its first datagram, for 8 s */
static uint64_t BLACKHOLE_UNTIL;
static long SENT_DGRAMS, LOST_DGRAMS, DUPS_TO_CLI;

static void put(wire *w, const uint8_t *d, size_t n) {
  SENT_DGRAMS++;
  if (BLACKHOLE && w == &TO_SRV) {
    if (!BLACKHOLE_UNTIL) BLACKHOLE_UNTIL = NOW_NS + 8000000000ull; /* the first datagram goes through; 3 PTO rounds */
    else if (NOW_NS < BLACKHOLE_UNTIL) {
      LOST_DGRAMS++;
      return;
    }
  }
  if ((int)(rnd() % 100) < LOSS) {
    LOST_DGRAMS++;
    return;
  }
  if (REORDER && rnd() % 100 == 0 && w->n < 4095) { /* a duplicate */
    if (w == &TO_CLI) DUPS_TO_CLI++;
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
    if (w->q[i].at <= NOW_NS &&
        (best < 0 || w->q[i].at < w->q[best].at || (w->q[i].at == w->q[best].at && w->q[i].seq < w->q[best].seq)))
      best = i;
  if (best < 0) return 0;
  *out = w->q[best];
  w->q[best] = w->q[--w->n];
  return 1;
}
static uint64_t next_arrival(void) {
  uint64_t t = UINT64_MAX;
  for (int i = 0; i < TO_SRV.n; i++)
    if (TO_SRV.q[i].at < t) t = TO_SRV.q[i].at;
  for (int i = 0; i < TO_CLI.n; i++)
    if (TO_CLI.q[i].at < t) t = TO_CLI.q[i].at;
  return t;
}

/* ---------------------------------------- ngtcp2 + nghttp3 server ---------------------------------------- */
static ptls_context_t NG_TLS;
static ptls_openssl_sign_certificate_t SRV_SIGN;
static ptls_iovec_t SRV_CERT;
static uint8_t BIG[1 << 20];
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
typedef struct {
  char path[64];
  int head, post, responded;
  size_t left; /* body bytes still to give nghttp3 */
  const uint8_t *body;
} sreq;
typedef struct {
  ngtcp2_conn *conn;
  ngtcp2_crypto_conn_ref ref;
  ngtcp2_crypto_picotls_ctx cptls;
  nghttp3_conn *h3;
  ngtcp2_path_storage ps;
  ptls_raw_extension_t exts[2];
  long requests, failed;
  sreq r[4096];
} ngsrv;
static ngsrv *NS;
static ngtcp2_conn *ng_get_conn(ngtcp2_crypto_conn_ref *r) { return ((ngsrv *)r->user_data)->conn; }
static void ng_rand(uint8_t *dest, size_t n, const ngtcp2_rand_ctx *rc) {
  (void)rc;
  for (size_t i = 0; i < n; i++) dest[i] = (uint8_t)rnd();
}
static int ng_new_cid(ngtcp2_conn *c, ngtcp2_cid *cid, ngtcp2_stateless_reset_token *tok, size_t len, void *u) {
  (void)c, (void)u;
  ng_rand(cid->data, len, NULL), cid->datalen = len;
  ng_rand(tok->data, sizeof tok->data, NULL);
  return 0;
}
static int och_h3(ptls_on_client_hello_t *self, ptls_t *tls, ptls_on_client_hello_parameters_t *p) {
  (void)self;
  for (size_t i = 0; i < p->negotiated_protocols.count; i++)
    if (p->negotiated_protocols.list[i].len == 2 && !memcmp(p->negotiated_protocols.list[i].base, "h3", 2))
      return ptls_set_negotiated_protocol(tls, "h3", 2);
  return PTLS_ALERT_NO_APPLICATION_PROTOCOL;
}
static ptls_on_client_hello_t OCH = { och_h3 };
static nghttp3_ssize s_body(nghttp3_conn *c, int64_t sid, nghttp3_vec *vec, size_t veccnt, uint32_t *fl, void *u,
                            void *su) {
  (void)c, (void)veccnt, (void)su;
  ngsrv *s = u;
  sreq *r = &s->r[(sid >> 2) % 4096];
  size_t m = r->left < 16384 ? r->left : 16384;
  vec[0].base = (uint8_t *)r->body, vec[0].len = m;
  r->body += m, r->left -= m;
  if (!r->left) *fl |= NGHTTP3_DATA_FLAG_EOF;
  return 1;
}
static void s_respond(ngsrv *s, int64_t sid) {
  sreq *r = &s->r[(sid >> 2) % 4096];
  if (r->responded) return;
  r->responded = 1, s->requests++;
  static const char *hello = "hello, world\n", *posted = "posted\n";
  const char *status = "200";
  r->body = (const uint8_t *)hello, r->left = 13;
  if (!strncmp(r->path, "/big/", 5)) r->body = BIG, r->left = (size_t)atoi(r->path + 5);
  else if (!strcmp(r->path, "/204")) status = "204", r->left = 0;
  else if (r->post) r->body = (const uint8_t *)posted, r->left = 7;
  char cl[24];
  snprintf(cl, sizeof cl, "%zu", r->left);
  if (r->head) r->left = 0;
  nghttp3_nv nv[3] = { { (uint8_t *)":status", (uint8_t *)status, 7, 3, 0 },
                       { (uint8_t *)"server", (uint8_t *)"nghttp3-test", 6, 12, 0 },
                       { (uint8_t *)"content-length", (uint8_t *)cl, 14, strlen(cl), 0 } };
  nghttp3_data_reader dr = { s_body };
  int n = !strcmp(status, "204") ? 2 : 3;
  if (nghttp3_conn_submit_response(s->h3, sid, nv, (size_t)n, r->left ? &dr : NULL)) s->failed++;
}
static int s_begin(nghttp3_conn *c, int64_t sid, void *u, void *su) {
  (void)c, (void)su;
  ngsrv *s = u;
  memset(&s->r[(sid >> 2) % 4096], 0, sizeof(sreq));
  return 0;
}
static int s_header(nghttp3_conn *c, int64_t sid, int32_t tok, nghttp3_rcbuf *n, nghttp3_rcbuf *v, uint8_t fl, void *u,
                    void *su) {
  (void)c, (void)tok, (void)fl, (void)su;
  ngsrv *s = u;
  sreq *r = &s->r[(sid >> 2) % 4096];
  nghttp3_vec nn = nghttp3_rcbuf_get_buf(n), vv = nghttp3_rcbuf_get_buf(v);
  if (nn.len == 5 && !memcmp(nn.base, ":path", 5) && vv.len < sizeof r->path) memcpy(r->path, vv.base, vv.len);
  if (nn.len == 7 && !memcmp(nn.base, ":method", 7))
    r->head = vv.len == 4 && !memcmp(vv.base, "HEAD", 4), r->post = vv.len == 4 && !memcmp(vv.base, "POST", 4);
  return 0;
}
static int s_end_headers(nghttp3_conn *c, int64_t sid, int fin, void *u, void *su) {
  (void)c, (void)fin, (void)su;
  ngsrv *s = u;
  if (!s->r[(sid >> 2) % 4096].post) s_respond(s, sid); /* a POST is answered at the end of its body */
  return 0;
}
static int s_data3(nghttp3_conn *c, int64_t sid, const uint8_t *d, size_t n, void *u, void *su) {
  (void)c, (void)d, (void)su;
  ngsrv *s = u;
  ngtcp2_conn_extend_max_stream_offset(s->conn, sid, n);
  ngtcp2_conn_extend_max_offset(s->conn, n);
  return 0;
}
static int s_deferred(nghttp3_conn *c, int64_t sid, size_t n, void *u, void *su) {
  (void)c, (void)su;
  ngsrv *s = u;
  ngtcp2_conn_extend_max_stream_offset(s->conn, sid, n);
  ngtcp2_conn_extend_max_offset(s->conn, n);
  return 0;
}
static int s_end_stream(nghttp3_conn *c, int64_t sid, void *u, void *su) {
  (void)c, (void)su;
  s_respond(u, sid);
  return 0;
}
static int s_acked3(nghttp3_conn *c, int64_t sid, uint64_t n, void *u, void *su) {
  (void)c, (void)sid, (void)n, (void)u, (void)su;
  return 0;
}
static int ng_handshake_done(ngtcp2_conn *c, void *u) {
  ngsrv *s = u;
  nghttp3_callbacks cb = { 0 };
  cb.begin_headers = s_begin, cb.recv_header = s_header, cb.end_headers = s_end_headers, cb.recv_data = s_data3,
  cb.deferred_consume = s_deferred, cb.end_stream = s_end_stream, cb.acked_stream_data = s_acked3;
  nghttp3_settings st;
  nghttp3_settings_default(&st);
  st.qpack_max_dtable_capacity = 4096, st.qpack_blocked_streams = 100;
  if (nghttp3_conn_server_new(&s->h3, &cb, &st, nghttp3_mem_default(), s)) return NGTCP2_ERR_CALLBACK_FAILURE;
  nghttp3_conn_set_max_client_streams_bidi(s->h3, 100);
  int64_t ctrl, enc, dec;
  if (ngtcp2_conn_open_uni_stream(c, &ctrl, NULL) || ngtcp2_conn_open_uni_stream(c, &enc, NULL) ||
      ngtcp2_conn_open_uni_stream(c, &dec, NULL))
    return NGTCP2_ERR_CALLBACK_FAILURE;
  nghttp3_conn_bind_control_stream(s->h3, ctrl);
  nghttp3_conn_bind_qpack_streams(s->h3, enc, dec);
  return 0;
}
static int ng_recv_stream(ngtcp2_conn *c, uint32_t fl, int64_t sid, uint64_t off, const uint8_t *d, size_t n, void *u,
                          void *su) {
  (void)c, (void)off, (void)su;
  ngsrv *s = u;
  if (!s->h3) return 0;
  nghttp3_ssize r = nghttp3_conn_read_stream(s->h3, sid, d, n, fl & NGTCP2_STREAM_DATA_FLAG_FIN);
  if (r < 0) {
    printf("ngtcp2 server h3 read: %s\n", nghttp3_strerror((int)r));
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  ngtcp2_conn_extend_max_stream_offset(s->conn, sid, (uint64_t)r);
  ngtcp2_conn_extend_max_offset(s->conn, (uint64_t)r);
  return 0;
}
static int ng_acked(ngtcp2_conn *c, int64_t sid, uint64_t off, uint64_t n, void *u, void *su) {
  (void)c, (void)off, (void)su;
  ngsrv *s = u;
  return s->h3 && nghttp3_conn_add_ack_offset(s->h3, sid, n) ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}
static int ng_stream_close(ngtcp2_conn *c, uint32_t fl, int64_t sid, uint64_t code, void *u, void *su) {
  (void)c, (void)su;
  ngsrv *s = u;
  if (!(fl & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET)) code = NGHTTP3_H3_NO_ERROR;
  if (s->h3) nghttp3_conn_close_stream(s->h3, sid, code);
  if (ngtcp2_is_bidi_stream(sid)) ngtcp2_conn_extend_max_streams_bidi(s->conn, 1);
  return 0;
}
static int ng_extend_remote_bidi(ngtcp2_conn *c, uint64_t max, void *u) {
  (void)c;
  ngsrv *s = u;
  if (s->h3) nghttp3_conn_set_max_client_streams_bidi(s->h3, max);
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
static void ng_server_tls_init(void) {
  make_cert();
  memset(&NG_TLS, 0, sizeof NG_TLS);
  NG_TLS.random_bytes = ptls_openssl_random_bytes;
  NG_TLS.get_time = &ptls_get_time;
  NG_TLS.key_exchanges = ptls_openssl_key_exchanges;
  NG_TLS.cipher_suites = ptls_openssl_cipher_suites;
  NG_TLS.certificates.list = &SRV_CERT, NG_TLS.certificates.count = 1;
  NG_TLS.sign_certificate = &SRV_SIGN.super;
  NG_TLS.on_client_hello = &OCH;
  ngtcp2_crypto_picotls_configure_server_context(&NG_TLS);
}
/* NG_RETRY: ngtcp2's server answers the first Initial with a Retry (ngtcp2_crypto_write_retry, its own tokens) */
static int NG_RETRY, NG_RETRIES;
static const uint8_t NG_SECRET[32] = "cursed-http interop retry secret";
static struct sockaddr_in NG_LA, NG_RA;
/* the first datagram: accept, then read it; 1 when a Retry went out instead (in *retry, *rn bytes) */
static int ng_accept(ngsrv *s, const uint8_t *d, size_t n, uint8_t *retry, size_t *rn) {
  ngtcp2_pkt_hd hd;
  if (ngtcp2_accept(&hd, d, n)) return -1;
  NG_LA.sin_family = NG_RA.sin_family = AF_INET, NG_LA.sin_port = htons(443), NG_RA.sin_port = htons(5555);
  ngtcp2_cid odcid = hd.dcid;
  int retried = 0;
  if (NG_RETRY && !hd.tokenlen) {
    ngtcp2_cid rscid;
    rscid.datalen = 8, ng_rand(rscid.data, 8, NULL);
    uint8_t tok[256];
    ngtcp2_ssize tl =
        ngtcp2_crypto_generate_retry_token(tok, NG_SECRET, sizeof NG_SECRET, hd.version, (struct sockaddr *)&NG_RA,
                                           sizeof NG_RA, &rscid, &hd.dcid, NOW_NS);
    ngtcp2_ssize w =
        tl < 0 ? -1 : ngtcp2_crypto_write_retry(retry, 1500, hd.version, &hd.scid, &rscid, &hd.dcid, tok, (size_t)tl);
    if (w < 0) return -1;
    *rn = (size_t)w, NG_RETRIES++;
    return 1;
  }
  if (NG_RETRY) {
    if (ngtcp2_crypto_verify_retry_token(&odcid, hd.token, hd.tokenlen, NG_SECRET, sizeof NG_SECRET, hd.version,
                                         (struct sockaddr *)&NG_RA, sizeof NG_RA, &hd.dcid, 10 * NGTCP2_SECONDS,
                                         NOW_NS))
      return -1;
    retried = 1;
  }
  ngtcp2_callbacks cb = { 0 };
  cb.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb,
  cb.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
  cb.encrypt = ngtcp2_crypto_encrypt_cb, cb.decrypt = ngtcp2_crypto_decrypt_cb, cb.hp_mask = ngtcp2_crypto_hp_mask_cb;
  cb.update_key = ngtcp2_crypto_update_key_cb, cb.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
  cb.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
  cb.get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb;
  cb.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
  cb.rand = ng_rand, cb.get_new_connection_id2 = ng_new_cid, cb.handshake_completed = ng_handshake_done;
  cb.recv_stream_data = ng_recv_stream, cb.acked_stream_data_offset = ng_acked, cb.stream_close = ng_stream_close;
  cb.extend_max_remote_streams_bidi = ng_extend_remote_bidi;
  ngtcp2_settings st;
  ngtcp2_settings_default(&st);
  st.initial_ts = NOW_NS;
  if (getenv("NGLOG")) st.log_printf = ng_log;
  ngtcp2_transport_params tp;
  ngtcp2_transport_params_default(&tp);
  tp.initial_max_streams_bidi = 100, tp.initial_max_streams_uni = 3;
  tp.initial_max_stream_data_bidi_local = tp.initial_max_stream_data_bidi_remote = 256 * 1024;
  tp.initial_max_stream_data_uni = 256 * 1024, tp.initial_max_data = 4 * 1024 * 1024;
  tp.original_dcid = odcid, tp.original_dcid_present = 1;
  if (retried) tp.retry_scid = hd.dcid, tp.retry_scid_present = 1;
  ngtcp2_cid scid;
  scid.datalen = 8, ng_rand(scid.data, 8, NULL);
  ngtcp2_path path = { { (struct sockaddr *)&NG_LA, sizeof NG_LA }, { (struct sockaddr *)&NG_RA, sizeof NG_RA }, NULL };
  if (ngtcp2_conn_server_new(&s->conn, &hd.scid, &scid, &path, hd.version, &cb, &st, &tp, NULL, s)) return -1;
  ngtcp2_path_storage_init(&s->ps, path.local.addr, path.local.addrlen, path.remote.addr, path.remote.addrlen, NULL);
  s->ref.get_conn = ng_get_conn, s->ref.user_data = s;
  ngtcp2_crypto_picotls_ctx_init(&s->cptls);
  s->cptls.ptls = ptls_server_new(&NG_TLS);
  *ptls_get_data_ptr(s->cptls.ptls) = &s->ref;
  s->exts[0] = (ptls_raw_extension_t){ 0, { NULL, 0 } }, s->exts[1] = (ptls_raw_extension_t){ UINT16_MAX, { NULL, 0 } };
  s->cptls.handshake_properties.additional_extensions = s->exts;
  if (ngtcp2_crypto_picotls_configure_server_session(&s->cptls)) return -1;
  ngtcp2_conn_set_tls_native_handle(s->conn, &s->cptls);
  ngtcp2_pkt_info pi = { 0 };
  return ngtcp2_conn_read_pkt(s->conn, &s->ps.path, &pi, d, n, NOW_NS) ? -1 : 0;
}
static int ng_write(ngsrv *s) {
  uint8_t buf[1500];
  for (int guard = 0; guard < 10000; guard++) {
    int64_t sid = -1;
    int fin = 0;
    nghttp3_vec vec[16];
    nghttp3_ssize nv = 0;
    if (s->h3) {
      nv = nghttp3_conn_writev_stream(s->h3, &sid, &fin, vec, 16);
      if (nv < 0) return -1;
    }
    ngtcp2_ssize ndata = -1;
    ngtcp2_pkt_info pi;
    uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE | (fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0);
    ngtcp2_ssize w = ngtcp2_conn_writev_stream(s->conn, &s->ps.path, &pi, buf, 1252, &ndata, flags, sid,
                                               (ngtcp2_vec *)vec, (size_t)nv, NOW_NS);
    if (w < 0) {
      if (w == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
        nghttp3_conn_block_stream(s->h3, sid);
        continue;
      }
      if (w == NGTCP2_ERR_STREAM_SHUT_WR) {
        nghttp3_conn_shutdown_stream_write(s->h3, sid);
        continue;
      }
      if (w == NGTCP2_ERR_WRITE_MORE) {
        nghttp3_conn_add_write_offset(s->h3, sid, (size_t)ndata);
        continue;
      }
      printf("ngtcp2 server write: %s\n", ngtcp2_strerror((int)w));
      return -1;
    }
    if (ndata >= 0 && s->h3) nghttp3_conn_add_write_offset(s->h3, sid, (size_t)ndata);
    if (!w) { /* done for now; ngtcp2 paces from here (its expiry says when it may write again) */
      ngtcp2_conn_update_pkt_tx_time(s->conn, NOW_NS);
      return 0;
    }
    put(&TO_CLI, buf, (size_t)w);
  }
  return 0;
}

/* ------------------------------------------ our client ------------------------------------------ */
static ptls_context_t CLI_TLS;
static quic_ctx CQX;
typedef struct {
  quic_conn q;
  h3_conn h;
  int ready, nreq, submitted, done, ok, failed, statuses_bad;
  long hdr_bytes, hdr_tail; /* request header frames: all, and the last quarter's */
  long body, want_body;
  int kind[4096];
  long want_s[4096], got_s[4096];
  size_t upload[4096];
  uint64_t up_off[4096];
} client;
static client *CLI;
static h3_scratch H3C;
static uint8_t UPBUF[1 << 16];
static int c_response(h3_conn *h, uint64_t sid, const h_response *r, int end, void *u) {
  (void)h, (void)end;
  client *cl = u;
  int k = cl->kind[(sid >> 2) % 4096];
  int want = k == 4 ? 204 : 200;
  if (r->status == want) cl->ok++;
  else cl->statuses_bad++;
  return 0;
}
static int c_data(h3_conn *h, uint64_t sid, const uint8_t *d, size_t n, int end, void *u) {
  (void)h, (void)sid, (void)d, (void)end;
  client *cl = u;
  cl->body += (long)n, cl->got_s[(sid >> 2) % 4096] += (long)n;
  return 0;
}
static void c_close(h3_conn *h, uint64_t sid, uint64_t err, void *u) {
  (void)h;
  client *cl = u;
  long ws = cl->want_s[(sid >> 2) % 4096], gs = cl->got_s[(sid >> 2) % 4096];
  if (!err && ws != gs) {
    printf("client: stream %llu (kind %d) body %ld want %ld\n", (unsigned long long)sid, cl->kind[(sid >> 2) % 4096],
           gs, ws);
    cl->failed = 1;
  }
  if (err) {
    printf("client: stream %llu closed with 0x%llx\n", (unsigned long long)sid, (unsigned long long)err);
    cl->failed = 1;
  }
  cl->done++;
}
static void c_reset(h3_conn *h, uint64_t sid, uint64_t code, void *u) {
  (void)h;
  quic_reset_stream(&((client *)u)->q, sid, code);
}
static const h3_callbacks H3CC = { NULL, c_data, NULL, NULL, c_close, c_reset, c_response };
static void submit_more(client *cl) {
  while (cl->submitted < cl->nreq && cl->submitted - cl->done < 50) {
    int64_t sid = quic_open_bidi(&cl->q);
    if (sid < 0) return; /* at the server's stream limit: MAX_STREAMS will raise it */
    int k = (int)(rnd() % 5);
    char *path = (char *)UPBUF + 60000 + (cl->submitted % 64) * 64;
    const char *m = k == 1 ? "POST" : k == 3 ? "HEAD" : "GET";
    long w = 0;
    if (k == 2) {
      size_t big = 1000 + rnd() % 200000;
      snprintf(path, 64, "/big/%zu", big), w = (long)big;
    } else if (k == 4) snprintf(path, 64, "/204");
    else snprintf(path, 64, "/p/%d", cl->submitted), w = k == 1 ? 7 : k == 3 ? 0 : 13;
    cl->want_body += w, cl->want_s[(sid >> 2) % 4096] = w, cl->got_s[(sid >> 2) % 4096] = 0;
    static char paths[4096][64];
    memcpy(paths[(sid >> 2) % 4096], path, 64);
    h_request rq = { 0 };
    rq.method = (const uint8_t *)m, rq.method_len = (uint32_t)strlen(m);
    rq.scheme = (const uint8_t *)"https", rq.scheme_len = 5, rq.authority = (const uint8_t *)"localhost",
    rq.authority_len = 9;
    rq.path = (const uint8_t *)paths[(sid >> 2) % 4096], rq.path_len = (uint32_t)strlen(path);
    static const hp_field ua = {
      (const uint8_t *)"user-agent", (const uint8_t *)"cursed-http-test", 10, 16, 0, 0, 0, 0
    };
    rq.fields = &ua, rq.nfields = 1;
    cl->kind[(sid >> 2) % 4096] = k;
    size_t up = k == 1 ? 1 + rnd() % 30000 : 0;
    if (h3_submit(&cl->h, (uint64_t)sid, &rq, up ? UPBUF : NULL, up, 1)) {
      cl->failed = 1;
      return;
    }
    long hb = h3__find(&cl->h, (uint64_t)sid)->hdr_len;
    cl->hdr_bytes += hb, cl->submitted++;
    if (cl->submitted > cl->nreq * 3 / 4) cl->hdr_tail += hb;
  }
}
static int64_t cq_on_stream(quic_conn *q, uint64_t sid, uint64_t off, const uint8_t *d, size_t len, int fin, void *u) {
  (void)q;
  client *cl = u;
  if (!cl->ready) return 0;
  int r = h3_recv(&cl->h, &H3C, sid, off, d, len, fin);
  uint64_t ub[H3_QPACK_BLOCKED]; /* streams whose QPACK inserts just arrived: their bytes again */
  for (int n; r >= 0 && (n = h3_unblocked(&cl->h, ub, H3_QPACK_BLOCKED)) > 0;)
    for (int i = 0; i < n; i++) quic_stream_redeliver(q, ub[i]);
  if (r < 0) return -(int64_t)h3_error(&cl->h);
  return r;
}
static size_t cq_send(quic_conn *q, uint64_t sid, uint8_t *out, size_t cap, int *fin, void *u) {
  (void)q;
  return h3_stream_send(&((client *)u)->h, sid, out, cap, fin);
}
static int cq_wants(quic_conn *q, uint64_t sid, void *u) {
  (void)q;
  return h3_stream_wants(&((client *)u)->h, sid);
}
static void cq_reset(quic_conn *q, uint64_t sid, uint64_t code, void *u) {
  (void)q;
  h3_peer_reset(&((client *)u)->h, sid, code);
}
static void cq_established(quic_conn *q, void *u) {
  client *cl = u;
  int64_t a = quic_open_uni(q), b = quic_open_uni(q), c = quic_open_uni(q);
  CHECK(a == 2 && b == 6 && c == 10, "client uni streams %lld %lld %lld", (long long)a, (long long)b, (long long)c);
  h3_init_client(&cl->h, &H3CC, cl, (uint64_t)a, (uint64_t)b, (uint64_t)c);
  cl->ready = 1;
  submit_more(cl);
}
static const quic_callbacks CQCB = { cq_on_stream, cq_send, cq_wants, cq_reset, cq_established, NULL };
static void client_tls_init(void) {
  memset(&CLI_TLS, 0, sizeof CLI_TLS);
  CLI_TLS.random_bytes = ptls_openssl_random_bytes;
  CLI_TLS.get_time = &ptls_get_time;
  CLI_TLS.key_exchanges = ptls_openssl_key_exchanges;
  CLI_TLS.cipher_suites = ptls_openssl_cipher_suites;
  quic_ctx_init(&CQX, &CLI_TLS); /* no verify_certificate: the test's self-signed server is accepted */
}

/* --------------------------------------------- one run --------------------------------------------- */
static int run(int nreq, int loss, int reorder) {
  LOSS = loss, REORDER = reorder, BLACKHOLE_UNTIL = 0;
  TO_SRV.n = TO_CLI.n = 0;
  static client cl;
  static ngsrv sv;
  CLI = &cl, NS = &sv;
  memset(&cl, 0, sizeof cl), memset(&sv, 0, sizeof sv);
  cl.nreq = nreq;
  int r0 = quic_connect(&cl.q, &CQX, "localhost", now_ms(), &CQCB, &cl);
  CHECK(r0 == 0, "quic_connect %d", r0);
  int accepted = 0, srv_failed = 0;
  long before = fails;
  uint8_t out[1500];
  uint64_t start = NOW_NS;
  for (int guard = 0; guard < 2000000; guard++) {
    if (cl.ready) submit_more(&cl);
    size_t n;
    while ((n = quic_send(&cl.q, out, sizeof out, now_ms())) > 0) put(&TO_SRV, out, n);
    dgram g;
    while (take(&TO_SRV, &g)) {
      if (!accepted) {
        uint8_t rt[1500];
        size_t rn = 0;
        int a = ng_accept(&sv, g.d, g.n, rt, &rn);
        if (a == 1) put(&TO_CLI, rt, rn);
        if (a == 0) accepted = 1;
        continue;
      }
      ngtcp2_pkt_info pi = { 0 };
      int r = ngtcp2_conn_read_pkt(sv.conn, &sv.ps.path, &pi, g.d, g.n, NOW_NS);
      if (r && r != NGTCP2_ERR_DRAINING) {
        printf("ngtcp2 server read_pkt: %s\n", ngtcp2_strerror(r));
        srv_failed = 1;
      }
    }
    if (accepted && ng_write(&sv)) srv_failed = 1;
    int got = 0;
    while (take(&TO_CLI, &g)) quic_recv(&cl.q, g.d, g.n, now_ms()), got = 1;
    if (got) { /* what that lets the client send (ACKs open its window) goes before time moves on, as a real loop does */
      if (cl.ready) submit_more(&cl);
      while ((n = quic_send(&cl.q, out, sizeof out, now_ms())) > 0) put(&TO_SRV, out, n);
    }
    if (srv_failed || cl.failed || cl.q.closing || cl.q.draining) break;
    if (cl.done == nreq && cl.submitted == nreq) break;
    if ((!TO_SRV.n && !TO_CLI.n) || next_arrival() > NOW_NS) {
      uint64_t t = next_arrival();
      int64_t ce = quic_timeout(&cl.q);
      if (ce != INT64_MAX && (uint64_t)ce * 1000000ull < t) t = (uint64_t)ce * 1000000ull;
      if (accepted) {
        ngtcp2_tstamp se = ngtcp2_conn_get_expiry2(sv.conn);
        if (se < t) t = se;
      }
      if (t == UINT64_MAX || t <= NOW_NS) t = NOW_NS + 1000000;
      NOW_NS = t;
      if (quic_timeout(&cl.q) <= now_ms()) quic_on_timeout(&cl.q, now_ms());
      if (accepted && ngtcp2_conn_get_expiry2(sv.conn) <= NOW_NS) ngtcp2_conn_handle_expiry(sv.conn, NOW_NS);
    }
    if (NOW_NS - start > 120ull * 1000000000ull) {
      CHECK(0, "run took > 120 simulated seconds");
      break;
    }
  }
  CHECK(accepted && cl.ready && !srv_failed,
        "handshake with ngtcp2 (loss %d%%): accepted %d client h3 %d server failed %d", loss, accepted, cl.ready,
        srv_failed);
  CHECK(!NG_RETRY || cl.q.retried, "the client followed ngtcp2's Retry");
  CHECK(cl.q.confirmed && cl.q.sp[QUIC_SP_INITIAL].discarded && cl.q.sp[QUIC_SP_HANDSHAKE].discarded,
        "client handshake confirmed by ngtcp2's HANDSHAKE_DONE");
  CHECK(!cl.failed && cl.done == nreq && cl.ok == nreq && !cl.statuses_bad,
        "loss %d%%: %d/%d done, %d right statuses, %d wrong", loss, cl.done, nreq, cl.ok, cl.statuses_bad);
  CHECK(cl.body == cl.want_body, "loss %d%%: body %ld want %ld", loss, cl.body, cl.want_body);
  CHECK(!cl.q.closing && !cl.q.draining, "client closed the connection: code 0x%llx frame 0x%llx (h3 0x%llx)",
        (unsigned long long)cl.q.close_code, (unsigned long long)cl.q.close_frame, (unsigned long long)h3_error(&cl.h));
  /* ngtcp2 sends 1-byte packet numbers when it may (RFC 9000 §17.1, sized by its largest acknowledged packet): with
   * reordering, a packet delayed more than 128 behind the newest we received cannot be placed and fails to decrypt,
   * as it should (it is retransmitted). Without reordering nothing may fail; with it, only a few */
  CHECK(sv.failed == 0 && (reorder ? cl.q.undecryptable * 20 <= (uint64_t)SENT_DGRAMS : cl.q.undecryptable == 0),
        "server failures %ld, client undecryptable %llu of %ld datagrams (duplicates injected %ld)", sv.failed,
        (unsigned long long)cl.q.undecryptable, SENT_DGRAMS, DUPS_TO_CLI);
  /* nghttp3's decoder takes a 4096-byte table and 100 blocked streams: inserts are referenced at once (once its
   * SETTINGS are in: a run's first 50 requests go before) */
  int tailn = nreq - nreq * 3 / 4;
  CHECK(nreq <= 50 || loss > 2 || (cl.h.qe.t.ins > 0 && cl.hdr_tail <= 16L * tailn),
        "QPACK: %u inserts, the last requests' headers %.1f bytes each", cl.h.qe.t.ins, (double)cl.hdr_tail / tailn);
  printf("  ngtcp2 server, loss %2d%% reorder %d: %d requests, %.1f simulated s, %ld datagrams (%ld lost), client cwnd "
         "%llu srtt %lld ms, request headers %.1f bytes each (%.1f at the end)\n",
         loss, reorder, nreq, (NOW_NS - start) / 1e9, SENT_DGRAMS, LOST_DGRAMS, (unsigned long long)cl.q.cwnd,
         (long long)cl.q.smoothed_rtt, (double)cl.hdr_bytes / nreq, (double)cl.hdr_tail / tailn);
  SENT_DGRAMS = LOST_DGRAMS = DUPS_TO_CLI = 0;
  quic_free(&cl.q);
  if (accepted) {
    if (sv.h3) nghttp3_conn_del(sv.h3);
    ngtcp2_conn_del(sv.conn);
    ngtcp2_crypto_picotls_deconfigure_session(&sv.cptls);
    ptls_free(sv.cptls.ptls);
  }
  return fails == before;
}

int main(int argc, char **argv) {
  for (int i = 0; i < (int)sizeof BIG; i++) BIG[i] = (uint8_t)i;
  ng_server_tls_init();
  client_tls_init();
  if (argc > 1) run(100, atoi(argv[1]), 1);
  else
    for (long r = 0; r < scale(); r++) {
      run(50, 0, 0);
      run(150, 0, 0); /* beyond ngtcp2's initial 100 bidi streams: its MAX_STREAMS credit */
      run(100, 0, 1);
      run(100, 2, 1);
      run(60, 10, 1);
      /* address validation first: ngtcp2's Retry, its token, retry_source_connection_id */
      NG_RETRY = 1, NG_RETRIES = 0, run(50, 0, 0), run(100, 2, 1), NG_RETRY = 0;
      CHECK(NG_RETRIES >= 2, "ngtcp2 sent %d Retry packets", NG_RETRIES);
    }
  printf("%s: %ld failures / %ld checks\n", fails ? "FAIL" : "PASS", fails, checks);
  return fails != 0;
}
