/* Raw QUIC (include/quic.h with an application protocol of our own, no HTTP/3): an echo protocol, ALPN "echo",
 * over the simulated network of test_quic_interop.c (latency, loss, reordering), in memory.
 *   - both sides open bidirectional streams: each sends a payload with a fin, the other echoes it back, every byte
 *     checked; streams opened by the server need the client to allow them (quic_ctx.max_streams_bidi)
 *   - ours against ours, ngtcp2's client against our server, and our client against ngtcp2's server (ngtcp2 has no
 *     HTTP layer either: what we send is raw QUIC to it)
 *   - ALPN: a server's own preference among what the client offers; no protocol in common fails the handshake
 * Usage: test_quic_raw. FUZZ=N scales the runs. */
#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "quic.h"
#include <picotls/openssl.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_picotls.h>

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
static uint64_t rs = 0x452821e638d01377ull;
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

/* ------------------------------------------ the network ------------------------------------------ */
static uint64_t NOW_NS = 1000000000ull;
static int64_t now_ms(void) { return (int64_t)(NOW_NS / 1000000); }
typedef struct {
  uint8_t d[1500];
  size_t n;
  uint64_t at, seq;
} dgram;
typedef struct {
  dgram q[4096];
  int n;
} wire;
static wire TO_SRV, TO_CLI;
static uint64_t SEQ;
static int LOSS, REORDER;
static void put(wire *w, const uint8_t *d, size_t n) {
  if ((int)(rnd() % 100) < LOSS || w->n == 4096 || n > 1500) return;
  dgram *g = &w->q[w->n++];
  memcpy(g->d, d, n), g->n = n, g->seq = SEQ++;
  g->at = NOW_NS + 10000000ull + (REORDER ? (rnd() % 8) * 3000000ull : 0); /* 10 ms one way, + jitter */
}
static int take(wire *w, dgram *out) {
  int best = -1;
  for (int i = 0; i < w->n; i++)
    if (w->q[i].at <= NOW_NS &&
        (best < 0 || w->q[i].at < w->q[best].at || (w->q[i].at == w->q[best].at && w->q[i].seq < w->q[best].seq)))
      best = i;
  if (best < 0) return 0;
  *out = w->q[best], w->q[best] = w->q[--w->n];
  return 1;
}
static uint64_t next_arrival(void) {
  uint64_t t = UINT64_MAX;
  for (int i = 0; i < TO_SRV.n; i++) t = TO_SRV.q[i].at < t ? TO_SRV.q[i].at : t;
  for (int i = 0; i < TO_CLI.n; i++) t = TO_CLI.q[i].at < t ? TO_CLI.q[i].at : t;
  return t;
}

/* -------------------------------------- the echo protocol -------------------------------------- */
/* a stream's payload, byte by byte, from its id and offset */
static uint8_t pay(int64_t sid, uint64_t off) { return (uint8_t)(sid * 131 + off * 7 + (off >> 8)); }
typedef struct {
  int64_t sid;
  int used, ours;      /* ours: we opened it, sent a payload, and check the echo */
  size_t len;          /* ours: the payload's length; else what we have received to echo */
  size_t sent, recv;   /* bytes given to the transport; bytes received */
  int fin_in, fin_out; /* the peer's fin arrived; ours went */
  uint8_t *buf;        /* the bytes to send (payload, or the echo) */
  size_t cap;
} est;
typedef struct {
  est s[64];
  int opened, open_target; /* streams we open */
  int done, bad;           /* ours echoed back correctly; byte or framing errors */
} echo;
static est *e_find(echo *e, int64_t sid, int create) {
  for (int i = 0; i < 64; i++)
    if (e->s[i].used && e->s[i].sid == sid) return &e->s[i];
  if (!create) return NULL;
  for (int i = 0; i < 64; i++)
    if (!e->s[i].used) {
      memset(&e->s[i], 0, sizeof e->s[i]), e->s[i].used = 1, e->s[i].sid = sid;
      return &e->s[i];
    }
  return NULL;
}
static void e_open(echo *e, int64_t sid) { /* a stream of ours: its payload, then a fin */
  est *s = e_find(e, sid, 1);
  s->ours = 1, s->len = 1 + rnd() % 60000, s->cap = s->len, s->buf = malloc(s->len);
  for (size_t i = 0; i < s->len; i++) s->buf[i] = pay(sid, i);
  e->opened++;
}
/* bytes in on sid at off: checked (ours) or kept to echo (the peer's); 0, or -1 if they are wrong */
static int e_in(echo *e, int64_t sid, uint64_t off, const uint8_t *d, size_t n, int fin) {
  est *s = e_find(e, sid, 1);
  if (!s || off != s->recv) return e->bad++, -1;
  if (s->ours) {
    for (size_t i = 0; i < n; i++)
      if (d[i] != pay(sid, off + i)) return e->bad++, -1;
  } else {
    if (s->len + n > s->cap) s->cap = (s->len + n) * 2 + 4096, s->buf = realloc(s->buf, s->cap);
    memcpy(s->buf + s->len, d, n), s->len += n;
  }
  s->recv += n;
  if (fin) {
    s->fin_in = 1;
    if (s->ours) {
      if (s->recv != s->len) return e->bad++, -1;
      e->done++;
    }
  }
  return 0;
}
/* what is still to send on s: [sent, len), and whether the fin is due after it */
static int e_fin_due(const est *s) { return !s->fin_out && (s->ours || s->fin_in); }
static void e_free(echo *e) {
  for (int i = 0; i < 64; i++) free(e->s[i].buf);
  memset(e, 0, sizeof *e);
}

/* ------------------------------------------ TLS contexts ------------------------------------------ */
static ptls_context_t SRV_TLS, CLI_TLS, NG_SRV_TLS, NG_CLI_TLS;
static ptls_openssl_sign_certificate_t SIGN;
static ptls_iovec_t CERT;
static void make_cert(void) {
  EVP_PKEY *pk = EVP_EC_gen("P-256");
  X509 *x = X509_new();
  X509_set_version(x, 2), ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
  X509_gmtime_adj(X509_getm_notBefore(x), -3600), X509_gmtime_adj(X509_getm_notAfter(x), 3600);
  X509_set_pubkey(x, pk);
  X509_NAME *nm = X509_get_subject_name(x);
  X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC, (const unsigned char *)"localhost", -1, -1, 0);
  X509_set_issuer_name(x, nm), X509_sign(x, pk, EVP_sha256());
  unsigned char *der = NULL;
  int dl = i2d_X509(x, &der);
  CERT = ptls_iovec_init(der, (size_t)dl);
  ptls_openssl_init_sign_certificate(&SIGN, pk);
  X509_free(x), EVP_PKEY_free(pk);
}
static void tls_base(ptls_context_t *t, int server) {
  memset(t, 0, sizeof *t);
  t->random_bytes = ptls_openssl_random_bytes, t->get_time = &ptls_get_time;
  t->key_exchanges = ptls_openssl_key_exchanges, t->cipher_suites = ptls_openssl_cipher_suites;
  if (server) t->certificates.list = &CERT, t->certificates.count = 1, t->sign_certificate = &SIGN.super;
}
static quic_ctx SQX, CQX; /* ours: a server's, a client's */
static const char *SRV_ALPN[2] = { "echo/2", "echo" }, *CLI_ALPN[2] = { "echo", "echo/2" };

/* ------------------------------------------ our endpoint ------------------------------------------ */
typedef struct {
  quic_conn q;
  echo e;
  int established;
} ours;
static int64_t o_on_stream(quic_conn *q, uint64_t sid, uint64_t off, const uint8_t *d, size_t len, int fin, void *u) {
  (void)q;
  ours *o = u;
  return e_in(&o->e, (int64_t)sid, off, d, len, fin) ? -0x100 : (int64_t)len; /* (-ret: an application error) */
}
static size_t o_send(quic_conn *q, uint64_t sid, uint8_t *out, size_t cap, int *fin, void *u) {
  (void)q;
  ours *o = u;
  est *s = e_find(&o->e, (int64_t)sid, 0);
  if (!s) return 0;
  size_t m = s->len - s->sent < cap ? s->len - s->sent : cap;
  memcpy(out, s->buf + s->sent, m), s->sent += m;
  if (s->sent == s->len && e_fin_due(s)) *fin = 1, s->fin_out = 1;
  return m;
}
static int o_wants(quic_conn *q, uint64_t sid, void *u) {
  (void)q;
  est *s = e_find(&((ours *)u)->e, (int64_t)sid, 0);
  return s && (s->sent < s->len || (s->sent == s->len && e_fin_due(s)));
}
static void o_reset(quic_conn *q, uint64_t sid, uint64_t code, void *u) {
  (void)q, (void)sid, (void)code;
  ((ours *)u)->e.bad++;
}
static void o_open_more(ours *o) {
  while (o->established && o->e.opened < o->e.open_target) {
    int64_t sid = quic_open_bidi(&o->q);
    if (sid < 0) return; /* at the peer's limit for now */
    e_open(&o->e, sid);
  }
}
static void o_established(quic_conn *q, void *u) {
  (void)q;
  ours *o = u;
  o->established = 1;
  o_open_more(o);
}
static const quic_callbacks OCB = { o_on_stream, o_send, o_wants, o_reset, o_established, NULL };
static void o_pump(ours *o, wire *to) {
  uint8_t out[1500];
  size_t n;
  o_open_more(o);
  while ((n = quic_send(&o->q, out, sizeof out, now_ms())) > 0) put(to, out, n);
}

/* ------------------------------------------ ngtcp2's endpoint ------------------------------------------ */
typedef struct {
  ngtcp2_conn *conn;
  ngtcp2_crypto_conn_ref ref;
  ngtcp2_crypto_picotls_ctx cptls;
  ngtcp2_path_storage ps;
  ptls_raw_extension_t exts[2];
  echo e;
  int established, failed, server;
} ng;
static void ng_rand(uint8_t *d, size_t n, const ngtcp2_rand_ctx *rc) {
  (void)rc;
  for (size_t i = 0; i < n; i++) d[i] = (uint8_t)rnd();
}
static int ng_new_cid(ngtcp2_conn *c, ngtcp2_cid *cid, ngtcp2_stateless_reset_token *tok, size_t len, void *u) {
  (void)c, (void)u;
  ng_rand(cid->data, len, NULL), cid->datalen = len, ng_rand(tok->data, sizeof tok->data, NULL);
  return 0;
}
static ngtcp2_conn *ng_get_conn(ngtcp2_crypto_conn_ref *r) { return ((ng *)r->user_data)->conn; }
static void ng_open_more(ng *g) {
  while (g->established && g->e.opened < g->e.open_target) {
    int64_t sid;
    if (ngtcp2_conn_open_bidi_stream(g->conn, &sid, NULL)) return;
    e_open(&g->e, sid);
  }
}
static int ng_handshake(ngtcp2_conn *c, void *u) {
  (void)c;
  ng *g = u;
  g->established = 1;
  ng_open_more(g);
  return 0;
}
static int ng_recv(ngtcp2_conn *c, uint32_t fl, int64_t sid, uint64_t off, const uint8_t *d, size_t n, void *u,
                   void *su) {
  (void)su;
  ng *g = u;
  if (e_in(&g->e, sid, off, d, n, (fl & NGTCP2_STREAM_DATA_FLAG_FIN) != 0)) return NGTCP2_ERR_CALLBACK_FAILURE;
  ngtcp2_conn_extend_max_stream_offset(c, sid, n), ngtcp2_conn_extend_max_offset(c, n);
  return 0;
}
static int ng_extend_bidi(ngtcp2_conn *c, uint64_t max, void *u) {
  (void)c, (void)max;
  ng_open_more(u);
  return 0;
}
static int ng_reset(ngtcp2_conn *c, int64_t sid, uint64_t fs, uint64_t code, void *u, void *su) {
  (void)c, (void)sid, (void)fs, (void)code, (void)su;
  ((ng *)u)->e.bad++;
  return 0;
}
/* ngtcp2 leaves MAX_STREAMS to the application: a stream the peer opened, once closed, makes room for another */
static int ng_close(ngtcp2_conn *c, uint32_t fl, int64_t sid, uint64_t code, void *u, void *su) {
  (void)fl, (void)code, (void)su, (void)u;
  if ((int)(sid & 1) != ngtcp2_conn_is_server(c) && !(sid & 2)) ngtcp2_conn_extend_max_streams_bidi(c, 1);
  return 0;
}
static void ng_callbacks(ngtcp2_callbacks *cb, int server) {
  memset(cb, 0, sizeof *cb);
  if (server) cb->recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
  else cb->client_initial = ngtcp2_crypto_client_initial_cb, cb->recv_retry = ngtcp2_crypto_recv_retry_cb;
  cb->recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
  cb->encrypt = ngtcp2_crypto_encrypt_cb, cb->decrypt = ngtcp2_crypto_decrypt_cb,
  cb->hp_mask = ngtcp2_crypto_hp_mask_cb;
  cb->update_key = ngtcp2_crypto_update_key_cb, cb->delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
  cb->delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
  cb->get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb;
  cb->version_negotiation = ngtcp2_crypto_version_negotiation_cb;
  cb->rand = ng_rand, cb->get_new_connection_id2 = ng_new_cid, cb->handshake_completed = ng_handshake;
  cb->recv_stream_data = ng_recv, cb->extend_max_local_streams_bidi = ng_extend_bidi, cb->stream_reset = ng_reset;
  cb->stream_close = ng_close;
}
static void ng_tp(ngtcp2_transport_params *tp) {
  ngtcp2_transport_params_default(tp);
  tp->initial_max_streams_bidi = 16, tp->initial_max_streams_uni = 3;
  tp->initial_max_stream_data_bidi_local = tp->initial_max_stream_data_bidi_remote = 256 * 1024;
  tp->initial_max_stream_data_uni = 256 * 1024, tp->initial_max_data = 4 * 1024 * 1024;
}
static struct sockaddr_in LA, RA;
static ngtcp2_path ng_path(void) {
  LA.sin_family = RA.sin_family = AF_INET, LA.sin_port = htons(5555), RA.sin_port = htons(443);
  ngtcp2_path p = { { (struct sockaddr *)&LA, sizeof LA }, { (struct sockaddr *)&RA, sizeof RA }, NULL };
  return p;
}
static int och_echo(ptls_on_client_hello_t *self, ptls_t *tls, ptls_on_client_hello_parameters_t *p) {
  (void)self;
  for (size_t i = 0; i < p->negotiated_protocols.count; i++)
    if (p->negotiated_protocols.list[i].len == 4 && !memcmp(p->negotiated_protocols.list[i].base, "echo", 4))
      return ptls_set_negotiated_protocol(tls, "echo", 4);
  return PTLS_ALERT_NO_APPLICATION_PROTOCOL;
}
static ptls_on_client_hello_t OCH = { och_echo };
static void ng_client_new(ng *g) {
  memset(g, 0, sizeof *g);
  ngtcp2_callbacks cb;
  ng_callbacks(&cb, 0);
  ngtcp2_cid dcid, scid;
  dcid.datalen = 18, scid.datalen = 8, ng_rand(dcid.data, 18, NULL), ng_rand(scid.data, 8, NULL);
  ngtcp2_settings st;
  ngtcp2_settings_default(&st), st.initial_ts = NOW_NS;
  ngtcp2_transport_params tp;
  ng_tp(&tp);
  ngtcp2_path path = ng_path();
  if (ngtcp2_conn_client_new(&g->conn, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1, &cb, &st, &tp, NULL, g)) exit(1);
  ngtcp2_path_storage_init(&g->ps, path.local.addr, path.local.addrlen, path.remote.addr, path.remote.addrlen, NULL);
  g->ref.get_conn = ng_get_conn, g->ref.user_data = g;
  ngtcp2_crypto_picotls_ctx_init(&g->cptls);
  g->cptls.ptls = ptls_client_new(&NG_CLI_TLS);
  *ptls_get_data_ptr(g->cptls.ptls) = &g->ref;
  g->exts[0] = (ptls_raw_extension_t){ 0, { NULL, 0 } }, g->exts[1] = (ptls_raw_extension_t){ UINT16_MAX, { NULL, 0 } };
  g->cptls.handshake_properties.additional_extensions = g->exts;
  ngtcp2_crypto_picotls_configure_client_session(&g->cptls, g->conn);
  static ptls_iovec_t alpn = { (uint8_t *)"echo", 4 };
  g->cptls.handshake_properties.client.negotiated_protocols.list = &alpn;
  g->cptls.handshake_properties.client.negotiated_protocols.count = 1;
  ptls_set_server_name(g->cptls.ptls, "localhost", 9);
  ngtcp2_conn_set_tls_native_handle(g->conn, &g->cptls);
}
static int ng_server_new(ng *g, const uint8_t *d, size_t n) {
  ngtcp2_pkt_hd hd;
  if (ngtcp2_accept(&hd, d, n)) return -1;
  memset(g, 0, sizeof *g), g->server = 1;
  ngtcp2_callbacks cb;
  ng_callbacks(&cb, 1);
  ngtcp2_settings st;
  ngtcp2_settings_default(&st), st.initial_ts = NOW_NS;
  ngtcp2_transport_params tp;
  ng_tp(&tp);
  tp.original_dcid = hd.dcid, tp.original_dcid_present = 1;
  ngtcp2_cid scid;
  scid.datalen = 8, ng_rand(scid.data, 8, NULL);
  ngtcp2_path path = ng_path();
  if (ngtcp2_conn_server_new(&g->conn, &hd.scid, &scid, &path, hd.version, &cb, &st, &tp, NULL, g)) return -1;
  ngtcp2_path_storage_init(&g->ps, path.local.addr, path.local.addrlen, path.remote.addr, path.remote.addrlen, NULL);
  g->ref.get_conn = ng_get_conn, g->ref.user_data = g;
  ngtcp2_crypto_picotls_ctx_init(&g->cptls);
  g->cptls.ptls = ptls_server_new(&NG_SRV_TLS);
  *ptls_get_data_ptr(g->cptls.ptls) = &g->ref;
  g->exts[0] = (ptls_raw_extension_t){ 0, { NULL, 0 } }, g->exts[1] = (ptls_raw_extension_t){ UINT16_MAX, { NULL, 0 } };
  g->cptls.handshake_properties.additional_extensions = g->exts;
  if (ngtcp2_crypto_picotls_configure_server_session(&g->cptls)) return -1;
  ngtcp2_conn_set_tls_native_handle(g->conn, &g->cptls);
  ngtcp2_pkt_info pi = { 0 };
  return ngtcp2_conn_read_pkt(g->conn, &g->ps.path, &pi, d, n, NOW_NS) ? -1 : 0;
}
/* everything ngtcp2 sends now: each stream's pending bytes, then whatever else (ACKs, control) */
static void ng_pump(ng *g, wire *to) {
  uint8_t out[1500];
  ng_open_more(g);
  for (int guard = 0; guard < 20000; guard++) {
    est *s = NULL;
    for (int i = 0; i < 64 && !s; i++)
      if (g->e.s[i].used &&
          (g->e.s[i].sent < g->e.s[i].len || (g->e.s[i].sent == g->e.s[i].len && e_fin_due(&g->e.s[i]))))
        s = &g->e.s[i];
    ngtcp2_vec v = { s ? s->buf + s->sent : NULL, s ? s->len - s->sent : 0 };
    int fin = s && e_fin_due(s);
    ngtcp2_ssize ndata = -1;
    ngtcp2_pkt_info pi;
    ngtcp2_ssize w = ngtcp2_conn_writev_stream(g->conn, &g->ps.path, &pi, out, 1252, &ndata,
                                               NGTCP2_WRITE_STREAM_FLAG_MORE | (fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0),
                                               s ? s->sid : -1, &v, s ? 1 : 0, NOW_NS);
    if (w == NGTCP2_ERR_STREAM_DATA_BLOCKED || w == NGTCP2_ERR_STREAM_SHUT_WR) { /* try the others, later */
      w = ngtcp2_conn_writev_stream(g->conn, &g->ps.path, &pi, out, 1252, &ndata, 0, -1, NULL, 0, NOW_NS);
      s = NULL;
    }
    if (w < 0 && w != NGTCP2_ERR_WRITE_MORE) {
      printf("ngtcp2 write: %s\n", ngtcp2_strerror((int)w)), g->failed = 1;
      return;
    }
    if (s && ndata >= 0) {
      s->sent += (size_t)ndata;
      if (fin && s->sent == s->len) s->fin_out = 1;
    }
    if (w == NGTCP2_ERR_WRITE_MORE) continue;
    if (!w) {
      ngtcp2_conn_update_pkt_tx_time(g->conn, NOW_NS);
      return;
    }
    put(to, out, (size_t)w);
  }
}
static int ng_read(ng *g, const dgram *d) {
  ngtcp2_pkt_info pi = { 0 };
  int r = ngtcp2_conn_read_pkt(g->conn, &g->ps.path, &pi, d->d, d->n, NOW_NS);
  if (r) printf("ngtcp2 read: %s\n", ngtcp2_strerror(r)), g->failed = 1;
  return r;
}
static void ng_free(ng *g) {
  if (g->conn) ngtcp2_conn_del(g->conn);
  if (g->cptls.ptls) ngtcp2_crypto_picotls_deconfigure_session(&g->cptls), ptls_free(g->cptls.ptls);
  e_free(&g->e);
}

/* ------------------------------------------ one run ------------------------------------------ */
enum { OURS_OURS, NG_CLIENT, NG_SERVER };
static const char *KIND[3] = { "ours <-> ours", "ngtcp2 client -> our server", "our client -> ngtcp2 server" };
static void run(int kind, int ncli, int nsrv, int loss, int reorder) {
  LOSS = loss, REORDER = reorder, TO_SRV.n = TO_CLI.n = 0;
  static ours oc, os;
  static ng gc, gs;
  memset(&oc, 0, sizeof oc), memset(&os, 0, sizeof os);
  int accepted = 0;
  echo *ce, *se; /* the two sides' echo state */
  if (kind == NG_CLIENT) ng_client_new(&gc), ce = &gc.e;
  else {
    CHECK(quic_connect(&oc.q, &CQX, "localhost", now_ms(), &OCB, &oc) == 0, "quic_connect");
    ce = &oc.e;
  }
  ce->open_target = ncli;
  se = kind == NG_SERVER ? &gs.e : &os.e;
  uint64_t start = NOW_NS;
  for (int guard = 0; guard < 3000000; guard++) {
    if (kind == NG_CLIENT) ng_pump(&gc, &TO_SRV);
    else o_pump(&oc, &TO_SRV);
    dgram g;
    while (take(&TO_SRV, &g)) {
      if (!accepted) {
        if (kind == NG_SERVER) accepted = ng_server_new(&gs, g.d, g.n) == 0;
        else accepted = quic_accept(&os.q, &SQX, g.d, g.n, now_ms(), &OCB, &os) == 0;
        if (accepted) se->open_target = nsrv;
        continue;
      }
      if (kind == NG_SERVER) ng_read(&gs, &g);
      else quic_recv(&os.q, g.d, g.n, now_ms());
    }
    if (accepted) {
      if (kind == NG_SERVER) ng_pump(&gs, &TO_CLI);
      else o_pump(&os, &TO_CLI);
    }
    int got = 0;
    while (take(&TO_CLI, &g)) {
      got = 1;
      if (kind == NG_CLIENT) ng_read(&gc, &g);
      else quic_recv(&oc.q, g.d, g.n, now_ms());
    }
    if (got) { /* what that lets the client send goes before time moves on */
      if (kind == NG_CLIENT) ng_pump(&gc, &TO_SRV);
      else o_pump(&oc, &TO_SRV);
    }
    int closed = (kind != NG_CLIENT && (oc.q.closing || oc.q.draining)) ||
                 (accepted && kind != NG_SERVER && (os.q.closing || os.q.draining)) || gc.failed || gs.failed;
    if (closed || ce->bad || se->bad) break;
    if (ce->done == ncli && se->done == nsrv) break;
    if ((!TO_SRV.n && !TO_CLI.n) || next_arrival() > NOW_NS) {
      uint64_t t = next_arrival();
      int64_t tm[2] = { kind == NG_CLIENT ? INT64_MAX : quic_timeout(&oc.q),
                        accepted && kind != NG_SERVER ? quic_timeout(&os.q) : INT64_MAX };
      for (int k = 0; k < 2; k++)
        if (tm[k] != INT64_MAX && (uint64_t)tm[k] * 1000000ull < t) t = (uint64_t)tm[k] * 1000000ull;
      if (kind == NG_CLIENT) t = ngtcp2_conn_get_expiry2(gc.conn) < t ? ngtcp2_conn_get_expiry2(gc.conn) : t;
      if (kind == NG_SERVER && accepted)
        t = ngtcp2_conn_get_expiry2(gs.conn) < t ? ngtcp2_conn_get_expiry2(gs.conn) : t;
      if (t == UINT64_MAX || t <= NOW_NS) t = NOW_NS + 1000000;
      NOW_NS = t;
      if (kind != NG_CLIENT && quic_timeout(&oc.q) <= now_ms()) quic_on_timeout(&oc.q, now_ms());
      if (accepted && kind != NG_SERVER && quic_timeout(&os.q) <= now_ms()) quic_on_timeout(&os.q, now_ms());
      if (kind == NG_CLIENT && ngtcp2_conn_get_expiry2(gc.conn) <= NOW_NS) ngtcp2_conn_handle_expiry(gc.conn, NOW_NS);
      if (kind == NG_SERVER && accepted && ngtcp2_conn_get_expiry2(gs.conn) <= NOW_NS)
        ngtcp2_conn_handle_expiry(gs.conn, NOW_NS);
    }
    if (NOW_NS - start > 60ull * 1000000000ull) break;
  }
  const char *alpn = kind == NG_CLIENT ? (accepted ? quic_alpn(&os.q) : NULL) : quic_alpn(&oc.q);
  CHECK(accepted && alpn && !strcmp(alpn, kind == OURS_OURS ? "echo/2" : "echo"),
        "%s: ALPN %s (the server's preference among the client's)", KIND[kind], alpn ? alpn : "none");
  CHECK(!ce->bad && !se->bad, "%s: echo errors client %d server %d", KIND[kind], ce->bad, se->bad);
  CHECK(ce->done == ncli && se->done == nsrv, "%s, loss %d%%: client's %d/%d echoed, server's %d/%d", KIND[kind], loss,
        ce->done, ncli, se->done, nsrv);
  printf("  %-28s loss %2d%% reorder %d: %d client + %d server streams echoed in %.2f simulated s\n", KIND[kind], loss,
         reorder, ce->done, se->done, (NOW_NS - start) / 1e9);
  if (kind != NG_CLIENT) quic_free(&oc.q);
  else ng_free(&gc);
  if (accepted && kind != NG_SERVER) quic_free(&os.q);
  else if (accepted) ng_free(&gs);
  e_free(&oc.e), e_free(&os.e);
}
/* no protocol in common: our client offers "other", the server takes "echo"s */
static void test_alpn_mismatch(void) {
  static const char *other[1] = { "other" };
  quic_ctx x = CQX;
  x.alpn = other, x.nalpn = 1;
  static ours oc, os;
  memset(&oc, 0, sizeof oc), memset(&os, 0, sizeof os);
  TO_SRV.n = TO_CLI.n = 0, LOSS = REORDER = 0;
  quic_connect(&oc.q, &x, "localhost", now_ms(), &OCB, &oc);
  int accepted = 0;
  for (int i = 0; i < 200 && !(oc.q.closing || oc.q.draining || os.q.closing); i++) {
    o_pump(&oc, &TO_SRV);
    dgram g;
    NOW_NS += 20000000ull;
    while (take(&TO_SRV, &g))
      if (!accepted) accepted = quic_accept(&os.q, &SQX, g.d, g.n, now_ms(), &OCB, &os) == 0;
      else quic_recv(&os.q, g.d, g.n, now_ms());
    if (accepted) o_pump(&os, &TO_CLI);
    NOW_NS += 20000000ull;
    while (take(&TO_CLI, &g)) quic_recv(&oc.q, g.d, g.n, now_ms());
  }
  CHECK((os.q.closing && os.q.close_code == (0x100 | PTLS_ALERT_NO_APPLICATION_PROTOCOL)) || !accepted,
        "no ALPN in common: the server closes with no_application_protocol (code 0x%llx)",
        (unsigned long long)os.q.close_code);
  CHECK(!oc.established, "and the client never established");
  quic_free(&oc.q);
  if (accepted) quic_free(&os.q);
  printf("  ALPN mismatch: refused\n");
}

int main(void) {
  make_cert();
  tls_base(&SRV_TLS, 1), tls_base(&CLI_TLS, 0), tls_base(&NG_SRV_TLS, 1), tls_base(&NG_CLI_TLS, 0);
  quic_ctx_init(&SQX, &SRV_TLS), quic_ctx_init(&CQX, &CLI_TLS);
  SQX.alpn = SRV_ALPN, SQX.nalpn = 2, CQX.alpn = CLI_ALPN, CQX.nalpn = 2;
  CQX.max_streams_bidi = 16; /* the server may open streams to us */
  NG_SRV_TLS.on_client_hello = &OCH;
  ngtcp2_crypto_picotls_configure_server_context(&NG_SRV_TLS);
  ngtcp2_crypto_picotls_configure_client_context(&NG_CLI_TLS);
  for (long r = 0; r < scale(); r++)
    for (int kind = 0; kind < 3; kind++) {
      run(kind, 10, 6, 0, 0);
      run(kind, 30, 10, 2, 1);
    }
  test_alpn_mismatch();
  printf("%s: %ld failures / %ld checks\n", fails ? "FAIL" : "PASS", fails, checks);
  return fails != 0;
}
