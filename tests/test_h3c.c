/* The client side of include/quic.h + include/h3.h (quic_connect, quic_open_bidi, h3_init_client, h3_submit)
 * against this library's own HTTP/3 server, in memory, over the simulated network of test_quic_interop.c:
 * one-way latency, loss, reordering and duplicates, a simulated clock driving both stacks' timers.
 *   - each run: handshake (ALPN h3, transport parameters checked both ways), then N requests (GETs, POSTs with
 *     bodies, large responses, HEAD); every status, body length and stream end is checked; both sides must
 *     finish without errors, and the client must confirm the handshake (HANDSHAKE_DONE).
 * Usage: test_h3c [loss_percent [bulk_requests]]. FUZZ=N scales the runs. */
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
static uint64_t rs = 0x13198a2e03707344ull;
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
static int BULK; /* every request is GET /big/1000000: slow start overfills the wire (4096 datagrams, tail drop) */
static int LOSS, REORDER, BLACKHOLE; /* BLACKHOLE: drop client->server after its first datagram, for 8 s */
static uint64_t BLACKHOLE_UNTIL;
static long SENT_DGRAMS, LOST_DGRAMS;

static void put(wire *w, const uint8_t *d, size_t n) {
  SENT_DGRAMS++;
  if (BLACKHOLE && w == &TO_SRV) {
    if (!BLACKHOLE_UNTIL) BLACKHOLE_UNTIL = NOW_NS + 8000000000ull; /* the first datagram goes through; 3 PTO rounds */
    else if (NOW_NS < BLACKHOLE_UNTIL) {
      LOST_DGRAMS++;
      return;
    }
  }
  /* BULK: once slow start has run for a while (far more than QUIC_SENT_MAX packets in flight), 1 in 200 */
  if ((int)(rnd() % 100) < LOSS || (BULK && w == &TO_CLI && SENT_DGRAMS > 12000 && rnd() % 200 == 0)) {
    LOST_DGRAMS++;
    return;
  }
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

/* --------------------------------------------- server --------------------------------------------- */
static ptls_context_t SRV_TLS;
static ptls_openssl_sign_certificate_t SRV_SIGN;
static ptls_iovec_t SRV_CERT;
static quic_ctx QX;
typedef struct {
  quic_conn q;
  h3_conn h;
  int h3_ready;
  long requests, closes, errors;
} server;
static server *SRV;
static h3_scratch H3S;
static uint8_t BIG[1 << 20];

static int s_request(h3_conn *h, uint64_t sid, const h_request *rq, int end, void *u) {
  server *s = u;
  s->requests++;
  static const hp_field ct = { (const uint8_t *)"content-type", (const uint8_t *)"text/plain", 12, 10, 0, 0, 0, 0 };
  if (rq->path_len > 5 && !memcmp(rq->path, "/big/", 5))
    return h3_respond(h, sid, 200, &ct, 1, BIG, (size_t)atoi((const char *)rq->path + 5), 1) < 0;
  if (h_eq(rq->method, rq->method_len, "HEAD")) {
    static const hp_field cl = { (const uint8_t *)"content-length", (const uint8_t *)"13", 14, 2, 0, 0, 0, 0 };
    return h3_respond(h, sid, 200, &cl, 1, NULL, 0, 1) < 0;
  }
  if (rq->path_len == 4 && !memcmp(rq->path, "/204", 4)) return h3_respond(h, sid, 204, NULL, 0, NULL, 0, 1) < 0;
  if (!end && h_eq(rq->method, rq->method_len, "POST"))
    return 0; /* answered at the end of the body; a GET's fin
                                                                    * may come after its HEADERS frame */
  return h3_respond(h, sid, 200, &ct, 1, (const uint8_t *)"hello, world\n", 13, 1) < 0;
}
static int s_data(h3_conn *h, uint64_t sid, const uint8_t *d, size_t n, int end, void *u) {
  (void)d, (void)n, (void)u;
  h3_stream *st = h3__find(h, sid);
  if (!end || !st || (st->flags & H3_ST_RESPONDED)) return 0;
  static const hp_field ct = { (const uint8_t *)"content-type", (const uint8_t *)"text/plain", 12, 10, 0, 0, 0, 0 };
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
static const h3_callbacks H3CB = { s_request, s_data, NULL, NULL, s_close, s_reset, NULL };

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
static const quic_callbacks QCB = { q_on_stream, q_send, q_wants, q_reset, q_established };

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

/* ------------------------------------------ our client ------------------------------------------ */
static ptls_context_t CLI_TLS;
static quic_ctx CQX;
typedef struct {
  quic_conn q;
  h3_conn h;
  int ready, nreq, submitted, done, ok, failed, statuses_bad;
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
    int k = BULK ? 2 : (int)(rnd() % 5);
    char *path = (char *)UPBUF + 60000 + (cl->submitted % 64) * 64;
    const char *m = k == 1 ? "POST" : k == 3 ? "HEAD" : "GET";
    long w = 0;
    if (k == 2) {
      size_t big = BULK ? sizeof BIG - 48576 : 1000 + rnd() % 200000;
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
    cl->submitted++;
  }
}
static int64_t cq_on_stream(quic_conn *q, uint64_t sid, uint64_t off, const uint8_t *d, size_t len, int fin, void *u) {
  (void)q;
  client *cl = u;
  if (!cl->ready) return 0;
  int r = h3_recv(&cl->h, &H3C, sid, off, d, len, fin);
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
static const quic_callbacks CQCB = { cq_on_stream, cq_send, cq_wants, cq_reset, cq_established };
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
  static server sv;
  CLI = &cl, SRV = &sv;
  memset(&cl, 0, sizeof cl), memset(&sv, 0, sizeof sv);
  cl.nreq = nreq;
  int r0 = quic_connect(&cl.q, &CQX, "localhost", now_ms(), &CQCB, &cl);
  CHECK(r0 == 0, "quic_connect %d", r0);
  int accepted = 0;
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
        if (quic_accept(&sv.q, &QX, g.d, g.n, now_ms(), &QCB, &sv) == 0) accepted = 1;
        continue;
      }
      quic_recv(&sv.q, g.d, g.n, now_ms());
    }
    if (accepted)
      while ((n = quic_send(&sv.q, out, sizeof out, now_ms())) > 0) put(&TO_CLI, out, n);
    while (take(&TO_CLI, &g)) quic_recv(&cl.q, g.d, g.n, now_ms());
    if (cl.failed || cl.q.closing || cl.q.draining || (accepted && (sv.q.closing || sv.q.draining))) break;
    if (cl.done == nreq && cl.submitted == nreq) break;
    if ((!TO_SRV.n && !TO_CLI.n) || next_arrival() > NOW_NS) {
      uint64_t t = next_arrival();
      int64_t ce = quic_timeout(&cl.q);
      if (ce != INT64_MAX && (uint64_t)ce * 1000000ull < t) t = (uint64_t)ce * 1000000ull;
      if (accepted) {
        int64_t se = quic_timeout(&sv.q);
        if (se != INT64_MAX && (uint64_t)se * 1000000ull < t) t = (uint64_t)se * 1000000ull;
      }
      if (t == UINT64_MAX || t <= NOW_NS) t = NOW_NS + 1000000;
      NOW_NS = t;
      if (quic_timeout(&cl.q) <= now_ms()) quic_on_timeout(&cl.q, now_ms());
      if (accepted && quic_timeout(&sv.q) <= now_ms()) quic_on_timeout(&sv.q, now_ms());
    }
    if (NOW_NS - start > 120ull * 1000000000ull) {
      CHECK(0, "run took > 120 simulated seconds");
      break;
    }
  }
  CHECK(accepted && sv.h3_ready && cl.ready, "handshake (loss %d%%): accepted %d server h3 %d client h3 %d", loss,
        accepted, sv.h3_ready, cl.ready);
  CHECK(cl.q.confirmed && cl.q.sp[QUIC_SP_INITIAL].discarded && cl.q.sp[QUIC_SP_HANDSHAKE].discarded,
        "client handshake confirmed (HANDSHAKE_DONE), Initial and Handshake keys discarded");
  CHECK(!cl.failed && cl.done == nreq && cl.ok == nreq && !cl.statuses_bad,
        "loss %d%%: %d/%d done, %d right statuses, %d wrong", loss, cl.done, nreq, cl.ok, cl.statuses_bad);
  CHECK(cl.body == cl.want_body, "loss %d%%: body %ld want %ld", loss, cl.body, cl.want_body);
  CHECK(!cl.q.closing && !cl.q.draining, "client closed the connection: code 0x%llx frame 0x%llx (h3 0x%llx)",
        (unsigned long long)cl.q.close_code, (unsigned long long)cl.q.close_frame, (unsigned long long)h3_error(&cl.h));
  CHECK(!sv.q.closing && !sv.q.draining, "server closed the connection: code 0x%llx frame 0x%llx",
        (unsigned long long)sv.q.close_code, (unsigned long long)sv.q.close_frame);
  CHECK(sv.errors == 0 && cl.q.undecryptable == 0, "server stream errors %ld, client undecryptable %llu", sv.errors,
        (unsigned long long)cl.q.undecryptable);
  printf(
      "  loss %2d%% reorder %d%s: %d requests, %.1f simulated s, %ld datagrams (%ld lost), client cwnd %llu srtt %lld ms\n",
      loss, reorder, BULK ? " bulk 1 MB, late 0.5%" : "", nreq, (NOW_NS - start) / 1e9, SENT_DGRAMS, LOST_DGRAMS,
      (unsigned long long)cl.q.cwnd, (long long)cl.q.smoothed_rtt);
  SENT_DGRAMS = LOST_DGRAMS = 0;
  quic_free(&cl.q);
  if (accepted) quic_free(&sv.q);
  return fails == before;
}

int main(int argc, char **argv) {
  for (int i = 0; i < 1000; i++) BIG[i] = (uint8_t)i;
  server_init();
  client_tls_init();
  printf("sizeof(quic_conn) = %zu, sizeof(h3_conn) = %zu\n", sizeof(quic_conn), sizeof(h3_conn));
  if (argc > 2) BULK = 1, run(atoi(argv[2]), atoi(argv[1]), 0);
  else if (argc > 1) run(100, atoi(argv[1]), 1);
  else
    for (long r = 0; r < scale(); r++) {
      run(50, 0, 0);
      run(150, 0, 0); /* beyond the server's initial 100 bidi streams: MAX_STREAMS credit */
      run(100, 0, 1);
      run(100, 2, 1);
      run(60, 10, 1);
      /* far more than QUIC_SENT_MAX packets in flight, then tail drops: a full record ring once forgot packets
       * whose losses were then never repaired, and the transfer stalled */
      BULK = 1, run(40, 0, 0), BULK = 0;
    }
  printf("%s: %ld failures / %ld checks\n", fails ? "FAIL" : "PASS", fails, checks);
  return fails != 0;
}
