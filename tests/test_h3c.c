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
static int PATH_MTU = 1500 - 28; /* the largest UDP payload the simulated path carries */
static int PRIO; /* 1: the 5th of five big responses is urgent by its priority field; 2: by PRIORITY_UPDATE */
static int ORDER[8], NORDER;
static int RETRY; /* the server validates the client's address with a Retry first */
static long EARLY_REQS;
static unsigned long long BLOCKED_SUM;
static int LAST_MTU;
/* the server's datagram size at the end of the last run */ /* QPACK sections our server held for inserts, over all runs */
static int EXPECT_EARLY;              /* resuming: 1 the server takes the 0-RTT requests, 0 it refuses them */
static quic_resume RES, *RESUME_FROM; /* what a run saves for the next; the run that resumes from it */
static int LOSE_STATE;                /* halfway, the server forgets the connection and answers with stateless resets */
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
  if ((int)n > PATH_MTU) { /* too big for the path: lost, silently */
    LOST_DGRAMS++;
    return;
  }
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
  if (!s->q.established) EARLY_REQS++; /* it came in 0-RTT */
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
  uint64_t ub[H3_QPACK_BLOCKED]; /* streams whose QPACK inserts just arrived: their bytes again */
  for (int n; r >= 0 && (n = h3_unblocked(&s->h, ub, H3_QPACK_BLOCKED)) > 0;)
    for (int i = 0; i < n; i++) quic_stream_redeliver(q, ub[i]);
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
static int q_prio(quic_conn *q, uint64_t sid, void *u) { /* RFC 9218: the request's priority orders its data */
  server *s = u;
  (void)q;
  return s->h3_ready ? h3_stream_priority(&s->h, sid) : H_URGENCY_DEFAULT << 1;
}
static const quic_callbacks QCB = { q_on_stream, q_send, q_wants, q_reset, q_established, q_prio };

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
  quic_ctx_resumption(&QX);
}

/* ------------------------------------------ our client ------------------------------------------ */
static ptls_context_t CLI_TLS;
static quic_ctx CQX;
typedef struct {
  quic_conn q;
  h3_conn h;
  int ready, nreq, submitted, done, ok, failed, statuses_bad, spilled, spill_waits;
  int64_t pending_sid;                      /* opened, h3_submit said AGAIN */
  long body, want_body, hdr_bytes, hdr_raw; /* request header frames sent; their fields' bytes */
  long tail_bytes, tail_raw;                /* the same for the last quarter of the requests */
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
  if (!err && NORDER < 8) ORDER[NORDER++] = (int)sid;
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
    int64_t sid = cl->pending_sid >= 0 ? cl->pending_sid : quic_open_bidi(&cl->q);
    if (sid < 0) return; /* at the server's stream limit: MAX_STREAMS will raise it */
    cl->pending_sid = -1;
    int k = BULK || PRIO ? 2 : (int)(rnd() % 5);
    char *path = (char *)UPBUF + 60000 + (cl->submitted % 64) * 64;
    const char *m = k == 1 ? "POST" : k == 3 ? "HEAD" : "GET";
    long w = 0;
    if (k == 2) {
      size_t big = BULK || PRIO ? sizeof BIG - 48576 : 1000 + rnd() % 200000;
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
    /* every 7th request carries a 1200-byte cookie: a header frame beyond H3_HDR_MAX (from the spill area) until
     * the table has it */
    static char cookie[1201];
    if (!cookie[0])
      for (int i = 0; i < 1200; i++) cookie[i] = i % 50 == 49 ? ';' : (char)('a' + i % 26);
    static const hp_field ua = {
      (const uint8_t *)"user-agent", (const uint8_t *)"cursed-http-test", 10, 16, 0, 0, 0, 0
    };
    hp_field fl[2] = { ua, { (const uint8_t *)"cookie", (const uint8_t *)cookie, 6, 1200, 0, 0, 0, 0 } };
    int big_hdr = !PRIO && cl->submitted % 7 == 3;
    rq.fields = fl, rq.nfields = big_hdr ? 2 : 1;
    if (PRIO) /* the priority field (RFC 9218): all u=5 but the 5th, u=1 (PRIO 1) */
      fl[1] = (hp_field){ (const uint8_t *)"priority",
                          (const uint8_t *)(PRIO == 1 && cl->submitted == 4 ? "u=1" : "u=5"),
                          8,
                          3,
                          0,
                          0,
                          0,
                          0 },
      rq.nfields = 2;
    cl->kind[(sid >> 2) % 4096] = k;
    size_t up = k == 1 ? 1 + rnd() % 30000 : 0;
    int r = h3_submit(&cl->h, (uint64_t)sid, &rq, up ? UPBUF : NULL, up, 1);
    if (r == H3_E_AGAIN) { /* the spill area is full of unsent headers: this sid again after quic_send */
      cl->want_body -= w, cl->pending_sid = sid, cl->spill_waits++;
      return;
    }
    if (r) {
      cl->failed = 1;
      return;
    }
    cl->spilled += big_hdr, cl->submitted++;
    long hb = h3__find(&cl->h, (uint64_t)sid)->hdr_len,
         hr = 7 + (long)strlen(m) + 7 + 5 + 10 + 9 + 5 + (long)strlen(path) + 10 + 16 + (big_hdr ? 6 + 1200 : 0);
    cl->hdr_bytes += hb, cl->hdr_raw += hr;
    if (cl->submitted > cl->nreq * 3 / 4) cl->tail_bytes += hb, cl->tail_raw += hr;
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
  quic_ctx_resumption(&CQX);     /* (saves tickets) */
}

/* --------------------------------------------- one run --------------------------------------------- */
static int run(int nreq, int loss, int reorder) {
  LOSS = loss, REORDER = reorder, BLACKHOLE_UNTIL = 0;
  TO_SRV.n = TO_CLI.n = 0;
  static client cl;
  static server sv;
  CLI = &cl, SRV = &sv;
  memset(&cl, 0, sizeof cl), memset(&sv, 0, sizeof sv);
  cl.nreq = nreq, cl.pending_sid = -1;
  static quic_resume from;
  if (RESUME_FROM) from = *RESUME_FROM; /* (RES is refilled by this run) */
  EARLY_REQS = 0;
  int r0 = quic_connect_resume(&cl.q, &CQX, "localhost", now_ms(), &CQCB, &cl, RESUME_FROM ? &from : NULL);
  cl.q.resume_out = &RES;
  CHECK(r0 == 0, "quic_connect %d", r0);
  int accepted = 0, retries = 0, max_burst = 0, over_burst = 0, over_allowed = 0;
  uint64_t lost_at = 0;
  int prio_sent = 0;
  NORDER = 0;
  long before = fails;
  uint8_t out[1500];
  uint64_t start = NOW_NS;
  for (int guard = 0; guard < 2000000; guard++) {
    if (cl.ready) submit_more(&cl);
    if (PRIO == 2 && !prio_sent && cl.body > 20000) { /* midway: the 5th request becomes urgent */
      CHECK(h3_priority_update(&cl.h, 16, 0, 0) == 0, "PRIORITY_UPDATE");
      prio_sent = 1;
    }
    size_t n;
    while ((n = quic_send(&cl.q, out, sizeof out, now_ms())) > 0) put(&TO_SRV, out, n);
    dgram g;
    while (take(&TO_SRV, &g)) {
      if (LOSE_STATE && cl.done >= nreq / 2) { /* the server restarted: it knows the connection no more */
        uint8_t rt[64];
        size_t rn = quic_stateless_reset(&QX, g.d, g.n, rt, sizeof rt);
        if (rn) put(&TO_CLI, rt, rn);
        if (!lost_at) lost_at = NOW_NS;
        continue;
      }
      if (!accepted) {
        static const char addr[] = "198.51.100.7:4433", other[] = "203.0.113.9:4433";
        int has_token = g.n > 7 && g.d[5] <= 20 && g.d[6 + g.d[5]] <= 20 && g.d[7 + g.d[5] + g.d[6 + g.d[5]]] != 0;
        if (RETRY && !has_token) { /* a Retry, after a forged one the client must ignore */
          uint8_t rt[256];
          size_t rn = quic_retry(&QX, g.d, g.n, addr, sizeof addr, now_ms(), rt, sizeof rt);
          CHECK(rn > 0, "quic_retry");
          CHECK(quic_retry(&QX, g.d, 1199, addr, sizeof addr, now_ms(), rt, sizeof rt) == 0 &&
                    quic_retry(&QX, g.d, 64, addr, sizeof addr, now_ms(), rt, sizeof rt) == 0,
                "no Retry for a datagram under 1200 bytes (it would amplify a spoofed one)");
          if (!retries++) { rt[rn - 1] ^= 1, put(&TO_CLI, rt, rn), rt[rn - 1] ^= 1; /* a bad integrity tag */ }
          put(&TO_CLI, rt, rn);
          continue;
        }
        if (RETRY && !RESUME_FROM) { /* a Retry token from another address (a NEW_TOKEN one would be ignored) */
          static quic_conn probe;
          CHECK(quic_accept_from(&probe, &QX, g.d, g.n, other, sizeof other, now_ms(), &QCB, &sv) == QUIC_E_DROP,
                "a token from another address is refused");
        }
        if (quic_accept_from(&sv.q, &QX, g.d, g.n, addr, sizeof addr, now_ms(), &QCB, &sv) == 0) accepted = 1;
        continue;
      }
      quic_recv(&sv.q, g.d, g.n, now_ms());
    }
    if (accepted) { /* pacing: the most the server sends at one instant */
      int burst = 0;
      /* what the pacer may send now: its bucket's cap (10 packets, or 2 ms at up to 2 cwnd / srtt) */
      double rtt = sv.q.rtt_sampled && sv.q.smoothed_rtt > 1 ? (double)sv.q.smoothed_rtt : 1;
      double cap = 4.0 * (double)sv.q.cwnd / rtt > QUIC_PACE_BURST ? 4.0 * (double)sv.q.cwnd / rtt : QUIC_PACE_BURST;
      int allowed = (int)(cap / QUIC_SEND_MAX) + 3; /* + ACK-only packets and a probe */
      while ((n = quic_send(&sv.q, out, sizeof out, now_ms())) > 0) put(&TO_CLI, out, n), burst++;
      if (burst > max_burst) max_burst = burst;
      if (burst > allowed && !over_burst) over_burst = burst, over_allowed = allowed;
    }
    int got = 0;
    while (take(&TO_CLI, &g)) quic_recv(&cl.q, g.d, g.n, now_ms()), got = 1;
    if (got) { /* what that lets the client send (ACKs open its window) goes before time moves on, as a real loop does */
      if (cl.ready) submit_more(&cl);
      while ((n = quic_send(&cl.q, out, sizeof out, now_ms())) > 0) put(&TO_SRV, out, n);
    }
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
  if (LOSE_STATE) { /* the client learns at once: the server's token came in its transport parameters */
    CHECK(cl.q.reset && cl.q.draining && lost_at && NOW_NS - lost_at < 1000000000ull,
          "stateless reset: client reset %d draining %d, %.3f s after the server lost the connection", cl.q.reset,
          cl.q.draining, lost_at ? (NOW_NS - lost_at) / 1e9 : -1.0);
    printf("  loss %2d%%: the server lost its state halfway; the client was reset after %.0f ms\n", loss,
           (NOW_NS - lost_at) / 1e6);
    quic_free(&cl.q);
    if (accepted) quic_free(&sv.q);
    return 1;
  }
  CHECK(accepted && sv.h3_ready && cl.ready, "handshake (loss %d%%): accepted %d server h3 %d client h3 %d", loss,
        accepted, sv.h3_ready, cl.ready);
  /* paced: no instant's sending beyond the bucket's cap at that moment */
  CHECK(!over_burst, "the server sent %d datagrams at one instant, %d allowed", over_burst, over_allowed);
  CHECK(!RETRY || RESUME_FROM || (cl.q.retried && sv.q.retried && retries >= 1), "Retry: client %d server %d (%d sent)",
        cl.q.retried, sv.q.retried, retries);
  if (RESUME_FROM) { /* 0-RTT: sent, then taken (served before the handshake completed) or refused (sent again) */
    CHECK(cl.q.zrtt_sent && (EXPECT_EARLY ? EARLY_REQS > 0 : EARLY_REQS == 0),
          "0-RTT: sent %d, %ld requests served early (%s expected)", cl.q.zrtt_sent, EARLY_REQS,
          EXPECT_EARLY ? "some" : "none");
    CHECK(!RETRY || retries == 0, "the NEW_TOKEN validated the address: no Retry (%d sent)", retries);
  }
  CHECK(cl.q.confirmed && cl.q.sp[QUIC_SP_INITIAL].discarded && cl.q.sp[QUIC_SP_HANDSHAKE].discarded,
        "client handshake confirmed (HANDSHAKE_DONE), Initial and Handshake keys discarded");
  CHECK(!cl.failed && cl.done == nreq && cl.ok == nreq && !cl.statuses_bad,
        "loss %d%%: %d/%d done, %d right statuses, %d wrong", loss, cl.done, nreq, cl.ok, cl.statuses_bad);
  CHECK(nreq < 20 || cl.spilled >= nreq / 7 - 1, "requests with big header frames (spilled): %d", cl.spilled);
  /* once the server has acknowledged the table's entries, a request is its :path and a few one-byte references (in
   * runs long enough, and with loss low enough, for acknowledgements to arrive before the last quarter is sent) */
  CHECK(nreq < 100 || loss > 2 || BULK || (cl.h.qe.krc > 0 && cl.tail_bytes * 3 < cl.tail_raw),
        "QPACK: the server acknowledged %u inserts; the last requests' headers took %ld bytes for %ld bytes of fields",
        cl.h.qe.krc, cl.tail_bytes, cl.tail_raw);
  CHECK(cl.body == cl.want_body, "loss %d%%: body %ld want %ld", loss, cl.body, cl.want_body);
  CHECK(!cl.q.closing && !cl.q.draining, "client closed the connection: code 0x%llx frame 0x%llx (h3 0x%llx)",
        (unsigned long long)cl.q.close_code, (unsigned long long)cl.q.close_frame, (unsigned long long)h3_error(&cl.h));
  CHECK(!sv.q.closing && !sv.q.draining, "server closed the connection: code 0x%llx frame 0x%llx",
        (unsigned long long)sv.q.close_code, (unsigned long long)sv.q.close_frame);
  CHECK(sv.errors == 0 && cl.q.undecryptable == 0, "server stream errors %ld, client undecryptable %llu", sv.errors,
        (unsigned long long)cl.q.undecryptable);
  printf(
      "  loss %2d%% reorder %d%s%s: %d requests, %.1f simulated s, %ld datagrams (%ld lost), client cwnd %llu srtt %lld ms, "
      "request headers %.1f%% of their fields (%.1f%% at the end), max burst %d, %llu blocked sections\n",
      loss, reorder, BULK ? " bulk 1 MB, late 0.5%" : "",
      RETRY         ? " after a Retry"
      : RESUME_FROM ? (EXPECT_EARLY ? " 0-RTT" : " 0-RTT refused")
                    : "",
      nreq, (NOW_NS - start) / 1e9, SENT_DGRAMS, LOST_DGRAMS, (unsigned long long)cl.q.cwnd,
      (long long)cl.q.smoothed_rtt, cl.hdr_raw ? 100.0 * (double)cl.hdr_bytes / (double)cl.hdr_raw : 0.0,
      cl.tail_raw ? 100.0 * (double)cl.tail_bytes / (double)cl.tail_raw : 0.0, max_burst,
      (unsigned long long)sv.h.blocked_total);
  BLOCKED_SUM += sv.h.blocked_total, LAST_MTU = sv.q.mtu;
  SENT_DGRAMS = LOST_DGRAMS = 0;
  quic_free(&cl.q);
  if (accepted) quic_free(&sv.q);
  return fails == before;
}

/* Version Negotiation to the client: ignored when it lists v1 or does not echo our connection IDs; otherwise the
 * client closes at once with VERSION_NEGOTIATION_ERROR */
static void test_vn(void) {
  static quic_conn q;
  static const quic_callbacks none = { 0 };
  uint8_t init[1500], vn[256];
  for (int k = 0; k < 4; k++) {
    CHECK(quic_connect(&q, &CQX, "localhost", now_ms(), &none, NULL) == 0, "quic_connect");
    size_t n = quic_send(&q, init, sizeof init, now_ms());
    size_t vl = quic_version_negotiation(vn, sizeof vn, init, n); /* lists v1 */
    CHECK(vl > 11, "a Version Negotiation packet");
    if (k >= 1) memcpy(vn + vl - 4, "\x6b\x33\x43\xcf", 4);      /* v2 only */
    if (k == 2) vn[6] ^= 1;                                      /* not our SCID */
    if (k == 3) memcpy(vn + vl, "\x0a\x0a\x0a\x0a", 4), vl += 4; /* v2 and a reserved version */
    quic_recv(&q, vn, vl, now_ms());
    int closes = k == 1 || k == 3;
    CHECK(closes == (q.draining && q.close_code == QUIC_VERSION_NEGOTIATION_ERROR && q.vn_version == 0x6b3343cf),
          "Version Negotiation case %d: draining %d code 0x%llx", k, q.draining, (unsigned long long)q.close_code);
    CHECK(!closes || quic_is_closed(&q, now_ms()), "closed at once");
    quic_free(&q);
  }
  printf("  Version Negotiation: %s\n", fails ? "FAILED" : "ok");
}

int main(int argc, char **argv) {
  for (int i = 0; i < 1000; i++) BIG[i] = (uint8_t)i;
  server_init();
  client_tls_init();
  test_vn();
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
      RETRY = 1, run(50, 0, 0), run(100, 2, 1), RETRY = 0; /* address validation first */
      LOSE_STATE = 1, run(60, 0, 0), run(60, 2, 1), LOSE_STATE = 0;
      /* path MTU discovery: the server's datagrams grow to what the path carries (1472: IPv4 over Ethernet), to
       * 1350 on a tunnel's 1400, and stay at 1252 on 1280 */
      for (PRIO = 1; PRIO <= 2; PRIO++) { /* RFC 9218: the urgent response first, then the others in order */
        run(5, 0, 0);
        CHECK(NORDER == 5 && ORDER[0] == 16 && ORDER[1] == 0 && ORDER[2] == 4 && ORDER[3] == 8 && ORDER[4] == 12,
              "%s: responses finished in the order %d %d %d %d %d (want 16 0 4 8 12)",
              PRIO == 1 ? "priority field" : "PRIORITY_UPDATE", ORDER[0], ORDER[1], ORDER[2], ORDER[3], ORDER[4]);
      }
      PRIO = 0;
      static const int paths[3] = { 1500 - 28, 1400 - 28, 1280 - 28 }, want[3] = { 1472, 1350, 1252 };
      for (int m = 0; m < 3; m++) {
        PATH_MTU = paths[m], BULK = 1, run(8, 0, 0), BULK = 0;
        CHECK(LAST_MTU == want[m], "path %d: the server sends %d-byte datagrams", PATH_MTU + 28, LAST_MTU);
      }
      PATH_MTU = 1500 - 28;
      /* resumption: a ticket, a NEW_TOKEN and the server's limits saved, then 0-RTT; then the server's ticket key
       * changes (a restart): the ticket is refused, and the 0-RTT requests go again in 1-RTT */
      memset(&RES, 0, sizeof RES), run(30, 0, 0);
      CHECK(RES.ticket_len && RES.early && RES.token_len && RES.max_streams_bidi, "saved: ticket %u early %d token %u",
            RES.ticket_len, RES.early, RES.token_len);
      quic_resume saved = RES;
      RESUME_FROM = &saved, EXPECT_EARLY = 1;
      run(50, 0, 0), RETRY = 1, run(50, 0, 0), RETRY = 0, run(100, 2, 1);
      CLI_TLS.random_bytes(QX.tickets.key, sizeof QX.tickets.key), EXPECT_EARLY = 0, run(50, 0, 0);
      RESUME_FROM = NULL;
    }
  if (argc <= 1) /* reordering makes request streams overtake the encoder stream: sections wait for inserts */
    CHECK(BLOCKED_SUM > 0, "no QPACK section was ever blocked: the blocked-streams path went untested");
  printf("%s: %ld failures / %ld checks\n", fails ? "FAIL" : "PASS", fails, checks);
  return fails != 0;
}
