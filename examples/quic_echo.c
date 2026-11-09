/* examples/quic_echo.c: raw QUIC (include/quic.h with no HTTP/3) over UDP: an echo protocol, ALPN "echo".
 *   ./quic_echo server cert.pem key.pem [port]
 *   ./quic_echo client host port [-n STREAMS] [-b BYTES] [-k]
 * The server echoes every bidirectional stream a client opens (bytes, then a fin), and also opens one of its own to
 * each client, carrying "hello from the server\n", which the client echoes back. The client opens STREAMS streams
 * (default 4) of BYTES bytes each (default 100000), checks every echoed byte, echoes the server's stream, and exits
 * 0 if everything came back intact. -k: do not verify the server's certificate.
 * What it shows: quic_ctx.alpn (our own protocol), a server opening bidirectional streams (the client allows them
 * with quic_ctx.max_streams_bidi), and quic_callbacks as the whole application interface. Not a production server:
 * poll(), loopback only, at most 16 connections, everything held in memory. */
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <openssl/pem.h>
#include "quic.h"
#include <picotls/openssl.h>

static const char *ALPN[1] = { "echo" };
static const char HELLO[] = "hello from the server\n";

static int64_t now_ms(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static uint8_t pattern(uint64_t sid, uint64_t off) { return (uint8_t)(sid * 31 + off * 7 + (off >> 9)); }

/* ---------------- one side's streams: what to send on each, and what came in ---------------- */
#define MAXS 64
typedef struct {
  uint64_t sid;
  int used, ours, fin_in, fin_out; /* ours: we opened it and check the echo; else we echo it */
  uint8_t *buf;                    /* to send: our payload, or the echo of what arrived */
  size_t len, cap, sent, recv;
} stream;
typedef struct {
  quic_conn q;
  stream s[MAXS];
  struct sockaddr_storage peer;
  socklen_t peerlen;
  int server, opened, done, bad;
} conn;
static stream *get(conn *c, uint64_t sid, int create) {
  for (int i = 0; i < MAXS; i++)
    if (c->s[i].used && c->s[i].sid == sid) return &c->s[i];
  for (int i = 0; create && i < MAXS; i++)
    if (!c->s[i].used) {
      memset(&c->s[i], 0, sizeof c->s[i]), c->s[i].used = 1, c->s[i].sid = sid;
      return &c->s[i];
    }
  return NULL;
}
static void conn_free(conn *c) {
  for (int i = 0; i < MAXS; i++) free(c->s[i].buf);
  quic_free(&c->q);
}
/* a stream of ours, with its payload */
static int open_stream(conn *c, const uint8_t *d, size_t n) {
  int64_t sid = quic_open_bidi(&c->q);
  if (sid < 0) return -1; /* at the peer's stream limit, for now */
  stream *s = get(c, (uint64_t)sid, 1);
  if (!s) return -1;
  s->ours = 1, s->len = s->cap = n, s->buf = malloc(n ? n : 1);
  for (size_t i = 0; i < n; i++) s->buf[i] = d ? d[i] : pattern((uint64_t)sid, i);
  c->opened++;
  return 0;
}

/* ---------------- quic_callbacks: the whole application interface ---------------- */
static int64_t on_stream(quic_conn *q, uint64_t sid, uint64_t off, const uint8_t *d, size_t n, int fin, void *u) {
  (void)q;
  conn *c = u;
  stream *s = get(c, sid, 1);
  if (!s || off != s->recv) return -1; /* (quic.h delivers in order; any error closes with that code) */
  if (s->ours) {                       /* the echo of our payload: every byte checked */
    for (size_t i = 0; i < n; i++)
      if (off + i >= s->len || d[i] != s->buf[off + i]) return c->bad++, -1;
  } else { /* the peer's: kept to send back */
    if (s->len + n > s->cap) s->cap = (s->len + n) * 2 + 4096, s->buf = realloc(s->buf, s->cap);
    memcpy(s->buf + s->len, d, n), s->len += n;
  }
  s->recv += n;
  if (fin) {
    s->fin_in = 1;
    if (s->ours && s->recv == s->len) c->done++;
    else if (s->ours) c->bad++;
  }
  return (int64_t)n; /* consumed: the flow-control window reopens by that much */
}
static int fin_due(const stream *s) { return !s->fin_out && (s->ours || s->fin_in); }
static size_t on_send(quic_conn *q, uint64_t sid, uint8_t *out, size_t cap, int *fin, void *u) {
  (void)q;
  stream *s = get(u, sid, 0);
  if (!s) return 0;
  size_t m = s->len - s->sent < cap ? s->len - s->sent : cap;
  memcpy(out, s->buf + s->sent, m), s->sent += m;
  if (s->sent == s->len && fin_due(s)) *fin = 1, s->fin_out = 1;
  return m;
}
static int wants(quic_conn *q, uint64_t sid, void *u) {
  (void)q;
  stream *s = get(u, sid, 0);
  return s && (s->sent < s->len || fin_due(s));
}
static void on_reset(quic_conn *q, uint64_t sid, uint64_t code, void *u) {
  (void)q;
  fprintf(stderr, "stream %llu reset by the peer: 0x%llx\n", (unsigned long long)sid, (unsigned long long)code);
  ((conn *)u)->bad++;
}
static void established(quic_conn *q, void *u) {
  conn *c = u;
  fprintf(stderr, "%s: established, ALPN %s\n", c->server ? "server" : "client", quic_alpn(q));
  if (c->server && open_stream(c, (const uint8_t *)HELLO, sizeof HELLO - 1))
    fprintf(stderr, "server: this client allows no streams from us\n");
}
static const quic_callbacks CB = { on_stream, on_send, wants, on_reset, established, NULL };

static void tls_init(ptls_context_t *t) {
  t->random_bytes = ptls_openssl_random_bytes, t->get_time = &ptls_get_time;
  t->key_exchanges = ptls_openssl_key_exchanges, t->cipher_suites = ptls_openssl_cipher_suites;
}

/* ---------------- the server ---------------- */
#define MAXC 16
static conn *C[MAXC];
static int find(const uint8_t *d, size_t n) { /* our connection ID is at a fixed place in either header */
  for (int i = 0; i < MAXC; i++) {
    if (!C[i]) continue;
    if (d[0] & 0x80) {
      if (n > 6 + QUIC_SCID_LEN && d[5] == QUIC_SCID_LEN && !memcmp(d + 6, C[i]->q.scid, QUIC_SCID_LEN)) return i;
      if (n > 6u + d[5] && d[5] == C[i]->q.idcid_len && !memcmp(d + 6, C[i]->q.idcid, d[5])) return i;
    } else if (n > 1 + QUIC_SCID_LEN && !memcmp(d + 1, C[i]->q.scid, QUIC_SCID_LEN)) {
      return i;
    }
  }
  return -1;
}
static int server(const char *certf, const char *keyf, int port) {
  static ptls_context_t tls;
  static ptls_openssl_sign_certificate_t sign;
  tls_init(&tls);
  FILE *kf = fopen(keyf, "rb");
  EVP_PKEY *pk = kf ? PEM_read_PrivateKey(kf, NULL, NULL, NULL) : NULL;
  if (kf) fclose(kf);
  if (ptls_load_certificates(&tls, certf) || !pk || ptls_openssl_init_sign_certificate(&sign, pk)) {
    fprintf(stderr, "cannot load %s / %s\n", certf, keyf);
    return 1;
  }
  tls.sign_certificate = &sign.super;
  static quic_ctx qx;
  quic_ctx_init(&qx, &tls);
  qx.alpn = ALPN, qx.nalpn = 1; /* only "echo": a client offering nothing else is refused (no_application_protocol) */
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  struct sockaddr_in a = { .sin_family = AF_INET,
                           .sin_port = htons((uint16_t)port),
                           .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
  if (fd < 0 || bind(fd, (struct sockaddr *)&a, sizeof a)) {
    perror("bind");
    return 1;
  }
  fprintf(stderr, "server: echo over QUIC on udp 127.0.0.1:%d\n", port);
  static uint8_t buf[65536], out[1500];
  for (;;) {
    int64_t now = now_ms(), next = now + 1000;
    for (int i = 0; i < MAXC; i++)
      if (C[i] && quic_timeout(&C[i]->q) < next) next = quic_timeout(&C[i]->q);
    struct pollfd p = { fd, POLLIN, 0 };
    poll(&p, 1, next > now ? (int)(next - now) : 0);
    now = now_ms();
    for (;;) {
      struct sockaddr_storage from;
      socklen_t fl = sizeof from;
      ssize_t n = recvfrom(fd, buf, sizeof buf, MSG_DONTWAIT, (struct sockaddr *)&from, &fl);
      if (n <= 0) break;
      int i = find(buf, (size_t)n);
      if (i >= 0) {
        quic_recv(&C[i]->q, buf, (size_t)n, now);
        continue;
      }
      if (!(buf[0] & 0x80)) continue;
      for (i = 0; i < MAXC && C[i]; i++) {}
      if (i == MAXC) continue;
      conn *c = calloc(1, sizeof *c);
      c->server = 1;
      int r = quic_accept_from(&c->q, &qx, buf, (size_t)n, &from, fl, now, &CB, c);
      if (r == QUIC_E_VN) {
        size_t vl = quic_version_negotiation(out, sizeof out, buf, (size_t)n);
        if (vl) sendto(fd, out, vl, 0, (struct sockaddr *)&from, fl);
      }
      if (r == 0) c->peer = from, c->peerlen = fl, C[i] = c;
      else {
        if (c->q.tls) quic_free(&c->q);
        free(c);
      }
    }
    for (int i = 0; i < MAXC; i++) {
      conn *c = C[i];
      if (!c) continue;
      if (quic_timeout(&c->q) <= now) quic_on_timeout(&c->q, now);
      size_t n;
      while ((n = quic_send(&c->q, out, sizeof out, now)) > 0)
        sendto(fd, out, n, 0, (struct sockaddr *)&c->peer, c->peerlen);
      if (quic_is_closed(&c->q, now) || (c->q.draining && !c->q.close_deadline)) {
        fprintf(stderr, "server: a connection closed (%d streams echoed back to it)\n", c->done);
        conn_free(c), free(c), C[i] = NULL;
      }
    }
  }
}

/* ---------------- the client ---------------- */
static int client(const char *host, const char *port, int nstreams, size_t bytes, int insecure) {
  struct addrinfo hints = { 0 }, *res;
  hints.ai_socktype = SOCK_DGRAM;
  if (getaddrinfo(host, port, &hints, &res)) return 2;
  int fd = socket(res->ai_family, SOCK_DGRAM, 0);
  if (fd < 0 || connect(fd, res->ai_addr, res->ai_addrlen)) {
    perror("connect");
    return 2;
  }
  freeaddrinfo(res);
  static ptls_context_t tls;
  static ptls_openssl_verify_certificate_t verifier;
  tls_init(&tls);
  if (!insecure) ptls_openssl_init_verify_certificate(&verifier, NULL), tls.verify_certificate = &verifier.super;
  static quic_ctx qx;
  quic_ctx_init(&qx, &tls);
  qx.alpn = ALPN, qx.nalpn = 1;
  qx.max_streams_bidi = 4; /* a client allows none by default (HTTP/3's servers open none): the echo server opens one */
  static conn c;
  if (quic_connect(&c.q, &qx, host, now_ms(), &CB, &c)) return 1;
  int64_t start = now_ms();
  static uint8_t buf[2048];
  /* done: all of ours echoed back and the server's stream echoed to it; then a moment for the last ACKs */
  int64_t linger = 0;
  for (;;) {
    stream *hs = NULL;
    for (int i = 0; i < MAXS; i++)
      if (c.s[i].used && !c.s[i].ours) hs = &c.s[i];
    if (!linger && c.done == nstreams && hs && hs->fin_out) linger = now_ms() + 200;
    if ((linger && now_ms() >= linger) || c.bad || quic_is_closed(&c.q, now_ms())) break;
    while (c.q.established && c.opened < nstreams && !open_stream(&c, NULL, bytes)) {}
    size_t n;
    while ((n = quic_send(&c.q, buf, sizeof buf, now_ms())) > 0)
      if (send(fd, buf, n, 0) < 0) perror("send");
    int64_t t = quic_timeout(&c.q), wait = t == INT64_MAX ? 1000 : t - now_ms();
    if (linger && linger - now_ms() < wait) wait = linger - now_ms();
    struct pollfd pf = { fd, POLLIN, 0 };
    if (poll(&pf, 1, wait < 0 ? 0 : wait > 1000 ? 1000 : (int)wait) > 0) {
      ssize_t r;
      while ((r = recv(fd, buf, sizeof buf, MSG_DONTWAIT)) > 0) quic_recv(&c.q, buf, (size_t)r, now_ms());
    }
    if (quic_timeout(&c.q) <= now_ms()) quic_on_timeout(&c.q, now_ms());
  }
  double secs = (double)(now_ms() - start) / 1000;
  if (c.q.closing || c.q.draining)
    fprintf(stderr, "client: connection closed: code 0x%llx\n", (unsigned long long)c.q.close_code);
  printf("client: %d/%d streams of %zu bytes echoed intact in %.3f s, %d errors; the server's stream: ", c.done,
         nstreams, bytes, secs, c.bad);
  for (int i = 0; i < MAXS; i++)
    if (c.s[i].used && !c.s[i].ours) printf("%.*s", (int)c.s[i].len, (const char *)c.s[i].buf);
  int ok = c.done == nstreams && !c.bad;
  quic_close(&c.q, 0);
  size_t n = quic_send(&c.q, buf, sizeof buf, now_ms());
  if (n) send(fd, buf, n, 0);
  conn_free(&c), close(fd);
  return ok ? 0 : 1;
}

int main(int argc, char **argv) {
  if (argc >= 4 && !strcmp(argv[1], "server")) return server(argv[2], argv[3], argc > 4 ? atoi(argv[4]) : 4434);
  if (argc >= 4 && !strcmp(argv[1], "client")) {
    int n = 4, k = 0;
    size_t b = 100000;
    for (int i = 4; i < argc; i++) {
      if (!strcmp(argv[i], "-n") && i + 1 < argc) n = atoi(argv[++i]);
      else if (!strcmp(argv[i], "-b") && i + 1 < argc) b = (size_t)atol(argv[++i]);
      else if (!strcmp(argv[i], "-k")) k = 1;
    }
    if (n < 1 || n > MAXS - 8) return 2;
    return client(argv[2], argv[3], n, b, k);
  }
  fprintf(stderr, "usage: %s server cert.pem key.pem [port]\n       %s client host port [-n STREAMS] [-b BYTES] [-k]\n",
          argv[0], argv[0]);
  return 2;
}
