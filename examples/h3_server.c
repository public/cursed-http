/* examples/h3_server.c: a minimal HTTP/3 server on include/quic.h + include/h3.h over UDP.
 * One thread, poll(), up to 64 connections found by our connection ID.
 *   ./h3_server cert.pem key.pem [port]     GET /big/N -> N bytes; GET anything else -> "hello, world\n";
 *                                           POST -> "ok\n"
 * Not a production server: no Retry/address validation tokens, no connection ID rotation,
 * connections are malloc'd. Build: see mk/h2h3.mk (needs picotls + OpenSSL libcrypto). */
#include <errno.h>
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
#include "h3.h"
#include <picotls/openssl.h>

#define MAXC 64
typedef struct {
  quic_conn q;
  h3_conn h;
  int ready;
  struct sockaddr_storage peer;
  socklen_t peerlen;
} conn;
static conn *C[MAXC];
static h3_scratch SC;

static int64_t now_ms(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

/* GET /big/N: N bytes (N <= 1 MiB), for responses spanning many frames or packets */
static uint8_t BIG[1 << 20];
static size_t big_len(const uint8_t *path, uint32_t len) {
  if (len < 6 || memcmp(path, "/big/", 5)) return SIZE_MAX;
  size_t n = 0;
  for (uint32_t i = 5; i < len && path[i] >= '0' && path[i] <= '9'; i++) n = n * 10 + (size_t)(path[i] - '0');
  return n > sizeof BIG ? sizeof BIG : n;
}
static int on_request(h3_conn *h, uint64_t sid, const h_request *rq, int end, void *u) {
  (void)u;
  static const hp_field ct = { (const uint8_t *)"content-type", (const uint8_t *)"text/plain", 12, 10, 0, 0, 0, 0 };
  size_t big = big_len(rq->path, rq->path_len);
  int head = rq->method_len == 4 && !memcmp(rq->method, "HEAD", 4); /* a response to HEAD has no content */
  if (end && big != SIZE_MAX) return h3_respond(h, sid, 200, &ct, 1, BIG, head ? 0 : big, 1) < 0;
  return end ? h3_respond(h, sid, 200, &ct, 1, (const uint8_t *)"hello, world\n", head ? 0 : 13, 1) < 0 : 0;
}
static int on_data(h3_conn *h, uint64_t sid, const uint8_t *d, size_t n, int end, void *u) {
  (void)d, (void)n, (void)u;
  h3_stream *s = h3__find(h, sid);
  static const hp_field ct = { (const uint8_t *)"content-type", (const uint8_t *)"text/plain", 12, 10, 0, 0, 0, 0 };
  if (!end || !s || (s->flags & H3_ST_RESPONDED)) return 0;
  return h3_respond(h, sid, 200, &ct, 1, (const uint8_t *)"ok\n", 3, 1) < 0;
}
static void h3_reset_cb(h3_conn *h, uint64_t sid, uint64_t code, void *u) {
  (void)h;
  quic_reset_stream(&((conn *)u)->q, sid, code);
}
static const h3_callbacks H3CB = { on_request, on_data, NULL, NULL, NULL, h3_reset_cb, NULL };

static int64_t q_stream(quic_conn *q, uint64_t sid, uint64_t off, const uint8_t *d, size_t len, int fin, void *u) {
  (void)q;
  conn *c = u;
  if (!c->ready) return 0;
  int r = h3_recv(&c->h, &SC, sid, off, d, len, fin);
  return r < 0 ? -(int64_t)h3_error(&c->h) : r;
}
static size_t q_send(quic_conn *q, uint64_t sid, uint8_t *out, size_t cap, int *fin, void *u) {
  (void)q;
  return h3_stream_send(&((conn *)u)->h, sid, out, cap, fin);
}
static int q_wants(quic_conn *q, uint64_t sid, void *u) {
  (void)q;
  return h3_stream_wants(&((conn *)u)->h, sid);
}
static void q_reset(quic_conn *q, uint64_t sid, uint64_t code, void *u) {
  (void)q;
  h3_peer_reset(&((conn *)u)->h, sid, code);
}
static void q_established(quic_conn *q, void *u) {
  conn *c = u;
  int64_t a = quic_open_uni(q), b = quic_open_uni(q), d = quic_open_uni(q);
  if (a < 0 || b < 0 || d < 0) {
    quic_close(q, H3_INTERNAL_ERROR);
    return;
  }
  h3_init(&c->h, &H3CB, c, (uint64_t)a, (uint64_t)b, (uint64_t)d);
  c->ready = 1;
}
static const quic_callbacks QCB = { q_stream, q_send, q_wants, q_reset, q_established };

/* the connection a datagram belongs to: our connection ID is at a fixed place in either header */
static int find(const uint8_t *d, size_t n) {
  for (int i = 0; i < MAXC; i++) {
    if (!C[i]) continue;
    if (d[0] & 0x80) {
      if (n > 6 + QUIC_SCID_LEN && d[5] == QUIC_SCID_LEN && !memcmp(d + 6, C[i]->q.scid, QUIC_SCID_LEN)) return i;
      if (n > 6u + d[5] && d[5] == C[i]->q.odcid_len && !memcmp(d + 6, C[i]->q.odcid, d[5]))
        return i; /* client Initial retransmits */
    } else if (n > 1 + QUIC_SCID_LEN && !memcmp(d + 1, C[i]->q.scid, QUIC_SCID_LEN)) {
      return i;
    }
  }
  return -1;
}

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "usage: %s cert.pem key.pem [port] [-r]   (-r: validate addresses with a Retry first)\n", argv[0]);
    return 1;
  }
  int port = argc > 3 ? atoi(argv[3]) : 4433, retry = argc > 4 && !strcmp(argv[4], "-r");
  memset(BIG, 'x', sizeof BIG);
  static ptls_context_t tls;
  static ptls_openssl_sign_certificate_t sign;
  tls.random_bytes = ptls_openssl_random_bytes, tls.get_time = &ptls_get_time;
  tls.key_exchanges = ptls_openssl_key_exchanges, tls.cipher_suites = ptls_openssl_cipher_suites;
  if (ptls_load_certificates(&tls, argv[1])) {
    fprintf(stderr, "cannot load %s\n", argv[1]);
    return 1;
  }
  FILE *kf = fopen(argv[2], "rb");
  EVP_PKEY *pk = kf ? PEM_read_PrivateKey(kf, NULL, NULL, NULL) : NULL;
  if (kf) fclose(kf);
  if (!pk || ptls_openssl_init_sign_certificate(&sign, pk)) {
    fprintf(stderr, "cannot load %s\n", argv[2]);
    return 1;
  }
  tls.sign_certificate = &sign.super;
  static quic_ctx qx;
  quic_ctx_init(&qx, &tls);

  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  struct sockaddr_in a = { .sin_family = AF_INET,
                           .sin_port = htons((uint16_t)port),
                           .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
  if (fd < 0 || bind(fd, (struct sockaddr *)&a, sizeof a)) {
    perror("bind");
    return 1;
  }
  fprintf(stderr, "h3_server: HTTP/3 on udp port %d\n", port);
  static uint8_t buf[65536], out[1500];
  for (;;) {
    int64_t now = now_ms(), next = now + 1000;
    for (int i = 0; i < MAXC; i++)
      if (C[i]) {
        int64_t t = quic_timeout(&C[i]->q);
        if (t < next) next = t;
      }
    struct pollfd p = { fd, POLLIN, 0 };
    poll(&p, 1, next > now ? (int)(next - now) : 0);
    now = now_ms();
    if (p.revents & POLLIN) {
      struct sockaddr_storage from;
      socklen_t fl = sizeof from;
      ssize_t n = recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
      if (n > 0) {
        int i = find(buf, (size_t)n);
        if (i >= 0) quic_recv(&C[i]->q, buf, (size_t)n, now);
        else if (!(buf[0] & 0x80)) { /* a short header for a connection we do not have (a restart?): reset it */
          size_t rl = quic_stateless_reset(&qx, buf, (size_t)n, out, sizeof out);
          if (rl) sendto(fd, out, rl, 0, (struct sockaddr *)&from, fl);
        } else {
          for (i = 0; i < MAXC && C[i]; i++) {}
          if (i < MAXC) {
            /* -r: an Initial without a token gets a Retry (bound to the client's address); one with a token is
             * accepted only if the token checks out */
            size_t tl = n > 7 && buf[5] <= 20 && buf[6 + buf[5]] <= 20 ? buf[7 + buf[5] + buf[6 + buf[5]]] : 0;
            if (retry && !tl) {
              size_t rl = quic_retry(&qx, buf, (size_t)n, &from, fl, now, out, sizeof out);
              if (rl) sendto(fd, out, rl, 0, (struct sockaddr *)&from, fl);
              continue;
            }
            conn *c = calloc(1, sizeof *c);
            int r = c ? quic_accept_from(&c->q, &qx, buf, (size_t)n, retry ? (const void *)&from : NULL, retry ? fl : 0,
                                         now, &QCB, c)
                      : QUIC_E_NOMEM;
            if (r == QUIC_E_VN) {
              size_t vl = quic_version_negotiation(out, sizeof out, buf, (size_t)n);
              if (vl) sendto(fd, out, vl, 0, (struct sockaddr *)&from, fl);
            }
            if (r == 0) c->peer = from, c->peerlen = fl, C[i] = c;
            else if (c) {
              if (c->q.tls) quic_free(&c->q);
              free(c);
            }
          }
        }
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
        quic_free(&c->q);
        free(c);
        C[i] = NULL;
      }
    }
  }
}
