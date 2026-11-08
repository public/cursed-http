/* examples/h3_client.c: a minimal HTTP/3 client on include/quic.h + include/h3.h over UDP.
 *   ./h3_client host port [-n COUNT] [-b BODY_BYTES] [-H] [-k] path...
 * Sends every path COUNT times on one connection (up to the server's stream limit at a time), then prints one
 * line per response: "<status> <body bytes> <trailers>", and exits 0 if every stream ended without an error.
 * -H: HEAD. -b: a POST body of that many bytes. -k: do not verify the server's certificate (else it must chain to
 * the system's trust store and match host). Not a production client: one connection, no 0-RTT, poll(). */
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "quic.h"
#include "h3.h"
#include <picotls/openssl.h>

#define MAXR 4096
typedef struct {
  int status, trailers;
  uint64_t err;
  long body;
} resp;
static resp R[MAXR];
static int ndone, nerr, ready, sent, total, npaths;
static long upload;
static const char *HOST, *METHOD = "GET";
static char **PATHS;
static uint8_t *BODY;
static h3_scratch SC;
static quic_conn Q;
static h3_conn H;
static int R_OF[MAXR]; /* stream index (sid / 4) -> request */

static int64_t now_ms(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static resp *of(uint64_t sid) { return &R[R_OF[(sid >> 2) % MAXR]]; }
static int on_response(h3_conn *c, uint64_t sid, const h_response *rs, int end, void *u) {
  (void)c, (void)end, (void)u;
  if (rs->status >= 200) of(sid)->status = rs->status;
  return 0;
}
static int on_data(h3_conn *c, uint64_t sid, const uint8_t *d, size_t n, int end, void *u) {
  (void)c, (void)d, (void)end, (void)u;
  of(sid)->body += (long)n;
  return 0;
}
static int on_trailers(h3_conn *c, uint64_t sid, const hp_field *f, int n, void *u) {
  (void)c, (void)f, (void)u;
  of(sid)->trailers = n;
  return 0;
}
static void on_close(h3_conn *c, uint64_t sid, uint64_t err, void *u) {
  (void)c, (void)u;
  of(sid)->err = err, ndone++;
  if (err) nerr++;
}
static void reset_stream(h3_conn *c, uint64_t sid, uint64_t code, void *u) {
  (void)c, (void)u;
  quic_reset_stream(&Q, sid, code);
}
static const h3_callbacks H3CB = { NULL, on_data, on_trailers, NULL, on_close, reset_stream, on_response };

static void submit_more(void) {
  while (ready && sent < total) {
    int64_t sid = quic_open_bidi(&Q);
    if (sid < 0) return;
    h_request rq = { 0 };
    const char *path = PATHS[sent % npaths];
    rq.method = (const uint8_t *)METHOD, rq.method_len = (uint32_t)strlen(METHOD);
    rq.scheme = (const uint8_t *)"https", rq.scheme_len = 5;
    rq.authority = (const uint8_t *)HOST, rq.authority_len = (uint32_t)strlen(HOST);
    rq.path = (const uint8_t *)path, rq.path_len = (uint32_t)strlen(path);
    static const hp_field ua = {
      (const uint8_t *)"user-agent", (const uint8_t *)"cursed-http-h3-client", 10, 21, 0, 0, 0, 0
    };
    rq.fields = &ua, rq.nfields = 1;
    R_OF[(sid >> 2) % MAXR] = sent;
    if (h3_submit(&H, (uint64_t)sid, &rq, BODY, (size_t)upload, 1)) {
      fprintf(stderr, "h3_submit failed\n");
      exit(1);
    }
    sent++;
  }
}
static int64_t q_on_stream(quic_conn *q, uint64_t sid, uint64_t off, const uint8_t *d, size_t len, int fin, void *u) {
  (void)q, (void)u;
  if (!ready) return 0;
  int r = h3_recv(&H, &SC, sid, off, d, len, fin);
  return r < 0 ? -(int64_t)h3_error(&H) : r;
}
static size_t q_send(quic_conn *q, uint64_t sid, uint8_t *out, size_t cap, int *fin, void *u) {
  (void)q, (void)u;
  return h3_stream_send(&H, sid, out, cap, fin);
}
static int q_wants(quic_conn *q, uint64_t sid, void *u) {
  (void)q, (void)u;
  return h3_stream_wants(&H, sid);
}
static void q_reset(quic_conn *q, uint64_t sid, uint64_t code, void *u) {
  (void)q, (void)u;
  h3_peer_reset(&H, sid, code);
}
static void q_established(quic_conn *q, void *u) {
  (void)u;
  int64_t a = quic_open_uni(q), b = quic_open_uni(q), c = quic_open_uni(q);
  if (a < 0 || b < 0 || c < 0) {
    fprintf(stderr, "the server allows too few unidirectional streams\n");
    exit(1);
  }
  h3_init_client(&H, &H3CB, NULL, (uint64_t)a, (uint64_t)b, (uint64_t)c);
  ready = 1;
  submit_more();
}
static const quic_callbacks QCB = { q_on_stream, q_send, q_wants, q_reset, q_established };

int main(int argc, char **argv) {
  if (argc < 4) {
    fprintf(stderr, "usage: %s host port [-n COUNT] [-b BODY_BYTES] [-H] [-k] path...\n", argv[0]);
    return 2;
  }
  HOST = argv[1];
  const char *port = argv[2];
  int count = 1, ai = 3, insecure = 0;
  for (; ai < argc && argv[ai][0] == '-'; ai++) {
    if (!strcmp(argv[ai], "-n") && ai + 1 < argc) count = atoi(argv[++ai]);
    else if (!strcmp(argv[ai], "-b") && ai + 1 < argc) upload = atol(argv[++ai]), METHOD = "POST";
    else if (!strcmp(argv[ai], "-H")) METHOD = "HEAD";
    else if (!strcmp(argv[ai], "-k")) insecure = 1;
  }
  npaths = argc - ai, PATHS = argv + ai, total = npaths * count;
  if (npaths <= 0 || total > MAXR) return 2;
  if (upload) BODY = calloc(1, (size_t)upload);
  struct addrinfo hints = { 0 }, *res;
  hints.ai_socktype = SOCK_DGRAM;
  if (getaddrinfo(HOST, port, &hints, &res)) return 2;
  int fd = socket(res->ai_family, SOCK_DGRAM, 0);
  if (fd < 0 || connect(fd, res->ai_addr, res->ai_addrlen)) {
    perror("connect");
    return 2;
  }
  freeaddrinfo(res);
  static ptls_context_t tls;
  static ptls_openssl_verify_certificate_t verifier;
  tls.random_bytes = ptls_openssl_random_bytes, tls.get_time = &ptls_get_time;
  tls.key_exchanges = ptls_openssl_key_exchanges, tls.cipher_suites = ptls_openssl_cipher_suites;
  if (!insecure) {
    ptls_openssl_init_verify_certificate(&verifier, NULL); /* the system's default trust store */
    tls.verify_certificate = &verifier.super;
  }
  static quic_ctx qx;
  quic_ctx_init(&qx, &tls);
  if (quic_connect(&Q, &qx, HOST, now_ms(), &QCB, NULL)) {
    fprintf(stderr, "quic_connect failed\n");
    return 1;
  }
  uint8_t buf[2048];
  while (ndone < total && !quic_is_closed(&Q, now_ms())) {
    submit_more();
    size_t n;
    while ((n = quic_send(&Q, buf, sizeof buf, now_ms())) > 0)
      if (send(fd, buf, n, 0) < 0) perror("send");
    int64_t t = quic_timeout(&Q), wait = t == INT64_MAX ? 1000 : t - now_ms();
    struct pollfd pf = { fd, POLLIN, 0 };
    int pr = poll(&pf, 1, wait < 0 ? 0 : wait > 1000 ? 1000 : (int)wait);
    if (pr > 0) {
      ssize_t r;
      while ((r = recv(fd, buf, sizeof buf, MSG_DONTWAIT)) > 0) quic_recv(&Q, buf, (size_t)r, now_ms());
    }
    if (quic_timeout(&Q) <= now_ms()) quic_on_timeout(&Q, now_ms());
  }
  if (Q.closing || Q.draining)
    fprintf(stderr, "connection closed: code 0x%llx frame 0x%llx (h3 0x%llx)\n", (unsigned long long)Q.close_code,
            (unsigned long long)Q.close_frame, (unsigned long long)h3_error(&H));
  for (int i = 0; i < total; i++)
    printf("%d %ld %d%s\n", R[i].status, R[i].body, R[i].trailers, R[i].err ? " (reset)" : "");
  quic_close(&Q, H3_NO_ERROR);
  size_t n = quic_send(&Q, buf, sizeof buf, now_ms());
  if (n) send(fd, buf, n, 0);
  close(fd);
  return ndone == total && !nerr ? 0 : 1;
}
