/* examples/h2_client.c: a minimal HTTP/2 client on include/h2.h over TCP: TLS with ALPN "h2" (-s), or cleartext
 * with prior knowledge ("h2c").
 *   ./h2_client host port [-s] [-k] [-m METHOD] [-n COUNT] [-b BODY_BYTES] [-H] path...
 * Sends every path COUNT times, all multiplexed on one connection (up to the server's MAX_CONCURRENT_STREAMS),
 * then prints one line per response: "<status> <body bytes> <trailers>" and exits 0 if every stream ended
 * without an error. -s: TLS (OpenSSL; the certificate must chain to the system's trust store and match host,
 * unless -k), the server must choose h2. -H: the method is HEAD. -b: a request body of that many bytes (POST).
 * Not a production client: no redirects, blocking I/O with poll(). */
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "h2.h"
#include <openssl/err.h>
#include <openssl/ssl.h>

static SSL *TLS; /* -s */
static ssize_t tx(int fd, const uint8_t *d, size_t n) {
  if (!TLS) return write(fd, d, n);
  int w = SSL_write(TLS, d, (int)n);
  return w > 0 ? w : -1;
}
static ssize_t rx(int fd, uint8_t *d, size_t cap) {
  if (!TLS) return read(fd, d, cap);
  int r = SSL_read(TLS, d, (int)cap);
  return r > 0 ? r : (SSL_get_error(TLS, r) == SSL_ERROR_ZERO_RETURN ? 0 : -1);
}

#define MAXR 4096
typedef struct {
  int status, trailers, closed;
  uint32_t err;
  long body;
} resp;
static resp R[MAXR];
static uint32_t SID2R[2 * MAXR + 2];
static int ndone, nerr;
static h2_scratch SC;

static int on_response(h2_conn *c, uint32_t sid, const h2_response *rs, int end, void *u) {
  (void)c, (void)end, (void)u;
  if (rs->status >= 200) R[SID2R[sid] - 1].status = rs->status;
  return 0;
}
static int on_data(h2_conn *c, uint32_t sid, const uint8_t *d, size_t n, int end, void *u) {
  (void)c, (void)d, (void)end, (void)u;
  R[SID2R[sid] - 1].body += (long)n;
  return 0;
}
static int on_trailers(h2_conn *c, uint32_t sid, const hp_field *f, int n, void *u) {
  (void)c, (void)f, (void)u;
  R[SID2R[sid] - 1].trailers = n;
  return 0;
}
static void on_close(h2_conn *c, uint32_t sid, uint32_t err, void *u) {
  (void)c, (void)u;
  resp *r = &R[SID2R[sid] - 1];
  r->closed = 1, r->err = err, ndone++;
  if (err) nerr++;
}

int main(int argc, char **argv) {
  if (argc < 4) {
    fprintf(stderr, "usage: %s host port [-s] [-k] [-m METHOD] [-n COUNT] [-b BODY_BYTES] [-H] path...\n", argv[0]);
    return 2;
  }
  const char *host = argv[1], *port = argv[2], *method = "GET";
  int count = 1, ai = 3, tls = 0, insecure = 0;
  long upload = 0;
  for (; ai < argc && argv[ai][0] == '-'; ai++) {
    if (!strcmp(argv[ai], "-m") && ai + 1 < argc) method = argv[++ai];
    else if (!strcmp(argv[ai], "-n") && ai + 1 < argc) count = atoi(argv[++ai]);
    else if (!strcmp(argv[ai], "-b") && ai + 1 < argc) upload = atol(argv[++ai]), method = "POST";
    else if (!strcmp(argv[ai], "-H")) method = "HEAD";
    else if (!strcmp(argv[ai], "-s")) tls = 1;
    else if (!strcmp(argv[ai], "-k")) insecure = 1;
  }
  int npaths = argc - ai, total = npaths * count;
  if (npaths <= 0 || total > MAXR) return 2;
  struct addrinfo hints = { 0 }, *ai_res;
  hints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo(host, port, &hints, &ai_res)) return 2;
  int fd = socket(ai_res->ai_family, SOCK_STREAM, 0);
  if (fd < 0 || connect(fd, ai_res->ai_addr, ai_res->ai_addrlen)) {
    perror("connect");
    return 2;
  }
  freeaddrinfo(ai_res);
  if (tls) { /* TLS 1.2+, ALPN h2 (RFC 9113 §3.2), SNI and certificate checks */
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    static const unsigned char alpn[] = { 2, 'h', '2' };
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_alpn_protos(ctx, alpn, sizeof alpn);
    if (!insecure) SSL_CTX_set_default_verify_paths(ctx), SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    TLS = SSL_new(ctx);
    SSL_set_fd(TLS, fd), SSL_set_tlsext_host_name(TLS, host);
    if (!insecure) SSL_set1_host(TLS, host);
    if (SSL_connect(TLS) != 1) {
      fprintf(stderr, "TLS handshake failed: ");
      ERR_print_errors_fp(stderr);
      return 1;
    }
    const unsigned char *proto;
    unsigned int pl;
    SSL_get0_alpn_selected(TLS, &proto, &pl);
    if (pl != 2 || memcmp(proto, "h2", 2)) {
      fprintf(stderr, "the server did not choose h2 (ALPN: %.*s)\n", (int)pl, pl ? (const char *)proto : "none");
      return 1;
    }
  }
  static h2_conn C;
  h2_callbacks cb = { NULL, on_data, on_trailers, NULL, on_close, on_response };
  h2_init_client(&C, &cb, NULL);
  uint8_t *body = upload ? calloc(1, (size_t)upload) : NULL;
  static uint8_t in[1 << 17], out[1 << 16];
  size_t inlen = 0;
  int sent = 0;
  while (ndone < total) {
    while (sent < total) { /* as many as the server lets us have open */
      h2_request rq = { 0 };
      const char *path = argv[ai + sent % npaths];
      rq.method = (const uint8_t *)method, rq.method_len = (uint32_t)strlen(method);
      rq.scheme = (const uint8_t *)(tls ? "https" : "http"), rq.scheme_len = tls ? 5 : 4;
      rq.authority = (const uint8_t *)host, rq.authority_len = (uint32_t)strlen(host);
      rq.path = (const uint8_t *)path, rq.path_len = (uint32_t)strlen(path);
      static char clen[24];
      static hp_field fl[2] = { { (const uint8_t *)"user-agent", (const uint8_t *)"cursed-http-h2-client", 10, 21, 0, 0,
                                  0, 0 },
                                { (const uint8_t *)"content-length", (const uint8_t *)clen, 14, 0, 0, 0, 0, 0 } };
      fl[1].vlen = (uint32_t)snprintf(clen, sizeof clen, "%ld", upload);
      rq.fields = fl, rq.nfields = upload ? 2 : 1;
      int sid = h2_submit(&C, &rq, body, (size_t)upload, 1);
      if (sid == H2_E_AGAIN) break;
      if (sid < 0) {
        fprintf(stderr, "h2_submit: %d\n", sid);
        return 1;
      }
      SID2R[sid] = (uint32_t)sent + 1, sent++;
    }
    size_t n;
    while ((n = h2_send(&C, out, sizeof out)) > 0)
      for (size_t o = 0; o < n;) {
        ssize_t w = tx(fd, out + o, n - o);
        if (w <= 0) {
          perror("write");
          return 1;
        }
        o += (size_t)w;
      }
    if (h2_is_closed(&C)) break;
    if (inlen) { /* h2_recv stops early while its output is backed up: retry the tail now that it is sent */
      int used = h2_recv(&C, &SC, in, inlen);
      if (used < 0) break;
      if (used > 0) {
        memmove(in, in + used, inlen - (size_t)used), inlen -= (size_t)used;
        continue;
      }
    }
    struct pollfd pf = { fd, POLLIN, 0 };
    if (!(TLS && SSL_pending(TLS)) && poll(&pf, 1, 10000) <= 0) { /* (TLS may hold bytes already read) */
      fprintf(stderr, "timeout: %d of %d done\n", ndone, total);
      return 1;
    }
    ssize_t r = rx(fd, in + inlen, sizeof in - inlen);
    if (r <= 0) {
      fprintf(stderr, "connection closed by the server: %d of %d done\n", ndone, total);
      break;
    }
    inlen += (size_t)r;
    int used = h2_recv(&C, &SC, in, inlen);
    if (used < 0) {
      fprintf(stderr, "h2_recv failed the connection\n");
      break;
    }
    memmove(in, in + used, inlen - (size_t)used), inlen -= (size_t)used;
  }
  for (int i = 0; i < total; i++)
    R[i].err ? printf("%d %ld %d (reset 0x%x)\n", R[i].status, R[i].body, R[i].trailers, (unsigned)R[i].err)
             : printf("%d %ld %d\n", R[i].status, R[i].body, R[i].trailers);
  close(fd);
  return ndone == total && !nerr ? 0 : 1;
}
