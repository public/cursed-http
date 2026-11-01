/* examples/h2_server.c: a minimal HTTP/2 (h2c, prior knowledge) server on include/h2.h, for h2spec
 * and manual testing. One thread, poll(), one h2_conn per connection.
 *   ./h2_server [port]          GET /big/N -> N bytes; GET anything else -> 200 "hello, world\n";
 *                               POST -> 200 with the body length
 * Not a production server: no TLS, no timeouts, connections are malloc'd. */
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "h2.h"

#define MAXC 256
typedef struct {
  int fd;
  h2_conn h2;
  uint8_t in[H2_MAX_BLOCK + 32768];
  size_t inlen;
  long body[2048]; /* request body bytes per stream id / 2, for POST answers */
  char reply[2048][24];
} conn;
static conn *C[MAXC];
static h2_scratch SC;

/* GET /big/N: N bytes (N <= 1 MiB), for responses spanning many frames or packets */
static uint8_t BIG[1 << 20];
static size_t big_len(const uint8_t *path, uint32_t len) {
  if (len < 6 || memcmp(path, "/big/", 5)) return SIZE_MAX;
  size_t n = 0;
  for (uint32_t i = 5; i < len && path[i] >= '0' && path[i] <= '9'; i++) n = n * 10 + (size_t)(path[i] - '0');
  return n > sizeof BIG ? sizeof BIG : n;
}
static int on_request(h2_conn *h, uint32_t sid, const h2_request *rq, int end, void *u) {
  conn *c = u;
  static const hp_field ct = { (const uint8_t *)"content-type", (const uint8_t *)"text/plain", 12, 10, 0, 0, 0, 0 };
  c->body[(sid / 2) % 2048] = 0;
  size_t big = big_len(rq->path, rq->path_len);
  if (end && big != SIZE_MAX) return h2_respond(h, sid, 200, &ct, 1, BIG, big, 1) < 0;
  if (end) return h2_respond(h, sid, 200, &ct, 1, (const uint8_t *)"hello, world\n", 13, 1) < 0;
  return 0;
}
static int on_data(h2_conn *h, uint32_t sid, const uint8_t *d, size_t n, int end, void *u) {
  conn *c = u;
  (void)d;
  c->body[(sid / 2) % 2048] += (long)n;
  if (!end) return 0;
  static const hp_field ct = { (const uint8_t *)"content-type", (const uint8_t *)"text/plain", 12, 10, 0, 0, 0, 0 };
  char *r = c->reply[(sid / 2) % 2048];
  int len = snprintf(r, 24, "%ld\n", c->body[(sid / 2) % 2048]);
  return h2_respond(h, sid, 200, &ct, 1, (const uint8_t *)r, (size_t)len, 1) < 0;
}
static int on_trailers(h2_conn *h, uint32_t sid, const hp_field *f, int n, void *u) {
  (void)f, (void)n;
  return on_data(h, sid, NULL, 0, 1, u);
}
static const h2_callbacks CB = { on_request, on_data, on_trailers, NULL, NULL };

static void drop(int i) {
  close(C[i]->fd);
  free(C[i]);
  C[i] = NULL;
}
/* write what h2_send has; 0 on success */
static int flush(conn *c) {
  static uint8_t out[1 << 16];
  for (;;) {
    size_t n = h2_send(&c->h2, out, sizeof out);
    if (!n) return 0;
    for (size_t o = 0; o < n;) {
      ssize_t w = write(c->fd, out + o, n - o);
      if (w < 0 && errno == EINTR) continue;
      if (w < 0 && errno == EAGAIN) {
        struct pollfd p = { c->fd, POLLOUT, 0 };
        poll(&p, 1, 1000);
        continue;
      }
      if (w <= 0) return -1;
      o += (size_t)w;
    }
  }
}

int main(int argc, char **argv) {
  int port = argc > 1 ? atoi(argv[1]) : 8080, one = 1;
  memset(BIG, 'x', sizeof BIG);
  signal(SIGPIPE, SIG_IGN);
  int ls = socket(AF_INET, SOCK_STREAM, 0);
  setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  struct sockaddr_in a = { .sin_family = AF_INET,
                           .sin_port = htons((uint16_t)port),
                           .sin_addr.s_addr = htonl(INADDR_ANY) };
  if (bind(ls, (struct sockaddr *)&a, sizeof a) || listen(ls, 128)) {
    perror("listen");
    return 1;
  }
  fprintf(stderr, "h2_server: h2c on port %d\n", port);
  for (;;) {
    struct pollfd p[MAXC + 1];
    int idx[MAXC + 1], np = 0;
    p[np].fd = ls, p[np].events = POLLIN, idx[np++] = -1;
    for (int i = 0; i < MAXC; i++)
      if (C[i]) p[np].fd = C[i]->fd, p[np].events = POLLIN, idx[np++] = i;
    if (poll(p, (nfds_t)np, -1) < 0) continue;
    if (p[0].revents & POLLIN) {
      int fd = accept(ls, NULL, NULL);
      if (fd >= 0) {
        int i = 0;
        while (i < MAXC && C[i]) i++;
        if (i == MAXC) close(fd);
        else {
          setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
          C[i] = calloc(1, sizeof(conn));
          C[i]->fd = fd;
          h2_init(&C[i]->h2, &CB, C[i]);
          if (flush(C[i])) drop(i);
        }
      }
    }
    for (int k = 1; k < np; k++) {
      int i = idx[k];
      if (!C[i] || !(p[k].revents & (POLLIN | POLLHUP | POLLERR))) continue;
      conn *c = C[i];
      ssize_t r = read(c->fd, c->in + c->inlen, sizeof c->in - c->inlen);
      if (r <= 0) {
        drop(i);
        continue;
      }
      c->inlen += (size_t)r;
      int dead = 0;
      for (;;) { /* h2_recv stops early under output backpressure: drain and go again */
        int u = h2_recv(&c->h2, &SC, c->in, c->inlen);
        if (flush(c)) {
          dead = 1;
          break;
        }
        if (u < 0) {
          dead = 1;
          break;
        }
        memmove(c->in, c->in + u, c->inlen - (size_t)u), c->inlen -= (size_t)u;
        if (!u || !c->inlen) break;
      }
      if (dead || h2_is_closed(&c->h2) || c->inlen == sizeof c->in) drop(i);
    }
  }
}
