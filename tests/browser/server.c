// tests/browser/server.c - HTTP/1.1 server on 127.0.0.1 for a real browser (tests/browser/drive.py).
//   server PORT PAGEDIR CAPDIR
// Serves PAGEDIR/page.html at / (its script makes the browser send many kinds of request, see page.html), saves every
// request raw to CAPDIR/NNN.http, and checks each with check.h as it arrives. GET /done ends the run: it prints the
// summary and exits 0 if nothing mismatched. Gives up after 60 s without traffic. Loopback only, one thread, poll().
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#include "fastparse.h"
#include "fbparse.h"
#include "picohttpparser.h"
#include "testlib.h"
#include "check.h"

#define MAXC   64
#define BUFCAP (1 << 20)
typedef struct {
  int fd;
  char *b;
  size_t n;
} conn_t;
static conn_t C[MAXC];
static int nreq, done, head_only; // head_only: the request is HEAD (no body in the reply)
static const char *pagedir, *capdir;

static char *slurp(const char *name, size_t *len) {
  char fn[1024];
  snprintf(fn, sizeof fn, "%s/%s", pagedir, name);
  FILE *f = fopen(fn, "rb");
  if (!f) return NULL;
  char *s = malloc(1 << 16);
  *len = fread(s, 1, 1 << 16, f);
  fclose(f);
  return s;
}
static void reply(int fd, int status, const char *ctype, const char *body, size_t bl) {
  char h[256];
  int hl = snprintf(h, sizeof h,
                    "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\nCache-Control: no-store\r\n\r\n",
                    status, status == 200 ? "OK" : "Not Found", ctype, bl);
  if (head_only) bl = 0; // a HEAD reply has the GET headers but no body (RFC 9110 9.3.2)
  if (write(fd, h, (size_t)hl) != hl || (bl && write(fd, body, bl) != (ssize_t)bl)) perror("write");
}
static int starts(const char *p, size_t pl, const char *s) {
  size_t n = strlen(s);
  return pl >= n && !memcmp(p, s, n);
}
static void route(int fd, const char *m, size_t ml, const char *p, size_t pl) {
  size_t bl;
  char *b = NULL, js[96];
  if (starts(p, pl, "/done")) {
    done = 1;
    reply(fd, 200, "text/html", "<p id=done>done</p>", 19);
  } else if ((pl == 1 && *p == '/') || starts(p, pl, "/frame") || starts(p, pl, "/s.css") || starts(p, pl, "/a.js")) {
    const char *f = pl == 1 ? "page.html" : p[1] == 'f' ? "frame.html" : p[1] == 's' ? "s.css" : "a.js";
    const char *t = p[1] == 's' ? "text/css" : p[1] == 'a' ? "application/javascript" : "text/html";
    if ((b = slurp(f, &bl))) reply(fd, 200, t, b, bl);
    else reply(fd, 404, "text/plain", "", 0);
  } else if (starts(p, pl, "/form-post")) {
    const char *s = "<script>location='/done?via=form'</script>";
    reply(fd, 200, "text/html", s, strlen(s));
  } else if (starts(p, pl, "/i.png") || starts(p, pl, "/favicon.ico")) reply(fd, 404, "text/plain", "", 0);
  else {
    int n = snprintf(js, sizeof js, "{\"method\":\"%.*s\",\"n\":%d}", (int)(ml < 32 ? ml : 32), m, nreq);
    reply(fd, 200, "application/json", js, (size_t)n);
  }
  free(b);
}
// a complete request at the start of c->b: its length (head + Content-Length body); 0 = need more; -1 = close
static long complete(const conn_t *c) {
  const char *m, *p;
  size_t ml, pl, nh = BC_NH;
  int mv;
  struct phr_header h[BC_NH];
  int r = phr_parse_request(c->b, c->n, &m, &ml, &p, &pl, &mv, h, &nh, 0);
  if (r == -2) return c->n < BUFCAP ? 0 : -1;
  if (r < 0) return -1;
  size_t cl = 0;
  for (size_t i = 0; i < nh; i++) {
    if (!h[i].name) continue;
    if (h[i].name_len == 14 && !strncasecmp(h[i].name, "content-length", 14)) cl = strtoul(h[i].value, NULL, 10);
    if (h[i].name_len == 17 && !strncasecmp(h[i].name, "transfer-encoding", 17)) {
      fprintf(stderr, "a chunked request body: not handled here, closing the connection\n");
      return -1;
    }
  }
  if ((size_t)r + cl > BUFCAP) return -1;
  return c->n >= (size_t)r + cl ? (long)((size_t)r + cl) : 0;
}
static void serve(conn_t *c, long n) {
  char tag[32], fn[1024];
  snprintf(tag, sizeof tag, "%03d", ++nreq);
  snprintf(fn, sizeof fn, "%s/%s.http", capdir, tag);
  FILE *f = fopen(fn, "wb");
  if (f) {
    fwrite(c->b, 1, (size_t)n, f);
    fclose(f);
  }
  long bad = bc_check(c->b, (size_t)n, fn);
  const char *m, *p;
  size_t ml, pl, nh = BC_NH;
  int mv;
  struct phr_header h[BC_NH];
  int hl = phr_parse_request(c->b, (size_t)n, &m, &ml, &p, &pl, &mv, h, &nh, 0);
  printf("%s %s %.*s %.*s (head %d B, body %ld B, %zu headers)\n", tag, bad ? "FAIL" : "ok  ", (int)ml, m,
         (int)(pl > 60 ? 60 : pl), p, hl, n - hl, nh);
  fflush(stdout);
  head_only = ml == 4 && !memcmp(m, "HEAD", 4);
  route(c->fd, m, ml, p, pl);
  memmove(c->b, c->b + n, c->n - (size_t)n);
  c->n -= (size_t)n;
}
int main(int argc, char **argv) {
  if (argc < 4) {
    fprintf(stderr, "usage: %s PORT PAGEDIR CAPDIR\n", argv[0]);
    return 2;
  }
  signal(SIGPIPE, SIG_IGN); // a browser closing a connection must not end the run
  pagedir = argv[2];
  capdir = argv[3];
  int s = socket(AF_INET, SOCK_STREAM, 0), one = 1;
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  struct sockaddr_in a = { .sin_family = AF_INET,
                           .sin_port = htons((uint16_t)atoi(argv[1])),
                           .sin_addr.s_addr = htonl(0x7f000001) };
  if (bind(s, (struct sockaddr *)&a, sizeof a) || listen(s, 64)) {
    perror("bind/listen");
    return 2;
  }
  printf("listening on 127.0.0.1:%s\n", argv[1]);
  fflush(stdout);
  for (int i = 0; i < MAXC; i++) C[i].fd = -1;
  while (!done) {
    struct pollfd P[MAXC + 1];
    int np = 0, map[MAXC + 1];
    P[np] = (struct pollfd){ .fd = s, .events = POLLIN };
    map[np++] = -1;
    for (int i = 0; i < MAXC; i++)
      if (C[i].fd >= 0) {
        P[np] = (struct pollfd){ .fd = C[i].fd, .events = POLLIN };
        map[np++] = i;
      }
    if (poll(P, (nfds_t)np, 60000) <= 0) {
      fprintf(stderr, "no traffic for 60 s: giving up\n");
      break;
    }
    for (int j = 0; j < np; j++) {
      if (!(P[j].revents & (POLLIN | POLLHUP | POLLERR))) continue;
      if (map[j] < 0) {
        int fd = accept(s, NULL, NULL), i = 0;
        while (i < MAXC && C[i].fd >= 0) i++;
        if (fd < 0 || i == MAXC) {
          if (fd >= 0) close(fd);
          continue;
        }
        C[i].fd = fd;
        C[i].n = 0;
        if (!C[i].b) C[i].b = malloc(BUFCAP);
        continue;
      }
      conn_t *c = &C[map[j]];
      ssize_t r = read(c->fd, c->b + c->n, BUFCAP - c->n);
      if (r <= 0) {
        close(c->fd);
        c->fd = -1;
        continue;
      }
      c->n += (size_t)r;
      long n;
      while ((n = complete(c)) > 0) serve(c, n);
      if (n < 0) {
        close(c->fd);
        c->fd = -1;
      }
    }
  }
  bc_summary("live");
  return done && !BC.bad ? 0 : 1;
}
