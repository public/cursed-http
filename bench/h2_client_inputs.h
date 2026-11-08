/* bench/h2_client_inputs.h: what the HTTP/2 and HTTP/3 client benchmarks (bench_h2h3.c, bench/codspeed) send
 * and get back. A request of bench/h2_headers.h as an h_request (pseudo-headers split out), and the response to
 * request i of each set: what a browser (a CDN's static file), a gRPC client (trailers) and h2load (a minimal
 * server) get back; every body is the 13 bytes of CI_BODY. Needs hreq.h and h2_headers.h first. */
#ifndef BENCH_H2_CLIENT_INPUTS_H
#define BENCH_H2_CLIENT_INPUTS_H
#include <stdio.h>
#include <string.h>

#define CI_BODY "hello, world\n"
typedef struct {
  const char *n;
  char v[96];
} rs_field;
typedef struct {
  int n, nt;
  rs_field f[16], t[2]; /* f[0] is :status; t: trailers */
} rs_set;
static void rs_build(rs_set *r, int s, int i) {
  r->n = r->nt = 0;
#define RF(N, ...) (r->f[r->n].n = N, snprintf(r->f[r->n].v, sizeof r->f[0].v, __VA_ARGS__), r->n++)
  RF(":status", "200");
  if (s == 0) {
    RF("date", "Sun, 08 Nov 2026 12:%02d:%02d GMT", i / 60 % 60, i % 60);
    RF("content-type", "%s", i % 3 ? "text/javascript; charset=utf-8" : "image/webp");
    RF("content-length", "13");
    RF("server", "nginx");
    RF("last-modified", "Mon, 02 Nov 2026 09:%02d:00 GMT", i % 60);
    RF("etag", "\"%08llx-%x\"", hs_mix((unsigned long long)i) & 0xffffffffull, i + 1000);
    RF("cache-control", "public, max-age=31536000, immutable");
    RF("vary", "Accept-Encoding");
    RF("x-content-type-options", "nosniff");
    RF("strict-transport-security", "max-age=63072000; includeSubDomains; preload");
    RF("alt-svc", "h3=\":443\"; ma=86400");
  } else if (s == 1) {
    RF("content-type", "application/grpc");
    RF("grpc-accept-encoding", "identity,deflate,gzip");
    r->t[0].n = "grpc-status", strcpy(r->t[0].v, "0");
    r->t[1].n = "grpc-message", strcpy(r->t[1].v, "OK");
    r->nt = 2;
  } else {
    RF("server", "h2o/2.3.0");
    RF("date", "Sun, 08 Nov 2026 12:00:%02d GMT", i % 60);
    RF("content-length", "13");
  }
#undef RF
}
/* fields (from 1: no :status) or trailers as hp_field, for h2_respond / h3_respond / *_trailers */
static int rs_fields(const rs_set *r, int trailers, hp_field *out) {
  const rs_field *f = trailers ? r->t : r->f + 1;
  int n = trailers ? r->nt : r->n - 1;
  for (int k = 0; k < n; k++)
    out[k] = (hp_field){
      (const uint8_t *)f[k].n, (const uint8_t *)f[k].v, (uint32_t)strlen(f[k].n), (uint32_t)strlen(f[k].v), 0, 0, 0, 0
    };
  return n;
}
/* a request as h_request; its regular fields go to f (24 at most) */
static void rq_build(const hs_set *h, h_request *q, hp_field *f) {
  memset(q, 0, sizeof *q);
  for (int k = 0; k < h->n; k++) {
    const uint8_t *v = (const uint8_t *)h->f[k].value;
    uint32_t vl = (uint32_t)strlen(h->f[k].value);
    const char *n = h->f[k].name;
    if (!strcmp(n, ":method")) q->method = v, q->method_len = vl;
    else if (!strcmp(n, ":scheme")) q->scheme = v, q->scheme_len = vl;
    else if (!strcmp(n, ":authority")) q->authority = v, q->authority_len = vl;
    else if (!strcmp(n, ":path")) q->path = v, q->path_len = vl;
    else f[q->nfields++] = (hp_field){ (const uint8_t *)n, v, (uint32_t)strlen(n), vl, 0, 0, 0, 0 };
  }
  q->fields = f, q->content_length = -1;
}
#endif
