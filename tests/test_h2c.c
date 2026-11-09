/* include/h2.h's client role (h2_init_client, h2_submit, on_response) against nghttp2's server, in memory.
 *   - traffic: GETs and POSTs whose path tells nghttp2's server what to answer (status, body size, trailers,
 *     a 103 first, a header block larger than one frame, HEAD, 204, 304), more requests than the server's
 *     MAX_CONCURRENT_STREAMS, large bodies both ways through small windows; input to h2_recv is cut at random
 *     points and output from h2_send drained in random sizes. Every response, body byte and trailer must
 *     arrive as sent.
 *   - the client against this library's own server role (h2_init), the same traffic.
 *   - malformed responses and frames (hand-built) get the RST_STREAM / GOAWAY codes RFC 9113 asks for.
 * FUZZ=N scales the counts. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef H2_STAGE
#define H2_STAGE 65536
#endif
#include "h2.h"
#include <nghttp2/nghttp2.h>

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
static uint64_t rs = 0x9e3779b97f4a7c15ull;
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
static h2_scratch SC;

typedef struct {
  uint8_t *p;
  size_t n, cap;
} bytes;
static void put(bytes *b, const uint8_t *d, size_t n) {
  if (b->n + n > b->cap) b->cap = (b->n + n) * 2 + 4096, b->p = realloc(b->p, b->cap);
  memcpy(b->p + b->n, d, n), b->n += n;
}

/* ------------------------------------- what each request asks for ------------------------------------- */
/* the path: /r/<status>/<body bytes>/<flags>/<id>; flags: t trailers, e a 103 first, h a big header block */
typedef struct {
  int status, early, trailers, bighdr, head;
  long body, upload;
} want_t;
#define MAXREQ 8192
static want_t W[MAXREQ];
static uint32_t SID2REQ[2 * MAXREQ + 2]; /* stream id -> request number + 1 */

typedef struct {
  long responses, informational, finals_ok, body, trailers, closes, close_errors, bad, retried;
  uint32_t last_err;
} cstats;
static cstats CS;
static long got_body[MAXREQ];
static int cli_on_response(h2_conn *c, uint32_t sid, const h2_response *r, int end, void *u) {
  (void)c, (void)u;
  int q = (int)SID2REQ[sid] - 1;
  CS.responses++;
  if (q < 0) {
    CS.bad++;
    return 0;
  }
  if (r->status < 200) {
    CS.informational++;
    if (!(W[q].early && r->status == 103)) CS.bad++;
    return 0;
  }
  if (r->status != W[q].status) CS.bad++;
  int has_big = 0;
  for (int i = 0; i < r->nfields; i++)
    if (r->fields[i].nlen == 5 && !memcmp(r->fields[i].name, "x-big", 5)) has_big = 1;
  if (has_big != W[q].bighdr) CS.bad++;
  if (end != ((W[q].body == 0 || W[q].head) && !W[q].trailers)) CS.bad++;
  CS.finals_ok++;
  return 0;
}
static int cli_on_data(h2_conn *c, uint32_t sid, const uint8_t *d, size_t n, int end, void *u) {
  (void)c, (void)d, (void)end, (void)u;
  int q = (int)SID2REQ[sid] - 1;
  if (q >= 0) got_body[q] += (long)n;
  CS.body += (long)n;
  return 0;
}
static int cli_on_trailers(h2_conn *c, uint32_t sid, const hp_field *f, int n, void *u) {
  (void)c, (void)u;
  int q = (int)SID2REQ[sid] - 1;
  if (q < 0 || !W[q].trailers || n != 2 || f[0].nlen != 11 || memcmp(f[0].name, "grpc-status", 11)) CS.bad++;
  CS.trailers++;
  return 0;
}
static int RETRY[MAXREQ], nretry;
static void cli_on_close(h2_conn *c, uint32_t sid, uint32_t err, void *u) {
  (void)c, (void)u;
  if (err == H2_REFUSED_STREAM && SID2REQ[sid]) { /* not processed: send it again, as a client would */
    RETRY[nretry++] = (int)SID2REQ[sid] - 1;
    SID2REQ[sid] = 0;
    return;
  }
  CS.closes++;
  if (err) CS.close_errors++, CS.last_err = err;
  int q = (int)SID2REQ[sid] - 1;
  if (q >= 0 && !err && got_body[q] != (W[q].head ? 0 : W[q].body)) CS.bad++;
}
static const h2_callbacks CLI_CB = { NULL, cli_on_data, cli_on_trailers, NULL, cli_on_close, cli_on_response };

/* ----------------------------------- the nghttp2 server ----------------------------------- */
typedef struct {
  int32_t sid;
  char path[96];
  int head;
  long left, uploaded;
} sreq;
static sreq SR[MAXREQ];
static int nsr;
static sreq *sr_find(int32_t sid) {
  for (int i = nsr - 1; i >= 0; i--)
    if (SR[i].sid == sid) return &SR[i];
  return NULL;
}
static int srv_on_begin(nghttp2_session *s, const nghttp2_frame *f, void *u) {
  (void)s, (void)u;
  if (f->hd.type == NGHTTP2_HEADERS && f->headers.cat == NGHTTP2_HCAT_REQUEST && nsr < MAXREQ) {
    memset(&SR[nsr], 0, sizeof SR[nsr]);
    SR[nsr++].sid = f->hd.stream_id;
  }
  return 0;
}
static int srv_on_header(nghttp2_session *s, const nghttp2_frame *f, const uint8_t *n, size_t nl, const uint8_t *v,
                         size_t vl, uint8_t fl, void *u) {
  (void)s, (void)fl, (void)u;
  sreq *r = sr_find(f->hd.stream_id);
  if (!r) return 0;
  if (nl == 5 && !memcmp(n, ":path", 5) && vl < sizeof r->path) memcpy(r->path, v, vl), r->path[vl] = 0;
  if (nl == 7 && !memcmp(n, ":method", 7) && vl == 4 && !memcmp(v, "HEAD", 4)) r->head = 1;
  return 0;
}
static int srv_on_chunk(nghttp2_session *s, uint8_t fl, int32_t sid, const uint8_t *d, size_t n, void *u) {
  (void)s, (void)fl, (void)d, (void)u;
  sreq *r = sr_find(sid);
  if (r) r->uploaded += (long)n;
  return 0;
}
static nghttp2_ssize srv_body(nghttp2_session *s, int32_t sid, uint8_t *buf, size_t len, uint32_t *fl,
                              nghttp2_data_source *src, void *u) {
  (void)s, (void)u;
  sreq *r = (sreq *)src->ptr;
  size_t m = r->left < (long)len ? (size_t)r->left : len;
  memset(buf, 'x', m);
  r->left -= (long)m;
  if (!r->left) {
    *fl |= NGHTTP2_DATA_FLAG_EOF;
    int q = (int)SID2REQ[sid] - 1;
    if (q >= 0 && W[q].trailers) {
      *fl |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
      nghttp2_nv t[2] = { { (uint8_t *)"grpc-status", (uint8_t *)"0", 11, 1, 0 },
                          { (uint8_t *)"grpc-message", (uint8_t *)"ok", 12, 2, 0 } };
      nghttp2_submit_trailer(s, sid, t, 2);
    }
  }
  return (nghttp2_ssize)m;
}
static char BIGV[20000];
static int srv_on_frame(nghttp2_session *s, const nghttp2_frame *f, void *u) {
  (void)u;
  if (!(f->hd.flags & NGHTTP2_FLAG_END_STREAM) || (f->hd.type != NGHTTP2_HEADERS && f->hd.type != NGHTTP2_DATA))
    return 0;
  sreq *r = sr_find(f->hd.stream_id);
  if (!r) return 0;
  int status = 200, early = 0, trl = 0, big = 0;
  long body = 0;
  char flags[16] = "";
  int id = -1;
  sscanf(r->path, "/r/%d/%ld/%15[^/]/%d", &status, &body, flags, &id);
  if (strcmp(flags, "-")) early = !!strchr(flags, 'e'), trl = !!strchr(flags, 't'), big = !!strchr(flags, 'h');
  if (id < 0 || id >= MAXREQ || W[id].upload != r->uploaded) CS.bad++; /* the request body arrived whole */
  if (early) {
    nghttp2_nv e[1] = { { (uint8_t *)"link", (uint8_t *)"</a.css>; rel=preload", 4, 21, 0 } };
    nghttp2_nv st[2] = { { (uint8_t *)":status", (uint8_t *)"103", 7, 3, 0 }, e[0] };
    nghttp2_submit_headers(s, NGHTTP2_FLAG_NONE, f->hd.stream_id, NULL, st, 2, NULL);
  }
  char sv[4];
  snprintf(sv, sizeof sv, "%03d", status);
  char cl[24];
  snprintf(cl, sizeof cl, "%ld", body);
  nghttp2_nv nv[5] = { { (uint8_t *)":status", (uint8_t *)sv, 7, 3, 0 },
                       { (uint8_t *)"content-type", (uint8_t *)"text/plain", 12, 10, 0 },
                       { (uint8_t *)"server", (uint8_t *)"nghttp2-test", 6, 12, 0 },
                       { (uint8_t *)"content-length", (uint8_t *)cl, 14, strlen(cl), 0 },
                       { (uint8_t *)"x-big", (uint8_t *)BIGV, 5, 18000, 0 } };
  int nnv = 3;
  if (!trl && status != 204 && status != 304) nv[nnv++] = nv[3];
  if (big) nv[nnv++] = nv[4];
  r->left = r->head || status == 204 || status == 304 ? 0 : body;
  nghttp2_data_provider2 dp = { { .ptr = r }, srv_body };
  nghttp2_submit_response2(s, f->hd.stream_id, nv, (size_t)nnv, r->left || trl ? &dp : NULL);
  return 0;
}

/* push server bytes into the client in random cuts, keeping the unconsumed tail */
static bytes INQ;
static int feed(h2_conn *c, const uint8_t *d, size_t n) {
  if (n) put(&INQ, d, n);
  size_t off = 0;
  while (off < INQ.n) {
    size_t lim = INQ.n - off;
    if (rnd() % 3 == 0) lim = 1 + rnd() % lim;
    int r = h2_recv(c, &SC, INQ.p + off, lim);
    if (r < 0) return r;
    if (r == 0 && lim == INQ.n - off) break;
    off += (size_t)r;
  }
  if (off) memmove(INQ.p, INQ.p + off, INQ.n - off), INQ.n -= off;
  return 0;
}

static uint8_t UPLOAD[1 << 21];
/* make request q: what it asks for, and the h2_request for it */
static void make_req(int q, int kind, char *path, size_t pl, h2_request *rq, hp_field *f) {
  static const int statuses[] = { 200, 200, 200, 201, 204, 206, 301, 304, 404, 500 };
  want_t *w = &W[q];
  memset(w, 0, sizeof *w);
  w->status = statuses[rnd() % 10];
  w->body = w->status == 204 || w->status == 304 ? 0 : (long)(rnd() % (kind == 2 ? 600000 : 3000));
  w->early = kind == 3 && rnd() % 3 == 0;
  w->trailers = kind == 1 && w->status != 204 && w->status != 304;
  w->bighdr = kind == 4;
  w->head = kind == 3 && rnd() % 5 == 0;
  w->upload = kind == 1 ? (long)(rnd() % 5000) : kind == 5 ? 400000 + (long)(rnd() % 600000) : 0;
  if (w->head) w->trailers = 0;
  char fl[8], *p = fl;
  if (w->trailers) *p++ = 't';
  if (w->early) *p++ = 'e';
  if (w->bighdr) *p++ = 'h';
  if (p == fl) *p++ = '-';
  *p = 0;
  snprintf(path, pl, "/r/%03d/%ld/%s/%d", w->status, w->body, fl, q);
  memset(rq, 0, sizeof *rq);
  const char *m = w->head ? "HEAD" : w->upload ? "POST" : "GET";
  rq->method = (const uint8_t *)m, rq->method_len = (uint32_t)strlen(m);
  rq->scheme = (const uint8_t *)"https", rq->scheme_len = 5;
  rq->authority = (const uint8_t *)"example.com", rq->authority_len = 11;
  rq->path = (const uint8_t *)path, rq->path_len = (uint32_t)strlen(path);
  static const char ua[] = "cursed-http-test/1", ck[] = "session=abcdef0123456789; theme=dark";
  f[0] = (hp_field){ (const uint8_t *)"user-agent", (const uint8_t *)ua, 10, sizeof ua - 1, 0, 0, 0, 0 };
  f[1] = (hp_field){ (const uint8_t *)"cookie", (const uint8_t *)ck, 6, sizeof ck - 1, 0, 0, 0, 1 };
  rq->fields = f, rq->nfields = 2;
}

/* kind: 0 GETs, 1 POSTs with trailers, 2 big downloads, 3 mixed (103, HEAD), 4 big header blocks, 5 uploads */
static void run_vs_nghttp2(int kind, int nreq, uint32_t srv_window, uint32_t max_streams) {
  static h2_conn C;
  h2_init_client(&C, &CLI_CB, NULL);
  INQ.n = 0, nsr = 0;
  memset(&CS, 0, sizeof CS), memset(got_body, 0, sizeof got_body), memset(SID2REQ, 0, sizeof SID2REQ);
  nghttp2_session_callbacks *cb;
  nghttp2_session *srv;
  nghttp2_session_callbacks_new(&cb);
  nghttp2_session_callbacks_set_on_begin_headers_callback(cb, srv_on_begin);
  nghttp2_session_callbacks_set_on_header_callback(cb, srv_on_header);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cb, srv_on_chunk);
  nghttp2_session_callbacks_set_on_frame_recv_callback(cb, srv_on_frame);
  nghttp2_session_server_new(&srv, cb, NULL);
  nghttp2_session_callbacks_del(cb);
  nghttp2_settings_entry st[] = { { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, max_streams },
                                  { NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, srv_window },
                                  { NGHTTP2_SETTINGS_HEADER_TABLE_SIZE, rnd() % 2 ? 4096 : 512 } };
  nghttp2_submit_settings(srv, NGHTTP2_FLAG_NONE, st, 3);
  int sent = 0;
  long want_body = 0, want_trl = 0, want_early = 0;
  static char paths[MAXREQ][64];
  static hp_field fs[MAXREQ][2];
  uint8_t out[70000];
  nretry = 0;
  for (int guard = 0; guard < 400000 && CS.closes < nreq; guard++) {
    while (nretry) { /* refused ones first, unchanged */
      int q = RETRY[nretry - 1];
      h2_request rq;
      memset(&rq, 0, sizeof rq);
      const char *m = W[q].head ? "HEAD" : W[q].upload ? "POST" : "GET";
      rq.method = (const uint8_t *)m, rq.method_len = (uint32_t)strlen(m);
      rq.scheme = (const uint8_t *)"https", rq.scheme_len = 5, rq.authority = (const uint8_t *)"example.com";
      rq.authority_len = 11, rq.path = (const uint8_t *)paths[q], rq.path_len = (uint32_t)strlen(paths[q]);
      rq.fields = fs[q], rq.nfields = 2;
      int r = h2_submit(&C, &rq, W[q].upload ? UPLOAD : NULL, (size_t)W[q].upload, 1);
      if (r < 0) break;
      SID2REQ[r] = (uint32_t)q + 1, got_body[q] = 0, nretry--, CS.retried++;
    }
    while (sent < nreq && !nretry) {
      h2_request rq;
      make_req(sent, kind, paths[sent], sizeof paths[sent], &rq, fs[sent]);
      int r = h2_submit(&C, &rq, W[sent].upload ? UPLOAD : NULL, (size_t)W[sent].upload, 1);
      if (r == H2_E_AGAIN) break; /* at the server's MAX_CONCURRENT_STREAMS: wait for a close */
      if (r < 0) {
        CHECK(0, "h2_submit %d", r);
        goto out;
      }
      SID2REQ[r] = (uint32_t)sent + 1;
      want_body += W[sent].head ? 0 : W[sent].body, want_trl += W[sent].trailers, want_early += W[sent].early;
      sent++;
    }
    size_t w;
    while ((w = h2_send(&C, out, 1 + rnd() % sizeof out)) > 0)
      if (nghttp2_session_mem_recv2(srv, out, w) < 0) {
        CHECK(0, "nghttp2 server rejected our client's output (kind %d)", kind);
        goto out;
      }
    const uint8_t *d;
    nghttp2_ssize n;
    if (feed(&C, NULL, 0) < 0) {
      CHECK(0, "client failed the connection (kind %d)", kind);
      goto out;
    }
    while ((n = nghttp2_session_mem_send2(srv, &d)) > 0)
      if (feed(&C, d, (size_t)n) < 0) {
        CHECK(0, "client failed the connection (kind %d)", kind);
        goto out;
      }
  }
out:
  CHECK(CS.closes == nreq && CS.close_errors == 0, "kind %d: %ld/%d closed, %ld with errors (last %u)", kind, CS.closes,
        nreq, CS.close_errors, CS.last_err);
  CHECK(CS.finals_ok == nreq && CS.bad == 0, "kind %d: %ld final responses of %d, %ld wrong", kind, CS.finals_ok, nreq,
        CS.bad);
  CHECK(CS.body == want_body, "kind %d: body %ld want %ld", kind, CS.body, want_body);
  CHECK(CS.trailers == want_trl, "kind %d: trailers %ld want %ld", kind, CS.trailers, want_trl);
  CHECK(CS.informational == want_early, "kind %d: 103s %ld want %ld", kind, CS.informational, want_early);
  nghttp2_session_del(srv);
}

/* ------------------------------ the client against our own server ------------------------------ */
static h2_conn S2;
static long s2_uploaded[MAXREQ];
static int s2_on_request(h2_conn *c, uint32_t sid, const h2_request *rq, int end, void *u) {
  (void)u, (void)end;
  int status = 200, id = -1;
  long body = 0;
  char flags[16] = "";
  char path[96];
  size_t pl = rq->path_len < sizeof path - 1 ? rq->path_len : sizeof path - 1;
  memcpy(path, rq->path, pl), path[pl] = 0;
  sscanf(path, "/r/%d/%ld/%15[^/]/%d", &status, &body, flags, &id);
  (void)id;
  int head = h_eq(rq->method, rq->method_len, "HEAD");
  static uint8_t ZB[600000];
  char cl[24];
  snprintf(cl, sizeof cl, "%ld", body);
  static char cls[MAXREQ][24];
  memcpy(cls[sid % MAXREQ], cl, sizeof cl);
  hp_field f[2] = { { (const uint8_t *)"server", (const uint8_t *)"cursed-http", 6, 11, 0, 0, 0, 0 },
                    { (const uint8_t *)"content-length", (const uint8_t *)cls[sid % MAXREQ], 14, (uint32_t)strlen(cl),
                      0, 0, 0, 0 } };
  int nf = status == 204 || status == 304 ? 1 : 2;
  long send = head || status == 204 || status == 304 ? 0 : body;
  if (!end) return 0; /* respond after the upload: on_data's end */
  return h2_respond(c, sid, status, f, nf, send ? ZB : NULL, (size_t)send, 1);
}
static int s2_on_data(h2_conn *c, uint32_t sid, const uint8_t *d, size_t n, int end, void *u) {
  (void)d;
  s2_uploaded[sid % MAXREQ] += (long)n;
  if (!end) return 0;
  h2_request rq; /* the path again: the request is gone from the callback's view; keep it simple */
  (void)rq, (void)u, (void)c;
  return 0;
}
static const h2_callbacks S2_CB = { s2_on_request, s2_on_data, NULL, NULL, NULL, NULL };

static void run_vs_self(int nreq) {
  static h2_conn C;
  h2_init_client(&C, &CLI_CB, NULL);
  h2_init(&S2, &S2_CB, NULL);
  INQ.n = 0;
  memset(&CS, 0, sizeof CS), memset(got_body, 0, sizeof got_body), memset(SID2REQ, 0, sizeof SID2REQ);
  static bytes TOS; /* bytes for the server */
  TOS.n = 0;
  static char paths[MAXREQ][64];
  static hp_field fs[MAXREQ][2];
  int sent = 0;
  long want_body = 0;
  uint8_t out[70000];
  for (int guard = 0; guard < 400000 && CS.closes < nreq; guard++) {
    while (sent < nreq) {
      h2_request rq;
      make_req(sent, 0, paths[sent], sizeof paths[sent], &rq, fs[sent]);
      W[sent].head = rnd() % 6 == 0;
      if (W[sent].head) rq.method = (const uint8_t *)"HEAD", rq.method_len = 4;
      int r = h2_submit(&C, &rq, NULL, 0, 1);
      if (r == H2_E_AGAIN) break;
      if (r < 0) {
        CHECK(0, "h2_submit vs self %d", r);
        return;
      }
      SID2REQ[r] = (uint32_t)sent + 1;
      want_body += W[sent].head ? 0 : W[sent].body;
      sent++;
    }
    size_t w;
    while ((w = h2_send(&C, out, 1 + rnd() % sizeof out)) > 0) put(&TOS, out, w);
    size_t off = 0;
    while (off < TOS.n) {
      int r = h2_recv(&S2, &SC, TOS.p + off, TOS.n - off);
      if (r < 0) {
        CHECK(0, "our server failed our client's connection");
        return;
      }
      if (!r) break;
      off += (size_t)r;
    }
    if (off) memmove(TOS.p, TOS.p + off, TOS.n - off), TOS.n -= off;
    while ((w = h2_send(&S2, out, 1 + rnd() % sizeof out)) > 0)
      if (feed(&C, out, w) < 0) {
        CHECK(0, "our client failed our server's connection");
        return;
      }
  }
  CHECK(CS.closes == nreq && CS.close_errors == 0 && CS.bad == 0, "vs self: %ld/%d closed, %ld errors, %ld wrong",
        CS.closes, nreq, CS.close_errors, CS.bad);
  CHECK(CS.body == want_body, "vs self: body %ld want %ld", CS.body, want_body);
}

/* ---------------------------------- hand-built bad responses ---------------------------------- */
static size_t frame(uint8_t *p, uint32_t len, uint8_t type, uint8_t fl, uint32_t sid, const void *pl) {
  h2__hdr(p, len, type, fl, sid);
  if (len) memcpy(p + 9, pl, len);
  return 9 + len;
}
static size_t hdrblock(uint8_t *b, const char *const *kv, int n) { /* literal fields, no Huffman, no indexing */
  size_t m = 0;
  for (int i = 0; i < 2 * n; i += 2) {
    size_t nl = strlen(kv[i]), vl = strlen(kv[i + 1]);
    b[m++] = 0, b[m++] = (uint8_t)nl, memcpy(b + m, kv[i], nl), m += nl;
    b[m++] = (uint8_t)vl, memcpy(b + m, kv[i + 1], vl), m += vl;
  }
  return m;
}
typedef struct {
  int failed;         /* h2_recv returned H2_E_CLOSED */
  uint32_t rst_code;  /* RST_STREAM we sent for stream 1 (0: none) */
  uint32_t goaway;    /* GOAWAY code we sent (0xffffffff: none) */
  uint32_t close_err; /* stream 1's on_close error (0xffffffff: not closed) */
  long responses, data;
} verdict;
static verdict VD;
static int vd_resp(h2_conn *c, uint32_t sid, const h2_response *r, int end, void *u) {
  (void)c, (void)sid, (void)r, (void)end, (void)u;
  VD.responses++;
  return 0;
}
static int vd_data(h2_conn *c, uint32_t sid, const uint8_t *d, size_t n, int end, void *u) {
  (void)c, (void)sid, (void)d, (void)end, (void)u;
  VD.data += (long)n;
  return 0;
}
static void vd_close(h2_conn *c, uint32_t sid, uint32_t err, void *u) {
  (void)c, (void)u;
  if (sid == 1) VD.close_err = err;
}
static const h2_callbacks VD_CB = { NULL, vd_data, NULL, NULL, vd_close, vd_resp };
/* a client that opened stream 1 (GET, or HEAD), then the server's bytes */
static verdict run_raw(const uint8_t *in, size_t n, int head, int nstreams) {
  static h2_conn C;
  memset(&VD, 0, sizeof VD);
  VD.goaway = 0xffffffff, VD.close_err = 0xffffffff;
  h2_init_client(&C, &VD_CB, NULL);
  for (int i = 0; i < nstreams; i++) {
    h2_request rq = { 0 };
    rq.method = (const uint8_t *)(head ? "HEAD" : "GET"), rq.method_len = head ? 4 : 3;
    rq.scheme = (const uint8_t *)"https", rq.scheme_len = 5, rq.authority = (const uint8_t *)"a", rq.authority_len = 1;
    rq.path = (const uint8_t *)"/", rq.path_len = 1;
    h2_submit(&C, &rq, NULL, 0, 1);
  }
  uint8_t out[65536];
  while (h2_send(&C, out, sizeof out)) {}
  int r = h2_recv(&C, &SC, in, n);
  VD.failed = r == H2_E_CLOSED;
  size_t w = h2_send(&C, out, sizeof out);
  for (size_t o = 0; o + 9 <= w;) {
    uint32_t len = h2__be24(out + o), sid = h2__be32(out + o + 5) & 0x7fffffff;
    if (out[o + 3] == H2F_RST_STREAM && sid == 1) VD.rst_code = h2__be32(out + o + 9);
    if (out[o + 3] == H2F_GOAWAY) VD.goaway = h2__be32(out + o + 13);
    o += 9 + len;
  }
  return VD;
}
static size_t SETTINGS_OK(uint8_t *p) { return frame(p, 0, H2F_SETTINGS, 0, 0, NULL); }

static void test_bad(void) {
  long before = fails;
  uint8_t in[70000], blk[4096];
  size_t n, bl;
#define RESP(fl, ...)                                                                                                  \
  do {                                                                                                                 \
    static const char *const kv_[] = { __VA_ARGS__ };                                                                  \
    bl = hdrblock(blk, kv_, (int)(sizeof kv_ / sizeof *kv_ / 2));                                                      \
    n = SETTINGS_OK(in);                                                                                               \
    n += frame(in + n, (uint32_t)bl, H2F_HEADERS, H2_FL_END_HEADERS | (fl), 1, blk);                                   \
  } while (0)
#define EXPECT_RST(code, what)                                                                                         \
  do {                                                                                                                 \
    verdict v_ = run_raw(in, n, 0, 1);                                                                                 \
    CHECK(!v_.failed && v_.rst_code == (code) && v_.close_err == (code), "%s: rst %u close %u failed %d", what,        \
          v_.rst_code, v_.close_err, v_.failed);                                                                       \
  } while (0)
#define EXPECT_GOAWAY(code, what)                                                                                      \
  do {                                                                                                                 \
    verdict v_ = run_raw(in, n, 0, 1);                                                                                 \
    CHECK(v_.failed &&v_.goaway == (code), "%s: goaway %u failed %d", what, v_.goaway, v_.failed);                     \
  } while (0)
  /* the good case first */
  RESP(H2_FL_END_STREAM, ":status", "200", "server", "x");
  {
    verdict v = run_raw(in, n, 0, 1);
    CHECK(!v.failed && v.responses == 1 && v.rst_code == 0 && v.close_err == 0, "good response: %ld rst %u",
          v.responses, v.rst_code);
  }
  RESP(H2_FL_END_STREAM, "server", "x");
  EXPECT_RST(H2_PROTOCOL_ERROR, "no :status");
  RESP(H2_FL_END_STREAM, ":status", "200", ":status", "200");
  EXPECT_RST(H2_PROTOCOL_ERROR, "two :status");
  RESP(H2_FL_END_STREAM, ":status", "20");
  EXPECT_RST(H2_PROTOCOL_ERROR, ":status of two digits");
  RESP(H2_FL_END_STREAM, ":status", "2x0");
  EXPECT_RST(H2_PROTOCOL_ERROR, ":status not digits");
  RESP(H2_FL_END_STREAM, ":status", "101");
  EXPECT_RST(H2_PROTOCOL_ERROR, ":status 101");
  RESP(H2_FL_END_STREAM, ":status", "099");
  EXPECT_RST(H2_PROTOCOL_ERROR, ":status 099");
  RESP(H2_FL_END_STREAM, ":status", "200", ":path", "/");
  EXPECT_RST(H2_PROTOCOL_ERROR, "request pseudo-header in a response");
  RESP(H2_FL_END_STREAM, "server", "x", ":status", "200");
  EXPECT_RST(H2_PROTOCOL_ERROR, "pseudo-header after a regular one");
  RESP(H2_FL_END_STREAM, ":status", "200", "Server", "x");
  EXPECT_RST(H2_PROTOCOL_ERROR, "uppercase name");
  RESP(H2_FL_END_STREAM, ":status", "200", "connection", "close");
  EXPECT_RST(H2_PROTOCOL_ERROR, "connection-specific field");
  RESP(H2_FL_END_STREAM, ":status", "200", "transfer-encoding", "chunked");
  EXPECT_RST(H2_PROTOCOL_ERROR, "transfer-encoding");
  RESP(H2_FL_END_STREAM, ":status", "200", "x", "a\rb");
  EXPECT_RST(H2_PROTOCOL_ERROR, "CR in a value");
  RESP(H2_FL_END_STREAM, ":status", "103");
  EXPECT_RST(H2_PROTOCOL_ERROR, "1xx with END_STREAM");
  RESP(H2_FL_END_STREAM, ":status", "200", "content-length", "5");
  EXPECT_RST(H2_PROTOCOL_ERROR, "END_STREAM with a content-length > 0");
  RESP(0, ":status", "200", "content-length", "5", "content-length", "6");
  EXPECT_RST(H2_PROTOCOL_ERROR, "content-lengths disagree");
  /* body shorter / longer than content-length */
  RESP(0, ":status", "200", "content-length", "5");
  n += frame(in + n, 3, H2F_DATA, H2_FL_END_STREAM, 1, "abc");
  EXPECT_RST(H2_PROTOCOL_ERROR, "body shorter than content-length");
  RESP(0, ":status", "200", "content-length", "2");
  n += frame(in + n, 3, H2F_DATA, H2_FL_END_STREAM, 1, "abc");
  EXPECT_RST(H2_PROTOCOL_ERROR, "body longer than content-length");
  /* DATA before the response */
  n = SETTINGS_OK(in);
  n += frame(in + n, 3, H2F_DATA, H2_FL_END_STREAM, 1, "abc");
  EXPECT_RST(H2_PROTOCOL_ERROR, "DATA before HEADERS");
  /* a body after 204, after a HEAD response */
  RESP(0, ":status", "204");
  n += frame(in + n, 3, H2F_DATA, H2_FL_END_STREAM, 1, "abc");
  EXPECT_RST(H2_PROTOCOL_ERROR, "body after 204");
  RESP(0, ":status", "200", "content-length", "3");
  n += frame(in + n, 3, H2F_DATA, H2_FL_END_STREAM, 1, "abc");
  {
    verdict v = run_raw(in, n, 1, 1);
    CHECK(v.rst_code == H2_PROTOCOL_ERROR && v.data == 0, "body after a HEAD response: rst %u data %ld", v.rst_code,
          v.data);
  }
  RESP(H2_FL_END_STREAM, ":status", "200", "content-length", "3");
  {
    verdict v = run_raw(in, n, 1, 1);
    CHECK(!v.failed && v.rst_code == 0 && v.close_err == 0 && v.responses == 1,
          "HEAD response with a content-length and no body: rst %u close %u", v.rst_code, v.close_err);
  }
  /* trailers without END_STREAM; trailers with a pseudo-header */
  RESP(0, ":status", "200");
  {
    static const char *const t[] = { "grpc-status", "0" };
    bl = hdrblock(blk, t, 1);
    n += frame(in + n, (uint32_t)bl, H2F_HEADERS, H2_FL_END_HEADERS, 1, blk);
  }
  EXPECT_RST(H2_PROTOCOL_ERROR, "trailers without END_STREAM");
  RESP(0, ":status", "200");
  {
    static const char *const t[] = { ":status", "200" };
    bl = hdrblock(blk, t, 1);
    n += frame(in + n, (uint32_t)bl, H2F_HEADERS, H2_FL_END_HEADERS | H2_FL_END_STREAM, 1, blk);
  }
  EXPECT_RST(H2_PROTOCOL_ERROR, "a pseudo-header in trailers");
  /* connection errors: HEADERS on a stream never opened, PUSH_PROMISE, ENABLE_PUSH = 1, bad HPACK */
  n = SETTINGS_OK(in);
  {
    static const char *const kv[] = { ":status", "200" };
    bl = hdrblock(blk, kv, 1);
    n += frame(in + n, (uint32_t)bl, H2F_HEADERS, H2_FL_END_HEADERS | H2_FL_END_STREAM, 3, blk);
  }
  EXPECT_GOAWAY(H2_PROTOCOL_ERROR, "HEADERS on a stream never opened");
  n = SETTINGS_OK(in);
  {
    uint8_t pp[8] = { 0, 0, 0, 2, 0x88 };
    n += frame(in + n, 5, H2F_PUSH_PROMISE, H2_FL_END_HEADERS, 1, pp);
  }
  EXPECT_GOAWAY(H2_PROTOCOL_ERROR, "PUSH_PROMISE");
  {
    uint8_t st[6] = { 0, 2, 0, 0, 0, 1 };
    n = frame(in, 6, H2F_SETTINGS, 0, 0, st);
  }
  EXPECT_GOAWAY(H2_PROTOCOL_ERROR, "SETTINGS_ENABLE_PUSH = 1 from a server");
  n = SETTINGS_OK(in);
  {
    uint8_t bad[2] = { 0xff, 0xff }; /* an index beyond any table */
    n += frame(in + n, 2, H2F_HEADERS, H2_FL_END_HEADERS | H2_FL_END_STREAM, 1, bad);
  }
  EXPECT_GOAWAY(H2_COMPRESSION_ERROR, "an HPACK index out of range");
  n = frame(in, 8, H2F_PING, 0, 0, "abcdefgh");
  EXPECT_GOAWAY(H2_PROTOCOL_ERROR, "a frame before the server's SETTINGS");
  /* GOAWAY: streams above the last stream id close as REFUSED_STREAM, the ones below stay open */
  {
    n = SETTINGS_OK(in);
    uint8_t g[8] = { 0, 0, 0, 1, 0, 0, 0, 0 }; /* last stream id 1, NO_ERROR */
    n += frame(in + n, 8, H2F_GOAWAY, 0, 0, g);
    static h2_conn C;
    static long refused;
    refused = 0;
    memset(&VD, 0, sizeof VD);
    VD.close_err = 0xffffffff;
    h2_callbacks cb = VD_CB;
    h2_init_client(&C, &cb, NULL);
    for (int i = 0; i < 3; i++) {
      h2_request rq = { 0 };
      rq.method = (const uint8_t *)"GET", rq.method_len = 3, rq.scheme = (const uint8_t *)"https", rq.scheme_len = 5;
      rq.authority = (const uint8_t *)"a", rq.authority_len = 1, rq.path = (const uint8_t *)"/", rq.path_len = 1;
      h2_submit(&C, &rq, NULL, 0, 1);
    }
    uint8_t out[4096];
    while (h2_send(&C, out, sizeof out)) {}
    int r = h2_recv(&C, &SC, in, n);
    for (int i = 0; i < H2_MAX_STREAMS; i++)
      if (C.s[i].state != H2S_FREE) refused += C.s[i].id == 1 ? 0 : 100;
    h2_request rq = { 0 };
    rq.method = (const uint8_t *)"GET", rq.method_len = 3, rq.scheme = (const uint8_t *)"https", rq.scheme_len = 5;
    rq.path = (const uint8_t *)"/", rq.path_len = 1;
    CHECK(r == (int)n && C.nactive == 1 && refused == 0 && h2_submit(&C, &rq, NULL, 0, 1) == H2_E_STATE,
          "GOAWAY: r %d nactive %d (want 1: streams 3 and 5 refused), new stream refused", r, C.nactive);
  }
  printf("bad responses: %s\n", fails == before ? "ok" : "FAILED");
}

static void test_traffic(void) {
  long before = fails;
  for (long r = 0; r < 2 * scale(); r++) {
    run_vs_nghttp2(0, 400, 65535, 100);                           /* GETs */
    run_vs_nghttp2(1, 200, 65535, 100);                           /* POSTs: body up, trailers down */
    run_vs_nghttp2(2, 20, 1000 + (uint32_t)(rnd() % 20000), 100); /* big downloads; uploads through small windows */
    run_vs_nghttp2(3, 300, 16384, 10);                            /* mixed, 103s, HEAD; 10 concurrent streams */
    run_vs_nghttp2(4, 30, 65535, 100);                            /* response header blocks > one frame */
    run_vs_nghttp2(5, 30, 32768, 100);                            /* 12-30 MB of uploads */
    run_vs_self(400);
  }
  printf("traffic vs nghttp2's server and our own: %s\n", fails == before ? "ok" : "FAILED");
}

int main(void) {
  memset(BIGV, '"', sizeof BIGV); /* a 10-bit Huffman code: sent raw, the block exceeds one frame */
  for (size_t i = 0; i < sizeof UPLOAD; i++) UPLOAD[i] = (uint8_t)i;
  printf("sizeof(h2_conn) = %zu\n", sizeof(h2_conn));
  test_bad();
  test_traffic();
  printf("%s: %ld failures / %ld checks\n", fails ? "FAIL" : "PASS", fails, checks);
  return fails != 0;
}
