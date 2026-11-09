/* h2.h: an HTTP/2 connection (RFC 9113), server or client, sans-IO and header-only. Never allocates: the
 * caller owns the h2_conn (sizeof ~ 26 KiB with the defaults below) and one h2_scratch per thread.
 *
 *   h2_init(&c, &callbacks, user)                       a server, before the client preface arrives
 *   h2_init_client(&c, &callbacks, user)                a client: the preface and SETTINGS are staged
 *   n = h2_recv(&c, &scratch, buf, len)                 bytes consumed (only whole frames), or
 *                                                       H2_E_CLOSED once the connection has failed
 *       Keep the unconsumed tail and call again with more bytes. h2_recv also stops early while
 *       more than half of H2_STAGE is waiting to be sent: call h2_send, then h2_recv again on the
 *       tail (so a response made in a callback always fits; a single response header block must
 *       stay under H2_STAGE / 2). A HEADERS frame is consumed only
 *       together with all its CONTINUATION frames, so a header block never has to be buffered
 *       per connection; the read buffer must hold H2_MAX_BLOCK + 9 * (frames) bytes for the largest
 *       header block accepted and 9 + 16384 for a DATA frame.
 *   n = h2_send(&c, out, cap)                           bytes to write to the socket
 *   h2_want_write(&c), h2_is_closed(&c)                 after a GOAWAY, close once h2_send is drained
 *
 *   h2_respond(&c, sid, status, fields, n, body, len, end)   HEADERS now, DATA from body (zero copy:
 *                                                       body must stay valid until on_close or
 *                                                       until the stream's on_sent), END_STREAM if end
 *   h2_data(&c, sid, body, len, end)                    more body once the previous one is sent
 *   h2_trailers(&c, sid, fields, n)                     trailers after the body (gRPC)
 *   h2_reset(&c, sid, code), h2_goaway(&c, code)
 *
 * Requests reach on_request already decoded and validated (RFC 9113 §8.1-8.3): a malformed request
 * gets RST_STREAM(PROTOCOL_ERROR) and is never shown to the application. Header validation uses
 * hpack.h's cached verdicts, so indexed fields are not re-scanned.
 *
 * Client side (h2_init_client): the same frame layer, flow control and send queue, with
 *   sid = h2_submit(&c, &rq, body, len, end)            a new stream: rq's method, scheme, authority, path
 *                                                       and regular fields (hreq.h's h_request), then DATA
 *                                                       from body (zero copy, as h2_respond). Returns the
 *                                                       stream id, or H2_E_AGAIN at the peer's
 *                                                       MAX_CONCURRENT_STREAMS, or H2_E_STATE (GOAWAY)
 *   h2_data / h2_trailers / h2_reset                    as on a server (h2_respond is a server call)
 * Responses reach on_response decoded and validated (§8.3.2): an informational (1xx) response first if
 * any, then the final one; then on_data and on_trailers as on a server. A malformed response resets the
 * stream with PROTOCOL_ERROR, and on_close reports it. The body of a response to HEAD, of a 204 and of a
 * 304 must be empty. Push is refused (SETTINGS_ENABLE_PUSH = 0). After the server's GOAWAY, the streams
 * above its last stream id close with REFUSED_STREAM (safe to retry) and h2_submit returns H2_E_STATE.
 */
#ifndef H2_H
#define H2_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "hpack.h"
#include "hreq.h"

#ifndef H2_MAX_STREAMS
#define H2_MAX_STREAMS 100 /* SETTINGS_MAX_CONCURRENT_STREAMS we advertise */
#endif
#ifndef H2_MAX_BLOCK
#define H2_MAX_BLOCK 65536 /* largest header block (HEADERS + CONTINUATION payloads) accepted */
#endif
#ifndef H2_MAX_LIST
#define H2_MAX_LIST 16384 /* SETTINGS_MAX_HEADER_LIST_SIZE we advertise */
#endif
#ifndef H2_STAGE
#define H2_STAGE 8192 /* pending control frames + HEADERS per connection */
#endif
#ifndef H2_TRAILER_MAX
#define H2_TRAILER_MAX 128 /* encoded trailer block per stream */
#endif
#define H2_MAX_FIELDS 256
#define H2_FRAME_MAX  16384 /* SETTINGS_MAX_FRAME_SIZE we keep (the default) */
#ifndef H2_CLIENT_MAX_LIST
#define H2_CLIENT_MAX_LIST H2_MAX_BLOCK /* a client's SETTINGS_MAX_HEADER_LIST_SIZE: responses carry big fields */
#endif
#ifndef H2_CLIENT_WINDOW
#define H2_CLIENT_WINDOW (1u << 20) /* a client's SETTINGS_INITIAL_WINDOW_SIZE: downloads need more than 64 KiB */
#endif
#define H2_CONN_WINDOW (16u << 20) /* raised once at start (HAProxy raises it to 2 GB) */

enum { H2_E_CLOSED = -1, H2_E_AGAIN = -2, H2_E_STATE = -3, H2_E_TOO_BIG = -4 };
enum {
  H2_NO_ERROR,
  H2_PROTOCOL_ERROR,
  H2_INTERNAL_ERROR,
  H2_FLOW_CONTROL_ERROR,
  H2_SETTINGS_TIMEOUT,
  H2_STREAM_CLOSED,
  H2_FRAME_SIZE_ERROR,
  H2_REFUSED_STREAM,
  H2_CANCEL,
  H2_COMPRESSION_ERROR,
  H2_CONNECT_ERROR,
  H2_ENHANCE_YOUR_CALM,
  H2_INADEQUATE_SECURITY,
  H2_HTTP_1_1_REQUIRED
};
enum {
  H2F_DATA,
  H2F_HEADERS,
  H2F_PRIORITY,
  H2F_RST_STREAM,
  H2F_SETTINGS,
  H2F_PUSH_PROMISE,
  H2F_PING,
  H2F_GOAWAY,
  H2F_WINDOW_UPDATE,
  H2F_CONTINUATION
};
#define H2_FL_END_STREAM  0x1
#define H2_FL_ACK         0x1
#define H2_FL_END_HEADERS 0x4
#define H2_FL_PADDED      0x8
#define H2_FL_PRIORITY    0x20

typedef struct h2_conn h2_conn;

typedef h_request h2_request;
typedef h_response h2_response;

typedef struct {
  /* return nonzero to reset the stream with INTERNAL_ERROR */
  int (*on_request)(h2_conn *c, uint32_t sid, const h2_request *rq, int end_stream, void *user);
  int (*on_data)(h2_conn *c, uint32_t sid, const uint8_t *d, size_t n, int end_stream, void *user);
  int (*on_trailers)(h2_conn *c, uint32_t sid, const hp_field *f, int n, void *user);
  void (*on_sent)(h2_conn *c, uint32_t sid, void *user);                  /* the body passed last is out */
  void (*on_close)(h2_conn *c, uint32_t sid, uint32_t error, void *user); /* the stream is gone */
  /* a client's: a response's header section (informational ones too, status < 200); nonzero resets the stream */
  int (*on_response)(h2_conn *c, uint32_t sid, const h2_response *rs, int end_stream, void *user);
} h2_callbacks;

/* per-thread scratch: header block reassembly and the decoded fields */
typedef struct {
  uint8_t block[H2_MAX_BLOCK];
  uint8_t arena[H2_MAX_BLOCK * 2];
  hp_field f[H2_MAX_FIELDS];
} h2_scratch;

enum { H2S_FREE, H2S_ACTIVE };
#define H2_ST_RESPONDED  2u
#define H2_ST_BODY_END   4u  /* END_STREAM goes on the last DATA of the current body */
#define H2_ST_TRAILERS   8u  /* trailers follow the body */
#define H2_ST_REMOTE_END 16u /* the client sent END_STREAM (half-closed remote) */
#define H2_ST_LOCAL_END  32u /* we sent END_STREAM (half-closed local) */
#define H2_ST_QUEUED     64u /* in the send queue */

#define H2_CS_HEAD  1u /* client: the request was HEAD (the response has no body) */
#define H2_CS_FINAL 2u /* client: the final (non-1xx) response is in */

typedef struct {
  uint32_t id;
  uint8_t state, flags;
  uint16_t trailer_len;
  uint8_t cflags;               /* H2_CS_* */
  uint8_t urgency, incremental; /* RFC 9218: lower urgency is served first; incremental ones are interleaved */
  int32_t send_win;
  uint32_t recv_unacked;
  int64_t content_length, data_seen;
  const uint8_t *body;
  size_t body_len, body_off;
  uint8_t trailer[H2_TRAILER_MAX];
} h2_stream;

struct h2_conn {
  h2_callbacks cb;
  void *user;
  uint32_t preface_left; /* client preface bytes still expected */
  uint8_t got_settings, closed, goaway_sent, goaway_recv;
  uint8_t client;       /* h2_init_client */
  uint32_t last_sid;    /* highest client stream id seen (a client: the last one it opened) */
  uint32_t next_sid;    /* a client's next stream id */
  uint32_t recv_window; /* the stream receive window we advertise: 65535 (server), H2_CLIENT_WINDOW (client) */
  uint32_t peer_max_frame, peer_max_concurrent, peer_initial_window, peer_header_table;
  int64_t conn_send_win;
  uint32_t conn_recv_unacked;
  int nactive;
  uint32_t qh, qn; /* send queue: ring of stream slots with a body or trailers pending */
  uint16_t q[H2_MAX_STREAMS];
  hp_enc enc; /* a client indexes its requests' fields; a server's table is 0 (one size update) */
  hp_dec dec;
  size_t stage_len, stage_off;
  uint8_t stage[H2_STAGE];
  h2_stream s[H2_MAX_STREAMS];
};

/* ------------------------------------------ framing ------------------------------------------ */
static inline uint32_t h2__be24(const uint8_t *p) { return (uint32_t)p[0] << 16 | (uint32_t)p[1] << 8 | p[2]; }
static inline uint32_t h2__be32(const uint8_t *p) {
  return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static inline void h2__hdr(uint8_t *p, uint32_t len, uint8_t type, uint8_t flags, uint32_t sid) {
  p[0] = (uint8_t)(len >> 16), p[1] = (uint8_t)(len >> 8), p[2] = (uint8_t)len, p[3] = type, p[4] = flags;
  p[5] = (uint8_t)(sid >> 24 & 0x7f), p[6] = (uint8_t)(sid >> 16), p[7] = (uint8_t)(sid >> 8), p[8] = (uint8_t)sid;
}
static inline void h2__put32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24), p[1] = (uint8_t)(v >> 16), p[2] = (uint8_t)(v >> 8), p[3] = (uint8_t)v;
}

/* append to the stage; 0 if it does not fit */
static inline uint8_t *h2__stage(h2_conn *c, size_t n) {
  if (c->stage_off && c->stage_len + n > sizeof c->stage) {
    memmove(c->stage, c->stage + c->stage_off, c->stage_len - c->stage_off);
    c->stage_len -= c->stage_off, c->stage_off = 0;
  }
  if (c->stage_len + n > sizeof c->stage) return NULL;
  uint8_t *p = c->stage + c->stage_len;
  c->stage_len += n;
  return p;
}
static inline int h2__stage_room(const h2_conn *c, size_t n) {
  return c->stage_len - c->stage_off + n <= sizeof c->stage;
}
static inline void h2__ctrl(h2_conn *c, uint8_t type, uint8_t flags, uint32_t sid, const uint8_t *payload, uint32_t n) {
  uint8_t *p = h2__stage(c, 9 + n);
  /* control frames are tiny; a full stage means a stuck peer */
  if (!p) {
    c->closed = 1;
    return;
  }
  h2__hdr(p, n, type, flags, sid);
  if (n) memcpy(p + 9, payload, n);
}
static inline void h2__window_update(h2_conn *c, uint32_t sid, uint32_t inc) {
  uint8_t b[4];
  h2__put32(b, inc & 0x7fffffff);
  h2__ctrl(c, H2F_WINDOW_UPDATE, 0, sid, b, 4);
}

/* ------------------------------------------ streams ------------------------------------------ */
/* streams live in slots probed from (sid / 2) % H2_MAX_STREAMS, so a lookup is O(1) on average */
static inline h2_stream *h2__find(h2_conn *c, uint32_t sid) {
  for (uint32_t k = 0, i = (sid >> 1) % H2_MAX_STREAMS; k < H2_MAX_STREAMS; k++, i = (i + 1) % H2_MAX_STREAMS)
    if (c->s[i].state != H2S_FREE && c->s[i].id == sid) return &c->s[i];
  return NULL;
}
static inline void h2__close_stream(h2_conn *c, h2_stream *s, uint32_t err) {
  uint32_t id = s->id;
  s->state = H2S_FREE, s->body = NULL;
  c->nactive--;
  if (c->cb.on_close) c->cb.on_close(c, id, err, c->user);
}
static inline void h2_reset(h2_conn *c, uint32_t sid, uint32_t code) {
  uint8_t b[4];
  h2__put32(b, code);
  h2__ctrl(c, H2F_RST_STREAM, 0, sid, b, 4);
  h2_stream *s = h2__find(c, sid);
  if (s) h2__close_stream(c, s, code);
}
static inline void h2_goaway(h2_conn *c, uint32_t code) {
  if (c->goaway_sent) return;
  uint8_t b[8];
  h2__put32(b, c->client ? 0 : c->last_sid), h2__put32(b + 4, code); /* a client processed no pushed streams */
  h2__ctrl(c, H2F_GOAWAY, 0, 0, b, 8);
  c->goaway_sent = 1;
}
/* connection error: GOAWAY, then nothing more is read */
static inline int h2__fail(h2_conn *c, uint32_t code) {
  h2_goaway(c, code);
  c->closed = 1;
  for (int i = 0; i < H2_MAX_STREAMS; i++)
    if (c->s[i].state != H2S_FREE) h2__close_stream(c, &c->s[i], code);
  return H2_E_CLOSED;
}
/* set an end flag; the stream is closed once both ends are done */
static inline void h2__end(h2_conn *c, h2_stream *s, uint8_t which) {
  s->flags |= which;
  if ((s->flags & (H2_ST_REMOTE_END | H2_ST_LOCAL_END)) == (H2_ST_REMOTE_END | H2_ST_LOCAL_END))
    h2__close_stream(c, s, 0);
}

static inline void h2__enqueue(h2_conn *c, h2_stream *s) {
  if (s->flags & H2_ST_QUEUED) return;
  s->flags |= H2_ST_QUEUED;
  c->q[(c->qh + c->qn++) % H2_MAX_STREAMS] = (uint16_t)(s - c->s);
}
static inline void h2_init(h2_conn *c, const h2_callbacks *cb, void *user) {
  memset(c, 0, offsetof(h2_conn, dec));
  c->cb = *cb, c->user = user;
  c->preface_left = 24;
  c->peer_max_frame = 16384, c->peer_max_concurrent = 0xffffffff, c->peer_initial_window = 65535,
  c->peer_header_table = 4096;
  c->conn_send_win = 65535;
  c->recv_window = 65535;
  c->stage_len = c->stage_off = 0;
  for (int i = 0; i < H2_MAX_STREAMS; i++) c->s[i].state = H2S_FREE;
  hp_dec_init(&c->dec, 4096);
  hp_enc_init(&c->enc, 4096), hp_enc_resize(&c->enc, 0); /* responses never index */
  /* server preface: SETTINGS, then the connection window raised once */
  uint8_t st[24];
  const uint16_t id[4] = { 0x3 /* MAX_CONCURRENT_STREAMS */, 0x6 /* MAX_HEADER_LIST_SIZE */, 0x2 /* ENABLE_PUSH */,
                           0x9 /* NO_RFC7540_PRIORITIES: RFC 9218's instead */ };
  const uint32_t v[4] = { H2_MAX_STREAMS, H2_MAX_LIST, 0, 1 };
  for (int i = 0; i < 4; i++)
    st[6 * i] = (uint8_t)(id[i] >> 8), st[6 * i + 1] = (uint8_t)id[i], h2__put32(st + 6 * i + 2, v[i]);
  h2__ctrl(c, H2F_SETTINGS, 0, 0, st, 24);
  h2__window_update(c, 0, H2_CONN_WINDOW - 65535);
}

/* a client connection: the connection preface (RFC 9113 §3.4), SETTINGS (no push, a larger stream window, the
 * header list size we accept), and the connection window raised once */
static inline void h2_init_client(h2_conn *c, const h2_callbacks *cb, void *user) {
  memset(c, 0, offsetof(h2_conn, dec));
  c->cb = *cb, c->user = user;
  c->client = 1, c->next_sid = 1;
  /* until the server's SETTINGS arrive, assume 100 concurrent streams (its likely minimum, RFC 9113 §6.5.2);
   * a lower limit there means a few REFUSED_STREAM, which are safe to retry */
  c->peer_max_frame = 16384, c->peer_max_concurrent = 100, c->peer_initial_window = 65535, c->peer_header_table = 4096;
  c->conn_send_win = 65535;
  c->recv_window = H2_CLIENT_WINDOW;
  c->stage_len = c->stage_off = 0;
  for (int i = 0; i < H2_MAX_STREAMS; i++) c->s[i].state = H2S_FREE;
  hp_dec_init(&c->dec, 4096);
  hp_enc_init(&c->enc, 4096); /* the peer's default SETTINGS_HEADER_TABLE_SIZE */
  uint8_t *p = h2__stage(c, 24);
  memcpy(p, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24);
  uint8_t st[24];
  const uint16_t id[4] = { 0x2 /* ENABLE_PUSH */, 0x4 /* INITIAL_WINDOW_SIZE */, 0x6 /* MAX_HEADER_LIST_SIZE */,
                           0x9 /* NO_RFC7540_PRIORITIES */ };
  const uint32_t v[4] = { 0, H2_CLIENT_WINDOW, H2_CLIENT_MAX_LIST, 1 };
  for (int i = 0; i < 4; i++)
    st[6 * i] = (uint8_t)(id[i] >> 8), st[6 * i + 1] = (uint8_t)id[i], h2__put32(st + 6 * i + 2, v[i]);
  h2__ctrl(c, H2F_SETTINGS, 0, 0, st, 24);
  h2__window_update(c, 0, H2_CONN_WINDOW - 65535);
}

/* ------------------------------------------ receive ------------------------------------------ */
/* a client's header block: a response (1xx first, then the final one) or trailers, on a stream it opened */
static inline int h2__response_block(h2_conn *c, h2_scratch *sc, uint32_t sid, uint8_t flags, const uint8_t *blk,
                                     size_t blen, int self_dep) {
  int hfl;
  int n = hp_decode_block(&c->dec, blk, blen, sc->f, H2_MAX_FIELDS / 2, sc->arena, sizeof sc->arena, H2_CLIENT_MAX_LIST,
                          &hfl);
  if (n == HP_E_COMPRESSION) return h2__fail(c, H2_COMPRESSION_ERROR);
  if (n < 0) return h2__fail(c, H2_ENHANCE_YOUR_CALM);
  if (sid > c->last_sid) return h2__fail(c, H2_PROTOCOL_ERROR); /* a stream we never opened (§5.1) */
  h2_stream *s = h2__find(c, sid);
  if (!s) return 0; /* closed (we reset it, say): the block was decoded, so the table is in sync */
  int end = flags & H2_FL_END_STREAM;
  if ((s->flags & H2_ST_REMOTE_END) || self_dep) {
    h2_reset(c, sid, s->flags & H2_ST_REMOTE_END ? H2_STREAM_CLOSED : H2_PROTOCOL_ERROR);
    return 0;
  }
  if (s->cflags & H2_CS_FINAL) { /* trailers: END_STREAM, regular fields only, and the body had its length */
    if (!end || !h_check_trailers(sc->f, n) || (s->content_length >= 0 && s->data_seen != s->content_length)) {
      h2_reset(c, sid, H2_PROTOCOL_ERROR);
      return 0;
    }
    int r = c->cb.on_trailers ? c->cb.on_trailers(c, sid, sc->f, n, c->user) : 0;
    if ((s = h2__find(c, sid))) {
      if (r) h2_reset(c, sid, H2_INTERNAL_ERROR);
      else h2__end(c, s, H2_ST_REMOTE_END);
    }
    return 0;
  }
  h2_response rs;
  if (!h_build_response(sc->f, n, &rs, sc->f + H2_MAX_FIELDS / 2) || (hfl & HP_F_LIST_TOO_BIG)) {
    h2_reset(c, sid, H2_PROTOCOL_ERROR);
    return 0;
  }
  if (rs.status < 200) { /* informational: never the end of the stream (§8.1) */
    if (end) {
      h2_reset(c, sid, H2_PROTOCOL_ERROR);
      return 0;
    }
  } else {
    s->cflags |= H2_CS_FINAL;
    /* the body's length: none after HEAD, 204 or 304 (RFC 9110 §6.4.1), else the content-length if any */
    s->content_length = (s->cflags & H2_CS_HEAD) || rs.status == 204 || rs.status == 304 ? 0 : rs.content_length;
    if (end && s->content_length > 0) {
      h2_reset(c, sid, H2_PROTOCOL_ERROR);
      return 0;
    }
  }
  int r = c->cb.on_response ? c->cb.on_response(c, sid, &rs, end, c->user) : 0;
  if ((s = h2__find(c, sid))) {
    if (r) h2_reset(c, sid, H2_INTERNAL_ERROR);
    else if (end) h2__end(c, s, H2_ST_REMOTE_END);
  }
  return 0;
}

static inline int h2__header_block(h2_conn *c, h2_scratch *sc, uint32_t sid, uint8_t flags, const uint8_t *blk,
                                   size_t blen, int self_dep) {
  if (c->client) return h2__response_block(c, sc, sid, flags, blk, blen, self_dep);
  int hfl;
  int n = hp_decode_block(&c->dec, blk, blen, sc->f, H2_MAX_FIELDS / 2, sc->arena, sizeof sc->arena, H2_MAX_LIST, &hfl);
  if (n == HP_E_COMPRESSION) return h2__fail(c, H2_COMPRESSION_ERROR);
  if (n < 0) return h2__fail(c, H2_ENHANCE_YOUR_CALM);
  int end = flags & H2_FL_END_STREAM;
  /* an id above any seen is a new stream: no lookup (a miss would probe every slot) */
  h2_stream *s = sid <= c->last_sid ? h2__find(c, sid) : NULL;
  if (s) { /* trailers: a second HEADERS on a stream the client has not ended */
    if (s->flags & H2_ST_REMOTE_END) {
      h2_reset(c, sid, H2_STREAM_CLOSED);
      return 0;
    }
    if (!end || self_dep) {
      h2_reset(c, sid, H2_PROTOCOL_ERROR);
      return 0;
    }
    for (int i = 0; i < n; i++)
      if (sc->f[i].nclass != HP_N_OK || !sc->f[i].vok) {
        h2_reset(c, sid, H2_PROTOCOL_ERROR);
        return 0;
      }
    if (s->content_length >= 0 && s->data_seen != s->content_length) {
      h2_reset(c, sid, H2_PROTOCOL_ERROR);
      return 0;
    }
    int r = c->cb.on_trailers ? c->cb.on_trailers(c, sid, sc->f, n, c->user) : 0;
    if ((s = h2__find(c, sid))) {
      if (r) h2_reset(c, sid, H2_INTERNAL_ERROR);
      else h2__end(c, s, H2_ST_REMOTE_END);
    }
    return 0;
  }
  if (sid <= c->last_sid) return h2__fail(c, H2_STREAM_CLOSED); /* HEADERS on a closed stream */
  c->last_sid = sid;
  /* §5.3.1 */
  if (self_dep) {
    h2_reset(c, sid, H2_PROTOCOL_ERROR);
    return 0;
  }
  if (c->goaway_sent) return 0;
  if (c->nactive >= H2_MAX_STREAMS) {
    h2_reset(c, sid, H2_REFUSED_STREAM);
    return 0;
  }
  for (uint32_t k = 0, i = (sid >> 1) % H2_MAX_STREAMS; k < H2_MAX_STREAMS; k++, i = (i + 1) % H2_MAX_STREAMS)
    if (c->s[i].state == H2S_FREE) {
      s = &c->s[i];
      break;
    }
  if (!s) return h2__fail(c, H2_INTERNAL_ERROR); /* cannot happen while nactive < H2_MAX_STREAMS */
  memset(s, 0, offsetof(h2_stream, trailer));
  s->id = sid, s->state = H2S_ACTIVE, s->urgency = H_URGENCY_DEFAULT;
  s->send_win = (int32_t)c->peer_initial_window;
  c->nactive++;
  h2_request rq;
  if (!h_build_request(sc->f, n, &rq, sc->f + H2_MAX_FIELDS / 2)) {
    h2_reset(c, sid, H2_PROTOCOL_ERROR);
    return 0;
  }
  s->content_length = rq.content_length;
  if (end && rq.content_length > 0) {
    h2_reset(c, sid, H2_PROTOCOL_ERROR);
    return 0;
  }
  if (end) s->flags |= H2_ST_REMOTE_END;
  if (hfl & HP_F_LIST_TOO_BIG) { /* answer 431 without involving the application */
    uint8_t b431[24];
    size_t bl = hp_enc_status(b431, 431);
    uint8_t *p = h2__stage(c, 9 + bl);
    if (!p) return h2__fail(c, H2_INTERNAL_ERROR);
    h2__hdr(p, (uint32_t)bl, H2F_HEADERS, H2_FL_END_HEADERS | H2_FL_END_STREAM, sid);
    memcpy(p + 9, b431, bl);
    s->flags |= H2_ST_RESPONDED;
    if (s->flags & H2_ST_REMOTE_END) h2__end(c, s, H2_ST_LOCAL_END);
    else h2_reset(c, sid, H2_NO_ERROR); /* §8.1: done with the request body too */
    return 0;
  }
  for (int i = 0; i < rq.nfields; i++) /* the priority field (RFC 9218 §5) */
    if (h_eq(rq.fields[i].name, rq.fields[i].nlen, "priority"))
      h_priority_parse(rq.fields[i].value, rq.fields[i].vlen, &s->urgency, &s->incremental);
  if (c->cb.on_request && c->cb.on_request(c, sid, &rq, end, c->user) && h2__find(c, sid))
    h2_reset(c, sid, H2_INTERNAL_ERROR);
  return 0;
}

/* HEADERS payload at pl (len bytes) plus following CONTINUATION frames into sc->block. Returns the
 * bytes used from p, 0 if more input is needed, or H2_E_CLOSED. */
static inline int h2__gather(h2_conn *c, h2_scratch *sc, const uint8_t *p, size_t avail, uint32_t sid, uint8_t fl,
                             const uint8_t *frag, size_t flen, size_t first_used, size_t *blen) {
  if (flen > sizeof sc->block) return h2__fail(c, H2_ENHANCE_YOUR_CALM);
  memcpy(sc->block, frag, flen);
  size_t bl = flen, used = first_used;
  while (!(fl & H2_FL_END_HEADERS)) {
    if (avail < used + 9) return 0;
    const uint8_t *q = p + used;
    uint32_t cl = h2__be24(q);
    if (q[3] != H2F_CONTINUATION || (h2__be32(q + 5) & 0x7fffffff) != sid) return h2__fail(c, H2_PROTOCOL_ERROR);
    if (cl > H2_FRAME_MAX) return h2__fail(c, H2_FRAME_SIZE_ERROR);
    if (avail < used + 9 + cl) return 0;
    if (bl + cl > sizeof sc->block) return h2__fail(c, H2_ENHANCE_YOUR_CALM);
    memcpy(sc->block + bl, q + 9, cl);
    bl += cl, used += 9 + cl, fl = q[4];
  }
  *blen = bl;
  return (int)used;
}

/* returns consumed bytes, 0 if the whole frame (or header block) is not here yet */
static inline int h2__frame(h2_conn *c, h2_scratch *sc, const uint8_t *p, size_t avail) {
  if (avail < 9) return 0;
  uint32_t len = h2__be24(p), sid = h2__be32(p + 5) & 0x7fffffff;
  uint8_t type = p[3], fl = p[4];
  if (len > H2_FRAME_MAX) return h2__fail(c, H2_FRAME_SIZE_ERROR);
  if (avail < 9 + (size_t)len) return 0;
  const uint8_t *pl = p + 9;
  if (!c->got_settings && type != H2F_SETTINGS) return h2__fail(c, H2_PROTOCOL_ERROR);
  switch (type) {
    case H2F_DATA: {
      if (!sid) return h2__fail(c, H2_PROTOCOL_ERROR);
      if (sid > c->last_sid) return h2__fail(c, H2_PROTOCOL_ERROR); /* idle stream */
      uint32_t pad = 0;
      if (fl & H2_FL_PADDED) {
        if (!len || (pad = pl[0]) >= len) return h2__fail(c, H2_PROTOCOL_ERROR);
        pl++;
      }
      size_t dlen = len - pad - ((fl & H2_FL_PADDED) ? 1 : 0);
      /* the connection window counts the whole frame, whatever happens to the stream */
      c->conn_recv_unacked += len;
      if (c->conn_recv_unacked > H2_CONN_WINDOW) return h2__fail(c, H2_FLOW_CONTROL_ERROR);
      if (c->conn_recv_unacked >= H2_CONN_WINDOW / 2)
        h2__window_update(c, 0, c->conn_recv_unacked), c->conn_recv_unacked = 0;
      h2_stream *s = h2__find(c, sid);
      if (!s || (s->flags & H2_ST_REMOTE_END)) { /* closed or half-closed (remote) */
        if (s) h2_reset(c, sid, H2_STREAM_CLOSED);
        else {
          uint8_t b[4];
          h2__put32(b, H2_STREAM_CLOSED);
          h2__ctrl(c, H2F_RST_STREAM, 0, sid, b, 4);
        }
        return (int)(9 + len);
      }
      if (c->client && !(s->cflags & H2_CS_FINAL)) { /* DATA before the response's header section */
        h2_reset(c, sid, H2_PROTOCOL_ERROR);
        return (int)(9 + len);
      }
      s->recv_unacked += len;
      if (s->recv_unacked > c->recv_window) {
        h2_reset(c, sid, H2_FLOW_CONTROL_ERROR);
        return (int)(9 + len);
      }
      s->data_seen += (int64_t)dlen;
      int end = fl & H2_FL_END_STREAM;
      if (s->content_length >= 0 && (s->data_seen > s->content_length || (end && s->data_seen != s->content_length))) {
        h2_reset(c, sid, H2_PROTOCOL_ERROR);
        return (int)(9 + len);
      }
      if (c->cb.on_data && c->cb.on_data(c, sid, pl, dlen, end, c->user)) {
        if (h2__find(c, sid)) h2_reset(c, sid, H2_INTERNAL_ERROR);
        return (int)(9 + len);
      }
      if (!(s = h2__find(c, sid))) return (int)(9 + len); /* the application reset it */
      if (end) h2__end(c, s, H2_ST_REMOTE_END);
      /* the application consumed it: reopen the window once half of it is used */
      else if (s->recv_unacked >= c->recv_window / 2) h2__window_update(c, sid, s->recv_unacked), s->recv_unacked = 0;
      return (int)(9 + len);
    }
    case H2F_HEADERS: {
      if (!sid || !(sid & 1)) return h2__fail(c, H2_PROTOCOL_ERROR);
      uint32_t off = 0, pad = 0;
      int self_dep = 0;
      if (fl & H2_FL_PADDED) {
        if (!len) return h2__fail(c, H2_PROTOCOL_ERROR);
        pad = pl[0], off = 1;
      }
      if (fl & H2_FL_PRIORITY) {
        if (len < off + 5) return h2__fail(c, H2_FRAME_SIZE_ERROR);
        self_dep = (h2__be32(pl + off) & 0x7fffffff) == sid;
        off += 5;
      }
      if (off + pad > len) return h2__fail(c, H2_PROTOCOL_ERROR);
      size_t bl = 0;
      int used = h2__gather(c, sc, p, avail, sid, fl, pl + off, len - off - pad, 9 + len, &bl);
      if (used <= 0) return used;
      int r = h2__header_block(c, sc, sid, fl, sc->block, bl, self_dep);
      return r < 0 ? r : used;
    }
    case H2F_PRIORITY:
      if (!sid) return h2__fail(c, H2_PROTOCOL_ERROR);
      if (len != 5) { /* stream error (§6.3); the stream may be idle, so no state to touch */
        uint8_t b[4];
        h2__put32(b, H2_FRAME_SIZE_ERROR);
        h2__ctrl(c, H2F_RST_STREAM, 0, sid, b, 4);
        return (int)(9 + len);
      }
      if ((h2__be32(pl) & 0x7fffffff) == sid) h2_reset(c, sid, H2_PROTOCOL_ERROR);
      return (int)(9 + len);
    case H2F_RST_STREAM: {
      if (!sid) return h2__fail(c, H2_PROTOCOL_ERROR);
      if (len != 4) return h2__fail(c, H2_FRAME_SIZE_ERROR);
      if (sid > c->last_sid) return h2__fail(c, H2_PROTOCOL_ERROR);
      h2_stream *s = h2__find(c, sid);
      if (s) h2__close_stream(c, s, h2__be32(pl));
      return (int)(9 + len);
    }
    case H2F_SETTINGS:
      if (sid) return h2__fail(c, H2_PROTOCOL_ERROR);
      if (fl & H2_FL_ACK) {
        if (len) return h2__fail(c, H2_FRAME_SIZE_ERROR);
        return 9;
      }
      if (len % 6) return h2__fail(c, H2_FRAME_SIZE_ERROR);
      for (uint32_t i = 0; i < len; i += 6) {
        uint16_t id = (uint16_t)(pl[i] << 8 | pl[i + 1]);
        uint32_t v = h2__be32(pl + i + 2);
        switch (id) {
          case 1:
            c->peer_header_table = v;
            if (c->client) hp_enc_resize(&c->enc, v);
            break;
          case 2: /* a server may only send 0 (§6.5.2) */
            if (v > 1 || (c->client && v)) return h2__fail(c, H2_PROTOCOL_ERROR);
            break;
          case 3: c->peer_max_concurrent = v; break;
          case 4: {
            if (v > 0x7fffffff) return h2__fail(c, H2_FLOW_CONTROL_ERROR);
            int64_t delta = (int64_t)v - c->peer_initial_window;
            for (int k = 0; k < H2_MAX_STREAMS; k++)
              if (c->s[k].state != H2S_FREE) {
                int64_t w = c->s[k].send_win + delta;
                if (w > 0x7fffffff) return h2__fail(c, H2_FLOW_CONTROL_ERROR);
                c->s[k].send_win = (int32_t)w;
              }
            c->peer_initial_window = v;
            break;
          }
          case 5:
            if (v < 16384 || v > 16777215) return h2__fail(c, H2_PROTOCOL_ERROR);
            c->peer_max_frame = v;
            break;
          default: break; /* 6 MAX_HEADER_LIST_SIZE is advisory; unknown settings are ignored */
        }
      }
      c->got_settings = 1;
      h2__ctrl(c, H2F_SETTINGS, H2_FL_ACK, 0, NULL, 0);
      return (int)(9 + len);
    case H2F_PUSH_PROMISE: return h2__fail(c, H2_PROTOCOL_ERROR); /* clients never push */
    case H2F_PING:
      if (sid) return h2__fail(c, H2_PROTOCOL_ERROR);
      if (len != 8) return h2__fail(c, H2_FRAME_SIZE_ERROR);
      if (!(fl & H2_FL_ACK)) h2__ctrl(c, H2F_PING, H2_FL_ACK, 0, pl, 8);
      return 17;
    case H2F_GOAWAY:
      if (sid) return h2__fail(c, H2_PROTOCOL_ERROR);
      if (len < 8) return h2__fail(c, H2_FRAME_SIZE_ERROR);
      c->goaway_recv = 1;
      if (c->client) { /* the streams above the server's last stream id were never processed: retry-safe */
        uint32_t last = h2__be32(pl) & 0x7fffffff;
        for (int k = 0; k < H2_MAX_STREAMS; k++)
          if (c->s[k].state != H2S_FREE && c->s[k].id > last) h2__close_stream(c, &c->s[k], H2_REFUSED_STREAM);
      }
      return (int)(9 + len);
    case H2F_WINDOW_UPDATE: {
      if (len != 4) return h2__fail(c, H2_FRAME_SIZE_ERROR);
      uint32_t inc = h2__be32(pl) & 0x7fffffff;
      if (!sid) {
        if (!inc) return h2__fail(c, H2_PROTOCOL_ERROR);
        if (c->conn_send_win + inc > 0x7fffffff) return h2__fail(c, H2_FLOW_CONTROL_ERROR);
        c->conn_send_win += inc;
        return 13;
      }
      if (sid > c->last_sid) return h2__fail(c, H2_PROTOCOL_ERROR);
      h2_stream *s = h2__find(c, sid);
      if (!s) return 13; /* closed: ignore */
      if (!inc) {
        h2_reset(c, sid, H2_PROTOCOL_ERROR);
        return 13;
      }
      if ((int64_t)s->send_win + inc > 0x7fffffff) {
        h2_reset(c, sid, H2_FLOW_CONTROL_ERROR);
        return 13;
      }
      s->send_win += (int32_t)inc;
      return 13;
    }
    case H2F_CONTINUATION: return h2__fail(c, H2_PROTOCOL_ERROR); /* without a HEADERS before it */
    case 0x10: { /* PRIORITY_UPDATE (RFC 9218 §7.1): a client's, on stream 0, for a request stream */
      if (c->client || sid || len < 4) return h2__fail(c, H2_PROTOCOL_ERROR);
      uint32_t ps = h2__be32(pl) & 0x7fffffff;
      if (!ps || !(ps & 1)) return h2__fail(c, H2_PROTOCOL_ERROR);
      h2_stream *s = h2__find(c, ps); /* (one not open yet, or gone: nothing to do) */
      if (s) h_priority_parse(pl + 4, len - 4, &s->urgency, &s->incremental);
      return (int)(9 + len);
    }
    default: return (int)(9 + len); /* unknown types are ignored (§4.1) */
  }
}

static inline int h2_recv(h2_conn *c, h2_scratch *sc, const uint8_t *buf, size_t len) {
  static const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
  if (c->closed) return H2_E_CLOSED;
  size_t used = 0;
  while (c->preface_left && used < len) {
    if (buf[used] != (uint8_t)preface[24 - c->preface_left]) return h2__fail(c, H2_PROTOCOL_ERROR);
    used++, c->preface_left--;
  }
  while (!c->preface_left && used < len && !c->closed) {
    /* backpressure: with half the stage pending, let the caller drain h2_send first, so responses
     * made from the callbacks always find room */
    if (c->stage_len - c->stage_off > sizeof c->stage / 2) break;
    int r = h2__frame(c, sc, buf + used, len - used);
    if (r < 0) return r;
    if (r == 0) break;
    used += (size_t)r;
  }
  return (int)used;
}

/* ------------------------------------------- send ------------------------------------------- */
/* staged: the block goes to the stage now, so it may carry the table size updates due (a server's one, to 0);
 * trailers wait in their stream and may reach the wire after later blocks, so they carry none */
static inline size_t h2__enc_block(h2_conn *c, uint8_t *dst, size_t cap, int staged, int status, const hp_field *f,
                                   int n) {
  uint8_t *p = dst, *e = dst + cap;
  if (cap < 32) return 0;
  if (staged) p += hp_enc_begin(&c->enc, p);
  if (status) p += hp_enc_status(p, status);
  for (int i = 0; i < n; i++) {
    if ((size_t)(e - p) < hp_enc_bound(f[i].nlen, f[i].vlen)) return 0;
    p += hp_enc_field(p, f[i].name, f[i].nlen, f[i].value, f[i].vlen, f[i].never);
  }
  return (size_t)(p - dst);
}
/* a header block as HEADERS + CONTINUATION frames into the stage */
static inline int h2__stage_block(h2_conn *c, uint32_t sid, const uint8_t *blk, size_t bl, uint8_t endflag) {
  size_t nfr = bl ? (bl + c->peer_max_frame - 1) / c->peer_max_frame : 1;
  uint8_t *p = h2__stage(c, bl + 9 * nfr);
  if (!p) return H2_E_AGAIN;
  size_t off = 0;
  for (size_t k = 0; k < nfr; k++) {
    size_t m = bl - off < c->peer_max_frame ? bl - off : c->peer_max_frame;
    uint8_t fl = (k == nfr - 1 ? H2_FL_END_HEADERS : 0) | (k == 0 ? endflag : 0);
    h2__hdr(p, (uint32_t)m, k == 0 ? H2F_HEADERS : H2F_CONTINUATION, fl, sid);
    memcpy(p + 9, blk + off, m);
    p += 9 + m, off += m;
  }
  return 0;
}

static inline int h2_respond(h2_conn *c, uint32_t sid, int status, const hp_field *f, int n, const uint8_t *body,
                             size_t len, int end) {
  h2_stream *s = h2__find(c, sid);
  if (c->client || !s || (s->flags & H2_ST_RESPONDED)) return H2_E_STATE;
  uint8_t blk[H2_STAGE];
  size_t bl = h2__enc_block(c, blk, sizeof blk, 1, status, f, n);
  if (!bl) return H2_E_TOO_BIG;
  int headers_end = end && !body;
  int r = h2__stage_block(c, sid, blk, bl, headers_end ? H2_FL_END_STREAM : 0);
  if (r) return r;
  s->flags |= H2_ST_RESPONDED;
  if (headers_end) {
    h2__end(c, s, H2_ST_LOCAL_END);
    return 0;
  }
  s->body = body ? body : (const uint8_t *)"", s->body_len = len, s->body_off = 0;
  if (end) s->flags |= H2_ST_BODY_END;
  h2__enqueue(c, s);
  return 0;
}
/* a request's pseudo-header: indexed when (name, value) is in the static table (GET, POST, http, https, "/",
 * "/index.html"), else a literal with the static name */
static inline uint8_t *h2__pseudo(uint8_t *p, int first, int last, const char *name, const uint8_t *v, uint32_t vl) {
  for (int i = first; i <= last; i++)
    if (hp_static[i].vl == vl && !memcmp(hp_static[i].v, v, vl)) {
      *p++ = (uint8_t)(0x80 | i);
      return p;
    }
  return p + hp_enc_field(p, (const uint8_t *)name, strlen(name), v, vl, 0);
}
/* client: open a stream with rq's request (see the top of the file). Returns the stream id or H2_E_* */
static inline int h2_submit(h2_conn *c, const h2_request *rq, const uint8_t *body, size_t len, int end) {
  if (!c->client || c->closed || c->goaway_recv || c->goaway_sent || c->next_sid > 0x7fffffff) return H2_E_STATE;
  if (c->nactive >= H2_MAX_STREAMS || (uint32_t)c->nactive >= c->peer_max_concurrent) return H2_E_AGAIN;
  uint32_t sid = c->next_sid;
  h2_stream *s = NULL;
  for (uint32_t k = 0, i = (sid >> 1) % H2_MAX_STREAMS; k < H2_MAX_STREAMS; k++, i = (i + 1) % H2_MAX_STREAMS)
    if (c->s[i].state == H2S_FREE) {
      s = &c->s[i];
      break;
    }
  if (!s) return H2_E_AGAIN;
  uint8_t blk[H2_STAGE];
  uint8_t *p = blk, *e = blk + sizeof blk;
  size_t need = 32 + rq->method_len + rq->scheme_len + rq->authority_len + rq->path_len;
  for (int i = 0; i < rq->nfields; i++) need += hp_enc_bound(rq->fields[i].nlen, rq->fields[i].vlen);
  if (need > sizeof blk) return H2_E_TOO_BIG;
  /* the encoder's table changes as the block is encoded: it must reach the stage, so check for room first */
  if (!h2__stage_room(c, need + 9 * ((need + c->peer_max_frame - 1) / c->peer_max_frame))) return H2_E_AGAIN;
  p += hp_enc_begin(&c->enc, p);
  p = h2__pseudo(p, 2, 3, ":method", rq->method, rq->method_len);
  if (rq->scheme) p = h2__pseudo(p, 6, 7, ":scheme", rq->scheme, rq->scheme_len);
  if (rq->authority)
    p += hp_enc_ifield(&c->enc, p, (const uint8_t *)":authority", 10, rq->authority, rq->authority_len, 0);
  if (rq->path) p = h2__pseudo(p, 4, 5, ":path", rq->path, rq->path_len);
  for (int i = 0; i < rq->nfields; i++) {
    const hp_field *f = &rq->fields[i];
    p += hp_enc_ifield(&c->enc, p, f->name, f->nlen, f->value, f->vlen, f->never);
  }
  (void)e;
  int headers_end = end && !body;
  int r = h2__stage_block(c, sid, blk, (size_t)(p - blk), headers_end ? H2_FL_END_STREAM : 0);
  if (r) return r;
  memset(s, 0, offsetof(h2_stream, trailer));
  s->id = sid, s->state = H2S_ACTIVE, s->flags = H2_ST_RESPONDED, s->urgency = H_URGENCY_DEFAULT; /* headers out */
  s->send_win = (int32_t)c->peer_initial_window, s->content_length = -1;
  if (h_eq(rq->method, rq->method_len, "HEAD")) s->cflags |= H2_CS_HEAD;
  c->nactive++, c->last_sid = sid, c->next_sid += 2;
  if (headers_end) h2__end(c, s, H2_ST_LOCAL_END);
  else {
    s->body = body ? body : (const uint8_t *)"", s->body_len = len, s->body_off = 0;
    if (end) s->flags |= H2_ST_BODY_END;
    h2__enqueue(c, s);
  }
  return (int)sid;
}
/* client: change a request's priority (RFC 9218 PRIORITY_UPDATE); 0, or H2_E_STATE / H2_E_AGAIN */
static inline int h2_priority_update(h2_conn *c, uint32_t sid, int urgency, int incremental) {
  if (!c->client || c->closed || !(sid & 1)) return H2_E_STATE;
  uint8_t pl[12];
  h2__put32(pl, sid);
  size_t n = 4 + h_priority_value((char *)pl + 4, urgency, incremental);
  if (!h2__stage_room(c, 9 + n)) return H2_E_AGAIN;
  h2__ctrl(c, 0x10, 0, 0, pl, (uint32_t)n);
  return 0;
}
static inline int h2_data(h2_conn *c, uint32_t sid, const uint8_t *body, size_t len, int end) {
  h2_stream *s = h2__find(c, sid);
  if (!s || !(s->flags & H2_ST_RESPONDED) || (s->body && s->body_off < s->body_len) ||
      (s->flags & (H2_ST_BODY_END | H2_ST_TRAILERS)))
    return H2_E_STATE;
  s->body = body, s->body_len = len, s->body_off = 0;
  if (end) s->flags |= H2_ST_BODY_END;
  h2__enqueue(c, s);
  return 0;
}
static inline int h2_trailers(h2_conn *c, uint32_t sid, const hp_field *f, int n) {
  h2_stream *s = h2__find(c, sid);
  if (!s || !(s->flags & H2_ST_RESPONDED) || (s->flags & (H2_ST_BODY_END | H2_ST_TRAILERS))) return H2_E_STATE;
  size_t bl = h2__enc_block(c, s->trailer, sizeof s->trailer, 0, 0, f, n);
  if (!bl) return H2_E_TOO_BIG;
  s->trailer_len = (uint16_t)bl, s->flags |= H2_ST_TRAILERS;
  if (!s->body) s->body = (const uint8_t *)"", s->body_len = s->body_off = 0;
  h2__enqueue(c, s);
  return 0;
}

static inline int h2_want_write(const h2_conn *c) {
  return c->stage_len > c->stage_off || (c->qn && c->conn_send_win > 0);
}
static inline int h2_is_closed(const h2_conn *c) { return c->closed && c->stage_len == c->stage_off; }

/* finish the local side of a stream whose body (and trailers) are out */
static inline void h2__local_end(h2_conn *c, h2_stream *s) {
  s->body = NULL;
  h2__end(c, s, H2_ST_LOCAL_END);
}

static inline size_t h2_send(h2_conn *c, uint8_t *out, size_t cap) {
  size_t w = 0;
  /* control frames and HEADERS first, in order */
  size_t pend = c->stage_len - c->stage_off;
  if (pend) {
    size_t m = pend < cap ? pend : cap;
    memcpy(out, c->stage + c->stage_off, m);
    c->stage_off += m, w += m;
    if (c->stage_off == c->stage_len) c->stage_off = c->stage_len = 0;
    if (m < pend) return w;
  }
  if (c->closed) return w;
  /* DATA from the send queue, round-robin, within the flow-control windows: each stream gets one
   * frame per turn and goes to the back while it has more */
  for (uint32_t idle = 0; c->qn && idle < c->qn && w + 9 < cap;) {
    /* the most urgent queued stream to the head (RFC 9218 §10): lowest urgency; at the same urgency the
     * non-incremental in stream order, one at a time, then the incremental round-robin (ring order). idle > 0
     * means the head was blocked: then plain ring order, so every stream gets its turn to be found blocked */
    if (!idle && c->qn > 1) {
      uint32_t best = 0;
      uint64_t bk = UINT64_MAX;
      for (uint32_t k = 0; k < c->qn; k++) {
        const h2_stream *t = &c->s[c->q[(c->qh + k) % H2_MAX_STREAMS]];
        uint64_t key = (uint64_t)t->urgency << 40 | (uint64_t)t->incremental << 39 | (t->incremental ? k : t->id);
        if (key < bk) bk = key, best = k;
      }
      uint32_t hi = c->qh, bi = (c->qh + best) % H2_MAX_STREAMS;
      uint16_t tmp = c->q[hi];
      c->q[hi] = c->q[bi], c->q[bi] = tmp;
    }
    h2_stream *s = &c->s[c->q[c->qh]];
    c->qh = (c->qh + 1) % H2_MAX_STREAMS, c->qn--;
    s->flags &= (uint8_t)~H2_ST_QUEUED;
    if (s->state == H2S_FREE || !s->body || (s->flags & H2_ST_LOCAL_END)) continue; /* gone or done */
    size_t left = s->body_len - s->body_off;
    int fin_flag = (s->flags & H2_ST_BODY_END) != 0, trl = (s->flags & H2_ST_TRAILERS) != 0;
    if (!left && !fin_flag && !trl) continue; /* waiting for h2_data, which queues it again */
    size_t m = left;
    if (m > c->peer_max_frame) m = c->peer_max_frame;
    if ((int64_t)m > s->send_win) m = s->send_win > 0 ? (size_t)s->send_win : 0;
    if ((int64_t)m > c->conn_send_win) m = c->conn_send_win > 0 ? (size_t)c->conn_send_win : 0;
    if (m > cap - w - 9) m = cap - w - 9;
    /* blocked by flow control or space */
    if (!m && left) {
      h2__enqueue(c, s), idle++;
      continue;
    }
    idle = 0;
    int last = m == left;
    uint8_t fl = last && fin_flag && !trl ? H2_FL_END_STREAM : 0;
    if (m || fl) {
      h2__hdr(out + w, (uint32_t)m, H2F_DATA, fl, s->id);
      memcpy(out + w + 9, s->body + s->body_off, m);
      w += 9 + m, s->body_off += m, s->send_win -= (int32_t)m, c->conn_send_win -= (int64_t)m;
    }
    if (!last) {
      h2__enqueue(c, s);
      continue;
    }
    if (trl) {
      if (w + 9 + s->trailer_len > cap) {
        h2__enqueue(c, s), idle++;
        continue;
      }
      h2__hdr(out + w, s->trailer_len, H2F_HEADERS, H2_FL_END_HEADERS | H2_FL_END_STREAM, s->id);
      memcpy(out + w + 9, s->trailer, s->trailer_len);
      w += 9 + s->trailer_len;
      h2__local_end(c, s);
    } else if (fin_flag) {
      h2__local_end(c, s);
    } else {
      s->body = NULL, s->body_len = s->body_off = 0;
      if (c->cb.on_sent) c->cb.on_sent(c, s->id, c->user);
    }
  }
  return w;
}
#endif
