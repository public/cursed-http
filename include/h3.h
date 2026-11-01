/* h3.h: an HTTP/3 server (RFC 9114) over abstract QUIC streams, sans-IO and header-only. Never
 * allocates: the caller owns the h3_conn and one h3_scratch per thread. The QUIC layer (any QUIC
 * stack) hands in stream bytes in order and pulls per-stream output.
 *
 *   h3_init(&c, &cb, user, ctrl_id, enc_id, dec_id)   ids of the three server unidirectional
 *                                                     streams the transport opened (3, 7, 11, ...)
 *   n = h3_recv(&c, &sc, stream_id, offset, buf, len, fin)
 *       bytes consumed (whole frames, except DATA payloads, which stream through); keep the tail
 *       and call again with more. offset is the stream offset of buf[0]. Returns H3_E_CLOSED once
 *       the connection has failed: close it with h3_error(&c) as the application error code.
 *   h3_peer_reset(&c, sid, code)          RESET_STREAM or STOP_SENDING arrived for a request stream
 *   n = h3_pending(&c, sids, max)         streams that have output (scans every stream)
 *   h3_stream_wants(&c, sid)              whether one stream has output (O(1) on average)
 *   n = h3_stream_send(&c, sid, out, cap, &fin)       up to cap bytes for that stream
 *
 *   h3_respond / h3_data / h3_trailers / h3_goaway    as in h2.h (zero-copy bodies)
 *
 * Requests are validated as in h2.h (hreq.h); a malformed one gets H3_MESSAGE_ERROR through the
 * reset_stream callback and is never shown to the application. QPACK: we advertise a 4096-byte
 * dynamic table and 0 blocked streams; our own encoder never uses its table.
 */
#ifndef H3_H
#define H3_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "qpack.h"
#include "hreq.h"

#ifndef H3_MAX_STREAMS
#define H3_MAX_STREAMS 100 /* concurrent request streams (the transport's MAX_STREAMS must not exceed it) */
#endif
#ifndef H3_HDR_MAX
#define H3_HDR_MAX 640 /* encoded response HEADERS frame per stream */
#endif
#ifndef H3_TRAILER_MAX
#define H3_TRAILER_MAX 128
#endif
#ifndef H3_MAX_SECTION
#define H3_MAX_SECTION 65536 /* largest HEADERS frame payload accepted */
#endif
#define H3_MAX_LIST 16384      /* SETTINGS_MAX_FIELD_SECTION_SIZE we advertise */
#define H3_QPACK_CAP 4096      /* SETTINGS_QPACK_MAX_TABLE_CAPACITY we advertise */
#define H3_MAX_FIELDS 256

enum { H3_E_CLOSED = -1, H3_E_AGAIN = -2, H3_E_STATE = -3, H3_E_TOO_BIG = -4 };
enum {
  H3_NO_ERROR = 0x100, H3_GENERAL_PROTOCOL_ERROR, H3_INTERNAL_ERROR, H3_STREAM_CREATION_ERROR, H3_CLOSED_CRITICAL_STREAM,
  H3_FRAME_UNEXPECTED, H3_FRAME_ERROR, H3_EXCESSIVE_LOAD, H3_ID_ERROR, H3_SETTINGS_ERROR, H3_MISSING_SETTINGS,
  H3_REQUEST_REJECTED, H3_REQUEST_CANCELLED, H3_REQUEST_INCOMPLETE, H3_MESSAGE_ERROR, H3_CONNECT_ERROR, H3_VERSION_FALLBACK,
  QPACK_DECOMPRESSION_FAILED = 0x200, QPACK_ENCODER_STREAM_ERROR, QPACK_DECODER_STREAM_ERROR
};
enum { H3F_DATA = 0, H3F_HEADERS = 1, H3F_CANCEL_PUSH = 3, H3F_SETTINGS = 4, H3F_PUSH_PROMISE = 5, H3F_GOAWAY = 7, H3F_MAX_PUSH_ID = 0xd };

typedef struct h3_conn h3_conn;
typedef struct {
  int (*on_request)(h3_conn *c, uint64_t sid, const h_request *rq, int end_stream, void *user);
  int (*on_data)(h3_conn *c, uint64_t sid, const uint8_t *d, size_t n, int end_stream, void *user);
  int (*on_trailers)(h3_conn *c, uint64_t sid, const hp_field *f, int n, void *user);
  void (*on_sent)(h3_conn *c, uint64_t sid, void *user);
  void (*on_close)(h3_conn *c, uint64_t sid, uint64_t error, void *user);
  /* to the transport: reset this request stream (RESET_STREAM + STOP_SENDING) with code */
  void (*reset_stream)(h3_conn *c, uint64_t sid, uint64_t code, void *user);
} h3_callbacks;

typedef struct {
  uint8_t arena[2 * H3_MAX_SECTION];
  hp_field f[H3_MAX_FIELDS];
} h3_scratch;

#define H3_ST_GOT_HEADERS 1u
#define H3_ST_GOT_TRAILERS 2u
#define H3_ST_REMOTE_END 4u
#define H3_ST_LOCAL_END 8u
#define H3_ST_RESPONDED 16u
#define H3_ST_BODY_END 32u
#define H3_ST_TRAILERS 64u

typedef struct {
  uint64_t id;
  uint8_t active, flags;
  uint64_t data_left, skip_left; /* rest of the DATA / unknown frame being received */
  int64_t content_length, data_seen;
  uint16_t hdr_len, hdr_off, trl_len, trl_off;
  const uint8_t *body;
  size_t body_len, body_off;
  uint8_t hdr[H3_HDR_MAX], trl[H3_TRAILER_MAX];
} h3_stream;

struct h3_conn {
  h3_callbacks cb;
  void *user;
  uint64_t error;                   /* connection error code once failed */
  uint64_t out_id[3];               /* control, QPACK encoder, QPACK decoder (ours) */
  uint8_t ctrl[64];                 /* our control stream: type, SETTINGS, later GOAWAY */
  uint16_t ctrl_len, ctrl_off, type_sent[2]; /* encoder / decoder stream type byte sent */
  int64_t in_id[3];                 /* the peer's control / encoder / decoder streams, -1 if none */
  uint64_t ctrl_skip;               /* rest of an unknown frame on the peer's control stream */
  uint8_t got_settings, goaway_sent;
  uint64_t max_sid;                 /* highest request stream seen + 4 (GOAWAY's id) */
  uint32_t rr;
  qp_dec qd;
  h3_stream s[H3_MAX_STREAMS];
};

static inline uint64_t h3_error(const h3_conn *c) { return c->error; }

/* QUIC varint encode */
static inline uint8_t *h3__put_vi(uint8_t *p, uint64_t v) {
  if (v < 64) { *p++ = (uint8_t)v; return p; }
  if (v < 16384) { *p++ = (uint8_t)(0x40 | v >> 8), *p++ = (uint8_t)v; return p; }
  if (v < (1u << 30)) { for (int i = 3; i >= 0; i--) p[3 - i] = (uint8_t)(v >> (8 * i)); p[0] |= 0x80; return p + 4; }
  for (int i = 7; i >= 0; i--) p[7 - i] = (uint8_t)(v >> (8 * i));
  p[0] |= 0xc0;
  return p + 8;
}

static inline int h3__fail(h3_conn *c, uint64_t code) {
  if (!c->error) c->error = code;
  return H3_E_CLOSED;
}
/* slots probed from (sid / 4) % H3_MAX_STREAMS: O(1) on average */
static inline h3_stream *h3__find(h3_conn *c, uint64_t sid) {
  for (uint32_t k = 0, i = (uint32_t)((sid >> 2) % H3_MAX_STREAMS); k < H3_MAX_STREAMS; k++, i = (i + 1) % H3_MAX_STREAMS)
    if (c->s[i].active && c->s[i].id == sid) return &c->s[i];
  return NULL;
}
static inline void h3__close(h3_conn *c, h3_stream *s, uint64_t err) {
  uint64_t id = s->id;
  s->active = 0, s->body = NULL;
  if (c->cb.on_close) c->cb.on_close(c, id, err, c->user);
}
static inline void h3__end(h3_conn *c, h3_stream *s, uint8_t which) {
  s->flags |= which;
  if ((s->flags & (H3_ST_REMOTE_END | H3_ST_LOCAL_END)) == (H3_ST_REMOTE_END | H3_ST_LOCAL_END)) h3__close(c, s, 0);
}
/* stream error: tell the transport, forget the stream */
static inline void h3__reset(h3_conn *c, h3_stream *s, uint64_t sid, uint64_t code) {
  if (c->cb.reset_stream) c->cb.reset_stream(c, sid, code, c->user);
  if (s && s->active && s->id == sid) h3__close(c, s, code);
}

static inline void h3_init(h3_conn *c, const h3_callbacks *cb, void *user, uint64_t ctrl_id, uint64_t enc_id, uint64_t dec_id) {
  memset(c, 0, offsetof(h3_conn, qd));
  c->cb = *cb, c->user = user;
  c->out_id[0] = ctrl_id, c->out_id[1] = enc_id, c->out_id[2] = dec_id;
  c->in_id[0] = c->in_id[1] = c->in_id[2] = -1;
  qp_dec_init(&c->qd, H3_QPACK_CAP);
  for (int i = 0; i < H3_MAX_STREAMS; i++) c->s[i].active = 0;
  /* control stream: type 0x00, then SETTINGS */
  uint8_t st[32], *q = st;
  q = h3__put_vi(q, 0x01), q = h3__put_vi(q, H3_QPACK_CAP); /* QPACK_MAX_TABLE_CAPACITY */
  q = h3__put_vi(q, 0x07), q = h3__put_vi(q, 0);            /* QPACK_BLOCKED_STREAMS */
  q = h3__put_vi(q, 0x06), q = h3__put_vi(q, H3_MAX_LIST);  /* MAX_FIELD_SECTION_SIZE */
  uint8_t *p = c->ctrl;
  *p++ = 0x00;
  p = h3__put_vi(p, H3F_SETTINGS), p = h3__put_vi(p, (uint64_t)(q - st));
  memcpy(p, st, (size_t)(q - st)), p += q - st;
  c->ctrl_len = (uint16_t)(p - c->ctrl);
}

/* a varint at p..end: 0 if incomplete */
static inline int h3__vi(const uint8_t *p, const uint8_t *end, uint64_t *v) {
  const uint8_t *q = qv_get_safe(v, p, end);
  return q ? (int)(q - p) : 0;
}
static inline int h3__reserved_h2(uint64_t t) { return t == 0x2 || t == 0x6 || t == 0x8 || t == 0x9; }

/* --------------------------------------- request streams --------------------------------------- */
static inline int h3__headers(h3_conn *c, h3_scratch *sc, h3_stream *s, uint64_t sid, const uint8_t *pl, size_t n, int end) {
  int hfl;
  int k = qp_decode_section(&c->qd, sid, pl, n, sc->f, H3_MAX_FIELDS / 2, sc->arena, sizeof sc->arena, H3_MAX_LIST, &hfl);
  if (k == QP_E_DECOMPRESSION) return h3__fail(c, QPACK_DECOMPRESSION_FAILED);
  if (k < 0) return h3__fail(c, H3_EXCESSIVE_LOAD);
  if (s->flags & H3_ST_GOT_HEADERS) { /* trailers */
    s->flags |= H3_ST_GOT_TRAILERS;
    for (int i = 0; i < k; i++)
      if (sc->f[i].nclass != HP_N_OK || !sc->f[i].vok) { h3__reset(c, s, sid, H3_MESSAGE_ERROR); return 0; }
    if (c->cb.on_trailers && c->cb.on_trailers(c, sid, sc->f, k, c->user) && h3__find(c, sid)) h3__reset(c, s, sid, H3_INTERNAL_ERROR);
    return 0;
  }
  s->flags |= H3_ST_GOT_HEADERS;
  h_request rq;
  if (!h_build_request(sc->f, k, &rq, sc->f + H3_MAX_FIELDS / 2) || (hfl & HP_F_LIST_TOO_BIG)) {
    h3__reset(c, s, sid, H3_MESSAGE_ERROR);
    return 0;
  }
  s->content_length = rq.content_length;
  if (end && rq.content_length > 0) { h3__reset(c, s, sid, H3_MESSAGE_ERROR); return 0; }
  if (end) s->flags |= H3_ST_REMOTE_END;
  if (c->cb.on_request && c->cb.on_request(c, sid, &rq, end, c->user) && h3__find(c, sid)) h3__reset(c, s, sid, H3_INTERNAL_ERROR);
  return 0;
}

/* the stream ended (QUIC fin) with everything consumed */
static inline int h3__req_fin(h3_conn *c, h3_stream *s, uint64_t sid) {
  if (s->data_left || s->skip_left) return h3__fail(c, H3_FRAME_ERROR); /* truncated frame */
  if (!(s->flags & H3_ST_GOT_HEADERS)) { h3__reset(c, s, sid, H3_REQUEST_INCOMPLETE); return 0; }
  if (s->flags & H3_ST_REMOTE_END) return 0;
  if (s->content_length >= 0 && s->data_seen != s->content_length) { h3__reset(c, s, sid, H3_MESSAGE_ERROR); return 0; }
  int r = 0;
  if (!(s->flags & H3_ST_GOT_TRAILERS) && c->cb.on_data) r = c->cb.on_data(c, sid, NULL, 0, 1, c->user);
  if (!(s = h3__find(c, sid))) return 0;
  if (r) { h3__reset(c, s, sid, H3_INTERNAL_ERROR); return 0; }
  h3__end(c, s, H3_ST_REMOTE_END);
  return 0;
}

static inline int h3__request_stream(h3_conn *c, h3_scratch *sc, uint64_t sid, uint64_t offset, const uint8_t *buf, size_t len, int fin) {
  h3_stream *s = h3__find(c, sid);
  if (!s) {
    /* QUIC opens streams in any order, so only the offset tells a new stream from one we already
     * finished or reset: a new one starts at 0 */
    if (offset) return (int)len;
    if (c->goaway_sent && sid >= c->max_sid) return (int)len;
    for (uint32_t k = 0, i = (uint32_t)((sid >> 2) % H3_MAX_STREAMS); k < H3_MAX_STREAMS; k++, i = (i + 1) % H3_MAX_STREAMS)
      if (!c->s[i].active) { s = &c->s[i]; break; }
    if (sid + 4 > c->max_sid) c->max_sid = sid + 4;
    if (!s) { h3__reset(c, NULL, sid, H3_REQUEST_REJECTED); return (int)len; }
    memset(s, 0, offsetof(h3_stream, hdr));
    s->id = sid, s->active = 1, s->content_length = -1;
  }
  size_t pos = 0;
  while (pos < len) {
    if (s->data_left) {
      size_t m = len - pos < s->data_left ? len - pos : (size_t)s->data_left;
      s->data_left -= m, s->data_seen += (int64_t)m, pos += m;
      if (s->content_length >= 0 && s->data_seen > s->content_length) { h3__reset(c, s, sid, H3_MESSAGE_ERROR); return (int)len; }
      int end = fin && pos == len && !s->data_left;
      if (end && s->content_length >= 0 && s->data_seen != s->content_length) { h3__reset(c, s, sid, H3_MESSAGE_ERROR); return (int)len; }
      if (c->cb.on_data && c->cb.on_data(c, sid, buf + pos - m, m, end, c->user)) {
        if (h3__find(c, sid)) h3__reset(c, s, sid, H3_INTERNAL_ERROR);
        return (int)len;
      }
      if (!h3__find(c, sid)) return (int)len;
      if (end) { h3__end(c, s, H3_ST_REMOTE_END); return (int)len; }
      continue;
    }
    if (s->skip_left) {
      size_t m = len - pos < s->skip_left ? len - pos : (size_t)s->skip_left;
      s->skip_left -= m, pos += m;
      continue;
    }
    uint64_t type, flen;
    int a = h3__vi(buf + pos, buf + len, &type), b = a ? h3__vi(buf + pos + a, buf + len, &flen) : 0;
    if (!a || !b) break; /* frame header incomplete */
    size_t hl = (size_t)a + (size_t)b;
    if (type == H3F_DATA) {
      if (!(s->flags & H3_ST_GOT_HEADERS) || (s->flags & H3_ST_GOT_TRAILERS)) return h3__fail(c, H3_FRAME_UNEXPECTED);
      pos += hl, s->data_left = flen;
      continue;
    }
    if (type == H3F_HEADERS) {
      if (s->flags & H3_ST_GOT_TRAILERS) return h3__fail(c, H3_FRAME_UNEXPECTED);
      if (flen > H3_MAX_SECTION) return h3__fail(c, H3_EXCESSIVE_LOAD);
      if (len - pos - hl < flen) break; /* wait for the whole frame */
      int end = fin && pos + hl + flen == len;
      int r = h3__headers(c, sc, s, sid, buf + pos + hl, (size_t)flen, end && !(s->flags & H3_ST_GOT_HEADERS));
      if (r < 0) return r;
      pos += hl + (size_t)flen;
      if (!(s = h3__find(c, sid))) return (int)len; /* reset */
      if (end && (s->flags & H3_ST_GOT_TRAILERS)) {
        if (s->content_length >= 0 && s->data_seen != s->content_length) { h3__reset(c, s, sid, H3_MESSAGE_ERROR); return (int)len; }
        h3__end(c, s, H3_ST_REMOTE_END);
        return (int)len;
      }
      if (end) return (int)len; /* request without a body: on_request saw end_stream */
      continue;
    }
    if (type == H3F_CANCEL_PUSH || type == H3F_SETTINGS || type == H3F_GOAWAY || type == H3F_MAX_PUSH_ID ||
        type == H3F_PUSH_PROMISE || h3__reserved_h2(type))
      return h3__fail(c, H3_FRAME_UNEXPECTED);
    pos += hl, s->skip_left = flen; /* unknown frame types are skipped (§9) */
  }
  if (fin && pos < len) return h3__fail(c, H3_FRAME_ERROR); /* the stream ends inside a frame (§7.1) */
  if (fin) {
    int r = h3__req_fin(c, s, sid);
    if (r < 0) return r;
  }
  return (int)pos;
}

/* ------------------------------------- unidirectional streams ------------------------------------- */
static inline int h3__control(h3_conn *c, const uint8_t *buf, size_t len) {
  size_t pos = 0;
  while (pos < len) {
    if (c->ctrl_skip) {
      size_t m = len - pos < c->ctrl_skip ? len - pos : (size_t)c->ctrl_skip;
      c->ctrl_skip -= m, pos += m;
      continue;
    }
    uint64_t type, flen;
    int a = h3__vi(buf + pos, buf + len, &type), b = a ? h3__vi(buf + pos + a, buf + len, &flen) : 0;
    if (!a || !b) break;
    size_t hl = (size_t)a + (size_t)b;
    if (!c->got_settings && type != H3F_SETTINGS) return h3__fail(c, H3_MISSING_SETTINGS);
    if (type == H3F_DATA || type == H3F_HEADERS || type == H3F_PUSH_PROMISE || h3__reserved_h2(type)) return h3__fail(c, H3_FRAME_UNEXPECTED);
    if (type == H3F_SETTINGS || type == H3F_GOAWAY || type == H3F_MAX_PUSH_ID || type == H3F_CANCEL_PUSH) {
      if (flen > 4096) return h3__fail(c, H3_EXCESSIVE_LOAD);
      if (len - pos - hl < flen) break;
      const uint8_t *p = buf + pos + hl, *e = p + flen;
      if (type == H3F_SETTINGS) {
        if (c->got_settings) return h3__fail(c, H3_FRAME_UNEXPECTED);
        uint64_t seen[16];
        int nseen = 0;
        while (p < e) {
          uint64_t id, v;
          int x = h3__vi(p, e, &id), y = x ? h3__vi(p + x, e, &v) : 0;
          if (!x || !y) return h3__fail(c, H3_FRAME_ERROR);
          if (id == 0x2 || id == 0x3 || id == 0x4 || id == 0x5) return h3__fail(c, H3_SETTINGS_ERROR); /* HTTP/2 settings */
          for (int k = 0; k < nseen; k++)
            if (seen[k] == id) return h3__fail(c, H3_SETTINGS_ERROR);
          if (nseen < 16) seen[nseen++] = id;
          p += x + y; /* the peer's QPACK limits only matter to our encoder, which never indexes */
        }
        c->got_settings = 1;
      } else {
        uint64_t v;
        int x = h3__vi(p, e, &v);
        if (!x || p + x != e) return h3__fail(c, H3_FRAME_ERROR);
        /* GOAWAY from the client (a push id), MAX_PUSH_ID, CANCEL_PUSH: we never push */
      }
      pos += hl + (size_t)flen;
      continue;
    }
    pos += hl, c->ctrl_skip = flen; /* unknown / reserved frame types */
  }
  return (int)pos;
}
static inline int h3__decoder_stream(h3_conn *c, const uint8_t *buf, size_t len) {
  size_t pos = 0;
  while (pos < len) { /* our encoder never inserts: only Stream Cancellation is acceptable */
    uint8_t b = buf[pos];
    const uint8_t *p = buf + pos;
    uint32_t v;
    if ((b & 0xc0) != 0x40) return h3__fail(c, QPACK_DECODER_STREAM_ERROR);
    if (qp__int(&p, buf + len, 6, &v)) break;
    pos = (size_t)(p - buf);
  }
  return (int)pos;
}

static inline int h3_recv(h3_conn *c, h3_scratch *sc, uint64_t sid, uint64_t offset, const uint8_t *buf, size_t len, int fin) {
  if (c->error) return H3_E_CLOSED;
  if ((sid & 3) == 0) return h3__request_stream(c, sc, sid, offset, buf, len, fin);
  if ((sid & 3) != 2) return h3__fail(c, H3_STREAM_CREATION_ERROR); /* server-initiated ids are ours */
  int which = sid == (uint64_t)c->in_id[0] ? 0 : sid == (uint64_t)c->in_id[1] ? 1 : sid == (uint64_t)c->in_id[2] ? 2 : -1;
  size_t pos = 0;
  if (which < 0) {
    if (offset) return (int)len; /* an unknown stream type we ignore */
    uint64_t type;
    int a = h3__vi(buf, buf + len, &type);
    if (!a) return fin ? (int)len : 0;
    pos = (size_t)a;
    if (type == 0x00 || type == 0x02 || type == 0x03) {
      which = type == 0 ? 0 : (int)type - 1;
      if (c->in_id[which] >= 0) return h3__fail(c, H3_STREAM_CREATION_ERROR);
      c->in_id[which] = (int64_t)sid;
    } else if (type == 0x01) {
      return h3__fail(c, H3_STREAM_CREATION_ERROR); /* clients cannot push */
    } else {
      return (int)len; /* unknown/grease types: read and discard (§6.2.3) */
    }
  }
  int r;
  if (which == 0) r = h3__control(c, buf + pos, len - pos);
  else if (which == 1) {
    r = qp_dec_encoder(&c->qd, buf + pos, len - pos);
    if (r < 0) return h3__fail(c, QPACK_ENCODER_STREAM_ERROR);
  } else r = h3__decoder_stream(c, buf + pos, len - pos);
  if (r < 0) return r;
  if (fin) return h3__fail(c, H3_CLOSED_CRITICAL_STREAM); /* critical streams never end */
  return (int)(pos + (size_t)r);
}

static inline void h3_peer_reset(h3_conn *c, uint64_t sid, uint64_t code) {
  h3_stream *s = h3__find(c, sid);
  if (!s) return;
  if (!(s->flags & H3_ST_GOT_HEADERS)) qp_dec_cancel(&c->qd, sid); /* §4.4.2 */
  h3__close(c, s, code ? code : H3_REQUEST_CANCELLED);
}

/* ---------------------------------------------- send ---------------------------------------------- */
static inline size_t h3__enc_frame(uint8_t *dst, size_t cap, int status, const hp_field *f, int n) {
  uint8_t blk[H3_HDR_MAX], *p = blk, *e = blk + sizeof blk;
  p += qp_enc_prefix(p);
  if (status) p += qp_enc_status(p, status);
  for (int i = 0; i < n; i++) {
    if ((size_t)(e - p) < qp_enc_bound(f[i].nlen, f[i].vlen)) return 0;
    p += qp_enc_field(p, f[i].name, f[i].nlen, f[i].value, f[i].vlen, f[i].never);
  }
  size_t bl = (size_t)(p - blk);
  uint8_t hdr[16], *q = h3__put_vi(h3__put_vi(hdr, H3F_HEADERS), bl);
  size_t hl = (size_t)(q - hdr);
  if (hl + bl > cap) return 0;
  memcpy(dst, hdr, hl), memcpy(dst + hl, blk, bl);
  return hl + bl;
}
static inline int h3_respond(h3_conn *c, uint64_t sid, int status, const hp_field *f, int n, const uint8_t *body, size_t len, int end) {
  h3_stream *s = h3__find(c, sid);
  if (!s || (s->flags & H3_ST_RESPONDED)) return H3_E_STATE;
  size_t fl = h3__enc_frame(s->hdr, sizeof s->hdr, status, f, n);
  if (!fl) return H3_E_TOO_BIG;
  s->hdr_len = (uint16_t)fl, s->hdr_off = 0, s->flags |= H3_ST_RESPONDED;
  s->body = body ? body : (const uint8_t *)"", s->body_len = body ? len : 0, s->body_off = 0;
  if (end) s->flags |= H3_ST_BODY_END;
  return 0;
}
static inline int h3_data(h3_conn *c, uint64_t sid, const uint8_t *body, size_t len, int end) {
  h3_stream *s = h3__find(c, sid);
  if (!s || !(s->flags & H3_ST_RESPONDED) || (s->body && s->body_off < s->body_len) || (s->flags & (H3_ST_BODY_END | H3_ST_TRAILERS)))
    return H3_E_STATE;
  s->body = body, s->body_len = len, s->body_off = 0;
  if (end) s->flags |= H3_ST_BODY_END;
  return 0;
}
static inline int h3_trailers(h3_conn *c, uint64_t sid, const hp_field *f, int n) {
  h3_stream *s = h3__find(c, sid);
  if (!s || !(s->flags & H3_ST_RESPONDED) || (s->flags & (H3_ST_BODY_END | H3_ST_TRAILERS))) return H3_E_STATE;
  size_t fl = h3__enc_frame(s->trl, sizeof s->trl, 0, f, n);
  if (!fl) return H3_E_TOO_BIG;
  s->trl_len = (uint16_t)fl, s->trl_off = 0, s->flags |= H3_ST_TRAILERS;
  if (!s->body) s->body = (const uint8_t *)"", s->body_len = s->body_off = 0;
  return 0;
}
static inline void h3_goaway(h3_conn *c) {
  if (c->goaway_sent || (size_t)c->ctrl_len + 10 > sizeof c->ctrl) return;
  uint8_t *p = c->ctrl + c->ctrl_len, *q = h3__put_vi(p + 2, c->max_sid);
  p[0] = H3F_GOAWAY, p[1] = (uint8_t)(q - p - 2);
  c->ctrl_len = (uint16_t)(q - c->ctrl), c->goaway_sent = 1;
}

static inline int h3__has_out(const h3_conn *c, const h3_stream *s) {
  (void)c;
  if (!s->active || !(s->flags & H3_ST_RESPONDED) || (s->flags & H3_ST_LOCAL_END)) return 0;
  if (s->hdr_off < s->hdr_len) return 1;
  if (s->body && s->body_off < s->body_len) return 1;
  return (s->flags & (H3_ST_BODY_END | H3_ST_TRAILERS)) != 0; /* the fin, or trailers, are still due */
}
/* does stream sid have output? (O(1) on average, for a transport's per-stream check) */
static inline int h3_stream_wants(h3_conn *c, uint64_t sid) {
  if (sid == c->out_id[0]) return c->ctrl_off < c->ctrl_len;
  if (sid == c->out_id[1]) return !c->type_sent[0];
  if (sid == c->out_id[2]) return !c->type_sent[1] || c->qd.fb_len || c->qd.inserted > c->qd.known;
  h3_stream *s = h3__find(c, sid);
  return s && h3__has_out(c, s);
}
static inline int h3_pending(h3_conn *c, uint64_t *sids, int max) {
  int n = 0;
  if (c->ctrl_off < c->ctrl_len && n < max) sids[n++] = c->out_id[0];
  if (!c->type_sent[0] && n < max) sids[n++] = c->out_id[1];
  if ((!c->type_sent[1] || c->qd.fb_len || c->qd.inserted > c->qd.known) && n < max) sids[n++] = c->out_id[2];
  for (int k = 0; k < H3_MAX_STREAMS && n < max; k++) {
    int i = (int)((c->rr + (uint32_t)k) % H3_MAX_STREAMS);
    if (h3__has_out(c, &c->s[i])) sids[n++] = c->s[i].id;
  }
  c->rr++;
  return n;
}
static inline size_t h3_stream_send(h3_conn *c, uint64_t sid, uint8_t *out, size_t cap, int *fin) {
  *fin = 0;
  if (sid == c->out_id[0]) {
    size_t m = (size_t)(c->ctrl_len - c->ctrl_off) < cap ? (size_t)(c->ctrl_len - c->ctrl_off) : cap;
    memcpy(out, c->ctrl + c->ctrl_off, m), c->ctrl_off = (uint16_t)(c->ctrl_off + m);
    return m;
  }
  if (sid == c->out_id[1]) {
    if (c->type_sent[0] || !cap) return 0;
    out[0] = 0x02, c->type_sent[0] = 1;
    return 1;
  }
  if (sid == c->out_id[2]) {
    size_t w = 0;
    if (!c->type_sent[1] && cap) out[w++] = 0x03, c->type_sent[1] = 1;
    return w + qp_dec_feedback(&c->qd, out + w, cap - w);
  }
  h3_stream *s = h3__find(c, sid);
  if (!s || !h3__has_out(c, s)) return 0;
  size_t w = 0;
  if (s->hdr_off < s->hdr_len) {
    size_t m = (size_t)(s->hdr_len - s->hdr_off) < cap ? (size_t)(s->hdr_len - s->hdr_off) : cap;
    memcpy(out, s->hdr + s->hdr_off, m), s->hdr_off = (uint16_t)(s->hdr_off + m), w += m;
    if (s->hdr_off < s->hdr_len) return w;
  }
  size_t left = s->body ? s->body_len - s->body_off : 0;
  if (left && cap - w > 3) { /* one DATA frame: type, length, as much body as fits */
    size_t room = cap - w - 1;
    size_t m = left, vl = m < 64 ? 1 : m < 16384 ? 2 : m < (1u << 30) ? 4 : 8;
    while (m + vl > room) { m = room > vl ? room - vl : 0; vl = m < 64 ? 1 : m < 16384 ? 2 : 4; if (!m) break; }
    if (m) {
      out[w++] = H3F_DATA;
      w = (size_t)(h3__put_vi(out + w, m) - out);
      memcpy(out + w, s->body + s->body_off, m), w += m, s->body_off += m;
    }
  }
  if (s->body && s->body_off == s->body_len) {
    if (s->flags & H3_ST_TRAILERS) {
      size_t m = (size_t)(s->trl_len - s->trl_off) < cap - w ? (size_t)(s->trl_len - s->trl_off) : cap - w;
      memcpy(out + w, s->trl + s->trl_off, m), s->trl_off = (uint16_t)(s->trl_off + m), w += m;
      if (s->trl_off == s->trl_len) { *fin = 1, s->body = NULL; h3__end(c, s, H3_ST_LOCAL_END); }
    } else if (s->flags & H3_ST_BODY_END) {
      *fin = 1, s->body = NULL;
      h3__end(c, s, H3_ST_LOCAL_END);
    } else if (s->body_len) {
      s->body = NULL, s->body_len = s->body_off = 0;
      if (c->cb.on_sent) c->cb.on_sent(c, sid, c->user);
    }
  }
  return w;
}
#endif
