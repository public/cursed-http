/* qpack.h: QPACK (RFC 9204) for an HTTP/3 server. Header-only; never allocates.
 *
 * Decoder: a real dynamic table (same one-block layout and validate-once verdicts as hpack.h).
 *   qp_dec_init(&d, max_capacity)          max_capacity = SETTINGS_QPACK_MAX_TABLE_CAPACITY we
 *                                          advertise (<= QP_TABLE_MAX). We advertise
 *                                          SETTINGS_QPACK_BLOCKED_STREAMS = 0, so a field section
 *                                          that needs entries not yet received is an error.
 *   r = qp_dec_encoder(&d, buf, len)       bytes of the peer's encoder stream consumed (complete
 *                                          instructions only; keep the tail), or QP_E_ENCODER
 *   n = qp_decode_section(&d, stream_id, in, len, f, maxf, arena, cap, max_list, &flags)
 *                                          one field section (a HEADERS frame payload): like
 *                                          hp_decode_block; QP_E_DECOMPRESSION on any error
 *   qp_dec_cancel(&d, stream_id)           the request stream was reset before its section
 *   n = qp_dec_feedback(&d, out, cap)      decoder-stream bytes to send (Insert Count Increment,
 *                                          Section Acknowledgment, Stream Cancellation)
 * Fields are hp_field (hpack.h); sidx holds the *HPACK* static index of the name, so hreq.h's
 * checks work unchanged for both protocols.
 *
 * Encoder (responses): no dynamic table (Required Insert Count 0): static references and literals,
 * Huffman-coded when shorter. qp_enc_prefix + qp_enc_status + qp_enc_field.
 */
#ifndef QPACK_H
#define QPACK_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "hpack.h"

#ifndef QP_TABLE_MAX
#define QP_TABLE_MAX 4096
#endif
#define QP_ENT_MAX (QP_TABLE_MAX / 32)
enum { QP_E_DECOMPRESSION = -1, QP_E_CALM = -2, QP_E_ENCODER = -3, QP_E_TRUNC = -4 /* internal: need more bytes */ };

typedef struct {
  const char *n, *v;
  uint8_t nl, vl, hsidx;
} qp_sent;
#define QPS(n, v, h)                                                                                                   \
  { n, v, sizeof(n) - 1, sizeof(v) - 1, h }
static const qp_sent qp_static[99] = {
  QPS(":authority", "", 1),                                                                   /* 0 */
  QPS(":path", "/", 4),                                                                       /* 1 */
  QPS("age", "0", 21),                                                                        /* 2 */
  QPS("content-disposition", "", 25),                                                         /* 3 */
  QPS("content-length", "0", 28),                                                             /* 4 */
  QPS("cookie", "", 32),                                                                      /* 5 */
  QPS("date", "", 33),                                                                        /* 6 */
  QPS("etag", "", 34),                                                                        /* 7 */
  QPS("if-modified-since", "", 40),                                                           /* 8 */
  QPS("if-none-match", "", 41),                                                               /* 9 */
  QPS("last-modified", "", 44),                                                               /* 10 */
  QPS("link", "", 45),                                                                        /* 11 */
  QPS("location", "", 46),                                                                    /* 12 */
  QPS("referer", "", 51),                                                                     /* 13 */
  QPS("set-cookie", "", 55),                                                                  /* 14 */
  QPS(":method", "CONNECT", 2),                                                               /* 15 */
  QPS(":method", "DELETE", 2),                                                                /* 16 */
  QPS(":method", "GET", 2),                                                                   /* 17 */
  QPS(":method", "HEAD", 2),                                                                  /* 18 */
  QPS(":method", "OPTIONS", 2),                                                               /* 19 */
  QPS(":method", "POST", 2),                                                                  /* 20 */
  QPS(":method", "PUT", 2),                                                                   /* 21 */
  QPS(":scheme", "http", 6),                                                                  /* 22 */
  QPS(":scheme", "https", 6),                                                                 /* 23 */
  QPS(":status", "103", 8),                                                                   /* 24 */
  QPS(":status", "200", 8),                                                                   /* 25 */
  QPS(":status", "304", 8),                                                                   /* 26 */
  QPS(":status", "404", 8),                                                                   /* 27 */
  QPS(":status", "503", 8),                                                                   /* 28 */
  QPS("accept", "*/*", 19),                                                                   /* 29 */
  QPS("accept", "application/dns-message", 19),                                               /* 30 */
  QPS("accept-encoding", "gzip, deflate, br", 16),                                            /* 31 */
  QPS("accept-ranges", "bytes", 18),                                                          /* 32 */
  QPS("access-control-allow-headers", "cache-control", 0),                                    /* 33 */
  QPS("access-control-allow-headers", "content-type", 0),                                     /* 34 */
  QPS("access-control-allow-origin", "*", 20),                                                /* 35 */
  QPS("cache-control", "max-age=0", 24),                                                      /* 36 */
  QPS("cache-control", "max-age=2592000", 24),                                                /* 37 */
  QPS("cache-control", "max-age=604800", 24),                                                 /* 38 */
  QPS("cache-control", "no-cache", 24),                                                       /* 39 */
  QPS("cache-control", "no-store", 24),                                                       /* 40 */
  QPS("cache-control", "public, max-age=31536000", 24),                                       /* 41 */
  QPS("content-encoding", "br", 26),                                                          /* 42 */
  QPS("content-encoding", "gzip", 26),                                                        /* 43 */
  QPS("content-type", "application/dns-message", 31),                                         /* 44 */
  QPS("content-type", "application/javascript", 31),                                          /* 45 */
  QPS("content-type", "application/json", 31),                                                /* 46 */
  QPS("content-type", "application/x-www-form-urlencoded", 31),                               /* 47 */
  QPS("content-type", "image/gif", 31),                                                       /* 48 */
  QPS("content-type", "image/jpeg", 31),                                                      /* 49 */
  QPS("content-type", "image/png", 31),                                                       /* 50 */
  QPS("content-type", "text/css", 31),                                                        /* 51 */
  QPS("content-type", "text/html; charset=utf-8", 31),                                        /* 52 */
  QPS("content-type", "text/plain", 31),                                                      /* 53 */
  QPS("content-type", "text/plain;charset=utf-8", 31),                                        /* 54 */
  QPS("range", "bytes=0-", 50),                                                               /* 55 */
  QPS("strict-transport-security", "max-age=31536000", 56),                                   /* 56 */
  QPS("strict-transport-security", "max-age=31536000; includesubdomains", 56),                /* 57 */
  QPS("strict-transport-security", "max-age=31536000; includesubdomains; preload", 56),       /* 58 */
  QPS("vary", "accept-encoding", 59),                                                         /* 59 */
  QPS("vary", "origin", 59),                                                                  /* 60 */
  QPS("x-content-type-options", "nosniff", 0),                                                /* 61 */
  QPS("x-xss-protection", "1; mode=block", 0),                                                /* 62 */
  QPS(":status", "100", 8),                                                                   /* 63 */
  QPS(":status", "204", 8),                                                                   /* 64 */
  QPS(":status", "206", 8),                                                                   /* 65 */
  QPS(":status", "302", 8),                                                                   /* 66 */
  QPS(":status", "400", 8),                                                                   /* 67 */
  QPS(":status", "403", 8),                                                                   /* 68 */
  QPS(":status", "421", 8),                                                                   /* 69 */
  QPS(":status", "425", 8),                                                                   /* 70 */
  QPS(":status", "500", 8),                                                                   /* 71 */
  QPS("accept-language", "", 17),                                                             /* 72 */
  QPS("access-control-allow-credentials", "FALSE", 0),                                        /* 73 */
  QPS("access-control-allow-credentials", "TRUE", 0),                                         /* 74 */
  QPS("access-control-allow-headers", "*", 0),                                                /* 75 */
  QPS("access-control-allow-methods", "get", 0),                                              /* 76 */
  QPS("access-control-allow-methods", "get, post, options", 0),                               /* 77 */
  QPS("access-control-allow-methods", "options", 0),                                          /* 78 */
  QPS("access-control-expose-headers", "content-length", 0),                                  /* 79 */
  QPS("access-control-request-headers", "content-type", 0),                                   /* 80 */
  QPS("access-control-request-method", "get", 0),                                             /* 81 */
  QPS("access-control-request-method", "post", 0),                                            /* 82 */
  QPS("alt-svc", "clear", 0),                                                                 /* 83 */
  QPS("authorization", "", 23),                                                               /* 84 */
  QPS("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'", 0), /* 85 */
  QPS("early-data", "1", 0),                                                                  /* 86 */
  QPS("expect-ct", "", 0),                                                                    /* 87 */
  QPS("forwarded", "", 0),                                                                    /* 88 */
  QPS("if-range", "", 42),                                                                    /* 89 */
  QPS("origin", "", 0),                                                                       /* 90 */
  QPS("purpose", "prefetch", 0),                                                              /* 91 */
  QPS("server", "", 54),                                                                      /* 92 */
  QPS("timing-allow-origin", "*", 0),                                                         /* 93 */
  QPS("upgrade-insecure-requests", "1", 0),                                                   /* 94 */
  QPS("user-agent", "", 58),                                                                  /* 95 */
  QPS("x-forwarded-for", "", 0),                                                              /* 96 */
  QPS("x-frame-options", "deny", 0),                                                          /* 97 */
  QPS("x-frame-options", "sameorigin", 0),                                                    /* 98 */
};
#undef QPS

typedef struct {
  uint32_t off, nlen, vlen;
  uint8_t sidx, nclass, vok, pad;
} qp_ent;

typedef struct {
  uint32_t max_cap; /* advertised SETTINGS_QPACK_MAX_TABLE_CAPACITY */
  uint32_t cap;     /* set by the peer's encoder (Set Dynamic Table Capacity) */
  uint32_t size;
  uint64_t inserted; /* Insert Count: absolute index of the next entry */
  uint64_t known;    /* Insert Count the peer has been told about */
  uint32_t first, n; /* ring of the n newest entries; absolute index of ent[first] = inserted - n */
  uint32_t used;
  uint32_t fb_len;
  uint8_t fb[256]; /* pending decoder-stream bytes */
  qp_ent ent[QP_ENT_MAX];
  uint8_t store[2 * QP_TABLE_MAX];
} qp_dec;

static inline void qp_dec_init(qp_dec *d, uint32_t max_cap) {
  memset(d, 0, offsetof(qp_dec, ent));
  d->max_cap = max_cap < QP_TABLE_MAX ? max_cap : QP_TABLE_MAX;
}

/* QPACK integers are HPACK integers (RFC 9204 §4.1.1), but 62-bit; we cap them at 2^32 */
#define qp__int hp__int
static inline uint8_t *qp__put_int(uint8_t *p, uint8_t first, int nbits, uint64_t v) {
  return hp__put_int(p, first, nbits, (uint32_t)v);
}

static inline void qp__feedback(qp_dec *d, uint8_t first, int nbits, uint64_t v) {
  if (d->fb_len + 12 > sizeof d->fb) return; /* the caller is not draining; nothing safe to drop... */
  d->fb_len = (uint32_t)(qp__put_int(d->fb + d->fb_len, first, nbits, v) - d->fb);
}
static inline size_t qp_dec_feedback(qp_dec *d, uint8_t *out, size_t cap) {
  if (d->inserted > d->known) { /* Insert Count Increment (§4.4.3) */
    qp__feedback(d, 0x00, 6, d->inserted - d->known);
    d->known = d->inserted;
  }
  size_t m = d->fb_len < cap ? d->fb_len : cap;
  memcpy(out, d->fb, m);
  memmove(d->fb, d->fb + m, d->fb_len - m), d->fb_len -= (uint32_t)m;
  return m;
}

static inline void qp__evict(qp_dec *d, uint32_t want) {
  while (d->n && d->size + want > d->cap) {
    qp_ent *e = &d->ent[d->first];
    d->size -= e->nlen + e->vlen + 32;
    d->first = (d->first + 1) % QP_ENT_MAX, d->n--;
  }
}
static inline int qp__insert(qp_dec *d, const uint8_t *name, uint32_t nl, const uint8_t *val, uint32_t vl, uint8_t sidx,
                             uint8_t nclass, uint8_t vok) {
  uint32_t sz = nl + vl + 32;
  if (sz > d->cap) return QP_E_ENCODER; /* §3.2.2: an entry larger than the capacity is an error */
  qp__evict(d, sz);
  if (d->used + nl + vl > sizeof d->store) {
    uint32_t w = 0;
    for (uint32_t k = 0; k < d->n; k++) {
      qp_ent *e = &d->ent[(d->first + k) % QP_ENT_MAX];
      memmove(d->store + w, d->store + e->off, e->nlen + e->vlen);
      e->off = w, w += e->nlen + e->vlen;
    }
    d->used = w;
  }
  qp_ent *e = &d->ent[(d->first + d->n) % QP_ENT_MAX];
  e->off = d->used, e->nlen = nl, e->vlen = vl, e->sidx = sidx, e->nclass = nclass, e->vok = vok;
  memcpy(d->store + d->used, name, nl);
  memcpy(d->store + d->used + nl, val, vl);
  d->used += nl + vl, d->size += sz, d->n++, d->inserted++;
  return 0;
}
/* entry by absolute index, or NULL if never inserted or evicted */
static inline const qp_ent *qp__abs(const qp_dec *d, uint64_t abs) {
  if (abs >= d->inserted || abs < d->inserted - d->n) return NULL;
  return &d->ent[(d->first + (uint32_t)(abs - (d->inserted - d->n))) % QP_ENT_MAX];
}

/* string with an N-bit length prefix whose H bit is 1 << nbits (§4.1.2) */
/* integer that may be cut off: QP_E_TRUNC if more bytes could complete it, error if it is too long */
static inline int qp__int2(const uint8_t **pp, const uint8_t *end, int nbits, uint32_t *v, int err) {
  if (*pp >= end) return QP_E_TRUNC;
  if (!qp__int(pp, end, nbits, v)) return 0;
  return end - *pp >= 6 ? err : QP_E_TRUNC; /* 2^32 fits in 1 + 5 bytes */
}
static inline int qp__str(const uint8_t **pp, const uint8_t *end, int nbits, hp__arena *ar, const uint8_t **s,
                          uint32_t *sl) {
  if (*pp >= end) return QP_E_TRUNC;
  int huff = **pp & (1 << nbits), r;
  uint32_t len;
  if ((r = qp__int2(pp, end, nbits, &len, QP_E_DECOMPRESSION))) return r;
  if ((uint32_t)(end - *pp) < len) return QP_E_TRUNC;
  const uint8_t *src = *pp;
  *pp += len;
  if (!huff) {
    *s = src, *sl = len, ar->fl = HH_F_VALUE | HH_F_NAME;
    return 0;
  }
  size_t need = (size_t)len * 8 / 5 + 8;
  if (ar->cap - ar->used < need) return QP_E_CALM;
  ssize_t dl = hh_decode_f(ar->a + ar->used, src, len, &ar->fl);
  if (dl < 0) return QP_E_DECOMPRESSION;
  *s = ar->a + ar->used, *sl = (uint32_t)dl, ar->used += (size_t)dl;
  return 0;
}

static inline void qp__static(int idx, hp_field *f) {
  const qp_sent *e = &qp_static[idx];
  f->name = (const uint8_t *)e->n, f->nlen = e->nl, f->value = (const uint8_t *)e->v, f->vlen = e->vl;
  f->sidx = e->hsidx, f->nclass = e->n[0] == ':' ? HP_N_PSEUDO : HP_N_OK, f->vok = 1;
}
static inline void qp__dyn(const qp_dec *d, const qp_ent *e, hp_field *f) {
  f->name = d->store + e->off, f->nlen = e->nlen, f->value = d->store + e->off + e->nlen, f->vlen = e->vlen;
  f->sidx = e->sidx, f->nclass = e->nclass, f->vok = e->vok;
}
static inline uint8_t qp__nclass(const uint8_t *p, uint32_t n) { return hp__nclass(p, n); }

/* ------------------------------------- encoder stream ------------------------------------- */
/* one instruction at p; returns bytes used, 0 if incomplete, or QP_E_ENCODER */
static inline int qp__enc_instr(qp_dec *d, const uint8_t *p0, const uint8_t *end) {
  const uint8_t *p = p0;
  uint8_t b = *p;
  uint32_t v;
  uint8_t scratch[2 * QP_TABLE_MAX];
  hp__arena ar = { scratch, 0, sizeof scratch, 0 };
  hp_field f = { 0 };
  int r;
#define QP_NEED(x)                                                                                                     \
  do {                                                                                                                 \
    int r_ = (x);                                                                                                      \
    if (r_ == QP_E_TRUNC) return 0;                                                                                    \
    if (r_) return QP_E_ENCODER;                                                                                       \
  } while (0)
  if (b & 0x80) { /* Insert With Name Reference: 1 T idx(6) value */
    QP_NEED(qp__int2(&p, end, 6, &v, QP_E_ENCODER));
    if (b & 0x40) {
      if (v >= 99) return QP_E_ENCODER;
      qp__static((int)v, &f);
    } else {
      if (v >= d->inserted) return QP_E_ENCODER;
      const qp_ent *e = qp__abs(d, d->inserted - 1 - v);
      if (!e) return QP_E_ENCODER;
      qp__dyn(d, e, &f);
      /* the name lives in the store, which the insert may compact: copy it out */
      memcpy(scratch, f.name, f.nlen), f.name = scratch, ar.used = f.nlen;
    }
    QP_NEED(qp__str(&p, end, 7, &ar, &f.value, &f.vlen));
  } else if (b & 0x40) { /* Insert With Literal Name: 01 H len(5) name, value */
    QP_NEED(qp__str(&p, end, 5, &ar, &f.name, &f.nlen));
    f.nclass = hp__nclass_f(f.name, f.nlen, ar.fl), f.sidx = (uint8_t)hp_name_index(f.name, f.nlen);
    QP_NEED(qp__str(&p, end, 7, &ar, &f.value, &f.vlen));
  } else if (b & 0x20) { /* Set Dynamic Table Capacity: 001 cap(5) */
    QP_NEED(qp__int2(&p, end, 5, &v, QP_E_ENCODER));
    if (v > d->max_cap) return QP_E_ENCODER;
    d->cap = v;
    qp__evict(d, 0);
    return (int)(p - p0);
  } else { /* Duplicate: 000 idx(5) */
    QP_NEED(qp__int2(&p, end, 5, &v, QP_E_ENCODER));
    if (v >= d->inserted) return QP_E_ENCODER;
    const qp_ent *e = qp__abs(d, d->inserted - 1 - v);
    if (!e) return QP_E_ENCODER;
    qp__dyn(d, e, &f);
    memcpy(scratch, f.name, f.nlen + f.vlen); /* name and value are adjacent in the store */
    f.name = scratch, f.value = scratch + f.nlen;
    if ((r = qp__insert(d, f.name, f.nlen, f.value, f.vlen, f.sidx, f.nclass, f.vok))) return r;
    return (int)(p - p0);
  }
  f.vok = (uint8_t)hp__vok(f.value, f.vlen, ar.fl);
  if ((r = qp__insert(d, f.name, f.nlen, f.value, f.vlen, f.sidx, f.nclass, f.vok))) return r;
  return (int)(p - p0);
#undef QP_NEED
}
static inline int qp_dec_encoder(qp_dec *d, const uint8_t *buf, size_t len) {
  size_t used = 0;
  while (used < len) {
    int r = qp__enc_instr(d, buf + used, buf + len);
    if (r < 0) return r;
    if (r == 0) break;
    used += (size_t)r;
  }
  return (int)used;
}

/* ------------------------------------- field sections ------------------------------------- */
static inline int qp__pin(qp_dec *d, hp__arena *ar, hp_field *f) {
  int nin = f->name >= d->store && f->name < d->store + sizeof d->store;
  int vin = f->value >= d->store && f->value < d->store + sizeof d->store;
  size_t need = (nin ? f->nlen : 0) + (vin ? f->vlen : 0);
  if (ar->cap - ar->used < need) return QP_E_CALM;
  if (nin) memcpy(ar->a + ar->used, f->name, f->nlen), f->name = ar->a + ar->used, ar->used += f->nlen;
  if (vin) memcpy(ar->a + ar->used, f->value, f->vlen), f->value = ar->a + ar->used, ar->used += f->vlen;
  return 0;
}

static inline int qp_decode_section(qp_dec *d, uint64_t stream_id, const uint8_t *in, size_t len, hp_field *out,
                                    int maxf, uint8_t *arena, size_t arena_cap, uint32_t max_list, int *flags) {
  const uint8_t *p = in, *end = in + len;
  hp__arena ar = { arena, 0, arena_cap, 0 };
  uint32_t enc_ric, delta;
  *flags = 0;
  /* prefix (§4.5.1): Required Insert Count (8-bit prefix), then S + Delta Base (7-bit prefix) */
  if (p >= end || qp__int(&p, end, 8, &enc_ric) || p >= end) return QP_E_DECOMPRESSION;
  int sign = *p & 0x80;
  if (qp__int(&p, end, 7, &delta)) return QP_E_DECOMPRESSION;
  uint64_t ric = 0, max_entries = d->max_cap / 32, full = 2 * max_entries;
  if (enc_ric) {
    if (enc_ric > full) return QP_E_DECOMPRESSION;
    uint64_t maxv = d->inserted + max_entries, wrapped = maxv / full * full;
    ric = wrapped + enc_ric - 1;
    if (ric > maxv) {
      if (ric <= full) return QP_E_DECOMPRESSION;
      ric -= full;
    }
    if (ric == 0) return QP_E_DECOMPRESSION;
  }
  if (ric > d->inserted) return QP_E_DECOMPRESSION; /* would block: we allow 0 blocked streams */
  uint64_t base;
  if (!sign) base = ric + delta;
  else {
    if (delta >= ric) return QP_E_DECOMPRESSION;
    base = ric - delta - 1;
  }
  uint64_t list = 0;
  int n = 0;
  while (p < end) {
    uint8_t b = *p;
    hp_field f = { 0 };
    uint32_t v;
    int r;
    if (b & 0x80) { /* Indexed Field Line: 1 T idx(6) */
      if (qp__int(&p, end, 6, &v)) return QP_E_DECOMPRESSION;
      if (b & 0x40) {
        if (v >= 99) return QP_E_DECOMPRESSION;
        qp__static((int)v, &f);
      } else {
        if (v >= base) return QP_E_DECOMPRESSION;
        const qp_ent *e = base - 1 - v < ric ? qp__abs(d, base - 1 - v) : NULL;
        if (!e) return QP_E_DECOMPRESSION;
        qp__dyn(d, e, &f);
      }
    } else if ((b & 0xf0) == 0x10) { /* Indexed Field Line With Post-Base Index: 0001 idx(4) */
      if (qp__int(&p, end, 4, &v)) return QP_E_DECOMPRESSION;
      const qp_ent *e = base + v < ric ? qp__abs(d, base + v) : NULL;
      if (!e) return QP_E_DECOMPRESSION;
      qp__dyn(d, e, &f);
    } else if (b & 0x40) { /* Literal With Name Reference: 01 N T idx(4) */
      f.never = (b & 0x20) != 0;
      if (qp__int(&p, end, 4, &v)) return QP_E_DECOMPRESSION;
      if (b & 0x10) {
        if (v >= 99) return QP_E_DECOMPRESSION;
        qp__static((int)v, &f);
      } else {
        if (v >= base) return QP_E_DECOMPRESSION;
        const qp_ent *e = base - 1 - v < ric ? qp__abs(d, base - 1 - v) : NULL;
        if (!e) return QP_E_DECOMPRESSION;
        qp__dyn(d, e, &f);
      }
      if ((r = qp__str(&p, end, 7, &ar, &f.value, &f.vlen))) return r == QP_E_CALM ? r : QP_E_DECOMPRESSION;
      f.vok = (uint8_t)hp__vok(f.value, f.vlen, ar.fl);
    } else if (b & 0x20) { /* Literal With Literal Name: 001 N H len(3) */
      f.never = (b & 0x10) != 0;
      if ((r = qp__str(&p, end, 3, &ar, &f.name, &f.nlen))) return r == QP_E_CALM ? r : QP_E_DECOMPRESSION;
      f.nclass = hp__nclass_f(f.name, f.nlen, ar.fl), f.sidx = (uint8_t)hp_name_index(f.name, f.nlen);
      if ((r = qp__str(&p, end, 7, &ar, &f.value, &f.vlen))) return r == QP_E_CALM ? r : QP_E_DECOMPRESSION;
      f.vok = (uint8_t)hp__vok(f.value, f.vlen, ar.fl);
    } else { /* Literal With Post-Base Name Reference: 0000 N idx(3) */
      f.never = (b & 0x08) != 0;
      if (qp__int(&p, end, 3, &v)) return QP_E_DECOMPRESSION;
      const qp_ent *e = base + v < ric ? qp__abs(d, base + v) : NULL;
      if (!e) return QP_E_DECOMPRESSION;
      qp__dyn(d, e, &f);
      if ((r = qp__str(&p, end, 7, &ar, &f.value, &f.vlen))) return r == QP_E_CALM ? r : QP_E_DECOMPRESSION;
      f.vok = (uint8_t)hp__vok(f.value, f.vlen, ar.fl);
    }
    if (qp__pin(d, &ar, &f)) return QP_E_CALM;
    list += (uint64_t)f.nlen + f.vlen + 32;
    if (list > max_list) *flags |= HP_F_LIST_TOO_BIG;
    if (n >= maxf) return QP_E_CALM;
    out[n++] = f;
  }
  if (ric) {
    qp__feedback(d, 0x80, 7, stream_id); /* Section Acknowledgment (§4.4.1) */
    if (ric > d->known) d->known = ric;  /* it acknowledges the inserts it needed */
  }
  return n;
}
static inline void qp_dec_cancel(qp_dec *d, uint64_t stream_id) {
  if (d->max_cap) qp__feedback(d, 0x40, 6, stream_id); /* Stream Cancellation (§4.4.2) */
}

/* ----------------------------------------- encoder ----------------------------------------- */
/* string with an N-bit prefix (H bit = 1 << nbits): Huffman when strictly shorter */
static inline size_t qp__int_len(int nbits, uint64_t v) {
  uint64_t m = (1u << nbits) - 1;
  size_t k = 1;
  if (v >= m)
    for (v -= m, k = 2; v >= 128; v >>= 7) k++;
  return k;
}
/* one pass: Huffman-code it in place after room for the raw length's prefix (the shorter code's is no longer),
 * moving it down a byte or so if its own prefix is shorter; raw when Huffman is not strictly shorter. Writes up
 * to n + 3 bytes past the prefix */
static inline uint8_t *qp__put_str(uint8_t *p, int nbits, uint8_t first, const uint8_t *s, size_t n) {
  size_t pl = qp__int_len(nbits, n), h = n > 1 ? hh_encode_upto(p + pl, s, n, n) : SIZE_MAX;
  if (h != SIZE_MAX) {
    size_t hl = qp__int_len(nbits, h);
    if (hl < pl) memmove(p + hl, p + pl, h);
    qp__put_int(p, (uint8_t)(first | (1 << nbits)), nbits, h);
    return p + hl + h;
  }
  p = qp__put_int(p, first, nbits, n);
  memcpy(p, s, n);
  return p + n;
}
/* RIC 0, base 0 */
static inline size_t qp_enc_prefix(uint8_t *dst) {
  dst[0] = 0, dst[1] = 0;
  return 2;
}
/* the static table's names by a collision-free hash (length, first and last two bytes): each name's first
 * index, and the next index with the same name (255: none) */
static const uint8_t qp__nslot[128] = { 255, 76,  11,  255, 96,  1,   255, 86,  255, 255, 255, 255, 255, 72,  5,   97,
                                        24,  255, 79,  12,  61,  73,  93,  255, 255, 255, 255, 255, 255, 95,  255, 255,
                                        255, 42,  255, 255, 91,  80,  255, 255, 255, 2,   14,  85,  55,  255, 15,  255,
                                        22,  255, 255, 255, 255, 255, 88,  35,  0,   255, 56,  255, 255, 255, 92,  44,
                                        59,  255, 255, 255, 13,  4,   255, 62,  255, 255, 255, 81,  255, 255, 255, 255,
                                        10,  255, 255, 255, 83,  36,  255, 87,  6,   255, 255, 255, 94,  255, 90,  29,
                                        255, 255, 7,   84,  255, 255, 255, 9,   255, 255, 255, 255, 255, 32,  255, 3,
                                        89,  255, 255, 255, 31,  255, 255, 8,   255, 255, 255, 255, 255, 255, 255, 33 };
static const uint8_t qp__nnext[99] = { 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                       16,  17,  18,  19,  20,  21,  255, 23,  255, 25,  26,  27,  28,  63,  30,
                                       255, 255, 255, 34,  75,  255, 37,  38,  39,  40,  41,  255, 43,  255, 45,
                                       46,  47,  48,  49,  50,  51,  52,  53,  54,  255, 255, 57,  58,  255, 60,
                                       255, 255, 255, 64,  65,  66,  67,  68,  69,  70,  71,  255, 255, 74,  255,
                                       255, 77,  78,  255, 255, 255, 82,  255, 255, 255, 255, 255, 255, 255, 255,
                                       255, 255, 255, 255, 255, 255, 255, 98,  255 };
static inline int qp__static_find(const uint8_t *n, size_t nl, const uint8_t *v, size_t vl, int *name_only) {
  *name_only = 1;
  if (nl < 2 || nl > 64) return -1;
  int i = qp__nslot[(nl * 19 + (size_t)n[0] * 13 + (size_t)n[nl - 1] * 20 + (size_t)n[nl - 2] * 9) & 127];
  if (i == 255 || qp_static[i].nl != nl || memcmp(qp_static[i].n, n, nl)) return -1;
  for (int k = i; k != 255; k = qp__nnext[k])
    if (qp_static[k].vl == vl && !memcmp(qp_static[k].v, v, vl)) {
      *name_only = 0;
      return k;
    }
  return i;
}
static inline size_t qp_enc_field(uint8_t *dst, const uint8_t *name, size_t nl, const uint8_t *val, size_t vl,
                                  int never) {
  int name_only, i = qp__static_find(name, nl, val, vl, &name_only);
  uint8_t *p = dst;
  if (i >= 0 && !name_only && !never) return (size_t)(qp__put_int(p, 0xc0, 6, (uint32_t)i) - dst);
  if (i >= 0) p = qp__put_int(p, (uint8_t)(0x50 | (never ? 0x20 : 0)), 4, (uint32_t)i);
  else p = qp__put_str(p, 3, (uint8_t)(0x20 | (never ? 0x10 : 0)), name, nl);
  return (size_t)(qp__put_str(p, 7, 0x00, val, vl) - dst);
}
static inline size_t qp_enc_status(uint8_t *dst, int status) {
  char v[3] = { (char)('0' + status / 100 % 10), (char)('0' + status / 10 % 10), (char)('0' + status % 10) };
  return qp_enc_field(dst, (const uint8_t *)":status", 7, (const uint8_t *)v, 3, 0);
}
static inline size_t qp_enc_bound(size_t nlen, size_t vlen) { return nlen + vlen + 16; }
#endif
