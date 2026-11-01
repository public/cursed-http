/* hpack.h: HPACK (RFC 7541) for an HTTP/2 server. Header-only; never allocates.
 *
 * Decoder: a real dynamic table, kept in one block inside hp_dec (descriptors in an array, strings in
 * a byte store that is compacted when it fills, as HAProxy does). Every field is validated once,
 * when its string is first decoded, and the verdict (name class, value ok, static name index) is
 * stored with the table entry, as h2o does: indexed fields are never re-scanned.
 *
 *   hp_dec_init(&d, table_limit)                  table_limit = the SETTINGS_HEADER_TABLE_SIZE we
 *                                                 advertise (<= HP_TABLE_MAX). Below 4096 the peer's
 *                                                 next block must begin with a size update.
 *   n = hp_decode_block(&d, in, len, f, maxf, arena, arena_cap, max_list, &flags)
 *       Decodes one complete header block into f[0..n). Returns n >= 0, or HP_E_COMPRESSION (the
 *       connection must end with COMPRESSION_ERROR), or HP_E_CALM (arena or field array exhausted:
 *       end the connection with ENHANCE_YOUR_CALM; the table may be out of sync). flags gets
 *       HP_F_LIST_TOO_BIG when sum(name+value+32) > max_list (the block was still fully decoded,
 *       so the table stays in sync; answer the stream with 431).
 *       Field strings point into `in` (raw literals), the arena (Huffman or table copies) or static
 *       memory; they stay valid while `in` and the arena do.
 *
 * Encoder (responses): no dynamic table, as HAProxy: static-table references and literals without
 * indexing, Huffman-coded when shorter. hp_enc_* write at dst and return the bytes written; dst
 * needs hp_enc_bound(nlen, vlen) bytes.
 */
#ifndef HPACK_H
#define HPACK_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "hfield.h"

#ifndef HP_TABLE_MAX
#define HP_TABLE_MAX 4096
#endif
#define HP_ENT_MAX (HP_TABLE_MAX / 32)

enum { HP_E_COMPRESSION = -1, HP_E_CALM = -2 };
enum { HP_F_LIST_TOO_BIG = 1 };
/* name classes: hv_check_nonempty_name's result for regular names; pseudo names are HP_N_PSEUDO */
enum { HP_N_BAD = 0, HP_N_OK = 1, HP_N_UPPER = 2, HP_N_PSEUDO = 3 };

typedef struct {
  const uint8_t *name, *value;
  uint32_t nlen, vlen;
  uint8_t sidx;   /* static-table index of the name (1..61), 0 if not a static name */
  uint8_t nclass; /* HP_N_* */
  uint8_t vok;    /* value passes RFC 9113 §8.2.1 (no NUL/CR/LF, no leading/trailing SP/HT) */
  uint8_t never;  /* sent as never-indexed */
} hp_field;

/* ------------------------------------- static table ------------------------------------- */
typedef struct {
  const char *n, *v;
  uint8_t nl, vl;
} hp_sent;
#define HPS(n, v)                                                                                                      \
  { n, v, sizeof(n) - 1, sizeof(v) - 1 }
static const hp_sent hp_static[62] = { { 0, 0, 0, 0 },
                                       HPS(":authority", ""),
                                       HPS(":method", "GET"),
                                       HPS(":method", "POST"),
                                       HPS(":path", "/"),
                                       HPS(":path", "/index.html"),
                                       HPS(":scheme", "http"),
                                       HPS(":scheme", "https"),
                                       HPS(":status", "200"),
                                       HPS(":status", "204"),
                                       HPS(":status", "206"),
                                       HPS(":status", "304"),
                                       HPS(":status", "400"),
                                       HPS(":status", "404"),
                                       HPS(":status", "500"),
                                       HPS("accept-charset", ""),
                                       HPS("accept-encoding", "gzip, deflate"),
                                       HPS("accept-language", ""),
                                       HPS("accept-ranges", ""),
                                       HPS("accept", ""),
                                       HPS("access-control-allow-origin", ""),
                                       HPS("age", ""),
                                       HPS("allow", ""),
                                       HPS("authorization", ""),
                                       HPS("cache-control", ""),
                                       HPS("content-disposition", ""),
                                       HPS("content-encoding", ""),
                                       HPS("content-language", ""),
                                       HPS("content-length", ""),
                                       HPS("content-location", ""),
                                       HPS("content-range", ""),
                                       HPS("content-type", ""),
                                       HPS("cookie", ""),
                                       HPS("date", ""),
                                       HPS("etag", ""),
                                       HPS("expect", ""),
                                       HPS("expires", ""),
                                       HPS("from", ""),
                                       HPS("host", ""),
                                       HPS("if-match", ""),
                                       HPS("if-modified-since", ""),
                                       HPS("if-none-match", ""),
                                       HPS("if-range", ""),
                                       HPS("if-unmodified-since", ""),
                                       HPS("last-modified", ""),
                                       HPS("link", ""),
                                       HPS("location", ""),
                                       HPS("max-forwards", ""),
                                       HPS("proxy-authenticate", ""),
                                       HPS("proxy-authorization", ""),
                                       HPS("range", ""),
                                       HPS("referer", ""),
                                       HPS("refresh", ""),
                                       HPS("retry-after", ""),
                                       HPS("server", ""),
                                       HPS("set-cookie", ""),
                                       HPS("strict-transport-security", ""),
                                       HPS("transfer-encoding", ""),
                                       HPS("user-agent", ""),
                                       HPS("vary", ""),
                                       HPS("via", ""),
                                       HPS("www-authenticate", "") };
#undef HPS

/* first static index whose name is (p, n), or 0. One pass over the 61 names, filtered by length and
 * first byte; called once per literal name (dynamic entries cache the result). */
static inline int hp_name_index(const uint8_t *p, size_t n) {
  if (n == 0 || n > 27) return 0;
  for (int i = 1; i <= 61; i++)
    if (hp_static[i].nl == n && hp_static[i].n[0] == p[0] && !memcmp(hp_static[i].n, p, n)) return i;
  return 0;
}

/* --------------------------------------- decoder --------------------------------------- */
typedef struct {
  uint32_t off, nlen, vlen;
  uint8_t sidx, nclass, vok, pad;
} hp_ent;

typedef struct {
  uint32_t limit;       /* SETTINGS_HEADER_TABLE_SIZE we advertised */
  uint32_t max;         /* current maximum size (last size update) */
  uint32_t size;        /* sum of entry sizes */
  uint32_t first, n;    /* ring of descriptors: newest at (first + n - 1) % HP_ENT_MAX */
  uint32_t used;        /* append position in store */
  uint32_t need_update; /* the limit is below the protocol's initial 4096: the next block must start
                         * with a size update (RFC 7541 §4.2), or the peer's table is not ours */
  hp_ent ent[HP_ENT_MAX];
  uint8_t store[2 * HP_TABLE_MAX];
} hp_dec;

static inline void hp_dec_init(hp_dec *d, uint32_t limit) {
  memset(d, 0, offsetof(hp_dec, ent));
  d->limit = d->max = limit < HP_TABLE_MAX ? limit : HP_TABLE_MAX;
  d->need_update = d->limit < 4096;
}

static inline void hp__evict(hp_dec *d, uint32_t want) {
  while (d->n && d->size + want > d->max) {
    hp_ent *e = &d->ent[d->first];
    d->size -= e->nlen + e->vlen + 32;
    d->first = (d->first + 1) % HP_ENT_MAX, d->n--;
  }
}

/* insert (name, value) as the newest entry */
static inline void hp__insert(hp_dec *d, const uint8_t *name, uint32_t nl, const uint8_t *val, uint32_t vl,
                              uint8_t sidx, uint8_t nclass, uint8_t vok) {
  /* name and value never point into the store here (hp_decode_block pins indexed names into the
   * arena first), so evicting the entry they came from (RFC 7541 §4.4) is safe */
  uint32_t sz = nl + vl + 32;
  hp__evict(d, sz);
  if (sz > d->max) return;                   /* larger than the table: the table is now empty, nothing inserted */
  if (d->used + nl + vl > sizeof d->store) { /* compact: live strings total <= max - 32n */
    uint32_t w = 0;
    for (uint32_t k = 0; k < d->n; k++) {
      hp_ent *e = &d->ent[(d->first + k) % HP_ENT_MAX];
      memmove(d->store + w, d->store + e->off, e->nlen + e->vlen);
      e->off = w, w += e->nlen + e->vlen;
    }
    d->used = w;
  }
  hp_ent *e = &d->ent[(d->first + d->n) % HP_ENT_MAX];
  e->off = d->used, e->nlen = nl, e->vlen = vl, e->sidx = sidx, e->nclass = nclass, e->vok = vok;
  memcpy(d->store + d->used, name, nl);
  memcpy(d->store + d->used + nl, val, vl);
  d->used += nl + vl, d->size += sz, d->n++;
}

/* HPACK integer with an N-bit prefix (RFC 7541 §5.1); -1 if truncated or > 2^32 */
static inline int hp__int(const uint8_t **pp, const uint8_t *end, int nbits, uint32_t *out) {
  const uint8_t *p = *pp;
  uint32_t mask = (1u << nbits) - 1, v = *p++ & mask;
  if (v == mask) {
    uint64_t acc = v;
    for (int sh = 0;; sh += 7) {
      if (p >= end || sh > 28) return -1;
      uint8_t b = *p++;
      acc += (uint64_t)(b & 0x7f) << sh;
      if (acc > 0xffffffffu) return -1;
      if (!(b & 0x80)) break;
    }
    v = (uint32_t)acc;
  }
  *out = v, *pp = p;
  return 0;
}

static inline uint8_t hp__nclass(const uint8_t *p, uint32_t n) {
  if (n == 0) return HP_N_BAD;
  if (p[0] == ':') return hv_check_name(p, n) ? HP_N_PSEUDO : HP_N_BAD;
  return (uint8_t)hv_check_nonempty_name(p, n);
}

typedef struct {
  uint8_t *a;
  size_t used, cap;
  uint32_t fl; /* the last string's HH_F_* check bits; all set for a raw (unchecked) string */
} hp__arena;

/* the checks of a string just decoded, skipping the rescan when the Huffman table showed every
 * byte passes (then only the RFC 9113 whitespace rule is left) */
static inline int hp__vok(const uint8_t *p, uint32_t n, uint32_t fl) {
  if (fl & HH_F_VALUE) return hv_check_value_rfc9113(p, n);
  return !n || (p[0] != ' ' && p[0] != '\t' && p[n - 1] != ' ' && p[n - 1] != '\t');
}
static inline uint8_t hp__nclass_f(const uint8_t *p, uint32_t n, uint32_t fl) {
  return n && !(fl & HH_F_NAME) ? (uint8_t)HP_N_OK : hp__nclass(p, n); /* ':' is not a token byte */
}

/* string literal (§5.2): raw strings point into the input, Huffman ones are decoded into the arena */
static inline int hp__str(const uint8_t **pp, const uint8_t *end, hp__arena *ar, const uint8_t **s, uint32_t *sl) {
  if (*pp >= end) return HP_E_COMPRESSION;
  int huff = **pp & 0x80;
  uint32_t len;
  if (hp__int(pp, end, 7, &len) || (uint32_t)(end - *pp) < len) return HP_E_COMPRESSION;
  const uint8_t *src = *pp;
  *pp += len;
  if (!huff) {
    *s = src, *sl = len, ar->fl = HH_F_VALUE | HH_F_NAME;
    return 0;
  }
  size_t need = (size_t)len * 8 / 5 + 8;
  if (ar->cap - ar->used < need) return HP_E_CALM;
  ssize_t r = hh_decode_f(ar->a + ar->used, src, len, &ar->fl);
  if (r < 0) return HP_E_COMPRESSION;
  *s = ar->a + ar->used, *sl = (uint32_t)r, ar->used += (size_t)r;
  return 0;
}

static inline int hp__lookup(const hp_dec *d, uint32_t idx, hp_field *f) {
  if (idx == 0) return HP_E_COMPRESSION;
  if (idx <= 61) {
    const hp_sent *e = &hp_static[idx];
    f->name = (const uint8_t *)e->n, f->nlen = e->nl, f->value = (const uint8_t *)e->v, f->vlen = e->vl;
    f->sidx = (uint8_t)(idx == 3                ? 2
                        : idx == 5              ? 4
                        : idx == 7              ? 6
                        : idx >= 9 && idx <= 14 ? 8
                                                : idx); /* first entry with this name */
    f->nclass = e->n[0] == ':' ? HP_N_PSEUDO : HP_N_OK, f->vok = 1;
    return 0;
  }
  idx -= 62;
  if (idx >= d->n) return HP_E_COMPRESSION;
  const hp_ent *e = &d->ent[(d->first + d->n - 1 - idx) % HP_ENT_MAX];
  f->name = d->store + e->off, f->nlen = e->nlen, f->value = d->store + e->off + e->nlen, f->vlen = e->vlen;
  f->sidx = e->sidx, f->nclass = e->nclass, f->vok = e->vok;
  return 0;
}

/* copy a field whose strings live in the table store into the arena (the store moves) */
static inline int hp__pin(hp_dec *d, hp__arena *ar, hp_field *f) {
  int nin = f->name >= d->store && f->name < d->store + sizeof d->store;
  int vin = f->value >= d->store && f->value < d->store + sizeof d->store;
  size_t need = (nin ? f->nlen : 0) + (vin ? f->vlen : 0);
  if (ar->cap - ar->used < need) return HP_E_CALM;
  if (nin) memcpy(ar->a + ar->used, f->name, f->nlen), f->name = ar->a + ar->used, ar->used += f->nlen;
  if (vin) memcpy(ar->a + ar->used, f->value, f->vlen), f->value = ar->a + ar->used, ar->used += f->vlen;
  return 0;
}

static inline int hp_decode_block(hp_dec *d, const uint8_t *in, size_t len, hp_field *out, int maxf, uint8_t *arena,
                                  size_t arena_cap, uint32_t max_list, int *flags) {
  const uint8_t *p = in, *end = in + len;
  hp__arena ar = { arena, 0, arena_cap, 0 };
  uint64_t list = 0;
  int n = 0, fields_seen = 0;
  *flags = 0;
  if (d->need_update && (p >= end || (*p & 0xe0) != 0x20)) return HP_E_COMPRESSION;
  while (p < end) {
    uint8_t b = *p;
    hp_field f = { 0 };
    uint32_t idx;
    if (b & 0x80) { /* indexed */
      if (hp__int(&p, end, 7, &idx) || hp__lookup(d, idx, &f)) return HP_E_COMPRESSION;
      if (hp__pin(d, &ar, &f)) return HP_E_CALM;
    } else if ((b & 0xe0) == 0x20) { /* dynamic table size update: only before the first field */
      if (fields_seen || hp__int(&p, end, 5, &idx) || idx > d->limit) return HP_E_COMPRESSION;
      d->max = idx, d->need_update = 0;
      hp__evict(d, 0);
      continue;
    } else { /* literal: 01 incremental (6-bit), 0000 without, 0001 never (4-bit) */
      int incr = (b & 0xc0) == 0x40, nbits = incr ? 6 : 4;
      f.never = (b & 0xf0) == 0x10;
      if (hp__int(&p, end, nbits, &idx)) return HP_E_COMPRESSION;
      int r;
      if (idx) {
        hp_field nf;
        if (hp__lookup(d, idx, &nf)) return HP_E_COMPRESSION;
        f.name = nf.name, f.nlen = nf.nlen, f.sidx = nf.sidx, f.nclass = nf.nclass;
        if (hp__pin(d, &ar, &f)) return HP_E_CALM; /* the insert below may move or evict it */
      } else {
        if ((r = hp__str(&p, end, &ar, &f.name, &f.nlen))) return r;
        f.nclass = hp__nclass_f(f.name, f.nlen, ar.fl), f.sidx = (uint8_t)hp_name_index(f.name, f.nlen);
      }
      if ((r = hp__str(&p, end, &ar, &f.value, &f.vlen))) return r;
      f.vok = (uint8_t)hp__vok(f.value, f.vlen, ar.fl);
      if (incr) hp__insert(d, f.name, f.nlen, f.value, f.vlen, f.sidx, f.nclass, f.vok);
    }
    fields_seen = 1;
    list += (uint64_t)f.nlen + f.vlen + 32;
    if (list > max_list) *flags |= HP_F_LIST_TOO_BIG;
    if (n >= maxf) return HP_E_CALM;
    out[n++] = f;
  }
  return n;
}

/* --------------------------------------- encoder --------------------------------------- */
static inline size_t hp_enc_bound(size_t nlen, size_t vlen) { return nlen + vlen + 16; }

static inline uint8_t *hp__put_int(uint8_t *p, uint8_t first, int nbits, uint32_t v) {
  uint32_t mask = (1u << nbits) - 1;
  if (v < mask) {
    *p++ = (uint8_t)(first | v);
    return p;
  }
  *p++ = (uint8_t)(first | mask), v -= mask;
  while (v >= 128) *p++ = (uint8_t)(v | 0x80), v >>= 7;
  *p++ = (uint8_t)v;
  return p;
}
/* string: Huffman when strictly shorter (hh_encode_upto writes it in one pass) */
static inline uint8_t *hp__put_str(uint8_t *p, const uint8_t *s, size_t n) {
  uint8_t tmp[64];
  if (n <= sizeof tmp - 4) {
    size_t h = hh_encode_upto(tmp, s, n, n);
    if (h != SIZE_MAX) {
      p = hp__put_int(p, 0x80, 7, (uint32_t)h);
      memcpy(p, tmp, h);
      return p + h;
    }
  } else {
    size_t h = hh_encode_len(s, n);
    if (h < n) {
      p = hp__put_int(p, 0x80, 7, (uint32_t)h);
      return p + hh_encode(p, s, n);
    }
  }
  p = hp__put_int(p, 0, 7, (uint32_t)n);
  memcpy(p, s, n);
  return p + n;
}
static inline size_t hp_enc_size_update(uint8_t *dst, uint32_t size) {
  return (size_t)(hp__put_int(dst, 0x20, 5, size) - dst);
}
static inline size_t hp_enc_status(uint8_t *dst, int status) {
  static const short codes[7] = { 200, 204, 206, 304, 400, 404, 500 };
  for (int i = 0; i < 7; i++)
    if (codes[i] == status) {
      dst[0] = (uint8_t)(0x80 | (8 + i));
      return 1;
    }
  char v[3] = { (char)('0' + status / 100 % 10), (char)('0' + status / 10 % 10), (char)('0' + status % 10) };
  uint8_t *p = hp__put_int(dst, 0x00, 4, 8);
  return (size_t)(hp__put_str(p, (const uint8_t *)v, 3) - dst);
}
/* literal without indexing (or never indexed); the name is a static reference when it is one */
static inline size_t hp_enc_field(uint8_t *dst, const uint8_t *name, size_t nl, const uint8_t *val, size_t vl,
                                  int never) {
  int si = hp_name_index(name, nl);
  uint8_t *p = dst;
  if (si) p = hp__put_int(p, never ? 0x10 : 0x00, 4, (uint32_t)si);
  else *p++ = never ? 0x10 : 0x00, p = hp__put_str(p, name, nl);
  return (size_t)(hp__put_str(p, val, vl) - dst);
}
#endif
