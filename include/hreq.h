/* hreq.h: HTTP/2 and HTTP/3 request header validation (RFC 9113 §8.1.1-8.3.1, RFC 9114 §4.1.2-4.3.1,
 * which state the same rules). Works on hpack.h's hp_field, whose validation verdicts were cached
 * when each field was first decoded. Used by h2.h and h3.h. */
#ifndef HREQ_H
#define HREQ_H
#include <stdint.h>
#include <string.h>
#include "hpack.h"

/* The request: pseudo-headers split out, regular fields in order (strings valid during the call). */
typedef struct {
  const uint8_t *method, *scheme, *authority, *path;
  uint32_t method_len, scheme_len, authority_len, path_len;
  const hp_field *fields; /* regular fields only */
  int nfields;
  int64_t content_length; /* -1 if absent */
} h_request;

static inline int h_eq(const uint8_t *p, uint32_t n, const char *s) { return n == strlen(s) && !memcmp(p, s, n); }

/* RFC 9113 §8.1.1-8.3.1; returns 0 if malformed */
static inline int h_build_request(const hp_field *f, int n, h_request *rq, hp_field *regular) {
  memset(rq, 0, sizeof *rq);
  rq->content_length = -1;
  int nreg = 0, seen_regular = 0;
  for (int i = 0; i < n; i++) {
    const hp_field *x = &f[i];
    if (!x->vok) return 0;
    if (x->nclass == HP_N_PSEUDO) {
      if (seen_regular) return 0;
      const uint8_t **dst;
      uint32_t *dl;
      if (h_eq(x->name, x->nlen, ":method")) dst = &rq->method, dl = &rq->method_len;
      else if (h_eq(x->name, x->nlen, ":scheme")) dst = &rq->scheme, dl = &rq->scheme_len;
      else if (h_eq(x->name, x->nlen, ":authority")) dst = &rq->authority, dl = &rq->authority_len;
      else if (h_eq(x->name, x->nlen, ":path")) dst = &rq->path, dl = &rq->path_len;
      else return 0;      /* unknown or response pseudo-header */
      if (*dst) return 0; /* duplicate */
      *dst = x->value ? x->value : (const uint8_t *)"", *dl = x->vlen;
      continue;
    }
    if (x->nclass != HP_N_OK) return 0; /* uppercase or invalid name */
    seen_regular = 1;
    /* connection-specific fields (§8.2.2) */
    switch (x->nlen) {
      case 2:
        if (h_eq(x->name, 2, "te") && !h_eq(x->value, x->vlen, "trailers")) return 0;
        break;
      case 7:
        if (h_eq(x->name, 7, "upgrade")) return 0;
        break;
      case 10:
        if (h_eq(x->name, 10, "connection") || h_eq(x->name, 10, "keep-alive")) return 0;
        break;
      case 14:
        if (x->sidx == 28) { /* content-length: digits only; repeats must agree */
          if (!x->vlen || x->vlen > 18) return 0;
          int64_t v = 0;
          for (uint32_t k = 0; k < x->vlen; k++) {
            if ((uint8_t)(x->value[k] - '0') > 9) return 0;
            v = v * 10 + (x->value[k] - '0');
          }
          if (rq->content_length >= 0 && rq->content_length != v) return 0;
          rq->content_length = v;
        }
        break;
      case 16:
        if (h_eq(x->name, 16, "proxy-connection")) return 0;
        break;
      case 17:
        if (x->sidx == 57) return 0;
        break; /* transfer-encoding */
    }
    regular[nreg++] = *x;
  }
  if (!rq->method) return 0;
  if (h_eq(rq->method, rq->method_len, "CONNECT")) {
    if (rq->scheme || rq->path || !rq->authority) return 0;
  } else if (!rq->scheme || !rq->path || !rq->path_len) {
    return 0;
  }
  rq->fields = regular, rq->nfields = nreg;
  return 1;
}

#endif
