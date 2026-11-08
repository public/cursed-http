/* hreq.h: HTTP/2 and HTTP/3 request and response header validation (RFC 9113 §8.1.1-8.3.2, RFC 9114
 * §4.1.2-4.3.2, which state the same rules). Works on hpack.h's hp_field, whose validation verdicts were
 * cached when each field was first decoded. Requests for the servers in h2.h and h3.h, responses for
 * their clients. */
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

/* the regular-field rules shared by requests and responses (§8.2, §8.2.2); 0 if malformed. A content-length
 * must be digits only, and its repeats must agree */
static inline int h__regular(const hp_field *x, int64_t *content_length) {
  if (x->nclass != HP_N_OK) return 0; /* uppercase or invalid name */
  switch (x->nlen) {                  /* connection-specific fields (§8.2.2) */
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
      if (x->sidx == 28) {
        if (!x->vlen || x->vlen > 18) return 0;
        int64_t v = 0;
        for (uint32_t k = 0; k < x->vlen; k++) {
          if ((uint8_t)(x->value[k] - '0') > 9) return 0;
          v = v * 10 + (x->value[k] - '0');
        }
        if (*content_length >= 0 && *content_length != v) return 0;
        *content_length = v;
      }
      break;
    case 16:
      if (h_eq(x->name, 16, "proxy-connection")) return 0;
      break;
    case 17:
      if (x->sidx == 57) return 0;
      break; /* transfer-encoding */
  }
  return 1;
}

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
    if (!h__regular(x, &rq->content_length)) return 0;
    seen_regular = 1;
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

/* The response: the status and the regular fields in order (strings valid during the call). */
typedef struct {
  int status;
  const hp_field *fields; /* regular fields only */
  int nfields;
  int64_t content_length; /* -1 if absent */
} h_response;

/* RFC 9113 §8.3.2 (and the §8.1 / §8.2 rules): exactly one :status, three digits; 101 is not a status HTTP/2 or
 * HTTP/3 can carry (§8.6), and a status below 100 is not one at all (RFC 9110 §15). No other pseudo-header, and
 * none after a regular field. Returns 0 if malformed. Trailers are checked by h_check_trailers. */
static inline int h_build_response(const hp_field *f, int n, h_response *rs, hp_field *regular) {
  rs->status = -1, rs->fields = regular, rs->nfields = 0, rs->content_length = -1;
  int nreg = 0, seen_regular = 0;
  for (int i = 0; i < n; i++) {
    const hp_field *x = &f[i];
    if (!x->vok) return 0;
    if (x->nclass == HP_N_PSEUDO) {
      if (seen_regular || rs->status >= 0 || !h_eq(x->name, x->nlen, ":status") || x->vlen != 3) return 0;
      unsigned d0 = x->value[0] - '0', d1 = x->value[1] - '0', d2 = x->value[2] - '0';
      if (d0 > 9 || d1 > 9 || d2 > 9) return 0;
      rs->status = (int)(d0 * 100 + d1 * 10 + d2);
      if (rs->status < 100 || rs->status == 101) return 0;
      continue;
    }
    if (!h__regular(x, &rs->content_length)) return 0;
    seen_regular = 1;
    regular[nreg++] = *x;
  }
  if (rs->status < 0) return 0;
  rs->nfields = nreg;
  return 1;
}

/* a trailer section (§8.1): regular fields only, valid names and values */
static inline int h_check_trailers(const hp_field *f, int n) {
  for (int i = 0; i < n; i++)
    if (f[i].nclass != HP_N_OK || !f[i].vok) return 0;
  return 1;
}

#endif
