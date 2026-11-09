// nodejs/http-parser (third_party/http-parser, Node.js's parser before llhttp, still embedded by many C clients;
// fetched by scripts/fetch-thirdparty.sh) in response mode behind picohttpparser's phr_parse_response signature, for
// bench/bench_resp.c: callbacks record the spans, on_headers_complete pauses, the pause position is the head length.
// The response-side copy of http_parser_shim.c.
#include <stddef.h>
#include "http_parser.h"
#include "picohttpparser.h"

typedef struct {
  http_parser p;
  const char *msg;
  size_t msg_len;
  struct phr_header *h;
  size_t nh, max;
  int field_open, overflow;
} hp_t;

static int on_status(http_parser *p, const char *at, size_t n) {
  hp_t *s = (hp_t *)p;
  if (!s->msg) s->msg = at;
  s->msg_len += n;
  return 0;
}
static int on_field(http_parser *p, const char *at, size_t n) {
  hp_t *s = (hp_t *)p;
  if (!s->field_open) {
    if (s->nh && s->h[s->nh - 1].value == NULL) {
      s->h[s->nh - 1].value = at;
      s->h[s->nh - 1].value_len = 0;
    }
    if (s->nh == s->max) {
      s->overflow = 1;
      return 1;
    }
    s->h[s->nh].name = at;
    s->h[s->nh].name_len = 0;
    s->h[s->nh].value = NULL;
    s->h[s->nh].value_len = 0;
    s->nh++;
    s->field_open = 1;
  }
  s->h[s->nh - 1].name_len += n;
  return 0;
}
static int on_value(http_parser *p, const char *at, size_t n) {
  hp_t *s = (hp_t *)p;
  struct phr_header *h = &s->h[s->nh - 1];
  if (!h->value) h->value = at;
  h->value_len += n;
  s->field_open = 0;
  return 0;
}
static int on_headers_done(http_parser *p) {
  http_parser_pause(p, 1);
  return 0;
}

static http_parser_settings SETTINGS = { .on_status = on_status,
                                         .on_header_field = on_field,
                                         .on_header_value = on_value,
                                         .on_headers_complete = on_headers_done };

int hpn_parse_response(const char *buf, size_t len, int *minor, int *status, const char **msg, size_t *msg_len,
                       struct phr_header *headers, size_t *num_headers, size_t last_len) {
  (void)last_len;
  hp_t s;
  http_parser_init(&s.p, HTTP_RESPONSE);
  s.msg = 0;
  s.msg_len = 0;
  s.h = headers;
  s.nh = 0;
  s.max = *num_headers;
  s.field_open = 0;
  s.overflow = 0;
  size_t used = http_parser_execute(&s.p, &SETTINGS, buf, len);
  enum http_errno e = HTTP_PARSER_ERRNO(&s.p);
  if (e == HPE_OK) return -2; // consumed everything without reaching the end of headers
  if (e != HPE_PAUSED) return -1;
  for (size_t i = 0; i < s.nh; i++)
    if (!headers[i].value) {
      headers[i].value = buf;
      headers[i].value_len = 0;
    }
  *minor = s.p.http_major == 1 ? s.p.http_minor : -1;
  *status = (int)s.p.status_code;
  *msg = s.msg;
  *msg_len = s.msg_len;
  for (size_t i = 0; i < s.nh; i++) // trim trailing OWS like pico
    while (headers[i].value_len &&
           (headers[i].value[headers[i].value_len - 1] == ' ' || headers[i].value[headers[i].value_len - 1] == '\t'))
      headers[i].value_len--;
  *num_headers = s.nh;
  if (used < len && buf[used] == '\n') used++; // paused in on_headers_complete, before consuming the final LF
  return (int)used;
}
