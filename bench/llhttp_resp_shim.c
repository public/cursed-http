// llhttp (vendor/llhttp, v9.4.3) in response mode behind picohttpparser's phr_parse_response signature: callbacks
// record the reason and header spans, on_headers_complete pauses, and the pause position is the head length.
// The response-side counterpart of llhttp_shim.c (bench/bench_resp.c).
#include <stddef.h>
#include "llhttp.h"
#include "picohttpparser.h"

typedef struct {
  llhttp_t p;
  const char *msg;
  size_t msg_len;
  struct phr_header *h;
  size_t nh, max;
  int field_open;
} lr_t;

static int on_status(llhttp_t *p, const char *at, size_t n) {
  lr_t *s = (lr_t *)p;
  if (!s->msg) s->msg = at;
  s->msg_len += n;
  return 0;
}
static int on_field(llhttp_t *p, const char *at, size_t n) {
  lr_t *s = (lr_t *)p;
  if (!s->field_open) {
    if (s->nh == s->max) return HPE_USER;
    s->h[s->nh].name = at;
    s->h[s->nh].name_len = 0;
    s->h[s->nh].value = at;
    s->h[s->nh].value_len = 0;
    s->field_open = 1;
  }
  s->h[s->nh].name_len += n;
  return 0;
}
static int on_value(llhttp_t *p, const char *at, size_t n) {
  lr_t *s = (lr_t *)p;
  struct phr_header *h = &s->h[s->nh];
  if (!h->value_len) h->value = at;
  h->value_len += n;
  return 0;
}
static int on_value_done(llhttp_t *p) {
  lr_t *s = (lr_t *)p;
  s->nh++;
  s->field_open = 0;
  return 0;
}
static int on_headers_done(llhttp_t *p) {
  (void)p;
  return HPE_PAUSED;
}
static llhttp_settings_t SETTINGS;
static int ready;

int lx_parse_response(const char *buf, size_t len, int *minor, int *status, const char **msg, size_t *msg_len,
                      struct phr_header *headers, size_t *num_headers, size_t last_len) {
  (void)last_len;
  if (!ready) {
    llhttp_settings_init(&SETTINGS);
    SETTINGS.on_status = on_status;
    SETTINGS.on_header_field = on_field;
    SETTINGS.on_header_value = on_value;
    SETTINGS.on_header_value_complete = on_value_done;
    SETTINGS.on_headers_complete = on_headers_done;
    ready = 1;
  }
  lr_t s;
  llhttp_init(&s.p, HTTP_RESPONSE, &SETTINGS);
  s.msg = 0;
  s.msg_len = 0;
  s.h = headers;
  s.nh = 0;
  s.max = *num_headers;
  s.field_open = 0;
  llhttp_errno_t e = llhttp_execute(&s.p, buf, len);
  if (e == HPE_OK) return -2;
  if (e != HPE_PAUSED) return -1;
  *minor = s.p.http_major == 1 ? s.p.http_minor : -1;
  *status = s.p.status_code;
  *msg = s.msg;
  *msg_len = s.msg_len;
  for (size_t i = 0; i < s.nh; i++)
    while (headers[i].value_len &&
           (headers[i].value[headers[i].value_len - 1] == ' ' || headers[i].value[headers[i].value_len - 1] == '\t'))
      headers[i].value_len--;
  *num_headers = s.nh;
  return (int)(llhttp_get_error_pos(&s.p) - buf);
}
