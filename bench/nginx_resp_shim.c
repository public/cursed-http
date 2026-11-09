// nginx's upstream (proxy) response parser (nginx 1.31.8, fetched and configured by tests/responses/fetch-clients.sh)
// behind picohttpparser's phr_parse_response signature, for bench/bench_resp.c: ngx_http_parse_status_line(), then
// ngx_http_parse_header_line() until the head ends, as ngx_http_proxy_module's process_status_line/process_header do.
// The proxy's per-field work after the parse (a hash lookup of the lowercased name, copying the field into the request
// pool) is not included: this is nginx's parser alone. Stubs stand in for the few core functions ngx_http_parse.c
// links against and these two parse functions don't call.
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "picohttpparser.h"

void ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err, const char *fmt, ...) {
  (void)level, (void)log, (void)err, (void)fmt;
}
void *ngx_pnalloc(ngx_pool_t *pool, size_t size) {
  (void)pool;
  return malloc(size);
}
u_char *ngx_strlcasestrn(u_char *s1, u_char *last, u_char *s2, size_t n) {
  (void)s1, (void)last, (void)s2, (void)n;
  return NULL;
}
ngx_int_t ngx_strncasecmp(u_char *s1, u_char *s2, size_t n) { return strncasecmp((char *)s1, (char *)s2, n); }
void ngx_unescape_uri(u_char **dst, u_char **src, size_t size, ngx_uint_t type) {
  (void)dst, (void)src, (void)size, (void)type;
}

int ngx_parse_response(const char *buf, size_t len, int *minor, int *status, const char **msg, size_t *msg_len,
                       struct phr_header *headers, size_t *num_headers, size_t last_len) {
  (void)last_len;
  static ngx_http_request_t r;
  ngx_http_status_t st;
  ngx_buf_t b;
  memset(&r.state, 0, sizeof r.state);
  r.state = 0;
  memset(&st, 0, sizeof st);
  b.pos = (u_char *)buf;
  b.last = (u_char *)buf + len;
  ngx_int_t rc = ngx_http_parse_status_line(&r, &b, &st);
  if (rc == NGX_AGAIN) return -2;
  if (rc != NGX_OK) return -1;
  *minor = (int)(st.http_version % 1000);
  *status = (int)st.code;
  *msg = (const char *)st.start;
  *msg_len = st.end > st.start ? (size_t)(st.end - st.start) : 0;
  size_t n = 0, max = *num_headers;
  r.state = 0;
  for (;;) {
    rc = ngx_http_parse_header_line(&r, &b, 1);
    if (rc == NGX_OK) {
      if (n == max) return -1;
      headers[n].name = (const char *)r.header_name_start;
      headers[n].name_len = (size_t)(r.header_name_end - r.header_name_start);
      headers[n].value = (const char *)r.header_start;
      headers[n].value_len = (size_t)(r.header_end - r.header_start);
      n++;
      continue;
    }
    if (rc == NGX_HTTP_PARSE_HEADER_DONE) break;
    if (rc == NGX_AGAIN) return -2;
    return -1; // NGX_HTTP_PARSE_INVALID_HEADER
  }
  *num_headers = n;
  return (int)((const char *)b.pos - buf);
}
