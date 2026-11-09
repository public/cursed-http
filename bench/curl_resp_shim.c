// libcurl's response-header processing (curl 8.23.0, fetched and built by tests/responses/fetch-clients.sh) behind
// picohttpparser's phr_parse_response signature, for bench/bench_resp.c. libcurl has no standalone response parser:
// Curl_http_write_resp_hds() is the code every transfer runs on the bytes it receives. It reads each line (memchr),
// copies it into a dynamic buffer, parses the status line and each header (Content-Length, Transfer-Encoding,
// Connection, ...), stores the headers for curl_easy_header(), and calls the header callback; at the empty line
// http_on_response() decides the body. Here it runs on a minimal easy handle with a connection set up by hand (no
// socket), and the request state is reset before each response, as libcurl does per request. Built against curl's
// internal headers (lib/), so it is pinned to that curl version.
#include "curl_setup.h"
#include "urldata.h"
#include "http.h"
#include "request.h"
#include "sendf.h"
#include "protocol.h"
#include "headers.h"
#include "picohttpparser.h"

static struct Curl_easy *cu;
char cu_err[CURL_ERROR_SIZE];
static size_t cu_fields;
static size_t on_header(char *b, size_t size, size_t n, void *u) {
  (void)b;
  (void)u;
  cu_fields++;
  return size * n;
}
static size_t on_body(char *b, size_t size, size_t n, void *u) {
  (void)b;
  (void)u;
  return size * n;
}
static void cu_setup(void) {
  curl_global_init(CURL_GLOBAL_NOTHING);
  CURL *e = curl_easy_init();
  curl_easy_setopt(e, CURLOPT_URL, "http://127.0.0.1/");
  curl_easy_setopt(e, CURLOPT_HEADERFUNCTION, on_header);
  curl_easy_setopt(e, CURLOPT_WRITEFUNCTION, on_body);
  curl_easy_setopt(e, CURLOPT_ERRORBUFFER, cu_err);
  cu = (struct Curl_easy *)e;
  struct connectdata *conn = calloc(1, sizeof *conn);
  conn->scheme = &Curl_scheme_http;
  cu->conn = conn;
  cu->state.httpreq = HTTPREQ_GET;
}

int cu_parse_response(const char *buf, size_t len, int *minor, int *status, const char **msg, size_t *msg_len,
                      struct phr_header *headers, size_t *num_headers, size_t last_len) {
  (void)headers;
  (void)last_len;
  if (!cu) cu_setup();
  struct Curl_easy *data = cu;
  Curl_req_hard_reset(&data->req, data);
  Curl_req_start(&data->req, data);
  Curl_headers_cleanup(data);
  curlx_dyn_reset(&data->state.headerb); // a previous partial head's bytes
  data->state.maybe_folded = FALSE;
  data->state.leading_unfold = FALSE;
  data->req.header = TRUE;
  data->req.allheadercount = 0; // libcurl caps a transfer's header bytes (300 KB): one response here is one transfer
  data->info.header_size = 0;
  data->req.size = -1;
  data->req.maxdownload = -1;
  cu_fields = 0;
  size_t consumed = 0;
  CURLcode rc = Curl_http_write_resp_hds(data, buf, len, &consumed);
  *msg = NULL;
  *msg_len = 0;
  *num_headers = cu_fields >= 2 ? cu_fields - 2 : 0; // the callback also sees the status line and the empty line
  if (rc) return -1;
  if (data->req.header) return -2; // still in the head
  *minor = data->req.httpversion % 10;
  *status = data->req.httpcode;
  return (int)consumed;
}
