// probe_cases.h - transport-level request shapes from an HTTP/1.1 conformance probe for small JSON API servers
// (Http11Probe, MIT): valid chunked bodies, HTTP/1.0 requests, a non-HTTP line, pipelined pairs, and the
// request framing of its auth and body checks (Basic / garbage / tampered / alg=none tokens, empty, whitespace,
// numeric, missing, malformed and 501-character bodies, multibyte UTF-8). The probe's application checks
// (signature verification, JSON validation, status codes) are not parser behaviour; their requests' framing is.
// Each case has the exact result fb_parse_req must give; tests/test_probe.c checks it, fast_parse (the same or
// FP_FALLBACK), the pico-style fb_parse_request, batchparse, and every truncation through fuzz/oracle.h.
#pragma once
#include <stdio.h>
#include <string.h>

// expected class of the fb_parse_req result
enum { PC_OK, PC_MINOR, PC_TE, PC_INVALID, PC_NEED_MORE };
typedef struct {
  const char *name;
  const char *method, *target, *version, *auth, *body; // built as the probe builds them (pc_build)
  const char *extra;                                   // extra header lines, each ending in \r\n
  const char *raw;                                     // instead of the builder: the bytes as they are
  int cls, route, id_ok;
  long long id;
  int body_cut;        // > 0: send only this many body bytes (incomplete)
  int fill;            // > 0: body = {"body":"<fill x 'a'>"} (pc_build)
  const char *decoded; // a chunked body: what decoding it must give
} probe_case_t;

// A token shaped like the API's JWTs (header.payload.signature, base64url), a copy with its last signature byte
// changed, and one with alg=none and an empty signature: the parser only frames them, it never verifies.
#define PC_TOK                                                                                                         \
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEsInVzZXJuYW1lIjoiYWxpY2UiLCJleHAiOjQxMDI0NDQ4MDB9.dGhlLXNpZ25hdHVyZS1ieXRlcy1nby1oZXJlLTAxMjM0NTY3"
#define PC_TOK_TAMPERED                                                                                                \
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEsInVzZXJuYW1lIjoiYWxpY2UiLCJleHAiOjQxMDI0NDQ4MDB9.dGhlLXNpZ25hdHVyZS1ieXRlcy1nby1oZXJlLTAxMjM0NTY4"
#define PC_TOK_NONE "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOjEsInVzZXJuYW1lIjoiYWxpY2UifQ."
#define PC_A(x)     "Bearer " x

static const probe_case_t PROBE_CASES[] = {
  // valid single-chunk body (RFC 9112 7.1: a recipient must decode it): the parser frames the head and reports
  // Transfer-Encoding; the caller decodes the body (tests/test_probe.c does it with phr_decode_chunked)
  { "te-chunked create",
    .raw =
        "POST /posts HTTP/1.1\r\nHost: localhost:8080\r\nAuthorization: Bearer " PC_TOK "\r\n"
        "Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n11\r\n{\"body\":\"chunky\"}\r\n0\r\n\r\n",
    .cls = PC_TE, .decoded = "{\"body\":\"chunky\"}" },
  { "te-chunked, no body",
    .raw = "GET /feed HTTP/1.1\r\nHost: localhost:8080\r\nAuthorization: Bearer " PC_TOK "\r\n"
           "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
    .cls = PC_TE },
  { "te-chunked lowercase",
    .raw = "POST /posts HTTP/1.1\r\nHost: localhost:8080\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n", .cls = PC_TE,
    .decoded = "" },
  // HTTP/1.0 (RFC 9112 9.3: served, then the connection closes): fb_parse_req_ex fills the request and its size
  { "http10 health", "GET", "/health", "1.0", PC_A(PC_TOK), NULL, .cls = PC_MINOR, .route = R_HEALTH },
  { "http10 feed", "GET", "/feed", "1.0", PC_A(PC_TOK), NULL, .cls = PC_MINOR, .route = R_FEED },
  { "http10 post by id", "GET", "/posts/1", "1.0", NULL, NULL, .cls = PC_MINOR, .route = R_GETPOST, .id_ok = 1,
    .id = 1 },
  { "http10 create with body", "POST", "/posts", "1.0", PC_A(PC_TOK), "{\"body\":\"http10\"}", .cls = PC_MINOR,
    .route = R_CREATE },
  { "http10 like", "POST", "/posts/1/like", "1.0", PC_A(PC_TOK), NULL, .cls = PC_MINOR, .route = R_LIKE, .id_ok = 1,
    .id = 1 },
  { "http10 with Connection: close", "GET", "/feed", "1.0", NULL, NULL, "Connection: close\r\n", .cls = PC_MINOR,
    .route = R_FEED },
  // not a request line at all: an error the server answers and closes on, never NEED_MORE (a stall)
  { "parse-error GARBAGE", .raw = "GARBAGE\r\n\r\n", .cls = PC_INVALID },
  // id validation is the application's; the parser reports the route with id_ok = 0
  { "invalid id 0", "GET", "/posts/0", "1.1", NULL, NULL, .cls = PC_OK, .route = R_GETPOST },
  { "invalid id -1", "GET", "/posts/-1", "1.1", NULL, NULL, .cls = PC_OK, .route = R_GETPOST },
  { "invalid id abc", "GET", "/posts/abc", "1.1", NULL, NULL, .cls = PC_OK, .route = R_GETPOST },
  { "unknown post", "GET", "/posts/999999", "1.1", NULL, NULL, .cls = PC_OK, .route = R_GETPOST, .id_ok = 1,
    .id = 999999 },
  { "like with bad id, no token", "POST", "/posts/abc/like", "1.1", NULL, NULL, .cls = PC_OK, .route = R_LIKE },
  { "like with bad id, Basic", "POST", "/posts/abc/like", "1.1", "Basic abc", NULL, .cls = PC_OK, .route = R_LIKE },
  { "like with bad id, token", "POST", "/posts/abc/like", "1.1", PC_A(PC_TOK), NULL, .cls = PC_OK, .route = R_LIKE },
  { "like unknown post", "POST", "/posts/999999/like", "1.1", PC_A(PC_TOK), NULL, .cls = PC_OK, .route = R_LIKE,
    .id_ok = 1, .id = 999999 },
  // the auth checks' requests: the parser extracts a Bearer token as written and nothing else
  { "create, no token", "POST", "/posts", "1.1", NULL, "{\"body\":\"x\"}", .cls = PC_OK, .route = R_CREATE },
  { "create, Basic abc", "POST", "/posts", "1.1", "Basic abc", "{\"body\":\"x\"}", .cls = PC_OK, .route = R_CREATE },
  { "create, Bearer abc", "POST", "/posts", "1.1", "Bearer abc", "{\"body\":\"x\"}", .cls = PC_OK, .route = R_CREATE },
  { "create, tampered signature", "POST", "/posts", "1.1", PC_A(PC_TOK_TAMPERED), "{\"body\":\"x\"}", .cls = PC_OK,
    .route = R_CREATE },
  { "create, alg none", "POST", "/posts", "1.1", PC_A(PC_TOK_NONE), "{\"body\":\"x\"}", .cls = PC_OK,
    .route = R_CREATE },
  // the body checks' requests: the parser frames bodies by Content-Length (bytes), whatever they contain
  { "body empty string", "POST", "/posts", "1.1", PC_A(PC_TOK), "{\"body\":\"\"}", .cls = PC_OK, .route = R_CREATE },
  { "body whitespace", "POST", "/posts", "1.1", PC_A(PC_TOK), "{\"body\":\"   \"}", .cls = PC_OK, .route = R_CREATE },
  { "body numeric", "POST", "/posts", "1.1", PC_A(PC_TOK), "{\"body\":123}", .cls = PC_OK, .route = R_CREATE },
  { "body missing", "POST", "/posts", "1.1", PC_A(PC_TOK), "{}", .cls = PC_OK, .route = R_CREATE },
  { "body malformed JSON", "POST", "/posts", "1.1", PC_A(PC_TOK), "{bad json", .cls = PC_OK, .route = R_CREATE },
  { "body 501 characters", "POST", "/posts", "1.1", PC_A(PC_TOK), NULL, .cls = PC_OK, .route = R_CREATE, .fill = 501 },
  { "body multibyte UTF-8", "POST", "/posts", "1.1", PC_A(PC_TOK),
    "{\"body\":\"h\xc3\xa9llo \xe2\x9c\x93 \xf0\x9f\x98\x80\"}", .cls = PC_OK, .route = R_CREATE },
  { "body arrives in pieces", "POST", "/posts", "1.1", PC_A(PC_TOK), "{\"body\":\"chunky\"}", .cls = PC_NEED_MORE,
    .route = R_CREATE, .body_cut = 5 },
  { "create ok", "POST", "/posts", "1.1", PC_A(PC_TOK), "{\"body\":\"hello world\"}", .cls = PC_OK, .route = R_CREATE },
  { "like ok", "POST", "/posts/1/like", "1.1", PC_A(PC_TOK), NULL, .cls = PC_OK, .route = R_LIKE, .id_ok = 1, .id = 1 },
};
#define N_PROBE_CASES ((int)(sizeof PROBE_CASES / sizeof *PROBE_CASES))

// pipelined pairs (RFC 9112 9.3: both answered, in order): the targets the probe pairs
static const char *const PROBE_PIPELINES[][2] = {
  { "/health", "/health" },
  { "/feed", "/feed" },
  { "/posts/1", "/posts/1" },
};

// the request as the probe writes it: request line, Host, Authorization, Content-Type + Content-Length (bytes)
static int pc_build(const probe_case_t *c, char *out, int cap, int *head_len, int *body_len) {
  if (c->raw) {
    int n = (int)strlen(c->raw);
    memcpy(out, c->raw, n);
    const char *e = strstr(c->raw, "\r\n\r\n");
    *head_len = e ? (int)(e - c->raw) + 4 : -1;
    *body_len = 0;
    return n;
  }
  int n = snprintf(out, cap, "%s %s HTTP/%s\r\nHost: localhost:8080\r\n", c->method, c->target, c->version);
  if (c->auth) n += snprintf(out + n, cap - n, "Authorization: %s\r\n", c->auth);
  if (c->extra) n += snprintf(out + n, cap - n, "%s", c->extra);
  static char fillbuf[1100];
  const char *body = c->body;
  if (c->fill) {
    int k = snprintf(fillbuf, sizeof fillbuf, "{\"body\":\"");
    memset(fillbuf + k, 'a', c->fill);
    strcpy(fillbuf + k + c->fill, "\"}");
    body = fillbuf;
  }
  int bl = body ? (int)strlen(body) : 0;
  if (body) n += snprintf(out + n, cap - n, "Content-Type: application/json\r\nContent-Length: %d\r\n", bl);
  n += snprintf(out + n, cap - n, "\r\n");
  *head_len = n;
  *body_len = bl;
  if (body) {
    int send = c->body_cut > 0 ? c->body_cut : bl;
    memcpy(out + n, body, send);
    n += send;
  }
  return n;
}
