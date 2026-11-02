// edges.h - edge-case requests with the expected fast_parse result, shared by every test.
// test_fastparse.c checks the expected values; the other tests use .req as differential inputs.
#pragma once
// ---- edge cases (curl-style requests + parser corners), with expected semantics ----
// ret: 1 = must parse fully (== len) and agree with ref; 2 = parses fully, ref falls back (known difference);
//      3 = parses fully, pico rejects the request (relaxed accept);
//      <= 0 = exact expected return of fast_parse (ref may differ: a fallback is always allowed)
typedef struct {
  const char *req;
  int ret, route, id_ok;
  int64_t id;
  int auth;
  const char *tok;
} edge_t;
static const edge_t EDGES[] = {
  { "GET /nope HTTP/1.1\r\nHost: x\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n", 1, R_NOTFOUND, 0, 0, 0, 0 },
  { "GET /posts/0 HTTP/1.1\r\nHost: x\r\n\r\n", 1, R_GETPOST, 0, 0, 0, 0 },
  { "GET /posts/-1 HTTP/1.1\r\nHost: x\r\n\r\n", 1, R_GETPOST, 0, 0, 0, 0 },
  { "GET /posts/abc HTTP/1.1\r\nHost: x\r\n\r\n", 1, R_GETPOST, 0, 0, 0, 0 },
  { "GET /posts/1.5 HTTP/1.1\r\nHost: x\r\n\r\n", 1, R_GETPOST, 0, 0, 0, 0 },
  { "GET /posts/999999999 HTTP/1.1\r\nHost: x\r\n\r\n", 1, R_GETPOST, 1, 999999999, 0, 0 },
  { "GET /posts/9007199254740991 HTTP/1.1\r\nHost: x\r\n\r\n", 1, R_GETPOST, 1, 9007199254740991ll, 0, 0 },
  { "GET /posts/9999999999999999 HTTP/1.1\r\nHost: x\r\n\r\n", 1, R_GETPOST, 1, 9999999999999999ll, 0, 0 },
  { "GET /posts/12345678901234567 HTTP/1.1\r\nHost: x\r\n\r\n", 1, R_GETPOST, 0, 0, 0, 0 }, // 17 digits
  { "GET /posts/00042 HTTP/1.1\r\nHost: x\r\n\r\n", 1, R_GETPOST, 1, 42, 0, 0 },
  { "GET /posts/0000000000000000 HTTP/1.1\r\nHost: x\r\n\r\n", 1, R_GETPOST, 0, 0, 0, 0 },
  { "GET /posts/12345678: HTTP/1.1\r\nHost: x\r\n\r\n", 1, R_GETPOST, 0, 0, 0, 0 }, // ':' = '0'+10
  { "GET /posts/ HTTP/1.1\r\nHost: x\r\n\r\n", 1, R_GETPOST, 0, 0, 0, 0 },
  { "GET /posts/1/2 HTTP/1.1\r\nHost: x\r\n\r\n", 1, R_NOTFOUND, 0, 0, 0, 0 },
  { "GET /health HTTP/1.1\r\nHost: x\r\n\r\n", 1, R_HEALTH, 0, 0, 0, 0 },
  { "GET /feed HTTP/1.1\r\nHost: x\r\n\r\n", 1, R_FEED, 0, 0, 0, 0 },
  { "GET  /feed   HTTP/1.1\r\nHost: x\r\n\r\n", 1, R_FEED, 0, 0, 0, 0 }, // extra SP (pico ok)
  { "GET /feed HTTP/1.1\r\n\r\n", 1, R_FEED, 0, 0, 0, 0 },               // no headers
  { "GET /feed/ HTTP/1.1\r\nHost: x\r\n\r\n", 1, R_NOTFOUND, 0, 0, 0, 0 },
  { "GET /feed HTTP/1.0\r\nHost: x\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 },
  // short request lines (l0 < 16 used to fall back): the homepage, a 1-byte method, no headers
  { "GET / HTTP/1.1\r\n\r\n", 1, R_NOTFOUND, 0, 0, 0, 0 },
  { "GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n", 1, R_NOTFOUND, 0, 0, 0, 0 },
  { "GET /a HTTP/1.1\r\n\r\n", 1, R_NOTFOUND, 0, 0, 0, 0 },
  { "M / HTTP/1.1\r\n\r\n", 1, R_NOTFOUND, 0, 0, 0, 0 },
  { "GET  / HTTP/1.1\r\n\r\n", 1, R_NOTFOUND, 0, 0, 0, 0 },
  { "GET / HTTP/1.1\r\nContent-Length: 2\r\n\r\nab", 1, R_NOTFOUND, 0, 0, 0, 0 },
  { "GET  HTTP/1.1\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 },
  { "X HTTP/1.1\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 },
  { "/ HTTP/1.1\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 },
  { " / HTTP/1.1\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 }, // empty method (any length: " /feed HTTP/1.1" too)
  { " /feed HTTP/1.1\r\nHost: x\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 },
  { "GET /feed HTTP/1.1\nHost: x\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 }, // bare LF request line
  { "POST /posts HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 12\r\n\r\n{\"body\":\"x\"}",
    1, R_CREATE, 0, 0, 0, 0 },
  { "POST /posts HTTP/1.1\r\nHost: x\r\nAuthorization: Basic abc\r\nContent-Length: 12\r\n\r\n{\"body\":\"x\"}", 1,
    R_CREATE, 0, 0, 0, 0 },
  { "POST /posts HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer abc\r\nContent-Length: 12\r\n\r\n{\"body\":\"x\"}", 1,
    R_CREATE, 0, 0, 1, "abc" },
  { "POST /posts HTTP/1.1\r\nHost: x\r\nauthorization:   Bearer abc  \r\ncontent-length:12\r\n\r\n{\"body\":\"x\"}", 1,
    R_CREATE, 0, 0, 1, "abc" },
  { "POST /posts HTTP/1.1\r\nAUTHORIZATION: Bearer a\r\nAuthorization: Bearer b\r\nCONTENT-LENGTH: 12\r\n\r\n{\"body\":\"x\"}",
    1, R_CREATE, 0, 0, 1, "a" },
  { "POST /posts HTTP/1.1\r\nAuthorization: Bearer \r\nContent-Length: 0\r\n\r\n", 1, R_CREATE, 0, 0, 0, 0 },
  { "POST /posts HTTP/1.1\r\nAuthorization: bearer abc\r\nContent-Length: 0\r\n\r\n", 1, R_CREATE, 0, 0, 0, 0 },
  { "POST /posts HTTP/1.1\r\nContent-Length: 12\r\nContent-Length: 12\r\n\r\n{\"body\":\"x\"}", FP_FALLBACK, 0, 0, 0, 0,
    0 },
  { "POST /posts HTTP/1.1\r\nContent-Length: 012\r\n\r\n{\"body\":\"x\"}", 2, R_CREATE, 0, 0, 0,
    0 }, // known difference: fast takes 12, ref falls back
  { "POST /posts HTTP/1.1\r\nContent-Length: 1234567890\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 },
  { "POST /posts HTTP/1.1\r\nContent-Length: 1x\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 },
  { "POST /posts HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 },
  { "POST /posts HTTP/1.1\r\nContent-Lengthy: 5\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 }, // "content-length" + non-':'
  // framing ambiguities found by a conformance run against third-party suites: never parse, always fall back
  { "PUT /url HTTP/1.1\r\nContent\rLength: 003\r\n\r\nabc", FP_FALLBACK, 0, 0, 0, 0, 0 },   // CR is not '-'
  { "POST /posts HTTP/1.1\r\nContent-Length : 4\r\n\r\nabcd", FP_FALLBACK, 0, 0, 0, 0, 0 }, // SP before ':'
  { "GET /feed HTTP/1.1\r\nContent-Length\t: 4\r\n\r\nabcd", FP_FALLBACK, 0, 0, 0, 0, 0 },
  { "POST /posts HTTP/1.1\r\nx:\rTransfer-Encoding: chunked\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 }, // bare CR
  { "GET /feed HTTP/1.1\r\nHost: a\rb\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 },
  { "GET /feed HTTP/1.1\r\nHost: a\r\n\rZGET /evil: HTTP/1.1\r\nHost: a\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 },
  { "POST /posts HTTP/1.1\r\nFoo: bar\r\n Content-Length: 38\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 }, // obs-fold
  { "GET /feed HTTP/1.1\r\nFoo: bar\r\n\tx\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 },
  { "POST /posts HTTP/1.1\r\nTransfer-\r\nEncoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n", FP_FALLBACK, 0, 0,
    0, 0, 0 },
  { "POST /posts HTTP/1.1\r\nContent-\r\nLength: 5\r\n\r\nabcde", FP_FALLBACK, 0, 0, 0, 0, 0 }, // split name
  { "POST /posts HTTP/1.1\r\nTransfer-Encoding : chunked\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 },
  { "POST /posts HTTP/1.1\r\nTransferX: 1\r\nContent-Length: 0\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 }, // any transfer*
  { "GET /feed HTTP/1.1\r\nContent-Type: text/plain\r\nCache-Control: no\r\nTE: x\r\n\r\n", 1, R_FEED, 0, 0, 0, 0 },
  { "GET /feed HTTP/1.1\r\nAuthorization: Bearer abc\r\n\r\n", 1, R_FEED, 0, 0, 0, 0 }, // auth only on POST routes
  { "POST /posts/abc/like HTTP/1.1\r\nHost: x\r\n\r\n", 1, R_LIKE, 0, 0, 0, 0 },
  { "POST /posts/77/like HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer t.o.k\r\nContent-Length: 0\r\n\r\n", 1, R_LIKE, 1,
    77, 1, "t.o.k" },
  { "POST /posts//like HTTP/1.1\r\nHost: x\r\n\r\n", 1, R_LIKE, 0, 0, 0, 0 },
  { "POST /posts/1/2/like HTTP/1.1\r\nHost: x\r\n\r\n", 1, R_NOTFOUND, 0, 0, 0, 0 },
  { "DELETE /posts/1 HTTP/1.1\r\nHost: x\r\n\r\n", 1, R_NOTFOUND, 0, 0, 0, 0 },
  { "GET /feed HTTP/1.1\r\nHost: x\nX-A: b\r\n\r\n", 1, R_FEED, 0, 0, 0, 0 }, // bare LF inside headers is a line end
  { "GET /feed HTTP/1.1\r\nA\nB: c\r\n\r\n", 3, R_FEED, 0, 0, 0, 0 },         // "\nA\n" is an end candidate, rejected
  { "\nA\n\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 },                            // candidate at p=2 (needs p>=3 guard)
  { "\r\nGET /feed HTTP/1.1\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 },
  // canonical request-line templates vs the general path
  { "GET /posts/1234567 HTTP/1.1\r\n\r\n", 1, R_GETPOST, 1, 1234567, 0, 0 },
  { "GET /posts/12345678 HTTP/1.1\r\n\r\n", 1, R_GETPOST, 1, 12345678, 0, 0 }, // 8 digits: general path
  { "GET /posts/123456789 HTTP/1.1\r\n\r\n", 1, R_GETPOST, 1, 123456789, 0, 0 },
  { "GET /posts/00 HTTP/1.1\r\n\r\n", 1, R_GETPOST, 0, 0, 0, 0 },
  { "GET /posts/7  HTTP/1.1\r\n\r\n", 1, R_GETPOST, 1, 7, 0, 0 },
  { "GET /posts/7 HTTP/1.1\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 }, // bare-LF ends -> fallback
  { "GET /feed HTTP/1.1\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 },
  { "GET /feed HTTP/1.1\r\n\n", FP_FALLBACK, 0, 0, 0, 0, 0 },
  { "GET /feed HTTP/1.1\r\nHost: x\n\n", FP_FALLBACK, 0, 0, 0, 0, 0 },
  { "GET /feed HTTP/1.1\r\nHost: x\n\r\nGET /feed HTTP/1.1\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 },
  { "POST /posts HTTP/1.1\r\nContent-Length: 4\r\n\r\n\n\n\n\n", 1, R_CREATE, 0, 0, 0, 0 }, // LFs in the body are fine
  { "GET /feedHTTP/1.1\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 },
  { "GET /feed HTTP/1.2\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 },
  { "GET /posts/1 HTTP/1.0\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 },
  { "POST /posts/0/like HTTP/1.1\r\n\r\n", 1, R_LIKE, 0, 0, 0, 0 },
  { "POST /posts/1/likes HTTP/1.1\r\n\r\n", 1, R_NOTFOUND, 0, 0, 0, 0 },
  { "POST /posts/12345678/like HTTP/1.1\r\nAuthorization: Bearer q\r\n\r\n", 1, R_LIKE, 1, 12345678, 1, "q" },
  { "POST /posts  HTTP/1.1\r\nAuthorization: Bearer q\r\n\r\n", 1, R_CREATE, 0, 0, 1, "q" },
  { "POST /postsHTTP/1.1\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 },
  { "POST /posts HTTP/1.1\r\n\r\n", 1, R_CREATE, 0, 0, 0, 0 }, // pico skips a leading CRLF; we don't
  { "POST /posts/5/like HTTP/1.1\r\nContent-Length: 0\r\nTE: x\r\nCookie: c\r\nauthorization: Bearer T\r\n\r\n", 1,
    R_LIKE, 1, 5, 1, "T" },
  // Connection (RFC 9112 9.6): only "keep-alive" stays on the fast path; anything else falls back, so the caller
  // sees a close (fb_info_t.close) or whatever else the header asks for
  { "GET /feed HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 },
  { "GET /feed HTTP/1.1\r\nConnection: Close\r\nHost: x\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 },
  { "GET /posts/7 HTTP/1.1\r\nCONNECTION: CLOSE\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 },
  { "GET /health HTTP/1.1\r\nHost: x\r\nconnection: keep-alive, close\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 },
  { "GET /health HTTP/1.1\r\nHost: x\r\nConnection: close, keep-alive\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 },
  { "GET /feed HTTP/1.1\r\nHost: x\r\nConnection:  close  \r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 },
  { "GET /feed HTTP/1.1\r\nHost: x\r\nConnection : close\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 }, // pico: invalid
  { "GET /feed HTTP/1.1\r\nHost: x\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 },
  { "GET /feed HTTP/1.1\r\nHost: x\r\nConnection: keep-alivex\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 },
  { "GET /feed HTTP/1.1\r\nHost: x\r\nConnection: keep-alive, Upgrade\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 },
  { "GET /feed HTTP/1.1\r\nHost: x\r\nConnection:\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 },
  { "GET /feed HTTP/1.1\r\nHost: x\r\nConnectionX: close\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0, 0 }, // any connection* name
  { "POST /posts HTTP/1.1\r\nAuthorization: Bearer t.o.k\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
    FP_FALLBACK, 0, 0, 0, 0, 0 },
  { "POST /posts/3/like HTTP/1.1\r\nConnection: close\r\nAuthorization: Bearer t.o.k\r\n\r\n", FP_FALLBACK, 0, 0, 0, 0,
    0 },
  { "GET /feed HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n", 1, R_FEED, 0, 0, 0, 0 },
  { "GET /feed HTTP/1.1\r\nCONNECTION: Keep-Alive\r\nHost: x\r\n\r\n", 1, R_FEED, 0, 0, 0, 0 },
  { "GET /posts/9 HTTP/1.1\r\nconnection:keep-alive \r\n\r\n", 1, R_GETPOST, 1, 9, 0, 0 },
  { "POST /posts HTTP/1.1\r\nConnection: keep-alive\r\nAuthorization: Bearer t.o.k\r\nContent-Length: 2\r\n\r\n{}", 1,
    R_CREATE, 0, 0, 1, "t.o.k" },
};
