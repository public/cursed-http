// resp_fixtures.h - the response-parser side of the CodSpeed benchmarks (include/fbresp.h; bench/resp_shapes.h).
#pragma once
#ifdef __cplusplus
extern "C" {
#endif
// n response heads of one bench/resp_shapes.h shape (0 nginx-static, 1 cdn, 2 api, 3 304), each in its own 64-byte
// aligned slot with 64 bytes of padding; deterministic
typedef struct cb_resp cb_resp;
cb_resp *cb_resp_new(int shape, int n);
// chunked bodies with a trailer section: `chunks` chunks of `size` bytes
cb_resp *cb_resp_chunked(int chunks, int size, int n);
int cb_resp_len(const cb_resp *c);
long cb_resp_bytes(const cb_resp *c);
void cb_resp_free(cb_resp *c);
// one out-of-line call per head (as bench/bench_resp.c); each returns a checksum
long cb_fb_parse_response_call(const cb_resp *c);
long cb_fb_parse_response_scalar_call(const cb_resp *c);
long cb_fbr_parse_call(const cb_resp *c);    // the head + RFC 9112 framing
long cb_fbr_chunked(const cb_resp *c);        // one shot, then the trailer section
long cb_fbr_chunked_stream(const cb_resp *c); // fed in 512-byte pieces through prog
#ifdef __cplusplus
}
#endif
