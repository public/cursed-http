// fixtures.h - the C side of the CodSpeed benchmarks (bench/codspeed). The parsers are header-only C, so they
// are compiled in fixtures.c with the same flags as the Makefile's benchmarks; bench.cpp (Google Benchmark)
// only builds the inputs once per benchmark and times one pass over them.
#pragma once
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// A corpus of HTTP/1.1 requests, each in its own 64-byte aligned slot followed by padding (the parsers read
// whole SIMD blocks). Generated with the deterministic PRNG of tests/testlib.h, so every run sees the same bytes.
typedef struct cb_corpus cb_corpus;
// shapes of tests/testlib.h gen(): 0 k6, 1 gocli -gzip, 2 gocli, 3 browser (no spec), 4 proxy (no spec)
cb_corpus *cb_corpus_fast(int shape, int n);
// shapes of tests/shapes.h gen_fb(): 0 curl, 1 chrome, 2 firefox, 3 http/1.0, 4 long headers, 5 chunked POST, 6 odd
cb_corpus *cb_corpus_fb(int shape, int n);
// perf_one's corpora: tests/testlib.h gen() shapes exactly as `bench/dump_corpus FILE SHAPE N` writes them (a fresh
// PRNG, the tokens, then the requests), the bytes bench/perf_one parses
cb_corpus *cb_corpus_perf(int shape, int n);
// chunked bodies: `chunks` chunks of `size` bytes, with chunk extensions when ext != 0
cb_corpus *cb_corpus_chunked(int chunks, int size, int ext, int n);
int cb_corpus_len(const cb_corpus *c);
long cb_corpus_bytes(const cb_corpus *c);
void cb_corpus_free(cb_corpus *c);

// One pass over the corpus; each returns a checksum of the results so nothing is optimized away.
long cb_fast_parse(const cb_corpus *c);
long cb_fast_parse_scalar(const cb_corpus *c);
long cb_fast_parse_learn(const cb_corpus *c, void *state); // state from cb_learn_new(), warmed by earlier passes
long cb_fast_parse_tmpl(const cb_corpus *c, void *state);  // state from cb_tmpl_new()
long cb_fast_parse_many(const cb_corpus *c);               // pipelined: the whole corpus as one buffer
long cb_fb_parse_request(const cb_corpus *c);
long cb_fb_parse_request_scalar(const cb_corpus *c);
long cb_fb_parse_req(const cb_corpus *c);
// the same three, with one out-of-line call per request (as perf_one calls the parser): the per-call setup is
// counted rather than hoisted out of the loop
long cb_fb_parse_request_call(const cb_corpus *c);
long cb_fb_parse_request_scalar_call(const cb_corpus *c);
long cb_fb_parse_req_call(const cb_corpus *c);
long cb_server_path(const cb_corpus *c); // fast_parse, then fb_parse_req on FP_FALLBACK
long cb_bp_parse(const cb_corpus *c, int batch);
long cb_fb_decode_chunked(const cb_corpus *c);

void *cb_learn_new(void);
void *cb_tmpl_new(void);
void cb_state_free(void *state);

// HPACK (include/hpack.h): request header blocks of bench/h2_headers.h sets (0 browser, 1 grpc, 2 h2load),
// encoded with hpack.h's own encoder (Huffman-coded literals), decoded with a fresh decoder per pass.
typedef struct cb_hpack cb_hpack;
cb_hpack *cb_hpack_new(int set, int n);
long cb_hpack_decode(cb_hpack *h);
long cb_huffman_decode(cb_hpack *h); // Huffman decode alone (hfield.h hh_decode) of the same header values
void cb_hpack_free(cb_hpack *h);

const char *cb_backend_name(void);

#ifdef __cplusplus
}
#endif
