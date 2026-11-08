// CodSpeed benchmarks (Google Benchmark, CodSpeed's fork): each benchmark times one pass over a fixed,
// deterministic corpus. The inputs and parser calls live in fixtures.c (the parsers are C headers).
//   cmake -S bench/codspeed -B build/codspeed -DCODSPEED_MODE=simulation && cmake --build build/codspeed -j
//   ./build/codspeed/cursed_http_bench
#include <benchmark/benchmark.h>

#include "fixtures.h"

// load-test traffic the example spec's fast path is built for (k6, gocli), and traffic it has no route for
enum FastShape { K6 = 0, GOCLI_GZIP = 1, GOCLI = 2, BROWSER = 3, PROXY = 4 };
// fallback-shaped traffic (tests/shapes.h)
enum FbShape { CURL = 0, CHROME = 1, FIREFOX = 2, HTTP10 = 3, LONG_HEADERS = 4, CHUNKED_POST = 5, ODD = 6 };
// request header sets of bench/h2_headers.h
enum HeaderSet { H_BROWSER = 0, H_GRPC = 1, H_H2LOAD = 2 };

static constexpr int kRequests = 256;

static void set_counters(benchmark::State &state, const cb_corpus *c) {
  state.SetItemsProcessed(state.iterations() * cb_corpus_len(c));
  state.SetBytesProcessed(state.iterations() * cb_corpus_bytes(c));
}

static void run(benchmark::State &state, cb_corpus *c, long (*fn)(const cb_corpus *)) {
  for (auto _ : state) {
    long r = fn(c);
    benchmark::DoNotOptimize(r);
  }
  set_counters(state, c);
  cb_corpus_free(c);
}
static void run_fast(benchmark::State &state, long (*fn)(const cb_corpus *), int shape) {
  run(state, cb_corpus_fast(shape, kRequests), fn);
}
static void run_fb(benchmark::State &state, long (*fn)(const cb_corpus *), int shape) {
  run(state, cb_corpus_fb(shape, shape == LONG_HEADERS ? 32 : kRequests), fn);
}

// ---------------- fastparse.h ----------------
static void BM_fast_parse(benchmark::State &state, int shape) { run_fast(state, cb_fast_parse, shape); }
BENCHMARK_CAPTURE(BM_fast_parse, k6, K6);
BENCHMARK_CAPTURE(BM_fast_parse, gocli_gzip, GOCLI_GZIP);
BENCHMARK_CAPTURE(BM_fast_parse, gocli, GOCLI);

static void BM_fast_parse_scalar(benchmark::State &state, int shape) { run_fast(state, cb_fast_parse_scalar, shape); }
BENCHMARK_CAPTURE(BM_fast_parse_scalar, k6, K6);
BENCHMARK_CAPTURE(BM_fast_parse_scalar, gocli, GOCLI);

// pipelined: the whole corpus as one buffer
static void BM_fast_parse_many(benchmark::State &state, int shape) { run_fast(state, cb_fast_parse_many, shape); }
BENCHMARK_CAPTURE(BM_fast_parse_many, k6, K6);

// learning modes: the state is warmed by one pass before timing, as on a running server
static void BM_fast_parse_learn(benchmark::State &state, int shape) {
  cb_corpus *c = cb_corpus_fast(shape, kRequests);
  void *learn = cb_learn_new();
  cb_fast_parse_learn(c, learn);
  for (auto _ : state) {
    long r = cb_fast_parse_learn(c, learn);
    benchmark::DoNotOptimize(r);
  }
  set_counters(state, c);
  cb_state_free(learn);
  cb_corpus_free(c);
}
BENCHMARK_CAPTURE(BM_fast_parse_learn, k6, K6);
BENCHMARK_CAPTURE(BM_fast_parse_learn, gocli, GOCLI);

static void BM_fast_parse_tmpl(benchmark::State &state, int shape) {
  cb_corpus *c = cb_corpus_fast(shape, kRequests);
  void *tmpl = cb_tmpl_new();
  cb_fast_parse_tmpl(c, tmpl);
  for (auto _ : state) {
    long r = cb_fast_parse_tmpl(c, tmpl);
    benchmark::DoNotOptimize(r);
  }
  set_counters(state, c);
  cb_state_free(tmpl);
  cb_corpus_free(c);
}
BENCHMARK_CAPTURE(BM_fast_parse_tmpl, k6, K6);
BENCHMARK_CAPTURE(BM_fast_parse_tmpl, browser, BROWSER);
BENCHMARK_CAPTURE(BM_fast_parse_tmpl, proxy, PROXY);

// the server path: fast_parse, and fbparse.h on FP_FALLBACK (browser / proxy traffic has no route in the spec)
static void BM_server_path(benchmark::State &state, int shape) { run_fast(state, cb_server_path, shape); }
BENCHMARK_CAPTURE(BM_server_path, k6, K6);
BENCHMARK_CAPTURE(BM_server_path, browser, BROWSER);
BENCHMARK_CAPTURE(BM_server_path, proxy, PROXY);

// ---------------- fbparse.h ----------------
static void BM_fb_parse_request(benchmark::State &state, int shape) { run_fb(state, cb_fb_parse_request, shape); }
BENCHMARK_CAPTURE(BM_fb_parse_request, curl, CURL);
BENCHMARK_CAPTURE(BM_fb_parse_request, chrome, CHROME);
BENCHMARK_CAPTURE(BM_fb_parse_request, firefox, FIREFOX);
BENCHMARK_CAPTURE(BM_fb_parse_request, http10, HTTP10);
BENCHMARK_CAPTURE(BM_fb_parse_request, long_headers, LONG_HEADERS);
BENCHMARK_CAPTURE(BM_fb_parse_request, chunked_post, CHUNKED_POST);
BENCHMARK_CAPTURE(BM_fb_parse_request, odd, ODD);

static void BM_fb_parse_request_scalar(benchmark::State &state, int shape) {
  run_fb(state, cb_fb_parse_request_scalar, shape);
}
BENCHMARK_CAPTURE(BM_fb_parse_request_scalar, curl, CURL);
BENCHMARK_CAPTURE(BM_fb_parse_request_scalar, chrome, CHROME);

// fb_parse_req: the parse plus fastparse.h's routing / Authorization / Content-Length logic
static void BM_fb_parse_req(benchmark::State &state, int shape) { run_fb(state, cb_fb_parse_req, shape); }
BENCHMARK_CAPTURE(BM_fb_parse_req, curl, CURL);
BENCHMARK_CAPTURE(BM_fb_parse_req, chrome, CHROME);
BENCHMARK_CAPTURE(BM_fb_parse_req, firefox, FIREFOX);

// ---------------- fbparse.h chunked bodies ----------------
static void BM_fb_decode_chunked(benchmark::State &state, int chunks, int size, int ext) {
  run(state, cb_corpus_chunked(chunks, size, ext, 64), cb_fb_decode_chunked);
}
BENCHMARK_CAPTURE(BM_fb_decode_chunked, 1x500B, 1, 500, 0);
BENCHMARK_CAPTURE(BM_fb_decode_chunked, 16x32B, 16, 32, 0);
BENCHMARK_CAPTURE(BM_fb_decode_chunked, 64x8B, 64, 8, 0);
BENCHMARK_CAPTURE(BM_fb_decode_chunked, 1x4KB, 1, 4096, 0);
BENCHMARK_CAPTURE(BM_fb_decode_chunked, 8x500B_extensions, 8, 500, 1);

// ---------------- batchparse.h ----------------
static void BM_bp_parse(benchmark::State &state) {
  int batch = static_cast<int>(state.range(0));
  cb_corpus *c = cb_corpus_fast(K6, kRequests);
  for (auto _ : state) {
    long r = cb_bp_parse(c, batch);
    benchmark::DoNotOptimize(r);
  }
  set_counters(state, c);
  cb_corpus_free(c);
}
BENCHMARK(BM_bp_parse)->ArgName("batch")->Arg(1)->Arg(8)->Arg(32);

// ---------------- hpack.h / hfield.h ----------------
// a connection's worth of requests (64) through one decoder, warm dynamic table
static void BM_hpack_decode(benchmark::State &state, int set) {
  cb_hpack *h = cb_hpack_new(set, 64);
  for (auto _ : state) {
    long r = cb_hpack_decode(h);
    benchmark::DoNotOptimize(r);
  }
  state.SetItemsProcessed(state.iterations() * 64);
  cb_hpack_free(h);
}
BENCHMARK_CAPTURE(BM_hpack_decode, browser, H_BROWSER);
BENCHMARK_CAPTURE(BM_hpack_decode, grpc, H_GRPC);
BENCHMARK_CAPTURE(BM_hpack_decode, h2load, H_H2LOAD);

static void BM_huffman_decode(benchmark::State &state, int set) {
  cb_hpack *h = cb_hpack_new(set, 16);
  for (auto _ : state) {
    long r = cb_huffman_decode(h);
    benchmark::DoNotOptimize(r);
  }
  cb_hpack_free(h);
}
BENCHMARK_CAPTURE(BM_huffman_decode, browser, H_BROWSER);
BENCHMARK_CAPTURE(BM_huffman_decode, grpc, H_GRPC);

// ---------------- HTTP/2 and HTTP/3 clients ----------------
// one connection: 256 requests encoded and sent, their responses decoded (fields, bodies, trailers)
static void BM_h2_client(benchmark::State &state, int set) {
  cb_h2c *c = cb_h2c_new(set);
  for (auto _ : state) {
    long r = cb_h2c_run(c);
    benchmark::DoNotOptimize(r);
  }
  state.SetItemsProcessed(state.iterations() * kRequests);
  cb_h2c_free(c);
}
BENCHMARK_CAPTURE(BM_h2_client, browser, H_BROWSER);
BENCHMARK_CAPTURE(BM_h2_client, grpc, H_GRPC);
BENCHMARK_CAPTURE(BM_h2_client, h2load, H_H2LOAD);

static void BM_h3_client(benchmark::State &state, int set) {
  cb_h3c *c = cb_h3c_new(set);
  for (auto _ : state) {
    long r = cb_h3c_run(c);
    benchmark::DoNotOptimize(r);
  }
  state.SetItemsProcessed(state.iterations() * kRequests);
  cb_h3c_free(c);
}
BENCHMARK_CAPTURE(BM_h3_client, browser, H_BROWSER);
BENCHMARK_CAPTURE(BM_h3_client, grpc, H_GRPC);
BENCHMARK_CAPTURE(BM_h3_client, h2load, H_H2LOAD);

// the request blocks of one connection through hp_enc, the indexing encoder (a fresh table per pass)
static void BM_hpack_encode(benchmark::State &state, int set) {
  cb_h2c *c = cb_h2c_new(set);
  for (auto _ : state) {
    long r = cb_hpack_encode(c);
    benchmark::DoNotOptimize(r);
  }
  state.SetItemsProcessed(state.iterations() * kRequests);
  cb_h2c_free(c);
}
BENCHMARK_CAPTURE(BM_hpack_encode, browser, H_BROWSER);
BENCHMARK_CAPTURE(BM_hpack_encode, grpc, H_GRPC);

BENCHMARK_MAIN();
