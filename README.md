# cursed-http-parser

![CI](https://github.com/public/cursed-http-parser/actions/workflows/ci.yml/badge.svg)
![License: MIT](https://img.shields.io/badge/license-MIT-orange)

Fast HTTP/1.1 request parsers in C, built on SIMD bitmasks (AVX2, AVX-512, NEON, with a scalar fallback).
They are header-only, stateless and never allocate.

This repository holds three single-header parsers plus a learning mode:
- **[`fastparse.h`](include/fastparse.h)**, a fast path for *your* API. Its routes are generated from a JSON spec,
  and it hands back the route, the numeric id, the `Bearer` token and the body framing directly.
- **`fast_parse_learn()`**, the learning mode of fastparse.h. It learns each route's most common header layout at
  runtime and checks later requests against that layout, with results identical to `fast_parse`.
- **[`fbparse.h`](include/fbparse.h)**, a general parser with picohttpparser's API and exactly its results.
- **[`batchparse.h`](include/batchparse.h)**, which parses many connections' requests in one lane-parallel call.

## Features

* **Bitmask parsing.** One ISA-specific step classifies 64 bytes into bitmasks; everything else is portable C on
  those masks.
* **Stateless, zero-copy, no allocation.** Results point into your buffer, and partial requests just return
  "need more".
* **Spec-generated routing.** `gen/httpgen.py` compiles your routes into canonical request-line templates matched
  with 64-bit compares. It can be profile-guided, and the profile contributes decisions only, never bytes.
* **Safe by construction, not by hope.**
  - Anything unusual returns `FP_FALLBACK`: HTTP/1.0, chunked, obs-fold, a bare CR, an odd Content-Length.
  - `fbparse.h` takes those requests with picohttpparser's exact accept/reject.
  - 298 third-party conformance cases (llhttp, HTTP Garden, picohttpparser, httparse) give 0 framing mismatches.
* **A drop-in for picohttpparser.** `fb_parse_request` has `phr_parse_request`'s signature and returns
  identical results on every input, including the -1 vs -2 decisions. Millions of differential inputs check that
  on every run.
* **Tested hard.** Differential fuzzing against picohttpparser, ASan/UBSan, planted-bug (mutation) checks, and
  real AVX-512 runs on a Xeon.

## Are we fast?

![benchmark chart](bench/bench.svg)

Intel Xeon Platinum 8260 (Cascade Lake), Ubuntu 24.04, kernel 6.8, gcc 13.3 `-O3 -march=native`, ns per request.
Each competitor is built at least as aggressively as its own project builds it (see
[Build flags](#build-flags-of-the-comparisons)). "+logic" means the general parser plus the same routing / Bearer /
Content-Length work fastparse does; that's the like-for-like column. Every parser + logic must agree with
fastparse on every request before it's timed.

**API traffic** (read-heavy mix, +logic):

| parser | ns/req | |
|---|---|---|
| **fastparse.h** (AVX2) | **46.7** | 1× |
| fastparse.h, generated from the spec + profile | 44.8 | 0.96× |
| lightning (C, AVX2/SSE4.2) | 95.4 | 2.0× slower |
| picohttpparser (SSE4.2) | 108.8 | 2.3× slower |
| hparse (Zig) ¹ | 122.9 | 2.6× slower |
| uWebSockets 20.80 (C++) | 126.1 | 2.7× slower |
| llhttp 9.4.3 (Node.js) | 254.4 | 5.4× slower |
| fasthttp 1.76 (Go) ² | 392.7 | 8.4× slower |
| http-parser 2.9.4 (Node.js, legacy) | 396.9 | 8.5× slower |

**General traffic** (fbparse.h against the general parsers, +logic):

| corpus | **fbparse.h** | lightning | picohttpparser | llhttp | hparse ¹ | fasthttp ² | http-parser |
|---|---|---|---|---|---|---|---|
| curl (181 B) | **101.7** | 114.6 | 125.8 | 321.0 | 157.4 | 485.1 | 611.4 |
| Chrome (1,040 B) | **353.9** | 405.0 | 442.9 | 1,059.5 | 716.6 | 1,546.8 | 2,970.3 |
| Firefox (813 B) | **339.4** | 364.0 | 402.0 | 949.7 | 572.5 | 1,365.9 | 2,425.8 |
| long headers (11 KB) | **595.5** | 615.2 | 1,542.2 | 4,758.4 | 3,252.7 | 5,574.2 | 26,015.6 |

**Raw parse, fbparse.h vs the fastest competitor (lightning).** These are medians over 8 code layouts × 3 rounds of
back-to-back pairs (see [Method](#method)):

| | k6 | gocli | curl | Chrome | Firefox | HTTP/1.0 | long headers | chunked |
|---|---|---|---|---|---|---|---|---|
| fbparse.h vs lightning | **−8.2%** | **−6.3%** | **−5.1%** | **−7.0%** | +1.5% | **−4.4%** | **−1.5%** | **−5.9%** |
| fbparse.h vs picohttpparser | **−13.6%** | **−11.2%** | **−13.0%** | **−18.3%** | **−8.1%** | **−16.2%** | **−61.7%** | **−13.3%** |

Lightning validates nothing: no token characters, no control bytes in values. fbparse.h checks every byte as
picohttpparser does, and still wins every corpus but one by raw time, and every corpus once the routing work is
added.

On an Apple M5 Pro, fbparse.h is the fastest general parser on every corpus, raw and +logic, against picohttpparser,
two Armv8-A NEON forks of it, lightning, llhttp, uWebSockets and http-parser. fastparse.h does the API mix in 14.2 ns,
against 40.3 for the best general parser.

¹ hparse and httparse need Zig and Rust toolchains, which the Xeon box doesn't have; hparse's numbers are from an
earlier run of the same harness. httparse was measured on Linux arm64 only; see below.
² fasthttp is Go. It is measured by its own harness on the same request bytes (`make compare-go`): it parses with
`RequestHeader.Read`, as its server does, and its "+logic" is the same routing in Go. There is no shared correctness
gate across languages; it accepted every request.

- **batchparse.h** at 16 connections per call is 4–7% faster than 16 `fast_parse` calls on mixed traffic and
  7–13% faster on GET-only traffic. 16 picohttpparser calls are about 2.2× slower.

Reproduce:

```bash
make bench
```

This runs pico and llhttp, which are vendored. To add uWebSockets, lightning, http-parser, the Armv8-A pico forks,
httparse (rustc) and hparse (zig 0.15), fetched at pinned commits:

```bash
make compare-all
```

fasthttp needs Go 1.26 or newer:

```bash
make compare-go
```

The full tables and the method are under [Benchmarks](#benchmarks).

## Usage

The example below reads a request from socket `sock` using `read(2)`. It parses the request with `fast_parse`,
passes anything unusual to `fbparse`, and prints what it got. It is
[`examples/read_loop.c`](examples/read_loop.c), and `make test` builds and runs it.

```c
#include "fastparse.h"
#include "fbparse.h"

char buf[8192 + 64];                       /* + 64: readable padding after the data, any contents */
int buflen = 0, ret;
req_t req;

while (1) {
    /* read the request */
    ssize_t n;
    while ((n = read(sock, buf + buflen, sizeof buf - 64 - buflen)) == -1 && errno == EINTR)
        ;
    if (n <= 0)
        return IOError;
    buflen += n;
    /* parse it: the API's canonical requests on the fast path, everything else pico-exact */
    ret = fast_parse(buf, buflen, &req);
    if (ret == FP_FALLBACK) {
        fb_info_t info;
        ret = fb_parse_req_ex(buf, buflen, &req, &info);
        if (ret == FP_FALLBACK && info.flags == FB_MINOR)
            ret = info.total;              /* HTTP/1.0: fine too */
    }
    if (ret > 0)
        break;                             /* complete request: head + body */
    if (ret == -2 || ret == FP_FALLBACK)
        return BadRequest;                 /* invalid, or chunked / odd Content-Length (or 501) */
    /* FP_NEED_MORE: request is incomplete, continue the loop */
    if (buflen == sizeof buf - 64)
        return RequestIsTooLongError;
}

printf("request is %d bytes, route %d\n", ret, req.route);
if (req.id_ok) printf("id is %lld\n", (long long)req.id);
if (req.auth)  printf("bearer token is %.*s\n", req.tok_len, req.tok);
printf("body is %d bytes at offset %d\n", req.body_len, req.body_off);
```

**Many connections at once:**

```c
bp_parse(n, bufs, lens, reqs, rets);   /* rets[i] == fast_parse(bufs[i], lens[i], &reqs[i]) */
```

**As a drop-in for picohttpparser:** keep your `phr_parse_request` call, rename it to `fb_parse_request`, and use
`struct fb_header`. That struct has the same layout as `struct phr_header`.

## Installation

The parsers are header-only. Copy `include/` into your tree, then add `-march=native` (x86) or `-mcpu=native`
(ARM); see the [build matrix](#build-matrix).

For your own routes, generate the header from your spec:

```bash
python3 gen/httpgen.py gen my_spec.json --base include/fastparse.h -o fastparse_my_api.h
```

To run the tests and benchmarks you need `cc`, `make` and `python3`:

```bash
make test
```

```bash
make bench
```

## Contents

- [Why it's fast](#why-its-fast)
- [API](#api)
- [The spec and the generator](#the-spec-and-the-generator)
- [Build matrix](#build-matrix)
- [Build and test](#build-and-test)
- [Correctness](#correctness)
- [Benchmarks](#benchmarks)
- [Limits and semantic differences](#limits-and-semantic-differences)
- [Acknowledgements](#acknowledgements)
- [Licence](#licence)

## Why it's fast

**fastparse.h**
- **One ISA-specific step.** Each backend has one function that turns 64 bytes into 64-bit masks. Everything
  else is shared C on masks and SWAR words.
  - AVX2: `vpcmpeqb` + `vpmovmskb`.
  - AVX-512: compares straight into `k` registers, on ymm by default.
  - NEON: `vld4q` + a `vsri` chain + `shrn #4` instead of a movemask.
  - Scalar: SWAR plus a multiply-gather.
- **End of headers from the LF mask alone.** Candidates are `lf & lf<<1` and `lf & lf<<2`, confirmed with byte
  loads. There's no CR mask.
- **Canonical request lines are matched from the first bytes.** For example `GET /posts/<digits> HTTP/1.1\r\n`
  is matched with 64-bit compares and a SWAR atoi, independent of the LF scan, so the route's branch resolves
  early. This was the biggest single win (14.4 → 10.5 ns on an Apple M5).
- **Only the header lines that matter are visited.** On GET routes only lines starting with `c`/`t` are looked
  at (`Content-Length`, `Transfer-Encoding`), found straight from a second mask: a typical GET never touches a
  header line. Routes that need `Authorization` walk every line start off the LF mask.
- **No token-character validation.** That is the main reason it beats general parsers even before their
  routing logic. It is safe for the values it returns, and it is spelled out under
  [Limits](#limits-and-semantic-differences).
- **Optional learned layout** (`fast_parse_learn`). Per route, it learns the most common header layout at
  runtime and checks later requests against it with independent compares, with identical results. It helps
  pipelined batches; it doesn't help single calls on real hardware.

**fbparse.h**
- **Same mask approach for pico's grammar.** There are four predicates: not-a-token-char (pico's
  `token_char_map` as a nibble LUT: two `pshufb`/`tbl` + AND), value end, path end, and LF.
- **Lazy classification.** Each predicate is classified per 64-byte block only when a search reaches that
  block.
- **Lines don't wait on each other.** Header line starts come straight from the LF mask, so a line doesn't wait
  for the previous line's name/value scans. That is −20% on long heads.
- **Long values stream like `memchr`.** Once a line has run past three blocks (a big cookie, a trace id), fbparse
  stops building exact masks and tests "could there be a control byte in the next 256–512 bytes?":
  - the windows are aligned to the address, so loads never split cache lines;
  - the test is two vector ops per 32 bytes: (int8)(x + 1) < 0x21 catches every control byte and DEL, and
    over-approximates on bytes ≥ 0x80, which just send that window to the exact path;
  - the loop prefetches 3 KB ahead.

  It then finds the line end with exact masks over the hit window, in one loop. On 11 KB heads this streams at
  `memchr` speed while still validating every byte (429 → 163 ns on the M5, 812 → 576 ns on the Xeon). Short and
  medium lines never enter it.

**batchparse.h**
- **The gain is mostly scheduling, not SIMD.** Request lines of all lanes are classified first, then lanes are
  bucketed by route shape with branch-free appends. Each loop then runs one shape only, so its branches are
  predictable over a random mix, and the out-of-order core overlaps the lanes' cache misses.
- **Vector request-line variants.** They gather the first 24 bytes of 4 or 8 requests with `vpgatherqq` (NULL
  base, the pointers are the indices), count id digits with `psadbw`/`vplzcntq` and convert them with
  `pmaddubsw → pmaddwd → pmuludq`. They are correct, but slower than the per-lane matcher on Cascade Lake
  because gathers are expensive. They stay selectable for experiments.

## API

All three headers are header-only and C99/C11 (GCC or Clang builtins and intrinsics). Include them, compile with
the right `-march`, done. **Padding contract:** every buffer must have at least 64 readable bytes after
`buf[len]`, any contents. Allocate receive buffers with 64 extra bytes.

### fastparse.h

```c
#include "fastparse.h"

enum { R_NOTFOUND, R_FEED, R_HEALTH, R_GETPOST, R_CREATE, R_LIKE };  // from the spec (example API)
enum { FP_NEED_MORE = 0, FP_FALLBACK = -1, FP_FULL = 1 };
typedef struct {
  int route;
  int id_ok; int64_t id;                    // {id} path parameter: positive integer, 1..16 digits
  int auth; const char *tok; int tok_len;   // "Authorization: Bearer <tok>", routes with "auth" only; points into buf
  int body_off, body_len;                   // body_off is relative to the buf you passed
} req_t;

int fast_parse(const char *buf, int len, req_t *r);   // > 0 bytes consumed (head + body) | FP_NEED_MORE | FP_FALLBACK
int fast_parse_scalar(const char *buf, int len, req_t *r);   // reference: scalar backend

typedef struct { int n, used, status; } fp_batch_t;   // pipelined requests in one buffer
fp_batch_t fast_parse_many(const char *buf, int len, req_t *out, int max);
//   n requests parsed, `used` bytes consumed; status describes buf + used:
//   FP_NEED_MORE (incomplete or empty), FP_FALLBACK (that request needs the slow path), FP_FULL (out[] is full)

fp_learn_t T = {0};                                    // 5.6 KB, one per thread, zero-initialised
int fast_parse_learn(const char *buf, int len, req_t *r, fp_learn_t *T);   // same results as fast_parse
fp_batch_t fast_parse_many_learn(const char *buf, int len, req_t *out, int max, fp_learn_t *T);
```

`FP_FALLBACK` is always safe: hand the bytes to a full parser (`fb_parse_req`) or answer 400.

### fbparse.h

```c
#include "fbparse.h"   // standalone; the req_t adapter needs fastparse.h included first

// picohttpparser's phr_parse_request: same arguments, same results (struct fb_header == struct phr_header)
int fb_parse_request(const char *buf, size_t len, const char **method, size_t *method_len,
                     const char **path, size_t *path_len, int *minor_version,
                     struct fb_header *headers, size_t *num_headers, size_t last_len);
//   > 0 head bytes, -1 invalid, -2 incomplete; num_headers: in = capacity, out = count

// adapter onto fastparse.h's req_t (routing from the same spec, 48 headers max)
int fb_parse_req(const char *buf, int len, req_t *r);
//   > 0 head + body bytes | FP_NEED_MORE | FP_FALLBACK | -2 invalid (send 400)
int fb_parse_req_ex(const char *buf, int len, req_t *r, fb_info_t *info);
//   same return; info->flags says why it fell back: FB_MINOR (HTTP/1.0 etc.), FB_TE (Transfer-Encoding),
//   FB_BADCL (odd or duplicate Content-Length). With flags == FB_MINOR only, r is filled and info->total
//   is the request size: enough to serve an HTTP/1.0 client.
```

There is no head-size limit. The header count is bounded by the caller's array.

### batchparse.h

```c
#include "batchparse.h"   // includes fastparse.h (override with -DBP_HTTP_H='"my_generated.h"')

const char *buf[n]; int len[n]; req_t out[n]; int ret[n];
bp_parse(n, buf, len, out, ret);   // ret[i] == fast_parse(buf[i], len[i], &out[i]); any n >= 0; lanes may alias
```

One request per lane: the first one in each buffer. Use it at n ≥ 8, and `fast_parse` below that.

## The spec and the generator

Everything API-specific in `fastparse.h` lives between `==== BEGIN API SPEC ====` and `==== END API SPEC ====`:
- the route enum;
- the router;
- the canonical request-line templates;
- three policy hooks.

The hand-written header ships with an example API ([`gen/example_spec.json`](gen/example_spec.json)): `GET /feed`,
`GET /health`, `GET /posts/{id}`, and `POST /posts` and `POST /posts/{id}/like` with bearer auth.

[`gen/httpgen.py`](gen/httpgen.py) regenerates that region for your own spec:

```json
{ "name": "my-api", "params": { "id": { "type": "positive-int", "max_digits": 16 } },
  "routes": [ { "name": "ITEM", "method": "GET", "path": "/items/{id}" },
              { "name": "PUT",  "method": "PUT", "path": "/items/{id}", "auth": "bearer" } ] }
```

```bash
python3 gen/httpgen.py gen my_spec.json --base include/fastparse.h -o my_fastparse.h
```

Optionally, it can be profile-guided:

```bash
python3 gen/httpgen.py profile my_spec.json capture.raw > profile.json
python3 gen/httpgen.py gen my_spec.json --base include/fastparse.h --profile profile.json -o my_fastparse.h
```

`capture.raw` is raw requests back to back. **A profile contributes decisions, never bytes.** It sets the
template order, which routes try the learned layout, and which methods use the walk core. The generator refuses
any non-numeric profile value, so no traffic bytes can reach the C.

The generator also checks the spec:
- it refuses templates another route would shadow;
- it warns about unreachable routes;
- `make gencheck` compares the generated router with the generator's own Python model on 200k vectors, for the
  example spec and for a deliberately awkward [`gen/toy_spec.json`](gen/toy_spec.json).

Spec limits: at most one `{param}` per path, `positive-int` with up to 16 digits, HTTP/1.1, bearer auth only.

`batchparse.h` works with any generated header in its default mode. Its vector request-line variants are
hand-specialised to the example routes, so build with `-DBP_CANON_ONLY` for other specs.
`tests/test_batch_spec.c` checks exactly that, on the toy spec.

## Build matrix

The backend is picked at compile time from the target flags.

| target | flags | backend (`FP_BACKEND_NAME`) | status |
|---|---|---|---|
| x86-64 with AVX2 | `-march=haswell` or newer, `-march=native` | `avx2` | **recommended on x86**, fastest on Cascade Lake |
| x86-64 with AVX-512BW/VL | `-march=cascadelake -DFP_USE_AVX512` | `avx512bw-ymm` | tested on a Xeon Platinum 8260; correct, 3 ns slower than AVX2 there |
| same, 512-bit registers | `... -DFP_USE_AVX512 -DFP_USE_ZMM` | `avx512bw-zmm` | tested; slower on small requests, and zmm triggers frequency-licence drops |
| AArch64 | (default) / `-mcpu=native` | `neon` | tested on Apple M5 (macOS) and Linux arm64 |
| anything else | `-DFP_FORCE_SCALAR` or no SIMD | `scalar` | tested everywhere; 2× slower than SIMD |

Other switches:
- `-DFP_WALK_ONLY`: SIMD backends use the walk core only (an A/B knob).
- `-DFB_WALK=0`: fbparse's sequential header loop (an A/B knob).
- `-DBP_AVX512`: batchparse's zmm variant.
- `-DBP_CANON_ONLY`: see above.

Test builds run the AVX-512 code paths on plain-C intrinsics (`-DFP_AVX512_EMU`, `-DBP_AVX512_EMU`), so their logic
is checked on any machine. Little-endian only.

## Build and test

Needs `cc` (GCC or Clang), `make` and `python3`. Nothing else: picohttpparser and llhttp are vendored for tests and
benchmarks only. The extras below download their third-party sources at pinned commits into `third_party/`
(git-ignored, never redistributed) with `scripts/fetch-thirdparty.sh`.

```bash
make test         # every differential test, all backends the host can run + emulated AVX-512 (~40 s)
make test-quick   # smaller fuzz counts (CI)
make asan         # ASan + UBSan builds (quick mode)
make mutants      # planted bugs: each must make a test fail (read the output)
make bench        # benchmarks (below)
make avx512       # real AVX-512 builds; `make avx512-run` on AVX-512 hardware

# extras (network + c++; rustc for httparse, zig 0.15 for hparse, each skipped when missing)
make conformance  # 298 third-party conformance cases x every truncation (llhttp, HTTP Garden, pico, httparse)
make compare-all  # + uWebSockets, lightning, http-parser, pico Armv8-A forks, httparse, hparse
make compare-go   # + fasthttp (Go >= 1.26) on the same corpora
make extras-check # both, as quick correctness gates (CI / Docker)
```

Linux in Docker, from any host:

```bash
./scripts/docker-test.sh amd64
```

```bash
./scripts/docker-test.sh arm64
```

`DOCKER_CPUS=8-13` pins the container to those CPUs. Each run uses gcc and clang.

## Correctness

The tests are differential: every input is compared against picohttpparser (commit `465a7ff`) with the same
routing logic on top. Any difference fails the test, except where the expected difference is listed per input in
[`tests/edges.h`](tests/edges.h).

**fastparse.h** (`tests/test_fastparse.c`)
- The SIMD masks and the SWAR digit parser are checked against byte loops on 200k random inputs.
- 78 edge cases at every truncation, and 800 block-boundary sweeps at every truncation.
- A 4,096-request corpus in three client shapes, plus every truncation of 300 of them, pipelined pairs, and 30k
  random pipelined batches.
- Fuzzing:
  - 300k mutate + truncate inputs;
  - 300k layout-preserving inputs;
  - 172k header swaps, where a line is rewritten into another name at the same length.
- **Every input is parsed every way and must match `fast_parse` exactly:**
  - both cores × SIMD/scalar classify;
  - the learned path with live tables;
  - `fp_try_layout` against 16 layouts per route (about 390k inputs claimed by a layout, all identical);
  - `fp_quick_get`.

**fbparse.h** (`tests/test_fbparse.c`)
- **0 tolerated differences:** the same return code, including -1 vs -2, and on success every output pointer and
  length.
- Inputs:
  - the edge cases, the corpus, and 7 fallback shapes (curl, Chrome, Firefox, HTTP/1.0, 2–20 KB heads, chunked,
    odd);
  - 1,680 block-boundary sweeps;
  - 2M mutations and 500k piece strings;
  - random header capacities and `last_len`.
- Each input is checked with both header loops, both classify paths and two paddings.
- Optionally, `FB_CASES=file` adds a corpus of third-party conformance cases (format in the test).

**batchparse.h** (`tests/test_batch.c`, `tests/test_batch_spec.c`)
- About 2.5M lanes per variant, in random mixed batches of 1–100.
- Lanes are separate mallocs with real continuation bytes after `len`, and some lanes alias.
- Every lane must equal `fast_parse`.
- The same check runs on the generated header, and on the toy spec with `-DBP_CANON_ONLY`.

**The tests catch planted bugs.** `make mutants` plants 32 bugs in fbparse.h (including 5 in the long-value skip
loop) and 9 in batchparse.h. Every one
fails on the platform it targets; the zero lines are backend-specific mutants run on another platform, plus one
deliberate no-op. During development, planted bugs in fastparse.h were caught as well. One of them survived plain
fuzzing, which is why the header-swap fuzzer exists.

**Conformance.** fastparse.h was also run against 298 cases from four third-party suites, with every truncation
of each (26,821 inputs):
- llhttp's request tests;
- HTTP Garden's request-smuggling trophies;
- picohttpparser's tests;
- httparse's tests.

The first run found 5 framing ambiguities that could matter for request smuggling. All are fixed and now fall
back:
- CR read as `-` in `Content\rLength`;
- `Content-Length : 4`;
- a bare CR in a header;
- obs-fold;
- a header name split across lines.

After the fixes, every backend has **0 mismatches and 0 stalls**, and the 5 shapes are fixed cases in
`tests/edges.h`. `make conformance` reruns it: it fetches the suites at pinned commits (HTTP Garden is GPL-3.0, so
it is downloaded, not shipped), extracts the cases with `conformance/extract.py`, and judges every input against
llhttp (strict, full message framing), pico + the same routing logic, and uWebSockets. It also feeds the same
cases to `tests/test_fbparse.c` (`FB_CASES`), where fbparse must match pico exactly. Current result:

```
298 cases (+26821 truncations):
  AGREE 26 · RELAXED 3 · ACCEPT-INVALID 4 · FALLBACK 164 · NEED_MORE 101 · MISMATCH 0 · STALL 0
```

The 7 inputs accepted against some reference's rejection don't affect framing or any returned field (for example
`Connection : upgrade`, or a form feed in a header value). The report lists each one in
`build/conformance-report.txt`.

**Platforms run:**

| platform | compilers | result |
|---|---|---|
| macOS arm64 (Apple M5 Pro) | Apple clang 21 | all tests, ASan/UBSan, mutants |
| Linux arm64 (Ubuntu 24.04, Docker) | gcc 13.3, clang 18.1 | all tests, ASan/UBSan |
| Linux amd64 (Ubuntu 24.04, Docker) | gcc 13.3, clang 18.1 | all tests (AVX2), ASan/UBSan, AVX-512 builds compile |
| Intel Xeon Platinum 8260 (Ubuntu 24.04, kernel 6.8) | gcc 13.3, clang 18.1 | all tests on real AVX2, AVX-512 ymm and zmm |

## Benchmarks

### Method

- **Units.** Every number is ns per request, hot cache: the best of 40–300 passes over the corpus.
- **Calls.** Every parser is called through a `noinline` function.
- **Order and buffers.** Requests run in random order, so branch mispredicts count, and each one sits in its own
  buffer.
- **The API corpus** is 4,096 requests in a read-heavy mix: 46% `GET /feed`, 46% `GET /posts/:id`, 7% `POST like`,
  1% `POST /posts`, the POSTs with a ~150-byte JWT.
  - It is formatted the way a minimal Go load generator writes requests, with `Accept-Encoding: gzip`: the
    "gocli -gzip" corpus. k6's format gives the same ordering.
- **The general corpora** are 512 requests per shape: curl, Chrome, Firefox, HTTP/1.0, 2–20 KB heads with big
  cookies ("long headers"), chunked POSTs, and odd but valid shapes.
- **Raw and +logic.** General parsers are measured two ways:
  - **raw** is the parse alone;
  - **+logic** adds exactly fastparse's job (route, id, Bearer token, Content-Length). +logic is the apples-to-apples
    number.
- **Correctness gate.** Each parser + logic must agree with `fast_parse` (or with pico's reference, for fbparse) on
  every request before it is timed. A `[n]` next to a number means it disagreed on n requests. Those parsers reject
  or accept differently from pico on odd inputs, so their "odd" column isn't comparable.
- **Code layout is randomised for the close calls.** On Cascade Lake the same parser's speed moves by 10–25%
  depending on where its code lands in memory (jump alignment, the JCC-erratum microcode), for every parser alike.
  So the "fbparse vs lightning" comparison works like this:
  - every parser is built in 8 layouts, shifting all code by 0–112 bytes (`-DPAD_BYTES`, `bench/perf_one.c`);
  - each fbparse / lightning / pico triple runs back to back, so slow phases of the shared VM affect all three alike;
  - the result is the median of the per-triple ratios over 8 layouts × 3 rounds.

**Hardware.**
- **Xeon:** Intel Xeon Platinum 8260 (Cascade Lake, 2.4 GHz, AVX-512, no SHA-NI), 1 vCPU VM, Ubuntu 24.04,
  kernel 6.8, gcc 13.3 `-O3 -march=native`, steal ≤ 0.01%.
- **ARM:** Apple M5 Pro, macOS, Apple clang 21, `-O3 -mcpu=native`. Linux arm64 numbers come from Docker on the same
  machine, with gcc 13.3.

### Build flags of the comparisons

Every competitor is built at least as aggressively as its own project builds it for release or benchmarks. Every
C/C++ parser, ours included, uses the same compiler and the same `-O3 -march=native`.

| parser | its own release / benchmark build | ours |
|---|---|---|
| picohttpparser | `-O2 -msse4.2` in H2O (its Makefile only builds tests) | `-O3 -march=native` (SSE4.2 path on x86) |
| picohttpparser Armv8-A forks ([volyrique](https://github.com/volyrique/picohttpparser) `armv8-a`, `armv8-a+tbl`) | as pico | `-O3 -mcpu=native` (NEON paths; ARM only) |
| lightning | CMake Release: `-O3 -DNDEBUG -mavx2` | `-O3 -DNDEBUG -march=native` |
| llhttp | CMake RelWithDebInfo, `-O2 -g` | `-O3 -march=native` |
| http-parser (Node.js, legacy) | `-O3` | `-O3 -march=native` |
| uWebSockets | `build.c`: `-march=native -O3 -std=c++2b -flto` | `-O3 -march=native -std=c++2b` (the parser is header-only in one TU, so LTO changes nothing) |
| httparse | `[profile.bench]`: opt-level 3, `lto = true`, `codegen-units = 1`; SIMD cfgs from `build.rs` | the same, plus `target-cpu=native` (as its AVX2 bench) |
| hparse | `zig build -Doptimize=ReleaseFast` (`-Dcpu=skylake` in its x86 bench) | ReleaseFast, `-mcpu=native` |
| fasthttp | `go build` (Go has no optimisation flags) | `go build`, Go 1.27.3, no PGO |

The harness treats every parser the same way:
- the general parsers get picohttpparser's `phr_parse_request` signature through a thin shim, which copies at most 8
  header structs (a few ns, counted against them);
- the same timing loop applies to all.

Ours does less work than a general parser where the README says so: fastparse doesn't validate token characters (see
[Limits](#limits-and-semantic-differences)). fbparse validates exactly as much as picohttpparser. Lightning validates
nothing.

### fastparse.h vs general parsers (`make bench` → `build/compare`; `make compare-all` adds the fetched ones)

Xeon, gocli -gzip corpus, raw / +logic:

| | mix | GET /feed | GET /posts/:id | POST like |
|---|---|---|---|---|
| lightning (C, AVX2) | 74.4 / **95.4** | 69.6 / 78.4 | 70.0 / 88.8 | 114.2 / 148.8 |
| picohttpparser (SSE4.2) | 85.8 / **108.8** | 73.8 / 85.1 | 76.2 / 96.4 | 124.3 / 161.4 |
| uWebSockets 20.80.0 (C++) | 107.7 / **126.1** | 85.8 / 99.3 | 88.4 / 109.7 | 138.9 / 176.1 |
| llhttp 9.4.3 | 227.3 / **254.4** | 195.6 / 211.5 | 205.7 / 233.5 | 372.2 / 415.7 |
| http-parser 2.9.4 | 372.3 / **396.9** | 282.1 / 293.8 | 332.7 / 356.1 | 956.2 / 995.3 |
| **fastparse, AVX2** | **46.7** | 31.1 | 36.0 | 93.1 |
| fastparse, generated from the spec | 45.6 | 30.7 | 35.1 | 87.0 |
| fastparse, generated, spec + profile | **44.8** | 30.8 | 34.4 | 84.3 |
| fastparse, learned layout | 49.2 | 29.3 | 36.6 | 94.4 |
| fastparse, scalar backend | 93.5 | 65.6 | 77.5 | 197.2 |

hparse (Zig) measured 97.2 / 122.9 on the mix in an earlier run of the same harness. fasthttp (Go) is at 355.1 /
392.7.

On the Xeon, AVX-512 (ymm or zmm), the walk-only core and the learned layout are correct but not faster than the
AVX2 default. Use `-march=native` with no `FP_*` flags, or a generated header.

Apple M5 Pro, gocli -gzip corpus, raw / +logic:

| | mix | GET /feed | GET /posts/:id | POST like |
|---|---|---|---|---|
| picohttpparser (no SIMD on ARM) | 35.2 / 41.7 | 23.8 / 27.4 | 28.1 / 33.8 | 74.3 / 99.1 |
| pico, Armv8-A TBL fork | 35.4 / **40.3** | 22.2 / 26.7 | 28.1 / 32.4 | 75.1 / 97.9 |
| pico, Armv8-A NEON fork | 33.7 / 42.2 | 28.0 / 32.5 | 32.4 / 38.9 | 48.6 / 71.4 |
| lightning (scalar on ARM) | 43.5 / 51.3 | 32.5 / 33.9 | 33.1 / 41.0 | 62.4 / 90.9 |
| uWebSockets | 51.5 / 57.4 | 44.1 / 45.5 | 44.9 / 49.4 | 69.7 / 93.8 |
| llhttp | 66.2 / 75.7 | 55.6 / 61.7 | 58.7 / 68.0 | 96.2 / 119.8 |
| http-parser | 106.9 / 116.5 | 85.0 / 87.1 | 97.3 / 101.4 | 236.4 / 259.5 |
| **fastparse NEON** | **14.2** | 9.1 | 10.7 | 29.4 |
| fastparse NEON, generated + profile | 14.9 | 9.9 | 10.9 | 29.6 |
| fastparse NEON, learned layout | 15.4 | 9.0 | 10.3 | 30.9 |
| fastparse scalar | 29.8 | 19.5 | 21.9 | 44.9 |

fasthttp (Go 1.27, M5) is at 113.1 / 117.2.

Linux arm64 (Docker on the M5, gcc 13.3 and rustc 1.75), with httparse built like its own bench profile, from one
run, raw / +logic on the mix:
- picohttpparser 35.5 / 41.9;
- httparse 41.3 / 46.7;
- llhttp 69.7 / 78.5;
- **fastparse 16.4**.

uWebSockets swings between about 35 and 95 ns from run to run under Linux on this machine, so it's left out there.

**Which to build.**
- On x86, use the AVX2 default (`-march=native`, no `FP_*` flags), or a generated header (equal within ±2 ns).
- Parsing is 10–50 ns of a request that costs tens of µs in a real server. Treat this as removing the parser from the
  profile, not as a throughput multiplier.

### fbparse.h vs general parsers (`build/bench_fbparse`; `make compare-all` adds the fetched ones)

Xeon, raw / +logic, ns/request:

| corpus (avg bytes) | **fbparse AVX2** | lightning | picohttpparser | llhttp | http-parser |
|---|---|---|---|---|---|
| curl (181) | **88.6 / 101.7** | 91.3 / 114.6 | 102.6 / 125.8 | 289.0 / 321.0 | 575.4 / 611.4 |
| Chrome (1040) | 325.8 / **353.9** | 315.5 / 405.0 | 368.9 / 442.9 | 966.9 / 1059.5 | 2879.2 / 2970.3 |
| Firefox (813) | 326.5 / **339.4** | 297.7 / 364.0 | 331.7 / 402.0 | 872.0 / 949.7 | 2342.1 / 2425.8 |
| HTTP/1.0 (166) | 91.8 / **88.0** | 90.1 / 91.5 | 107.8 / 108.3 | 286.8 / 288.3 | 578.9 / 581.8 |
| long headers (11206) | **575.7 / 595.5** | 581.0 / 615.2 | 1505.3 / 1542.2 | 4721.2 / 4758.4 | 25963.8 / 26015.6 |
| chunked POST (456) | **161.3 / 165.8** | 162.5 / 182.5 | 175.8 / 200.2 | 511.7 / 547.0 | 1279.2 / 1316.9 |
| odd (246) | 193.9 / 247.8 | 178.9 / 209.3 [167] | 224.8 / 258.9 | 262.7 / 272.7 [1546] | 916.7 / 943.7 [667] |
| k6 (130) | **69.9 / 82.2** | 74.9 / 93.8 | 81.0 / 101.6 | 227.9 / 255.4 | 430.6 / 470.3 |
| gocli (80) | **52.7 / 65.9** | 59.4 / 76.5 | 64.3 / 83.7 | 183.7 / 210.5 | 308.3 / 335.5 |

This table is one layout. The layout-randomised medians above are the better guide where the numbers are close: raw
Chrome is −7.0% against lightning there, and raw Firefox +1.5%.

fasthttp (Go) +logic on the same corpora: curl 485.1, Chrome 1546.8, Firefox 1365.9, HTTP/1.0 533.3, long headers
5574.2, chunked 920.6. hparse +logic, from the earlier run: curl 157.4, Chrome 716.6, Firefox 572.5, long headers
3252.7.

**Server path** (fast_parse, then fbparse on fallback), Xeon, ns/request:

| | fast + fbparse | fast + pico |
|---|---|---|
| HTTP/1.0 | 125.7 | 141.4 |
| long headers | 1293.8 | 2236.5 |
| chunked | 263.8 | 293.5 |

Apple M5 Pro, raw / +logic:

| corpus | **fbparse NEON** | pico NEON fork | pico TBL fork | picohttpparser | lightning | llhttp |
|---|---|---|---|---|---|---|
| curl | **32.5 / 37.4** | 37.8 / 50.5 | 48.8 / 61.0 | 47.9 / 59.8 | 58.1 / 71.0 | 83.0 / 97.9 |
| Chrome | **124.8 / 133.8** | 152.1 / 179.2 | 208.0 / 234.6 | 220.0 / 245.6 | 205.3 / 231.2 | 263.4 / 292.2 |
| Firefox | **111.3 / 131.1** | 139.6 / 170.2 | 176.5 / 207.8 | 184.6 / 214.6 | 196.0 / 225.6 | 236.6 / 266.6 |
| HTTP/1.0 | **32.5 / 35.6** | 38.8 / 39.1 | 49.8 / 50.5 | 51.3 / 52.2 | 54.2 / 54.7 | 83.0 / 83.3 |
| long headers | **163.1 / 168.7** | 198.5 / 217.5 | 1718.0 / 1735.6 | 1713.4 / 1731.4 | 275.4 / 293.0 | 463.6 / 481.0 |
| chunked POST | **53.5 / 55.9** | 70.3 / 91.8 | 89.4 / 111.6 | 98.4 / 121.6 | 106.4 / 133.3 | 143.3 / 167.5 |
| k6 | **22.0 / 29.3** | 29.8 / 38.8 | 35.2 / 41.0 | 35.4 / 41.5 | 39.8 / 48.3 | 69.3 / 75.9 |
| gocli | **15.1 / 22.7** | 21.0 / 29.8 | 26.9 / 31.7 | 24.9 / 30.8 | 30.5 / 38.1 | 55.2 / 62.3 |

Linux arm64 (Docker on the M5, gcc 13.3), +logic, with httparse (Rust, NEON) from the same run: curl 39.3 against
httparse's 56.9; Chrome 140.4 against 170.7; k6 29.3 against 44.3; gocli 22.2 against 39.6.

Variants on the Xeon:
- AVX-512 ymm ≈ AVX2;
- zmm is 10–15% slower on small requests;
- the sequential loop is about 1.7× slower on long heads;
- the scalar backend is 4–6× slower.

### batchparse.h vs fast_parse × N (`build/bench_batch`)

Xeon, gocli -gzip mix, each request in its own buffer:

| batch | vs fast_parse × N |
|---|---|
| N = 1 | +8 to +24% (no overlap possible) |
| N = 4 | about −5% |
| N = 16–32, mixed traffic | **−4 to −7%** |
| N = 16, GET-only | −7 to −13% |
| N = 16, POST-only | +3 to +7% |

picohttpparser × N with the same logic is about 2.2× slower than `bp_parse`. Of the request-line variants, per-lane
canon is the fastest on the Xeon at every batch size. The AVX2 gather variant reaches parity and zmm trails it.

## Limits and semantic differences

fastparse.h is deliberately partial: what it doesn't check, it either ignores safely or declines with
`FP_FALLBACK`.

**Not validated:**
- token characters;
- control characters in the method, path or header values;
- header lines without a colon (ignored);
- empty header names;
- more than 48 headers.

Requests pico rejects may therefore be accepted (about a third of random fuzz inputs). The values it returns are
parsed strictly: route, id, Content-Length, and the Bearer token, which you should verify cryptographically
anyway.

**Always falls back:**
- anything but HTTP/1.1, and a request line ending in a bare LF;
- a header block not ending in `\r\n\r\n`;
- a bare CR anywhere in the head;
- obs-fold, i.e. a header line starting with SP/HT/control;
- a `c`/`t` header line without `:`;
- `content-length` not directly followed by `:`;
- any `transfer*` header;
- an odd or duplicate Content-Length (only 1–9 digits are accepted);
- a leading empty line;
- heads over 8 KB.

**One accepted difference from pico + logic:** a Content-Length with leading zeros (`012` = 12).

**Routing and Authorization:**
- ids are 1–16 digits, leading zeros allowed;
- `0`, 17+ digits or non-digits give `id_ok = 0`;
- `/posts/x/y` is NOTFOUND;
- `Authorization` is only extracted on routes with `"auth": "bearer"`, and the first one wins;
- `Bearer ` is case-sensitive with one SP.

**Other limits:**
- `fp_learn_t` is per thread, not thread-safe.
- POST layouts rarely stick in the learned path, because token lengths vary.
- The spec format is as listed above.
- picohttpparser itself is undefined for `last_len > len + 3`, and so is `fb_parse_request`.

## Acknowledgements

This project builds on, and is measured against:

* [h2o/picohttpparser](https://github.com/h2o/picohttpparser): the reference every test compares against, and the
  API `fbparse.h` reproduces
* [nodejs/llhttp](https://github.com/nodejs/llhttp), [nodejs/http-parser](https://github.com/nodejs/http-parser),
  [seanmonstar/httparse](https://github.com/seanmonstar/httparse), [nikneym/hparse](https://github.com/nikneym/hparse),
  [uNetworking/uWebSockets](https://github.com/uNetworking/uWebSockets),
  [softwaredc/lightning](https://github.com/softwaredc/lightning), [valyala/fasthttp](https://github.com/valyala/fasthttp)
  and [volyrique's Armv8-A picohttpparser branches](https://github.com/volyrique/picohttpparser): comparison and
  conformance references
* [narfindustries/http-garden](https://github.com/narfindustries/http-garden): request-smuggling payloads that
  found real framing bugs here
* [simdjson](https://github.com/simdjson/simdjson) and Geoff Langdale's and Daniel Lemire's work on bitmask
  parsing
* [SWAR explained: parsing eight digits](https://lemire.me/blog/2022/01/21/swar-explained-parsing-eight-digits/)
  by Daniel Lemire
* [Bit Twiddling Hacks](https://graphics.stanford.edu/~seander/bithacks.html) by Sean Eron Anderson

## Licence

MIT, see [LICENSE](LICENSE). Vendored test and benchmark code (picohttpparser, llhttp) keeps its own licence; see
[THIRD_PARTY.md](THIRD_PARTY.md).
