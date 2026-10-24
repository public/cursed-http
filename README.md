# cursed-http-parser

Three single-header C parsers for HTTP/1.1 requests, built to be fast on x86-64 (AVX2, AVX-512) and
ARM64 (NEON), with a portable scalar fallback:

| header | what it is | typical cost |
|---|---|---|
| [`include/fastparse.h`](include/fastparse.h) | **Fast path for one known API.** Its routes are generated from a JSON spec. It returns the route, a numeric path id, the `Bearer` token and the body framing, and says `FP_FALLBACK` for anything unusual | 2.3× faster than picohttpparser doing the same job |
| [`include/fbparse.h`](include/fbparse.h) | **A general parser that matches picohttpparser exactly.** It has pico's `phr_parse_request` API and gives the same result on every input, including every -1/-2 | 16–47% faster than pico on a Xeon |
| [`include/batchparse.h`](include/batchparse.h) | **A lane-parallel batch parser.** It parses N requests from N connections in one call, and gives exactly `fast_parse`'s result per lane | 4–13% faster than N `fast_parse` calls at N ≥ 8 |

The intended server path is `fast_parse` first, then `fbparse` for whatever it declines:

```c
int c = fast_parse(buf, len, &req);              // > 0: done; 0: need more bytes
if (c == FP_FALLBACK) c = fb_parse_req(buf, len, &req);
```

All three are differentially tested against picohttpparser on millions of inputs per run (see
[Correctness](#correctness)).

## Contents

- [Why it's fast](#why-its-fast)
- [API](#api)
- [The spec and the generator](#the-spec-and-the-generator)
- [Build matrix](#build-matrix)
- [Build and test](#build-and-test)
- [Correctness](#correctness)
- [Benchmarks](#benchmarks)
- [Limits and semantic differences](#limits-and-semantic-differences)
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
  block, so a 10 KB cookie costs one cheap mask per 64 bytes.
- **Lines don't wait on each other.** Header line starts come straight from the LF mask, so a line doesn't wait
  for the previous line's name/value scans. That is −20% on long heads.

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
benchmarks only.

```bash
make test         # every differential test, all backends the host can run + emulated AVX-512 (~40 s)
make test-quick   # smaller fuzz counts (CI)
make asan         # ASan + UBSan builds (quick mode)
make mutants      # planted bugs: each must make a test fail (read the output)
make bench        # benchmarks (below)
make avx512       # real AVX-512 builds; `make avx512-run` on AVX-512 hardware
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

**The tests catch planted bugs.** `make mutants` plants 27 bugs in fbparse.h and 9 in batchparse.h. Every one
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

After the fixes, every backend has **0 mismatches and 0 stalls**. The cases are built into tests/edges.h. The
harness isn't shipped, because the HTTP Garden payloads are GPL-3.0.

**Platforms run:**

| platform | compilers | result |
|---|---|---|
| macOS arm64 (Apple M5 Pro) | Apple clang 21 | all tests, ASan/UBSan, mutants |
| Linux arm64 (Ubuntu 24.04, Docker) | gcc 13.3, clang 18.1 | all tests, ASan/UBSan |
| Linux amd64 (Ubuntu 24.04, Docker) | gcc 13.3, clang 18.1 | all tests (AVX2), ASan/UBSan, AVX-512 builds compile |
| Intel Xeon Platinum 8260 (Ubuntu 24.04, kernel 6.8) | gcc 13.3, clang 18.1 | all tests on real AVX2, AVX-512 ymm and zmm |

## Benchmarks

**Method.**
- Every number is ns per request: the best of 50–300 passes over the corpus, hot cache.
- Every parser is called through a `noinline` function.
- Requests are in random order, so branch mispredicts count.
- The corpus is 4,096 requests in a read-heavy mix: 46% `GET /feed`, 46% `GET /posts/:id`, 7% `POST like`,
  1% `POST /posts`, the POSTs with a ~150-byte JWT.
- They're formatted the way a minimal Go load generator writes them, with `Accept-Encoding: gzip` (the
  "gocli -gzip" corpus); k6's format gives the same ordering.
- **General parsers are measured two ways:**
  - **raw** is the parse alone;
  - **+logic** adds exactly fastparse's job (route, id, Bearer token, Content-Length). +logic is the
    apples-to-apples number.
- **Correctness gate.** Each parser+logic must agree with `fast_parse` on every request before it's timed.

**Hardware.**
- Xeon: Intel Xeon Platinum 8260 (Cascade Lake, 2.4 GHz), 1 vCPU VM, Ubuntu 24.04, kernel 6.8, gcc 13.3
  `-O3 -march=native`, steal ≤ 0.01%.
- ARM: Apple M5 Pro, macOS, Apple clang 21, `-O3 -mcpu=native`.

### fastparse.h vs general parsers (`make bench` → `build/compare`)

Xeon, gocli -gzip corpus:

| | mix | GET /feed | GET /posts/:id | POST like |
|---|---|---|---|---|
| picohttpparser (SSE4.2), raw / +logic | 87.1 / **107.2** | 75.4 / 85.0 | 77.2 / 95.5 | 121.6 / 159.6 |
| llhttp 9.4.3, raw / +logic | 220.8 / **248.5** | 191.7 / 205.3 | 200.5 / 226.3 | 367.6 / 411.8 |
| fastparse, AVX2 ¹ | **39.0** | 22.5 | 28.6 | 80.8 |
| fastparse, generated from the spec ¹ | 37.5 | 21.8 | 26.5 | 77.5 |
| fastparse, generated, spec + profile ¹ | 37.0 | 22.0 | 26.4 | 79.2 |
| fastparse, learned layout ¹ | 42.9 | 23.1 | 35.0 | 85.7 |
| fastparse, scalar backend ¹ | 65.4 | 45.0 | 52.2 | 123.8 |
| fastparse, `-DFP_WALK_ONLY` ¹ | 46.5 | 27.0 | 39.5 | 80.4 |
| fastparse, AVX-512 ymm / zmm ¹ | 42.3 / 44.1 | 23.7 / 24.7 | 30.2 / 32.2 | 83.1 / 95.2 |
| **fastparse, current build (with the conformance fixes)** | **47.5** | | | |

¹ Before the conformance fixes. They cost +8.5 ns on this mix (39.0 → 47.5); the rows above are still valid
relative to each other. Against pico+logic re-measured in the same run (108.6 ns), the current build is **2.3×
faster**. It is also faster than pico's raw parse, because it doesn't validate token characters.

On the Xeon, uWebSockets' parser (+logic 122.9) and the Zig hparse (122.9) were measured too, but their harnesses
aren't included. Among general parsers, pico is the fastest there.

Apple M5 Pro, current build (`build/compare`, gocli -gzip corpus, one run, load average ~6.5):

| | mix | GET /feed | GET /posts/:id | POST like |
|---|---|---|---|---|
| picohttpparser (no SIMD on ARM), raw / +logic | 35.6 / 42.5 | 24.2 / 27.6 | 29.3 / 35.2 | 76.8 / 99.4 |
| llhttp, raw / +logic | 67.1 / 77.4 | 57.2 / 62.6 | 58.9 / 66.8 | 97.9 / 122.7 |
| fastparse NEON | **14.4** | 9.5 | 11.6 | 33.5 |
| fastparse NEON, generated + profile | 15.9 | 10.6 | 11.6 | 30.6 |
| fastparse NEON, learned layout | 15.9 | 9.1 | 10.0 | 31.1 |
| fastparse scalar | 29.8 | 19.5 | 21.6 | 45.4 |

**Which to build.**
- On x86, use the AVX2 default with `-march=native` and no `FP_*` flags, or a generated header (equal within
  ±2 ns).
- AVX-512, the walk core and the learned layout are correct but not faster on Cascade Lake.
- Parsing is 10–50 ns of a request that costs tens of µs in a real server. Treat this as removing the parser from
  the profile, not as a throughput multiplier.

### fbparse.h vs picohttpparser and llhttp (`build/bench_fbparse`)

Xeon, +logic (raw in brackets), ns/request:

| corpus (avg bytes) | picohttpparser | **fbparse AVX2** | Δ | llhttp |
|---|---|---|---|---|
| curl (181) | 125.8 (102.4) | **101.7** (85.1) | −19% | 323.1 |
| Chrome (1040) | 448.9 (363.8) | **345.2** (295.6) | −23% | 1056.6 |
| Firefox (813) | 402.1 (328.8) | **347.4** (299.8) | −14% | 948.2 |
| HTTP/1.0 (166) | 108.6 (107.8) | **105.4** (88.1) | −3% | 288.7 |
| long headers (11206) | 1543.7 (1505.3) | **812.4** (780.9) | −47% | 4760.9 |
| chunked POST (456) | 201.3 (176.9) | **167.6** (156.7) | −17% | 550.7 |
| k6 (130) | 101.7 (80.9) | **83.7** (66.8) | −18% | 257.6 |
| gocli (80) | 83.8 (64.4) | **65.0** (49.0) | −22% | 211.9 |

Variants on the Xeon:
- AVX-512 ymm ≈ AVX2.
- zmm is 10–15% slower on small requests; it wins only on long heads.
- The sequential loop ties on small requests and is 25% slower on long heads.
- The scalar backend is 4–6× slower.

**Server path** (fast_parse, then fbparse on fallback), ns/request:

| | fast + fbparse | fast + pico |
|---|---|---|
| HTTP/1.0 | 137 | 143 |
| long headers | 1472 | 2190 |
| chunked | 254 | 294 |

On the Apple M5 (NEON, same load), fbparse +logic vs pico +logic: curl 40.3 vs 58.6, Chrome 150.6 vs 250.2, long
headers 429.7 vs 1761.2, chunked 61.0 vs 124.5, gocli 24.4 vs 31.2. pico has no SIMD path on ARM. Run `make bench`
for your machine's table.

### batchparse.h vs fast_parse × N (`build/bench_batch`)

Xeon, gocli -gzip mix, each request in its own buffer:

| batch | vs fast_parse × N |
|---|---|
| N = 1 | +8 to +24% (no overlap possible) |
| N = 4 | about −5% |
| N = 16–32, mixed traffic | **−4 to −7%** |
| N = 16, GET-only | −7 to −13% |
| N = 16, POST-only | +3 to +7% |

picohttpparser × N with the same logic is about 2.2× slower than `bp_parse`. Of the request-line variants,
per-lane canon is the fastest on the Xeon at every batch size. The AVX2 gather variant reaches parity and zmm
trails it.

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

## Licence

MIT, see [LICENSE](LICENSE). Vendored test and benchmark code (picohttpparser, llhttp) keeps its own licence; see
[THIRD_PARTY.md](THIRD_PARTY.md).
