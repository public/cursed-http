# Third-party code and credits

## Vendored (tests and benchmarks only; the headers in `include/` do not use them)

### picohttpparser — `vendor/pico/`

https://github.com/h2o/picohttpparser, commit `465a7ff09fbd3432fe56c673451f5460154d1f07`, files copied
verbatim (`vendor/pico/COMMIT`). Dual-licensed under the Perl License or the MIT License; used under MIT:

```
Copyright (c) 2009-2014 Kazuho Oku, Tokuhiro Matsuno, Daisuke Murase,
                        Shigeo Mitsunari

The software is licensed under either the MIT License (below) or the Perl
license.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to
deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
IN THE SOFTWARE.
```

picohttpparser is the reference every test compares against. `tests/test_fbparse.c` also carries a copy of its
`token_char_map` table (static in `picohttpparser.c`) to check `fbparse.h`'s token LUT byte by byte.

### llhttp — `vendor/llhttp/`

https://github.com/nodejs/llhttp, release v9.4.3 (`0e815792b167a9bd8ace259b95b7da953776c288`), the generated C
from the release tag. MIT licence, Copyright Fedor Indutny, 2018; full text in `vendor/llhttp/LICENSE` and
`vendor/llhttp/LICENSE-MIT`. Used only as a benchmark contender (`bench/`).

## Behaviour reproduced (no code copied)

`include/fbparse.h` reproduces picohttpparser's validation rules and its -1/-2 (invalid/incomplete) decisions,
including its `is_complete()` last-length check, and is tested to agree with it on every input.

## Fetched on demand (never committed): `scripts/fetch-thirdparty.sh` → `third_party/`

Used only by `make conformance`, `make compare-all`, `make extras-check` and the HTTP/2/3 targets (`make
test-h2h3`, `make h2spec`, `make real-clients`); of these, only picotls is needed by code in `include/` (`quic.h`). Each is downloaded at a pinned commit
and keeps its own licence.

| name | project | commit | licence | used for |
|---|---|---|---|---|
| uws | https://github.com/uNetworking/uWebSockets v20.80.0 | `3ffd6f44c9c3` | Apache-2.0 | comparison benchmark, conformance reference |
| httparse | https://github.com/seanmonstar/httparse v1.10.1 | `9f29e79f9832` | MIT / Apache-2.0 | comparison benchmark (rustc), conformance cases |
| hparse | https://github.com/nikneym/hparse | `4fb3d836e804` | MIT | comparison benchmark (zig 0.15) |
| llhttp-src | https://github.com/nodejs/llhttp | `69936dbc2292` | MIT | conformance cases (`test/request/*.md`) |
| garden | https://github.com/narfindustries/http-garden | `b417e806c1b1` | **GPL-3.0** | conformance cases (`TROPHIES.md` payloads) |
| pico-src | https://github.com/h2o/picohttpparser | `465a7ff09fbd` | MIT / Perl | conformance cases (`test.c`) |
| lightning | https://github.com/softwaredc/lightning | `7b3b0cb1cb59` | Apache-2.0 | comparison benchmark |
| pico-a64, pico-a64tbl | https://github.com/volyrique/picohttpparser (branches `armv8-a`, `armv8-a+tbl`) | `a47c4d00644f`, `b93abc18204c` | MIT / Perl | comparison benchmark (ARM) |
| http-parser | https://github.com/nodejs/http-parser | `ec8b5ee63f0e` | MIT | comparison benchmark |
| nghttp2 | https://github.com/nghttp2/nghttp2 v1.70.0 | `85e300c79fb6` | MIT | HTTP/2 + HPACK reference (`make test-h2h3`, benchmarks) |
| nghttp3 (+ sfparse) | https://github.com/ngtcp2/nghttp3 v1.18.0, https://github.com/ngtcp2/sfparse | `dbfc24286138`, `4b313cfd2e1b` | MIT | HTTP/3 + QPACK reference (`make test-h2h3`, benchmarks) |
| h2spec | https://github.com/summerwind/h2spec v2.6.0 | `70ac22940108` | MIT | HTTP/2 conformance suite (`make h2spec`) |
| picotls | https://github.com/h2o/picotls | `1e034d8418c1` | MIT | **the TLS 1.3 handshake `include/quic.h` builds on** (with OpenSSL libcrypto) |
| ngtcp2 | https://github.com/ngtcp2/ngtcp2 v1.25.0 | `f9e9ff01ad2c` | MIT | QUIC reference client (`make test-h2h3`) |
| ls-hpack | https://github.com/litespeedtech/ls-hpack v2.3.5 | `cf0f70dd10b3` | MIT | HPACK comparison benchmark (`make bench-h2h3-rivals`) |
| ls-qpack | https://github.com/litespeedtech/ls-qpack v2.7.0 | `91567706c41c` | MIT | QPACK comparison benchmark (`make bench-h2h3-rivals`) |
| h2o | https://github.com/h2o/h2o (master, 2026-11-01) | `0d22c901981c` | MIT | HPACK / QPACK comparison benchmark (9 of its source files) |

`make real-clients` installs [aioquic](https://github.com/aiortc/aioquic) 1.6.1 (BSD-3-Clause) from PyPI into a
virtualenv under `build/`, as the HTTP/3 client.

The HTTP/2 / HTTP/3 comparison harnesses download their dependencies through their own toolchains, pinned by
their lock files: `bench/go-h2h3` uses golang.org/x/net v0.62.0 (BSD-3-Clause) and github.com/quic-go/qpack v0.6.0
(MIT), pinned by `go.sum`; `bench/rust-h2` uses the h2 0.4.20, http, bytes and tokio crates (MIT), pinned by
`Cargo.lock`.

`make compare-go` builds `bench/go-fasthttp` against [valyala/fasthttp](https://github.com/valyala/fasthttp) v1.76.0 (MIT)
and its dependencies, pinned by `bench/go-fasthttp/go.sum` and downloaded by the Go toolchain into its module cache.

The shims in `bench/` (`uws_shim.cpp`, `httparse_shim.rs`, `hparse_shim.zig`, `llhttp_shim.c`, `lightning_shim.c`,
`http_parser_shim.c`) are this project's own code (MIT); they adapt each parser to picohttpparser's
`phr_parse_request` signature.
