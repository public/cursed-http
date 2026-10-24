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

Used only by `make conformance`, `make compare-all` and `make extras-check`. Each is downloaded at a pinned commit
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

`make compare-go` builds `bench/go-fasthttp` against [valyala/fasthttp](https://github.com/valyala/fasthttp) v1.76.0 (MIT)
and its dependencies, pinned by `bench/go-fasthttp/go.sum` and downloaded by the Go toolchain into its module cache.

The shims in `bench/` (`uws_shim.cpp`, `httparse_shim.rs`, `hparse_shim.zig`, `llhttp_shim.c`, `lightning_shim.c`,
`http_parser_shim.c`) are this project's own code (MIT); they adapt each parser to picohttpparser's
`phr_parse_request` signature.
