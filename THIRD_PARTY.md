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
