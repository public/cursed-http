# Simplifying cursed-http: inventory and ranked options

Status: 2026-11-01, measured on `main` at `91e7fd3`. Prototypes are draft PRs and nothing is merged.

| PR | option | library lines | codegen | Xeon |
|---|---|---|---|---|
| [#10](https://github.com/public/cursed-http/pull/10) | 1. hfield.h dead tables | −270 | byte-identical | exp1372 |
| [#9](https://github.com/public/cursed-http/pull/9) | 2. fbparse.h vector layer | −104 | byte-identical | exp1369, exp1370 |
| [#11](https://github.com/public/cursed-http/pull/11) | 3. dead A/B knobs (stacked on #9) | −37 | byte-identical | pending |

**The rule used for "without hurting performance".** A change qualifies only if, before and after, the machine code
and `.rodata` of every public entry point are **byte-identical** under:
- gcc and clang;
- every backend: AVX2, SSE2, AVX-512 ymm/zmm, NEON and scalar.

The Xeon same-run A/B is done as well, as the brief asks. It can't decide 1% questions on its own. Past same-run
A/Bs of an unchanged header spread 0.6–3 pp per corpus, and a single code layout can move a cell by 10–25%. So with
identical code it is an A/A run that shows that noise floor. Options that do change codegen (marked "A/B needed"
below) need many layouts and rounds to resolve 1%. Expect 2–3% resolution, not 1.

## 1. Inventory (tracked files, `wc -l`)

| kind | component | files | lines |
|---|---|---|---|
| library | `fastparse.h` (hand-written base; the generator rewrites only the API-spec region) | 1 | 1099 |
| library | `fbparse.h` | 1 | 1230 |
| library | `batchparse.h` | 1 | 370 |
| library | `chp.h` + `src/chp*.c` (runtime dispatch) | 9 | 213 |
| library | `h2.h`, `h3.h`, `hpack.h`, `qpack.h`, `hreq.h` | 5 | 2233 |
| library | `hfield.h`: 802 of its lines are generated tables | 1 | 1306 |
| library | `quic.h` + `qhp.h` | 2 | 2024 |
| **library total** | | 20 | **8475** |
| tooling | fastparse generator (`gen/httpgen.py`, specs, `check_gen.c`) | 6 | 719 |
| tooling | h2/h3 table generators | 4 | 305 |
| tooling | Makefile, `mk/`, `scripts/`, CI | 24 | 1385 |
| tests | HTTP/1 tests, fuzz, conformance | 31 | 4707 |
| tests | h2/h3/QUIC tests (`rfc*_vectors.h`: 154 generated) | 10 | 2735 |
| bench | `bench/` | 22 | 2096 |
| examples / docs | | 9 | 1743 |
| vendored | picohttpparser, llhttp | 12 | 13384 |

Without vendored code the repo is about 22,000 lines. Of those, 8,475 are library: about 7,500 hand-written and
about 960 generated. Tests and bench are 9,500, and tooling is 2,400.

**Learning modes.** The learned-layout mode (`fast_parse_learn`, about 190 lines) sits inside `fastparse.h`.
Draft PR #2 adds learned templates: 615 more lines in `fastparse.h`, plus 326 in `test_fastparse.c` and 145 in
`testlib.h`.

### Where the duplication is

**Per-ISA copies of the same logic**

- **`fbparse.h`**: 381 lines of backend code. The same four byte predicates (nt, ct, pe, lf) and seven block
  functions were written once each for NEON, AVX2, AVX-512 (ymm, zmm, emulated) and SSE2, about 75 lines per
  backend. → #9
- **`fastparse.h`**: 187 lines of the same kind (lf, c/t classes, bare-CR check) per backend. Its 47-line backend
  selection prologue (`FP_BACKEND`, includes, names) is copied almost verbatim into `fbparse.h`.
- **`batchparse.h`**: about 113 lines of lane-parallel AVX2/zmm request-line code. It has a different shape (it
  works across lanes), so it can't share code with the two above.
- **`hfield.h` / `qhp.h`**: their own small AVX2/AVX-512/NEON/SWAR dispatch, 28 `#if` arms.

**Generated vs hand-written**

- `hfield.h` holds about 800 lines of generated tables. The generator, `gen/gen_hfield.py`:
  - wrote to a `src/` that doesn't exist here;
  - named a lab script (`scripts/gen_tables.py`);
  - still generated a table nobody used (`hh_dec11`).

  So the checked-in tables could no longer be reproduced. → #10 fixes this and adds `make hfield-check`.
- `qp_static` (101 lines) was printed by `gen_qpack_static.py` and pasted by hand. There is no check that the two
  still agree.
- `fastparse.h` is the one file that is both hand-written and the generator's `--base`. That's by design: the
  generator rewrites only the API-spec region.

**Dead code and dead variants** (A/B evidence from the lab's RESULTS.md and README; experiment ids where known)

- Lost their A/B:
  - `FP_WALK_ONLY`: exp11, +19%.
  - `FB_CTANY_EXACTISH`: exp82.
  - `FB_NAME_CACHED`: exp106.
  - `FB_WALK=0`: exp82/83, 1.15–1.35× slower.
  - `FP_USE_ZMM`: exp11, +13%, and frequency-licence drops.
  - `BP_AVX512` (zmm lanes): trails canon at every batch size.
- No gain on Cascade Lake: `FP_USE_AVX512` ymm (exp11: 42.3 vs 39.0 ns for AVX2; exp83: fbparse level; chp
  `avx512` is level with `avx2`).
- Never selected anywhere:
  - `HH_K=11` with its 2048-entry table;
  - `BP_PHASE_A_ONLY`;
  - `hh_code[]`.
- Present but broken: `-DFB_NO_CTANY` didn't build on x86. #9 fixes the guard.
- Unused public functions:
  - `hh_decode_n` (48 lines);
  - `hv_check_path` and `hv_check_authority` (about 45 with their tables and backend arms);
  - `qhp_aes_masks_keys` and `qhp_apply` (about 44).
- Never executed: qhp's batched AES/ChaCha paths (about 80 lines). `quic.h` always passes n = 1, and no test
  covers them.
- Unbuilt bench files: `bench/scan_one.c` (no rule, but it uses the `FB_CTANY_*` knobs), `bench/chart.py`, and the
  `dumpcorpus` mode of `test_fastparse.c`. `bench/perf_one.c` has no rule either, but it is the Xeon A/B driver:
  keep it.

**Overlapping test harnesses**

- `test_fbparse.c`, `test_fastparse.c` and `test_batch.c` re-implement checks that `fuzz/oracle.h` already has:
  - `check_phr`/`check_ax` match `fz_phr`/`fz_adapter`;
  - `check_backends` matches `fz_fast_backends`;
  - the `B_*` wrappers match `fz_b_*`.
- Mutation stages are copied between tests: byte mutation, header swap with the same `NAMES` list, and the
  block-boundary sweep.
- The newer tests (probe, hdrspec, chunked) already go through the oracle.
- There are three AVX-512 emulation headers (305 lines) with three naming schemes.
- The h2/h3/QUIC tests each carry the same `CHECK`/PRNG preamble, about 23 lines × 6.

**Bench**

- There is no shared bench library. The best-of-N timer is written 11 times, the strided corpus build 5 times, and
  the `.bin` loader 3 times.
- About 900–1,100 lines only serve comparisons with other parsers: the shims, go-fasthttp, the rival half of
  `compare.c`/`bench_fbparse.c`, `build-extras.sh` and chart tooling. That is the part a sqlgauntlet-style external
  harness would take.

**Varint and Huffman**

- Already shared. Huffman (`hh_*`) and the HPACK/QPACK prefix integers (`hp__int`, `hp__put_int`) are written once
  in `hfield.h`/`hpack.h`. QPACK only aliases them.
- What is still duplicated:
  - the QUIC varint **encoder**: `h3__put_vi` and `quic__put_vi`;
  - the HPACK/QPACK dynamic-table bookkeeping (evict, compaction, pin and lookup are near-identical).

## 2. Options, ranked

Ranked by lines saved per unit of risk, with conflicts against open PRs counted as cost. "Lines" means library lines
unless marked tests or tooling.

| # | option | lines saved | risk | public API | performance | status |
|---|---|---|---|---|---|---|
| 1 | Drop `hh_dec11`, `hh_code[]` and the `HH_K` switch; make the `hfield.h` tables checkable | **270** | very low | `-DHH_K` gone (undocumented) | none: byte-identical code and `.rodata` | **#10** |
| 2 | `fbparse.h`: one classify over a thin per-backend vector layer (mask, compare, pack) | **104** | low | none | none: byte-identical | **#9** |
| 3 | Drop the knobs that lost their A/B: `FB_CTANY_EXACTISH`, `FB_NAME_CACHED`, `FB_WALK`, `BP_PHASE_A_ONLY` | **37** | very low | four `-D` switches gone | none: byte-identical | **#11** (on #9) |
| 4 | Drop the AVX-512 backends (fast/fb/batch, chp's avx512 object, `HV_USE_AVX512`, the three emu headers, Makefile rows) | about 530 (225 library, 305 test emu) | low for correctness | removes `-DFP_USE_AVX512`/`FP_USE_ZMM`/`BP_AVX512`/`HV_USE_AVX512`; chp would pick avx2 | none on Cascade Lake (no gain measured anywhere); **unknown** on Ice Lake, SPR and Zen 4, where AVX-512 has no licence penalty | **owner's decision**; not prototyped |
| 5 | Same vector layer for `fastparse.h`, plus one shared backend-selection prologue | about 120–150 | low to medium | none, if the layer stays inside each header; one more file to ship if shared | aim for byte-identical as in #9 | blocked: `fastparse.h` is being rewritten by draft PR #2 |
| 6 | HTTP/1 tests onto `fuzz/oracle.h`; shared mutators in `testlib.h` | about 250–300 (tests) | low | none | none (tests only) | blocked by PR #2: `test_fastparse.c`, `testlib.h`, `oracle.h` |
| 7 | qhp.h: remove `qhp_aes_masks_keys`, `qhp_apply` and the never-executed batched paths, keeping the signatures | about 125 | low to medium (crypto, but the removed paths have no test) | two unused functions gone | none for `quic.h` (n = 1) | `H2H3.md` says "batched" (PR #7 edits that file) |
| 8 | Remove unused public functions `hh_decode_n`, `hv_check_path`, `hv_check_authority` and their tables and backend arms | about 95 | low | three functions gone | none | owner's decision (API) |
| 9 | `bench/benchlib.h` (timer, corpus, parser registry), then move the rival-comparison shims to an external sqlgauntlet-style harness | about 150 (in-tree lib) + about 1,000 moved out | medium: README tables would then come from outside the repo | none | none | conflicts with PR #2 (`compare.c`, `ours.c`, `build-extras.sh`) |
| 10 | Shared `tests/h2h3_check.h` (CHECK, counters, PRNG, `scale`) | about 90 (110 with `test_quic_interop.c`) | very low | none | none | ready; `test_quic_interop.c` is in PR #7, so 90 without it |
| 11 | Makefile test matrix through `define`/`eval` (variant × test) | about 45–50 (tooling) | low | none | none (same compile lines) | PR #2 touches Makefile lightly |
| 12 | Shared HPACK/QPACK dynamic-table helpers (evict, compaction, pin, lookup) | about 40 | medium (`offsetof` memset layout trick) | none | **A/B needed**: codegen changes | not prototyped |
| 13 | One AVX-512 emulation header for all three users | about 50 (tests) | low | none | none | PR #2 adds ops to `avx512_emu.h` |
| 14 | `scripts/mutlib.sh` for the three mutant scripts (also: none exits non-zero on a survivor, and none runs in CI) | about 30 | very low | none | none | — |
| 15 | One QUIC varint encoder in `hfield.h` | about 13 | low | none | **A/B needed** (the per-length branches and the loop differ; h3 DATA frames use it) | touches `quic.h` (PR #7) |
| 16 | Generated-table check for `qp_static`, as `make hfield-check` does for `hfield.h` | +15 (adds lines) | none | none | none | worth doing; a correctness item, not a cut |

**Evaluated and not recommended**

- **One portable SIMD abstraction shared by all headers** (a generic `simd64.h`). The per-header layer in #9 gets
  most of the saving. A shared header would:
  - make `fbparse.h` and `fastparse.h` stop being standalone single files;
  - change their include contract;
  - save only about another 50 lines once option 5 is done.

  Do it only if a fourth user appears.
- **Sharing one header/line scanner between fbparse, fastparse and batchparse.** They answer different questions:
  - fbparse: pico-exact validation of arbitrary headers;
  - fastparse: route-specific fast path with fallback;
  - batchparse: lane-transposed request lines.

  What they genuinely share is the 64-byte classify step, which is options 2 and 5. A common scanner would put
  branches into three tuned hot loops, and the codegen would change.
- **Generating the per-ISA backends** (from a Python template, like `httpgen.py`). It trades 100–200 lines of C for
  a generator and a second source of truth. After #9 the hand-written per-backend part is only the primitives, about
  20–35 lines per ISA, which is already small enough to read.
- **Merging `h2.h` and `h3.h` request/stream handling.** Request validation is already shared (`hreq.h`). The rest
  differs in struct and protocol. A merge would need macros, for only about 6 lines (a shared trailer-field check).

**Proofs.** The library repo has no machine-checked proofs. Its correctness arguments are:
- comment proofs, e.g. `fp_nondigit`'s carry argument and the ctany over-approximation;
- the exhaustive 256-byte classify check in `test_fbparse.c`;
- the differential tests and fuzzers.

None of #9, #10 or #11 changes a predicate, a comment proof or the exhaustive checks. #9 moves the predicates to one
place, so a mutant in a shared predicate now bites on every backend. That is stronger than before: kills went from
27 to 28 natively and from 23 to 24 under `EMU=1`.

## 3. Prototypes: what was done, tried and dropped

**#9 (fbparse.h vector layer)**
- Each backend keeps its own load placement through two hooks: `FB_BLK`/`FB_BPACK`, plus `FB_PACK` for lazy loads.
- Tried and dropped:
  - a block struct loaded once: +46 spills on clang AVX-512 ymm and different AVX2 allocation on gcc;
  - a one-expression ymm combine: a different clang schedule.

**#10 (hfield.h)**
- `gen_hfield.py --check` compares every table with the copy in `hfield.h`.
- Kept out of the PR: `hh_decode_n` and `hv_check_*`. They are public API, so they're listed above as option 8.

**#11 (knobs)**
- Not touched: `FP_WALK_ONLY`, because it lives in `fastparse.h` (PR #2).

**Verification on each PR**
- `objdump -d` identity (plus `.rodata` for #10): gcc 14.2 and clang 21 here, gcc and clang on the Xeon.
- `make test-quick` on arm64; `make test-h2h3` for #10.
- The mutant scripts, before vs after, with every mutant still applying.
- CI on x86-64 Linux.
- On the Xeon: real-hardware AVX2/SSE2/AVX-512 tests and the x86-only mutants, plus a same-run timing A/B (6
  corpora × 8 layouts × 4 rounds × gcc/clang for fbparse; 9 HPACK/QPACK/Huffman cells for hfield).

**Not done here**
- A full fuzz sweep: libFuzzer isn't in Apple clang, so `fuzz-replay` of the seeds and regressions ran instead.
  Run `make fuzz` on Linux before merging.
- Real-hardware AVX-512 mutants beyond the x86-only set.

**Order to land**
1. #10 and #9, independently.
2. #11 after #9.
3. After PR #2 merges: options 5, 6 and the `FP_WALK_ONLY` knob.
4. Option 4 if the owner agrees that Cascade Lake decides AVX-512.
