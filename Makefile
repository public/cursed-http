# cursed-http (formerly cursed-http-parser)
#   make test         every differential test (native backend, scalar, emulated AVX-512, generated headers)
#   make test-quick   the same with smaller fuzz counts (CI)
#   make asan         ASan + UBSan builds of the tests (quick mode)
#   make bench        benchmarks: fastparse, fbparse, batchparse, and the comparison vs pico / llhttp
#   make bench-codspeed  the CodSpeed benchmark suite (bench/codspeed; CMake, fetches Google Benchmark)
#   make avx512       real AVX-512 builds (need an AVX-512 CPU to run: make avx512-run)
#   make mutants      planted bugs: every mutant must make a test fail
#   make compare-all  + uWebSockets, httparse, hparse (fetched at pinned commits; rustc / zig optional)
#   make compare-go   + fasthttp (Go >= 1.26) on the same corpora
#   make conformance  third-party conformance suites (fetched at pinned commits)
#   make real-browsers Chromium, Firefox and WebKit (Playwright) against the HTTP/1.1 parsers; make browser-replay
#                     replays their saved requests (tests/browser/captures/) under every backend (part of make test)
#   make top1k-full   the Tranco top-1k sites' real requests (tests/top1k/) at every length, every backend;
#                     make top1k-replay (part of make test) checks them at the lengths next to line ends
#   make fuzz         libFuzzer: fbparse / fastparse / batchparse differential targets (clang with libFuzzer;
#                     FUZZ_TIME=s per target, default 30)
#   make hypothesis   Hypothesis properties on grammar-built requests (venv in build/; HYP_EXAMPLES, default 300)
#   make lib          build/libchp.a: every backend of this architecture, picked at load time (include/chp.h)
#   make gen          regenerate build/fastparse_gen.h and build/fastparse_pgo.h from gen/example_spec.json
#   make lint         formatting + lint checks (clang-format, shfmt, ruff, shellcheck, cppcheck; Docker)
#   make format       apply the formatters; make hooks installs the pre-commit check (.githooks/)
# Everything is built into build/. The library itself is header-only: include/*.h.
CC ?= cc
PYTHON ?= python3
B := build
CFLAGS ?= -O3
WARN := -Wall -Wextra -Wno-unused-function -Wno-deprecated-declarations
ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
  MARCH ?= -march=haswell
else
  MARCH ?= -mcpu=native
endif
INC := -Iinclude -Itests -Ivendor/pico
PICO := vendor/pico/picohttpparser.c
HDRS := include/fastparse.h include/fbparse.h include/batchparse.h $(wildcard tests/*.h)
SAN := -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
CC_T = $(CC) $(CFLAGS) $(WARN) $(MARCH) $(INC)

FP_BINS := $(B)/test_fastparse $(B)/test_fastparse_scalar $(B)/test_fastparse_emu512 $(B)/test_fastparse_emuzmm \
           $(B)/test_fastparse_gen $(B)/test_fastparse_pgo $(B)/test_fastparse_pgo_scalar
FB_BINS := $(B)/test_fbparse $(B)/test_fbparse_scalar $(B)/test_fbparse_emu512 $(B)/test_fbparse_emuzmm
BP_BINS := $(B)/test_batch $(B)/test_batch_emu $(B)/test_batch_gen $(B)/test_batch_spec
GENCHECK := $(B)/check_example_spec $(B)/check_toy_spec $(B)/check_headers_spec
PR_BINS := $(B)/test_probe $(B)/test_probe_scalar $(B)/test_probe_emu512 $(B)/test_chunked $(B)/test_hdrspec $(B)/test_hdrspec_scalar $(B)/test_hdrspec_emu512

# ---- include/chp.h: every backend in one library, picked at load time (src/chp.c) ----
# Each backend's object gets exactly the flags src/chp.c checks the CPU for; the rest is built for the
# architecture's baseline, so libchp.a and test_chp run on any CPU of the architecture.
ifeq ($(ARCH),x86_64)
  CHP_BASE := -march=x86-64 -mtune=generic
  CHP_T := scalar sse2 avx2 avx512
  # the x86 baseline (SSE2) builds of the differential tests: the backend a default-flags build gets
  FP_BINS += $(B)/test_fastparse_sse2
  FB_BINS += $(B)/test_fbparse_sse2
  BP_BINS += $(B)/test_batch_sse2
  PR_BINS += $(B)/test_probe_sse2 $(B)/test_hdrspec_sse2
else ifneq ($(filter arm64 aarch64,$(ARCH)),)
  CHP_BASE :=
  CHP_T := scalar neon
else
  CHP_BASE :=
  CHP_T := scalar
endif
CHP_FLAGS_scalar := -DFP_FORCE_SCALAR
CHP_FLAGS_sse2 :=
CHP_FLAGS_neon :=
CHP_FLAGS_avx2 := -mavx2 -mbmi -mbmi2 -mpopcnt
CHP_FLAGS_avx512 := $(CHP_FLAGS_avx2) -mavx512f -mavx512bw -mavx512vl -mavx512cd -mavx512dq -DFP_USE_AVX512
CHP_OBJ := $(B)/chp.o $(foreach t,$(CHP_T),$(B)/chp_$(t).o)
$(B)/chp_%.o: src/chp_%.c src/chp_impl.h src/chp_table.h $(HDRS) | $(B)
	$(CC) $(CFLAGS) $(WARN) $(CHP_BASE) $(CHP_FLAGS_$*) -Iinclude -Isrc -c $< -o $@
$(B)/chp.o: src/chp.c include/chp.h src/chp_table.h $(HDRS) | $(B)
	$(CC) $(CFLAGS) $(WARN) $(CHP_BASE) -Iinclude -Isrc -c $< -o $@
$(B)/libchp.a: $(CHP_OBJ)
	rm -f $@ && ar rcs $@ $(CHP_OBJ)
lib: $(B)/libchp.a
$(B)/pico_base.o: $(PICO) | $(B)
	$(CC) -O3 $(CHP_BASE) -c $(PICO) -o $@
$(B)/test_chp: tests/test_chp.c include/chp.h $(HDRS) $(B)/libchp.a $(B)/pico_base.o
	$(CC) $(CFLAGS) $(WARN) $(CHP_BASE) $(INC) $< $(B)/pico_base.o $(B)/libchp.a -o $@
$(B)/test_fastparse_sse2: tests/test_fastparse.c $(HDRS) $(B)/pico_base.o
	$(CC) $(CFLAGS) $(WARN) $(CHP_BASE) $(INC) $< $(B)/pico_base.o -o $@
$(B)/test_fbparse_sse2: tests/test_fbparse.c $(HDRS) $(B)/pico_base.o
	$(CC) $(CFLAGS) $(WARN) $(CHP_BASE) $(INC) $< $(B)/pico_base.o -o $@
$(B)/test_batch_sse2: tests/test_batch.c $(HDRS) $(B)/pico_base.o
	$(CC) $(CFLAGS) $(WARN) $(CHP_BASE) $(INC) $< $(B)/pico_base.o -o $@

# the transport-level request shapes of an HTTP/1.1 conformance probe (tests/probe_cases.h), every backend
PR_DEPS := tests/test_probe.c tests/probe_cases.h fuzz/oracle.h $(HDRS) $(B)/pico.o
PR_W := -Wno-missing-field-initializers
$(B)/test_probe: $(PR_DEPS)
	$(CC_T) $(PR_W) -Ifuzz $< $(B)/pico.o -o $@
$(B)/test_probe_scalar: $(PR_DEPS)
	$(CC_T) $(PR_W) -Ifuzz -DFP_FORCE_SCALAR $< $(B)/pico.o -o $@
# the AVX-512 logic on C stand-ins; batchparse's x86 variants need the real intrinsics, so canon lanes only here
# (test_batch_emu covers the emulated zmm lanes)
$(B)/test_probe_emu512: $(PR_DEPS)
	$(CC_T) $(PR_W) -Ifuzz -DFP_AVX512_EMU -DBP_CANON_ONLY $< $(B)/pico.o -o $@
# fb_decode_chunked vs picohttpparser's decoder (plain C: one build)
$(B)/test_chunked: tests/test_chunked.c fuzz/oracle.h $(HDRS) $(B)/pico.o
	$(CC_T) -Ifuzz $< $(B)/pico.o -o $@
$(B)/test_probe_sse2: tests/test_probe.c tests/probe_cases.h fuzz/oracle.h $(HDRS) $(B)/pico_base.o
	$(CC) $(CFLAGS) $(WARN) $(PR_W) $(CHP_BASE) $(INC) -Ifuzz $< $(B)/pico_base.o -o $@

all: $(FP_BINS) $(FB_BINS) $(BP_BINS) $(PR_BINS) $(GENCHECK) $(B)/test_chp

$(B):
	mkdir -p $(B)

# ---- generated headers (gen/httpgen.py): the API-specific region of fastparse.h from a spec ----
# a spec that asks for headers by name (req_t.hdr): tests/test_hdrspec.c
$(B)/fastparse_hdr.h: gen/headers_spec.json gen/httpgen.py include/fastparse.h | $(B)
	$(PYTHON) gen/httpgen.py gen gen/headers_spec.json --base include/fastparse.h -o $@
HS_DEPS := tests/test_hdrspec.c fuzz/oracle.h $(HDRS) $(B)/fastparse_hdr.h
HS_F := -I$(B) -Ifuzz -DBP_CANON_ONLY '-DBP_HTTP_H="fastparse_hdr.h"'
$(B)/test_hdrspec: $(HS_DEPS) $(B)/pico.o
	$(CC_T) $(HS_F) $< $(B)/pico.o -o $@
$(B)/test_hdrspec_scalar: $(HS_DEPS) $(B)/pico.o
	$(CC_T) $(HS_F) -DFP_FORCE_SCALAR $< $(B)/pico.o -o $@
$(B)/test_hdrspec_emu512: $(HS_DEPS) $(B)/pico.o
	$(CC_T) $(HS_F) -DFP_AVX512_EMU $< $(B)/pico.o -o $@
$(B)/test_hdrspec_sse2: $(HS_DEPS) $(B)/pico_base.o
	$(CC) $(CFLAGS) $(WARN) $(CHP_BASE) $(INC) $(HS_F) $< $(B)/pico_base.o -o $@
$(B)/fastparse_gen.h: gen/example_spec.json gen/httpgen.py include/fastparse.h | $(B)
	$(PYTHON) gen/httpgen.py gen gen/example_spec.json --base include/fastparse.h -o $@
$(B)/fastparse_pgo.h: gen/example_spec.json gen/example_profile.json gen/httpgen.py include/fastparse.h | $(B)
	$(PYTHON) gen/httpgen.py gen gen/example_spec.json --base include/fastparse.h --profile gen/example_profile.json -o $@
gen: $(B)/fastparse_gen.h $(B)/fastparse_pgo.h

# ---- fastparse.h vs picohttpparser ----
$(B)/pico.o: $(PICO) | $(B)
	$(CC) -O3 $(MARCH) -c $(PICO) -o $@
$(B)/test_fastparse: tests/test_fastparse.c $(HDRS) $(B)/pico.o
	$(CC_T) $< $(B)/pico.o -o $@
$(B)/test_fastparse_scalar: tests/test_fastparse.c $(HDRS) $(B)/pico.o
	$(CC_T) -DFP_FORCE_SCALAR $< $(B)/pico.o -o $@
$(B)/test_fastparse_emu512: tests/test_fastparse.c $(HDRS) $(B)/pico.o
	$(CC_T) -DFP_AVX512_EMU $< $(B)/pico.o -o $@
$(B)/test_fastparse_emuzmm: tests/test_fastparse.c $(HDRS) $(B)/pico.o
	$(CC_T) -DFP_AVX512_EMU -DFP_USE_ZMM $< $(B)/pico.o -o $@
$(B)/test_fastparse_gen: tests/test_fastparse.c $(HDRS) $(B)/fastparse_gen.h $(B)/pico.o
	$(CC_T) -I$(B) '-DHTTP_HEADER="fastparse_gen.h"' $< $(B)/pico.o -o $@
$(B)/test_fastparse_pgo: tests/test_fastparse.c $(HDRS) $(B)/fastparse_pgo.h $(B)/pico.o
	$(CC_T) -I$(B) '-DHTTP_HEADER="fastparse_pgo.h"' $< $(B)/pico.o -o $@
$(B)/test_fastparse_pgo_scalar: tests/test_fastparse.c $(HDRS) $(B)/fastparse_pgo.h $(B)/pico.o
	$(CC_T) -I$(B) -DFP_FORCE_SCALAR '-DHTTP_HEADER="fastparse_pgo.h"' $< $(B)/pico.o -o $@

# ---- generator self-check: the generated router vs the generator's own model, real and adversarial spec ----
$(B)/check_%.h: gen/%.json gen/httpgen.py include/fastparse.h | $(B)
	$(PYTHON) gen/httpgen.py gen $< --base include/fastparse.h -o $@
$(B)/check_%: gen/check_gen.c $(B)/check_%.h
	$(CC_T) -I$(B) '-DHTTP_HEADER="check_$*.h"' $< -o $@
gencheck: $(GENCHECK)
	for s in example_spec toy_spec headers_spec; do $(PYTHON) gen/httpgen.py vectors gen/$$s.json $(GENVECTORS) 1 | $(B)/check_$$s || exit 1; done

# ---- fbparse.h vs picohttpparser ----
$(B)/test_fbparse: tests/test_fbparse.c $(HDRS) $(B)/pico.o
	$(CC_T) $< $(B)/pico.o -o $@
$(B)/test_fbparse_scalar: tests/test_fbparse.c $(HDRS) $(B)/pico.o
	$(CC_T) -DFP_FORCE_SCALAR $< $(B)/pico.o -o $@
$(B)/test_fbparse_emu512: tests/test_fbparse.c $(HDRS) $(B)/pico.o
	$(CC_T) -DFP_AVX512_EMU $< $(B)/pico.o -o $@
$(B)/test_fbparse_emuzmm: tests/test_fbparse.c $(HDRS) $(B)/pico.o
	$(CC_T) -DFP_AVX512_EMU -DFP_USE_ZMM $< $(B)/pico.o -o $@

# ---- batchparse.h vs fast_parse, lane by lane ----
$(B)/test_batch: tests/test_batch.c $(HDRS) $(B)/pico.o
	$(CC_T) $< $(B)/pico.o -o $@
$(B)/test_batch_emu: tests/test_batch.c $(HDRS) $(B)/pico.o
	$(CC_T) -DBP_AVX512_EMU $< $(B)/pico.o -o $@
$(B)/test_batch_gen: tests/test_batch.c $(HDRS) $(B)/fastparse_pgo.h $(B)/pico.o
	$(CC_T) -I$(B) -DBP_AVX512_EMU '-DBP_HTTP_H="fastparse_pgo.h"' $< $(B)/pico.o -o $@

# batchparse.h with -DBP_CANON_ONLY on the generated parser of another spec (gen/toy_spec.json)
$(B)/test_batch_spec: tests/test_batch_spec.c $(HDRS) $(B)/check_toy_spec.h
	$(CC_T) -I$(B) -DBP_CANON_ONLY '-DBP_HTTP_H="check_toy_spec.h"' $< -o $@

# the README's usage example must build and parse
$(B)/read_loop: examples/read_loop.c $(HDRS)
	$(CC_T) $< -o $@
example-check: $(B)/read_loop
	@printf 'GET /posts/42 HTTP/1.1\r\nHost: x\r\n\r\n' | ./$(B)/read_loop | grep -q "route GETPOST, id 42" && \
	  printf 'GET /feed HTTP/1.0\r\nHost: x\r\n\r\n' | ./$(B)/read_loop | grep -q "route FEED" && \
	  printf 'POST /posts HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n' | ./$(B)/read_loop 2>&1 | grep -q "400" && \
	  printf 'POST /posts HTTP/1.1\r\nAuthorization: Bearer t.o.k\r\nContent-Length: 2\r\n\r\n{}' | ./$(B)/read_loop | grep -q "route CREATE, bearer token t.o.k, body 2" && \
	  echo "example: OK"

GENVECTORS ?= 200000
FBMODE ?=
RUN := ./scripts/run_test.sh
test: all gencheck example-check fuzz-replay browser-replay top1k-replay
	@set -e; for t in $(FP_BINS); do $(RUN) 1 $$t nobench; done
	@set -e; $(RUN) 2 $(B)/test_fbparse $(FBMODE); \
	  for t in $(notdir $(filter-out $(B)/test_fbparse,$(FB_BINS))); do $(RUN) 1 $(B)/$$t quick; done
	@set -e; for t in $(BP_BINS); do $(RUN) 1 $$t; done
	@set -e; for t in $(PR_BINS); do $(RUN) 1 $$t $(FBMODE); done
	@set -e; $(RUN) 1 $(B)/test_chp $(FBMODE)
	@$(MAKE) --no-print-directory test-resp FBMODE=$(FBMODE)
	@echo "ALL TESTS PASSED"
test-quick:
	$(MAKE) test FBMODE=quick GENVECTORS=50000

# ---- sanitizers ----
$(B)/asan_fastparse: tests/test_fastparse.c $(HDRS) | $(B)
	$(CC) $(SAN) $(WARN) $(MARCH) $(INC) $< $(PICO) -o $@
$(B)/asan_fbparse: tests/test_fbparse.c $(HDRS) | $(B)
	$(CC) $(SAN) $(WARN) $(MARCH) $(INC) $< $(PICO) -o $@
$(B)/asan_fbparse_emu: tests/test_fbparse.c $(HDRS) | $(B)
	$(CC) $(SAN) $(WARN) $(MARCH) $(INC) -DFP_AVX512_EMU $< $(PICO) -o $@
$(B)/asan_chunked: tests/test_chunked.c fuzz/oracle.h $(HDRS) | $(B)
	$(CC) $(SAN) $(WARN) $(MARCH) $(INC) -Ifuzz $< $(PICO) -o $@
$(B)/asan_batch: tests/test_batch.c $(HDRS) | $(B)
	$(CC) $(SAN) $(WARN) $(MARCH) $(INC) -DBP_AVX512_EMU $< $(PICO) -o $@
asan: $(B)/asan_fastparse $(B)/asan_fbparse $(B)/asan_fbparse_emu $(B)/asan_batch $(B)/asan_chunked
	@set -e; export ASAN_OPTIONS=detect_leaks=0; $(RUN) 1 $(B)/asan_fastparse nobench; \
	  $(RUN) 1 $(B)/asan_fbparse quick; $(RUN) 1 $(B)/asan_fbparse_emu quick; $(RUN) 1 $(B)/asan_batch; \
	  $(RUN) 1 $(B)/asan_chunked quick
	@echo "ASAN/UBSAN CLEAN"

# ---- benchmarks ----
LLHTTP_O := $(B)/llhttp_llhttp.o $(B)/llhttp_api.o $(B)/llhttp_http.o
$(B)/llhttp_%.o: vendor/llhttp/src/%.c | $(B)
	$(CC) -O3 $(MARCH) -w -Ivendor/llhttp/include -c $< -o $@
$(B)/llhttp_shim.o: bench/llhttp_shim.c | $(B)
	$(CC) -O3 $(MARCH) -Ivendor/llhttp/include -Ivendor/pico -c $< -o $@
$(B)/ours_%.o: bench/ours.c $(HDRS) $(B)/fastparse_gen.h $(B)/fastparse_pgo.h | $(B)
	$(CC) $(CFLAGS) $(MARCH) -Iinclude -I$(B) '-DOURS_HDR="$(OURS_HDR_$*)"' -DOURS=$* -c $< -o $@
OURS_HDR_hand := fastparse.h
OURS_HDR_gen := fastparse_gen.h
OURS_HDR_pgo := fastparse_pgo.h
# hnc: the hand-written header with the learned templates' cost model compiled out (FP_TM_NOCOST)
$(B)/ours_hnc.o: bench/ours.c $(HDRS) | $(B)
	$(CC) $(CFLAGS) $(MARCH) -Iinclude '-DOURS_HDR="fastparse.h"' -DOURS=hnc -DFP_TM_NOCOST -c $< -o $@
OURS_O := $(B)/ours_hand.o $(B)/ours_gen.o $(B)/ours_pgo.o $(B)/ours_hnc.o
$(B)/compare: bench/compare.c $(HDRS) $(OURS_O) $(B)/pico.o $(LLHTTP_O) $(B)/llhttp_shim.o
	$(CC_T) $< $(OURS_O) $(B)/pico.o $(LLHTTP_O) $(B)/llhttp_shim.o -o $@
$(B)/bench_fbparse: bench/bench_fbparse.c $(HDRS) $(B)/pico.o $(LLHTTP_O) $(B)/llhttp_shim.o
	$(CC_T) $< $(B)/pico.o $(LLHTTP_O) $(B)/llhttp_shim.o -o $@
$(B)/bench_batch: bench/bench_batch.c $(HDRS) $(B)/pico.o
	$(CC_T) $< $(B)/pico.o -o $@
$(B)/bench_chunked: bench/bench_chunked.c $(HDRS) $(B)/pico.o
	$(CC_T) $< $(B)/pico.o -o $@
$(B)/bench_chp: bench/bench_chp.c include/chp.h $(HDRS) $(B)/libchp.a $(B)/pico.o
	$(CC_T) $< $(B)/pico.o $(B)/libchp.a -o $@
bench: $(B)/test_fastparse $(B)/compare $(B)/bench_fbparse $(B)/bench_batch $(B)/bench_chp $(B)/bench_chunked
	./$(B)/test_fastparse benchonly
	./$(B)/compare
	./$(B)/bench_fbparse
	./$(B)/bench_batch
	./$(B)/bench_chp
	./$(B)/bench_chunked
# the CodSpeed benchmarks (bench/codspeed: Google Benchmark through CodSpeed's fork, fetched by CMake; network)
# as plain Google Benchmark timings; CI builds them with -DCODSPEED_MODE=simulation (.github/workflows/codspeed.yml)
bench-codspeed: | $(B)
	cmake -S bench/codspeed -B $(B)/codspeed
	cmake --build $(B)/codspeed -j
	./$(B)/codspeed/cursed_http_bench

# ---- real AVX-512 (compile anywhere with gcc/clang; run only on AVX-512BW/VL hardware) ----
AVX512 := -march=cascadelake
avx512: $(B)/pico.o $(HDRS)
	$(CC) $(CFLAGS) $(WARN) $(AVX512) $(INC) -DFP_USE_AVX512 tests/test_fastparse.c $(PICO) -o $(B)/test_fastparse_avx512
	$(CC) $(CFLAGS) $(WARN) $(AVX512) $(INC) -DFP_USE_AVX512 -DFP_USE_ZMM tests/test_fastparse.c $(PICO) -o $(B)/test_fastparse_zmm
	$(CC) $(CFLAGS) $(WARN) $(AVX512) $(INC) -DFP_USE_AVX512 tests/test_fbparse.c $(PICO) -o $(B)/test_fbparse_avx512
	$(CC) $(CFLAGS) $(WARN) $(AVX512) $(INC) -DFP_USE_AVX512 -DFP_USE_ZMM tests/test_fbparse.c $(PICO) -o $(B)/test_fbparse_zmm
	$(CC) $(CFLAGS) $(WARN) $(AVX512) $(INC) -DBP_AVX512 tests/test_batch.c $(PICO) -o $(B)/test_batch_avx512
avx512-run: avx512
	@set -e; $(RUN) 1 $(B)/test_fastparse_avx512 nobench; $(RUN) 1 $(B)/test_fastparse_zmm nobench; \
	  $(RUN) 1 $(B)/test_fbparse_avx512 quick; $(RUN) 1 $(B)/test_fbparse_zmm quick; $(RUN) 1 $(B)/test_batch_avx512

# ---- extras that need third-party sources fetched at pinned commits (network; nothing is vendored) ----
fetch:
	./scripts/fetch-thirdparty.sh
# fastparse / fbparse vs pico, llhttp, uWebSockets, httparse (rustc), hparse (zig 0.15)
compare-all: fetch
	./scripts/build-extras.sh
	./$(B)/compare_all
	./$(B)/bench_fbparse_all
# fasthttp (Go >= 1.26, modules pinned by bench/go-fasthttp/go.sum; network for the first download)
$(B)/dump_corpus: bench/dump_corpus.c $(HDRS)
	$(CC_T) $< $(PICO) -o $@
compare-go: $(B)/dump_corpus
	cd bench/go-fasthttp && go build -o ../../$(B)/fasthttp_bench .
	@for s in 1 0 2 10 11 12 13 14 15; do ./$(B)/dump_corpus $(B)/corpus$$s.bin $$s 4096; ./$(B)/fasthttp_bench $(B)/corpus$$s.bin 60; done

# quick check of all of the above (correctness gates only, short benchmarks): used by CI / Docker
extras-check: conformance
	./$(B)/compare_all gate
	$(RUN) 2 $(B)/bench_fbparse_all 2
# conformance: 298 cases from llhttp, HTTP Garden, picohttpparser and httparse suites, every truncation
$(B)/cases.bin: conformance/extract.py | $(B)
	./scripts/fetch-thirdparty.sh llhttp-src garden pico-src httparse
	$(PYTHON) conformance/extract.py third_party/llhttp-src third_party/garden third_party/pico-src/test.c third_party/httparse/src/lib.rs > $@
conformance: $(B)/cases.bin all
	./scripts/fetch-thirdparty.sh uws
	./scripts/build-extras.sh
	./$(B)/conf $(B)/cases.bin $(B)/conformance-report.txt
	@for t in test_fbparse test_fbparse_scalar test_fbparse_emu512; do FB_CASES=$(B)/cases.bin ./$(B)/$$t quick | grep -E "conformance|TOTAL"; done

# static throughput estimates of the SIMD kernels per backend and CPU model (llvm-mca; + uiCA once
# scripts/mca/fetch-uica.sh has fetched it): for CPUs we can't run on; see README, "Estimating other CPUs"
mca:
	./scripts/mca/mca.sh
# the same kernels measured with perf on this machine (x86-64 Linux), added as a column next to the estimates
mca-validate: | $(B)
	./scripts/mca/validate.sh > $(B)/mca-measured.txt
	MEASURED=$(B)/mca-measured.txt ./scripts/mca/mca.sh

# planted bugs that the tests must catch (prints one line per mutant; read the output)
mutants:
	./scripts/mutants_fbparse.sh
	EMU=1 ./scripts/mutants_fbparse.sh | grep -i 'avx512\|simd\|SELF'
	./scripts/mutants_batch.sh

# ---- fuzzing (fuzz/): differential oracles shared by libFuzzer targets and Hypothesis properties ----
FUZZ_T := fbparse fastparse batchparse chunked
FUZZ_TIME ?= 30
FUZZ_CC ?= clang
FUZZ_SAN := -O1 -g -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all
FZ_INC := $(INC) -Ifuzz
FZ_DEPS := $(HDRS) fuzz/oracle.h fuzz/fuzz.h
$(B)/fuzz_seeds: fuzz/seeds.c $(HDRS) | $(B)
	$(CC_T) $< $(PICO) -o $@
$(B)/fuzz-seeds/.done: $(B)/fuzz_seeds
	mkdir -p $(B)/fuzz-seeds && ./$(B)/fuzz_seeds $(B)/fuzz-seeds && touch $@
# any compiler: the targets with a replay main(), on the seeds and the saved regressions
$(B)/replay_%: fuzz/fuzz_%.c fuzz/replay.c $(FZ_DEPS) | $(B)
	$(CC) $(CFLAGS) $(WARN) $(MARCH) $(FZ_INC) $< fuzz/replay.c $(PICO) -o $@
fuzz-replay: $(addprefix $(B)/replay_,$(FUZZ_T)) $(B)/fuzz-seeds/.done
	@set -e; for t in $(FUZZ_T); do ./$(B)/replay_$$t $(B)/fuzz-seeds fuzz/regressions; done
$(B)/fuzz_%: fuzz/fuzz_%.c $(FZ_DEPS) | $(B)
	$(FUZZ_CC) $(FUZZ_SAN) $(WARN) $(MARCH) $(FZ_INC) $< $(PICO) -o $@
fuzz: $(addprefix $(B)/fuzz_,$(FUZZ_T)) $(B)/fuzz-seeds/.done
	@for t in $(FUZZ_T); do mkdir -p $(B)/fuzz-corpus/$$t; \
	  ./$(B)/fuzz_$$t -max_total_time=$(FUZZ_TIME) -max_len=8192 -dict=fuzz/http.dict -print_final_stats=1 \
	    -artifact_prefix=$(B)/fuzz-$$t- $(B)/fuzz-corpus/$$t $(B)/fuzz-seeds fuzz/regressions > $(B)/fuzz-$$t.log 2>&1; rc=$$?; \
	  echo "$$t: $$(grep -h 'stat::number_of_executed_units' $(B)/fuzz-$$t.log | awk '{print $$2}') runs, corpus $$(ls $(B)/fuzz-corpus/$$t | wc -l | tr -d ' ')"; \
	  if [ $$rc != 0 ]; then grep -A3 -E "MISMATCH|ERROR: " $(B)/fuzz-$$t.log | head -20; echo "FUZZ FAILED: $$t (input saved as $(B)/fuzz-$$t-*, log $(B)/fuzz-$$t.log)"; exit 1; fi; done
	@echo "FUZZ: no mismatch"
# Hypothesis (pinned in fuzz/hyp/requirements.txt), through the oracle as a shared library
$(B)/libfuzzoracle.so: fuzz/oracle_lib.c $(FZ_DEPS) | $(B)
	$(CC) -O1 -g -shared -fPIC $(WARN) $(MARCH) $(FZ_INC) $< $(PICO) -o $@
$(B)/venv/.done: fuzz/hyp/requirements.txt | $(B)
	$(PYTHON) -m venv $(B)/venv && $(B)/venv/bin/pip -q install -r $< && touch $@
hypothesis: $(B)/libfuzzoracle.so $(B)/venv/.done
	$(B)/venv/bin/python fuzz/hyp/props.py
# the planted fbparse.h bugs against the Hypothesis properties (MUT_ONLY=regex for a subset)
mutants-fuzz: $(B)/venv/.done
	./scripts/mutants_fuzz.sh

# formatting and linting (scripts/lint.sh; pinned tools in ci/lint.Dockerfile, run through Docker)
format:
	./scripts/lint.sh --fix
lint:
	./scripts/lint.sh
hooks:
	git config core.hooksPath .githooks
clean:
	rm -rf $(B)
.PHONY: all lib mca mca-validate gen gencheck test test-quick asan bench bench-codspeed avx512 avx512-run mutants example-check fetch compare-all compare-go conformance extras-check fuzz fuzz-replay hypothesis mutants-fuzz format lint hooks clean
include mk/h2h3.mk
include mk/browser.mk
include mk/resp.mk
