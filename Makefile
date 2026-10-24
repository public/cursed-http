# cursed-http-parser
#   make test         every differential test (native backend, scalar, emulated AVX-512, generated headers)
#   make test-quick   the same with smaller fuzz counts (CI)
#   make asan         ASan + UBSan builds of the tests (quick mode)
#   make bench        benchmarks: fastparse, fbparse, batchparse, and the comparison vs pico / llhttp
#   make avx512       real AVX-512 builds (need an AVX-512 CPU to run: make avx512-run)
#   make mutants      planted bugs: every mutant must make a test fail
#   make compare-all  + uWebSockets, httparse, hparse (fetched at pinned commits; rustc / zig optional)
#   make conformance  third-party conformance suites (fetched at pinned commits)
#   make gen          regenerate build/fastparse_gen.h and build/fastparse_pgo.h from gen/example_spec.json
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
GENCHECK := $(B)/check_example_spec $(B)/check_toy_spec

all: $(FP_BINS) $(FB_BINS) $(BP_BINS) $(GENCHECK)

$(B):
	mkdir -p $(B)

# ---- generated headers (gen/httpgen.py): the API-specific region of fastparse.h from a spec ----
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
	for s in example_spec toy_spec; do $(PYTHON) gen/httpgen.py vectors gen/$$s.json $(GENVECTORS) 1 | $(B)/check_$$s || exit 1; done

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

GENVECTORS ?= 200000
FBMODE ?=
RUN := ./scripts/run_test.sh
test: all gencheck
	@set -e; for t in $(FP_BINS); do $(RUN) 1 $$t nobench; done
	@set -e; $(RUN) 2 $(B)/test_fbparse $(FBMODE); \
	  for t in test_fbparse_scalar test_fbparse_emu512 test_fbparse_emuzmm; do $(RUN) 1 $(B)/$$t quick; done
	@set -e; for t in $(BP_BINS); do $(RUN) 1 $$t; done
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
$(B)/asan_batch: tests/test_batch.c $(HDRS) | $(B)
	$(CC) $(SAN) $(WARN) $(MARCH) $(INC) -DBP_AVX512_EMU $< $(PICO) -o $@
asan: $(B)/asan_fastparse $(B)/asan_fbparse $(B)/asan_fbparse_emu $(B)/asan_batch
	@set -e; export ASAN_OPTIONS=detect_leaks=0; $(RUN) 1 $(B)/asan_fastparse nobench; \
	  $(RUN) 1 $(B)/asan_fbparse quick; $(RUN) 1 $(B)/asan_fbparse_emu quick; $(RUN) 1 $(B)/asan_batch
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
$(B)/compare: bench/compare.c $(HDRS) $(B)/ours_hand.o $(B)/ours_gen.o $(B)/ours_pgo.o $(B)/pico.o $(LLHTTP_O) $(B)/llhttp_shim.o
	$(CC_T) $< $(B)/ours_hand.o $(B)/ours_gen.o $(B)/ours_pgo.o $(B)/pico.o $(LLHTTP_O) $(B)/llhttp_shim.o -o $@
$(B)/bench_fbparse: bench/bench_fbparse.c $(HDRS) $(B)/pico.o $(LLHTTP_O) $(B)/llhttp_shim.o
	$(CC_T) $< $(B)/pico.o $(LLHTTP_O) $(B)/llhttp_shim.o -o $@
$(B)/bench_batch: bench/bench_batch.c $(HDRS) $(B)/pico.o
	$(CC_T) $< $(B)/pico.o -o $@
bench: $(B)/test_fastparse $(B)/compare $(B)/bench_fbparse $(B)/bench_batch
	./$(B)/test_fastparse benchonly
	./$(B)/compare
	./$(B)/bench_fbparse
	./$(B)/bench_batch

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

# planted bugs that the tests must catch (prints one line per mutant; read the output)
mutants:
	./scripts/mutants_fbparse.sh
	EMU=1 ./scripts/mutants_fbparse.sh | grep -i 'avx512\|SELF'
	./scripts/mutants_batch.sh

clean:
	rm -rf $(B)
.PHONY: all gen gencheck test test-quick asan bench avx512 avx512-run mutants fetch compare-all conformance extras-check clean
