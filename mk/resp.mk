# HTTP/1.x responses for clients (include/fbresp.h)
#   make test-resp    the differential tests vs picohttpparser: native backend, scalar, SSE2, emulated AVX-512
RESP_CORPUS := $(B)/resp-corpus/responses.dat
RESP_HDRS := include/fbresp.h include/fbparse.h tests/fb_avx512_emu.h tests/resp_gen.h
RESP_BINS := $(B)/test_resp $(B)/test_resp_scalar $(B)/test_resp_emu512 $(B)/test_resp_llhttp
ifneq ($(HTTPARSE),)
  RESP_BINS += $(B)/test_resp_httparse
endif
ifeq ($(ARCH),x86_64)
  RESP_BINS += $(B)/test_resp_sse2
endif
$(B)/test_resp: tests/test_resp.c $(RESP_HDRS) $(B)/pico.o
	$(CC_T) $< $(B)/pico.o -o $@
$(B)/test_resp_scalar: tests/test_resp.c $(RESP_HDRS) $(B)/pico.o
	$(CC_T) -DFP_FORCE_SCALAR $< $(B)/pico.o -o $@
$(B)/test_resp_emu512: tests/test_resp.c $(RESP_HDRS) $(B)/pico.o
	$(CC_T) -DFP_AVX512_EMU $< $(B)/pico.o -o $@
$(B)/test_resp_sse2: tests/test_resp.c $(RESP_HDRS) $(B)/pico_base.o
	$(CC) $(CFLAGS) $(WARN) $(CHP_BASE) $(INC) $< $(B)/pico_base.o -o $@
$(B)/asan_resp: tests/test_resp.c $(RESP_HDRS) | $(B)
	$(CC) $(SAN) $(WARN) $(MARCH) $(INC) $< $(PICO) -o $@
test-resp: $(RESP_BINS) $(B)/asan_resp $(B)/check_resp_corpus $(RESP_CORPUS) $(B)/replay_resp
	@set -e; $(RUN) 4 $(B)/test_resp $(FBMODE); \
	  for t in $(filter-out $(B)/test_resp,$(RESP_BINS)); do $(RUN) 4 $$t quick; done; \
	  ASAN_OPTIONS=detect_leaks=0 $(RUN) 4 $(B)/asan_resp quick; \
	  echo "== $(B)/check_resp_corpus"; ./$(B)/check_resp_corpus $(dir $(RESP_CORPUS)) > $(B)/logs/check_resp_corpus.log \
	    || { tail -30 $(B)/logs/check_resp_corpus.log; exit 1; }; tail -3 $(B)/logs/check_resp_corpus.log; \
	  ./$(B)/replay_resp fuzz/regressions-resp
	@echo "RESPONSE TESTS PASSED"
# framing vs llhttp (response mode)
$(B)/test_resp_llhttp: tests/test_resp_llhttp.c $(RESP_HDRS) $(LLHTTP_O)
	$(CC_T) -Ivendor/llhttp/include $< $(LLHTTP_O) -o $@
# libFuzzer: fbresp.h vs pico (fuzz/fuzz_resp.c); RESP_FUZZ_TIME seconds, default 30. replay_resp: any compiler
RESP_FUZZ_TIME ?= 30
$(B)/fuzz_resp: fuzz/fuzz_resp.c $(RESP_HDRS) $(FZ_DEPS) | $(B)
	$(FUZZ_CC) $(FUZZ_SAN) $(WARN) $(MARCH) $(FZ_INC) $< $(PICO) -o $@
$(B)/replay_resp: fuzz/fuzz_resp.c fuzz/replay.c $(RESP_HDRS) $(FZ_DEPS) | $(B)
	$(CC) $(CFLAGS) $(WARN) $(MARCH) $(FZ_INC) $< fuzz/replay.c $(PICO) -o $@
fuzz-resp: $(B)/fuzz_resp
	mkdir -p $(B)/fuzz-corpus/resp
	./$(B)/fuzz_resp -max_total_time=$(RESP_FUZZ_TIME) -max_len=8192 -dict=fuzz/http.dict -print_final_stats=1 \
	  -artifact_prefix=$(B)/fuzz-resp- $(B)/fuzz-corpus/resp $(wildcard tests/responses/corpus)
# the captured response corpus (tests/responses/README.md)
$(B)/check_resp_corpus: tests/responses/check.c $(RESP_HDRS) $(LLHTTP_O) $(B)/pico.o
	$(CC_T) -Ivendor/llhttp/include $< $(B)/pico.o $(LLHTTP_O) -o $@
$(RESP_CORPUS): tests/responses/corpus/responses.dat.gz tests/responses/corpus/index.tsv
	@mkdir -p $(dir $@)
	gzip -dc $< > $@ && cp tests/responses/corpus/index.tsv $(dir $@)
check-resp-corpus: $(B)/check_resp_corpus $(RESP_CORPUS)
	./$(B)/check_resp_corpus $(dir $(RESP_CORPUS))
# httparse's Response (needs rustc and scripts/fetch-thirdparty.sh httparse): the same build as scripts/build-extras.sh
RUSTC ?= rustc
ifeq ($(ARCH),x86_64)
  RESP_RCPU ?= -C target-cpu=haswell
endif
RESP_RCFG := --cfg 'feature="std"' --cfg httparse_simd --cfg httparse_simd_neon_intrinsics
ifeq ($(ARCH),x86_64)
  RESP_RCFG += --cfg httparse_simd_target_feature_avx2 --cfg httparse_simd_target_feature_sse42
endif
RESP_RFL := -C opt-level=3 -C codegen-units=1 $(RESP_RCPU)
$(B)/resp_rs/libhttparse.rlib: third_party/httparse/src/lib.rs
	@mkdir -p $(dir $@)
	$(RUSTC) --edition 2018 --crate-type rlib --crate-name httparse $(RESP_RFL) $(RESP_RCFG) $< -o $@
$(B)/libhx_resp.a: bench/httparse_resp_shim.rs $(B)/resp_rs/libhttparse.rlib
	$(RUSTC) --edition 2018 --crate-type staticlib $(RESP_RFL) -C lto=fat -C panic=abort \
	  --extern httparse=$(B)/resp_rs/libhttparse.rlib -L $(B)/resp_rs $< -o $@
$(B)/test_resp_httparse: tests/test_resp_httparse.c $(RESP_HDRS) $(B)/libhx_resp.a $(B)/pico.o
	$(CC_T) $< $(B)/pico.o $(B)/libhx_resp.a -lpthread -ldl -lm -o $@
# benchmarks: make bench-resp (pico, llhttp; + httparse with HTTPARSE=1, needs rustc)
$(B)/llhttp_resp_shim.o: bench/llhttp_resp_shim.c | $(B)
	$(CC) -O3 $(MARCH) -Ivendor/llhttp/include -Ivendor/pico -c $< -o $@
RESP_BENCH_O := $(B)/pico.o $(LLHTTP_O) $(B)/llhttp_resp_shim.o
$(B)/bench_resp: bench/bench_resp.c $(RESP_HDRS) $(RESP_BENCH_O)
	$(CC_T) $< $(RESP_BENCH_O) -o $@
$(B)/bench_resp_hx: bench/bench_resp.c $(RESP_HDRS) $(RESP_BENCH_O) $(B)/libhx_resp.a
	$(CC_T) -DHAVE_HTTPARSE $< $(RESP_BENCH_O) $(B)/libhx_resp.a -lpthread -ldl -lm -o $@
bench-resp: $(if $(HTTPARSE),$(B)/bench_resp_hx,$(B)/bench_resp) $(RESP_CORPUS)
	./$< 200 $(dir $(RESP_CORPUS))
