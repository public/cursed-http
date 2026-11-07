# HTTP/1.x responses for clients (include/fbresp.h)
#   make test-resp    the differential tests vs picohttpparser: native backend, scalar, SSE2, emulated AVX-512
RESP_HDRS := include/fbresp.h include/fbparse.h tests/fb_avx512_emu.h
RESP_BINS := $(B)/test_resp $(B)/test_resp_scalar $(B)/test_resp_emu512
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
test-resp: $(RESP_BINS) $(B)/asan_resp
	@set -e; $(RUN) 4 $(B)/test_resp $(FBMODE); \
	  for t in $(filter-out $(B)/test_resp,$(RESP_BINS)); do $(RUN) 4 $$t quick; done; \
	  ASAN_OPTIONS=detect_leaks=0 $(RUN) 4 $(B)/asan_resp quick
	@echo "RESPONSE TESTS PASSED"
# framing vs llhttp (response mode)
$(B)/test_resp_llhttp: tests/test_resp_llhttp.c $(RESP_HDRS) $(LLHTTP_O)
	$(CC_T) -Ivendor/llhttp/include $< $(LLHTTP_O) -o $@
RESP_BINS += $(B)/test_resp_llhttp
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
