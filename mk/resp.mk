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
