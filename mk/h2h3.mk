# HTTP/2 + HTTP/3 (include/hfield.h, hpack.h, h2.h, ...). Reference libraries come from
# scripts/fetch-thirdparty.sh nghttp2 nghttp3 and are built here from source.
#   make test-h2h3     every HTTP/2 / HTTP/3 test
TP := third_party
N2 := $(TP)/nghttp2/lib
N3 := $(TP)/nghttp3/lib
H2B := $(B)/h2h3
N2INC := -I$(N2)/includes -I$(H2B)/gen -I$(N2) -DNGHTTP2_STATICLIB -DHAVE_ARPA_INET_H -DHAVE_NETINET_IN_H
N3INC := -I$(N3)/includes -I$(H2B)/gen -I$(N3) -DNGHTTP3_STATICLIB -DHAVE_ARPA_INET_H -DHAVE_NETINET_IN_H
H2HDRS := include/hfield.h include/hpack.h include/hreq.h $(wildcard include/h2.h include/qpack.h include/h3.h include/quic.h)
H2CC = $(CC) $(CFLAGS) $(WARN) $(MARCH) -Iinclude -Itests

$(H2B)/gen/nghttp2/nghttp2ver.h: $(N2)/includes/nghttp2/nghttp2ver.h.in
	@mkdir -p $(dir $@)
	sed -e 's/@PACKAGE_VERSION@/1.70.0/' -e 's/@PACKAGE_VERSION_NUM@/0x014600/' $< > $@
$(H2B)/gen/nghttp3/version.h: $(N3)/includes/nghttp3/version.h.in
	@mkdir -p $(dir $@)
	sed -e 's/@PACKAGE_VERSION@/1.18.0/' -e 's/@PACKAGE_VERSION_NUM@/0x011200/' $< > $@
H2GEN := $(H2B)/gen/nghttp2/nghttp2ver.h $(H2B)/gen/nghttp3/version.h
$(H2B)/n2/%.o: $(N2)/%.c $(H2GEN)
	@mkdir -p $(dir $@)
	$(CC) -O2 -g $(N2INC) -w -c $< -o $@
$(H2B)/n3/%.o: $(N3)/%.c $(H2GEN)
	@mkdir -p $(dir $@)
	$(CC) -O2 -g $(N3INC) -w -c $< -o $@
$(H2B)/libnghttp2.a: $(patsubst $(N2)/%.c,$(H2B)/n2/%.o,$(wildcard $(N2)/*.c))
	ar rcs $@ $^
$(H2B)/libnghttp3.a: $(patsubst $(N3)/%.c,$(H2B)/n3/%.o,$(wildcard $(N3)/*.c) $(N3)/sfparse/sfparse.c)
	ar rcs $@ $^

$(H2B)/test_hpack: tests/test_hpack.c tests/rfc7541_vectors.h $(H2HDRS) $(H2B)/libnghttp2.a
	$(H2CC) $(N2INC) $< $(H2B)/libnghttp2.a -o $@
$(H2B)/test_hpack_scalar: tests/test_hpack.c tests/rfc7541_vectors.h $(H2HDRS) $(H2B)/libnghttp2.a
	$(H2CC) -DHV_FORCE_SCALAR $(N2INC) $< $(H2B)/libnghttp2.a -o $@

$(H2B)/test_h2: tests/test_h2.c $(H2HDRS) $(H2B)/libnghttp2.a
	$(H2CC) $(N2INC) $< $(H2B)/libnghttp2.a -o $@
$(H2B)/test_h2_scalar: tests/test_h2.c $(H2HDRS) $(H2B)/libnghttp2.a
	$(H2CC) -DHV_FORCE_SCALAR $(N2INC) $< $(H2B)/libnghttp2.a -o $@
$(H2B)/test_h2_asan: tests/test_h2.c $(H2HDRS) $(H2B)/libnghttp2.a
	$(CC) $(SAN) $(WARN) $(MARCH) -Iinclude -Itests $(N2INC) $< $(H2B)/libnghttp2.a -o $@

$(H2B)/test_qpack: tests/test_qpack.c $(H2HDRS) $(H2B)/libnghttp3.a
	$(H2CC) $(N3INC) $< $(H2B)/libnghttp3.a -o $@
$(H2B)/test_qpack_asan: tests/test_qpack.c $(H2HDRS) $(H2B)/libnghttp3.a
	$(CC) $(SAN) $(WARN) $(MARCH) -Iinclude -Itests $(N3INC) $< $(H2B)/libnghttp3.a -o $@

$(H2B)/test_h3: tests/test_h3.c $(H2HDRS) $(H2B)/libnghttp3.a
	$(H2CC) $(N3INC) $< $(H2B)/libnghttp3.a -o $@
$(H2B)/test_h3_asan: tests/test_h3.c $(H2HDRS) $(H2B)/libnghttp3.a
	$(CC) $(SAN) $(WARN) $(MARCH) -Iinclude -Itests $(N3INC) $< $(H2B)/libnghttp3.a -o $@

H2TESTS := $(H2B)/test_quic $(H2B)/test_quic_interop $(H2B)/test_h3 $(H2B)/test_qpack $(H2B)/test_hpack $(H2B)/test_hpack_scalar $(H2B)/test_h2 $(H2B)/test_h2_scalar
test-h2h3: $(H2TESTS)
	@for t in $(H2TESTS); do echo "== $$t"; $$t || exit 1; done
.PHONY: test-h2h3

mutants-h2: $(H2B)/libnghttp2.a $(H2B)/libnghttp3.a
	python3 -I scripts/mutants_h2.py include $(H2B)/mutants
	@for d in $(H2B)/mutants/*/; do \
	  $(CC) $(SAN) -w $(MARCH) -I$$d -Itests $(N2INC) tests/test_h2.c $(H2B)/libnghttp2.a -o $$d/t2 && \
	  $(CC) $(SAN) -w $(MARCH) -I$$d -Itests $(N2INC) tests/test_hpack.c $(H2B)/libnghttp2.a -o $$d/thp && \
	  $(CC) $(SAN) -w $(MARCH) -I$$d -Itests $(N3INC) tests/test_h3.c $(H2B)/libnghttp3.a -o $$d/t3 && \
	  $(CC) $(SAN) -w $(MARCH) -I$$d -Itests $(N3INC) tests/test_qpack.c $(H2B)/libnghttp3.a -o $$d/tqp && \
	  if timeout 120 $$d/t2 > $$d/out.txt 2>&1 && timeout 120 $$d/thp >> $$d/out.txt 2>&1 && \
	     timeout 120 $$d/t3 >> $$d/out.txt 2>&1 && timeout 120 $$d/tqp >> $$d/out.txt 2>&1; then echo "mutant $$d SURVIVED"; \
	  else echo "mutant $$d killed: $$(grep -m1 FAIL $$d/out.txt | cut -c1-90)"; fi; done
.PHONY: mutants-h2

# h2spec (summerwind/h2spec, fetched at a pinned commit, built with Go) against examples/h2_server.c
$(H2B)/h2_server: examples/h2_server.c $(H2HDRS)
	@mkdir -p $(H2B)
	$(CC) -O2 $(WARN) -Iinclude $< -o $@
$(H2B)/h2spec:
	cd $(TP)/h2spec && CGO_ENABLED=0 go build -o $(abspath $@) ./cmd/h2spec
h2spec: $(H2B)/h2_server $(H2B)/h2spec
	@$(H2B)/h2_server 18080 2>/dev/null & pid=$$!; sleep 0.3; \
	$(H2B)/h2spec -h 127.0.0.1 -p 18080 -S; rc=$$?; kill $$pid; exit $$rc
.PHONY: h2spec

# picotls (TLS 1.3 for quic.h) from scripts/fetch-thirdparty.sh picotls, with the OpenSSL backend
PTLS := $(TP)/picotls
PTLS_SRC := $(PTLS)/lib/picotls.c $(PTLS)/lib/openssl.c $(PTLS)/lib/pembase64.c $(PTLS)/lib/hpke.c
$(H2B)/ptls/%.o: $(PTLS)/lib/%.c
	@mkdir -p $(dir $@)
	$(CC) -O2 -g -I$(PTLS)/include -w -c $< -o $@
$(H2B)/libpicotls.a: $(patsubst $(PTLS)/lib/%.c,$(H2B)/ptls/%.o,$(PTLS_SRC))
	ar rcs $@ $^
QINC := -I$(PTLS)/include
$(H2B)/test_quic: tests/test_quic.c tests/rfc9001_vectors.h $(H2HDRS) include/qhp.h $(H2B)/libpicotls.a
	$(H2CC) $(QINC) $< $(H2B)/libpicotls.a -lcrypto -o $@

# ngtcp2 (QUIC reference client for the interop test), with its picotls crypto backend
NT := $(TP)/ngtcp2
NTINC := -I$(NT)/lib/includes -I$(H2B)/gen -I$(NT)/lib -I$(NT)/crypto/includes -I$(NT)/crypto $(QINC) -DNGTCP2_STATICLIB -DHAVE_ARPA_INET_H -DHAVE_NETINET_IN_H
$(H2B)/gen/ngtcp2/version.h: $(NT)/lib/includes/ngtcp2/version.h.in
	@mkdir -p $(dir $@)
	sed -e 's/@PACKAGE_VERSION@/1.25.0/' -e 's/@PACKAGE_VERSION_NUM@/0x011900/' $< > $@
$(H2B)/nt/%.o: $(NT)/%.c $(H2B)/gen/ngtcp2/version.h
	@mkdir -p $(dir $@)
	$(CC) -O2 -g $(NTINC) -w -c $< -o $@
NT_SRC := $(wildcard $(NT)/lib/*.c) $(NT)/crypto/shared.c $(NT)/crypto/picotls/picotls.c
$(H2B)/libngtcp2.a: $(patsubst $(NT)/%.c,$(H2B)/nt/%.o,$(NT_SRC))
	ar rcs $@ $^
$(H2B)/test_quic_interop: tests/test_quic_interop.c $(H2HDRS) include/qhp.h $(H2B)/libngtcp2.a $(H2B)/libpicotls.a $(H2B)/libnghttp3.a
	$(H2CC) $(QINC) $(N3INC) $(NTINC) $< $(H2B)/libngtcp2.a $(H2B)/libnghttp3.a $(H2B)/libpicotls.a -lcrypto -o $@
$(H2B)/test_quic_interop_asan: tests/test_quic_interop.c $(H2HDRS) include/qhp.h $(H2B)/libngtcp2.a $(H2B)/libpicotls.a $(H2B)/libnghttp3.a
	$(CC) $(SAN) $(WARN) $(MARCH) -Iinclude -Itests $(QINC) $(N3INC) $(NTINC) $< $(H2B)/libngtcp2.a $(H2B)/libnghttp3.a $(H2B)/libpicotls.a -lcrypto -o $@
