# HTTP/2 + HTTP/3 (include/hfield.h, hpack.h, h2.h, ...). Reference libraries come from
# scripts/fetch-thirdparty.sh nghttp2 nghttp3 and are built here from source.
#   make test-h2h3     every HTTP/2 / HTTP/3 test
TP := third_party
N2 := $(TP)/nghttp2/lib
N3 := $(TP)/nghttp3/lib
H2B := $(B)/h2h3
N2INC := -I$(N2)/includes -I$(H2B)/gen -I$(N2) -DNGHTTP2_STATICLIB -DHAVE_ARPA_INET_H -DHAVE_NETINET_IN_H
N3INC := -I$(N3)/includes -I$(H2B)/gen -I$(N3) -DNGHTTP3_STATICLIB -DHAVE_ARPA_INET_H -DHAVE_NETINET_IN_H
H2HDRS := include/hfield.h include/hpack.h $(wildcard include/h2.h include/qpack.h include/h3.h)
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

H2TESTS := $(H2B)/test_hpack $(H2B)/test_hpack_scalar
test-h2h3: $(H2TESTS)
	@for t in $(H2TESTS); do echo "== $$t"; $$t || exit 1; done
.PHONY: test-h2h3
