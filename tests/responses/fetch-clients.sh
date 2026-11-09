#!/bin/sh
# Fetch and build the HTTP client parsers bench/bench_resp.c compares with (make bench-resp-clients), at pinned
# release tarballs (sha256-checked): libcurl 8.23.0 (a minimal static build: HTTP only, no TLS, no compression) and
# nginx 1.31.8 (configured, for the headers ngx_http_parse.c needs). Into third_party/resp-clients/ (git-ignored).
#   tests/responses/fetch-clients.sh
set -eu
cd "$(dirname "$0")/../.."
T=third_party/resp-clients
mkdir -p "$T"
get() { # get URL FILE SHA256
  [ -f "$T/$2" ] || curl -fsSL "$1" -o "$T/$2"
  echo "$3  $T/$2" | sha256sum -c --quiet - || {
    echo "fetch-clients: $2: sha256 mismatch" >&2
    exit 1
  }
}
get https://curl.se/download/curl-8.23.0.tar.xz curl-8.23.0.tar.xz \
  8dadd7d2536a314f982ad05a651b713f426bf7d02cc2c76cffb9796f2218e6c5
get https://nginx.org/download/nginx-1.31.8.tar.gz nginx-1.31.8.tar.gz \
  0652b760b3b772d2ec17b47c2fc15d9a95e6fe35cd5b877eadc1a62d9bc75af1
[ -d "$T/curl-8.23.0" ] || tar -C "$T" -xJf "$T/curl-8.23.0.tar.xz"
[ -d "$T/nginx-1.31.8" ] || tar -C "$T" -xzf "$T/nginx-1.31.8.tar.gz"
CFLAGS_RC=${CFLAGS_RC:--O3 -march=haswell}
if [ ! -f "$T/curl-build/lib/libcurl.a" ]; then
  cmake -S "$T/curl-8.23.0" -B "$T/curl-build" -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS="$CFLAGS_RC" \
    -DBUILD_SHARED_LIBS=OFF -DBUILD_CURL_EXE=OFF -DBUILD_TESTING=OFF -DBUILD_LIBCURL_DOCS=OFF -DBUILD_MISC_DOCS=OFF \
    -DENABLE_CURL_MANUAL=OFF -DHTTP_ONLY=ON -DCURL_ENABLE_SSL=OFF -DCURL_USE_LIBPSL=OFF -DCURL_USE_LIBSSH2=OFF \
    -DCURL_ZLIB=OFF -DCURL_BROTLI=OFF -DCURL_ZSTD=OFF -DUSE_NGHTTP2=OFF -DUSE_LIBIDN2=OFF \
    -DENABLE_THREADED_RESOLVER=OFF -DCURL_DISABLE_ALTSVC=ON -DCURL_DISABLE_HSTS=ON >"$T/curl-cmake.log" 2>&1
  cmake --build "$T/curl-build" -j"${JOBS:-1}" >"$T/curl-build.log" 2>&1
fi
if [ ! -f "$T/nginx-1.31.8/objs/ngx_auto_config.h" ]; then
  (cd "$T/nginx-1.31.8" && ./configure --with-cc-opt="$CFLAGS_RC" --without-http_rewrite_module \
    --without-http_gzip_module --without-pcre --without-http-cache >../nginx-configure.log 2>&1)
fi
scripts/fetch-thirdparty.sh http-parser
echo "fetch-clients: curl, nginx and http-parser ready in third_party/"
