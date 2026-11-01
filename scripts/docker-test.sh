#!/bin/sh
# docker-test.sh [amd64|arm64] [make targets...]   (default: the host's arch, "test-quick asan")
# Runs the tests in Linux (Ubuntu 24.04) with gcc and clang. The checkout is mounted read-only and copied.
# DOCKER_CPUS sets --cpuset-cpus (e.g. DOCKER_CPUS=8-13 to keep off cores another job uses).
set -e
cd "$(dirname "$0")/.."
ARCH=${1:-$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')}
[ $# -gt 0 ] && shift
TARGETS=${*:-test-quick asan}
IMG=cursed-http-parser-test:$ARCH
docker build -q --platform linux/$ARCH -t $IMG ci >/dev/null
docker run --rm --platform linux/$ARCH ${DOCKER_CPUS:+--cpuset-cpus $DOCKER_CPUS} -v "$PWD":/src:ro $IMG sh -c "
  set -e; uname -sm
  for cc in gcc clang; do
    echo \"===== \$cc: \$(\$cc --version | head -1)\"
    rm -rf /w; mkdir /w; cd /src; tar --exclude=./build --exclude=./.git --exclude=./third_party -cf - . | tar -C /w -xf -; cd /w
    make -s CC=\$cc $TARGETS
  done"
