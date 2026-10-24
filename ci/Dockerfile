# Test image: Ubuntu 24.04 with gcc 13, clang 18, make and python3.
FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential clang libclang-rt-18-dev make python3 && rm -rf /var/lib/apt/lists/*
