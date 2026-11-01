# Lint image: the pinned formatters and linters scripts/lint.sh runs (locally via Docker, in CI, and in the
# pre-commit hook), so everyone gets byte-identical formatting.
FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      clang-format-18 cppcheck shellcheck shfmt git pipx ca-certificates \
 && ln -s /usr/bin/clang-format-18 /usr/local/bin/clang-format \
 && PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install ruff==0.6.9 \
 && rm -rf /var/lib/apt/lists/*
