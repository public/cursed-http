#!/usr/bin/env bash
# lint.sh [--fix] [--staged]: formatting and lint checks for first-party code (vendor/ and third_party/ excluded).
#   formatting: clang-format (C, .clang-format), shfmt -i 2 -ci (shell), ruff format (Python, ruff.toml)
#   linting:    shellcheck (warnings and errors), ruff check, cppcheck (warning + portability, library sources;
#               skipped with --staged: it takes minutes)
#   --fix       rewrite files with the formatters (and ruff's safe fixes) instead of reporting
#   --staged    only the files staged for commit (the pre-commit hook)
# The tools are pinned in ci/lint.Dockerfile. Unless LINT_LOCAL=1 (CI sets it inside that image), this script
# re-runs itself in that image, so formatting is identical on every machine. Exits non-zero on any finding.
set -euo pipefail
cd "$(dirname "$0")/.."

# per-repository: which C sources cppcheck analyses (it follows their #includes)
CPPCHECK_SRC=(src/*.c)

fix=0 staged=0
for a in "$@"; do
  case $a in
    --fix) fix=1 ;;
    --staged) staged=1 ;;
    *) echo "usage: $0 [--fix] [--staged]" >&2 && exit 2 ;;
  esac
done

if [ "${LINT_LOCAL:-0}" != 1 ]; then
  command -v docker >/dev/null || { echo "lint.sh: needs Docker (or LINT_LOCAL=1 with the tools in ci/lint.Dockerfile)" >&2 && exit 2; }
  img=lint-$(basename "$PWD"):$(git hash-object ci/lint.Dockerfile | cut -c1-12)
  docker image inspect "$img" >/dev/null 2>&1 || docker build -q -t "$img" -f ci/lint.Dockerfile ci >/dev/null
  files="" # the host may have bash 3.2 (macOS): no mapfile out here
  [ $staged = 1 ] && files=$(git diff --cached --name-only --diff-filter=ACMR | tr '\n' ' ')
  exec docker run --rm -e LINT_LOCAL=1 -e LINT_FILES="$files" -e LINT_STAGED=$staged \
    -v "$PWD":/r -w /r -u "$(id -u):$(id -g)" -e HOME=/tmp "$img" bash scripts/lint.sh "$@"
fi

git() { command git -c safe.directory='*' "$@"; }
pick() { # tracked first-party files matching the globs; with --staged, only staged ones
  local all
  all=$(git ls-files -- "$@" | grep -vE '^(vendor|third_party|src/fiat)/' || true)
  if [ "${LINT_STAGED:-$staged}" = 1 ]; then
    [ -n "${LINT_FILES:-}" ] || return 0
    grep -xF -f <(tr ' ' '\n' <<<"$LINT_FILES") <<<"$all" || true
  else
    printf '%s\n' "$all"
  fi
}
mapfile -t C < <(pick '*.c' '*.h' '*.inc' '*.cpp' | sed '/^$/d')
mapfile -t SH < <(pick '*.sh' | sed '/^$/d')
mapfile -t PY < <(pick '*.py' | sed '/^$/d')
bad=0
step() { printf '== %s\n' "$1"; }

if [ ${#C[@]} -gt 0 ]; then
  step "clang-format (${#C[@]} files)"
  if [ $fix = 1 ]; then clang-format -i "${C[@]}"; else clang-format --dry-run --Werror "${C[@]}" || bad=1; fi
fi
if [ ${#SH[@]} -gt 0 ]; then
  step "shfmt (${#SH[@]} files)"
  if [ $fix = 1 ]; then shfmt -w -i 2 -ci "${SH[@]}"; else shfmt -d -i 2 -ci "${SH[@]}" || bad=1; fi
  step "shellcheck"
  shellcheck -S warning "${SH[@]}" || bad=1
fi
if [ ${#PY[@]} -gt 0 ]; then
  step "ruff (${#PY[@]} files)"
  if [ $fix = 1 ]; then
    ruff format --no-cache -q "${PY[@]}"
    ruff check --no-cache -q --fix "${PY[@]}" || bad=1
  else
    ruff format --no-cache --check -q "${PY[@]}" || bad=1
    ruff check --no-cache -q "${PY[@]}" || bad=1
  fi
fi
if [ "${LINT_STAGED:-$staged}" != 1 ]; then # whole-program and slow (~2 min): make lint and CI, not the hook
  step "cppcheck"
  cppcheck -q --error-exitcode=1 --enable=warning,portability --inline-suppr --std=c11 -Iinclude -Isrc \
    --max-configs=1 --suppress=missingIncludeSystem --suppress=toomanyconfigs "${CPPCHECK_SRC[@]}" || bad=1
fi

if [ $bad = 1 ]; then
  [ $fix = 1 ] && echo "lint: the remaining findings need a manual fix" >&2 || echo "lint: run scripts/lint.sh --fix to apply the formatters" >&2
  exit 1
fi
echo "lint: clean"
