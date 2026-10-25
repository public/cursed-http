#!/bin/sh
# validate.sh - measures what mca.sh estimates, on the machine it runs on (x86-64 Linux with perf): each kernel of
# scripts/mca/kernels.c per backend, 50M back-to-back calls on L1-hot data (kbench.c) under `perf stat -e cycles`,
# minus the empty kernel's call overhead. Prints "kernel backend cycles" lines; feed them back to mca.sh:
#   scripts/mca/validate.sh > measured.txt          (perf needs perf_event_paranoid <= 2 or root)
#   MEASURED=measured.txt scripts/mca/mca.sh        adds a "measured" column next to the estimates
# The README's calibration table is this script on a Xeon Platinum 8260, clang 18. Pin it (taskset -c N) on a busy box.
cd "$(dirname "$0")/../.."
CC=${CC:-$(command -v clang || command -v gcc)}; N=${N:-50000000}
command -v perf >/dev/null || { echo "perf not found" >&2; exit 1; }
case "$(uname -m)" in x86_64) ;; *) echo "validate.sh: x86-64 only (the backends below are x86)" >&2; exit 1;; esac
S=$(mktemp -d "${TMPDIR:-/tmp}/kb.XXXXXX"); trap 'rm -rf "$S"' EXIT
A2="-mavx2 -mbmi -mbmi2 -mpopcnt"; A5="$A2 -mavx512f -mavx512bw -mavx512vl -mavx512cd -mavx512dq -DFP_USE_AVX512"
echo "# $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //'); $($CC --version | head -1)" >&2
cyc() { perf stat -x, -e cycles "$S/kb_$1" "$2" "$N" 2>&1 >/dev/null | awk -F, '/cycles/{print $1}'; }
for spec in "scalar|-DFP_FORCE_SCALAR" "sse2|" "avx2|$A2" "avx512|$A5" "zmm|$A5 -DFP_USE_ZMM"; do
  be=${spec%%|*}; fl=${spec#*|}
  case "$be" in avx512|zmm) grep -q avx512bw /proc/cpuinfo || { echo "# $be: CPU lacks AVX-512, skipped" >&2; continue; };; esac
  $CC -O3 -w -march=x86-64 $fl -Iinclude scripts/mca/kbench.c -o "$S/kb_$be" || exit 1
  base=$(cyc "$be" empty)
  for k in fp_cls64 fb_all64 fb_nt64 fb_lfct64 fb_ctany512 fp_digits; do
    "$S/kb_$be" "$k" 1 >/dev/null || continue   # not in this build
    c=$(cyc "$be" "$k"); [ -n "$c" ] && echo "$k $be $(awk -v c="$c" -v b="$base" -v n="$N" 'BEGIN{printf "%.2f", (c - b) / n}')"
  done
done
