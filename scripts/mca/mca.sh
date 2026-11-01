#!/bin/sh
# mca.sh - static throughput estimates of the SIMD kernels (scripts/mca/kernels.c) per backend and CPU model,
# with llvm-mca (LLVM, Apache-2.0; e.g. `brew install llvm`, or apt's llvm). Cycles per kernel call = the
# region's block reciprocal throughput: back-to-back calls, every load an L1 hit, no branch mispredicts. Use it
# to rank kernel variants and to look at CPUs we can't run on, not to predict whole-request times.
# With uiCA fetched (scripts/mca/fetch-uica.sh; AGPL, never vendored), the x86 kernels are also run through uiCA's
# Intel models, which track the Xeon's measured cycles much more closely than llvm-mca's (README, Benchmarks).
#   scripts/mca/mca.sh [LLVM_BIN_DIR]     (default: $LLVM, then /opt/homebrew/opt/llvm/bin, then PATH)
#   MEASURED=file scripts/mca/mca.sh      + a "measured" column from scripts/mca/validate.sh's output
cd "$(dirname "$0")/../.." || exit 1
M=${1:-${LLVM:-/opt/homebrew/opt/llvm/bin}}
[ -x "$M/llvm-mca" ] || M=$(dirname "$(command -v llvm-mca)")
[ -x "$M/llvm-mca" ] || {
  echo "llvm-mca not found (brew install llvm, or apt install llvm)"
  exit 1
}
S=$(mktemp -d "${TMPDIR:-/tmp}/mca.XXXXXX")
trap 'rm -rf "$S"' EXIT
U=${UICA:-third_party/uiCA}
UPY=${PYTHON:-build/venv/bin/python} # UICA=: an existing uiCA checkout (fetch-uica.sh)
[ -x "$UPY" ] && UPY=$(cd "$(dirname "$UPY")" && pwd)/$(basename "$UPY")
X86_CPUS="cascadelake icelake-server sapphirerapids graniterapids znver3 znver4 znver5 alderlake sierraforest"
ARM_CPUS="neoverse-n1 neoverse-n2 neoverse-v1 neoverse-v2 neoverse-v3 ampere1b apple-m4"
A2="-mavx2 -mbmi -mbmi2 -mpopcnt"
# cross-compiling needs system headers: on macOS the SDK's (Apple triples), elsewhere the host's (Linux triples)
if [ "$(uname)" = Darwin ]; then
  X86=x86_64-apple-macos13
  ARM=arm64-apple-macos13
  SYS="-isysroot $(xcrun --show-sdk-path)"
else
  X86=x86_64-linux-gnu
  ARM=aarch64-linux-gnu
  SYS=
fi
# backend name | target | flags
cat >"$S/backends" <<B
scalar|$X86|-march=x86-64 -DFP_FORCE_SCALAR
sse2|$X86|-march=x86-64
avx2|$X86|-march=x86-64 $A2
avx512|$X86|-march=x86-64 $A2 -mavx512f -mavx512bw -mavx512vl -mavx512cd -mavx512dq -DFP_USE_AVX512
zmm|$X86|-march=x86-64 $A2 -mavx512f -mavx512bw -mavx512vl -mavx512cd -mavx512dq -DFP_USE_AVX512 -DFP_USE_ZMM
neon|$ARM|-march=armv8-a
B
while IFS='|' read -r be tgt fl; do
  "$M/clang" -target "$tgt" $SYS -O3 -S -w $fl -Iinclude scripts/mca/kernels.c -o "$S/$be.s" || exit 1
  # llvm-mca's Mach-O x86 parser counts each region marker twice: there the marked regions are re-emitted as
  # plain asm (instructions and local labels) and analysed with the ELF triple. Other targets keep their file.
  # A region with a branch inside (a loop) is flagged: mca ignores branches, so a loop body would count once.
  python3 - "$S/$be.s" "$tgt" "$S/loops" <<'PY'
import re, sys
rewrite = sys.argv[2].startswith("x86_64-apple")
out, keep, name, br = [], False, None, set()
for l in open(sys.argv[1]):
    m = re.search(r"LLVM-MCA-(BEGIN|END) (\S+)", l)
    if m: keep, name = m.group(1) == "BEGIN", m.group(2); out.append(f"# LLVM-MCA-{m.group(1)} {name}\n" if rewrite else l); continue
    t = l.strip()
    if not keep or not t or t.startswith((".", "#", "//", ";")):
        if not rewrite: out.append(l)
        continue
    out.append(l)
    if True:
        if (t.endswith(":") and not t.startswith("Lloh")) or re.match(r"(j[a-z]+|b\.[a-z]+|b|cbn?z|tbn?z)\s", t): br.add(name)
open(sys.argv[1], "w").write("".join(out))
with open(sys.argv[3], "a") as f:
    for n in br: f.write(f"{n} {sys.argv[1].rsplit('/', 1)[1][:-2]}\n")
PY
  case "$tgt" in x86_64-apple*) mt=x86_64-linux-gnu ;; *) mt=$tgt ;; esac
  case "$tgt" in x86*) cpus=$X86_CPUS ;; *) cpus=$ARM_CPUS ;; esac
  for c in $cpus; do
    "$M/llvm-mca" -mtriple="$mt" -mcpu="$c" -iterations=200 "$S/$be.s" 2>/dev/null |
      awk -v be="$be" -v c="$c" '/Code Region - /{r=$NF} /Block RThroughput:/{print be, c, r, $3}'
  done
  # uiCA (Intel only): each region alone, assembled as the host's object format (its XED reads that)
  case "$tgt" in x86*) if [ -f $U/uiCA.py ] && [ -f $U/instrData/CLX_data.py ]; then
    if [ "$(uname)" = Darwin ]; then ot=x86_64-apple-macos13; else ot=x86_64-linux-gnu; fi
    for reg in $(sed -n 's/^# LLVM-MCA-BEGIN //p' "$S/$be.s"); do
      awk -v r="$reg" '$0 ~ "LLVM-MCA-BEGIN "r"$"{k=1;next} $0 ~ "LLVM-MCA-END "r"$"{k=0} k' "$S/$be.s" |
        perl -pe 's/\bL(CPI|_)/_x$1/g; s/##.*$//' >"$S/u.s"
      "$M/llvm-mc" -triple $ot -filetype=obj "$S/u.s" -o "$S/u.o" 2>/dev/null || continue
      for a in CLX ICL TGL; do
        t=$(cd $U && "$UPY" uiCA.py "$S/u.o" -arch $a -TPonly 2>/dev/null) && echo "$be uica-$a $reg $t"
      done
    done
  fi ;; esac
done <"$S/backends" >"$S/out"
touch "$S/loops"
[ -n "$MEASURED" ] && grep -v '^#' "$MEASURED" | awk '{print $2, "measured", $1, $3}' >>"$S/out"
python3 - "$S/out" "$S/loops" <<'PY'
import sys, collections
loops = {tuple(l.split()) for l in open(sys.argv[2])}
d = collections.OrderedDict(); cpus = ["measured"]
for l in open(sys.argv[1]):
    be, cpu, reg, t = l.split()
    d.setdefault((reg, be), {})[cpu] = float(t)
    if cpu not in cpus: cpus.append(cpu)
for arch in ("x86", "uica", "arm"):
    kind = lambda c: "arm" if c.startswith(("neoverse", "ampere", "apple")) else "uica" if c.startswith("uica") else "x86"
    cs = [c for c in cpus if kind(c) == arch or (c == "measured" and arch != "arm")]   # measured: an x86 box
    if not any(c != "measured" for c in cs): continue
    if not any("measured" in v for v in d.values()): cs = [c for c in cs if c != "measured"]
    # a CPU whose numbers equal an earlier column on every kernel shares that scheduling model
    same = {}
    for i, c in enumerate(cs):
        for e in cs[:i]:
            if all(v.get(c) == v.get(e) for v in d.values()) and e not in same: same[c] = e; break
    print(f"\n{'cycles per call (block rthroughput)':38s}" + "".join(f"{c[:12]:>13s}" for c in cs))
    for (reg, be), v in d.items():
        if reg == "empty" or not any(c in v for c in cs): continue
        flag = " *" if (reg, be) in loops else ""
        print(f"{(reg + ' / ' + be + flag):38s}" + "".join(f"{v[c]:13.2f}" if c in v else f"{'-':>13s}" for c in cs))
    for c, e in same.items(): print(f"  {c}: same numbers as {e} ({'uiCA' if arch == 'uica' else 'LLVM'} has no separate model for it)")
print("\n* the region contains a branch (a loop): mca counts its body once, so the number is not the kernel's cost")
PY
