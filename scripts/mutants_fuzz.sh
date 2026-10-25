#!/bin/sh
# The planted bugs of scripts/mutants_fbparse.sh, against the fuzzing tools instead of the unit test: each
# mutated copy of include/fbparse.h is built into the Hypothesis oracle library, and the properties
# (fuzz/hyp/props.py, HYP_EXAMPLES each, default 300) must fail. Needs build/venv (make hypothesis).
# MUT_ONLY=regex runs only the matching mutants (a dev-cycle check); HYP_ONLY limits the properties.
# Backend-specific mutants only bite on their platform; the ASan-only mutant needs an ASan build.
cd "$(dirname "$0")/.."; S=$(mktemp -d "${TMPDIR:-/tmp}/fz-mutants.XXXXXX"); mkdir -p $S/include $S/db
case "$(uname -m)" in x86_64|amd64) M=-march=haswell;; *) M=-mcpu=native;; esac
F="-O1 -g -shared -fPIC -w ${MARCH:-$M} ${EMU:+-DFP_AVX512_EMU}"
mut() { [ -n "$MUT_ONLY" ] && ! echo "$2" | grep -qE "$MUT_ONLY" && return
  sed "$1" include/fbparse.h > $S/include/fbparse.h
  if cmp -s include/fbparse.h $S/include/fbparse.h; then echo "$2: SED DID NOT APPLY"; return; fi
  ${CC:-cc} $F -I$S/include -Iinclude -Itests -Ivendor/pico -Ifuzz fuzz/oracle_lib.c vendor/pico/picohttpparser.c -o $S/libfuzzoracle.so 2>&1 | head -3
  rm -rf $S/db; FZ_BUILD=$S HYP_DB=$S/db HYP_EXAMPLES=${HYP_EXAMPLES:-300} build/venv/bin/python fuzz/hyp/props.py > $S/out.txt 2>&1
  r=$(grep -c FAILED $S/out.txt); echo "$2: $r properties failed ($(grep FAILED $S/out.txt | cut -d: -f1 | tr '\n' ' '))"; }
eval "$(grep '^mut ' scripts/mutants_fbparse.sh)"
rm -rf $S
