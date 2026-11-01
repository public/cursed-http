#!/bin/sh
# fetch-uica.sh - uiCA (Abel & Reineke, uops.info; AGPL-3.0, fetched, never vendored) into third_party/uiCA at a
# pinned commit, with its XED module and instruction data. Needs git, curl, a C compiler and python3 with
# setuptools (make hypothesis's build/venv has pip; this script installs setuptools there).
set -e
cd "$(dirname "$0")/../.."
T=third_party/uiCA
PY=${PYTHON:-build/venv/bin/python}
[ -x "$PY" ] || {
  python3 -m venv build/venv
  PY=build/venv/bin/python
}
"$PY" -m pip -q install setuptools
[ -d $T/.git ] || git clone -q https://github.com/andreas-abel/uiCA.git $T
git -C $T checkout -q 6ebeeab # 2024-01-14
git -C $T submodule update --init -q
(cd $T/XED-to-XML && "../../../$PY" ./mfile.py --opt=2 --no-encoder pymodule >../xedbuild.log 2>&1) || {
  echo "XED build failed: $T/xedbuild.log"
  exit 1
}
cp $T/XED-to-XML/xed.* $T/
curl -sSfL -o $T/instructions.xml https://www.uops.info/instructions.xml
(cd $T && "../../$PY" ./convertXML.py instructions.xml && rm instructions.xml)
echo "uiCA ready: $T (archs: $(ls $T/instrData | sed -n 's/_data.py//p' | tr '\n' ' '))"
