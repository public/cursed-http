#!/usr/bin/env python3
"""Extract the QPACK static table (RFC 9204 Appendix A) into C, and check it entry by entry against
nghttp3's copy when third_party/nghttp3 is present.
    curl -fsSL -o build/rfc9204.txt https://www.rfc-editor.org/rfc/rfc9204.txt
    python3 -I gen/gen_qpack_static.py build/rfc9204.txt   (prints the QPS(...) rows used in include/qpack.h)"""
import re, sys, os
lines = [l.rstrip("\n") for l in open(sys.argv[1], encoding="utf-8")]
a = next(i for i, l in enumerate(lines) if l.startswith("Appendix A.  Static Table"))
b = next(i for i, l in enumerate(lines) if l.startswith("Appendix B."))
rows, cur = [], None
for l in lines[a:b]:
    t = l.strip()
    if t.startswith("+-") or t.startswith("+="):
        if cur: rows.append(cur)
        cur = None
        continue
    if not t.startswith("|"):
        continue  # page headers / footers inside the table
    cells = [c.strip() for c in t.strip("|").split("|")]
    if len(cells) != 3 or cells[0] == "Index":
        continue
    if cur is None:
        cur = [cells[0], cells[1], cells[2]]
    else:  # wrapped row: continue name / value
        cur[1] += cells[1]
        if cells[2]:  # the RFC wraps long values at a space, or right after '-' / '/'
            cur[2] += ("" if not cur[2] or cur[2].endswith(("-", "/")) else " ") + cells[2]
if cur: rows.append(cur)
tab = [(int(i), n, v) for i, n, v in rows if i.isdigit()]
assert [t[0] for t in tab] == list(range(99)), [t[0] for t in tab]
ref = os.path.join(os.path.dirname(__file__), "..", "third_party/nghttp3/lib/nghttp3_qpack.c")
if os.path.exists(ref):
    s = open(ref).read()
    body = s[s.index("nghttp3_qpack_static_header stable[] = {"):]
    got = re.findall(r'MAKE_STATIC_HD\(\s*"([^"]*)",\s*"([^"]*)"', body[:body.index("};")])
    assert len(got) == 99, len(got)
    bad = [(i, n, v, got[i]) for i, n, v in tab if got[i] != (n, v)]
    assert not bad, bad[:5]
    print("/* checked against nghttp3's static table (stable[]): all 99 entries equal */")
print("/* RFC 9204 Appendix A, extracted by gen/gen_qpack_static.py */")
for i, n, v in tab:
    print('  QPS("%s", "%s"), /* %d */' % (n, v, i))
