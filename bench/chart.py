#!/usr/bin/env python3
"""chart.py > bench/bench.svg: the README's benchmark chart (Xeon Platinum 8260 numbers from README.md, ns/request,
general parsers +logic, i.e. doing the same routing / Bearer / Content-Length work as fastparse)."""
PANELS = [
    ("API traffic, read-heavy mix (fastparse.h's job)", [
        ("fastparse.h (AVX2)", 47.5, True), ("picohttpparser", 108.6, False), ("hparse (Zig)", 122.9, False),
        ("uWebSockets", 122.9, False), ("llhttp", 248.5, False)]),
    ("General traffic: a Chrome request, 1 KB (fbparse.h's job)", [
        ("fbparse.h (AVX2)", 345.2, True), ("picohttpparser", 448.9, False), ("hparse (Zig)", 716.6, False),
        ("llhttp", 1056.6, False)]),
]
W, LBL, BAR, ROW, GAP = 760, 190, 470, 26, 46
h = 40 + sum(GAP + ROW * len(r) for _, r in PANELS) + 20
o = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{h}" viewBox="0 0 {W} {h}" font-family="-apple-system,Segoe UI,Helvetica,Arial,sans-serif" font-size="13">',
     f'<rect width="{W}" height="{h}" fill="#ffffff"/>',
     f'<text x="16" y="26" font-size="15" font-weight="600" fill="#1f2328">ns per request, lower is better · Xeon Platinum 8260, gcc 13.3 -O3 -march=native</text>']
y = 40
for title, rows in PANELS:
    y += 30; o.append(f'<text x="16" y="{y - 8}" font-weight="600" fill="#1f2328">{title}</text>')
    mx = max(v for _, v, _ in rows)
    for name, v, ours in rows:
        w = BAR * v / mx
        o.append(f'<text x="{LBL - 8}" y="{y + 17}" text-anchor="end" fill="#1f2328"{" font-weight=\"600\"" if ours else ""}>{name}</text>')
        o.append(f'<rect x="{LBL}" y="{y + 4}" width="{w:.1f}" height="{ROW - 8}" rx="3" fill="{"#2f81f7" if ours else "#8c959f"}"/>')
        o.append(f'<text x="{LBL + w + 6:.1f}" y="{y + 17}" fill="#1f2328">{v:g}</text>')
        y += ROW
    y += GAP - 30
o.append('</svg>')
print("\n".join(o))
