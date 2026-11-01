#!/usr/bin/env python3
"""chart_h2h3.py > bench/bench_h2h3.svg: the README's HTTP/2 and HTTP/3 chart (Xeon Platinum 8260 numbers from
README.md, ns per request, the browser header set of bench/h2_headers.h). Same layout as bench/chart.py."""

PANELS = [
    (
        "HTTP/2 server: request in, response out (h2.h's job)",
        [
            ("h2.h", 564.7, True),
            ("nghttp2", 2319.0, False),
            ("h2 (Rust, hyper's)", 5141.0, False),
            ("x/net/http2 (Go)", 29824.3, False),
        ],
    ),
    (
        "HPACK decode (hpack.h's job)",
        [
            ("hpack.h", 323.1, True),
            ("ls-hpack (LiteSpeed)", 446.9, False),
            ("nghttp2", 627.4, False),
            ("h2o", 737.7, False),
            ("x/net/http2/hpack (Go)", 839.9, False),
        ],
    ),
    (
        "HTTP/3 server above QUIC (h3.h's job)",
        [
            ("h3.h", 3162.8, True),
            ("nghttp3", 4861.2, False),
        ],
    ),
    (
        "QPACK decode, 4 KB dynamic table (qpack.h's job)",
        [
            ("qpack.h", 1265.0, True),
            ("ls-qpack (LiteSpeed)", 1263.9, False),
            ("h2o", 1821.0, False),
            ("nghttp3", 1831.3, False),
        ],
    ),
    (
        "QPACK decode, static table only",
        [
            ("qpack.h", 2630.6, True),
            ("ls-qpack (LiteSpeed)", 2650.7, False),
            ("nghttp3", 4012.9, False),
            ("h2o", 5284.5, False),
            ("quic-go/qpack (Go)", 9061.5, False),
        ],
    ),
]
W, LBL, BAR, ROW, GAP = 760, 190, 470, 26, 46
h = 40 + sum(GAP + ROW * len(r) for _, r in PANELS) + 20
o = [
    f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{h}" viewBox="0 0 {W} {h}" font-family="-apple-system,Segoe UI,Helvetica,Arial,sans-serif" font-size="13">',
    f'<rect width="{W}" height="{h}" fill="#ffffff"/>',
    '<text x="16" y="26" font-size="15" font-weight="600" fill="#1f2328">ns per request, lower is better · Xeon Platinum 8260, in memory, a Chrome request</text>',
]
y = 40
for title, rows in PANELS:
    y += 30
    o.append(f'<text x="16" y="{y - 8}" font-weight="600" fill="#1f2328">{title}</text>')
    mx = max(v for _, v, _ in rows)
    for name, v, ours in rows:
        w = BAR * v / mx
        o.append(
            f'<text x="{LBL - 8}" y="{y + 17}" text-anchor="end" fill="#1f2328"{" font-weight=\"600\"" if ours else ""}>{name}</text>'
        )
        o.append(
            f'<rect x="{LBL}" y="{y + 4}" width="{w:.1f}" height="{ROW - 8}" rx="3" fill="{"#2f81f7" if ours else "#8c959f"}"/>'
        )
        o.append(f'<text x="{LBL + w + 6:.1f}" y="{y + 17}" fill="#1f2328">{v:,.0f}</text>')
        y += ROW
    y += GAP - 30
o.append("</svg>")
print("\n".join(o))
