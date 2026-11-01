#!/usr/bin/env python3
"""Property tests for the parsers with Hypothesis, through build/libfuzzoracle (fuzz/oracle_lib.c).

    make hypothesis                      (HYP_EXAMPLES=n per property, default 300; HYP_SEED=n to fix the seed)

Requests come from a grammar, not from byte mutation. Valid requests are built from parts whose
meaning is known, so that the expected result can be written down independently of any parser.
Messy requests are valid ones with damage applied in the places where parsers tend to disagree. Long
values and padding headers are sized so that line ends and the end of the head land on 16/32/64-byte
block boundaries and on the long-value skip windows.

Properties:
  differential   fbparse == picohttpparser, the fastparse contract, every batchparse lane == fast_parse
                 (the same oracles as the libFuzzer targets), on valid and on messy requests
  damaged        the same oracles on valid requests with exactly one damaged field
  prefixes       fbparse == picohttpparser on every prefix of a valid or messy request
  fb_model       fb_parse_request on a valid request: the head length, method, path, minor version and
                 every header name/value are exactly what the grammar put there
  req_model      fb_parse_req on a valid request: route, id, Bearer token, body framing are exactly what
                 the routing rules (README) say; fast_parse gives the same or falls back
Hypothesis shrinks a failure to a minimal request and saves it in build/hyp-db, so the next run tries it
first.
"""

import ctypes
import os
import sys

from hypothesis import HealthCheck, given, note, seed, settings, strategies as st
from hypothesis.database import DirectoryBasedExampleDatabase

HERE = os.path.dirname(os.path.abspath(__file__))
BUILD = os.environ.get("FZ_BUILD", os.path.join(HERE, "..", "..", "build"))
LIB = ctypes.CDLL(os.path.join(BUILD, "libfuzzoracle.so"))
LIB.fz_fb.argtypes = [
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.c_size_t,
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_size_t,
]
LIB.fz_fast.argtypes = LIB.fz_batch.argtypes = LIB.fz_fb_prefixes.argtypes = [
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_size_t,
]
LIB.fz_fbparse.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_int)]
LIB.fz_req.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int, ctypes.POINTER(ctypes.c_longlong)]

NEED_MORE, FALLBACK, INVALID = 0, -1, -2
R_NOTFOUND, R_FEED, R_HEALTH, R_GETPOST, R_CREATE, R_LIKE = range(6)
MAXH = 40  # the reference allows 48 headers; stay below
SETTINGS = settings(
    max_examples=int(os.environ.get("HYP_EXAMPLES", "300")),
    deadline=None,
    database=DirectoryBasedExampleDatabase(os.environ.get("HYP_DB", os.path.join(BUILD, "hyp-db"))),
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large, HealthCheck.large_base_example],
)

# ---- the grammar ----
TCHAR = b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
VCHAR = bytes(range(0x21, 0x7F))
PATHCHAR = bytes(c for c in range(0x21, 0x7F))
# sizes just below, at and above the block and window boundaries the SIMD code works in
BOUNDARY = sorted(
    {
        n + d
        for n in (8, 16, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 2048, 3072, 4096)
        for d in (-2, -1, 0, 1, 2)
    }
)
token = st.binary(min_size=1, max_size=12).map(lambda b: bytes(TCHAR[c % len(TCHAR)] for c in b))


def chars_of(alphabet, size):
    return st.binary(min_size=size, max_size=size).map(lambda b: bytes(alphabet[c % len(alphabet)] for c in b))


def recase(name):
    return st.sampled_from([name, name.lower(), name.upper(), name.title()]) | st.binary(
        min_size=len(name), max_size=len(name)
    ).map(lambda m: bytes(c ^ 0x20 if (k & 1 and chr(c).isalpha()) else c for c, k in zip(name, m)))


ident = st.one_of(
    st.integers(1, 10**16 - 1).map(lambda n: str(n).encode()),  # an id that parses
    st.integers(0, 10**20).map(lambda n: str(n).encode()),  # 0, and too many digits
    st.tuples(st.integers(1, 6), st.integers(1, 10**6)).map(
        lambda t: b"0" * t[0] + str(t[1]).encode()
    ),  # leading zeros
    st.sampled_from([b"", b"-1", b"+1", b"1.5", b"abc", b"1a", b"0x10", b"%31"]),
    chars_of(PATHCHAR, 3),
)
method = st.one_of(
    st.sampled_from([b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS", b"PATCH", b"get", b"Post"]), token
)
path = st.one_of(
    st.sampled_from([b"/feed", b"/health", b"/posts", b"/", b"*", b"/feed/", b"/posts/", b"/healthz"]),
    ident.map(lambda i: b"/posts/" + i),
    ident.map(lambda i: b"/posts/" + i + b"/like"),
    st.tuples(
        st.sampled_from([b"/feed", b"/posts/1", b"/x"]), st.integers(0, 40).flatmap(lambda n: chars_of(PATHCHAR, n))
    ).map(lambda t: t[0] + b"?" + t[1]),
    st.integers(1, 600).flatmap(lambda n: chars_of(PATHCHAR, n)).map(lambda p: b"/" + p),
)


def value_of(size):
    """A header value: visible characters with interior SP/HT; never starts or ends with whitespace."""
    if size == 0:
        return st.just(b"")
    return st.tuples(chars_of(VCHAR, size), st.binary(max_size=size)).map(
        lambda t: bytes(
            (b" \t"[m & 1] if (m % 7 == 0 and 0 < i < size - 1) else c)
            for i, (c, m) in enumerate(zip(t[0], t[1] + bytes(size)))
        )
    )


value_len = st.one_of(st.integers(0, 40), st.sampled_from(BOUNDARY))
generic_value = value_len.flatmap(value_of)
ows = st.sampled_from([b"", b"", b" ", b"\t", b"  ", b" \t"])
header_name = st.one_of(
    st.sampled_from(
        [
            b"Host",
            b"User-Agent",
            b"Accept",
            b"Accept-Encoding",
            b"Cookie",
            b"Connection",
            b"X-Request-Id",
            b"Content-Type",
            b"Contentlength",
            b"Content-Len",
            b"Content-Lengths",
            b"Authorizations",
            b"Transfer-Encodin",
            b"X-Content-Length",
        ]
    ).flatmap(recase),
    token,
)


@st.composite
def header(draw):
    kind = draw(st.integers(0, 9))
    if kind == 0:
        name = draw(recase(b"Content-Length"))
        val = draw(
            st.one_of(
                st.integers(0, 200).map(lambda n: str(n).encode()),
                st.integers(0, 10**12).map(lambda n: str(n).encode()),
                st.sampled_from([b"00", b"01", b"-1", b"1 1", b"1,1", b"", b"+5", b"0x5", b"5 "]).map(
                    lambda v: v.strip()
                ),
            )
        )
    elif kind == 1:
        name = draw(recase(b"Authorization"))
        val = draw(
            st.one_of(
                token.map(lambda t: b"Bearer " + t),
                value_len.flatmap(value_of).map(lambda t: b"Bearer " + t),
                st.sampled_from([b"Bearer", b"bearer x", b"Basic dXNlcg==", b"Bearer  two", b"BEARER x"]),
            )
        )
    elif kind == 2:
        name = draw(recase(b"Transfer-Encoding"))
        val = draw(st.sampled_from([b"chunked", b"gzip, chunked", b"identity"]))
    elif kind == 3:
        name = draw(recase(b"Connection"))
        val = draw(
            st.sampled_from(
                [
                    b"keep-alive",
                    b"Keep-Alive",
                    b"close",
                    b"Close",
                    b"keep-alive, close",
                    b"close, keep-alive",
                    b"upgrade",
                    b"keep-alivex",
                    b"Keep-Alive, Upgrade",
                    b"te, close",
                ]
            )
        )
    else:
        name, val = draw(header_name), draw(generic_value)
    return name, draw(ows), val, draw(ows)


api_path = st.one_of(
    st.sampled_from([b"/feed", b"/health", b"/posts"]),
    ident.map(lambda i: b"/posts/" + i),
    ident.map(lambda i: b"/posts/" + i + b"/like"),
)


@st.composite
def api_header(draw):
    return (
        draw(header())
        if draw(st.integers(0, 2))
        else draw(
            st.sampled_from(
                [
                    (b"Authorization", b" ", b"Bearer abc.def", b""),
                    (b"authorization", b"\t", b"Bearer second", b""),
                    (b"Content-Length", b" ", b"2", b""),
                    (b"content-length", b"", b"0", b" "),
                    (b"Content-Length", b" ", b"02", b""),
                    (b"Transfer-Encoding", b" ", b"chunked", b""),
                ]
            )
        )
    )


@st.composite
def valid_request(draw, api=False, long_value=False):
    """(bytes, parts): a request picohttpparser and RFC 9112 both accept, and what it is made of."""
    m = draw(st.sampled_from([b"GET", b"POST"])) if api else draw(method)
    p = draw(api_path) if api else draw(path)
    minor = draw(st.sampled_from([1, 1, 1, 1, 0]))
    head = m + b" " + p + b" HTTP/1." + str(minor).encode() + b"\r\n"
    spans = [
        ("method", 0, len(m)),
        ("path", len(m) + 1, len(m) + 1 + len(p)),
        ("version", len(head) - 10, len(head) - 2),
        ("eol", len(head) - 2, len(head)),
    ]
    headers = draw(st.lists(api_header() if api else header(), max_size=8 if api else MAXH - 1))
    if long_value:  # one value long enough for fbparse's skip windows (they start after two 64-byte blocks)
        headers.insert(
            draw(st.integers(0, len(headers))),
            (b"X-Long", b" ", draw(st.sampled_from([1100, 2100, 600, 4200, 300, 200]).flatmap(value_of)), b""),
        )
    if draw(st.booleans()):  # a padding header that puts the end of the head near a 64-byte boundary
        cur = (
            len(head)
            + sum(len(n) + 1 + len(a) + len(v) + len(b) + 2 for n, a, v, b in headers)
            + len(b"X-Pad: \r\n\r\n")
        )
        target = (cur // 64 + draw(st.integers(1, 3))) * 64 + draw(st.integers(-3, 3))
        headers.insert(draw(st.integers(0, len(headers))), (b"X-Pad", b" ", draw(value_of(max(0, target - cur))), b""))
    for n, a, v, b in headers:
        spans += [
            ("name", len(head), len(head) + len(n)),
            ("value", len(head) + len(n) + 1 + len(a), len(head) + len(n) + 1 + len(a) + len(v)),
        ]
        head += n + b":" + a + v + b + b"\r\n"
        spans.append(("eol", len(head) - 2, len(head)))
    head += b"\r\n"
    spans.append(("eol", len(head) - 2, len(head)))
    body = draw(st.binary(max_size=300))
    data = head + body
    if draw(st.integers(0, 3)) == 0:  # a second request behind it (pipelining)
        data += draw(
            st.sampled_from(
                [
                    b"GET /feed HTTP/1.1\r\nHost: x\r\n\r\n",
                    b"POST /posts/7/like HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}",
                ]
            )
        )
    return data, dict(
        method=m, path=p, minor=minor, headers=[(n, v) for n, a, v, b in headers], head_len=len(head), spans=spans
    )


# bytes that change what a field is, by class (drawn class first, so rare classes like DEL come up often)
POISON = st.one_of(
    st.sampled_from([0x7F, 0x1F, 0x20, 0x21, 0x7E, 0x80]),
    st.integers(0, 0x1F),
    st.sampled_from(b" \t"),
    st.just(0x7F),
    st.sampled_from([0x80, 0xC3, 0xFF]),
    st.sampled_from(b':;"/\\()<>@,=?[]{}'),
    st.sampled_from(b"0:"),
).map(lambda c: bytes([c]))


@st.composite
def field_damage(draw, data, spans):
    """One byte of POISON put into, onto or at the edge of one field (method, path, version, header name, header
    value), an emptied field, or a changed line ending; positions favour the field edges and 64-byte boundaries."""
    # Hypothesis favours the first choice: the fields where a byte changes most come first
    kind = draw(
        st.sampled_from(
            [k for k in ("path", "value", "name", "version", "method", "eol") if any(k == x for x, _, _ in spans)]
        )
    )
    s, e = draw(st.sampled_from([(a, b) for k, a, b in spans if k == kind]))
    if kind == "eol":
        data[s:e] = draw(st.sampled_from([b"\n", b"\r", b"\r\r\n", b"\n\r", b"\r\x00\n"]))
        return data
    if kind == "version" and draw(st.booleans()):
        data[s:e] = draw(
            st.sampled_from(
                [
                    b"HTTP/1.:",
                    b"HTTP/1./",
                    b"HTTP/1.a",
                    b"HTTP/1.10",
                    b"HTTP/1.",
                    b"HTTP/1",
                    b"HTTP/2.0",
                    b"HTTP/0.9",
                    b"http/1.1",
                    b"HTTP/1.1 ",
                    b"HTTP /1.1",
                    b"HTTP/1.1\x00",
                    b"HTTP/1.9",
                ]
            )
        )
        return data
    op = draw(st.integers(0, 4))
    if op == 0:
        data[s:e] = b""
        return data
    edges = [s, max(s, e - 1), e, min(e, s + 1)] + [x for x in range(s - s % 64 + 64, e, 64)]
    pos = (
        draw(st.one_of(st.sampled_from(edges), st.integers(s, e)))
        if e - s < 128
        else draw(st.one_of(st.integers(s, e), st.sampled_from(edges)))
    )
    if op <= 2 and pos < e:
        data[pos : pos + 1] = draw(POISON)
    else:
        data[pos:pos] = draw(POISON)
    return data


@st.composite
def messy_request(draw):
    """A valid request with damage where parsers disagree: one damaged field (field_damage), then up to three
    byte-level changes: line endings, whitespace, control bytes, folding, a leading empty line, truncation."""
    data, parts = draw(valid_request(api=draw(st.booleans())))
    data = draw(field_damage(bytearray(data), parts["spans"]))
    for _ in range(draw(st.integers(0, 3))):
        if not data:
            break
        i = draw(st.integers(0, len(data) - 1))
        op = draw(st.integers(0, 10))
        if op == 0:
            crlf = data.find(b"\r\n", i)
            if crlf >= 0:
                data[crlf : crlf + 2] = draw(st.sampled_from([b"\n", b"\r", b"\r\r\n", b"\n\r", b"\r\n "]))
        elif op == 1:
            data[i:i] = draw(
                st.one_of(
                    st.integers(0, 0x20).map(lambda c: bytes([c])),
                    st.sampled_from([b"\x7f", b"\x80", b"\xff", b":"]),
                    st.integers(0x80, 0xFF).map(lambda c: bytes([c])),
                )
            )
        elif op == 2:
            data[i : i + 1] = b""
        elif op == 3:
            colon = data.find(b":", i)
            if colon >= 0:
                data[colon:colon] = draw(st.sampled_from([b" ", b"\t", b"\r", b"\x00"]))
        elif op == 4:
            crlf = data.find(b"\r\n", i)
            if crlf >= 0:
                data[crlf + 2 : crlf + 2] = b" folded" + b"\r\n" if draw(st.booleans()) else b"\t\r\n"
        elif op == 5:
            data[i] = data[i] ^ 0x20
        elif op == 6:
            line_end = data.find(b"\r\n", i)
            line_start = data.rfind(b"\r\n", 0, i)
            if line_end >= 0 and line_start >= 0:
                data[line_end + 2 : line_end + 2] = data[line_start + 2 : line_end + 2]  # duplicate a line
        elif op == 7:
            del data[draw(st.integers(0, len(data))) :]  # truncate
        elif op == 8:
            data[0:0] = draw(st.sampled_from([b"\r\n", b"\n", b"\r\n\r\n", b" ", b"\r"]))  # leading empty line
        elif op == 9:
            eol = data.find(b"\n")
            if eol >= 0:
                data[eol + 1 : eol + 1] = draw(
                    st.sampled_from([b" ", b"\t", b" x\r\n", b"\tx: y\r\n"])
                )  # fold right after the request line
        else:
            data[i:i] = draw(st.binary(min_size=1, max_size=8))
    return bytes(data)


any_request = st.one_of(valid_request().map(lambda t: t[0]), messy_request(), st.binary(max_size=600))
model_request = st.one_of(valid_request(), valid_request(api=True))


# ---- the properties ----
def check_differential(data, max_headers, last_len):
    err = ctypes.create_string_buffer(256)
    for name, call in (
        ("fbparse vs pico", lambda: LIB.fz_fb(data, len(data), max_headers, last_len, err, 256)),
        ("fastparse contract", lambda: LIB.fz_fast(data, len(data), err, 256)),
        ("batchparse lanes", lambda: LIB.fz_batch(data, len(data), err, 256)),
    ):
        assert call() == 0, f"{name}: {err.value.decode(errors='replace')}"


@SETTINGS
@given(any_request, st.sampled_from([64, 64, 64, 0, 1, 2, 3, 8]), st.integers(0, 2000))
def differential(data, max_headers, last_len):
    note(f"request: {data!r}")
    check_differential(data, max_headers, min(last_len, len(data)))


@st.composite
def damaged_request(draw):
    """A valid request with exactly one damaged field: a second fault could hide the first (both sides -1)."""
    if draw(st.integers(0, 2)) == 0:  # damage inside a long value
        data, parts = draw(valid_request(long_value=True))
        longest = max((x for x in parts["spans"] if x[0] == "value"), key=lambda x: x[2] - x[1])
        return bytes(draw(field_damage(bytearray(data), [longest])))
    data, parts = draw(valid_request(api=draw(st.booleans())))
    return bytes(draw(field_damage(bytearray(data), parts["spans"])))


@SETTINGS
@given(damaged_request())
def damaged(data):
    note(f"request: {data!r}")
    check_differential(data, 64, 0)


@SETTINGS
@given(st.one_of(valid_request().map(lambda t: t[0]), messy_request()))
def prefixes(data):
    note(f"request: {data!r}")
    err = ctypes.create_string_buffer(256)
    assert (
        LIB.fz_fb_prefixes(data, len(data), err, 256) == 0
    ), f"fbparse vs pico on a prefix: {err.value.decode(errors='replace')}"


def strip_ows(v):
    return v.strip(b" \t")


@SETTINGS
@given(model_request)
def fb_model(req):
    data, parts = req
    note(f"request: {data!r}")
    out = (ctypes.c_int * (6 + 4 * 64))()
    r = LIB.fz_fbparse(data, len(data), out)
    assert r == parts["head_len"], f"fb_parse_request returned {r}, the head is {parts['head_len']} bytes"
    get = lambda off, n: data[off : off + n]
    assert get(out[0], out[1]) == parts["method"]
    assert get(out[2], out[3]) == parts["path"]
    assert out[4] == parts["minor"]
    assert out[5] == len(parts["headers"]), f"{out[5]} headers, expected {len(parts['headers'])}"
    for i, (n, v) in enumerate(parts["headers"]):
        o = out[6 + 4 * i : 10 + 4 * i]
        assert o[0] >= 0 and get(o[0], o[1]) == n, f"header {i} name {get(o[0], o[1])!r}, expected {n!r}"
        assert get(o[2], o[3]) == strip_ows(v), f"header {i} value {get(o[2], o[3])!r}, expected {v!r}"


def model(data, parts, zeros=False):
    """The routing rules (README, fastparse.h) on a valid request: (ret, fields) independently of any parser.
    zeros: fast_parse's one documented difference, a Content-Length with leading zeros (012 = 12)."""
    if parts["minor"] != 1:
        return FALLBACK, None
    m, p = parts["method"], parts["path"]

    def digits(s):
        return int(s) if 1 <= len(s) <= 16 and s.isdigit() and int(s) > 0 else None

    route, ident = R_NOTFOUND, None
    if m == b"GET":
        if p == b"/feed":
            route = R_FEED
        elif p == b"/health":
            route = R_HEALTH
        elif p.startswith(b"/posts/"):
            ident = digits(p[7:])
            route = R_GETPOST if ident is not None or b"/" not in p[7:] else R_NOTFOUND
    elif m == b"POST":
        if p == b"/posts":
            route = R_CREATE
        elif len(p) >= 12 and p.startswith(b"/posts/") and p.endswith(b"/like"):
            ident = digits(p[7:-5])
            route = R_LIKE if ident is not None or b"/" not in p[7:-5] else R_NOTFOUND
    cl, have_cl, tok = 0, False, None
    seen_auth = False
    for n, v in parts["headers"]:
        v, ln = strip_ows(v), n.lower()
        if ln == b"authorization" and not seen_auth:
            seen_auth = True
            if v.startswith(b"Bearer "):
                tok = v[7:]
        elif ln == b"content-length":
            if (
                have_cl
                or not 1 <= len(v) <= 9
                or not v.isdigit()
                or (len(v) > 1 and v[:1] == b"0" and not (zeros and int(v) > 0))
            ):
                return FALLBACK, None
            cl, have_cl = int(v), True
        elif len(ln) >= 16 and ln.startswith(b"transfer-encodin"):
            return FALLBACK, None
    if route not in (R_CREATE, R_LIKE):
        tok = None
    if parts["head_len"] + cl > len(data):
        return NEED_MORE, None
    return parts["head_len"] + cl, dict(route=route, id=ident, tok=tok, body=(parts["head_len"], cl))


def got_fields(data, out):
    return dict(
        route=out[0],
        id=out[2] if out[1] else None,
        tok=data[out[4] : out[4] + out[5]] if out[3] else None,
        body=(out[6], out[7]),
    )


@SETTINGS
@given(model_request)
def req_model(req):
    data, parts = req
    note(f"request: {data!r}")
    want, fields = model(data, parts)
    out = (ctypes.c_longlong * 8)()
    r = LIB.fz_req(data, len(data), 1, out)  # fb_parse_req: always the exact answer
    assert r == want, f"fb_parse_req returned {r}, the rules say {want}"
    if want > 0:
        assert got_fields(data, out) == fields, f"fb_parse_req {got_fields(data, out)}, the rules say {fields}"
    want, fields = model(data, parts, zeros=True)
    r = LIB.fz_req(data, len(data), 0, out)  # fast_parse: the exact answer, or FALLBACK
    # RFC 9112 9.6: a Connection header other than exactly keep-alive must reach the caller, so the fast path falls back
    if any(n.lower() == b"connection" and strip_ows(v).lower() != b"keep-alive" for n, v in parts["headers"]):
        assert r == FALLBACK, f"fast_parse returned {r} on a request whose Connection header is not keep-alive"
    if r != FALLBACK:
        assert r == want, f"fast_parse returned {r}, the rules say {want}"
        if want > 0:
            assert got_fields(data, out) == fields, f"fast_parse {got_fields(data, out)}, the rules say {fields}"


PROPS = [differential, damaged, prefixes, fb_model, req_model]

if __name__ == "__main__":
    s = os.environ.get("HYP_SEED")
    only = os.environ.get("HYP_ONLY")  # e.g. HYP_ONLY=damaged,prefixes
    if only:
        PROPS = [p for p in PROPS if p.__name__ in only.split(",")]
    failed = 0
    for prop in PROPS:
        test = seed(int(s))(prop) if s else prop
        try:
            test()
            print(f"{prop.__name__}: OK ({SETTINGS.max_examples} examples)")
        except Exception as e:  # Hypothesis has already printed the shrunk example
            failed += 1
            print(f"{prop.__name__}: FAILED: {e}")
    sys.exit(1 if failed else 0)
