#!/usr/bin/env python3
"""Capture raw HTTP/1.x responses from a server on 127.0.0.1 into the corpus (tests/responses/README.md).

  capture.py SERVER PORT OUTDIR      appends to OUTDIR/responses.dat (u32 LE length + bytes) and OUTDIR/index.tsv

One connection per case; every byte the server sends is kept, until it closes or goes quiet. The index says which
requests the connection carried (so a checker knows HEAD from GET), in order.
"""

import re
import socket
import struct
import sys
import time

HOST = "Host: 127.0.0.1\r\nUser-Agent: cursed-http-capture/1\r\n"


def req(method, path, extra="", version="1.1", body=b""):
    return f"{method} {path} HTTP/{version}\r\n{HOST}{extra}\r\n".encode() + body


# name, [(method, bytes)], mode: "pipe" = all at once, "seq" = one after another on the same connection
CASES = [
    ("small", [("GET", req("GET", "/small.txt"))], "seq"),
    ("big", [("GET", req("GET", "/big.html"))], "seq"),
    ("gzip", [("GET", req("GET", "/big.html", "Accept-Encoding: gzip\r\n"))], "seq"),
    ("head", [("HEAD", req("HEAD", "/small.txt"))], "seq"),
    ("head-gzip", [("HEAD", req("HEAD", "/big.html", "Accept-Encoding: gzip\r\n"))], "seq"),
    ("range", [("GET", req("GET", "/big.html", "Range: bytes=0-99\r\n"))], "seq"),
    ("multirange", [("GET", req("GET", "/big.html", "Range: bytes=0-9,20-29\r\n"))], "seq"),
    ("notfound", [("GET", req("GET", "/does-not-exist"))], "seq"),
    ("dir-redirect", [("GET", req("GET", "/sub"))], "seq"),
    ("http10", [("GET", req("GET", "/small.txt", version="1.0"))], "seq"),
    ("http10-ka", [("GET", req("GET", "/small.txt", "Connection: keep-alive\r\n", version="1.0"))], "seq"),
    ("close", [("GET", req("GET", "/small.txt", "Connection: close\r\n"))], "seq"),
    (
        "keepalive-seq",
        [
            ("GET", req("GET", "/small.txt")),
            ("HEAD", req("HEAD", "/big.html")),
            ("GET", req("GET", "/big.html", "Accept-Encoding: gzip\r\n")),
        ],
        "seq",
    ),
    (
        "pipeline",
        [
            ("GET", req("GET", "/small.txt")),
            ("HEAD", req("HEAD", "/small.txt")),
            ("GET", req("GET", "/does-not-exist")),
            ("GET", req("GET", "/big.html", "Accept-Encoding: gzip\r\n")),
        ],
        "pipe",
    ),
    ("expect-100", [("POST", req("POST", "/echo", "Expect: 100-continue\r\nContent-Length: 5\r\n"))], "expect"),
    ("post", [("POST", req("POST", "/echo", "Content-Length: 5\r\n", body=b"hello"))], "seq"),
    ("options", [("OPTIONS", req("OPTIONS", "*"))], "seq"),
    ("bad-request", [("GET", b"GET /\x01 HTTP/1.1\r\n" + HOST.encode() + b"\r\n")], "seq"),
    ("chunked", [("GET", req("GET", "/chunked"))], "seq"),
    ("trailers", [("GET", req("GET", "/trailers", "TE: trailers\r\n"))], "seq"),
    ("gzip-dyn", [("GET", req("GET", "/gzip", "Accept-Encoding: gzip\r\n"))], "seq"),
    ("204", [("GET", req("GET", "/204"))], "seq"),
    ("304", [("GET", req("GET", "/304"))], "seq"),
    ("close-delimited", [("GET", req("GET", "/close"))], "seq"),
    ("early-hints", [("GET", req("GET", "/early"))], "seq"),
    (
        "upgrade",
        [
            (
                "GET",
                req(
                    "GET",
                    "/upgrade",
                    "Connection: Upgrade\r\nUpgrade: websocket\r\n"
                    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                    "Sec-WebSocket-Version: 13\r\n",
                ),
            )
        ],
        "seq",
    ),
]


def read_quiet(s, quiet):
    out = b""
    s.settimeout(quiet)
    while True:
        try:
            d = s.recv(65536)
        except socket.timeout:
            return out, False
        if not d:
            return out, True
        out += d


def run(port, reqs, mode, quiet=0.4):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    got = b""
    if mode == "pipe":
        s.sendall(b"".join(r for _, r in reqs))
        got, _ = read_quiet(s, quiet * 2)
    elif mode == "expect":
        s.sendall(reqs[0][1])
        got, closed = read_quiet(s, quiet)
        if not closed:
            s.sendall(b"hello")
            more, _ = read_quiet(s, quiet)
            got += more
    else:
        for _, r in reqs:
            try:
                s.sendall(r)
            except OSError:
                break
            d, closed = read_quiet(s, quiet)
            got += d
            if closed:
                break
    s.close()
    return got


def conditional(port):
    """GET once for the validators, then the conditional GET (only that one is kept): a 304."""
    first = run(port, [("GET", req("GET", "/small.txt"))], "seq")
    h = first.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    extra = ""
    m = re.search(r"(?im)^etag:\s*(.+?)\s*$", h)
    if m:
        extra += f"If-None-Match: {m.group(1)}\r\n"
    m = re.search(r"(?im)^last-modified:\s*(.+?)\s*$", h)
    if m:
        extra += f"If-Modified-Since: {m.group(1)}\r\n"
    if not extra:
        return None
    reqs = [("GET", req("GET", "/small.txt", extra))]
    return reqs, run(port, reqs, "seq")


def main():
    server, port, outdir = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    for _ in range(100):  # wait for the server to listen
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            break
        except OSError:
            time.sleep(0.1)
    rows = []
    for name, reqs, mode in CASES:
        rows.append((name, reqs, run(port, reqs, mode)))
    c = conditional(port)
    if c:
        rows.append(("conditional", c[0], c[1]))
    with open(f"{outdir}/responses.dat", "ab") as dat, open(f"{outdir}/index.tsv", "a") as idx:
        for name, reqs, got in rows:
            if not got:
                continue
            dat.write(struct.pack("<I", len(got)) + got)
            idx.write(f"{server}\t{name}\t{','.join(m for m, _ in reqs)}\t{len(got)}\n")
    print(f"{server}: {sum(1 for r in rows if r[2])} connections captured")


if __name__ == "__main__":
    main()
