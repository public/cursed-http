"""scripts/top1k_post.py - turn top1k_crawl.py's output (one or more chunk directories) into tests/top1k/.

    top1k_post.py OUTDIR CRAWLER_IP CHUNKDIR...

- merges the chunks (requests.dat + index.tsv, responses.dat + responses-index.tsv), ordered by rank and kind;
- bodies: scrubbed shape-preservingly (as the crawler does cookie values) and cut to 1 KB, with Content-Length
  rewritten to match. A body only matters to the parsers through its framing, and analytics payloads describe the
  crawler;
- CRAWLER_IP: every occurrence of the crawling machine's address (sites echo it in payloads and response fields) is
  replaced by a TEST-NET-3 address of the same length (RFC 5737), so lengths and byte classes stay as they were;
- writes OUTDIR/requests.dat.gz, index.tsv, responses.dat.gz, responses-index.tsv and sites.tsv.
"""

import gzip
import random
import struct
import sys

BODY_MAX = 1024


def doc_ip(ip: str) -> bytes:  # a TEST-NET-3 address with as many characters as ip
    for last in range(256):
        s = f"203.0.113.{last}"
        if len(s) == len(ip):
            return s.encode()
    s = "203.0.113.1"
    return (s + "0" * (len(ip) - len(s))).encode()[: len(ip)]


def scrub(b: bytes, rng: random.Random) -> bytes:
    out = bytearray(b)
    for i, c in enumerate(out):
        if 97 <= c <= 122:
            out[i] = 97 + rng.randrange(26)
        elif 65 <= c <= 90:
            out[i] = 65 + rng.randrange(26)
        elif 48 <= c <= 57:
            out[i] = 48 + rng.randrange(10)
    return bytes(out)


def fix_body(raw: bytes, rng: random.Random) -> bytes:
    e = raw.find(b"\r\n\r\n")
    if e < 0 or e + 4 == len(raw):
        return raw
    head, body = raw[: e + 4], scrub(raw[e + 4 :][:BODY_MAX], rng)
    lines = head[:-4].split(b"\r\n")
    lines = [ln for ln in lines if not ln.lower().startswith(b"content-length:")]
    lines.append(b"Content-Length: " + str(len(body)).encode())
    return b"\r\n".join(lines) + b"\r\n\r\n" + body


def read(chunk, dat, ix):
    d = open(f"{chunk}/{dat}", "rb").read()
    rows = open(f"{chunk}/{ix}").read().splitlines()[1:]
    p, out = 0, []
    for row in rows:
        (n,) = struct.unpack("<I", d[p : p + 4])
        f = row.split("\t")
        out.append((int(f[1]), f[2], f[3], d[p + 4 : p + 4 + n]))
        p += 4 + n
    assert p == len(d), chunk
    return out


def main():
    outdir, ip, chunks = sys.argv[1], sys.argv[2], sys.argv[3:]
    ipb, rep = ip.encode(), doc_ip(ip)
    for dat, ix, body in (("requests.dat", "index.tsv", True), ("responses.dat", "responses-index.tsv", False)):
        recs = sorted((r for c in chunks for r in read(c, dat, ix)), key=lambda r: (r[0], r[2]))
        with gzip.GzipFile(f"{outdir}/{dat}.gz", "wb", 9, mtime=0) as o, open(f"{outdir}/{ix}", "w") as x:
            x.write("n\trank\tdomain\tkind\tbytes\theader_lines\n")
            for n, (rank, dom, kind, raw) in enumerate(recs):
                raw = raw.replace(ipb, rep)
                if body:
                    raw = fix_body(raw, random.Random(f"body:{rank}:{dom}:{kind}"))
                head = raw[: raw.find(b"\r\n\r\n")]
                o.write(struct.pack("<I", len(raw)) + raw)
                x.write(f"{n}\t{rank}\t{dom}\t{kind}\t{len(raw)}\t{head.count(b'\r\n') + 1}\n")
        print(f"{dat}: {len(recs)} records")
    rows = {}
    for c in chunks:
        for row in open(f"{c}/sites.tsv").read().splitlines()[1:]:
            rows[int(row.split("\t")[0])] = row
    with open(f"{outdir}/sites.tsv", "w") as o:
        o.write("rank\tdomain\tstatus\trequests_seen\tlargest_head\tmost_header_lines\n")
        o.write("".join(rows[k] + "\n" for k in sorted(rows)))
    print(f"sites: {len(rows)}")


if __name__ == "__main__":
    main()
