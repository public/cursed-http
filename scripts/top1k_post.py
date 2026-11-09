"""scripts/top1k_post.py - turn top1k_crawl.py's output (one or more chunk directories) into tests/top1k/.

    top1k_post.py OUTDIR CRAWLER_IP CHUNKDIR...
    top1k_post.py --rescrub DIR CRAWLER_IP     (the address and key scrubs again, on DIR's .dat.gz files in place)

- merges the chunks (requests.dat + index.tsv, responses.dat + responses-index.tsv), ordered by rank and kind;
- bodies: scrubbed shape-preservingly (as the crawler does cookie values) and cut to 1 KB, with Content-Length
  rewritten to match. A body only matters to the parsers through its framing, and analytics payloads describe the
  crawler;
- CRAWLER_IP: every occurrence of the crawling machine's address (sites echo it in payloads and response fields) is
  replaced by a TEST-NET-3 address of the same length (RFC 5737), so lengths and byte classes stay as they were;
  The same goes for the address inside base64 (standard or URL-safe, in headers and URLs, possibly nested in a binary
  payload) and in hex, and its /24 (sites mask the last octet), so the whole a.b.c. prefix is replaced wherever it
  appears;
- a base64 payload that describes the crawling VM (its host, its location) is scrubbed whole, like cookie values;
- Google API keys (AIza...: public browser keys, but secret scanners flag them) are scrubbed like cookie values;
- writes OUTDIR/requests.dat.gz, index.tsv, responses.dat.gz, responses-index.tsv and sites.tsv.
"""

import base64
import gzip
import random
import re
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


B64_RUN = re.compile(rb"[A-Za-z0-9+/_-]{8,}")
AIZA = re.compile(rb"AIza[0-9A-Za-z_-]{35}")
ABOUT_US = (b"vultr", b"canary wharf")  # what geolocation payloads say about the crawling VM


def _b64(run: bytes, k: int):  # (decoded, urlsafe) for run[k:], or None
    s = run[k:]
    s = s[: len(s) - 1] if len(s) % 4 == 1 else s
    for url in (False, True):
        if (url and (b"+" in s or b"/" in s)) or (not url and (b"-" in s or b"_" in s)):
            continue
        try:
            dec = (base64.urlsafe_b64decode if url else base64.b64decode)(s + b"=" * (-len(s) % 4))
        except ValueError:
            continue
        return dec, url, len(s)
    return None


def scrub_ip(raw: bytes, prefix: bytes, rep: bytes, rng: random.Random) -> bytes:
    """the crawler's a.b.c. prefix (so also its /24) -> rep, as text and inside base64; Google API keys scrubbed"""
    raw = raw.replace(prefix, rep)
    hx, hrep = _hex3(prefix), _hex3(rep)  # also in hex (client-IP fields, IDs built from the address)
    raw = raw.replace(hx, hrep).replace(hx.upper(), hrep.upper())
    out = bytearray(raw)
    for m in B64_RUN.finditer(raw):
        run = m.group()
        for k in range(4):
            d = _b64(run, k)
            if not d or not (prefix in d[0] or rep in d[0] and any(w in d[0].lower() for w in ABOUT_US)):
                continue
            dec, url, n = d
            if any(w in dec.lower() for w in ABOUT_US):  # a payload describing the crawler: all of it scrubbed
                out[m.start() : m.end()] = scrub(run, rng)
                break
            enc = (base64.urlsafe_b64encode if url else base64.b64encode)(dec.replace(prefix, rep))
            enc = enc.rstrip(b"=")[:n] if len(enc.rstrip(b"=")) >= n else enc[:n]
            out[m.start() + k : m.start() + k + n] = enc
            break
    raw = bytes(out)
    return AIZA.sub(lambda m: scrub(m.group(), rng), raw)  # (the AIza too: scanners match on it)


def _hex3(prefix: bytes) -> bytes:  # a.b.c. -> its three octets in lowercase hex
    return "".join(f"{int(o):02x}" for o in prefix[:-1].decode().split(".")).encode()


def ip_prefix(ip: str):  # (the crawler's a.b.c. prefix, a TEST-NET-3 one of the same length)
    a = ip.rsplit(".", 1)[0] + "."
    r = doc_ip(ip)[: len(a)]
    return a.encode(), r[:-1] + b"."


def rescrub(d: str, ip: str):
    prefix, rep = ip_prefix(ip)
    for dat in ("requests.dat", "responses.dat"):
        b = gzip.open(f"{d}/{dat}.gz").read()
        p, out, changed = 0, bytearray(), 0
        while p < len(b):
            (n,) = struct.unpack("<I", b[p : p + 4])
            raw = b[p + 4 : p + 4 + n]
            new = scrub_ip(raw, prefix, rep, random.Random(f"rescrub:{dat}:{p}"))
            assert len(new) == n
            changed += new != raw
            out += b[p : p + 4] + new
            p += 4 + n
        with gzip.GzipFile(f"{d}/{dat}.gz", "wb", 9, mtime=0) as o:
            o.write(bytes(out))
        print(f"{dat}: {changed} records changed")


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
    if sys.argv[1] == "--rescrub":
        return rescrub(sys.argv[2], sys.argv[3])
    outdir, ip, chunks = sys.argv[1], sys.argv[2], sys.argv[3:]
    ipb, rep = ip.encode(), doc_ip(ip)
    prefix, prep = ip_prefix(ip)
    for dat, ix, body in (("requests.dat", "index.tsv", True), ("responses.dat", "responses-index.tsv", False)):
        recs = sorted((r for c in chunks for r in read(c, dat, ix)), key=lambda r: (r[0], r[2]))
        with gzip.GzipFile(f"{outdir}/{dat}.gz", "wb", 9, mtime=0) as o, open(f"{outdir}/{ix}", "w") as x:
            x.write("n\trank\tdomain\tkind\tbytes\theader_lines\n")
            for n, (rank, dom, kind, raw) in enumerate(recs):
                raw = raw.replace(ipb, rep)
                raw = scrub_ip(raw, prefix, prep, random.Random(f"ip:{rank}:{dom}:{kind}"))
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
