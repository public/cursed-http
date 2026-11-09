"""scripts/top1k_crawl.py - real requests and header fields from the Tranco top sites, for tests/top1k/.

    top1k_crawl.py LIST.csv OUTDIR [--offset K] [--limit N] [--concurrency C] [--deadline UNIX]
                                     (sites K+1 .. K+N of the list; outputs rewritten every 20 s)

LIST.csv is a Tranco list (rank,domain). Each site is opened once in headless Chromium (Playwright, pinned in
tests/browser/requirements.txt) in a fresh context, at https://DOMAIN/ (then https://www.DOMAIN/), and left a few
seconds for late requests. Two kinds of test input come out of every site:

  - requests: what Chromium sent to the site and to every host its page pulled in, rebuilt as HTTP/1.1 (the request
    line from method + URL, Host from the authority, the header lines in the order sent, the body with a matching
    Content-Length). Up to 5 per site: the document, the largest head, the most header lines, the longest target, the
    first request with a body; duplicates dropped.
  - response header fields: the document response's header lines, put into one GET request as request header lines
    (the field grammar is the same, and real-world values are far more varied than what browsers send).

Privacy: cookie values (Cookie, Set-Cookie), Authorization, and any header whose name says token/auth/session/csrf
are scrubbed shape-preservingly: letters become random letters of the same case and digits random digits, so every
byte keeps its class (token character or not, control or not), the lengths and the punctuation stay the same, and the
values the sites issued are not kept. Nothing else is changed.

  - responses (for a response parser): the document's response head and the two largest other ones, as HTTP/1.1
    (status line "HTTP/1.1 CODE REASON", the reason empty where HTTP/2 has none; the header lines in order).

Writes OUTDIR/requests.dat (u32 little-endian length + bytes, repeated; the bench/dump_corpus format),
OUTDIR/index.tsv (one line per request), OUTDIR/responses.dat + responses-index.tsv, and OUTDIR/sites.tsv (one line
per site: status, requests seen, stats).
"""

import argparse
import asyncio
import os
import random
import re
import struct
import time
from urllib.parse import urlsplit

from playwright.async_api import async_playwright

SECRET = re.compile(r"token|auth|session|csrf|xsrf|secret|signature|api-key|apikey", re.I)


def scrub_value(v: bytes, rng: random.Random) -> bytes:
    out = bytearray(v)
    for i, c in enumerate(out):
        if 97 <= c <= 122:
            out[i] = 97 + rng.randrange(26)
        elif 65 <= c <= 90:
            out[i] = 65 + rng.randrange(26)
        elif 48 <= c <= 57:
            out[i] = 48 + rng.randrange(10)
    return bytes(out)


def scrub_cookie(v: bytes, rng: random.Random) -> bytes:  # "a=1; b=2": the values only
    parts = []
    for p in v.split(b";"):
        if b"=" in p:
            k, _, val = p.partition(b"=")
            parts.append(k + b"=" + scrub_value(val, rng))
        else:
            parts.append(p)
    return b";".join(parts)


def scrub_set_cookie(v: bytes, rng: random.Random) -> bytes:  # "n=VALUE; Path=/; ...": the value only
    first, sep, rest = v.partition(b";")
    k, eq, val = first.partition(b"=")
    return k + eq + scrub_value(val, rng) + sep + rest


def enc(s: str) -> bytes:
    try:
        return s.encode("latin-1")  # header values arrive as Latin-1 strings: their bytes
    except UnicodeEncodeError:
        return s.encode("utf-8")


def field(name: str, value: str, rng: random.Random) -> list:
    n, out = enc(name), []
    for v in value.split("\n"):  # (a joined repeated field: one line each)
        b = enc(v)
        ln = name.lower()
        if ln == "cookie":
            b = scrub_cookie(b, rng)
        elif ln == "set-cookie":
            b = scrub_set_cookie(b, rng)
        elif SECRET.search(ln):
            b = scrub_value(b, rng)
        out.append(n + b": " + b)
    return out


def rebuild(method, url, headers, body, rng):
    u = urlsplit(url)
    target = (u.path or "/") + ("?" + u.query if u.query else "")
    lines, host = [], None
    for h in headers:
        n = h["name"]
        if n.startswith(":"):
            if n == ":authority":
                host = h["value"]
            continue
        ln = n.lower()
        if ln in ("content-length", "transfer-encoding"):
            continue
        if ln == "host":
            host = None
        lines += field(n, h["value"], rng)
    if host is not None or not any(x.lower().startswith(b"host:") for x in lines):
        lines.insert(0, b"Host: " + enc(host or u.netloc))
    if body:
        lines.append(b"Content-Length: " + str(len(body)).encode())
    head = enc(method) + b" " + enc(target) + b" HTTP/1.1\r\n" + b"".join(x + b"\r\n" for x in lines) + b"\r\n"
    return head + (body or b""), len(lines) + 1


async def site(browser, rank, domain, sem, out, stats, rout, deadline, done):
    async with sem:
        if time.time() > deadline - 60:  # leave the last minute for writing out
            stats.append((rank, domain, "skipped (deadline)", 0, 0, 0))
            return
        ctxs = []
        try:
            await asyncio.wait_for(site1(browser, rank, domain, out, stats, rout, ctxs), 60)
        except Exception as e:  # noqa: BLE001 - one site must not end the crawl (a hang ends at 60 s)
            stats.append((rank, domain, "error " + type(e).__name__, 0, 0, 0))
            print(f"{rank:5d} {domain:40s} error {e!r:.80}", flush=True)
        finally:
            for c in ctxs:
                try:
                    await asyncio.wait_for(c.close(), 10)
                except Exception:  # noqa: BLE001
                    pass
        done.append(rank)


async def site1(browser, rank, domain, out, stats, rout, ctxs):
    rng = random.Random(f"{rank}:{domain}")
    ctx = await browser.new_context(ignore_https_errors=True)
    ctxs.append(ctx)
    page = await ctx.new_page()
    reqs, resps, resp, status = [], [], None, "ok"
    page.on("request", lambda r: reqs.append(r))
    page.on("response", lambda r: resps.append(r))
    for url in (f"https://{domain}/", f"https://www.{domain}/"):
        try:
            resp = await page.goto(url, wait_until="load", timeout=20000)
            break
        except Exception as e:  # noqa: BLE001
            status = type(e).__name__
    if resp is not None:
        status = f"ok {resp.status}"
        await page.wait_for_timeout(3000)
    built = []
    for r in reqs:
        if not r.url.startswith(("http://", "https://")):
            continue
        try:
            hs = await asyncio.wait_for(r.headers_array(), 2)  # (never resolves for some blocked requests)
            body = r.post_data_buffer
        except Exception:  # noqa: BLE001
            continue
        try:
            nav = r.is_navigation_request() and r.frame == page.main_frame
        except Exception:  # noqa: BLE001 - e.g. a service worker's request has no frame
            nav = False
        raw, nh = rebuild(r.method, r.url, hs, body, rng)
        built.append((raw, nh, nav))
    picks = []
    if built:
        heads = [(raw.index(b"\r\n\r\n") + 4, nh, raw, nav) for raw, nh, nav in built]
        doc = next((x for x in heads if x[3]), None)
        cands = [
            ("document", doc),
            ("largest-head", max(heads, key=lambda x: x[0])),
            ("most-headers", max(heads, key=lambda x: x[1])),
            ("longest-target", max(heads, key=lambda x: len(x[2].split(b" ", 2)[1]))),
            ("first-body", next((x for x in heads if len(x[2]) > x[0]), None)),
        ]
        seen = set()
        for kind, x in cands:
            if x and x[2] not in seen:
                seen.add(x[2])
                picks.append((kind, x[2], x[1]))
        stats.append((rank, domain, status, len(built), max(h[0] for h in heads), max(h[1] for h in heads)))
    else:
        stats.append((rank, domain, status, 0, 0, 0))
    if resp is not None:
        try:
            hs = await asyncio.wait_for(resp.headers_array(), 2)
            lines = []
            for h in hs:
                if not h["name"].startswith(":"):
                    lines += field(h["name"], h["value"], rng)
            raw = (
                b"GET /response-fields HTTP/1.1\r\nHost: "
                + enc(domain)
                + b"\r\n"
                + b"".join(x + b"\r\n" for x in lines)
                + b"\r\n"
            )
            picks.append(("response-fields", raw, len(lines) + 1))
        except Exception:  # noqa: BLE001
            pass
    for kind, raw, nh in picks:
        out.append((rank, domain, kind, raw, nh))
    # responses: the document's head and the two largest other heads, as HTTP/1.1 (status line + fields in order)
    heads = []
    for r in resps:
        try:
            hs = await asyncio.wait_for(r.headers_array(), 2)
        except Exception:  # noqa: BLE001
            continue
        lines = []
        for h in hs:
            if not h["name"].startswith(":"):
                lines += field(h["name"], h["value"], rng)
        st = b"HTTP/1.1 %d " % r.status + enc(r.status_text or "") + b"\r\n"
        raw = st + b"".join(x + b"\r\n" for x in lines) + b"\r\n"
        heads.append(("document" if resp is not None and r == resp else "subresource", raw, len(lines) + 1))
    doc = [h for h in heads if h[0] == "document"][:1]
    rest = sorted((h for h in heads if h[0] != "document"), key=lambda h: -len(h[1]))[:2]
    for kind, raw, nh in doc + rest:
        rout.append((rank, domain, kind, raw, nh))
    print(f"{rank:5d} {domain:40s} {status:28s} {len(built):4d} requests, kept {len(picks)}", flush=True)


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("list")
    ap.add_argument("outdir")
    ap.add_argument("--offset", type=int, default=0)
    ap.add_argument("--limit", type=int, default=1000)
    ap.add_argument("--concurrency", type=int, default=3)
    ap.add_argument("--deadline", type=float, default=0, help="unix time: stop starting sites a minute before")
    a = ap.parse_args()
    sites = []
    for line in open(a.list):
        r, d = line.strip().split(",")
        sites.append((int(r), d))
    sites = sites[a.offset : a.offset + a.limit]
    out, stats, rout, done, sem = [], [], [], [], asyncio.Semaphore(a.concurrency)
    deadline = a.deadline or time.time() + 86400
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        print(f"chromium {browser.version}, {len(sites)} sites", flush=True)
        jobs = asyncio.gather(*(site(browser, r, d, sem, out, stats, rout, deadline, done) for r, d in sites))
        while not jobs.done():  # write what is done every 20 s: a kill keeps it
            await asyncio.wait([jobs], timeout=20)
            write(a.outdir, out, rout, stats)
            if time.time() > deadline - 30:
                jobs.cancel()
                break
        try:
            await asyncio.wait_for(browser.close(), 20)
        except Exception:  # noqa: BLE001
            pass
    write(a.outdir, out, rout, stats)
    print(f"{len(out)} requests from {sum(1 for s in stats if s[3])} of {len(sites)} sites ({len(done)} finished)")


def write(outdir, out, rout, stats):
    for name, rows in (("requests.dat", out), ("responses.dat", rout)):
        ixname = "index.tsv" if name == "requests.dat" else "responses-index.tsv"
        rows = sorted(rows, key=lambda x: (x[0], x[2]))
        with open(f"{outdir}/{name}.t", "wb") as f, open(f"{outdir}/{ixname}.t", "w") as ix:
            ix.write("n\trank\tdomain\tkind\tbytes\theader_lines\n")
            for i, (rank, domain, kind, raw, nh) in enumerate(rows):
                f.write(struct.pack("<I", len(raw)) + raw)
                ix.write(f"{i}\t{rank}\t{domain}\t{kind}\t{len(raw)}\t{nh}\n")
        os.replace(f"{outdir}/{name}.t", f"{outdir}/{name}")
        os.replace(f"{outdir}/{ixname}.t", f"{outdir}/{ixname}")
    with open(f"{outdir}/sites.tsv", "w") as st:
        st.write("rank\tdomain\tstatus\trequests_seen\tlargest_head\tmost_header_lines\n")
        for x in sorted(stats):
            st.write("\t".join(map(str, x)) + "\n")


if __name__ == "__main__":
    asyncio.run(main())
