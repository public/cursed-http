# tests/top1k: real requests and header fields from the Tranco top 1,000 sites

Inputs for the HTTP/1.1 parsers that come from the real web rather than from generators. Made by
[`scripts/top1k_crawl.py`](../../scripts/top1k_crawl.py) with headless Chromium (Playwright, pinned in
`tests/browser/requirements.txt`), one homepage load per site in a fresh browser context, then
[`scripts/top1k_post.py`](../../scripts/top1k_post.py).

**This snapshot:**
- Source: Tranco list [Q2VV4](https://tranco-list.eu/list/Q2VV4/1000) (2026-11-06). Crawled 2026-11-07 with Chromium 156 from a throwaway Vultr VM, which was destroyed afterwards.
- All 1,000 sites visited: 708 homepages loaded; the rest are API, CDN or DNS domains whose failed navigations still produced requests.
- 61,681 requests seen. Kept: **3,533 requests** from 993 sites, and **2,054 response heads**.
- Requests:
  - methods: 2,755 GET, 776 POST, one each of HEAD and PUT; 629 have a body;
  - median head 678 B, largest 58 KB (a 57 KB tracker URL); 125 heads are over 4 KB and 24 over 8 KB (`FP_MAXHDR`: fast_parse hands those to fbparse);
  - up to 65 header lines: 2 requests are over the `req_t` adapter's cap of 48 (#25);
  - 2 heads have bytes >= 0x80, 3 have tabs.

| file | what |
|---|---|
| `requests.dat.gz` | the requests, u32 little-endian length + bytes each (the `bench/dump_corpus` format), gzip'd |
| `index.tsv` | one line per request: rank, domain, kind, bytes, header lines |
| `responses.dat.gz`, `responses-index.tsv` | response heads (status line + header lines), for a response parser |

**Kinds of request, per site (duplicates dropped):**
- `document`: the homepage request;
- `largest-head`, `most-headers`, `longest-target`: the extreme requests among everything the page made Chromium send, to the site and to every third party it pulled in;
- `first-body`: the first request with a body (usually analytics);
- `response-fields`: the document response's header lines (Set-Cookie, CSP, Link, ...) as the header lines of one GET request. The field grammar is the same, and real response values are far more varied than what browsers send.

Requests over HTTP/2 are rebuilt as HTTP/1.1:
- the request line comes from the method and URL;
- `Host` comes from `:authority`;
- the header lines keep the order and case Chromium sent (lowercase over HTTP/2);
- a body gets a matching `Content-Length`.

**Scrubbing.** Before anything is saved (the crawler), these values are rewritten shape-preservingly:
- cookie values (`Cookie`, the value part of `Set-Cookie`);
- `Authorization`;
- any field whose name contains token, auth, session, csrf, xsrf, secret, signature or api-key.

Letters become random letters of the same case, and digits random digits. Every byte keeps its class for the parser (token character or not, control or not), and the lengths and punctuation stay the same. The IDs the sites issued to the crawler are not kept.

Then `top1k_post.py` does two more things:
- **Bodies:** scrubbed the same way and cut to 1 KB, with `Content-Length` rewritten. A body matters to the parsers only through its framing, and analytics payloads describe the crawler.
- **The crawler's IP:** sites echo it in payloads and response fields. Every occurrence is replaced by a TEST-NET-3 address of the same length (RFC 5737).

Nothing else is changed.

**Tests:**
All three use tests/browser/check.h on every backend:
- `make top1k-replay` (part of `make test`, about 2 s per backend) checks the lengths next to each line end, plus both ends.
- `make top1k-focused` also checks next to every `:` and SP and at 64-byte block edges.
- `make top1k-full` checks every length, with both paddings and both header-array sizes: 8.4 M lengths, about 3 min per backend.

Result of this snapshot: 0 mismatches in all three, on avx2, scalar, sse2 and emulated AVX-512 ymm and zmm. Only the 2 requests over 48 headers show the documented relaxed accept.

**Refreshing:** run the crawler on a throwaway machine, not one you browse from, because the traffic looks like a crawler. It took 4 runs of 250 sites at 16 pages each, about 2.5 min per run on 4 vCPU. Then post-process:
```
build/venv-playwright/bin/python scripts/top1k_crawl.py top-1k.csv OUT1 --offset 0 --limit 250 --concurrency 16
...
python3 scripts/top1k_post.py tests/top1k CRAWLER_IP OUT1 OUT2 OUT3 OUT4
```
