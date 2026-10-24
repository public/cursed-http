#!/usr/bin/env python3
"""Build one request corpus from third-party HTTP/1.1 parser test suites.

  extract.py LLHTTP_DIR GARDEN_DIR PICO_TEST_C HTTPARSE_LIB_RS > build/cases.bin

Sources (pinned commits in scripts/fetch-thirdparty.sh; fetched, never redistributed):
  llhttp      test/request/*.md: inputs + expected event logs. Strict-mode cases give an accept/reject verdict;
              lenient-mode cases are kept as inputs without a verdict.
  http-garden TROPHIES.md: the trigger payload of every parser bug the HTTP Garden found (mostly request
              smuggling). There's no verdict, since these are the cases where real servers disagreed.
  pico        test.c PARSE(...) cases with their expected result (0 complete, -1 error, -2 partial).
  httparse    src/lib.rs req!{...} cases with their expected status.

Output: records of  name\\0 source\\0 verdict\\0 <u32 len> <bytes>,  where verdict is accept|reject|partial|""
(empty = no verdict). Only the first request of a case is judged; the rest stays as trailing bytes.
"""
import glob, json, os, re, struct, sys


def out(name, src, verdict, data, sink):
    sink.write(name.encode() + b"\0" + src.encode() + b"\0" + verdict.encode() + b"\0" + struct.pack("<I", len(data)) + data)


def llhttp(d, sink):
    n = 0
    for fn in sorted(glob.glob(os.path.join(d, "test/request/*.md"))):
        text = open(fn, encoding="utf-8").read()
        base = os.path.basename(fn)[:-3]
        # a test = meta comment, ```http block, ```log block (md-test.ts)
        for m in re.finditer(r"<!-- meta=(\{.*?\}) -->\s*```http\n(.*?)```\s*```log\n(.*?)```", text, re.S):
            meta, inp, log = json.loads(m.group(1)), m.group(2), m.group(3)
            title = re.findall(r"^#+ (.*)$", text[:m.start()], re.M)[-1].strip()
            if "${" in inp: continue                                   # inline JS, never used by request tests
            # md-test.ts transforms, in order
            inp = re.sub(r"\n$", "", inp)
            inp = re.sub(r"\\(\r\n|\r|\n)", "", inp)
            inp = re.sub(r"\r\n|\r|\n", "\r\n", inp)
            inp = inp.replace("\\r", "\r").replace("\\n", "\n").replace("\\t", "\t").replace("\\f", "\f")
            inp = re.sub(r"\\x([0-9a-fA-F]+)", lambda x: chr(int(x.group(1), 16)), inp)
            inp = re.sub(r"\\([0-7]{1,3})", lambda x: chr(int(x.group(1), 8)), inp)
            data = b"".join(bytes([ord(c)]) if ord(c) < 256 else c.encode("utf-8") for c in inp)   # \xHH = one byte
            verdict = ""
            if meta.get("type") == "request" and not meta.get("pause") and not meta.get("skipBody"):
                lines = [l for l in log.split("\n") if l]
                err = next((i for i, l in enumerate(lines) if " error code=" in l or " error=" in l), None)
                done = next((i for i, l in enumerate(lines) if l.endswith("message complete")), None)
                verdict = "accept" if done is not None and (err is None or done < err) else "reject" if err is not None else ""
            out(f"llhttp/{base}: {title}", "llhttp-" + meta.get("type", "?"), verdict, data, sink); n += 1
    return n


def py_unescape(s):   # TROPHIES payloads are Python-style escaped strings
    return s.encode("latin-1", "backslashreplace").decode("unicode_escape").encode("latin-1")


def garden(d, sink):
    n = 0
    text = open(os.path.join(d, "TROPHIES.md"), encoding="utf-8").read()
    for i, m in enumerate(re.finditer(r"^(\d+)\. (.*?)\n(?:(?!^\d+\. ).)*?Payload: `([^`]*)`", text, re.S | re.M)):
        num, title, payload = m.group(1), m.group(2).strip(), m.group(3)
        t = text.find("### Transducer")
        section = "transducer" if 0 <= t < m.start() else "server"
        out(f"garden/{section} bug {num}: {title[:90]}", "garden", "", py_unescape(payload), sink); n += 1
    return n


def c_unescape(lit):
    out_b, i = bytearray(), 0
    while i < len(lit):
        c = lit[i]
        if c != "\\": out_b += c.encode("latin-1"); i += 1; continue
        e = lit[i + 1]
        if e in "01234567":
            j = i + 1
            while j < len(lit) and j < i + 4 and lit[j] in "01234567": j += 1
            out_b.append(int(lit[i + 1:j], 8) & 255); i = j; continue
        if e == "x":
            j = i + 2
            while j < len(lit) and lit[j] in "0123456789abcdefABCDEF": j += 1
            out_b.append(int(lit[i + 2:j], 16) & 255); i = j; continue
        out_b += {"r": b"\r", "n": b"\n", "t": b"\t", "\\": b"\\", '"': b'"', "'": b"'", "0": b"\0"}[e]; i += 2
    return bytes(out_b)


def pico(fn, sink):
    n = 0
    src = open(fn, encoding="latin-1").read()
    body = src[src.index("static void test_request(void)"):]
    body = body[:body.index("\n}\n")]
    for m in re.finditer(r'PARSE\(((?:\s*"(?:[^"\\]|\\.)*")+)\s*,\s*(\d+)\s*,\s*(-?\d+)\s*,\s*"([^"]*)"\)', body):
        data = b"".join(c_unescape(x) for x in re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(1)))
        last_len, exp = int(m.group(2)), int(m.group(3))
        if last_len: continue                                          # incremental re-parse cases: same bytes
        out(f"pico/test.c: {m.group(4)}", "pico", {0: "accept", -1: "reject", -2: "partial"}.get(exp, ""), data, sink); n += 1
    return n


def httparse(fn, sink):
    n = 0
    src = open(fn, encoding="utf-8").read()
    for m in re.finditer(r'\breq! \{\s*(\w+),\s*b"((?:[^"\\]|\\.)*)"\s*,\s*(?:([^|]*?)\s*,\s*)?\|', src, re.S):
        name, lit, status = m.group(1), m.group(2), m.group(3) or ""
        data = c_unescape(lit.replace("\\\n", ""))
        verdict = "reject" if "Err(" in status else "partial" if "Partial" in status else "accept"
        if status.startswith("|"): verdict = "accept"
        out(f"httparse/lib.rs: {name}", "httparse", verdict, data, sink); n += 1
    # req!{name, b"..", |req| ..} (no explicit status) is matched above with status = "" -> accept
    return n


if __name__ == "__main__":
    sink = sys.stdout.buffer
    counts = {"llhttp": llhttp(sys.argv[1], sink), "garden": garden(sys.argv[2], sink),
              "pico": pico(sys.argv[3], sink), "httparse": httparse(sys.argv[4], sink)}
    print(counts, file=sys.stderr)
