"""tests/browser/drive.py - drive real browsers (Playwright: Chromium, Firefox, WebKit) against tests/browser/server.c.

    drive.py SERVER CAPDIR [BROWSER...]     (default: chromium firefox webkit)

For each browser: start the server on a free loopback port (requests saved to CAPDIR/BROWSER/), open / headless, wait
until the page has walked through its steps and the form post has led to /done, then collect the server's verdict.
Exit 1 if any server reported a mismatch, any step failed in a browser, or a browser never reached /done.
"""

import os
import socket
import subprocess
import sys

from playwright.sync_api import sync_playwright

HERE = os.path.dirname(os.path.abspath(__file__))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run(pw, name, server, capdir):
    out = os.path.join(capdir, name)
    os.makedirs(out, exist_ok=True)
    port = free_port()
    srv = subprocess.Popen([server, str(port), HERE, out], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    assert "listening" in srv.stdout.readline()
    browser = getattr(pw, name).launch(headless=True)
    ok, steps = True, []
    try:
        page = browser.new_page()
        page.on("console", lambda m: m.text.startswith("step: ") and steps.append(m.text[6:]))
        page.goto(f"http://127.0.0.1:{port}/")
        page.wait_for_url("**/done*", timeout=60000)
    except Exception as e:  # noqa: BLE001 - report and carry on with the next browser
        print(f"{name}: did not reach /done: {e}")
        ok = False
    finally:
        browser.close()
    try:
        log, _ = srv.communicate(timeout=90)
    except subprocess.TimeoutExpired:
        srv.kill()
        log, _ = srv.communicate()
        ok = False
    print(f"==== {name} {browser.version}")
    print(log, end="")
    errs = [s for s in steps if not s.startswith("ok ")]
    for s in errs:
        print(f"{name}: step failed in the browser: {s}")
    print(f"{name}: {len(steps) - len(errs)} of {len(steps)} page steps ok")
    return ok and srv.returncode == 0 and not errs and len(steps) > 0, steps


def main():
    server, capdir = sys.argv[1], sys.argv[2]
    names = sys.argv[3:] or ["chromium", "firefox", "webkit"]
    bad = []
    with sync_playwright() as pw:
        for name in names:
            ok, _ = run(pw, name, server, capdir)
            if not ok:
                bad.append(name)
    print("real browsers: " + ("PASS" if not bad else "FAILED: " + " ".join(bad)))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
