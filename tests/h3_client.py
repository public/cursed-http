#!/usr/bin/env python3
"""HTTP/3 client for tests/real_clients.sh, on aioquic (an independent Python QUIC + HTTP/3 stack).
    h3_client.py HOST PORT
Runs against examples/h3_server.c: 20 concurrent GETs, a 1 MiB GET, a 300 KB POST, a key update
mid-connection, then 20 more GETs. Exits non-zero on any wrong status or body."""

import asyncio
import ssl
import sys

from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration


class Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.h3 = H3Connection(self._quic)
        self.pending = {}

    def quic_event_received(self, event):
        for ev in self.h3.handle_event(event):
            if not isinstance(ev, (HeadersReceived, DataReceived)) or ev.stream_id not in self.pending:
                continue
            r = self.pending[ev.stream_id]
            if isinstance(ev, HeadersReceived):
                r["headers"] = dict(ev.headers)
            else:
                r["body"] += ev.data
            if ev.stream_ended:
                r["done"].set_result(r)

    async def request(self, method, path, body=b""):
        sid = self._quic.get_next_available_stream_id()
        headers = [(b":method", method), (b":scheme", b"https"), (b":authority", b"localhost"), (b":path", path)]
        self.h3.send_headers(sid, headers, end_stream=not body)
        if body:
            self.h3.send_data(sid, body, end_stream=True)
        r = {"headers": None, "body": b"", "done": asyncio.get_running_loop().create_future()}
        self.pending[sid] = r
        self.transmit()
        return await asyncio.wait_for(r["done"], 20)


async def main(host, port):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN, verify_mode=ssl.CERT_NONE, server_name="localhost")
    bad = 0

    def check(what, r, status, body):
        nonlocal bad
        ok = r["headers"].get(b":status") == status and r["body"] == body
        print(("ok  " if ok else "FAIL"), what, r["headers"].get(b":status"), len(r["body"]))
        bad += not ok

    async with connect(host, port, configuration=cfg, create_protocol=Client) as c:
        rs = await asyncio.gather(*(c.request(b"GET", b"/p/%d" % i) for i in range(20)))
        for i, r in enumerate(rs):
            check("GET /p/%d" % i, r, b"200", b"hello, world\n")
        r = await c.request(b"GET", b"/big/1048576")
        check("GET /big/1048576", r, b"200", b"x" * 1048576)
        r = await c.request(b"POST", b"/upload", b"u" * 300000)
        check("POST 300000 B", r, b"200", b"ok\n")
        c._quic.request_key_update()
        rs = await asyncio.gather(*(c.request(b"GET", b"/after-key-update/%d" % i) for i in range(20)))
        for i, r in enumerate(rs):
            check("GET after key update %d" % i, r, b"200", b"hello, world\n")
    print("h3_client:", "FAILED" if bad else "PASS")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv[1], int(sys.argv[2]))))
