# aioquic's HTTP/3 server: files from DOCROOT, POST echoes, /trailers sends trailers.
#   python3 aioquic_h3.py PORT DOCROOT CERT KEY
import asyncio, os, sys
from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated

PORT, ROOT, CERT, KEY = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]


class P(QuicConnectionProtocol):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.h3, self.req = None, {}

    def answer(self, sid, method, path, body):
        h3 = self.h3
        path = path.decode()
        if path == "/204":
            h3.send_headers(sid, [(b":status", b"204")], end_stream=True)
        elif path == "/trailers":
            h3.send_headers(sid, [(b":status", b"200"), (b"content-type", b"text/plain")])
            h3.send_data(sid, b"data with trailers\n", end_stream=False)
            h3.send_headers(sid, [(b"x-checksum", b"abc123")], end_stream=True)
        elif method == b"POST":
            h3.send_headers(sid, [(b":status", b"200"), (b"content-length", str(len(body)).encode())])
            h3.send_data(sid, body, end_stream=True)
        else:
            f = os.path.join(ROOT, os.path.normpath(path).lstrip("/"))
            if not os.path.isfile(f):
                h3.send_headers(sid, [(b":status", b"404")])
                h3.send_data(sid, b"not found\n", end_stream=True)
                return
            d = open(f, "rb").read()
            h3.send_headers(sid, [(b":status", b"200"), (b"content-length", str(len(d)).encode())],
                            end_stream=method == b"HEAD")
            if method != b"HEAD":
                h3.send_data(sid, d, end_stream=True)

    def quic_event_received(self, ev):
        if isinstance(ev, ProtocolNegotiated) and ev.alpn_protocol in H3_ALPN:
            self.h3 = H3Connection(self._quic)
        if self.h3 is None:
            return
        for e in self.h3.handle_event(ev):
            if isinstance(e, HeadersReceived):
                h = dict(e.headers)
                self.req[e.stream_id] = [h.get(b":method"), h.get(b":path", b"/"), b""]
            elif isinstance(e, DataReceived) and e.stream_id in self.req:
                self.req[e.stream_id][2] += e.data
            if getattr(e, "stream_ended", False) and e.stream_id in self.req:
                self.answer(e.stream_id, *self.req.pop(e.stream_id))
        self.transmit()


async def main():
    cfg = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN, max_datagram_frame_size=None)
    cfg.load_cert_chain(CERT, KEY)
    await serve("127.0.0.1", PORT, configuration=cfg, create_protocol=P)
    await asyncio.Future()


asyncio.run(main())
