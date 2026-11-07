# Python http.server origin for the response captures (tests/responses/README.md): the dynamic endpoints.
#   python3 origin.py PORT DOCROOT
import gzip
import http.server
import os
import sys


class H(http.server.SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive and chunked; the default is HTTP/1.0

    def _chunks(self, parts, trailers=None):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Transfer-Encoding", "chunked")
        if trailers:
            self.send_header("Trailer", ", ".join(k for k, _ in trailers))
        self.end_headers()
        if self.command == "HEAD":
            return
        for p in parts:
            self.wfile.write(b"%x\r\n%s\r\n" % (len(p), p))
        self.wfile.write(b"0\r\n")
        for k, v in trailers or []:
            self.wfile.write(f"{k}: {v}\r\n".encode())
        self.wfile.write(b"\r\n")

    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/chunked":
            return self._chunks([b"hello ", b"chunked " * 50, b"world\n"])
        if p == "/trailers":
            return self._chunks([b"data with trailers\n"], [("X-Checksum", "abc123"), ("Server-Timing", "app;dur=3")])
        if p == "/gzip":
            body = gzip.compress(b"compressible " * 400)
            self.send_response(200)
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
            return
        if p == "/204":
            self.send_response(204)
            self.end_headers()
            return
        if p == "/304":
            self.send_response(304)
            self.send_header("ETag", '"v1"')
            self.end_headers()
            return
        if p == "/close":  # no length: the body ends at the close
            self.send_response(200)
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            if self.command != "HEAD":
                self.wfile.write(b"close-delimited body\n" * 20)
            return
        if p == "/early":
            self.send_response_only(103)
            self.send_header("Link", "</style.css>; rel=preload; as=style")
            self.end_headers()
            body = b"after early hints\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if p == "/upgrade":
            self.send_response(101)
            self.send_header("Connection", "Upgrade")
            self.send_header("Upgrade", "websocket")
            self.end_headers()
            self.wfile.write(b"\x81\x05hello")  # not HTTP any more
            self.close_connection = True
            return
        return super().do_HEAD() if self.command == "HEAD" else super().do_GET()

    do_HEAD = do_GET  # the dynamic paths check self.command; static files go to SimpleHTTPRequestHandler.do_HEAD

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n)
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    os.chdir(sys.argv[2])
    http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
