# HTTP/1.1 origin behind the proxies in run.sh: POST /echo returns the body; /trailers is chunked with
# trailers; /204 is empty; other paths are files from DOCROOT.   python3 origin.py PORT DOCROOT
import os, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path == "/trailers":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Trailer", "X-Checksum")
            self.end_headers()
            body = b"data with trailers\n"
            self.wfile.write(b"%x\r\n%s\r\n0\r\nX-Checksum: abc123\r\n\r\n" % (len(body), body))
            return
        f = os.path.join(sys.argv[2], os.path.normpath(self.path).lstrip("/"))
        body = open(f, "rb").read() if self.path != "/204" and os.path.isfile(f) else b""
        self.send_response(204 if self.path == "/204" else 200 if body else 404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        f = os.path.join(sys.argv[2], os.path.normpath(self.path).lstrip("/"))
        self.send_response(200 if os.path.isfile(f) else 404)
        self.send_header("Content-Length", str(os.path.getsize(f)) if os.path.isfile(f) else "0")
        self.end_headers()

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        if not n and self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            while True:
                size = int(self.rfile.readline().split(b";")[0], 16)
                if not size:
                    while self.rfile.readline() not in (b"\r\n", b""):
                        pass
                    break
                body += self.rfile.read(size)
                self.rfile.readline()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


ThreadingHTTPServer.request_queue_size = 512
ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
