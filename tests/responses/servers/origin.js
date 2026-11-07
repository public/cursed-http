// Node http origin for the response captures (tests/responses/README.md).   node origin.js PORT DOCROOT
const http = require("http"), fs = require("fs"), path = require("path"), zlib = require("zlib");
const [port, root] = [Number(process.argv[2]), process.argv[3]];
const srv = http.createServer((req, res) => {
  const p = req.url.split("?")[0];
  if (p === "/chunked") { res.write("hello "); res.write("chunked ".repeat(50)); return res.end("world\n"); }
  if (p === "/trailers") {
    res.writeHead(200, { "Content-Type": "text/plain", Trailer: "X-Checksum" });
    res.write("data with trailers\n"); res.addTrailers({ "X-Checksum": "abc123" }); return res.end();
  }
  if (p === "/gzip") {
    res.writeHead(200, { "Content-Encoding": "gzip" });
    return res.end(zlib.gzipSync("compressible ".repeat(400)));
  }
  if (p === "/204") { res.writeHead(204); return res.end(); }
  if (p === "/304") { res.writeHead(304, { ETag: '"v1"' }); return res.end(); }
  if (p === "/close") { res.writeHead(200, { Connection: "close" }); res.useChunkedEncodingByDefault = false; return res.end("close-delimited body\n".repeat(20)); }
  if (p === "/early") { res.writeEarlyHints({ link: "</style.css>; rel=preload; as=style" }); return res.end("after early hints\n"); }
  if (req.method === "POST") { const b = []; req.on("data", (c) => b.push(c)); return req.on("end", () => res.end(Buffer.concat(b))); }
  const f = path.join(root, path.normalize(p));
  fs.readFile(f, (e, d) => {
    if (e) { res.writeHead(404, { "Content-Type": "text/plain" }); return res.end("not found\n"); }
    res.writeHead(200, { "Content-Type": "text/html", "Last-Modified": fs.statSync(f).mtime.toUTCString() });
    res.end(req.method === "HEAD" ? undefined : d);
  });
});
srv.on("upgrade", (req, sock) => {
  sock.end("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n\x81\x05hello");
});
srv.on("checkContinue", (req, res) => { res.writeContinue(); srv.emit("request", req, res); });
srv.listen(port, "127.0.0.1");
