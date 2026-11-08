// Node's http2 module: h2c with prior knowledge.   node node.js PORT DOCROOT
// node node.js PORT DOCROOT [TLSPORT CERT KEY]: also HTTP/2 over TLS (ALPN h2) on TLSPORT
const http2 = require("http2"), fs = require("fs"), path = require("path");
const [port, root] = [Number(process.argv[2]), process.argv[3]];
const srv = http2.createServer({ settings: { maxConcurrentStreams: 100 } });
const onStream = (st, h) => {
  const p = h[":path"].split("?")[0], m = h[":method"];
  if (p === "/204") return st.respond({ ":status": 204 }, { endStream: true });
  if (p === "/trailers") {
    st.respond({ ":status": 200, "content-type": "text/plain" }, { waitForTrailers: true });
    st.on("wantTrailers", () => st.sendTrailers({ "x-checksum": "abc123" }));
    return st.end("data with trailers\n");
  }
  if (m === "POST") {
    const b = [];
    st.on("data", (c) => b.push(c));
    return st.on("end", () => { st.respond({ ":status": 200 }); st.end(Buffer.concat(b)); });
  }
  fs.readFile(path.join(root, path.normalize(p)), (e, d) => {
    if (e) { st.respond({ ":status": 404 }); return st.end("not found\n"); }
    st.respond({ ":status": 200, "content-length": d.length }, { endStream: m === "HEAD" });
    if (m !== "HEAD") st.end(d);
  });
};
srv.on("stream", onStream);
srv.listen(port, "127.0.0.1");
if (process.argv[4]) {
  const tls = http2.createSecureServer({ cert: fs.readFileSync(process.argv[5]), key: fs.readFileSync(process.argv[6]),
                                        settings: { maxConcurrentStreams: 100 } });
  tls.on("stream", onStream);
  tls.listen(Number(process.argv[4]), "127.0.0.1");
}
