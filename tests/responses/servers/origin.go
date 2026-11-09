// Go net/http origin for the response captures (tests/responses/README.md).   go run origin.go PORT DOCROOT
package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"os"
	"strings"
)

func main() {
	port, root := os.Args[1], os.Args[2]
	m := http.NewServeMux()
	m.HandleFunc("/chunked", func(w http.ResponseWriter, r *http.Request) {
		f := w.(http.Flusher)
		io.WriteString(w, "hello ")
		f.Flush()
		io.WriteString(w, strings.Repeat("chunked ", 50))
		f.Flush()
		io.WriteString(w, "world\n")
	})
	m.HandleFunc("/trailers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "X-Checksum")
		io.WriteString(w, "data with trailers\n")
		w.Header().Set("X-Checksum", "abc123")
	})
	m.HandleFunc("/gzip", func(w http.ResponseWriter, r *http.Request) {
		var b bytes.Buffer
		z := gzip.NewWriter(&b)
		io.WriteString(z, strings.Repeat("compressible ", 400))
		z.Close()
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(b.Bytes())
	})
	m.HandleFunc("/204", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	m.HandleFunc("/304", func(w http.ResponseWriter, r *http.Request) { w.Header().Set("ETag", `"v1"`); w.WriteHeader(304) })
	m.HandleFunc("/close", func(w http.ResponseWriter, r *http.Request) {
		c, rw, _ := w.(http.Hijacker).Hijack()
		rw.WriteString("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" + strings.Repeat("close-delimited body\n", 20))
		rw.Flush()
		c.Close()
	})
	m.HandleFunc("/early", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", "</style.css>; rel=preload; as=style")
		w.WriteHeader(103)
		io.WriteString(w, "after early hints\n")
	})
	m.HandleFunc("/upgrade", func(w http.ResponseWriter, r *http.Request) {
		c, rw, _ := w.(http.Hijacker).Hijack()
		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n\x81\x05hello")
		rw.Flush()
		c.Close()
	})
	m.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) { io.Copy(w, r.Body) })
	m.Handle("/", http.FileServer(http.Dir(root)))
	http.ListenAndServe("127.0.0.1:"+port, m)
}
