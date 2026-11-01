// go-h2h3: Go's HTTP/2 stack on the inputs bench_h2h3 --dump writes, in memory, one goroutine at a
// time (GOMAXPROCS 1, like the C benchmarks):
//   - golang.org/x/net/http2/hpack: the decoder net/http's HTTP/2 server uses
//   - golang.org/x/net/http2 Server: the same nghttp2 client byte stream as bench_h2h3's HTTP/2
//     server benchmark, through ServeConn on an in-memory net.Conn; the handler answers 200 with
//     the same 13-byte body
//   - github.com/quic-go/qpack: quic-go's QPACK decoder (static table only: it has no dynamic table)
//
// Every decoder's output is checked against the dumped requests before it is timed. Prints the same
// "= bench set impl ns" lines as bench_h2h3.
//
//	go run . DIR [passes]
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/qpack"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

var sets = []string{"browser", "gRPC", "h2load"}

type field struct{ name, value string }

func records(dir, what, set string) [][]byte {
	b, err := os.ReadFile(filepath.Join(dir, what+"_"+set+".bin"))
	if err != nil {
		panic(err)
	}
	var out [][]byte
	for len(b) > 0 {
		n := binary.LittleEndian.Uint32(b)
		out = append(out, b[4:4+n])
		b = b[4+n:]
	}
	return out
}

func fields(dir, set string) [][]field {
	r := records(dir, "fields", set)
	var out [][]field
	for len(r) > 0 {
		n, _ := strconv.Atoi(string(r[0]))
		var f []field
		for k := 0; k < n; k++ {
			f = append(f, field{string(r[1+2*k]), string(r[2+2*k])})
		}
		out = append(out, f)
		r = r[1+2*n:]
	}
	return out
}

var gateBad int

func gate(who string, want []field, k int, name, value string) {
	if k < len(want) && want[k].name == name && want[k].value == value {
		return
	}
	if gateBad++; gateBad <= 5 {
		fmt.Fprintf(os.Stderr, "%s: field %d: got %q: %q\n", who, k, name, value)
	}
}

func gateN(who string, want []field, k int) {
	if k != len(want) {
		if gateBad++; gateBad <= 5 {
			fmt.Fprintf(os.Stderr, "%s: %d fields, want %d\n", who, k, len(want))
		}
	}
}

var sink int

func best(passes int, f func(check bool)) float64 {
	b := 1e18
	for p := 0; p < passes; p++ {
		t0 := time.Now()
		f(p == 0)
		if t := float64(time.Since(t0).Nanoseconds()); t < b {
			b = t
		}
	}
	return b
}

func hpackBench(blocks [][]byte, want [][]field, passes int) float64 {
	return best(passes, func(check bool) {
		var cur []field
		k := 0
		d := hpack.NewDecoder(4096, func(f hpack.HeaderField) {
			sink += len(f.Value)
			if check {
				gate("x/net/http2/hpack", cur, k, f.Name, f.Value)
			}
			k++
		})
		for i, b := range blocks {
			cur, k = want[i], 0
			if _, err := d.Write(b); err != nil {
				panic(err)
			}
			if err := d.Close(); err != nil {
				panic(err)
			}
			if check {
				gateN("x/net/http2/hpack", cur, k)
			}
		}
	}) / float64(len(blocks))
}

func qpackBench(recs [][]byte, want [][]field, passes int) float64 {
	return best(passes, func(check bool) {
		d := qpack.NewDecoder()
		for i := 0; i < len(recs)/2; i++ {
			next := d.Decode(recs[2*i+1])
			k := 0
			for {
				f, err := next()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					panic(err)
				}
				sink += len(f.Value)
				if check {
					gate("quic-go/qpack", want[i], k, f.Name, f.Value)
				}
				k++
			}
			if check {
				gateN("quic-go/qpack", want[i], k)
			}
		}
	}) / float64(len(recs)/2)
}

// memConn: reads the recorded client bytes, then blocks until the server has finished every
// response (DATA with END_STREAM), then EOF. Writes are parsed just enough to count those.
type memConn struct {
	in       *bytes.Reader
	out      []byte
	want     int
	done     int
	finished chan struct{}
	once     sync.Once
}

func (c *memConn) Read(p []byte) (int, error) {
	if c.in.Len() > 0 {
		if len(p) > 16384 {
			p = p[:16384] // in 16 KiB reads, as the C benchmarks feed their servers
		}
		return c.in.Read(p)
	}
	<-c.finished
	return 0, io.EOF
}

func (c *memConn) Write(p []byte) (int, error) {
	c.out = append(c.out, p...)
	for len(c.out) >= 9 {
		n := int(c.out[0])<<16 | int(c.out[1])<<8 | int(c.out[2])
		if len(c.out) < 9+n {
			break
		}
		if c.out[3] == 0 && c.out[4]&1 != 0 { // DATA, END_STREAM
			if c.done++; c.done == c.want {
				c.once.Do(func() { close(c.finished) })
			}
		}
		c.out = c.out[9+n:]
	}
	return len(p), nil
}

func (c *memConn) Close() error                       { c.once.Do(func() { close(c.finished) }); return nil }
func (c *memConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *memConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *memConn) SetDeadline(t time.Time) error      { return nil }
func (c *memConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *memConn) SetWriteDeadline(t time.Time) error { return nil }

var body = []byte("hello, world\n")

func h2Bench(client []byte, nreq, passes int) float64 {
	srv := &http2.Server{MaxConcurrentStreams: 1000}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write(body)
	})
	var done int
	t := best(passes, func(check bool) {
		c := &memConn{in: bytes.NewReader(client), want: nreq, finished: make(chan struct{})}
		srv.ServeConn(c, &http2.ServeConnOpts{Handler: h})
		done = c.done
	}) / float64(nreq)
	if done != nreq {
		fmt.Fprintf(os.Stderr, "x/net/http2 answered %d of %d\n", done, nreq)
		gateBad++
	}
	return t
}

func main() {
	runtime.GOMAXPROCS(1)
	dir := os.Args[1]
	passes := 100
	if len(os.Args) > 2 {
		passes, _ = strconv.Atoi(os.Args[2])
	}
	for _, s := range sets {
		want := fields(dir, s)
		fmt.Printf("= hpack %s x/net-hpack-go %.1f\n", s, hpackBench(records(dir, "hpack", s), want, passes))
		fmt.Printf("= h2server %s x/net-http2-go %.1f\n", s, h2Bench(records(dir, "h2client", s)[0], len(want), passes/4+1))
		fmt.Printf("= qpack-static %s quic-go-qpack %.1f\n", s, qpackBench(records(dir, "qpack_static", s), want, passes/2+1))
	}
	if gateBad > 0 {
		fmt.Printf("GATE FAILED: %d\n", gateBad)
		os.Exit(1)
	}
	fmt.Println("gate: every decoder returned every request's fields exactly; every request answered")
	_ = sink
}
