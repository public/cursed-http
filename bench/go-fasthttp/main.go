// fasthttp (github.com/valyala/fasthttp) on the same corpora as the C benchmarks: ns/request for
//   raw    RequestHeader.Read from a bufio.Reader over the request bytes (how fasthttp's server parses)
//   +logic the same, then the routing / id / Bearer / Content-Length work fastparse does
// Corpus files come from build/dump_corpus (u32 little-endian length + bytes per request).
//   go run . corpus.bin [passes]
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/valyala/fasthttp"
)

func load(fn string) [][]byte {
	raw, err := os.ReadFile(fn)
	if err != nil {
		panic(err)
	}
	var out [][]byte
	for p := 0; p+4 <= len(raw); {
		n := int(binary.LittleEndian.Uint32(raw[p:]))
		out = append(out, raw[p+4:p+4+n])
		p += 4 + n
	}
	return out
}

var sink int

// the reference logic (tests/testlib.h ref_parse_with): route, id, first Authorization "Bearer ", Content-Length
func digits(s []byte) (int64, bool) {
	if len(s) < 1 || len(s) > 16 {
		return 0, false
	}
	var v int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		v = v*10 + int64(c-'0')
	}
	return v, v > 0
}

func logic(h *fasthttp.RequestHeader) int {
	m, p := h.Method(), h.RequestURI()
	route := 0
	var id int64
	switch {
	case string(m) == "GET" && string(p) == "/feed":
		route = 1
	case string(m) == "GET" && string(p) == "/health":
		route = 2
	case string(m) == "GET" && bytes.HasPrefix(p, []byte("/posts/")):
		id, _ = digits(p[7:])
		route = 3
	case string(m) == "POST" && string(p) == "/posts":
		route = 4
	case string(m) == "POST" && len(p) >= 12 && bytes.HasPrefix(p, []byte("/posts/")) && bytes.HasSuffix(p, []byte("/like")):
		id, _ = digits(p[7 : len(p)-5])
		route = 5
	}
	tok := 0
	if route >= 4 {
		if a := h.Peek("Authorization"); len(a) >= 7 && string(a[:7]) == "Bearer " {
			tok = len(a) - 7
		}
	}
	return route + int(id) + tok + h.ContentLength()
}

func main() {
	reqs := load(os.Args[1])
	passes := 50
	if len(os.Args) > 2 {
		passes, _ = strconv.Atoi(os.Args[2])
	}
	var h fasthttp.RequestHeader
	rd := bytes.NewReader(nil)
	br := bufio.NewReaderSize(rd, 32768)
	bad := 0
	run := func(withLogic bool) float64 {
		best := 1e18
		for pass := 0; pass < passes; pass++ {
			t0 := time.Now()
			for _, r := range reqs {
				rd.Reset(r)
				br.Reset(rd)
				h.Reset()
				if err := h.Read(br); err != nil {
					if pass == 0 && !withLogic {
						bad++
					}
					continue
				}
				if withLogic {
					sink += logic(&h)
				} else {
					sink += len(h.RequestURI())
				}
			}
			if d := float64(time.Since(t0).Nanoseconds()) / float64(len(reqs)); d < best {
				best = d
			}
		}
		return best
	}
	raw := run(false)
	full := run(true)
	fmt.Printf("fasthttp %s: raw %.1f / +logic %.1f ns/request (%d requests, %d rejected, best of %d passes)\n",
		os.Args[1], raw, full, len(reqs), bad, passes)
}
