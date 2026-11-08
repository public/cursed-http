// The Go clients' response parsers on the heads bench/bench_resp.c times (bench_resp --dump DIR CORPUS...):
// ns per head for
//   net/http  http.ReadResponse on a reused bufio.Reader (what http.Client runs on every response; it builds the
//             Response and its Header map)
//   fasthttp  ResponseHeader.Read on a reused bufio.Reader and ResponseHeader (fasthttp.Client's path)
// Each pass parses every head once; the best of the passes is kept, the two parsers interleaved.
//   go run . DIR [passes]     (DIR: one subdirectory per corpus with a responses.dat)
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
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

func passNet(heads [][]byte, rd *bytes.Reader, br *bufio.Reader) (time.Duration, int) {
	bad := 0
	t0 := time.Now()
	for _, h := range heads {
		rd.Reset(h)
		br.Reset(rd)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			bad++
			continue
		}
		sink += resp.StatusCode + len(resp.Header)
	}
	return time.Since(t0), bad
}

func passFast(heads [][]byte, rd *bytes.Reader, br *bufio.Reader, h *fasthttp.ResponseHeader) (time.Duration, int) {
	bad := 0
	t0 := time.Now()
	for _, x := range heads {
		rd.Reset(x)
		br.Reset(rd)
		h.Reset()
		if err := h.Read(br); err != nil {
			bad++
			continue
		}
		sink += h.StatusCode() + h.Len()
	}
	return time.Since(t0), bad
}

func main() {
	passes := 300
	if len(os.Args) > 2 {
		passes, _ = strconv.Atoi(os.Args[2])
	}
	dirs, _ := filepath.Glob(filepath.Join(os.Args[1], "*", "responses.dat"))
	sort.Strings(dirs)
	for _, fn := range dirs {
		heads := load(fn)
		name := filepath.Base(filepath.Dir(fn))
		rd := bytes.NewReader(nil)
		br := bufio.NewReaderSize(rd, 64<<10)
		var fh fasthttp.ResponseHeader
		bn, bf := time.Duration(1<<62), time.Duration(1<<62)
		_, badN := passNet(heads, rd, br)
		_, badF := passFast(heads, rd, br, &fh)
		for i := 0; i < passes; i++ {
			if t, _ := passNet(heads, rd, br); t < bn {
				bn = t
			}
			if t, _ := passFast(heads, rd, br, &fh); t < bf {
				bf = t
			}
		}
		n := float64(len(heads))
		fmt.Printf("%-14s %6d heads:  net/http %.1f ns (%d rejected)  fasthttp %.1f ns (%d rejected)\n", name,
			len(heads), float64(bn.Nanoseconds())/n, badN, float64(bf.Nanoseconds())/n, badF)
	}
	if sink == 42 {
		fmt.Println()
	}
}
