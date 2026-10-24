// dump_corpus.c: write the benchmark corpora as length-prefixed records (u32 little-endian length, bytes), so
// harnesses in other languages (bench/go-fasthttp) parse exactly the same requests.
//   dump_corpus FILE SHAPE N     SHAPE: 0 k6, 1 gocli -gzip, 2 gocli (the read-heavy mix); 10+s: fallback shape s
#include <stdio.h>
#include <stdlib.h>
#include "fastparse.h"
#include "picohttpparser.h"
#include "testlib.h"
#include "shapes.h"

int main(int argc, char **argv) {
  if (argc < 4) { fprintf(stderr, "usage: %s FILE SHAPE N\n", argv[0]); return 2; }
  FILE *f = fopen(argv[1], "wb"); if (!f) { perror(argv[1]); return 2; }
  int shape = atoi(argv[2]), n = atoi(argv[3]);
  static char buf[65536];
  mk_tokens();
  for (int i = 0; i < n; i++) {
    int l = shape >= 10 ? gen_fb(buf, shape - 10) : gen(buf, shape);
    uint32_t u = (uint32_t)l; fwrite(&u, 4, 1, f); fwrite(buf, 1, (size_t)l, f);
  }
  return fclose(f) != 0;
}
