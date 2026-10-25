// seeds.c - writes the seed corpus for the fuzzers: the edge cases, the client corpus (k6, gocli), the
// fallback shapes (curl, Chrome, Firefox, HTTP/1.0, long heads, chunked, odd) and pipelined pairs, one file
// per input.   build/fuzz_seeds DIR
#include <stdio.h>
#include "fastparse.h"
#include "picohttpparser.h"
#include "testlib.h"
#include "shapes.h"
#include "edges.h"

static int nfiles;
static void put(const char *dir, const char *d, int n) {
  char p[4096]; snprintf(p, sizeof p, "%s/seed-%05d", dir, nfiles++);
  FILE *f = fopen(p, "wb"); if (!f) { perror(p); exit(2); }
  fwrite(d, 1, n, f); fclose(f);
}
int main(int argc, char **argv) {
  if (argc < 2) { fprintf(stderr, "usage: %s DIR\n", argv[0]); return 2; }
  static char a[32768], b[32768];
  mk_tokens();
  for (size_t i = 0; i < sizeof EDGES / sizeof *EDGES; i++) put(argv[1], EDGES[i].req, (int)strlen(EDGES[i].req));
  for (int shape = 0; shape < 3; shape++) for (int i = 0; i < 40; i++) put(argv[1], a, gen(a, shape));
  for (int shape = 0; shape < S_NSHAPES; shape++) for (int i = 0; i < 20; i++) put(argv[1], a, gen_fb(a, shape));
  for (int i = 0; i < 40; i++) { int l = gen(a, i % 3), m = gen_fb(b, i % S_NSHAPES);   // pipelined pairs
    if (l + m < (int)sizeof a) { memcpy(a + l, b, m); put(argv[1], a, l + m); } }
  printf("%d seeds in %s\n", nfiles, argv[1]);
  return 0;
}
