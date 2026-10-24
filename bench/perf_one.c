// perf_one.c: one parser, one corpus, many passes, nothing else, for hardware counters (perf stat).
//   perf_one CORPUS.bin PARSER PASSES      PARSER: fb | pico | lightning (-DHAVE_LIGHTNING) | httparse (-DHAVE_HTTPARSE)
// -DPAD_BYTES=n shifts the code layout (for layout-randomised comparisons: the median over several n).
// CORPUS.bin comes from build/dump_corpus. Each request sits in its own malloc'd buffer with 64 bytes of padding.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "picohttpparser.h"
#include "fbparse.h"
#ifdef HAVE_HTTPARSE
int hx_parse_request(const char *, size_t, const char **, size_t *, const char **, size_t *, int *, struct phr_header *, size_t *, size_t);
#endif
#ifdef HAVE_LIGHTNING
int lt_parse_request(const char *, size_t, const char **, size_t *, const char **, size_t *, int *, struct phr_header *, size_t *, size_t);
#endif
#ifdef PAD_BYTES   // layout randomisation: shift everything after this by PAD_BYTES of code (0 is fine)
#define PAD_STR2(x) #x
#define PAD_STR(x) PAD_STR2(x)
__attribute__((used, noinline)) void layout_pad(void) { __asm__ volatile(".skip " PAD_STR(PAD_BYTES) ", 0x90"); }
#endif
typedef int (*phr_fn)(const char *, size_t, const char **, size_t *, const char **, size_t *, int *, struct phr_header *, size_t *, size_t);
static int fb(const char *b, size_t l, const char **m, size_t *ml, const char **p, size_t *pl, int *mv, struct phr_header *h, size_t *nh, size_t ll) {
  return fb_parse_request(b, l, m, ml, p, pl, mv, (struct fb_header *)h, nh, ll); }

int main(int argc, char **argv) {
  if (argc < 4) { fprintf(stderr, "usage: %s CORPUS PARSER PASSES\n", argv[0]); return 2; }
  FILE *f = fopen(argv[1], "rb"); if (!f) { perror(argv[1]); return 2; }
  static char *req[65536]; static int len[65536]; int n = 0; uint32_t l;
  while (n < 65536 && fread(&l, 4, 1, f) == 1) { req[n] = malloc(l + 64); if (fread(req[n], 1, l, f) != l) return 2; memset(req[n] + l, 0, 64); len[n++] = (int)l; }
  phr_fn fn = !strcmp(argv[2], "fb") ? fb : !strcmp(argv[2], "pico") ? phr_parse_request :
#ifdef HAVE_LIGHTNING
              !strcmp(argv[2], "lightning") ? lt_parse_request :
#endif
#ifdef HAVE_HTTPARSE
              !strcmp(argv[2], "httparse") ? hx_parse_request :
#endif
              NULL;
  if (!fn) { fprintf(stderr, "unknown parser %s\n", argv[2]); return 2; }
  int passes = atoi(argv[3]); long sink = 0; struct timespec t0, t1; clock_gettime(CLOCK_MONOTONIC, &t0);
  for (int r = 0; r < passes; r++) for (int i = 0; i < n; i++) {
    const char *m, *p; size_t ml, pl, nh = 48; int mv; struct phr_header h[48];
    sink += fn(req[i], (size_t)len[i], &m, &ml, &p, &pl, &mv, h, &nh, 0) + (int)nh;
  }
  clock_gettime(CLOCK_MONOTONIC, &t1);
  printf("%s %s: %.1f ns/request over %d x %d (sink %ld)\n", argv[2], argv[1], ((t1.tv_sec - t0.tv_sec) * 1e9 + (t1.tv_nsec - t0.tv_nsec)) / ((double)passes * n), passes, n, sink);
  return 0;
}
