// scan_one.c: raw scan speed over the cookie values of the same request buffers, no parsing: glibc/libc memchr for a byte that is
// absent (reads every byte) vs fbparse's skip test (fb_ctany_simd) over aligned windows. Tells whether a gap on
// long headers is the scan itself or the parse around it.   scan_one CORPUS.bin PASSES
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "fbparse.h"
static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1e9 + t.tv_nsec; }
int main(int argc, char **argv) {
  FILE *f = fopen(argv[1], "rb"); if (!f) return 2;
  static char *req[65536]; static int len[65536]; int n = 0; uint32_t l;
  while (n < 65536 && fread(&l, 4, 1, f) == 1) {
    char *b = malloc(l + 64); if (fread(b, 1, l, f) != l) return 2; memset(b + l, 0, 64);
    char *c = strstr(b, "\r\nCookie: "); if (!c) { free(b); continue; }
    char *e = strstr(c + 10, "\r\n");   // scan the cookie value only: no control byte in it
    req[n] = c + 10; len[n++] = (int)(e - (c + 10));
  }
  int passes = atoi(argv[2]); long sink = 0; double t0, best_m = 1e18, best_w = 1e18;
  for (int r = 0; r < passes; r++) {
    t0 = now(); for (int i = 0; i < n; i++) sink += memchr(req[i], 0x01, (size_t)len[i]) != NULL;
    double d = (now() - t0) / n; if (d < best_m) best_m = d;
#ifdef FB_HAVE_CTANY
    t0 = now();
    for (int i = 0; i < n; i++) {
      const char *q = (const char *)(((uintptr_t)req[i] + 63) & ~(uintptr_t)63), *lim = req[i] + len[i] - 64 * (FB_CTANY_BLOCKS - 1);
      while (q < lim && !fb_ctany_simd(q, FB_CTANY_BLOCKS)) q += 64 * FB_CTANY_BLOCKS;
      sink += q - req[i];
    }
    d = (now() - t0) / n; if (d < best_w) best_w = d;
#endif
  }
  printf("%s: memchr %.1f ns/request, fbparse skip windows %.1f ns/request (sink %ld)\n", argv[1], best_m, best_w, sink);
  return 0;
}
