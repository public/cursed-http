// bench_chunked.c - ns per chunked body: fbparse.h's fb_decode_chunked (in place and out of place) against
// picohttpparser's phr_decode_chunked (in place, consume_trailer = 1), on body shapes from one small chunk to many.
// Each body is decoded from a fresh copy (pico rewrites its input; fb_decode_chunked in place does too); the copy
// is timed alone and subtracted.   ./bench_chunked [rounds]
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fastparse.h"
#include "fbparse.h"
#include "picohttpparser.h"
#include "testlib.h"

enum { N = 512 };
static char *src[N], *work[N], *out; static int len_[N];
static volatile long sink;
static int build(char *b, int chunks, int size, int ext) {
  int n = 0;
  for (int c = 0; c < chunks; c++) {
    n += sprintf(b + n, ext ? "%x;name=value\r\n" : "%x\r\n", size);
    for (int i = 0; i < size; i++) b[n++] = (char)('a' + (i + c) % 26);
    n += sprintf(b + n, "\r\n");
  }
  return n + sprintf(b + n, "0\r\n\r\n");
}
static double t_copy(void) { double best = 1e18;
  for (int r = 0; r < 50; r++) { double t0 = now(); for (int i = 0; i < N; i++) { memcpy(work[i], src[i], len_[i]); sink += work[i][0]; } double t = now() - t0; if (t < best) best = t; }
  return best / N; }
static double t_fb(int inplace) { double best = 1e18;
  for (int r = 0; r < 50; r++) { double t0 = now();
    for (int i = 0; i < N; i++) { memcpy(work[i], src[i], len_[i]); int bl; sink += fb_decode_chunked(work[i], len_[i], inplace ? work[i] : out, 1 << 20, &bl) + bl; }
    double t = now() - t0; if (t < best) best = t; }
  return best / N; }
static double t_pico(void) { double best = 1e18;
  for (int r = 0; r < 50; r++) { double t0 = now();
    for (int i = 0; i < N; i++) { memcpy(work[i], src[i], len_[i]); struct phr_chunked_decoder d; memset(&d, 0, sizeof d); d.consume_trailer = 1;
      size_t sz = len_[i]; sink += phr_decode_chunked(&d, work[i], &sz) + (long)sz; }
    double t = now() - t0; if (t < best) best = t; }
  return best / N; }

int main(int argc, char **argv) {
  int rounds = argc > 1 ? atoi(argv[1]) : 5;
  static const struct { const char *name; int chunks, size, ext; } S[] = {
    {"1 x 17 B (the probe's body)", 1, 17, 0}, {"1 x 500 B", 1, 500, 0}, {"4 x 128 B", 4, 128, 0},
    {"16 x 32 B", 16, 32, 0}, {"64 x 8 B", 64, 8, 0}, {"1 x 4 KB", 1, 4096, 0}, {"8 x 500 B, extensions", 8, 500, 1}};
  out = malloc(1 << 16);
  printf("ns per body (decode only: the copy of the input is subtracted), best of %d rounds\n%-28s %10s %10s %10s\n", rounds, "", "fb in place", "fb to out", "pico");
  for (size_t s = 0; s < sizeof S / sizeof *S; s++) {
    for (int i = 0; i < N; i++) { src[i] = malloc(1 << 16); work[i] = malloc(1 << 16); len_[i] = build(src[i], S[s].chunks, S[s].size, S[s].ext); }
    double a = 1e18, b = 1e18, c = 1e18, z = 1e18;
    for (int r = 0; r < rounds; r++) { double t;
      if ((t = t_copy()) < z) z = t;
      if ((t = t_fb(1)) < a) a = t;
      if ((t = t_fb(0)) < b) b = t;
      if ((t = t_pico()) < c) c = t; }
    printf("%-28s %10.1f %10.1f %10.1f\n", S[s].name, a - z, b - z, c - z);
    for (int i = 0; i < N; i++) { free(src[i]); free(work[i]); }
  }
  return 0;
}
