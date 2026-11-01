// kbench.c - measures what mca.sh estimates: back-to-back calls of one kernel on L1-hot data, so that
// `perf stat -e cycles` / calls - the k_empty baseline is comparable with the region's block rthroughput.
//   cc -O3 <backend flags> -Iinclude scripts/mca/kbench.c -o kbench && perf stat -e cycles ./kbench fb_all64 100000000
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kernels.c"

int main(int argc, char **argv) {
  static const struct {
    const char *n;
    void (*f)(const char *, uint64_t *);
  } K_[] = { { "empty", k_empty },
             { "fp_cls64", k_fp_cls64 },
             { "fb_all64", k_fb_all64 },
             { "fb_nt64", k_fb_nt64 },
             { "fb_lfct64", k_fb_lfct64 },
#ifdef FB_HAVE_CTANY
             { "fb_ctany512", k_fb_ctany512 },
#endif
             { "fp_digits", k_fp_digits } };
  if (argc < 3) {
    fprintf(stderr, "usage: %s KERNEL CALLS\n", argv[0]);
    return 2;
  }
  void (*f)(const char *, uint64_t *) = NULL;
  for (size_t i = 0; i < sizeof K_ / sizeof *K_; i++)
    if (!strcmp(K_[i].n, argv[1])) f = K_[i].f;
  if (!f) {
    printf("%s: not in this build\n", argv[1]);
    return 3;
  } // e.g. fb_ctany512 without SIMD: nothing to time
  long calls = atol(argv[2]);
  // 8 KB of header-like bytes (L1-resident), walked in 64-byte steps; 512 extra for the 512-byte window kernel
  static char buf[8192 + 1024] __attribute__((aligned(64)));
  const char *txt =
      "Host: example.com\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64)\r\nAccept: */*\r\nCookie: a=1; b=2\r\n";
  for (size_t i = 0; i < sizeof buf; i++) buf[i] = txt[i % strlen(txt)];
  memcpy(buf, "123456789012", 12);
  uint64_t o[4] = { 0 }, acc = 0;
  for (long i = 0; i < calls; i++) {
    f(buf + ((i * 64) & 8191), o);
    acc += o[0] ^ o[1];
  }
  printf("%s %ld calls (%llu)\n", argv[1], calls, (unsigned long long)acc);
  return 0;
}
