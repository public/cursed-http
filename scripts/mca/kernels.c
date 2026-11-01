// kernels.c - the SIMD hot kernels as llvm-mca regions (scripts/mca/mca.sh): each function's body between the
// markers is one region; mca reports its steady-state throughput (block reciprocal throughput, L1 hits, no
// branch mispredicts). Built once per backend with that backend's flags.
#include "fastparse.h"
#include "fbparse.h"

#if defined(__aarch64__)
#define MCA(name, ...)                                                                                                 \
  do {                                                                                                                 \
    __asm volatile("// LLVM-MCA-BEGIN " name ::: "memory");                                                            \
    __VA_ARGS__;                                                                                                       \
    __asm volatile("// LLVM-MCA-END " name ::: "memory");                                                              \
  } while (0)
#else
#define MCA(name, ...)                                                                                                 \
  do {                                                                                                                 \
    __asm volatile("# LLVM-MCA-BEGIN " name ::: "memory");                                                             \
    __VA_ARGS__;                                                                                                       \
    __asm volatile("# LLVM-MCA-END " name ::: "memory");                                                               \
  } while (0)
#endif
#define K __attribute__((noinline)) void

K k_empty(const char *p, uint64_t *o) { MCA("empty", o[0] = (uint64_t)(uintptr_t)p); } // call overhead (kbench.c)

// fastparse.h: LF + c/t/ctl masks of one 64-byte block (fp_cls64, the per-block classify of every request)
K k_fp_cls64(const char *p, uint64_t *o) { MCA("fp_cls64", fp_cls64(FP_BACKEND != 0, p, &o[0], &o[1])); }
// fbparse.h: all four masks of one block (block 0 of every request)
K k_fb_all64(const char *p, uint64_t *o) { MCA("fb_all64", fb_all64(FB_BACKEND != 0, p, o)); }
// fbparse.h: the not-a-token-char mask alone (header names)
K k_fb_nt64(const char *p, uint64_t *o) { MCA("fb_nt64", o[0] = fb_cls64(FB_BACKEND != 0, FB_NT, p)); }
// fbparse.h: LF + ctl masks (the value scan)
K k_fb_lfct64(const char *p, uint64_t *o) { MCA("fb_lfct64", fb_lfct64(FB_BACKEND != 0, p, &o[0], &o[1])); }
#ifdef FB_HAVE_CTANY
// fbparse.h: the long-value skip test over a 512-byte window (8 blocks)
K k_fb_ctany512(const char *p, uint64_t *o) { MCA("fb_ctany512", o[0] = (uint64_t)fb_ctany_simd(p, 8)); }
#endif
// fastparse.h: SWAR atoi of up to 16 digits (ids, Content-Length); the same code on every backend
K k_fp_digits(const char *p, uint64_t *o) {
  MCA("fp_digits", {
    int ok;
    o[0] = (uint64_t)fp_digits(p, 12, &ok);
    o[1] = (uint64_t)ok;
  });
}
