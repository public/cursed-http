// chp.h - cursed-http-parser behind one ABI, for binaries that run on any CPU of their architecture.
// Part of cursed-http-parser. MIT licence, see LICENSE.
//
// The headers pick their SIMD backend at compile time (-march). A binary built for the x86-64 baseline
// therefore gets SSE2, and one built with -mavx2 dies on a CPU without it. Link build/libchp.a instead
// (make lib) and call these: every backend this architecture can have is compiled into the library, each
// in its own object file with its own -m flags, and the best one the CPU and OS support is picked once,
// at load time:
//   x86-64:  avx512 (AVX-512BW/VL on ymm) > avx2 > sse2 > scalar
//   aarch64: neon > scalar
//   other:   scalar
// The results are identical on every backend (tests/test_chp.c checks each against scalar).
//
//   CHP_BACKEND=avx2 ./server    pick a backend by name (ignored, with a note on stderr, if unsupported)
//   chp_select("sse2")           the same from code; call it before any thread parses
//   chp_backend()                the name in use
// Each call costs one indirect call over the inline header functions (about 1 ns).
#pragma once
#include "fastparse.h"   // req_t, fp_batch_t, fp_learn_t: the same layout on every backend
#include "fbparse.h"     // struct fb_header, fb_info_t

#ifdef __cplusplus
extern "C" {
#endif
int chp_fast_parse(const char *buf, int len, req_t *r);
fp_batch_t chp_fast_parse_many(const char *buf, int len, req_t *out, int max);
int chp_fast_parse_learn(const char *buf, int len, req_t *r, fp_learn_t *T);
int chp_fb_parse_request(const char *buf, size_t len, const char **method, size_t *method_len, const char **path,
                         size_t *path_len, int *minor_version, struct fb_header *headers, size_t *num_headers, size_t last_len);
int chp_fb_parse_req(const char *buf, int len, req_t *r);
int chp_fb_parse_req_ex(const char *buf, int len, req_t *r, fb_info_t *info);
void chp_bp_parse(int n, const char *const *buf, const int *len, req_t *out, int *ret);

const char *chp_backend(void);                 // "avx512", "avx2", "sse2", "neon" or "scalar"
int chp_select(const char *name);              // 0 = switched, -1 = unknown or unsupported here (unchanged)
const char *const *chp_backends(void);         // NULL-terminated: the backends this CPU supports, best first
#ifdef __cplusplus
}
#endif
