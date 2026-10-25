// chp.c - load-time backend selection for include/chp.h. Built with the architecture's baseline flags.
// The CPU is checked once (a constructor, or the first call if another constructor parses first); every
// call is then one load of the table pointer and one indirect call.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "chp.h"
#include "chp_table.h"

extern const chp_impl_t chp_impl_scalar;
#if defined(__x86_64__) || defined(__i386__)
extern const chp_impl_t chp_impl_sse2, chp_impl_avx2, chp_impl_avx512;
#define CHP_X86 1
#elif defined(__aarch64__)
extern const chp_impl_t chp_impl_neon;
#endif

typedef struct { const chp_impl_t *impl; int (*ok)(void); } chp_cand_t;
#ifdef CHP_X86
// __builtin_cpu_supports checks the OS too (XGETBV: the AVX / AVX-512 register state is enabled). Each
// backend asks for exactly the -m flags its object is built with (Makefile, CHP_FLAGS_*).
static int chp_ok_avx512(void) {
  return __builtin_cpu_supports("avx512f") && __builtin_cpu_supports("avx512bw") && __builtin_cpu_supports("avx512vl") &&
         __builtin_cpu_supports("avx512cd") && __builtin_cpu_supports("avx512dq") && __builtin_cpu_supports("avx2") &&
         __builtin_cpu_supports("bmi") && __builtin_cpu_supports("bmi2") && __builtin_cpu_supports("popcnt");
}
static int chp_ok_avx2(void) {
  return __builtin_cpu_supports("avx2") && __builtin_cpu_supports("bmi") && __builtin_cpu_supports("bmi2") &&
         __builtin_cpu_supports("popcnt");
}
#endif
static int chp_ok_always(void) { return 1; }
static const chp_cand_t CHP_CANDS[] = {   // best first
#ifdef CHP_X86
  {&chp_impl_avx512, chp_ok_avx512}, {&chp_impl_avx2, chp_ok_avx2}, {&chp_impl_sse2, chp_ok_always},
#elif defined(__aarch64__)
  {&chp_impl_neon, chp_ok_always},
#endif
  {&chp_impl_scalar, chp_ok_always},
};
#define CHP_NCANDS (int)(sizeof CHP_CANDS / sizeof *CHP_CANDS)

static const chp_impl_t *chp_cur;   // set once at load; chp_select may replace it (atomic pointer stores)
static const char *chp_names[CHP_NCANDS + 1];

static const chp_impl_t *chp_find(const char *name) {
  for (int i = 0; i < CHP_NCANDS; i++)
    if (!strcmp(CHP_CANDS[i].impl->name, name)) return CHP_CANDS[i].ok() ? CHP_CANDS[i].impl : NULL;
  return NULL;
}
static const chp_impl_t *chp_init(void) {
#ifdef CHP_X86
  __builtin_cpu_init();   // needed when this runs before libgcc's own constructor
#endif
  int n = 0;
  for (int i = 0; i < CHP_NCANDS; i++) if (CHP_CANDS[i].ok()) chp_names[n++] = CHP_CANDS[i].impl->name;
  chp_names[n] = NULL;
  const chp_impl_t *t = NULL;
  const char *env = getenv("CHP_BACKEND");
  if (env && *env && !(t = chp_find(env))) fprintf(stderr, "chp: CHP_BACKEND=%s is unknown or unsupported here; using %s\n", env, chp_names[0]);
  if (!t) t = chp_find(chp_names[0]);
  __atomic_store_n(&chp_cur, t, __ATOMIC_RELEASE);
  return t;
}
__attribute__((constructor)) static void chp_ctor(void) { chp_init(); }
static inline const chp_impl_t *chp_get(void) {
  const chp_impl_t *t = __atomic_load_n(&chp_cur, __ATOMIC_ACQUIRE);
  return __builtin_expect(t != NULL, 1) ? t : chp_init();
}

const char *chp_backend(void) { return chp_get()->name; }
const char *const *chp_backends(void) { chp_get(); return chp_names; }
int chp_select(const char *name) {
  chp_get();
  const chp_impl_t *t = chp_find(name);
  if (!t) return -1;
  __atomic_store_n(&chp_cur, t, __ATOMIC_RELEASE);
  return 0;
}

int chp_fast_parse(const char *b, int len, req_t *r) { return chp_get()->fast_parse(b, len, r); }
fp_batch_t chp_fast_parse_many(const char *b, int len, req_t *o, int max) { return chp_get()->fast_parse_many(b, len, o, max); }
int chp_fast_parse_learn(const char *b, int len, req_t *r, fp_learn_t *T) { return chp_get()->fast_parse_learn(b, len, r, T); }
int chp_fb_parse_request(const char *b, size_t len, const char **m, size_t *ml, const char **p, size_t *pl, int *mv,
                         struct fb_header *h, size_t *nh, size_t last_len) {
  return chp_get()->fb_parse_request(b, len, m, ml, p, pl, mv, h, nh, last_len);
}
int chp_fb_parse_req(const char *b, int len, req_t *r) { return chp_get()->fb_parse_req(b, len, r); }
int chp_fb_parse_req_ex(const char *b, int len, req_t *r, fb_info_t *i) { return chp_get()->fb_parse_req_ex(b, len, r, i); }
void chp_bp_parse(int n, const char *const *b, const int *l, req_t *o, int *r) { chp_get()->bp_parse(n, b, l, o, r); }
