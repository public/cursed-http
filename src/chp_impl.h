// chp_impl.h - one backend's entry points as a table (include/chp.h). Each src/chp_<backend>.c sets CHP_IMPL
// (the table's name) and CHP_WANT (the FP_BACKEND number its -m flags must produce), then includes this.
#include "batchparse.h"
#include "fbparse.h"
#include "chp_table.h"

#if FP_BACKEND != CHP_WANT || FB_BACKEND != CHP_WANT
#error "this backend's compiler flags select a different FP_BACKEND / FB_BACKEND"
#endif

static int w_fast_parse(const char *b, int len, req_t *r) { return fast_parse(b, len, r); }
static fp_batch_t w_fast_parse_many(const char *b, int len, req_t *o, int max) {
  return fast_parse_many(b, len, o, max);
}
static int w_fast_parse_learn(const char *b, int len, req_t *r, fp_learn_t *T) {
  return fast_parse_learn(b, len, r, T);
}
static int w_fb_parse_request(const char *b, size_t len, const char **m, size_t *ml, const char **p, size_t *pl,
                              int *mv, struct fb_header *h, size_t *nh, size_t last_len) {
  return fb_parse_request(b, len, m, ml, p, pl, mv, h, nh, last_len);
}
static int w_fb_parse_req(const char *b, int len, req_t *r) { return fb_parse_req(b, len, r); }
static int w_fb_parse_req_ex(const char *b, int len, req_t *r, fb_info_t *i) { return fb_parse_req_ex(b, len, r, i); }
static void w_bp_parse(int n, const char *const *b, const int *l, req_t *o, int *r) { bp_parse(n, b, l, o, r); }

const chp_impl_t CHP_IMPL = { CHP_NAME,           w_fast_parse,   w_fast_parse_many, w_fast_parse_learn,
                              w_fb_parse_request, w_fb_parse_req, w_fb_parse_req_ex, w_bp_parse };
