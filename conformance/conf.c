// Conformance run of fastparse.h against third-party test suites (cases.bin, built by conformance/extract.py
// from sources fetched by scripts/fetch-thirdparty.sh).   make conformance
//   build/conf [cases.bin] [report.txt]   -> summary on stdout, one line per non-trivial case in the report
//
// Our contract is partial by design: for every input fast_parse must either FALL BACK, or say NEED_MORE when
// the request really is incomplete, or return exactly what a correct parser would. It must never accept a
// request with a different framing or different fields.
// References, run live on every case and on every truncation of it:
//   llhttp  (strict, full message incl. body framing: Content-Length / chunked) -> accept(end) / partial / reject
//   pico    (request line + headers; + the reference logic for route/id/token/CL)
//   uWS     (request line + headers, its own validation)
// Plus each suite's own expected verdict where it has one (llhttp strict mode, pico test.c, httparse).
//
// Categories for an input we ACCEPT (> 0):
//   AGREE         llhttp accepts with the same end, and pico+logic gives identical fields
//   RELAXED       some reference rejects, but no reference that accepts frames it differently: we skip a
//                 validation (e.g. token characters). Listed for triage.
//   ACCEPT-INVALID every reference rejects or wants more, and we accept. Listed for triage.
//   MISMATCH      a reference accepts with a different end or fields. Always a bug (desync / smuggling risk).
// For NEED_MORE: STALL if a reference accepts the complete request (we would wait forever: a bug).
#ifdef HTTP_HEADER
#include HTTP_HEADER
#else
#include "fastparse.h"
#endif
#include "picohttpparser.h"
#include "llhttp.h"
#include "testlib.h"

int uw_parse_request(const char *, size_t, const char **, size_t *, const char **, size_t *, int *, struct phr_header *,
                     size_t *, size_t);

// ---- llhttp, whole first message ----
typedef struct {
  llhttp_t p;
  int done;
} lm_t;
static int lm_done(llhttp_t *p) {
  ((lm_t *)p)->done = 1;
  return HPE_PAUSED;
}
static llhttp_settings_t LMS;
enum { V_ACCEPT = 1, V_PARTIAL = 0, V_REJECT = -1 };
static int llhttp_message(const char *b, size_t len, int *end) {
  lm_t s;
  llhttp_init(&s.p, HTTP_REQUEST, &LMS);
  s.done = 0;
  llhttp_errno_t e = llhttp_execute(&s.p, b, len);
  if (e == HPE_PAUSED && s.done) {
    *end = (int)(llhttp_get_error_pos(&s.p) - b);
    return V_ACCEPT;
  }
  if (e == HPE_OK) return V_PARTIAL;
  return V_REJECT;
}
static int phr_verdict(int r) { return r > 0 ? V_ACCEPT : r == -2 ? V_PARTIAL : V_REJECT; }

typedef struct {
  char name[200], src[64], verdict[16];
  int len;
  char *data;
} case_t;

static const char *vs(int v) { return v == V_ACCEPT ? "accept" : v == V_PARTIAL ? "partial" : "reject"; }
static FILE *rep;
static long cnt[16];
enum { C_AGREE, C_RELAXED, C_INVALID, C_MISMATCH, C_FALLBACK, C_NEEDMORE, C_STALL, C_SCALAR, C_N };
static const char *CN[] = { "AGREE",    "RELAXED",   "ACCEPT-INVALID", "MISMATCH",
                            "FALLBACK", "NEED_MORE", "STALL",          "SCALAR/LEARN-DIFF" };
// learned-layout path: one table for the whole run (layouts learned from one case are tried on all
// later cases and truncations), every input parsed twice so a layout learned from it is tried at once
static fp_learn_t T;
static long learn_hits;

static void show(const char *b, int len, int max) {
  for (int i = 0; i < len && i < max; i++) {
    unsigned char c = (unsigned char)b[i];
    if (c == '\r') fputs("\\r", rep);
    else if (c == '\n') fputs("\\n", rep);
    else if (c < 32 || c > 126) fprintf(rep, "\\x%02x", c);
    else fputc(c, rep);
  }
  if (len > max) fputs("...", rep);
}

// judge one input; returns its category. trunc >= 0: this is a prefix of the case
static int judge(const case_t *k, const char *b, int len, int trunc, int report) {
  req_t f, s, q1, q2;
  int a = fast_parse(b, len, &f), a2 = fast_parse_scalar(b, len, &s);
  uint64_t h0 = T.hits;
  int a3 = fast_parse_learn(b, len, &q1, &T), a4 = fast_parse_learn(b, len, &q2, &T);
  learn_hits += T.hits != h0;
  int cat;
  int lend = -1, lv = llhttp_message(b, len, &lend);
  const char *m, *p;
  size_t ml, pl, nh = 48;
  int minor;
  struct phr_header h[48];
  int pv = phr_verdict(phr_parse_request(b, len, &m, &ml, &p, &pl, &minor, h, &nh, 0));
  char *ub = malloc(len + PAD);
  memcpy(ub, b, len);
  memset(ub + len, 0, PAD); // uWS writes into its buffer
  nh = 48;
  int uv = phr_verdict(uw_parse_request(ub, len, &m, &ml, &p, &pl, &minor, h, &nh, 0));
  free(ub);
  req_t g;
  int ref = ref_parse(b, len, &g); // pico + the reference logic (route/id/token/CL)
  if (!same(a, &f, a2, &s) || (a > 0 && f.id != s.id) || !same(a, &f, a3, &q1) || !same(a, &f, a4, &q2) ||
      (a > 0 && (f.id != q1.id || f.id != q2.id)))
    cat = C_SCALAR;
  else if (a == FP_FALLBACK) cat = C_FALLBACK;
  else if (a == FP_NEED_MORE) cat = (lv == V_ACCEPT || (pv == V_ACCEPT && ref > 0)) ? C_STALL : C_NEEDMORE;
  else {
    int bad = (lv == V_ACCEPT && lend != a) || (ref > 0 && !same(a, &f, ref, &g)) || (ref > 0 && f.id != g.id);
    if (bad) cat = C_MISMATCH;
    else if (lv == V_ACCEPT && pv == V_ACCEPT && uv == V_ACCEPT) cat = C_AGREE;
    else if (lv == V_ACCEPT || pv == V_ACCEPT || uv == V_ACCEPT) cat = C_RELAXED;
    else cat = C_INVALID;
  }
  // report 1: everything non-trivial; 2 (truncations): bugs only
  if ((report == 1 && cat != C_AGREE && cat != C_FALLBACK && cat != C_NEEDMORE) ||
      (report == 2 && (cat == C_MISMATCH || cat == C_STALL || cat == C_SCALAR))) {
    fprintf(rep, "%-14s %s%s  [suite: %s | llhttp %s%s pico %s uws %s | ours %d route %d id_ok %d cl %d]\n    ",
            CN[cat], k->name, trunc >= 0 ? " (truncated)" : "", k->verdict[0] ? k->verdict : "-", vs(lv),
            lv == V_ACCEPT ? "" : "", vs(pv), vs(uv), a, a > 0 ? f.route : -1, a > 0 ? f.id_ok : -1,
            a > 0 ? f.body_len : -1);
    show(b, len, 160);
    fputc('\n', rep);
  }
  return cat;
}

int main(int argc, char **argv) {
  llhttp_settings_init(&LMS);
  LMS.on_message_complete = lm_done;
  const char *fn = argc > 1 ? argv[1] : "build/cases.bin";
  FILE *fi = fopen(fn, "rb");
  if (!fi) {
    perror(fn);
    return 2;
  }
  fseek(fi, 0, SEEK_END);
  long sz = ftell(fi);
  fseek(fi, 0, SEEK_SET);
  char *all = malloc(sz);
  if (fread(all, 1, sz, fi) != (size_t)sz) return 2;
  fclose(fi);
  rep = fopen(argc > 2 ? argv[2] : "build/conformance-report.txt", "w");
  printf("parser: %s / %s\n", FP_SPEC_NAME, FP_BACKEND_NAME);
  long ncase = 0, ntrunc = 0, tcnt[C_N] = { 0 }, suite_disagree = 0;
  for (long i = 0; i < sz;) {
    case_t k;
    memset(&k, 0, sizeof k);
    snprintf(k.name, sizeof k.name, "%s", all + i);
    i += strlen(all + i) + 1;
    snprintf(k.src, sizeof k.src, "%s", all + i);
    i += strlen(all + i) + 1;
    snprintf(k.verdict, sizeof k.verdict, "%s", all + i);
    i += strlen(all + i) + 1;
    uint32_t n;
    memcpy(&n, all + i, 4);
    i += 4;
    k.len = (int)n;
    k.data = malloc(k.len + PAD);
    memcpy(k.data, all + i, k.len);
    memset(k.data + k.len, 0x5a, PAD);
    i += k.len;
    int c = judge(&k, k.data, k.len, -1, 1);
    cnt[c]++;
    ncase++;
    // the suite's own verdict vs ours: we may only "accept" where the suite does not say reject
    if (k.verdict[0] && !strcmp(k.verdict, "reject") && (c == C_AGREE || c == C_RELAXED || c == C_INVALID)) {
      suite_disagree++;
      fprintf(rep, "SUITE-REJECTS  %s: the suite expects reject, we accept (category %s)\n", k.name, CN[c]);
    }
    for (int t = 0; t < k.len; t++) { // every truncation, judged the same way
      char *b = malloc(t + PAD);
      memcpy(b, k.data, t);
      memset(b + t, 0x5a, PAD);
      int ct = judge(&k, b, t, t, 2);
      tcnt[ct]++;
      ntrunc++;
      free(b);
    }
    free(k.data);
  }
  printf("%ld cases (+%ld truncations):\n", ncase, ntrunc);
  for (int c = 0; c < C_N; c++) printf("  %-15s %5ld   (truncations: %ld)\n", CN[c], cnt[c], tcnt[c]);
  printf("  suite says reject, we accept: %ld\n", suite_disagree);
  printf("  learned-layout fast path used on %ld inputs (all identical to fast_parse unless counted above)\n",
         learn_hits);
  long bugs = cnt[C_MISMATCH] + cnt[C_STALL] + cnt[C_SCALAR] + tcnt[C_MISMATCH] + tcnt[C_STALL] + tcnt[C_SCALAR];
  printf("BUGS (MISMATCH + STALL + SCALAR-DIFF, incl. truncations): %ld\n", bugs);
  fclose(rep);
  return bugs != 0;
}
