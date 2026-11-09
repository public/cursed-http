// tests/browser/replay.c - the requests real browsers sent (saved by server.c), checked again with check.h under
// this build's backend (make builds it for each: native, scalar, SSE2 baseline, emulated AVX-512, real AVX-512).
//   replay [-s] FILE.http...       exit 1 on any mismatch (-s: or any relaxed accept)
//   replay [-s] [-f|-l] -c CORPUS [INDEX]  the requests of a length-prefixed corpus (u32 little-endian length + bytes, as
//                                  bench/dump_corpus and scripts/top1k_crawl.py write); -f: only the lengths where a
//                                  decision can change (check.h BC_FOCUS);
//                                  -l: only next to line ends (lighter: make test). INDEX (tests/top1k/index.tsv) names them.
#include "fastparse.h"
#include "fbparse.h"
#include "picohttpparser.h"
#include "testlib.h"
#include "check.h"

static int corpus(const char *fn, const char *index) {
  FILE *f = fopen(fn, "rb"), *ix = index ? fopen(index, "r") : NULL;
  if (!f) {
    perror(fn);
    return 2;
  }
  char line[1024], tag[1100];
  if (ix && !fgets(line, sizeof line, ix)) ix = NULL; // (header line)
  uint32_t l;
  for (long i = 0; fread(&l, 4, 1, f) == 1; i++) {
    char *b = malloc(l + 1);
    if (fread(b, 1, l, f) != l) return 2;
    snprintf(tag, sizeof tag, "%s #%ld", fn, i);
    if (ix && fgets(line, sizeof line, ix)) {
      line[strcspn(line, "\n")] = 0;
      snprintf(tag, sizeof tag, "#%s", line);
    }
    bc_check(b, l, tag);
    free(b);
  }
  fclose(f);
  if (ix) fclose(ix);
  return 0;
}

int main(int argc, char **argv) {
  int a = 1, strict = 0;
  if (a < argc && !strcmp(argv[a], "-s"))
    strict = 1, a++; // -s: no relaxed accepts either (the fast path and
                     // fb_parse_req must answer every request the same way)
  if (a < argc && !strcmp(argv[a], "-f")) BC_FOCUS = 1, a++;
  else if (a < argc && !strcmp(argv[a], "-l")) BC_FOCUS = 2, a++;
  if (a + 1 < argc && !strcmp(argv[a], "-c")) {
    int r = corpus(argv[a + 1], a + 2 < argc ? argv[a + 2] : NULL);
    if (r) return r;
    bc_summary(BC_FOCUS == 2 ? "corpus (line-end lengths)" : BC_FOCUS ? "corpus (focused lengths)" : "corpus");
    if (strict && BC.relaxed_accept) printf("STRICT: %ld relaxed accepts (want none)\n", BC.relaxed_accept);
    return BC.bad != 0 || (strict && BC.relaxed_accept);
  }
  for (int i = a; i < argc; i++) {
    FILE *f = fopen(argv[i], "rb");
    if (!f) {
      perror(argv[i]);
      return 2;
    }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    rewind(f);
    char *b = malloc((size_t)n + 1);
    if (fread(b, 1, (size_t)n, f) != (size_t)n) return 2;
    fclose(f);
    bc_check(b, (size_t)n, argv[i]);
    free(b);
  }
  bc_summary("replay");
  if (strict && BC.relaxed_accept) printf("STRICT: %ld relaxed accepts (want none)\n", BC.relaxed_accept);
  return BC.bad != 0 || (strict && BC.relaxed_accept);
}
