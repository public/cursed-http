// tests/browser/replay.c - the requests real browsers sent (saved by server.c), checked again with check.h under
// this build's backend (make builds it for each: native, scalar, SSE2 baseline, emulated AVX-512, real AVX-512).
//   replay FILE.http...     exit 1 on any mismatch
#include "fastparse.h"
#include "fbparse.h"
#include "picohttpparser.h"
#include "testlib.h"
#include "check.h"

int main(int argc, char **argv) {
  for (int i = 1; i < argc; i++) {
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
  return BC.bad != 0;
}
