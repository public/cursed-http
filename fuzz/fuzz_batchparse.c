// libFuzzer target: every batchparse.h lane == fast_parse (fz_check_batch in oracle.h). The lanes are
// the request starts of the input read as a pipelined stream, full and truncated, aliasing one buffer.
#include "fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
  char err[256];
  if (fz_check_batch((const char *)d, n, err, sizeof err)) fz_report("batchparse", err, d, n);
  return 0;
}
