// libFuzzer target: fastparse.h's contract on every input (fz_check_fast in oracle.h): all cores agree,
// it never disagrees with pico + the routing logic except by falling back, no prefix of a complete
// request completes, and fast_parse_many == repeated fast_parse on the input read as a pipelined stream.
#include "fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
  char err[256];
  if (fz_check_fast((const char *)d, n, err, sizeof err)) fz_report("fastparse", err, d, n);
  return 0;
}
