// libFuzzer target: fbparse.h == picohttpparser on every input (fz_check_fb in oracle.h).
// max_headers and last_len are derived from the input, so each input checks one more configuration.
#include "fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
  char err[256];
  uint64_t h = fz_hash((const char *)d, n);
  size_t max = (h & 3) ? FZ_MAXH : (h >> 2) % 9, last_len = (h & 0x30) == 0x30 && n ? (h >> 8) % (n + 1) : 0;
  if (fz_check_fb((const char *)d, n, max, last_len, err, sizeof err)) fz_report("fbparse", err, d, n);
  return 0;
}
