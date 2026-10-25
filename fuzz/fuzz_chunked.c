// libFuzzer target: fbparse.h's chunked-body decoder vs picohttpparser's phr_decode_chunked
// (fz_check_chunked in oracle.h): never more lenient, same body and length when it accepts.
#include "fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
  char err[256];
  if (fz_check_chunked((const char *)d, n, err, sizeof err)) fz_report("chunked", err, d, n);
  return 0;
}
