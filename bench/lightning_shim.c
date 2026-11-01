// lightning (third_party/lightning, softwaredc/lightning 7b3b0cb, fetched by scripts/fetch-thirdparty.sh) behind
// picohttpparser's phr_parse_request signature. lht_header_t has phr_header's layout; lightning returns the body
// offset (= pico's head length) or LHT_EAGAIN (incomplete, pico's -2) / another LHT_E* error (pico's -1).
#include <stddef.h>
#include "lightning/lightning.h"
#include "picohttpparser.h"

_Static_assert(sizeof(lht_header_t) == sizeof(struct phr_header), "lht_header_t must match phr_header");

int lt_parse_request(const char *buf, size_t len, const char **method, size_t *method_len, const char **path,
                     size_t *path_len, int *minor, struct phr_header *headers, size_t *num_headers, size_t last_len) {
  (void)last_len;
  int r = lht_parse_request(buf, len, method, method_len, path, path_len, minor, (lht_header_t *)headers, num_headers);
  return r >= 0 ? r : r == LHT_EAGAIN ? -2 : -1;
}
