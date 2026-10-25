// fuzz.h - shared by the libFuzzer targets: report a mismatch (the check's message and the input, escaped)
// and abort, so libFuzzer saves the input as a crash file. Replay a saved input with the target binary.
#pragma once
#include <stdint.h>
#include "oracle.h"

static void fz_report(const char *what, const char *err, const uint8_t *d, size_t n) {
  fprintf(stderr, "\n%s MISMATCH: %s\ninput (%zu bytes): \"", what, err, n);
  for (size_t i = 0; i < n && i < 4096; i++) { unsigned c = d[i];
    if (c == '\r') fputs("\\r", stderr); else if (c == '\n') fputs("\\n", stderr); else if (c == '\\' || c == '"') fprintf(stderr, "\\%c", c);
    else if (c < 32 || c > 126) fprintf(stderr, "\\x%02x", c); else fputc(c, stderr); }
  fprintf(stderr, "%s\"\n", n > 4096 ? "..." : "");
  abort();
}
