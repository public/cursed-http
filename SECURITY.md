# Security

These parsers sit in front of servers, so a bug in how they frame a request (where it ends, which Content-Length
counts) can enable request smuggling, and any out-of-bounds read is a memory-safety bug. Please report those privately.

- **How to report:** use GitHub's private vulnerability reporting (the "Report a vulnerability" button under this
  repository's Security tab). Please don't open a public issue for a suspected vulnerability.
- **What helps:** the request bytes, which parser and backend (`fast_parse`, `fb_parse_request`, `bp_parse`; AVX2,
  AVX-512, NEON or scalar), the CPU, the compiler and the build flags.
- **Supported versions:** there are no releases yet; fixes go to `main`.

In scope: framing disagreements with picohttpparser or with RFC 9112, out-of-bounds reads (beyond the documented
64 bytes of padding), and differences between backends. Out of scope: fastparse.h accepting malformed header names
or values it doesn't use; that's documented under "Limits and semantic differences" in the README.

The library has not had an external security review.
