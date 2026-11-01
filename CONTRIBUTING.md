# Contributing

Bug reports, test cases and pull requests are welcome.

- **Tests first.** `make test` must pass on your machine; `make asan` too for anything that touches parsing.
- **Differential, not self-checking.** A new path or backend is compared against picohttpparser (or the existing
  reference in `tests/testlib.h`) on the shared corpora and fuzzed inputs. A difference is either a bug or an entry,
  with a reason, in `tests/edges.h`.
- **Planted bugs must still be caught.** If you change a check, run `make mutants` and make sure every mutant still
  fails a test.
- **Speed claims need their context:** the CPU, compiler, flags and corpus, from `make bench` (and `make compare-all`
  for the fetched parsers).
- **Third-party code stays fetched.** Only picohttpparser and llhttp are vendored, for tests and benchmarks. The other
  comparison and conformance sources are downloaded at pinned commits by `scripts/fetch-thirdparty.sh`; don't commit
  them or any build output.

Contributions are accepted under the MIT licence in [LICENSE](LICENSE).
