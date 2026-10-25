// replay.c - a main() for the libFuzzer targets, for compilers without libFuzzer (gcc, Apple clang):
// runs LLVMFuzzerTestOneInput on every file named, and on every file inside each directory named.
//   build/replay_fbparse build/fuzz-corpus/fbparse crash-1234
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n);

static long files;
static void run_file(const char *path) {
  FILE *f = fopen(path, "rb"); if (!f) { perror(path); exit(2); }
  fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
  uint8_t *d = malloc(n ? n : 1);
  if (n && fread(d, 1, n, f) != (size_t)n) { perror(path); exit(2); }
  fclose(f);
  LLVMFuzzerTestOneInput(d, (size_t)n); free(d); files++;
}
int main(int argc, char **argv) {
  for (int i = 1; i < argc; i++) {
    struct stat st; if (stat(argv[i], &st)) { perror(argv[i]); return 2; }
    if (!S_ISDIR(st.st_mode)) { run_file(argv[i]); continue; }
    DIR *dir = opendir(argv[i]); struct dirent *e;
    while ((e = readdir(dir))) { if (e->d_name[0] == '.') continue;
      char p[4096]; snprintf(p, sizeof p, "%s/%s", argv[i], e->d_name); run_file(p); }
    closedir(dir);
  }
  printf("%s: %ld inputs, no mismatch\n", argv[0], files);
  return 0;
}
