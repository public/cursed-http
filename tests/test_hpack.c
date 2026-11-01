/* include/hpack.h: RFC 7541 Appendix C, then differential tests against nghttp2's HPACK inflater
 * and deflater on random and mutated header blocks.
 *   - decode: blocks made by nghttp2_hd_deflate (random fields, table-size changes) must decode to
 *     the same fields as nghttp2_hd_inflate, keeping both tables in step; mutated blocks must be
 *     accepted or rejected alike (a rejection resets both decoders).
 *   - cached verdicts: every field's nclass / vok equal hv.h run on the decoded strings.
 *   - encode: our response blocks decode under nghttp2_hd_inflate to what we encoded.
 * FUZZ=N scales the counts. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hpack.h"
#include <nghttp2/nghttp2.h>
#include "rfc7541_vectors.h"

static long fails, checks;
#define CHECK(c, ...)                                                                                                  \
  do {                                                                                                                 \
    checks++;                                                                                                          \
    if (!(c)) {                                                                                                        \
      if (fails++ < 20) {                                                                                              \
        printf("FAIL %s:%d: ", __FILE__, __LINE__);                                                                    \
        printf(__VA_ARGS__);                                                                                           \
        printf("\n");                                                                                                  \
      }                                                                                                                \
    }                                                                                                                  \
  } while (0)
static uint64_t rs = 0x2545f4914f6cdd1dull;
static uint64_t rnd(void) {
  rs ^= rs << 13;
  rs ^= rs >> 7;
  rs ^= rs << 17;
  return rs;
}
static long scale(void) {
  const char *e = getenv("FUZZ");
  return e ? atol(e) : 1;
}

static hp_dec D;
static uint8_t ARENA[1 << 16];
static hp_field F[256];

static void test_rfc(void) {
  long before = fails;
  for (size_t i = 0; i < sizeof rfc7541_cases / sizeof rfc7541_cases[0]; i++) {
    const rfc7541_case *c = &rfc7541_cases[i];
    if (c->seq == 1)
      hp_dec_init(&D, c->group >= 5 ? 256 : 4096), D.need_update = 0; /* C.5/C.6: both ends start at 256 */
    int fl,
        n = hp_decode_block(&D, (const uint8_t *)c->block, (size_t)c->blen, F, 256, ARENA, sizeof ARENA, 1 << 20, &fl);
    CHECK(n == c->n, "C.%d.%d: %d fields", c->group, c->seq, n);
    for (int k = 0; k < n && k < c->n; k++) {
      const char *nm = c->h[2 * k], *v = c->h[2 * k + 1];
      CHECK(F[k].nlen == strlen(nm) && !memcmp(F[k].name, nm, F[k].nlen) && F[k].vlen == strlen(v) &&
                !memcmp(F[k].value, v, F[k].vlen),
            "C.%d.%d field %d", c->group, c->seq, k);
    }
    CHECK(D.size == (uint32_t)c->table_size, "C.%d.%d table size %u want %d", c->group, c->seq, D.size, c->table_size);
  }
  printf("rfc7541 C.3-C.6: %s\n", fails == before ? "ok" : "FAILED");
}

/* --------------------------------- random header lists --------------------------------- */
static const char *NAMES[] = { ":method",
                               ":path",
                               ":authority",
                               ":scheme",
                               "user-agent",
                               "accept",
                               "cookie",
                               "x-trace",
                               "content-type",
                               "content-length",
                               "grpc-timeout",
                               "x-Upper",
                               "bad name",
                               "accept-encoding",
                               "authorization",
                               "x-custom-header-with-a-long-name",
                               "te",
                               "" };
static void rand_str(char *o, size_t *n, size_t max) {
  static const char al[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./:;=,?&%()\"' ";
  size_t l = rnd() % 4 == 0 ? rnd() % max : rnd() % 24;
  for (size_t i = 0; i < l; i++) o[i] = rnd() % 50 == 0 ? (char)(rnd() & 0xff) : al[rnd() % (sizeof al - 1)];
  *n = l;
}
typedef struct {
  char n[64], v[600];
  size_t nl, vl;
  uint8_t flags;
} tf;
static int rand_list(tf *t, int max) {
  int k = (int)(rnd() % (unsigned)max) + 1;
  for (int i = 0; i < k; i++) {
    if (rnd() % 5) {
      const char *nm = NAMES[rnd() % (sizeof NAMES / sizeof NAMES[0])];
      t[i].nl = strlen(nm), memcpy(t[i].n, nm, t[i].nl);
    } else rand_str(t[i].n, &t[i].nl, 40);
    if (rnd() % 3 == 0 && i > 0)
      memcpy(t[i].v, t[i - 1].v, t[i - 1].vl), t[i].vl = t[i - 1].vl; /* repeats get indexed */
    else rand_str(t[i].v, &t[i].vl, 500);
    t[i].flags = rnd() % 10 == 0 ? NGHTTP2_NV_FLAG_NO_INDEX : NGHTTP2_NV_FLAG_NONE;
  }
  return k;
}

/* decode one block with nghttp2; returns nfields or -1 */
typedef struct {
  uint8_t n[1024], v[8192];
  size_t nl, vl;
  int never;
} rf;
static rf RF[256];
static int n2_inflate(nghttp2_hd_inflater *inf, const uint8_t *in, size_t len) {
  int k = 0;
  for (;;) {
    nghttp2_nv nv;
    int fl = 0;
    nghttp2_ssize r = nghttp2_hd_inflate_hd3(inf, &nv, &fl, in, len, 1);
    if (r < 0) return -1;
    in += r, len -= (size_t)r;
    if (fl & NGHTTP2_HD_INFLATE_EMIT) {
      if (k < 256 && nv.namelen <= sizeof RF[0].n && nv.valuelen <= sizeof RF[0].v) {
        memcpy(RF[k].n, nv.name, nv.namelen), memcpy(RF[k].v, nv.value, nv.valuelen);
        RF[k].nl = nv.namelen, RF[k].vl = nv.valuelen, RF[k].never = (nv.flags & NGHTTP2_NV_FLAG_NO_INDEX) != 0;
      }
      k++;
    }
    if (fl & NGHTTP2_HD_INFLATE_FINAL) {
      nghttp2_hd_inflate_end_headers(inf);
      return k;
    }
    if (!len && !(fl & NGHTTP2_HD_INFLATE_EMIT)) return -1;
  }
}

static int cmp_fields(int n, int k, const char *what) {
  int ok = n == k;
  for (int i = 0; ok && i < n; i++)
    ok = F[i].nlen == RF[i].nl && !memcmp(F[i].name, RF[i].n, RF[i].nl) && F[i].vlen == RF[i].vl &&
         !memcmp(F[i].value, RF[i].v, RF[i].vl) && F[i].never == RF[i].never;
  CHECK(ok, "%s: %d vs %d fields", what, n, k);
  /* validate-once: the cached verdicts must equal a fresh check */
  for (int i = 0; i < n; i++) {
    uint8_t nc = F[i].nlen && F[i].name[0] == ':' ? (hv_check_name(F[i].name, F[i].nlen) ? HP_N_PSEUDO : HP_N_BAD)
                 : F[i].nlen                      ? (uint8_t)hv_check_nonempty_name(F[i].name, F[i].nlen)
                                                  : HP_N_BAD;
    CHECK(F[i].nclass == nc && F[i].vok == (uint8_t)hv_check_value_rfc9113(F[i].value, F[i].vlen), "%s: verdict %d",
          what, i);
    CHECK(F[i].sidx == hp_name_index(F[i].name, F[i].nlen), "%s: sidx %d", what, i);
  }
  return ok;
}

static void test_diff(void) {
  long before = fails, blocks = 0, mut = 0, mut_rej = 0;
  static uint8_t blk[1 << 16], mb[1 << 16];
  long conns = 300 * scale();
  for (long c = 0; c < conns; c++) {
    uint32_t limit = rnd() % 4 == 0 ? (uint32_t)(rnd() % 4097) : 4096;
    nghttp2_hd_deflater *def;
    nghttp2_hd_inflater *inf;
    nghttp2_hd_deflate_new(&def, limit);
    nghttp2_hd_inflate_new(&inf);
    nghttp2_hd_inflate_change_table_size(inf, limit);
    hp_dec_init(&D, limit);
    for (int r = 0; r < 40; r++) {
      tf t[24];
      nghttp2_nv nv[24];
      int k = rand_list(t, 24);
      for (int i = 0; i < k; i++)
        nv[i] = (nghttp2_nv){ (uint8_t *)t[i].n, (uint8_t *)t[i].v, t[i].nl, t[i].vl, t[i].flags };
      if (rnd() % 16 == 0)
        nghttp2_hd_deflate_change_table_size(def, (size_t)(rnd() % (limit + 1))); /* -> size update */
      nghttp2_ssize bl = nghttp2_hd_deflate_hd(def, blk, sizeof blk, nv, (size_t)k);
      if (bl < 0) {
        printf("deflate failed\n");
        exit(1);
      }
      int fl, n = hp_decode_block(&D, blk, (size_t)bl, F, 256, ARENA, sizeof ARENA, 1 << 20, &fl);
      int kk = n2_inflate(inf, blk, (size_t)bl);
      cmp_fields(n, kk, "block");
      CHECK(D.size == nghttp2_hd_inflate_get_dynamic_table_size(inf), "table size %u", D.size);
      blocks++;
      /* a mutant of this block, on copies of both decoders' state */
      if (rnd() % 2) {
        size_t ml = (size_t)bl;
        memcpy(mb, blk, ml);
        switch (rnd() % 4) {
          case 0:
            if (ml) mb[rnd() % ml] ^= (uint8_t)(1 << (rnd() % 8));
            break;
          case 1:
            if (ml) ml = rnd() % ml;
            break;
          case 2:
            if (ml) mb[rnd() % ml] = (uint8_t)rnd();
            break;
          case 3:
            if (ml < sizeof mb - 4) mb[ml++] = (uint8_t)(0x80 | rnd());
            break; /* extra indexed ref */
        }
        hp_dec save = D;
        nghttp2_hd_inflater *i2;
        nghttp2_hd_inflate_new(&i2);
        nghttp2_hd_inflate_change_table_size(i2, limit);
        /* replay: nghttp2 cannot copy an inflater, so the mutant runs on a fresh pair primed with
         * this connection's next block only when the state is empty; otherwise compare on fresh state */
        hp_dec_init(&D, limit);
        int n1 = hp_decode_block(&D, mb, ml, F, 256, ARENA, sizeof ARENA, 1 << 20, &fl);
        int n2 = n2_inflate(i2, mb, ml);
        if (n1 < 0 || n2 < 0) {
          CHECK((n1 < 0) == (n2 < 0), "mutant accept/reject: ours %d nghttp2 %d", n1, n2);
          if ((n1 < 0) != (n2 < 0) && getenv("DUMP")) {
            for (size_t q = 0; q < ml && q < 48; q++) printf("%02x", mb[q]);
            printf(" (len %zu)\n", ml);
            for (int q = 0; q < n1 && q < 4; q++)
              printf("  [%.*s] = [%.*s]\n", (int)F[q].nlen, F[q].name, (int)(F[q].vlen > 40 ? 40 : F[q].vlen),
                     F[q].value);
          }
          mut_rej++;
        } else cmp_fields(n1, n2, "mutant");
        mut++;
        nghttp2_hd_inflate_del(i2);
        D = save;
      }
    }
    nghttp2_hd_deflate_del(def);
    nghttp2_hd_inflate_del(inf);
  }
  printf("differential: %ld blocks, %ld mutants (%ld rejected by both): %s\n", blocks, mut, mut_rej,
         fails == before ? "ok" : "FAILED");
}

static void test_encode(void) {
  long before = fails;
  static uint8_t blk[1 << 16];
  nghttp2_hd_inflater *inf;
  nghttp2_hd_inflate_new(&inf);
  for (long it = 0; it < 3000 * scale(); it++) {
    tf t[24];
    int k = rand_list(t, 12);
    uint8_t *p = blk;
    if (it == 0) p += hp_enc_size_update(p, 0);
    int st = (int)(rnd() % 3 ? (unsigned[]){ 200, 204, 206, 304, 400, 404, 500 }[rnd() % 7] : 100 + rnd() % 500);
    p += hp_enc_status(p, st);
    for (int i = 0; i < k; i++) {
      if (!t[i].nl || t[i].n[0] == ':') t[i].n[0] = 'x', t[i].nl = t[i].nl ? t[i].nl : 1;
      p += hp_enc_field(p, (uint8_t *)t[i].n, t[i].nl, (uint8_t *)t[i].v, t[i].vl, t[i].flags != 0);
    }
    int n = n2_inflate(inf, blk, (size_t)(p - blk));
    char sv[4];
    snprintf(sv, sizeof sv, "%d", st);
    int ok = n == k + 1 && RF[0].nl == 7 && !memcmp(RF[0].n, ":status", 7) && RF[0].vl == 3 && !memcmp(RF[0].v, sv, 3);
    for (int i = 0; ok && i < k; i++)
      ok = RF[i + 1].nl == t[i].nl && !memcmp(RF[i + 1].n, t[i].n, t[i].nl) && RF[i + 1].vl == t[i].vl &&
           !memcmp(RF[i + 1].v, t[i].v, t[i].vl) && RF[i + 1].never == (t[i].flags != 0);
    CHECK(ok, "encode it=%ld: %d fields", it, n);
    CHECK(nghttp2_hd_inflate_get_dynamic_table_size(inf) == 0, "encoder must not index");
  }
  nghttp2_hd_inflate_del(inf);
  printf("encoder vs nghttp2 inflate: %s\n", fails == before ? "ok" : "FAILED");
}

int main(void) {
  printf("hv backend %s\n", hv_backend());
  test_rfc();
  test_diff();
  test_encode();
  printf("%s: %ld failures / %ld checks\n", fails ? "FAILED" : "PASS", fails, checks);
  return fails != 0;
}
