/* include/qpack.h: RFC 9204 Appendix B, then differential tests against nghttp3.
 *   - B.1-B.5: encoder-stream instructions, field sections, table sizes and our decoder-stream bytes.
 *   - live: nghttp3's encoder (dynamic table, 0 blocked streams) encodes random requests; our decoder
 *     and nghttp3's decoder both read its encoder stream and sections and must agree. Our decoder-
 *     stream output is fed back to nghttp3's encoder, so its acknowledgements must be right for the
 *     encoder to keep using the table.
 *   - mutants of sections must be accepted or rejected as nghttp3 does.
 *   - our static-only encoder decodes under nghttp3's decoder to what we encoded.
 * FUZZ=N scales the counts. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "qpack.h"
#include <nghttp3/nghttp3.h>

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
static uint64_t rs = 0x853c49e6748fea9bull;
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
static void hex(uint8_t *o, size_t *n, const char *h) {
  *n = 0;
  for (; *h; h += 2) sscanf(h, "%2hhx", &o[(*n)++]);
}

static qp_dec D;
static uint8_t ARENA[1 << 16];
static hp_field F[256];

static int field_is(const hp_field *f, const char *n, const char *v) {
  return f->nlen == strlen(n) && !memcmp(f->name, n, f->nlen) && f->vlen == strlen(v) && !memcmp(f->value, v, f->vlen);
}

static void test_rfc(void) {
  long before = fails;
  uint8_t b[256], fb[64];
  size_t n;
  int fl, k;
  qp_dec_init(&D, 220);
  /* B.1 */
  hex(b, &n, "0000510b2f696e6465782e68746d6c");
  k = qp_decode_section(&D, 0, b, n, F, 256, ARENA, sizeof ARENA, 1 << 20, &fl);
  CHECK(k == 1 && field_is(&F[0], ":path", "/index.html"), "B.1");
  CHECK(qp_dec_feedback(&D, fb, sizeof fb) == 0, "B.1: no decoder-stream output");
  /* B.2 */
  hex(b, &n, "3fbd01c00f7777772e6578616d706c652e636f6dc10c2f73616d706c652f70617468");
  CHECK(qp_dec_encoder(&D, b, n) == (int)n && D.size == 106 && D.inserted == 2, "B.2 encoder: size %u", D.size);
  hex(b, &n, "03811011");
  k = qp_decode_section(&D, 4, b, n, F, 256, ARENA, sizeof ARENA, 1 << 20, &fl);
  CHECK(k == 2 && field_is(&F[0], ":authority", "www.example.com") && field_is(&F[1], ":path", "/sample/path"),
        "B.2 section");
  size_t m = qp_dec_feedback(&D, fb, sizeof fb);
  CHECK(m == 1 && fb[0] == 0x84, "B.2 decoder stream: %zu bytes %02x", m, fb[0]);
  /* B.3 */
  hex(b, &n, "4a637573746f6d2d6b65790c637573746f6d2d76616c7565");
  CHECK(qp_dec_encoder(&D, b, n) == (int)n && D.size == 160, "B.3 encoder: size %u", D.size);
  m = qp_dec_feedback(&D, fb, sizeof fb);
  CHECK(m == 1 && fb[0] == 0x01, "B.3 decoder stream: Insert Count Increment(1)");
  /* B.4 */
  hex(b, &n, "02");
  CHECK(qp_dec_encoder(&D, b, n) == 1 && D.size == 217, "B.4 duplicate: size %u", D.size);
  hex(b, &n, "050080c181");
  k = qp_decode_section(&D, 8, b, n, F, 256, ARENA, sizeof ARENA, 1 << 20, &fl);
  CHECK(k == 3 && field_is(&F[0], ":authority", "www.example.com") && field_is(&F[1], ":path", "/") &&
            field_is(&F[2], "custom-key", "custom-value"),
        "B.4 section");
  m = qp_dec_feedback(&D, fb, sizeof fb); /* the section ack (we decoded it; the RFC's decoder cancelled) */
  CHECK(m == 1 && fb[0] == 0x88, "B.4 section ack");
  qp_dec_cancel(&D, 8);
  m = qp_dec_feedback(&D, fb, sizeof fb);
  CHECK(m == 1 && fb[0] == 0x48, "B.4 Stream Cancellation(8)");
  /* B.5 */
  hex(b, &n, "810d637573746f6d2d76616c756532");
  CHECK(qp_dec_encoder(&D, b, n) == (int)n && D.size == 215 && D.inserted == 5 && D.n == 4, "B.5: size %u entries %u",
        D.size, D.n);
  hex(b, &n, "0000"); /* evicted entry 0 must be gone; entry 4 present */
  CHECK(qp__abs(&D, 0) == NULL && qp__abs(&D, 4) && D.store[qp__abs(&D, 4)->off] == 'c', "B.5 eviction");
  /* every cut of B.2's encoder stream: complete instructions only, the rest waits */
  qp_dec_init(&D, 220);
  hex(b, &n, "3fbd01c00f7777772e6578616d706c652e636f6dc10c2f73616d706c652f70617468");
  for (size_t cut = 0; cut <= n; cut++) {
    qp_dec_init(&D, 220);
    int r1 = qp_dec_encoder(&D, b, cut);
    int r2 = r1 >= 0 ? qp_dec_encoder(&D, b + r1, n - (size_t)r1) : -1;
    CHECK(r1 >= 0 && r2 >= 0 && (size_t)(r1 + r2) == n && D.size == 106, "B.2 cut at %zu", cut);
  }
  /* an entry larger than the capacity is an encoder-stream error (§3.2.2) */
  qp_dec_init(&D, 4096);
  hex(b, &n,
      "3f21"
      "4a637573746f6d2d6b6579"
      "40"
      "414141414141414141414141414141414141414141414141414141414141414141414141");
  b[13] = 36; /* value length 36: 10 + 36 + 32 = 78 > 64 */
  CHECK(qp_dec_encoder(&D, b, n) == QP_E_ENCODER, "entry larger than the capacity");
  printf("rfc9204 B.1-B.5: %s\n", fails == before ? "ok" : "FAILED");
}

/* ---------------------------------------- differential ---------------------------------------- */
static const char *NAMES[] = { ":method",       ":path",   ":authority", ":scheme",      "user-agent",
                               "accept",        "cookie",  "x-trace",    "content-type", "accept-encoding",
                               "authorization", "x-Upper", "custom-key", "te",           "x-long-custom-header-name" };
typedef struct {
  char n[48], v[300];
  size_t nl, vl;
  uint8_t flags;
} tf;
static int rand_list(tf *t, int max, int seq) {
  static const char al[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./:;=,?&%\" ";
  int k = 1 + (int)(rnd() % (unsigned)max);
  for (int i = 0; i < k; i++) {
    const char *nm = NAMES[rnd() % (sizeof NAMES / sizeof NAMES[0])];
    t[i].nl = strlen(nm), memcpy(t[i].n, nm, t[i].nl);
    if (rnd() % 2) { /* values that repeat across requests: the encoder will index them */
      int len = snprintf(t[i].v, sizeof t[i].v, "value-%d", (int)(rnd() % 12));
      t[i].vl = (size_t)len;
    } else {
      t[i].vl = rnd() % 4 == 0 ? rnd() % 250 : rnd() % 20;
      for (size_t j = 0; j < t[i].vl; j++)
        t[i].v[j] = rnd() % 60 == 0 ? (char)(rnd() & 0xff) : al[rnd() % (sizeof al - 1)];
    }
    t[i].flags = rnd() % 12 == 0 ? NGHTTP3_NV_FLAG_NEVER_INDEX : 0;
    (void)seq;
  }
  return k;
}

typedef struct {
  uint8_t n[512], v[4096];
  size_t nl, vl;
} rf;
static rf RF[256];
static int n3_section(nghttp3_qpack_decoder *dec, int64_t sid, const uint8_t *in, size_t len) {
  const nghttp3_mem *mem = nghttp3_mem_default();
  nghttp3_qpack_stream_context *sc;
  nghttp3_qpack_stream_context_new(&sc, sid, mem);
  int k = 0, ok = -1;
  for (;;) {
    nghttp3_qpack_nv nv;
    uint8_t fl = 0;
    nghttp3_ssize r = nghttp3_qpack_decoder_read_request(dec, sc, &nv, &fl, in, len, 1);
    if (r < 0) break;
    in += r, len -= (size_t)r;
    if (fl & NGHTTP3_QPACK_DECODE_FLAG_EMIT) {
      nghttp3_vec nn = nghttp3_rcbuf_get_buf(nv.name), vv = nghttp3_rcbuf_get_buf(nv.value);
      if (k < 256 && nn.len <= sizeof RF[0].n && vv.len <= sizeof RF[0].v)
        memcpy(RF[k].n, nn.base, nn.len), memcpy(RF[k].v, vv.base, vv.len), RF[k].nl = nn.len, RF[k].vl = vv.len;
      k++;
      nghttp3_rcbuf_decref(nv.name), nghttp3_rcbuf_decref(nv.value);
    }
    if (fl & NGHTTP3_QPACK_DECODE_FLAG_FINAL) {
      ok = k;
      break;
    }
    if (fl & NGHTTP3_QPACK_DECODE_FLAG_BLOCKED) break;
    if (!len && !(fl & NGHTTP3_QPACK_DECODE_FLAG_EMIT)) break;
  }
  nghttp3_qpack_stream_context_del(sc);
  return ok;
}
static void cmp(int n, int k, const char *what) {
  int ok = n == k;
  for (int i = 0; ok && i < n; i++)
    ok = F[i].nlen == RF[i].nl && !memcmp(F[i].name, RF[i].n, RF[i].nl) && F[i].vlen == RF[i].vl &&
         !memcmp(F[i].value, RF[i].v, RF[i].vl);
  CHECK(ok, "%s: %d vs %d fields", what, n, k);
  for (int i = 0; i < n; i++) { /* cached verdicts == fresh checks */
    uint8_t nc = F[i].nlen && F[i].name[0] == ':' ? (hv_check_name(F[i].name, F[i].nlen) ? HP_N_PSEUDO : HP_N_BAD)
                 : F[i].nlen                      ? (uint8_t)hv_check_nonempty_name(F[i].name, F[i].nlen)
                                                  : HP_N_BAD;
    CHECK(F[i].nclass == nc && F[i].vok == (uint8_t)hv_check_value_rfc9113(F[i].value, F[i].vlen) &&
              F[i].sidx == hp_name_index(F[i].name, F[i].nlen),
          "%s: verdict %d", what, i);
  }
}

static void test_live(void) {
  long before = fails, sections = 0, dyn_sections = 0, mutants = 0, rejected = 0;
  const nghttp3_mem *mem = nghttp3_mem_default();
  static uint8_t estream[1 << 20];
  for (long c = 0; c < 300 * scale(); c++) {
    uint32_t cap = rnd() % 3 == 0 ? (uint32_t)(64 + rnd() % 1000) : 4096;
    nghttp3_qpack_encoder *enc;
    nghttp3_qpack_decoder *ref;
    nghttp3_qpack_encoder_new(&enc, cap, mem);
    nghttp3_qpack_encoder_set_max_dtable_capacity(enc, cap);
    nghttp3_qpack_encoder_set_max_blocked_streams(enc, 0);
    nghttp3_qpack_decoder_new(&ref, cap, 0, mem);
    qp_dec_init(&D, cap);
    size_t elen = 0, eoff = 0; /* our encoder-stream buffer: unconsumed tail kept */
    for (int r = 0; r < 60; r++) {
      tf t[24];
      nghttp3_nv nv[24];
      int k = rand_list(t, 20, r);
      for (int i = 0; i < k; i++)
        nv[i] = (nghttp3_nv){ (uint8_t *)t[i].n, (uint8_t *)t[i].v, t[i].nl, t[i].vl, t[i].flags };
      nghttp3_buf pb, rb, eb;
      nghttp3_buf_init(&pb), nghttp3_buf_init(&rb), nghttp3_buf_init(&eb);
      int64_t sid = 4 * (int64_t)(c * 100 + r);
      if (nghttp3_qpack_encoder_encode(enc, &pb, &rb, &eb, sid, nv, (size_t)k)) {
        printf("encode failed\n");
        exit(1);
      }
      /* encoder stream: both decoders read it; ours in random cuts */
      size_t el = (size_t)(eb.last - eb.pos);
      CHECK(nghttp3_qpack_decoder_read_encoder(ref, eb.pos, el) == (nghttp3_ssize)el, "nghttp3 read_encoder");
      if (el) memcpy(estream + elen, eb.pos, el), elen += el;
      while (eoff < elen) {
        size_t lim = rnd() % 2 ? elen - eoff : 1 + rnd() % (elen - eoff);
        int used = qp_dec_encoder(&D, estream + eoff, lim);
        CHECK(used >= 0, "our encoder-stream error %d", used);
        if (used < 0) goto next_conn;
        eoff += (size_t)used;
        if (!used && lim == elen - eoff) break;
      }
      CHECK(eoff == elen, "encoder stream fully consumed at a section boundary");
      /* the field section: prefix + representations */
      static uint8_t sec[1 << 16];
      size_t pl = (size_t)(pb.last - pb.pos), rl = (size_t)(rb.last - rb.pos);
      if (pl) memcpy(sec, pb.pos, pl);
      if (rl) memcpy(sec + pl, rb.pos, rl);
      int fl, n = qp_decode_section(&D, (uint64_t)sid, sec, pl + rl, F, 256, ARENA, sizeof ARENA, 1 << 20, &fl);
      int kk = n3_section(ref, sid, sec, pl + rl);
      cmp(n, kk, "section");
      sections++, dyn_sections += sec[0] != 0;
      /* our decoder-stream bytes go back to nghttp3's encoder */
      uint8_t fbk[256];
      size_t fn;
      while ((fn = qp_dec_feedback(&D, fbk, sizeof fbk)) > 0) {
        nghttp3_ssize rr = nghttp3_qpack_encoder_read_decoder(enc, fbk, fn);
        CHECK(
            rr == (nghttp3_ssize)fn,
            "nghttp3 rejected our decoder stream: %d (%s) on %zu bytes %02x %02x, sid %lld r=%d ric-byte %02x inserted %llu",
            (int)rr, nghttp3_strerror((int)rr), fn, fbk[0], fn > 1 ? fbk[1] : 0, (long long)sid, r, sec[0],
            (unsigned long long)D.inserted);
        if (rr != (nghttp3_ssize)fn) goto next_conn;
      }
      /* a mutant of the section, decoded against the same table states (sections do not change the
       * table, so both decoders stay in step) */
      if (rnd() % 16 == 0 && pl + rl) { /* real feedback is already delivered; the mutant's ack is dropped below */
        size_t ml = pl + rl;
        switch (rnd() % 3) {
          case 0: sec[rnd() % ml] ^= (uint8_t)(1 << (rnd() % 8)); break;
          case 1: ml = rnd() % ml; break;
          case 2: sec[rnd() % ml] = (uint8_t)rnd(); break;
        }
        n = qp_decode_section(&D, (uint64_t)sid + 1, sec, ml, F, 256, ARENA, sizeof ARENA, 1 << 20, &fl);
        kk = n3_section(ref, sid + 1, sec, ml);
        if (n < 0 || kk < 0) { /* a decompression error is fatal for the connection in both */
          CHECK((n < 0) == (kk < 0), "mutant: ours %d nghttp3 %d", n, kk);
          rejected++, mutants++;
          nghttp3_buf_free(&pb, mem), nghttp3_buf_free(&rb, mem), nghttp3_buf_free(&eb, mem);
          goto next_conn;
        } else cmp(n, kk, "mutant");
        mutants++;
        while (qp_dec_feedback(&D, fbk, sizeof fbk) > 0) {} /* drop the ack for the mutant's stream */
      }
      nghttp3_buf_free(&pb, mem), nghttp3_buf_free(&rb, mem), nghttp3_buf_free(&eb, mem);
    }
  next_conn:
    nghttp3_qpack_encoder_del(enc);
    nghttp3_qpack_decoder_del(ref);
  }
  printf("live vs nghttp3: %ld sections (%ld using the dynamic table), %ld mutants (%ld rejected by both): %s\n",
         sections, dyn_sections, mutants, rejected, fails == before ? "ok" : "FAILED");
}

static void test_encoder(void) {
  long before = fails;
  const nghttp3_mem *mem = nghttp3_mem_default();
  nghttp3_qpack_decoder *ref;
  nghttp3_qpack_decoder_new(&ref, 0, 0, mem);
  static uint8_t blk[1 << 16];
  for (long it = 0; it < 3000 * scale(); it++) {
    tf t[24];
    int k = rand_list(t, 12, 0);
    uint8_t *p = blk + qp_enc_prefix(blk);
    int st = (int)(rnd() % 2 ? (unsigned[]){ 200, 204, 304, 404, 500, 503, 103 }[rnd() % 7] : 100 + rnd() % 500);
    p += qp_enc_status(p, st);
    for (int i = 0; i < k; i++) {
      if (t[i].n[0] == ':') t[i].n[0] = 'x';
      p += qp_enc_field(p, (uint8_t *)t[i].n, t[i].nl, (uint8_t *)t[i].v, t[i].vl, t[i].flags != 0);
    }
    int n = n3_section(ref, 4 * it, blk, (size_t)(p - blk));
    char sv[4];
    snprintf(sv, sizeof sv, "%d", st);
    int ok = n == k + 1 && RF[0].nl == 7 && !memcmp(RF[0].n, ":status", 7) && RF[0].vl == 3 && !memcmp(RF[0].v, sv, 3);
    for (int i = 0; ok && i < k; i++)
      ok = RF[i + 1].nl == t[i].nl && !memcmp(RF[i + 1].n, t[i].n, t[i].nl) && RF[i + 1].vl == t[i].vl &&
           !memcmp(RF[i + 1].v, t[i].v, t[i].vl);
    CHECK(ok, "encode %ld: %d fields", it, n);
  }
  nghttp3_qpack_decoder_del(ref);
  printf("encoder vs nghttp3 decoder: %s\n", fails == before ? "ok" : "FAILED");
}

/* qp_enc (the client's indexing encoder) against nghttp3's decoder: request-like streams of sections from a pool of
 * fields, the peer's table capacity and blocked-streams limit random per connection. The encoder stream and the
 * decoder's feedback both arrive late (a few sections behind), some sections are cancelled before they arrive, and
 * a section is decoded only once the inserts it needs have arrived: the sections waiting so must never exceed the
 * peer's blocked-streams limit. Every decoded section must equal its fields. */
typedef struct {
  int64_t sid;
  uint8_t *p;
  size_t n;
  uint32_t ric;
  int k;
  tf t[16];
} qsec;
static void test_enc_table(void) {
  long before = fails, sections = 0, dyn = 0, bytes = 0, raw = 0, cancelled = 0, waited = 0;
  const nghttp3_mem *mem = nghttp3_mem_default();
  static qp_enc E;
  static const char *names[] = { "user-agent", "accept",        "accept-language", "cookie",   "referer",
                                 "x-trace-id", "authorization", ":authority",      "priority", "x-big" };
  for (long c = 0; c < 150 * scale(); c++) {
    uint32_t cap = rnd() % 3 ? 4096 : (uint32_t)(rnd() % 4097), blocked = (uint32_t[]){ 0, 1, 4, 100 }[rnd() % 4];
    nghttp3_qpack_decoder *dec;
    nghttp3_qpack_decoder_new(&dec, cap, blocked, mem);
    qp_enc_init(&E);
    int settings_at = (int)(rnd() % 3); /* sections before the peer's SETTINGS: static only */
    tf pool[30];
    for (int i = 0; i < 30; i++) {
      const char *n = names[rnd() % (sizeof names / sizeof names[0])];
      pool[i].nl = strlen(n), memcpy(pool[i].n, n, pool[i].nl);
      pool[i].vl = !strcmp(n, "x-big") ? 200 + rnd() % 90 : rnd() % 4 ? 1 + rnd() % 100 : rnd() % 25;
      for (size_t q = 0; q < pool[i].vl; q++) pool[i].v[q] = (char)(' ' + 1 + rnd() % 94);
      pool[i].flags = rnd() % 12 == 0;
    }
    static qsec wait[64];
    int nwait = 0;
    static uint8_t es[1 << 16], fb[1 << 14];
    size_t esn = 0, fbn = 0;
    for (int r = 0; r < 80 && fails == before; r++) {
      if (r == settings_at) qp_enc_settings(&E, cap, blocked);
      qsec *q = &wait[nwait];
      q->sid = 4 * r, q->k = 1 + (int)(rnd() % 12);
      static uint8_t blk[1 << 15];
      qp_esec st;
      qp_enc_begin(&E, &st, (uint64_t)q->sid);
      uint8_t *p = blk + 8;
      for (int i = 0; i < q->k; i++) {
        q->t[i] = pool[rnd() % 30];
        if (rnd() % 8 == 0)
          for (size_t z = 0; z < q->t[i].vl; z++) q->t[i].v[z] = (char)(' ' + 1 + rnd() % 94);
        size_t w = qp_enc_ifield(&E, &st, p, (uint8_t *)q->t[i].n, q->t[i].nl, (uint8_t *)q->t[i].v, q->t[i].vl,
                                 q->t[i].flags);
        CHECK(w <= qp_enc_bound(q->t[i].nl, q->t[i].vl), "field longer than qp_enc_bound");
        raw += (long)(q->t[i].nl + q->t[i].vl), p += w;
      }
      q->n = qp_enc_end(&E, &st, blk + 8, p, blk), q->ric = st.ric;
      q->p = malloc(q->n), memcpy(q->p, blk, q->n), nwait++;
      bytes += (long)q->n, sections++, dyn += q->ric != 0;
      esn += qp_enc_take(&E, es + esn, sizeof es - esn);
      CHECK(!qp_enc_pending(&E), "encoder stream drained");
      /* the network: maybe deliver the encoder stream, maybe the feedback; then every section that can be decoded */
      if (rnd() % 3 == 0 || nwait > 40) {
        nghttp3_ssize u = nghttp3_qpack_decoder_read_encoder(dec, es, esn);
        CHECK(u == (nghttp3_ssize)esn, "nghttp3 rejected our encoder stream: %d (%s)", (int)u,
              nghttp3_strerror((int)u));
        esn = 0;
      }
      if (rnd() % 4 == 0 && nwait > 1) { /* the peer gives up on a section before reading it */
        int i = (int)(rnd() % (unsigned)nwait);
        nghttp3_qpack_decoder_cancel_stream(dec, wait[i].sid);
        free(wait[i].p), wait[i] = wait[--nwait], cancelled++;
      }
      uint64_t icnt = nghttp3_qpack_decoder_get_icnt(dec);
      int blockedn = 0;
      for (int i = 0; i < nwait; i++) blockedn += wait[i].ric > icnt;
      CHECK((uint32_t)blockedn <= blocked, "conn %ld: %d sections wait for inserts, the peer allows %u", c, blockedn,
            blocked);
      waited += blockedn;
      for (int i = 0; i < nwait;) {
        if (wait[i].ric > icnt) {
          i++;
          continue;
        }
        int kk = n3_section(dec, wait[i].sid, wait[i].p, wait[i].n);
        int ok = kk == wait[i].k;
        for (int f = 0; ok && f < kk; f++)
          ok = RF[f].nl == wait[i].t[f].nl && !memcmp(RF[f].n, wait[i].t[f].n, RF[f].nl) &&
               RF[f].vl == wait[i].t[f].vl && !memcmp(RF[f].v, wait[i].t[f].v, RF[f].vl);
        CHECK(ok, "conn %ld section %lld: nghttp3 decoded %d of %d fields", c, (long long)wait[i].sid, kk, wait[i].k);
        free(wait[i].p), wait[i] = wait[--nwait];
      }
      nghttp3_buf db;
      db.begin = db.pos = db.last = fb + fbn, db.end = fb + sizeof fb;
      if (nghttp3_qpack_decoder_get_decoder_streamlen2(dec) <= sizeof fb - fbn) {
        nghttp3_qpack_decoder_write_decoder(dec, &db);
        fbn += (size_t)(db.last - db.pos);
      }
      if (rnd() % 2 && fbn) {
        int u = qp_enc_feedback(&E, fb, fbn);
        CHECK(u == (int)fbn, "our encoder rejected nghttp3's decoder stream (%d of %zu bytes)", u, fbn);
        fbn = 0;
      }
    }
    for (int i = 0; i < nwait; i++) free(wait[i].p);
    nghttp3_qpack_decoder_del(dec);
  }
  printf("indexing encoder vs nghttp3 decoder: %s (%ld sections, %ld with dynamic references, %ld cancelled, %ld "
         "waits for inserts; %.1f%% of the field bytes)\n",
         fails == before ? "ok" : "FAILED", sections, dyn, cancelled, waited, 100.0 * (double)bytes / (double)raw);
}

int main(void) {
  test_rfc();
  test_live();
  test_encoder();
  test_enc_table();
  printf("%s: %ld failures / %ld checks\n", fails ? "FAILED" : "PASS", fails, checks);
  return fails != 0;
}
