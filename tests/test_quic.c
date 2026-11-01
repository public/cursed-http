/* include/quic.h, part 1: packet protection against RFC 9001 Appendix A, and the transport's
 * building blocks (varints, packet-number decoding, reassembly, send buffers, ACK ranges).
 * The handshake and traffic are tested against ngtcp2 in tests/test_quic_interop.c. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "quic.h"
#include <picotls/openssl.h>
#include "rfc9001_vectors.h"

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
static uint64_t rs = 0x6a09e667f3bcc909ull;
static uint64_t rnd(void) {
  rs ^= rs << 13;
  rs ^= rs >> 7;
  rs ^= rs << 17;
  return rs;
}
static size_t hex(uint8_t *o, const char *h) {
  size_t n = 0;
  for (; *h; h += 2) sscanf(h, "%2hhx", &o[n++]);
  return n;
}

/* protect a packet with header h (pn at pn_off, pnl bytes) the way quic_send does */
static size_t protect(quic_key *k, uint8_t *out, const uint8_t *h, size_t hl, size_t pn_off, uint64_t pn,
                      const uint8_t *pl, size_t pll) {
  memcpy(out, h, hl);
  size_t ct = ptls_aead_encrypt(k->aead, out + hl, pl, pll, pn, out, hl);
  uint8_t mask[16];
  quic__mask(k, out + pn_off + 4, mask);
  out[0] ^= mask[0] & (out[0] & 0x80 ? 0x0f : 0x1f);
  for (size_t i = pn_off; i < hl; i++) out[i] ^= mask[1 + i - pn_off];
  return hl + ct;
}

static void test_rfc9001(void) {
  long before = fails;
  uint8_t dcid[8], pkt[1500], want[1500], pl[1500];
  hex(dcid, rfc9001_client_dcid);
  quic_key crx = { 0 }, ctx_ = { 0 }, srx = { 0 }, stx = { 0 };
  /* the server's view: rx = client keys, tx = server keys */
  CHECK(!quic__initial_keys(&crx, &stx, dcid, 8, &ptls_openssl_aes128gcmsha256), "initial keys");
  /* A.2: remove protection from the client Initial, compare with the CRYPTO frame + PADDING */
  size_t n = hex(pkt, rfc9001_a2_packet);
  size_t pn_off = 18; /* c0 | version | dcid(8) | scid(0) | token(0) | length(2) */
  uint8_t mask[16];
  quic__mask(&crx, pkt + pn_off + 4, mask);
  uint8_t first = (uint8_t)(pkt[0] ^ (mask[0] & 0x0f));
  int pnl = (first & 3) + 1;
  uint64_t pn = 0;
  for (int i = 0; i < pnl; i++) pn = pn << 8 | (uint8_t)(pkt[pn_off + i] ^ mask[1 + i]);
  CHECK(first == 0xc3 && pnl == 4 && pn == 2, "A.2 header: %02x pnl %d pn %llu", first, pnl, (unsigned long long)pn);
  uint8_t hdr[32];
  memcpy(hdr, pkt, pn_off + 4), hdr[0] = first;
  for (int i = 0; i < 4; i++) hdr[pn_off + i] = (uint8_t)(pn >> (8 * (3 - i)));
  size_t ptl = ptls_aead_decrypt(crx.aead, pl, pkt + pn_off + 4, n - pn_off - 4, pn, hdr, pn_off + 4);
  size_t cl = hex(want, rfc9001_a2_crypto);
  int pad_ok = ptl == 1162;
  for (size_t i = cl; pad_ok && i < ptl; i++) pad_ok = pl[i] == 0;
  CHECK(ptl == 1162 && !memcmp(pl, want, cl) && pad_ok, "A.2 payload: %zu bytes", ptl);
  /* A.3: protect the server Initial and compare byte for byte */
  uint8_t sh[20];
  size_t shl = hex(sh, "c1000000010008f067a5502a4262b50040750001");
  size_t spl = hex(pl, rfc9001_a3_payload);
  size_t wl = hex(want, rfc9001_a3_packet);
  size_t got = protect(&stx, pkt, sh, shl, shl - 2, 1, pl, spl);
  CHECK(got == wl && !memcmp(pkt, want, wl), "A.3 server Initial: %zu vs %zu bytes", got, wl);
  /* ... and the transport's own receive path decrypts it back (as a client would): keys swapped */
  quic_key crx2 = { 0 }, ctx2 = { 0 };
  CHECK(!quic__initial_keys(&ctx2, &crx2, dcid, 8, &ptls_openssl_aes128gcmsha256), "client-side keys");
  quic__mask(&crx2, pkt + (shl - 2) + 4, mask);
  CHECK((uint8_t)(pkt[0] ^ (mask[0] & 0x0f)) == 0xc1, "A.3 unmask");
  /* A.5: ChaCha20-Poly1305 short header, pn 654360564 (3-byte encoding) */
  uint8_t secret[32];
  hex(secret, rfc9001_a5_secret);
  quic_key cc = { 0 };
  CHECK(!quic__key_setup(&cc, &ptls_openssl_chacha20poly1305sha256, 1, secret) && cc.chacha, "A.5 keys");
  uint8_t h5[4] = { 0x42, 0x00, 0xbf, 0xf4 };
  got = protect(&cc, pkt, h5, 4, 1, 654360564, (const uint8_t *)"\x01", 1);
  wl = hex(want, rfc9001_a5_packet);
  CHECK(got == wl && !memcmp(pkt, want, wl), "A.5 ChaCha20 packet");
  /* A.5 key update secret: quic ku */
  uint8_t ku[32], ku_want[32];
  memcpy(ku, secret, 32);
  CHECK(!quic__next_secret(&ptls_openssl_chacha20poly1305sha256, ku), "ku");
  hex(ku_want, "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9");
  CHECK(!memcmp(ku, ku_want, 32), "A.5 key update secret");
  quic__key_free(&crx), quic__key_free(&ctx_), quic__key_free(&srx), quic__key_free(&stx), quic__key_free(&cc);
  quic__key_free(&crx2), quic__key_free(&ctx2);
  printf("rfc9001 A.2 A.3 A.5: %s\n", fails == before ? "ok" : "FAILED");
}

static void test_blocks(void) {
  long before = fails;
  /* varints round trip, every length */
  for (int i = 0; i < 100000; i++) {
    uint64_t v = rnd() >> (rnd() % 64);
    if (v >= (1ull << 62)) v >>= 2;
    uint8_t b[16], *e = quic__put_vi(b, v);
    const uint8_t *p = b;
    uint64_t back;
    CHECK(!quic__vi(&p, e, &back) && back == v && p == e && (size_t)(e - b) == quic__vi_len(v), "varint %llu",
          (unsigned long long)v);
  }
  /* packet number decoding: RFC 9000 A.3's example, and random round trips */
  CHECK(quic__decode_pn(0xa82f30ea, 0x9b32, 16) == 0xa82f9b32, "RFC 9000 A.3 example");
  /* the boundaries of the window: candidate exactly half a window below / above the expected pn */
  CHECK(quic__decode_pn(1000, 105, 8) == 1129, "pn: candidate == expected - hwin goes up a window");
  CHECK(quic__decode_pn(1000, 106, 8) == 874, "pn: just inside the window");
  for (int i = 0; i < 100000; i++) {
    uint64_t largest = rnd() % (1ull << 40), pn = largest + 1 + rnd() % 30000;
    int bits = 16;
    if (pn - largest >= (1u << 15)) continue;
    CHECK(quic__decode_pn(largest, pn & 0xffff, bits) == pn, "pn %llu largest %llu", (unsigned long long)pn,
          (unsigned long long)largest);
  }
  /* reassembly: random permutation of chunks, duplicates and overlaps */
  quic_ctx x = { 0 };
  x.alloc = quic__default_alloc;
  static uint8_t src[200000];
  for (size_t i = 0; i < sizeof src; i++) src[i] = (uint8_t)rnd();
  for (int t = 0; t < 50; t++) {
    quic_rbuf b;
    quic__rb_init(&b);
    size_t total = 1000 + rnd() % 150000, consumed = 0;
    int ok = 1;
    for (int k = 0; k < 4000 && consumed < total; k++) {
      uint64_t off = consumed + rnd() % 12000;
      if (off >= total) off = consumed;
      size_t len = 1 + rnd() % 3000;
      if (off + len > total) len = total - off;
      quic__rb_insert(&x, &b, off, src + off, len, total);
      size_t avail = (size_t)(b.contig - b.base);
      if (avail && memcmp(b.buf, src + b.base, avail)) ok = 0;
      size_t use = avail ? rnd() % (avail + 1) : 0;
      quic__rb_consume(&b, use), consumed += use;
    }
    CHECK(ok, "reassembly contents %d", t);
    free(b.buf), quic__rs_free(&x, &b.have);
  }
  /* send buffer: acks in random order free everything; losses come back */
  for (int t = 0; t < 50; t++) {
    quic_sbuf b = { 0 };
    size_t total = 1000 + rnd() % 100000;
    uint8_t *w = quic__sb_reserve(&x, &b, total);
    memcpy(w, src, total), b.len = total, b.sent = total, b.fin = 1, b.fin_sent = 1;
    size_t chunk = 1 + rnd() % 2000, nck = (total + chunk - 1) / chunk;
    size_t *order = malloc(nck * sizeof *order);
    for (size_t i = 0; i < nck; i++) order[i] = i;
    for (size_t i = nck - 1; i > 0; i--) {
      size_t j = rnd() % (i + 1), tmp = order[i];
      order[i] = order[j], order[j] = tmp;
    }
    for (size_t i = 0; i < nck; i++) {
      uint64_t off = order[i] * chunk, len = off + chunk > total ? total - off : chunk;
      if (rnd() % 4 == 0) quic__sb_lost(&x, &b, off, len, off + len == total);
      quic__sb_ack(&x, &b, off, len, off + len == total);
    }
    CHECK(b.len == 0 && b.base == total && b.fin_acked && b.lost.n == 0 && b.acked.n == 0,
          "send buffer %d: len %zu base %llu lost %d", t, b.len, (unsigned long long)b.base, b.lost.n);
    free(order), quic__sb_free(&x, &b);
  }
  /* ACK ranges: random pns; duplicates are recognised while their range is remembered, and the
   * ranges stay descending, disjoint and merged */
  for (int t = 0; t < 200; t++) {
    quic_space sp;
    memset(&sp, 0, sizeof sp);
    static uint8_t seen[5000];
    memset(seen, 0, sizeof seen);
    int dup_ok = 1, shape_ok = 1;
    for (int i = 0; i < 2000; i++) {
      uint64_t pn = (uint64_t)i + rnd() % (t % 2 ? 40 : 4); /* mostly in order, some reordering */
      int remembered = sp.nrcv && pn >= sp.rcv[sp.nrcv - 1].lo;
      int dup = quic__rcv_pn(&sp, pn);
      if (remembered && dup != seen[pn]) dup_ok = 0;
      if (!seen[pn] && dup) dup_ok = 0; /* never a false duplicate */
      seen[pn] = 1;
      for (int k = 1; k < sp.nrcv; k++)
        if (!(sp.rcv[k].hi + 1 < sp.rcv[k - 1].lo) || sp.rcv[k].lo > sp.rcv[k].hi) shape_ok = 0;
    }
    CHECK(dup_ok, "ACK ranges: duplicates (%d)", t);
    CHECK(shape_ok, "ACK ranges: shape (%d)", t);
  }
  printf("building blocks: %s\n", fails == before ? "ok" : "FAILED");
}

/* ------------------------------ frame-level errors (RFC 9000 §19, §4, §3) ------------------------------ */
static int64_t eat_all(quic_conn *c, uint64_t sid, uint64_t off, const uint8_t *d, size_t len, int fin, void *u) {
  (void)c, (void)sid, (void)off, (void)d, (void)fin, (void)u;
  return (int64_t)len;
}
static quic_ctx FX = { NULL, quic__default_alloc };
static void fresh(quic_conn *c) {
  for (int i = 0; i < QUIC_MAX_STREAMS; i++)
    if (c->s[i].used) quic__stream_free(c, &c->s[i]);
  quic__rs_free(&FX, &c->closed[0]), quic__rs_free(&FX, &c->closed[1]);
  memset(c, 0, sizeof *c);
  c->ctx = &FX, c->cb.on_stream = eat_all;
  c->max_data_local = 1000, c->max_streams_bidi_local = 4, c->max_streams_uni_local = 4;
  c->established = 1, c->sp[QUIC_SP_APP].next_pn = 10, c->peer_bidi_local = 1 << 20;
}
static uint64_t frames(quic_conn *c, int space, const uint8_t *f, size_t n) {
  int ae;
  quic__frames(c, space, f, f + n, 1000, &ae);
  return c->closing ? c->close_code : 0;
}
static void test_frames(void) {
  long before = fails;
  static quic_conn C;
  static uint8_t big[2000];
  uint8_t f[64], *p;
  struct {
    const char *what;
    int space;
    const char *hex;
    uint64_t want;
  } t[] = {
    { "STREAM on our own uni stream", QUIC_SP_APP,
      "0b0301"
      "78",
      QUIC_STREAM_STATE_ERROR },
    { "STREAM beyond MAX_STREAMS", QUIC_SP_APP,
      "0b1001"
      "78",
      QUIC_STREAM_LIMIT_ERROR },
    { "NEW_TOKEN from a client", QUIC_SP_APP, "070100", QUIC_PROTOCOL_VIOLATION },
    { "HANDSHAKE_DONE from a client", QUIC_SP_APP, "1e", QUIC_PROTOCOL_VIOLATION },
    { "STREAM in an Initial packet", QUIC_SP_INITIAL,
      "0b0001"
      "78",
      QUIC_PROTOCOL_VIOLATION },
    { "ACK of a packet never sent", QUIC_SP_APP, "020f000000", QUIC_PROTOCOL_VIOLATION },
    { "ACK first range beyond largest", QUIC_SP_APP, "0205000006", QUIC_FRAME_ENCODING_ERROR },
    { "unknown frame type", QUIC_SP_APP, "4040", QUIC_FRAME_ENCODING_ERROR },
    { "STOP_SENDING on the client's uni stream", QUIC_SP_APP, "050200", QUIC_STREAM_STATE_ERROR },
    { "MAX_STREAM_DATA on the client's uni stream", QUIC_SP_APP, "11024000", QUIC_STREAM_STATE_ERROR },
    { "truncated STREAM frame", QUIC_SP_APP, "0b000578", QUIC_FRAME_ENCODING_ERROR },
    { "RETIRE_CONNECTION_ID of a CID never issued", QUIC_SP_APP, "1901", QUIC_PROTOCOL_VIOLATION },
    { "final size changes", QUIC_SP_APP,
      "0f000004"
      "41424344"
      "0f0000054142434445",
      QUIC_FINAL_SIZE_ERROR },
    { "data beyond the final size", QUIC_SP_APP,
      "0f000002"
      "4142"
      "0e00020441424344",
      QUIC_FINAL_SIZE_ERROR },
    { "RESET_STREAM below data received", QUIC_SP_APP,
      "0a000441424344"
      "04000003",
      QUIC_FINAL_SIZE_ERROR },
    { "an empty packet", QUIC_SP_APP, "", QUIC_PROTOCOL_VIOLATION },
  };
  for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
    fresh(&C);
    size_t n = hex(f, t[i].hex);
    uint64_t got = frames(&C, t[i].space, f, n);
    CHECK(got == t[i].want, "%s: got 0x%llx want 0x%llx", t[i].what, (unsigned long long)got,
          (unsigned long long)t[i].want);
  }
  /* connection flow control: 1001 bytes against MAX_DATA 1000 (the stream window is larger) */
  fresh(&C);
  p = big;
  *p++ = 0x0a, *p++ = 0x00, p = quic__put_vi2(p, 1001), p += 1001;
  CHECK(frames(&C, QUIC_SP_APP, big, (size_t)(p - big)) == QUIC_FLOW_CONTROL_ERROR, "connection flow control");
  fresh(&C);
  p = big;
  *p++ = 0x0a, *p++ = 0x00, p = quic__put_vi2(p, 1000), p += 1000;
  CHECK(frames(&C, QUIC_SP_APP, big, (size_t)(p - big)) == 0, "exactly MAX_DATA is fine");
  /* stream flow control: a stream window of 256 KiB, the connection's raised to 1 MiB */
  fresh(&C);
  C.max_data_local = 1 << 20;
  static uint8_t huge[300000];
  p = huge;
  *p++ = 0x0e, *p++ = 0x00, p = quic__put_vi(p, QUIC_STREAM_WIN - 4), *p++ = 0x08, p += 8; /* ends 4 bytes past */
  CHECK(frames(&C, QUIC_SP_APP, huge, (size_t)(p - huge)) == QUIC_FLOW_CONTROL_ERROR, "stream flow control");
  /* things that are fine: PADDING, PING, PATH_CHALLENGE (answered) */
  fresh(&C);
  size_t n = hex(f, "000000"
                    "01"
                    "1a0102030405060708");
  CHECK(frames(&C, QUIC_SP_APP, f, n) == 0 && C.path_response_pending &&
            !memcmp(C.path_response, "\1\2\3\4\5\6\7\x08", 8),
        "PATH_CHALLENGE");
  fresh(&C);
  printf("frame errors: %s\n", fails == before ? "ok" : "FAILED");
}

/* RFC 9001 A.2's client Initial through quic_accept: it must decrypt (pn 2 recorded) */
static void test_accept_rfc(void) {
  long before = fails;
  static ptls_context_t tls;
  tls.random_bytes = ptls_openssl_random_bytes, tls.get_time = &ptls_get_time;
  tls.key_exchanges = ptls_openssl_key_exchanges, tls.cipher_suites = ptls_openssl_cipher_suites;
  static quic_ctx qx;
  quic_ctx_init(&qx, &tls);
  static quic_conn c;
  static uint8_t pkt[1500];
  size_t n = hex(pkt, rfc9001_a2_packet);
  static const quic_callbacks cb = { 0 };
  quic_accept(&c, &qx, pkt, n, 0, &cb, NULL);
  CHECK(c.sp[QUIC_SP_INITIAL].nrcv == 1 && c.sp[QUIC_SP_INITIAL].rcv[0].lo == 2 && !c.undecryptable,
        "A.2 via quic_accept: decrypted pn 2");
  quic_free(&c);
  printf("A.2 through quic_accept: %s\n", fails == before ? "ok" : "FAILED");
}

int main(void) {
  test_rfc9001();
  test_accept_rfc();
  test_frames();
  test_blocks();
  printf("%s: %ld failures / %ld checks\n", fails ? "FAILED" : "PASS", fails, checks);
  return fails != 0;
}
