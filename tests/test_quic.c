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
#define CHECK(c, ...) do { checks++; if (!(c)) { if (fails++ < 20) { printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } } while (0)
static uint64_t rs = 0x6a09e667f3bcc909ull;
static uint64_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }
static size_t hex(uint8_t *o, const char *h) { size_t n = 0; for (; *h; h += 2) sscanf(h, "%2hhx", &o[n++]); return n; }

/* protect a packet with header h (pn at pn_off, pnl bytes) the way quic_send does */
static size_t protect(quic_key *k, uint8_t *out, const uint8_t *h, size_t hl, size_t pn_off, uint64_t pn, const uint8_t *pl, size_t pll) {
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
  quic_key crx = {0}, ctx_ = {0}, srx = {0}, stx = {0};
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
  quic_key crx2 = {0}, ctx2 = {0};
  CHECK(!quic__initial_keys(&ctx2, &crx2, dcid, 8, &ptls_openssl_aes128gcmsha256), "client-side keys");
  quic__mask(&crx2, pkt + (shl - 2) + 4, mask);
  CHECK((uint8_t)(pkt[0] ^ (mask[0] & 0x0f)) == 0xc1, "A.3 unmask");
  /* A.5: ChaCha20-Poly1305 short header, pn 654360564 (3-byte encoding) */
  uint8_t secret[32];
  hex(secret, rfc9001_a5_secret);
  quic_key cc = {0};
  CHECK(!quic__key_setup(&cc, &ptls_openssl_chacha20poly1305sha256, 1, secret) && cc.chacha, "A.5 keys");
  uint8_t h5[4] = {0x42, 0x00, 0xbf, 0xf4};
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
    CHECK(!quic__vi(&p, e, &back) && back == v && p == e && (size_t)(e - b) == quic__vi_len(v), "varint %llu", (unsigned long long)v);
  }
  /* packet number decoding: RFC 9000 A.3's example, and random round trips */
  CHECK(quic__decode_pn(0xa82f30ea, 0x9b32, 16) == 0xa82f9b32, "RFC 9000 A.3 example");
  for (int i = 0; i < 100000; i++) {
    uint64_t largest = rnd() % (1ull << 40), pn = largest + 1 + rnd() % 30000;
    int bits = 16;
    if (pn - largest >= (1u << 15)) continue;
    CHECK(quic__decode_pn(largest, pn & 0xffff, bits) == pn, "pn %llu largest %llu", (unsigned long long)pn, (unsigned long long)largest);
  }
  /* reassembly: random permutation of chunks, duplicates and overlaps */
  quic_ctx x = {0};
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
    quic_sbuf b = {0};
    size_t total = 1000 + rnd() % 100000;
    uint8_t *w = quic__sb_reserve(&x, &b, total);
    memcpy(w, src, total), b.len = total, b.sent = total, b.fin = 1, b.fin_sent = 1;
    size_t chunk = 1 + rnd() % 2000, nck = (total + chunk - 1) / chunk;
    size_t *order = malloc(nck * sizeof *order);
    for (size_t i = 0; i < nck; i++) order[i] = i;
    for (size_t i = nck - 1; i > 0; i--) { size_t j = rnd() % (i + 1), tmp = order[i]; order[i] = order[j], order[j] = tmp; }
    for (size_t i = 0; i < nck; i++) {
      uint64_t off = order[i] * chunk, len = off + chunk > total ? total - off : chunk;
      if (rnd() % 4 == 0) quic__sb_lost(&x, &b, off, len, off + len == total);
      quic__sb_ack(&x, &b, off, len, off + len == total);
    }
    CHECK(b.len == 0 && b.base == total && b.fin_acked && b.lost.n == 0 && b.acked.n == 0, "send buffer %d: len %zu base %llu lost %d", t, b.len,
          (unsigned long long)b.base, b.lost.n);
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

int main(void) {
  test_rfc9001();
  test_blocks();
  printf("%s: %ld failures / %ld checks\n", fails ? "FAILED" : "PASS", fails, checks);
  return fails != 0;
}
