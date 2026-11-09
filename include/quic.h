/* quic.h: a QUIC v1 transport (RFC 9000, 9001, 9002), server and client, sans-IO and header-only.
 *
 * Datagrams in (quic_recv), datagrams out (quic_send), one timer (quic_timeout / quic_on_timeout).
 * The TLS 1.3 handshake is picotls's (MIT, linked: third_party/picotls lib/picotls.c + lib/openssl.c,
 * with OpenSSL libcrypto); everything else is here: packets and coalescing, packet protection
 * (AEAD through picotls, header protection through qhp.h's AES-NI / ARMv8 AES / ChaCha20 kernels),
 * CRYPTO and STREAM reassembly, flow control, ACKs, loss detection and CUBIC congestion control
 * (RFC 9002 Appendix A/B), transport parameters, peer-initiated key updates, connection close.
 *
 * Memory: the connection struct is the caller's; stream buffers come from ctx->alloc (realloc-like,
 * default realloc) and grow only up to the flow-control windows we advertise. picotls allocates
 * its own handshake state.
 *
 * Scope: QUIC v1 (other versions get Version Negotiation); Retry, 0-RTT and resumption (quic_ctx_resumption),
 * NEW_TOKEN, stateless resets, the peer's connection IDs (NEW_CONNECTION_ID, retire_prior_to) but one of ours,
 * pacing, path MTU discovery; no migration (PATH_CHALLENGE is answered on the current path), no ECN.
 * Any application protocol: quic_ctx.alpn (default "h3"), streams opened by either side, limits and windows in
 * quic_ctx (examples/quic_echo.c: raw QUIC; include/h3.h: HTTP/3 on top).
 *
 *   quic_ctx_init(&ctx, tls_ctx)                      tls_ctx: a ptls_context_t (a server's with certificates,
 *                                                     a client's with its certificate verifier)
 *   quic_accept(&c, &ctx, dgram, len, now_ms, &cb, user)   server: from a client Initial; 0 or QUIC_E_*
 *   quic_connect(&c, &ctx, server_name, now_ms, &cb, user) client: the ClientHello is queued (ctx's ALPN);
 *                                                     quic_send the first datagram, then as above
 *   quic_open_bidi(&c)                                a new stream (or -1 at the peer's limit); quic_alpn(&c)
 *   quic_recv(&c, dgram, len, now_ms)                 every later datagram for this connection
 *   n = quic_send(&c, out, cap, now_ms)               one datagram to send, 0 when idle (or paced: then
 *                                                     quic_timeout says when to call it again)
 *   quic_timeout(&c) / quic_on_timeout(&c, now_ms)    the next deadline and its handler
 *   quic_open_uni(&c) / quic_reset_stream / quic_close / quic_is_closed / quic_free
 * The application sees streams through callbacks: on_stream (contiguous bytes from the first
 * unconsumed offset; returns how many it consumed, the rest is offered again with more),
 * stream_send (pull: fill up to cap bytes of new data for a stream, set fin), on_stream_reset.
 */
#ifndef QUIC_H
#define QUIC_H
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <picotls.h>
#include "hfield.h"
#include "qhp.h"

#ifndef QUIC_MAX_STREAMS
#define QUIC_MAX_STREAMS 128 /* stream slots: client bidi + uni + our uni */
#endif
#define QUIC_MAX_BIDI      100          /* initial_max_streams_bidi we advertise */
#define QUIC_MAX_UNI       8            /* initial_max_streams_uni */
#define QUIC_STREAM_WIN    (256u << 10) /* initial_max_stream_data_bidi_remote / _uni */
#define QUIC_CONN_WIN      (4u << 20)   /* initial_max_data */
#define QUIC_PEER_CIDS     4            /* active_connection_id_limit we advertise */
#define QUIC_MAX_UDP       1472         /* max_udp_payload_size we accept, and the most we probe the path for */
#define QUIC_SEND_MAX      1252         /* datagrams before path MTU discovery finds more room */
#define QUIC_MIN_INITIAL   1200
#define QUIC_SCID_LEN      8
#define QUIC_IDLE_MS       30000
#define QUIC_MAX_ACK_DELAY 25
#define QUIC_ACK_RANGES    32
#define QUIC_SENT_MAX      1024 /* packets in flight per space */
#define QUIC_FREC_MAX      10   /* frames remembered per sent packet */
#define QUIC_V1            0x00000001u

enum { QUIC_E_DROP = -1, QUIC_E_CLOSED = -2, QUIC_E_NOMEM = -3, QUIC_E_VN = -4 /* send Version Negotiation */ };
enum { QUIC_SP_INITIAL, QUIC_SP_HANDSHAKE, QUIC_SP_APP, QUIC_NSP };
/* transport error codes (RFC 9000 §20.1) */
enum {
  QUIC_NO_ERROR,
  QUIC_INTERNAL_ERROR,
  QUIC_CONNECTION_REFUSED,
  QUIC_FLOW_CONTROL_ERROR,
  QUIC_STREAM_LIMIT_ERROR,
  QUIC_STREAM_STATE_ERROR,
  QUIC_FINAL_SIZE_ERROR,
  QUIC_FRAME_ENCODING_ERROR,
  QUIC_TRANSPORT_PARAMETER_ERROR,
  QUIC_CONNECTION_ID_LIMIT_ERROR,
  QUIC_PROTOCOL_VIOLATION,
  QUIC_INVALID_TOKEN,
  QUIC_APPLICATION_ERROR,
  QUIC_CRYPTO_BUFFER_EXCEEDED,
  QUIC_KEY_UPDATE_ERROR,
  QUIC_AEAD_LIMIT_REACHED,
  QUIC_NO_VIABLE_PATH
};

typedef struct quic_conn quic_conn;
typedef struct {
  /* contiguous received bytes of stream sid starting at stream offset `off` (the first byte not yet
   * consumed); fin = the stream ends at off + len. Return the bytes consumed (0..len), or < 0 to
   * close the connection with the application error code -ret. */
  int64_t (*on_stream)(quic_conn *c, uint64_t sid, uint64_t off, const uint8_t *d, size_t len, int fin, void *user);
  /* fill up to cap bytes of new data for sid; set *fin when the stream ends after them */
  size_t (*stream_send)(quic_conn *c, uint64_t sid, uint8_t *out, size_t cap, int *fin, void *user);
  /* nonzero if sid has data to give stream_send */
  int (*stream_wants)(quic_conn *c, uint64_t sid, void *user);
  void (*on_stream_reset)(quic_conn *c, uint64_t sid, uint64_t code, void *user); /* RESET_STREAM or STOP_SENDING */
  void (*on_established)(quic_conn *c, void *user); /* handshake complete (a client may send 1-RTT data now) */
  /* optional: a stream's priority, urgency (0..7) << 1 | incremental (RFC 9218), for the order of its data */
  int (*stream_priority)(quic_conn *c, uint64_t sid, void *user);
} quic_callbacks;

/* what a client keeps to resume (quic_connect_resume): a session ticket (for 0-RTT if early), a NEW_TOKEN token
 * (address validation, no Retry), and the server's transport parameters (the limits 0-RTT may use). Filled by a
 * connection whose resume_out points at it */
#ifndef QUIC_TICKET_MAX
#define QUIC_TICKET_MAX 2048
#endif
typedef struct {
  uint8_t ticket[QUIC_TICKET_MAX], token[64];
  uint16_t ticket_len, token_len;
  uint8_t early; /* the ticket allows early data */
  uint64_t max_data, bidi_local, bidi_remote, uni, max_streams_bidi, max_streams_uni;
} quic_resume;

typedef struct {
  ptls_encrypt_ticket_t super;
  uint8_t key[16];
} quic__ticket_enc;
typedef struct {
  ptls_context_t *tls;
  void *(*alloc)(void *p, size_t n); /* realloc-like; n == 0 frees */
  quic__ticket_enc tickets;          /* a server's session tickets (quic_ctx_resumption) */
  /* the application protocol and what we let the peer do (set after quic_ctx_init; 0 / NULL: the defaults,
   * HTTP/3's): ALPN, offered by a client in this order, chosen by a server by its own; the peer's streams
   * (max_streams_bidi: a server 100, a client 0, as HTTP/3 servers open none; max_streams_uni 8), and our receive
   * windows per stream and per connection (256 KiB, 4 MiB) */
  const char *const *alpn;
  size_t nalpn;
  uint64_t max_streams_bidi, max_streams_uni, stream_window, conn_window;
  uint8_t token_key[16]; /* a server's Retry tokens (random per quic_ctx_init) */
  uint8_t reset_key[32]; /* a server's stateless reset tokens: HMAC of the connection ID */
} quic_ctx;

/* --------------------------------------------- varints --------------------------------------------- */
static inline size_t quic__vi_len(uint64_t v) { return v < 64 ? 1 : v < 16384 ? 2 : v < (1u << 30) ? 4 : 8; }
static inline uint8_t *quic__put_vi(uint8_t *p, uint64_t v) {
  size_t n = quic__vi_len(v);
  for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(v >> (8 * (n - 1 - i)));
  p[0] |= (uint8_t)((n == 1 ? 0 : n == 2 ? 1 : n == 4 ? 2 : 3) << 6);
  return p + n;
}
/* a 2-byte varint: v < 16384 */
static inline uint8_t *quic__put_vi2(uint8_t *p, uint64_t v) {
  p[0] = (uint8_t)(0x40 | v >> 8), p[1] = (uint8_t)v;
  return p + 2;
}
/* decode at *pp; -1 if truncated */
static inline int quic__vi(const uint8_t **pp, const uint8_t *end, uint64_t *v) {
  const uint8_t *q = qv_get_safe(v, *pp, end);
  if (!q) return -1;
  *pp = q;
  return 0;
}

/* ---------------------------------------------- keys ---------------------------------------------- */
typedef struct {
  ptls_aead_context_t *aead;
  int chacha; /* header protection: 0 AES (qhp_aes_key), 1 ChaCha20 */
  qhp_aes_key hp;
  uint8_t hp_cc[32];
} quic_key;

static const uint8_t quic_initial_salt[20] = { 0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
                                               0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a };

static inline void quic__key_free(quic_key *k) {
  if (k->aead) ptls_aead_free(k->aead);
  memset(k, 0, sizeof *k);
}
/* key, iv and hp from a traffic secret (RFC 9001 §5.1) */
static inline int quic__key_setup(quic_key *k, ptls_cipher_suite_t *cs, int is_enc, const uint8_t *secret) {
  uint8_t key[PTLS_MAX_SECRET_SIZE], iv[PTLS_MAX_IV_SIZE], hp[PTLS_MAX_SECRET_SIZE];
  ptls_iovec_t sec = ptls_iovec_init(secret, cs->hash->digest_size), none = ptls_iovec_init(NULL, 0);
  size_t kl = cs->aead->key_size;
  if (ptls_hkdf_expand_label(cs->hash, key, kl, sec, "quic key", none, NULL) ||
      ptls_hkdf_expand_label(cs->hash, iv, cs->aead->iv_size, sec, "quic iv", none, NULL) ||
      ptls_hkdf_expand_label(cs->hash, hp, kl, sec, "quic hp", none, NULL))
    return -1;
  quic__key_free(k);
  if (!(k->aead = ptls_aead_new_direct(cs->aead, is_enc, key, iv))) return -1;
  k->chacha = kl == 32 && !strcmp(cs->aead->name, "CHACHA20-POLY1305");
  if (k->chacha) memcpy(k->hp_cc, hp, 32);
  else qhp_aes_init(&k->hp, hp, (int)kl);
  ptls_clear_memory(key, sizeof key), ptls_clear_memory(hp, sizeof hp);
  return 0;
}
/* a key update replaces the AEAD key and IV only: the header protection key stays (RFC 9001 §6) */
static inline int quic__key_update(quic_key *k, const quic_key *hp_from, ptls_cipher_suite_t *cs, int is_enc,
                                   const uint8_t *secret) {
  uint8_t key[PTLS_MAX_SECRET_SIZE], iv[PTLS_MAX_IV_SIZE];
  ptls_iovec_t sec = ptls_iovec_init(secret, cs->hash->digest_size), none = ptls_iovec_init(NULL, 0);
  if (ptls_hkdf_expand_label(cs->hash, key, cs->aead->key_size, sec, "quic key", none, NULL) ||
      ptls_hkdf_expand_label(cs->hash, iv, cs->aead->iv_size, sec, "quic iv", none, NULL))
    return -1;
  ptls_aead_context_t *a = ptls_aead_new_direct(cs->aead, is_enc, key, iv);
  ptls_clear_memory(key, sizeof key);
  if (!a) return -1;
  quic_key nk = *hp_from; /* header protection as before */
  nk.aead = a;
  if (k->aead) ptls_aead_free(k->aead); /* k's previous AEAD (k may be hp_from itself) */
  *k = nk;
  return 0;
}
static inline void quic__mask(const quic_key *k, const uint8_t *sample, uint8_t mask[16]) {
  const uint8_t *s[1] = { sample };
  if (k->chacha) qhp_chacha_masks(k->hp_cc, s, mask, 1);
  else qhp_aes_masks(&k->hp, s, mask, 1);
}
/* Initial keys from the client's Destination Connection ID (RFC 9001 §5.2) */
static inline int quic__initial_keys_role(quic_key *rx, quic_key *tx, const uint8_t *dcid, size_t len,
                                          ptls_cipher_suite_t *aes128, int client) {
  uint8_t isec[32], csec[32], ssec[32];
  ptls_hash_algorithm_t *h = aes128->hash;
  ptls_iovec_t none = ptls_iovec_init(NULL, 0);
  if (ptls_hkdf_extract(h, isec, ptls_iovec_init(quic_initial_salt, 20), ptls_iovec_init(dcid, len)) ||
      ptls_hkdf_expand_label(h, csec, 32, ptls_iovec_init(isec, 32), "client in", none, NULL) ||
      ptls_hkdf_expand_label(h, ssec, 32, ptls_iovec_init(isec, 32), "server in", none, NULL))
    return -1;
  if (client) /* a client reads the server's Initial packets and writes its own */
    return quic__key_setup(rx, aes128, 0, ssec) || quic__key_setup(tx, aes128, 1, csec) ? -1 : 0;
  return quic__key_setup(rx, aes128, 0, csec) || quic__key_setup(tx, aes128, 1, ssec) ? -1 : 0;
}

static inline int quic__initial_keys(quic_key *rx, quic_key *tx, const uint8_t *dcid, size_t len,
                                     ptls_cipher_suite_t *aes128) {
  return quic__initial_keys_role(rx, tx, dcid, len, aes128, 0);
}

/* ------------------------------------------ range sets ------------------------------------------ */
/* sorted, disjoint, non-adjacent [lo, hi) ranges in memory from the context's allocator */
typedef struct {
  uint64_t lo, hi;
} quic_range;
typedef struct {
  quic_range *r;
  int n, cap;
} quic_rset;
static inline int quic__rs_add(quic_ctx *x, quic_rset *s, uint64_t lo, uint64_t hi) {
  if (lo >= hi) return 0;
  int i = 0;
  while (i < s->n && s->r[i].hi < lo) i++; /* first range that may touch [lo, hi) */
  int j = i;
  while (j < s->n && s->r[j].lo <= hi) { /* merge every range touching it */
    if (s->r[j].lo < lo) lo = s->r[j].lo;
    if (s->r[j].hi > hi) hi = s->r[j].hi;
    j++;
  }
  if (j > i) { /* replace ranges i..j-1 with one */
    s->r[i].lo = lo, s->r[i].hi = hi;
    memmove(&s->r[i + 1], &s->r[j], (size_t)(s->n - j) * sizeof *s->r);
    s->n -= j - i - 1;
    return 0;
  }
  if (s->n == s->cap) {
    int nc = s->cap ? 2 * s->cap : 8;
    quic_range *nr = x->alloc(s->r, (size_t)nc * sizeof *nr);
    if (!nr) return -1;
    s->r = nr, s->cap = nc;
  }
  memmove(&s->r[i + 1], &s->r[i], (size_t)(s->n - i) * sizeof *s->r);
  s->r[i].lo = lo, s->r[i].hi = hi, s->n++;
  return 0;
}
/* remove everything below v */
static inline void quic__rs_trim(quic_rset *s, uint64_t v) {
  int k = 0;
  while (k < s->n && s->r[k].hi <= v) k++;
  if (k) memmove(s->r, s->r + k, (size_t)(s->n - k) * sizeof *s->r), s->n -= k;
  if (s->n && s->r[0].lo < v) s->r[0].lo = v;
}
static inline void quic__rs_free(quic_ctx *x, quic_rset *s) {
  if (s->r) x->alloc(s->r, 0);
  memset(s, 0, sizeof *s);
}
static inline int quic__rs_covers(const quic_rset *s, uint64_t lo, uint64_t hi) {
  for (int i = 0; i < s->n; i++)
    if (s->r[i].lo <= lo && s->r[i].hi >= hi) return 1;
  return 0;
}

/* ------------------------------------- stream byte buffers ------------------------------------- */
/* receive: bytes from `base` (first unconsumed offset); `have` marks ranges received beyond the
 * contiguous prefix [base, contig) */
typedef struct {
  uint8_t *buf;
  size_t cap;
  uint64_t base, contig, fin; /* fin = final size, or UINT64_MAX */
  quic_rset have;             /* ranges received beyond contig */
} quic_rbuf;
static inline void quic__rb_init(quic_rbuf *b) { memset(b, 0, sizeof *b), b->fin = UINT64_MAX; }
static inline uint64_t quic__rb_top(const quic_rbuf *b) { return b->have.n ? b->have.r[b->have.n - 1].hi : b->contig; }
static inline int quic__rb_insert(quic_ctx *x, quic_rbuf *b, uint64_t off, const uint8_t *d, size_t len,
                                  uint64_t limit) {
  uint64_t end = off + len;
  if (end > limit) return -QUIC_FLOW_CONTROL_ERROR;
  if (b->fin != UINT64_MAX && end > b->fin) return -QUIC_FINAL_SIZE_ERROR;
  if (end <= b->contig || !len) return 0;
  if (off < b->contig) d += b->contig - off, len -= (size_t)(b->contig - off), off = b->contig;
  size_t need = (size_t)(end - b->base);
  if (need > b->cap) {
    size_t nc = b->cap ? b->cap : 4096;
    while (nc < need) nc *= 2;
    uint8_t *nb = x->alloc(b->buf, nc);
    if (!nb) return -QUIC_INTERNAL_ERROR;
    b->buf = nb, b->cap = nc;
  }
  memcpy(b->buf + (off - b->base), d, len);
  if (off > b->contig) return quic__rs_add(x, &b->have, off, end) ? -QUIC_INTERNAL_ERROR : 0;
  b->contig = end; /* off == contig: extend, then absorb the ranges it now reaches */
  while (b->have.n && b->have.r[0].lo <= b->contig) {
    if (b->have.r[0].hi > b->contig) b->contig = b->have.r[0].hi;
    memmove(b->have.r, b->have.r + 1, (size_t)(--b->have.n) * sizeof *b->have.r);
  }
  return 0;
}
static inline int quic__rb_set_fin(quic_rbuf *b, uint64_t fin) {
  if (b->fin != UINT64_MAX && b->fin != fin) return -QUIC_FINAL_SIZE_ERROR;
  if (fin < quic__rb_top(b)) return -QUIC_FINAL_SIZE_ERROR;
  b->fin = fin;
  return 0;
}
static inline void quic__rb_consume(quic_rbuf *b, size_t n) {
  if (!n) return;
  memmove(b->buf, b->buf + n, (size_t)(quic__rb_top(b) - b->base) - n);
  b->base += n;
}

/* send: bytes [base, base + len) held until acked; [base, sent) went out once; lost ranges wait for
 * a resend; acked ranges above base are remembered so base can advance */
typedef struct {
  uint8_t *buf;
  size_t cap, len;
  uint64_t base, sent;
  quic_rset acked, lost;
  uint8_t fin, fin_sent, fin_acked, fin_lost;
} quic_sbuf;
static inline uint8_t *quic__sb_reserve(quic_ctx *x, quic_sbuf *b, size_t n) {
  if (b->len + n > b->cap) {
    size_t nc = b->cap ? b->cap : 4096;
    while (nc < b->len + n) nc *= 2;
    uint8_t *nb = x->alloc(b->buf, nc);
    if (!nb) return NULL;
    b->buf = nb, b->cap = nc;
  }
  return b->buf + b->len;
}
static inline void quic__sb_ack(quic_ctx *x, quic_sbuf *b, uint64_t off, uint64_t len, int fin) {
  if (fin) b->fin_acked = 1, b->fin_lost = 0;
  if (!len || off + len <= b->base) return;
  if (off < b->base) len -= b->base - off, off = b->base;
  quic__rs_add(x, &b->acked, off, off + len);
  if (b->acked.n && b->acked.r[0].lo <= b->base) { /* advance base over the acked prefix */
    uint64_t hi = b->acked.r[0].hi;
    size_t n = (size_t)(hi - b->base);
    memmove(b->buf, b->buf + n, b->len - n), b->len -= n, b->base = hi;
    quic__rs_trim(&b->acked, hi);
  }
  quic__rs_trim(&b->lost, b->base);
}
static inline void quic__sb_lost(quic_ctx *x, quic_sbuf *b, uint64_t off, uint64_t len, int fin) {
  if (fin && !b->fin_acked) b->fin_lost = 1;
  if (!len || off + len <= b->base) return;
  if (off < b->base) len -= b->base - off, off = b->base;
  if (quic__rs_covers(&b->acked, off, off + len)) return; /* acked since */
  quic__rs_add(x, &b->lost, off, off + len);
}
static inline void quic__sb_free(quic_ctx *x, quic_sbuf *b) {
  if (b->buf) x->alloc(b->buf, 0);
  quic__rs_free(x, &b->acked), quic__rs_free(x, &b->lost);
}

/* --------------------------------------------- streams --------------------------------------------- */
typedef struct {
  uint64_t id;
  uint8_t used, recv_done, send_done, reset_sent, stop_sent, recv_reset;
  uint64_t reset_code, stop_code;
  quic_rbuf in;
  quic_sbuf out;
  uint64_t max_recv; /* MAX_STREAM_DATA we granted */
  uint64_t max_send; /* MAX_STREAM_DATA the peer granted */
  uint8_t send_max_stream_data, send_reset, send_stop;
} quic_stream;

/* ------------------------------------------ packet spaces ------------------------------------------ */
enum {
  QF_STREAM = 1,
  QF_CRYPTO,
  QF_MAX_DATA,
  QF_MAX_STREAM_DATA,
  QF_MAX_STREAMS_BIDI,
  QF_MAX_STREAMS_UNI,
  QF_HANDSHAKE_DONE,
  QF_RESET,
  QF_STOP,
  QF_PING,
  QF_ACK,
  QF_RETIRE_CID,
  QF_NEW_TOKEN,
  QF_PMTU /* a path MTU probe (a: its size) */
};
typedef struct {
  uint8_t type, fin;
  uint64_t a, b, c;
} quic_frec; /* STREAM: a sid, b offset, c length */
typedef struct {
  uint64_t pn;
  int64_t sent_at;
  uint16_t size;
  uint8_t ack_eliciting, in_flight, nf, acked, lost;
  int64_t lost_at;      /* kept after being declared lost, so a late ACK reveals a spurious loss */
  uint64_t largest_ack; /* largest pn this packet acknowledged (for trimming our ACK ranges) */
  quic_frec f[QUIC_FREC_MAX];
} quic_sent;

typedef struct {
  quic_key rx, tx;
  uint8_t have_rx, have_tx, discarded;
  uint64_t next_pn;
  struct {
    uint64_t lo, hi;
  } rcv[QUIC_ACK_RANGES]; /* received pns, descending, for ACK frames */
  int nrcv;
  int64_t largest_rcv_at;
  int ack_eliciting_unacked; /* ack-eliciting packets received since our last ACK */
  int64_t ack_deadline;
  uint64_t largest_acked;
  uint8_t any_acked;
  int64_t loss_time, last_ack_eliciting_at;
  quic_rbuf crypto_in;
  quic_sbuf crypto_out;
  quic_sent *sent; /* ring, oldest at head */
  uint32_t shead, nsent;
} quic_space;

struct quic_conn {
  quic_ctx *ctx;
  quic_callbacks cb;
  void *user;
  ptls_t *tls;
  ptls_handshake_properties_t props;
  ptls_buffer_t tpbuf;
  ptls_raw_extension_t tpext[2];
  uint8_t dcid[20], scid[QUIC_SCID_LEN], odcid[20], dcid_len, odcid_len;
  uint8_t idcid[20], idcid_len;          /* a server's: the DCID of the client's Initials (odcid, or after a Retry its
                                           * Source Connection ID) */
  uint8_t retried, rscid[20], rscid_len; /* a Retry happened: the server's Retry Source Connection ID */
  uint8_t *token;                        /* a client's: the Retry token its Initials carry */
  uint32_t vn_version;                   /* a client's: after Version Negotiation, the server's first version */
  /* the peer's connection IDs (RFC 9000 §5.1): seq 0 is its first; the one in use is in dcid. Each may come with a
   * stateless reset token. retire_prior: the peer's retire_prior_to; retire_q: RETIRE_CONNECTION_IDs to send */
  struct {
    uint64_t seq;
    uint8_t len, cid[20], token[16], has_token;
  } pcid[QUIC_PEER_CIDS];
  int npcid;
  uint64_t pcid_seq, retire_prior, retire_q[8]; /* pcid_seq: the one in use */
  int nretire;
  uint8_t got_packet;                 /* a packet of the current datagram decrypted (else: a stateless reset?) */
  uint8_t tp_token[16], has_tp_token; /* the server's stateless_reset_token transport parameter */
  uint8_t reset;                      /* closed by the peer's stateless reset */
  /* 0-RTT (RFC 9001 §4.6): a client's early keys and whether it sent with them; a server's early read keys. A
   * client's resume_out receives what a later connection resumes with */
  quic_key zrtt;
  uint8_t have_zrtt, zrtt_sent, early_open;
  uint32_t zrtt_recv; /* a server's: 0-RTT packets read */
  quic_resume *resume_out;
  uint8_t new_token[64], new_token_len, send_new_token; /* a server's NEW_TOKEN for the client */
  size_t early_max;                                     /* picotls: early data allowed (client) */
  uint16_t token_len;
  quic_space sp[QUIC_NSP];
  ptls_cipher_suite_t *cs; /* negotiated suite (for key updates) */
  uint8_t app_secret_rx[PTLS_MAX_DIGEST_SIZE], app_secret_tx[PTLS_MAX_DIGEST_SIZE];
  quic_key next_rx; /* the next key phase's read key, ready for a peer key update */
  quic_key prev_rx; /* the previous phase's read key, for late packets (RFC 9001 §6.5) */
  uint8_t key_phase, have_next_rx, have_prev_rx;
  uint64_t phase_first_pn; /* first packet number seen in the current key phase */
  int64_t prev_rx_until;
  /* state */
  uint8_t established, confirmed, handshake_done_pending, addr_validated, peer_tp_ok;
  uint8_t client, got_server_cid; /* quic_connect; a client adopts the server's SCID from its first Initial */
  uint8_t closing, draining, close_sent_once, close_app;
  uint64_t close_code, close_frame;
  int64_t idle_deadline, close_deadline;
  /* flow control */
  uint64_t max_data_local, data_recv, data_consumed, max_data_peer, data_sent;
  uint8_t send_max_data, send_max_streams_bidi, send_max_streams_uni;
  uint64_t max_streams_bidi_local, max_streams_uni_local, opened_bidi, opened_uni;
  quic_rset closed[2]; /* indices of finished client streams (bidi, uni): opening stream N
                                 * implicitly opens all lower ones, which may still arrive later */
  uint64_t peer_max_streams_uni, peer_init_stream_data_uni, peer_bidi_local, peer_max_ack_delay, peer_ack_delay_exp;
  uint64_t next_uni_id, next_bidi_id;
  uint64_t stream_win, conn_win;                    /* our receive windows (quic_ctx) */
  ptls_iovec_t alpn_iov[8];                         /* a client's ALPN offer */
  uint64_t peer_bidi_remote, peer_max_streams_bidi; /* a client: limits on the bidi streams it opens */
  /* path */
  uint8_t path_response[8], path_response_pending;
  /* recovery (RFC 9002) */
  int64_t latest_rtt, smoothed_rtt, rttvar, min_rtt;
  uint8_t rtt_sampled;
  uint32_t pto_count, probes_due;
  uint64_t bytes_in_flight, cwnd, ssthresh;
  /* CUBIC (RFC 9438) */
  double cubic_wmax, cubic_k, cubic_west; /* in bytes, seconds, bytes */
  int64_t cubic_epoch;                    /* start of the current congestion-avoidance epoch, or 0 */
  /* spurious-loss handling: adaptive reordering thresholds and undo of a congestion event that
   * turned out to be reordering */
  uint32_t pkt_thresh, time_thresh_8; /* packet threshold; time threshold in eighths of an RTT */
  uint64_t undo_cwnd, undo_ssthresh;
  double undo_wmax, undo_k;
  uint32_t episode_lost, episode_spurious;
  uint64_t spurious_losses, cc_undos;
  /* pacing (RFC 9002 §7.7): a token bucket refilled at 1.25 cwnd / srtt, its bytes and last refill */
  double pace_tokens;
  int64_t pace_at;
  int64_t recovery_start;
  uint64_t bytes_recv, bytes_sent; /* before address validation: 3x limit */
  int64_t last_send_at;            /* a client's anti-deadlock probe before the handshake is confirmed */
  uint8_t pace_blocked;            /* quic_send last held data back for pacing */
  /* path MTU discovery (DPLPMTUD, RFC 8899 / RFC 9000 §14.3): the datagram size in use, the peer's
   * max_udp_payload_size, the probe in flight (its size), failures at that size, and when to probe next */
  uint16_t mtu, pmtu_probe, pmtu_fails;
  uint8_t pmtu_done;
  uint64_t peer_max_udp;
  int64_t pmtu_next_at;
  uint64_t undecryptable; /* packets dropped because they failed to decrypt */
  quic_stream s[QUIC_MAX_STREAMS];
  uint32_t rr;
};

/* stream ids: bit 0 is the initiator (0 client, 1 server), bit 1 uni. "ours": we opened it */
#define QUIC__OURS(c, sid) ((((sid) & 1) != 0) != ((c)->client != 0))

static inline void *quic__default_alloc(void *p, size_t n) {
  if (!n) {
    free(p);
    return NULL;
  }
  return realloc(p, n);
}
static inline int quic__update_traffic_key(ptls_update_traffic_key_t *self, ptls_t *tls, int is_enc, size_t epoch,
                                           const void *secret);
static ptls_update_traffic_key_t quic__utk = { quic__update_traffic_key };

static inline void quic_ctx_init(quic_ctx *x, ptls_context_t *tls) {
  x->tls = tls, x->alloc = quic__default_alloc;
  tls->omit_end_of_early_data = 1;
  tls->update_traffic_key = &quic__utk;
  tls->max_early_data_size = 0;
  tls->random_bytes(x->token_key, sizeof x->token_key);
  tls->random_bytes(x->reset_key, sizeof x->reset_key);
}
/* a server's stateless reset token for its connection ID (RFC 9000 §10.3.2): HMAC-SHA256 under the context's key,
 * so a server that lost the connection can still compute it. 0, or -1 */
static inline int quic_reset_token(const quic_ctx *x, const uint8_t *cid, size_t len, uint8_t token[16]) {
  extern ptls_hash_algorithm_t ptls_openssl_sha256;
  uint8_t h[32];
  ptls_hash_context_t *m = ptls_hmac_create(&ptls_openssl_sha256, x->reset_key, sizeof x->reset_key);
  if (!m) return -1;
  m->update(m, cid, len), m->final(m, h, PTLS_HASH_FINAL_MODE_FREE);
  memcpy(token, h, 16), ptls_clear_memory(h, sizeof h);
  return 0;
}
/* a server's answer to a short-header datagram d for a connection it does not have (RFC 9000 §10.3): a stateless
 * reset in out (smaller than d, so two endpoints never loop), or 0 (d too small to answer, or no room) */
static inline size_t quic_stateless_reset(const quic_ctx *x, const uint8_t *d, size_t len, uint8_t *out, size_t cap) {
  if ((d[0] & 0x80) || len < 1 + QUIC_SCID_LEN || len - 1 < 21) return 0;
  size_t n = len - 1 < 43 ? len - 1 : 43; /* 43: what a 1-RTT packet of a few bytes would be */
  if (n > cap) return 0;
  x->tls->random_bytes(out, n - 16);
  out[0] = (uint8_t)(0x40 | (out[0] & 0x3f));
  return quic_reset_token(x, d + 1, QUIC_SCID_LEN, out + n - 16) ? 0 : n;
}

/* session tickets (a server's): AES-128-GCM under the context's key, a random nonce in front */
static inline int quic__ticket_crypt(ptls_encrypt_ticket_t *self, ptls_t *tls, int enc, ptls_buffer_t *dst,
                                     ptls_iovec_t src) {
  extern ptls_aead_algorithm_t ptls_openssl_aes128gcm;
  quic__ticket_enc *t = (quic__ticket_enc *)self;
  uint8_t iv[12];
  int r;
  if (enc) {
    ptls_get_context(tls)->random_bytes(iv, sizeof iv);
    if ((r = ptls_buffer_reserve(dst, 12 + src.len + 16))) return r;
    memcpy(dst->base + dst->off, iv, 12);
  } else {
    if (src.len < 12 + 16) return PTLS_ALERT_DECODE_ERROR;
    if ((r = ptls_buffer_reserve(dst, src.len))) return r;
    memcpy(iv, src.base, 12);
  }
  ptls_aead_context_t *a = ptls_aead_new_direct(&ptls_openssl_aes128gcm, enc, t->key, iv);
  if (!a) return PTLS_ERROR_NO_MEMORY;
  size_t n = enc ? ptls_aead_encrypt(a, dst->base + dst->off + 12, src.base, src.len, 0, NULL, 0)
                 : ptls_aead_decrypt(a, dst->base + dst->off, src.base + 12, src.len - 12, 0, NULL, 0);
  ptls_aead_free(a);
  if (n == SIZE_MAX) return PTLS_ERROR_SESSION_NOT_FOUND; /* not ours (another key: a restart) */
  dst->off += enc ? 12 + n : n;
  return 0;
}
/* a client's: a ticket arrived; with the server's transport parameters, it goes to resume_out */
static inline int quic__save_ticket(ptls_save_ticket_t *self, ptls_t *tls, ptls_iovec_t in,
                                    const ptls_save_ticket_properties_t *pr) {
  (void)self;
  quic_conn *c = *ptls_get_data_ptr(tls);
  quic_resume *r = c->resume_out;
  if (!r || in.len > sizeof r->ticket) return 0;
  memcpy(r->ticket, in.base, in.len), r->ticket_len = (uint16_t)in.len;
  r->early = pr && pr->early_data && pr->max_early_data_size == 0xffffffffu; /* QUIC's value (RFC 9001 §4.6.1) */
  r->max_data = c->max_data_peer, r->bidi_local = c->peer_bidi_local, r->bidi_remote = c->peer_bidi_remote;
  r->uni = c->peer_init_stream_data_uni, r->max_streams_bidi = c->peer_max_streams_bidi;
  r->max_streams_uni = c->peer_max_streams_uni;
  return 0;
}
static ptls_save_ticket_t quic__stc = { quic__save_ticket };
/* resumption (and 0-RTT) on this context: a server issues session tickets (lifetime a day) and takes early data;
 * a client saves tickets to its connections' resume_out. 0-RTT requests can be replayed by an attacker: a server
 * should serve early only what is safe to repeat (RFC 8470); quic_conn.established is 0 while they arrive */
static inline void quic_ctx_resumption(quic_ctx *x) {
  x->tickets.super.cb = quic__ticket_crypt;
  x->tls->random_bytes(x->tickets.key, sizeof x->tickets.key);
  x->tls->encrypt_ticket = &x->tickets.super, x->tls->ticket_lifetime = 86400;
  x->tls->max_early_data_size = 0xffffffffu, x->tls->save_ticket = &quic__stc;
}

/* slots probed from a hash of the id: O(1) on average */
static inline uint32_t quic__slot(uint64_t sid) { return (uint32_t)(((sid >> 2) * 4 + (sid & 3)) % QUIC_MAX_STREAMS); }
static inline quic_stream *quic__stream(quic_conn *c, uint64_t sid) {
  for (uint32_t k = 0, i = quic__slot(sid); k < QUIC_MAX_STREAMS; k++, i = (i + 1) % QUIC_MAX_STREAMS)
    if (c->s[i].used && c->s[i].id == sid) return &c->s[i];
  return NULL;
}
static inline quic_stream *quic__stream_new(quic_conn *c, uint64_t sid) {
  for (uint32_t k = 0, i = quic__slot(sid); k < QUIC_MAX_STREAMS; k++, i = (i + 1) % QUIC_MAX_STREAMS)
    if (!c->s[i].used) {
      quic_stream *s = &c->s[i];
      memset(s, 0, sizeof *s);
      s->used = 1, s->id = sid;
      quic__rb_init(&s->in);
      int uni = (sid & 2) != 0, ours = QUIC__OURS(c, sid);
      s->max_recv = ours && uni ? 0 : c->stream_win;
      /* our sending limit: the peer's initial_max_stream_data for its uni / its own bidi / our bidi */
      s->max_send = uni ? (ours ? c->peer_init_stream_data_uni : 0) : ours ? c->peer_bidi_remote : c->peer_bidi_local;
      return s;
    }
  return NULL;
}
static inline void quic__stream_free(quic_conn *c, quic_stream *s) {
  if (s->in.buf) c->ctx->alloc(s->in.buf, 0);
  quic__rs_free(c->ctx, &s->in.have);
  quic__sb_free(c->ctx, &s->out);
  s->used = 0;
}

/* ------------------------------------------ close / errors ------------------------------------------ */
static inline void quic__error(quic_conn *c, uint64_t code, uint64_t frame) {
  if (c->closing || c->draining) return;
  c->closing = 1, c->close_code = code, c->close_frame = frame, c->close_app = 0;
}
static inline void quic_close(quic_conn *c, uint64_t app_code) {
  if (c->closing || c->draining) return;
  c->closing = 1, c->close_code = app_code, c->close_frame = 0, c->close_app = 1;
}
static inline int quic_is_closed(const quic_conn *c, int64_t now) {
  return (c->closing || c->draining) && c->close_deadline && now >= c->close_deadline;
}

/* ------------------------------------------- RTT and timers ------------------------------------------- */
static inline int64_t quic__pto(const quic_conn *c, int space) {
  int64_t srtt = c->rtt_sampled ? c->smoothed_rtt : 333, var = c->rtt_sampled ? c->rttvar : 333 / 2;
  int64_t pto = srtt + (4 * var > 1 ? 4 * var : 1);
  if (space == QUIC_SP_APP) pto += (int64_t)c->peer_max_ack_delay;
  return pto << (c->pto_count < 16 ? c->pto_count : 16);
}
static inline void quic__rtt_sample(quic_conn *c, int64_t latest, int64_t ack_delay) {
  c->latest_rtt = latest;
  if (!c->rtt_sampled) {
    c->min_rtt = latest, c->smoothed_rtt = latest, c->rttvar = latest / 2, c->rtt_sampled = 1;
    return;
  }
  if (latest < c->min_rtt) c->min_rtt = latest;
  if (c->confirmed && ack_delay > (int64_t)c->peer_max_ack_delay) ack_delay = (int64_t)c->peer_max_ack_delay;
  int64_t adj = latest;
  if (latest >= c->min_rtt + ack_delay) adj = latest - ack_delay;
  int64_t d = c->smoothed_rtt > adj ? c->smoothed_rtt - adj : adj - c->smoothed_rtt;
  c->rttvar = (3 * c->rttvar + d) / 4;
  c->smoothed_rtt = (7 * c->smoothed_rtt + adj) / 8;
}

/* ----------------------------------------- sent packet records ----------------------------------------- */
static inline quic_sent *quic__sent_at(quic_space *sp, uint32_t i) {
  return &sp->sent[(sp->shead + i) % QUIC_SENT_MAX];
}
/* drop records from the head that are acked, or lost long enough ago that an ACK for them would no
 * longer be expected (a late ACK of a lost packet marks a spurious loss) */
static inline void quic__sent_pop_acked(quic_space *sp, int64_t now, int64_t keep) {
  while (sp->nsent) {
    quic_sent *p = quic__sent_at(sp, 0);
    if (!p->acked && !(p->lost && (now - p->lost_at > keep || sp->nsent > QUIC_SENT_MAX - 64))) break;
    sp->shead = (sp->shead + 1) % QUIC_SENT_MAX, sp->nsent--;
  }
}

static inline void quic__frame_acked(quic_conn *c, quic_space *sp, const quic_frec *f) {
  quic_stream *s;
  switch (f->type) {
    case QF_STREAM:
      if ((s = quic__stream(c, f->a))) quic__sb_ack(c->ctx, &s->out, f->b, f->c, f->fin);
      break;
    case QF_CRYPTO: quic__sb_ack(c->ctx, &sp->crypto_out, f->b, f->c, 0); break;
    case QF_PMTU: /* the path carries datagrams this big: use them, and try the next size */
      if (f->a > c->mtu) c->mtu = (uint16_t)f->a;
      if (c->pmtu_probe == f->a) c->pmtu_probe = 0, c->pmtu_fails = 0;
      break;
    case QF_ACK: { /* the peer has our ACK up to f->a: stop repeating ranges below it */
      int w = 0;
      for (int i = 0; i < sp->nrcv; i++)
        if (sp->rcv[i].hi > f->a) sp->rcv[w++] = sp->rcv[i];
      if (w) sp->nrcv = w;
      break;
    }
    default: break;
  }
}
static inline void quic__retire_queue(quic_conn *c, uint64_t seq) {
  for (int i = 0; i < c->nretire; i++)
    if (c->retire_q[i] == seq) return;
  if (c->nretire < 8) c->retire_q[c->nretire++] = seq;
}
/* ------------------------------------- the peer's connection IDs ------------------------------------- */
/* the peer's first connection ID (seq 0), once known: the DCID in use */
static inline void quic__pcid_first(quic_conn *c) {
  c->pcid[0].seq = 0, c->pcid[0].len = c->dcid_len, memcpy(c->pcid[0].cid, c->dcid, c->dcid_len);
  if (!c->npcid) c->npcid = 1;
  c->pcid_seq = 0;
}
/* NEW_CONNECTION_ID (RFC 9000 §19.15): 0, or a transport error code */
static inline uint64_t quic__new_cid(quic_conn *c, uint64_t seq, uint64_t rpt, const uint8_t *cid, uint8_t len,
                                     const uint8_t *token) {
  for (int i = 0; i < c->npcid; i++)
    if (c->pcid[i].seq == seq) /* a repeat: it must be the same */
      return c->pcid[i].len == len && !memcmp(c->pcid[i].cid, cid, len) ? 0 : QUIC_PROTOCOL_VIOLATION;
  if (seq < c->retire_prior) { /* retired already: say so again */
    quic__retire_queue(c, seq);
    return 0;
  }
  if (rpt > c->retire_prior) { /* retire everything below rpt */
    c->retire_prior = rpt;
    for (int i = 0; i < c->npcid;)
      if (c->pcid[i].seq < rpt) quic__retire_queue(c, c->pcid[i].seq), c->pcid[i] = c->pcid[--c->npcid];
      else i++;
  }
  if (c->npcid == QUIC_PEER_CIDS) return QUIC_CONNECTION_ID_LIMIT_ERROR;
  int k = c->npcid++;
  c->pcid[k].seq = seq, c->pcid[k].len = len, memcpy(c->pcid[k].cid, cid, len);
  memcpy(c->pcid[k].token, token, 16), c->pcid[k].has_token = 1;
  if (c->pcid_seq < c->retire_prior) { /* ours was retired: the oldest left takes over */
    int best = 0;
    for (int i = 1; i < c->npcid; i++)
      if (c->pcid[i].seq < c->pcid[best].seq) best = i;
    c->pcid_seq = c->pcid[best].seq, c->dcid_len = c->pcid[best].len;
    memcpy(c->dcid, c->pcid[best].cid, c->dcid_len);
  }
  return 0;
}
/* a datagram that decrypted to nothing: a stateless reset (RFC 9000 §10.3) if it ends with one of the peer's
 * tokens; then the connection is over, at once */
static inline int quic__is_reset(quic_conn *c, const uint8_t *d, size_t len) {
  if (len < 21 || (d[0] & 0x80)) return 0;
  for (int i = 0; i < c->npcid; i++)
    if (c->pcid[i].has_token && ptls_mem_equal(d + len - 16, c->pcid[i].token, 16)) return 1; /* (constant time) */
  return 0;
}

static inline void quic__frame_lost(quic_conn *c, quic_space *sp, const quic_frec *f) {
  quic_stream *s;
  switch (f->type) {
    case QF_STREAM:
      if ((s = quic__stream(c, f->a))) quic__sb_lost(c->ctx, &s->out, f->b, f->c, f->fin);
      break;
    case QF_CRYPTO: quic__sb_lost(c->ctx, &sp->crypto_out, f->b, f->c, 0); break;
    case QF_MAX_DATA: c->send_max_data = 1; break;
    case QF_MAX_STREAM_DATA:
      if ((s = quic__stream(c, f->a))) s->send_max_stream_data = 1;
      break;
    case QF_MAX_STREAMS_BIDI: c->send_max_streams_bidi = 1; break;
    case QF_MAX_STREAMS_UNI: c->send_max_streams_uni = 1; break;
    case QF_HANDSHAKE_DONE: c->handshake_done_pending = 1; break;
    case QF_RETIRE_CID: quic__retire_queue(c, f->a); break;
    case QF_NEW_TOKEN: c->send_new_token = 1; break;
    case QF_PMTU: /* the path did not carry it: three times, and that size is out of reach */
      if (c->pmtu_probe == f->a) c->pmtu_probe = 0, c->pmtu_done |= ++c->pmtu_fails >= 3;
      break;
    case QF_RESET:
      if ((s = quic__stream(c, f->a))) s->send_reset = 1;
      break;
    case QF_STOP:
      if ((s = quic__stream(c, f->a))) s->send_stop = 1;
      break;
    default: break;
  }
}

/* CUBIC (RFC 9438): cwnd in bytes, time in seconds; C = 0.4 segments/s^3, beta = 0.7 */
#define QUIC_CUBIC_C    0.4
#define QUIC_CUBIC_BETA 0.7
static inline double quic__cbrt(double x) { /* Newton's method: no libm needed */
  if (x <= 0) return 0;
  double r = x > 1 ? x / 3 : 1;
  for (int i = 0; i < 40; i++) r = (2 * r + x / (r * r)) / 3;
  return r;
}
static inline void quic__cc_acked(quic_conn *c, const quic_sent *p, int64_t now) {
  if (!p->in_flight) return;
  c->bytes_in_flight -= p->size;
  if (p->sent_at <= c->recovery_start) return; /* in recovery */
  if (c->cwnd < c->ssthresh) {                 /* slow start */
    c->cwnd += p->size;
    return;
  }
  double mss = QUIC_SEND_MAX;
  if (!c->cubic_epoch) { /* first ACK of congestion avoidance (or after slow start) */
    c->cubic_epoch = now;
    if (c->cubic_wmax < (double)c->cwnd) c->cubic_wmax = (double)c->cwnd, c->cubic_k = 0;
    c->cubic_west = (double)c->cwnd;
  }
  double t = (double)(now - c->cubic_epoch + (c->rtt_sampled ? c->smoothed_rtt : 0)) / 1000.0;
  double target = QUIC_CUBIC_C * (t - c->cubic_k) * (t - c->cubic_k) * (t - c->cubic_k) * mss + c->cubic_wmax;
  /* the Reno-friendly estimate (alpha = 3 (1 - beta) / (1 + beta)) */
  c->cubic_west += 3.0 * (1 - QUIC_CUBIC_BETA) / (1 + QUIC_CUBIC_BETA) * mss * p->size / (double)c->cwnd;
  if (target < c->cubic_west) target = c->cubic_west;
  if (target > 1.5 * (double)c->cwnd) target = 1.5 * (double)c->cwnd; /* at most 50% growth per RTT */
  if (target > (double)c->cwnd) c->cwnd += (uint64_t)((target - (double)c->cwnd) * p->size / (double)c->cwnd);
}
static inline void quic__cc_lost(quic_conn *c, const quic_sent *p, int64_t now) {
  if (!p->in_flight) return;
  c->bytes_in_flight -= p->size;
  if (p->nf && p->f[0].type == QF_PMTU) return; /* a probe's loss says nothing about congestion (§14.4) */
  c->episode_lost++;
  if (p->sent_at <= c->recovery_start) return; /* one reduction per episode */
  /* a new congestion event: remember the state for undo, then reduce */
  c->undo_cwnd = c->cwnd, c->undo_ssthresh = c->ssthresh, c->undo_wmax = c->cubic_wmax, c->undo_k = c->cubic_k;
  c->episode_lost = 1, c->episode_spurious = 0;
  c->recovery_start = now;
  double w = (double)c->cwnd;
  c->cubic_wmax = w < c->cubic_wmax ? w * (1 + QUIC_CUBIC_BETA) / 2 : w; /* fast convergence */
  c->cwnd = (uint64_t)(w * QUIC_CUBIC_BETA) > 2 * QUIC_SEND_MAX ? (uint64_t)(w * QUIC_CUBIC_BETA) : 2 * QUIC_SEND_MAX;
  c->ssthresh = c->cwnd;
  c->cubic_k = quic__cbrt(c->cubic_wmax * (1 - QUIC_CUBIC_BETA) / (QUIC_CUBIC_C * QUIC_SEND_MAX));
  c->cubic_epoch = 0;
}
/* a packet we declared lost was acknowledged after all: the network reordered, it did not drop */
static inline void quic__cc_spurious(quic_conn *c, const quic_sent *p, int64_t largest_acked) {
  c->spurious_losses++, c->episode_spurious++;
  /* reorder more before calling loss (RACK-like): packet threshold up to the observed displacement,
   * time threshold up by 1/8 RTT, to 2 RTT at most */
  uint64_t disp = (uint64_t)largest_acked > p->pn ? (uint64_t)largest_acked - p->pn + 1 : 3;
  if (disp > c->pkt_thresh) c->pkt_thresh = disp > 256 ? 256 : (uint32_t)disp;
  if (c->time_thresh_8 < 16) c->time_thresh_8++;
  /* every loss of this congestion event was spurious: undo the reduction */
  if (p->lost_at >= c->recovery_start && c->episode_spurious >= c->episode_lost && c->undo_cwnd) {
    if (c->undo_cwnd > c->cwnd) c->cwnd = c->undo_cwnd;
    c->ssthresh = c->undo_ssthresh, c->cubic_wmax = c->undo_wmax, c->cubic_k = c->undo_k;
    c->recovery_start = INT64_MIN, c->undo_cwnd = 0, c->cubic_epoch = 0, c->cc_undos++;
  }
}

static inline void quic__detect_lost(quic_conn *c, int space, int64_t now) {
  quic_space *sp = &c->sp[space];
  sp->loss_time = 0;
  if (!sp->any_acked) return;
  int64_t rtt = c->latest_rtt > c->smoothed_rtt ? c->latest_rtt : c->smoothed_rtt;
  int64_t delay = rtt * (int64_t)c->time_thresh_8 / 8 > 1 ? rtt * (int64_t)c->time_thresh_8 / 8 : 1;
  for (uint32_t i = 0; i < sp->nsent; i++) {
    quic_sent *p = quic__sent_at(sp, i);
    if (p->acked || p->lost || p->pn > sp->largest_acked) continue;
    if (p->sent_at <= now - delay || sp->largest_acked >= p->pn + c->pkt_thresh) {
      p->lost = 1, p->lost_at = now;
      for (int k = 0; k < p->nf; k++) quic__frame_lost(c, sp, &p->f[k]);
      quic__cc_lost(c, p, now);
    } else {
      int64_t t = p->sent_at + delay;
      if (!sp->loss_time || t < sp->loss_time) sp->loss_time = t;
    }
  }
  quic__sent_pop_acked(sp, now, 4 * (rtt > 1 ? rtt : 1) + 100);
}

static inline void quic__discard_space(quic_conn *c, int space) {
  quic_space *sp = &c->sp[space];
  if (sp->discarded) return;
  for (uint32_t i = 0; i < sp->nsent; i++) {
    quic_sent *p = quic__sent_at(sp, i);
    if (!p->acked && !p->lost && p->in_flight) c->bytes_in_flight -= p->size;
  }
  sp->nsent = 0, sp->loss_time = 0, sp->ack_eliciting_unacked = 0;
  quic__key_free(&sp->rx), quic__key_free(&sp->tx);
  sp->have_rx = sp->have_tx = 0, sp->discarded = 1;
  c->pto_count = 0;
}

/* -------------------------------------------- TLS glue -------------------------------------------- */
static inline int quic__update_traffic_key(ptls_update_traffic_key_t *self, ptls_t *tls, int is_enc, size_t epoch,
                                           const void *secret) {
  (void)self;
  quic_conn *c = *ptls_get_data_ptr(tls);
  ptls_cipher_suite_t *cs = ptls_get_cipher(tls);
  int space = epoch == 2 ? QUIC_SP_HANDSHAKE : epoch == 3 ? QUIC_SP_APP : -1;
  if (epoch == 1) { /* 0-RTT: a client's to send with, a server's to read with */
    if ((c->client != 0) != (is_enc != 0) || quic__key_setup(&c->zrtt, cs, is_enc, secret)) return PTLS_ERROR_LIBRARY;
    c->have_zrtt = 1;
    return 0;
  }
  if (space < 0) return 0;
  quic_space *sp = &c->sp[space];
  if (quic__key_setup(is_enc ? &sp->tx : &sp->rx, cs, is_enc, secret)) return PTLS_ERROR_LIBRARY;
  if (is_enc) sp->have_tx = 1;
  else sp->have_rx = 1;
  if (space == QUIC_SP_APP) {
    c->cs = cs;
    memcpy(is_enc ? c->app_secret_tx : c->app_secret_rx, secret, cs->hash->digest_size);
  }
  return 0;
}
/* the next key phase's secret (RFC 9001 §6.1) */
static inline int quic__next_secret(ptls_cipher_suite_t *cs, uint8_t *secret) {
  uint8_t n[PTLS_MAX_DIGEST_SIZE];
  if (ptls_hkdf_expand_label(cs->hash, n, cs->hash->digest_size, ptls_iovec_init(secret, cs->hash->digest_size),
                             "quic ku", ptls_iovec_init(NULL, 0), NULL))
    return -1;
  memcpy(secret, n, cs->hash->digest_size);
  return 0;
}

/* transport parameters (RFC 9000 §18) */
static inline uint8_t *quic__tp_int(uint8_t *p, uint64_t id, uint64_t v) {
  p = quic__put_vi(p, id), p = quic__put_vi(p, quic__vi_len(v));
  return quic__put_vi(p, v);
}
static inline int quic__decode_tp(quic_conn *c, const uint8_t *p, const uint8_t *end) {
  uint64_t seen = 0, bidi_remote = 0;
  int have_iscid = 0, have_odcid = 0, have_rscid = 0;
  c->peer_max_ack_delay = 25, c->peer_ack_delay_exp = 3;
  uint64_t bidi_local = 0;
  while (p < end) {
    uint64_t id, len, v = 0;
    if (quic__vi(&p, end, &id) || quic__vi(&p, end, &len) || (uint64_t)(end - p) < len) return -1;
    const uint8_t *q = p, *qe = p + len;
    if (id < 64) {
      if (seen >> id & 1) return -1; /* duplicate */
      seen |= 1ull << id;
    }
    int is_int = id == 0x01 || id == 0x03 || (id >= 0x04 && id <= 0x0b) || id == 0x0e;
    if (is_int && (quic__vi(&q, qe, &v) || q != qe)) return -1;
    switch (id) {
      case 0x00: /* original_destination_connection_id: a server's, the DCID of the client's first Initial */
        if (!c->client || len != c->odcid_len || memcmp(p, c->odcid, len)) return -1;
        have_odcid = 1;
        break;
      case 0x02: /* stateless_reset_token: for the server's first connection ID */
        if (!c->client || len != 16) return -1;
        memcpy(c->tp_token, p, 16), c->has_tp_token = 1;
        if (c->npcid) memcpy(c->pcid[0].token, p, 16), c->pcid[0].has_token = 1;
        break;
      case 0x0d: /* preferred_address: we stay on the first path */
        if (!c->client) return -1;
        break;
      case 0x10: /* retry_source_connection_id: present exactly when there was a Retry, and its SCID */
        if (!c->client || !c->retried || len != c->rscid_len || memcmp(p, c->rscid, len)) return -1;
        have_rscid = 1;
        break;
      case 0x06: bidi_remote = v; break;
      case 0x03:
        if (v < 1200) return -1;
        c->peer_max_udp = v;
        break;
      case 0x04: c->max_data_peer = v; break;
      case 0x05: bidi_local = v; break;
      case 0x07: c->peer_init_stream_data_uni = v; break;
      case 0x09:
        if (v > (1ull << 60)) return -1;
        c->peer_max_streams_uni = v;
        break;
      case 0x08:
        if (v > (1ull << 60)) return -1;
        c->peer_max_streams_bidi = v;
        break;
      case 0x0a:
        if (v > 20) return -1;
        c->peer_ack_delay_exp = v;
        break;
      case 0x0b:
        if (v >= (1u << 14)) return -1;
        c->peer_max_ack_delay = v;
        break;
      case 0x0e:
        if (v < 2) return -1;
        break;
      case 0x0f: /* initial_source_connection_id must equal the SCID of the peer's first Initial (our DCID) */
        if (len != c->dcid_len || memcmp(p, c->dcid, len)) return -1;
        have_iscid = 1;
        break;
      default: break;
    }
    p += len;
  }
  if (!have_iscid || (c->client && (!have_odcid || have_rscid != c->retried))) return -1;
  c->peer_bidi_local = bidi_local, c->peer_bidi_remote = bidi_remote;
  for (int i = 0; i < QUIC_MAX_STREAMS; i++)
    if (c->s[i].used && !(c->s[i].id & 2)) c->s[i].max_send = QUIC__OURS(c, c->s[i].id) ? bidi_remote : bidi_local;
  c->peer_tp_ok = 1;
  return 0;
}


/* a connection's limits from its context's settings (0: the defaults) */
static inline void quic__settings(quic_conn *c, const quic_ctx *x) {
  c->conn_win = x->conn_window ? x->conn_window : QUIC_CONN_WIN;
  c->stream_win = x->stream_window ? x->stream_window : QUIC_STREAM_WIN;
  c->max_streams_bidi_local = x->max_streams_bidi ? x->max_streams_bidi : c->client ? 0 : QUIC_MAX_BIDI;
  c->max_streams_uni_local = x->max_streams_uni ? x->max_streams_uni : QUIC_MAX_UNI;
  c->max_data_local = c->conn_win;
}
/* the application protocol agreed on (ALPN), once the handshake has got that far; NULL before */
static inline const char *quic_alpn(quic_conn *c) { return c->tls ? ptls_get_negotiated_protocol(c->tls) : NULL; }
static inline int quic__alpn_ok(const quic_ctx *x, const char *a) {
  if (!a) return 0;
  if (!x->nalpn) return !strcmp(a, "h3");
  for (size_t i = 0; i < x->nalpn; i++)
    if (!strcmp(a, x->alpn[i])) return 1;
  return 0;
}
static inline int quic__on_client_hello(ptls_on_client_hello_t *self, ptls_t *tls,
                                        ptls_on_client_hello_parameters_t *params) {
  (void)self;
  quic_conn *c = *ptls_get_data_ptr(tls);
  static const char *const h3[1] = { "h3" };
  const char *const *ours = c->ctx->nalpn ? c->ctx->alpn : h3;
  size_t n = c->ctx->nalpn ? c->ctx->nalpn : 1;
  for (size_t k = 0; k < n; k++) /* our preference first */
    for (size_t i = 0; i < params->negotiated_protocols.count; i++) {
      ptls_iovec_t p = params->negotiated_protocols.list[i];
      if (p.len == strlen(ours[k]) && !memcmp(p.base, ours[k], p.len))
        return ptls_set_negotiated_protocol(tls, ours[k], p.len);
    }
  return PTLS_ALERT_NO_APPLICATION_PROTOCOL;
}
static ptls_on_client_hello_t quic__och = { quic__on_client_hello };

static inline int quic__collect_ext(ptls_t *tls, ptls_handshake_properties_t *p, uint16_t type) {
  (void)tls, (void)p;
  return type == 0x39; /* quic_transport_parameters */
}
static inline int quic__collected_ext(ptls_t *tls, ptls_handshake_properties_t *props, ptls_raw_extension_t *slots) {
  quic_conn *c = *ptls_get_data_ptr(tls);
  (void)props;
  if (slots[0].type == UINT16_MAX) return PTLS_ALERT_MISSING_EXTENSION;
  if (quic__decode_tp(c, slots[0].data.base, slots[0].data.base + slots[0].data.len)) {
    quic__error(c, QUIC_TRANSPORT_PARAMETER_ERROR, 0x06);
    return PTLS_ALERT_ILLEGAL_PARAMETER;
  }
  if (c->client) return 0; /* a client's own went out with its ClientHello */
  /* ours, sent in EncryptedExtensions */
  uint8_t tp[160], *p = tp;
  p = quic__put_vi(p, 0x00), p = quic__put_vi(p, c->odcid_len), memcpy(p, c->odcid, c->odcid_len), p += c->odcid_len;
  p = quic__tp_int(p, 0x01, QUIC_IDLE_MS);
  p = quic__tp_int(p, 0x03, QUIC_MAX_UDP);
  p = quic__tp_int(p, 0x04, c->conn_win);
  p = quic__tp_int(p, 0x05, c->stream_win); /* bidi_local: the peer's side of the streams we open */
  p = quic__tp_int(p, 0x06, c->stream_win);
  p = quic__tp_int(p, 0x07, c->stream_win);
  p = quic__tp_int(p, 0x08, c->max_streams_bidi_local);
  p = quic__tp_int(p, 0x09, c->max_streams_uni_local);
  p = quic__put_vi(p, 0x0c), p = quic__put_vi(p, 0); /* disable_active_migration */
  p = quic__put_vi(p, 0x0f), p = quic__put_vi(p, QUIC_SCID_LEN), memcpy(p, c->scid, QUIC_SCID_LEN), p += QUIC_SCID_LEN;
  p = quic__tp_int(p, 0x0e, QUIC_PEER_CIDS);          /* active_connection_id_limit */
  p = quic__put_vi(p, 0x02), p = quic__put_vi(p, 16); /* stateless_reset_token */
  if (quic_reset_token(c->ctx, c->scid, QUIC_SCID_LEN, p)) return PTLS_ERROR_LIBRARY;
  p += 16;
  if (c->retried) /* retry_source_connection_id */
    p = quic__put_vi(p, 0x10), p = quic__put_vi(p, c->rscid_len), memcpy(p, c->rscid, c->rscid_len), p += c->rscid_len;
  ptls_buffer_init(&c->tpbuf, "", 0);
  if (ptls_buffer_reserve(&c->tpbuf, (size_t)(p - tp))) return PTLS_ERROR_NO_MEMORY;
  memcpy(c->tpbuf.base, tp, (size_t)(p - tp)), c->tpbuf.off = (size_t)(p - tp);
  c->tpext[0] = (ptls_raw_extension_t){ 0x39, { c->tpbuf.base, c->tpbuf.off } };
  c->tpext[1] = (ptls_raw_extension_t){ UINT16_MAX, { NULL, 0 } };
  c->props.additional_extensions = c->tpext;
  return 0;
}

static inline int quic__space_of_epoch(size_t e) {
  return e == 0 ? QUIC_SP_INITIAL : e == 2 ? QUIC_SP_HANDSHAKE : QUIC_SP_APP;
}

static inline int quic__stream_deliver(quic_conn *c, quic_stream *s);
/* the server would not take our 0-RTT: what went in it is lost (RFC 9001 §4.6.2), and goes again in 1-RTT;
 * it was never in the network's way, so congestion control does not see a loss */
static inline void quic__zrtt_rejected(quic_conn *c) {
  quic_space *sp = &c->sp[QUIC_SP_APP];
  for (uint32_t i = 0; i < sp->nsent; i++) {
    quic_sent *r = quic__sent_at(sp, i);
    if (r->acked || r->lost) continue;
    if (r->in_flight) c->bytes_in_flight -= r->size, r->in_flight = 0;
    r->lost = 1, r->lost_at = 0;
    for (int k = 0; k < r->nf; k++) quic__frame_lost(c, sp, &r->f[k]);
  }
}
/* contiguous CRYPTO bytes of a space go to TLS; its output goes to the spaces' crypto_out */
static inline void quic__crypto_feed(quic_conn *c, int space) {
  quic_space *sp = &c->sp[space];
  size_t n = (size_t)(sp->crypto_in.contig - sp->crypto_in.base);
  if (!n || c->closing) return;
  ptls_buffer_t out;
  size_t eo[5] = { 0 };
  ptls_buffer_init(&out, "", 0);
  size_t epoch = space == QUIC_SP_INITIAL ? 0 : space == QUIC_SP_HANDSHAKE ? 2 : 3;
  int r = ptls_handle_message(c->tls, &out, eo, epoch, sp->crypto_in.buf, n, &c->props);
  quic__rb_consume(&sp->crypto_in, n);
  for (size_t e = 0; e < 4; e++) {
    size_t len = eo[e + 1] - eo[e];
    if (!len) continue;
    quic_space *dst = &c->sp[quic__space_of_epoch(e)];
    uint8_t *w = quic__sb_reserve(c->ctx, &dst->crypto_out, len);
    if (!w) {
      quic__error(c, QUIC_INTERNAL_ERROR, 0x06);
      break;
    }
    memcpy(w, out.base + eo[e], len), dst->crypto_out.len += len;
  }
  ptls_buffer_dispose(&out);
  if (!c->client && c->have_zrtt && c->sp[QUIC_SP_APP].have_tx && !c->established && !c->early_open) {
    /* 0-RTT taken: the application starts now and may answer in 0.5-RTT (RFC 9001 §4.1.1); established is 0
     * until the handshake completes, so it can tell early requests (replayable: RFC 8470) */
    c->early_open = 1;
    if (c->cb.on_established) c->cb.on_established(c, c->user);
  }
  if (r == 0 && !c->established && ptls_handshake_is_complete(c->tls)) { /* 0 also means "flight sent, waiting" */
    if (c->client) { /* "h3" or nothing; confirmed later, by HANDSHAKE_DONE (RFC 9001 §4.1.2) */
      if (!quic__alpn_ok(c->ctx, ptls_get_negotiated_protocol(c->tls))) { /* one we offered, or nothing */
        quic__error(c, 0x100 | PTLS_ALERT_NO_APPLICATION_PROTOCOL, 0x06);
        return;
      }
      c->established = 1;
      if (c->zrtt_sent && c->props.client.early_data_acceptance != PTLS_EARLY_DATA_ACCEPTED)
        quic__zrtt_rejected(c); /* everything sent in 0-RTT goes again, in 1-RTT */
      if (c->have_zrtt) quic__key_free(&c->zrtt), c->have_zrtt = 0;
    } else {
      c->established = c->confirmed = 1; /* the server's handshake is confirmed when it completes (§4.1.2) */
      c->handshake_done_pending = 1;
      quic__discard_space(c, QUIC_SP_HANDSHAKE);
    }
    if (c->cs && !quic__next_secret(c->cs, c->app_secret_rx) &&
        !quic__key_update(&c->next_rx, &c->sp[QUIC_SP_APP].rx, c->cs, 0, c->app_secret_rx))
      c->have_next_rx = 1;
    if (c->cb.on_established && !c->early_open) c->cb.on_established(c, c->user);
    if (!c->client) /* early data that came before the application was ready: offer it now */
      for (int i = 0; i < QUIC_MAX_STREAMS; i++)
        if (c->s[i].used && quic__stream_deliver(c, &c->s[i]) < 0) return;
    if (!c->client && c->new_token_len) c->send_new_token = 1;
  } else if (r != 0 && r != PTLS_ERROR_IN_PROGRESS) {
    quic__error(c, 0x100 | (uint64_t)(r & 0xff), 0x06); /* CRYPTO_ERROR + TLS alert */
  }
}

/* ------------------------------------------------ frames ------------------------------------------------ */
static inline int quic__stream_deliver(quic_conn *c, quic_stream *s) {
  for (;;) {
    size_t avail = (size_t)(s->in.contig - s->in.base);
    int fin = s->in.fin != UINT64_MAX && s->in.contig == s->in.fin;
    if (s->recv_done || (!avail && !fin)) return 0;
    int64_t used =
        c->cb.on_stream ? c->cb.on_stream(c, s->id, s->in.base, s->in.buf, avail, fin, c->user) : (int64_t)avail;
    if (used < 0) {
      quic_close(c, (uint64_t)-used);
      return -1;
    }
    if (!(s = quic__stream(c, s->id))) return 0;
    if ((size_t)used > avail) used = (int64_t)avail;
    quic__rb_consume(&s->in, (size_t)used);
    c->data_consumed += (uint64_t)used;
    if (fin && (size_t)used == avail) s->recv_done = 1;
    /* reopen windows once half is used */
    if (!s->recv_done && s->max_recv - s->in.base < c->stream_win / 2)
      s->max_recv = s->in.base + c->stream_win, s->send_max_stream_data = 1;
    if (c->max_data_local - c->data_consumed < c->conn_win / 2)
      c->max_data_local = c->data_consumed + c->conn_win, c->send_max_data = 1;
    if (!used || s->recv_done) return 0;
  }
}

/* a stream id from a frame: ours (it must exist), or the peer's (check limits, open it if new) */
static inline quic_stream *quic__peer_stream(quic_conn *c, uint64_t sid, int *err) {
  *err = 0;
  int uni = (sid & 2) != 0, ours = QUIC__OURS(c, sid);
  uint64_t idx = sid >> 2, *opened = uni ? &c->opened_uni : &c->opened_bidi;
  quic_stream *s = ours || idx < *opened ? quic__stream(c, sid) : NULL; /* beyond opened: new, no lookup */
  if (s) return s;
  /* ours: one we opened and have since finished is gone, and late frames for it are ignored; one we never
   * opened is an error (RFC 9000 §19.8) */
  if (ours) {
    if (sid < (uni ? c->next_uni_id : c->next_bidi_id)) return NULL;
    *err = QUIC_STREAM_STATE_ERROR;
    return NULL;
  }
  if (idx >= (uni ? c->max_streams_uni_local : c->max_streams_bidi_local)) {
    *err = QUIC_STREAM_LIMIT_ERROR;
    return NULL;
  }
  if (quic__rs_covers(&c->closed[uni], idx, idx + 1)) return NULL; /* finished and freed: ignore */
  if (idx + 1 > *opened) *opened = idx + 1;
  s = quic__stream_new(c, sid);
  if (!s) *err = QUIC_INTERNAL_ERROR;
  else if (uni) s->send_done = 1;
  return s;
}
static inline void quic__stream_maybe_free(quic_conn *c, quic_stream *s) {
  if (!s->recv_done || !s->send_done) return;
  int peer = !QUIC__OURS(c, s->id), uni = (s->id & 2) != 0;
  if (peer) quic__rs_add(c->ctx, &c->closed[uni], s->id >> 2, (s->id >> 2) + 1);
  quic__stream_free(c, s);
  if (peer) { /* grant a new stream in place of this one */
    if (uni) c->max_streams_uni_local++, c->send_max_streams_uni = 1;
    else c->max_streams_bidi_local++, c->send_max_streams_bidi = 1;
  }
}

static inline void quic__on_ack(quic_conn *c, int space, uint64_t largest, uint64_t delay, const uint64_t *rng,
                                int nrng, int64_t now) {
  quic_space *sp = &c->sp[space];
  int newly_largest = 0;
  int64_t largest_sent_at = 0;
  for (uint32_t i = 0; i < sp->nsent; i++) {
    quic_sent *p = quic__sent_at(sp, i);
    if (p->acked) continue;
    int in = 0;
    for (int k = 0; k < nrng && !in; k++) in = p->pn >= rng[2 * k] && p->pn <= rng[2 * k + 1];
    if (!in) continue;
    p->acked = 1;
    for (int k = 0; k < p->nf; k++) quic__frame_acked(c, sp, &p->f[k]); /* also for a "lost" one: its data arrived */
    if (p->lost) { /* declared lost earlier, but it arrived: reordering (its bytes left flight then) */
      if (space == QUIC_SP_APP) quic__cc_spurious(c, p, (int64_t)largest);
      continue;
    }
    if (p->pn == largest && p->ack_eliciting) newly_largest = 1, largest_sent_at = p->sent_at;
    quic__cc_acked(c, p, now);
  }
  if (!sp->any_acked || largest > sp->largest_acked) sp->largest_acked = largest, sp->any_acked = 1;
  if (newly_largest)
    quic__rtt_sample(c, now - largest_sent_at,
                     space == QUIC_SP_APP ? (int64_t)((delay << c->peer_ack_delay_exp) / 1000) : 0);
  c->pto_count = 0;
  quic__detect_lost(c, space, now);
  /* streams whose fin is acked are done sending */
  for (int i = 0; i < QUIC_MAX_STREAMS; i++) {
    quic_stream *s = &c->s[i];
    if (s->used && !s->send_done && s->out.fin_acked && !s->out.len) s->send_done = 1, quic__stream_maybe_free(c, s);
  }
}

#define QUIC__NEED(x)                                                                                                  \
  do {                                                                                                                 \
    if (x) {                                                                                                           \
      quic__error(c, QUIC_FRAME_ENCODING_ERROR, type);                                                                 \
      return -1;                                                                                                       \
    }                                                                                                                  \
  } while (0)
/* frames of one decrypted packet; returns 0, or -1 once the connection is closing */
static inline int quic__frames(quic_conn *c, int space, const uint8_t *p, const uint8_t *end, int64_t now,
                               int *ack_eliciting) {
  *ack_eliciting = 0;
  /* a packet must carry a frame */
  if (p == end) {
    quic__error(c, QUIC_PROTOCOL_VIOLATION, 0);
    return -1;
  }
  while (p < end) {
    uint64_t type = 0; /* reported as the frame type if the type itself does not parse */
    QUIC__NEED(quic__vi(&p, end, &type));
    if (type != 0x00 && type != 0x02 && type != 0x03 && type != 0x1c && type != 0x1d) *ack_eliciting = 1;
    /* Initial and Handshake carry only PADDING, PING, ACK, CRYPTO, CONNECTION_CLOSE (§12.4) */
    if (space != QUIC_SP_APP && !(type <= 0x03 || type == 0x06 || type == 0x1c)) {
      quic__error(c, QUIC_PROTOCOL_VIOLATION, type);
      return -1;
    }
    uint64_t a, b, d, e;
    switch (type) {
      case 0x00:
        while (p < end && !*p) p++;
        break;          /* PADDING */
      case 0x01: break; /* PING */
      case 0x02:
      case 0x03: { /* ACK */
        uint64_t largest, delay, count, first;
        QUIC__NEED(quic__vi(&p, end, &largest) || quic__vi(&p, end, &delay) || quic__vi(&p, end, &count) ||
                   quic__vi(&p, end, &first));
        uint64_t rng[2 * 64];
        if (first > largest || largest >= c->sp[space].next_pn) {
          quic__error(c, largest >= c->sp[space].next_pn ? QUIC_PROTOCOL_VIOLATION : QUIC_FRAME_ENCODING_ERROR, type);
          return -1;
        }
        int nr = 0;
        uint64_t hi = largest, lo = largest - first;
        rng[0] = lo, rng[1] = hi, nr = 1;
        for (uint64_t k = 0; k < count; k++) {
          uint64_t gap, len;
          QUIC__NEED(quic__vi(&p, end, &gap) || quic__vi(&p, end, &len));
          if (gap + 2 > lo || len > lo - gap - 2) {
            quic__error(c, QUIC_FRAME_ENCODING_ERROR, type);
            return -1;
          }
          hi = lo - gap - 2, lo = hi - len;
          if (nr < 64) rng[2 * nr] = lo, rng[2 * nr + 1] = hi, nr++;
        }
        if (type == 0x03)
          QUIC__NEED(quic__vi(&p, end, &a) || quic__vi(&p, end, &b) || quic__vi(&p, end, &d)); /* ECN counts */
        quic__on_ack(c, space, largest, delay, rng, nr, now);
        break;
      }
      case 0x04: { /* RESET_STREAM */
        QUIC__NEED(quic__vi(&p, end, &a) || quic__vi(&p, end, &b) || quic__vi(&p, end, &d));
        /* our uni stream: send-only */
        if ((a & 2) && QUIC__OURS(c, a)) {
          quic__error(c, QUIC_STREAM_STATE_ERROR, type);
          return -1;
        }
        int err;
        quic_stream *s = quic__peer_stream(c, a, &err);
        if (err) {
          quic__error(c, (uint64_t)err, type);
          return -1;
        }
        if (!s || s->recv_done) break;
        if (quic__rb_set_fin(&s->in, d)) {
          quic__error(c, QUIC_FINAL_SIZE_ERROR, type);
          return -1;
        }
        if (d > s->max_recv) {
          quic__error(c, QUIC_FLOW_CONTROL_ERROR, type);
          return -1;
        }
        s->recv_done = 1, s->recv_reset = 1;
        if (c->cb.on_stream_reset) c->cb.on_stream_reset(c, a, b, c->user);
        if ((s = quic__stream(c, a))) quic__stream_maybe_free(c, s);
        break;
      }
      case 0x05: { /* STOP_SENDING */
        QUIC__NEED(quic__vi(&p, end, &a) || quic__vi(&p, end, &b));
        /* the peer's uni stream: we never send on it */
        if ((a & 2) && !QUIC__OURS(c, a)) {
          quic__error(c, QUIC_STREAM_STATE_ERROR, type);
          return -1;
        }
        int err = 0; /* ours: a lookup (one already finished is ignored); the peer's: check it, open it */
        quic_stream *s = QUIC__OURS(c, a) ? quic__stream(c, a) : quic__peer_stream(c, a, &err);
        if (err) {
          quic__error(c, (uint64_t)err, type);
          return -1;
        }
        if (!s || s->send_done || s->reset_sent) break;
        s->send_reset = 1, s->reset_code = b; /* answer with RESET_STREAM (§3.5) */
        if (c->cb.on_stream_reset) c->cb.on_stream_reset(c, a, b, c->user);
        break;
      }
      case 0x06: { /* CRYPTO */
        QUIC__NEED(quic__vi(&p, end, &a) || quic__vi(&p, end, &b) || (uint64_t)(end - p) < b);
        quic_space *sp = &c->sp[space];
        int r = quic__rb_insert(c->ctx, &sp->crypto_in, a, p, (size_t)b, sp->crypto_in.base + 65536);
        if (r) {
          quic__error(c, r == -QUIC_FLOW_CONTROL_ERROR ? QUIC_CRYPTO_BUFFER_EXCEEDED : (uint64_t)-r, type);
          return -1;
        }
        p += b;
        quic__crypto_feed(c, space);
        if (c->closing) return -1;
        break;
      }
      case 0x07: /* NEW_TOKEN: a client keeps it for its next connection (resume_out); from a client, an error */
        if (!c->client) {
          quic__error(c, QUIC_PROTOCOL_VIOLATION, type);
          return -1;
        }
        QUIC__NEED(quic__vi(&p, end, &a) || !a || (uint64_t)(end - p) < a);
        if (c->resume_out && a <= sizeof c->resume_out->token)
          memcpy(c->resume_out->token, p, a), c->resume_out->token_len = (uint16_t)a;
        p += a;
        break;
      case 0x08:
      case 0x09:
      case 0x0a:
      case 0x0b:
      case 0x0c:
      case 0x0d:
      case 0x0e:
      case 0x0f: { /* STREAM */
        uint64_t off = 0, len;
        QUIC__NEED(quic__vi(&p, end, &a));
        if (type & 0x04) QUIC__NEED(quic__vi(&p, end, &off));
        if (type & 0x02) QUIC__NEED(quic__vi(&p, end, &len));
        else len = (uint64_t)(end - p);
        QUIC__NEED((uint64_t)(end - p) < len);
        if (off + len >= (1ull << 62)) {
          quic__error(c, QUIC_FRAME_ENCODING_ERROR, type);
          return -1;
        }
        /* data on our send-only stream */
        if ((a & 2) && QUIC__OURS(c, a)) {
          quic__error(c, QUIC_STREAM_STATE_ERROR, type);
          return -1;
        }
        int err;
        quic_stream *s = quic__peer_stream(c, a, &err);
        if (err) {
          quic__error(c, (uint64_t)err, type);
          return -1;
        }
        if (s && s->recv_done && s->in.fin != UINT64_MAX &&
            (off + len > s->in.fin || ((type & 0x01) && off + len != s->in.fin))) {
          quic__error(c, QUIC_FINAL_SIZE_ERROR, type); /* even once all of it was received (RFC 9000 §4.5) */
          return -1;
        }
        if (s && !s->recv_done) {
          uint64_t before = quic__rb_top(&s->in);
          int r = quic__rb_insert(c->ctx, &s->in, off, p, (size_t)len, s->max_recv);
          if (!r && (type & 0x01)) r = quic__rb_set_fin(&s->in, off + len);
          if (r) {
            quic__error(c, (uint64_t)-r, type);
            return -1;
          }
          uint64_t after = quic__rb_top(&s->in);
          if (after > before) {
            c->data_recv += after - before;
            if (c->data_recv > c->max_data_local) {
              quic__error(c, QUIC_FLOW_CONTROL_ERROR, type);
              return -1;
            }
          }
          if (quic__stream_deliver(c, s) < 0) return -1;
          if ((s = quic__stream(c, a))) quic__stream_maybe_free(c, s);
        }
        p += len;
        break;
      }
      case 0x10:
        QUIC__NEED(quic__vi(&p, end, &a));
        if (a > c->max_data_peer) c->max_data_peer = a;
        break;
      case 0x11: { /* MAX_STREAM_DATA */
        QUIC__NEED(quic__vi(&p, end, &a) || quic__vi(&p, end, &b));
        /* receive-only for us: the peer's uni stream */
        if ((a & 2) && !QUIC__OURS(c, a)) {
          quic__error(c, QUIC_STREAM_STATE_ERROR, type);
          return -1;
        }
        quic_stream *s = quic__stream(c, a);
        if (s && b > s->max_send) s->max_send = b;
        break;
      }
      case 0x12:
      case 0x13: /* MAX_STREAMS */
        QUIC__NEED(quic__vi(&p, end, &a));
        if (a > (1ull << 60)) {
          quic__error(c, QUIC_FRAME_ENCODING_ERROR, type);
          return -1;
        }
        if (type == 0x13 && a > c->peer_max_streams_uni) c->peer_max_streams_uni = a;
        if (type == 0x12 && a > c->peer_max_streams_bidi) c->peer_max_streams_bidi = a;
        break;
      case 0x14: QUIC__NEED(quic__vi(&p, end, &a)); break;                          /* DATA_BLOCKED */
      case 0x15: QUIC__NEED(quic__vi(&p, end, &a) || quic__vi(&p, end, &b)); break; /* STREAM_DATA_BLOCKED */
      case 0x16:
      case 0x17: QUIC__NEED(quic__vi(&p, end, &a)); break; /* STREAMS_BLOCKED */
      case 0x18: {                                         /* NEW_CONNECTION_ID */
        QUIC__NEED(quic__vi(&p, end, &a) || quic__vi(&p, end, &b) || p >= end);
        uint8_t l = *p++;
        if (b > a || l < 1 || l > 20) {
          quic__error(c, QUIC_FRAME_ENCODING_ERROR, type);
          return -1;
        }
        QUIC__NEED((size_t)(end - p) < (size_t)l + 16);
        uint64_t err = quic__new_cid(c, a, b, p, l, p + l);
        if (err) {
          quic__error(c, err, type);
          return -1;
        }
        p += l + 16;
        break;
      }
      case 0x19:
        QUIC__NEED(quic__vi(&p, end, &a));
        if (a > 0) {
          quic__error(c, QUIC_PROTOCOL_VIOLATION, type);
          return -1;
        }
        break;
      case 0x1a:
        QUIC__NEED(end - p < 8);
        memcpy(c->path_response, p, 8), c->path_response_pending = 1, p += 8;
        break;
      case 0x1b:
        QUIC__NEED(end - p < 8);
        p += 8;
        break; /* we never challenge */
      case 0x1c:
      case 0x1d: { /* CONNECTION_CLOSE */
        QUIC__NEED(quic__vi(&p, end, &a));
        if (type == 0x1c) QUIC__NEED(quic__vi(&p, end, &b));
        QUIC__NEED(quic__vi(&p, end, &e) || (uint64_t)(end - p) < e);
        p += e;
        c->draining = 1, c->close_deadline = now + 3 * quic__pto(c, QUIC_SP_APP);
        return -1;
      }
      case 0x1e: /* HANDSHAKE_DONE: the client's handshake is confirmed (RFC 9001 §4.1.2); from a client, an error */
        if (!c->client) {
          quic__error(c, QUIC_PROTOCOL_VIOLATION, type);
          return -1;
        }
        if (!c->confirmed) c->confirmed = 1, quic__discard_space(c, QUIC_SP_HANDSHAKE);
        break;
      default: quic__error(c, QUIC_FRAME_ENCODING_ERROR, type); return -1;
    }
  }
  return 0;
}
#undef QUIC__NEED

/* --------------------------------------------- receive --------------------------------------------- */
/* RFC 9000 Appendix A.3 */
static inline uint64_t quic__decode_pn(uint64_t largest, uint64_t truncated, int bits) {
  uint64_t expected = largest + 1, win = 1ull << bits, hwin = win / 2, mask = win - 1;
  uint64_t cand = (expected & ~mask) | truncated;
  if (cand + hwin <= expected && cand < (1ull << 62) - win) return cand + win;
  if (cand > expected + hwin && cand >= win) return cand - win;
  return cand;
}
/* record a received pn; returns 1 if it was already seen (duplicate) */
static inline int quic__rcv_pn(quic_space *sp, uint64_t pn) {
  for (int i = 0; i < sp->nrcv; i++)
    if (pn >= sp->rcv[i].lo && pn <= sp->rcv[i].hi) return 1;
  /* insert keeping descending order, merging neighbours */
  int i = 0;
  while (i < sp->nrcv && sp->rcv[i].lo > pn) i++;
  if (i < sp->nrcv && sp->rcv[i].hi + 1 == pn) {
    sp->rcv[i].hi = pn;
    if (i > 0 && sp->rcv[i - 1].lo == pn + 1) {
      sp->rcv[i - 1].lo = sp->rcv[i].lo;
      memmove(&sp->rcv[i], &sp->rcv[i + 1], (size_t)(sp->nrcv - i - 1) * sizeof sp->rcv[0]);
      sp->nrcv--;
    }
    return 0;
  }
  if (i > 0 && sp->rcv[i - 1].lo == pn + 1) {
    sp->rcv[i - 1].lo = pn;
    return 0;
  }
  /* forget the oldest range */
  if (sp->nrcv == QUIC_ACK_RANGES) {
    if (i == QUIC_ACK_RANGES) return 0;
    sp->nrcv--;
  }
  memmove(&sp->rcv[i + 1], &sp->rcv[i], (size_t)(sp->nrcv - i) * sizeof sp->rcv[0]);
  sp->rcv[i].lo = sp->rcv[i].hi = pn, sp->nrcv++;
  return 0;
}
static inline uint64_t quic__largest_rcv(const quic_space *sp) { return sp->nrcv ? sp->rcv[0].hi : 0; }

static inline uint32_t quic__be32(const uint8_t *p) {
  return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}


/* ---------------------------------------- Version Negotiation ---------------------------------------- */
#define QUIC_VERSION_NEGOTIATION_ERROR 0x11 /* RFC 9368 */
/* a client's Version Negotiation (RFC 9000 §6.2): valid before any server packet, with our connection IDs echoed
 * and v1 not listed, it ends the connection at once: closed (draining) with VERSION_NEGOTIATION_ERROR and the
 * server's first version in vn_version. Anything else about it means it is ignored. Returns the bytes used */
static inline size_t quic__on_vn(quic_conn *c, const uint8_t *p, const uint8_t *end, int64_t now) {
  size_t n = (size_t)(end - p);
  const uint8_t *q = p + 5;
  if (c->got_server_cid || c->retried || c->closing || c->draining || q >= end) return n;
  uint8_t dl = *q++;
  if ((size_t)(end - q) < (size_t)dl + 1 || dl != QUIC_SCID_LEN || memcmp(q, c->scid, dl)) return n;
  q += dl;
  uint8_t sl = *q++;
  if ((size_t)(end - q) < sl || sl != c->odcid_len || memcmp(q, c->odcid, sl)) return n;
  q += sl;
  if (end - q < 4 || (end - q) % 4) return n;
  for (const uint8_t *v = q; v < end; v += 4)
    if (quic__be32(v) == QUIC_V1) return n; /* it lists ours: not a valid one (§6.2) */
  c->vn_version = quic__be32(q);
  c->closing = c->draining = 1, c->close_code = QUIC_VERSION_NEGOTIATION_ERROR, c->close_frame = 0;
  c->close_deadline = now;
  return n;
}

/* ---------------------------------------------- Retry ---------------------------------------------- */
/* the Retry Integrity Tag (RFC 9001 §5.8): AES-128-GCM over the Retry pseudo-packet (ODCID, then the packet
 * without its tag), with QUIC v1's fixed key and nonce; tag is 16 bytes */
static inline int quic__retry_tag(const uint8_t *odcid, size_t odl, const uint8_t *pkt, size_t n, uint8_t *tag) {
  static const uint8_t key[16] = { 0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
                                   0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e };
  static const uint8_t iv[12] = { 0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb };
  extern ptls_aead_algorithm_t ptls_openssl_aes128gcm;
  uint8_t aad[1 + 20 + 1500];
  if (odl > 20 || n > 1500) return -1;
  aad[0] = (uint8_t)odl, memcpy(aad + 1, odcid, odl), memcpy(aad + 1 + odl, pkt, n);
  ptls_aead_context_t *a = ptls_aead_new_direct(&ptls_openssl_aes128gcm, 1, key, iv);
  if (!a) return -1;
  ptls_aead_encrypt(a, tag, "", 0, 0, aad, 1 + odl + n);
  ptls_aead_free(a);
  return 0;
}
/* a client's Retry (RFC 9000 §17.2.5): p..end the datagram's rest (a Retry is the last packet), scid its Source
 * Connection ID, tok its token. Used once, before any server Initial: then the Initials go again, to the new
 * Destination Connection ID with new keys and the token. Returns the bytes used (all of them) */
static inline size_t quic__on_retry(quic_conn *c, const uint8_t *p, const uint8_t *end, const uint8_t *scid, size_t sl,
                                    const uint8_t *tok) {
  size_t n = (size_t)(end - p);
  if (c->retried || c->got_server_cid || end - tok <= 16 || n > 1500 ||
      (sl == c->odcid_len && !memcmp(scid, c->odcid, sl)))
    return n;
  uint8_t tag[16];
  if (quic__retry_tag(c->odcid, c->odcid_len, p, n - 16, tag) || memcmp(tag, end - 16, 16)) return n;
  size_t tl = (size_t)(end - 16 - tok);
  uint8_t *t = c->ctx->alloc(NULL, tl);
  if (!t) return n;
  if (c->token) c->ctx->alloc(c->token, 0); /* a NEW_TOKEN one from a resumption, replaced */
  c->token = t, c->token_len = (uint16_t)tl, memcpy(t, tok, tl);
  c->retried = 1, memcpy(c->rscid, scid, sl), c->rscid_len = (uint8_t)sl;
  memcpy(c->dcid, scid, sl), c->dcid_len = (uint8_t)sl;
  extern ptls_cipher_suite_t ptls_openssl_aes128gcmsha256;
  quic_space *sp = &c->sp[QUIC_SP_INITIAL];
  quic__key_free(&sp->rx), quic__key_free(&sp->tx);
  if (quic__initial_keys_role(&sp->rx, &sp->tx, scid, sl, &ptls_openssl_aes128gcmsha256, 1)) {
    quic__error(c, QUIC_INTERNAL_ERROR, 0);
    return n;
  }
  /* what was sent in Initials goes again (packet numbers carry on, RFC 9000 §17.2.5.3): it all counts as lost,
   * without counting against congestion control (nothing was lost in the network) */
  for (uint32_t i = 0; i < sp->nsent; i++) {
    quic_sent *r = quic__sent_at(sp, i);
    if (r->acked || r->lost) continue;
    if (r->in_flight) c->bytes_in_flight -= r->size;
    for (int k = 0; k < r->nf; k++) quic__frame_lost(c, sp, &r->f[k]);
  }
  sp->nsent = 0, sp->loss_time = 0, c->pto_count = 0;
  return n;
}

/* one packet at p (datagram end at end): returns the bytes it occupies, or 0 to drop the rest */
static inline size_t quic__packet(quic_conn *c, uint8_t *p, uint8_t *end, int64_t now) {
  size_t avail = (size_t)(end - p), pn_off;
  uint8_t *pkt_end;
  int space, zrtt = 0;         /* zrtt: a 0-RTT packet (a server's, in the App space) */
  const uint8_t *pscid = NULL; /* a long header's SCID: a client adopts the server's from its first Initial */
  uint8_t pscid_len = 0;
  if (p[0] & 0x80) {
    if (avail >= 7 && quic__be32(p + 1) == 0 && c->client) return quic__on_vn(c, p, end, now);
    if (avail < 7 || quic__be32(p + 1) != QUIC_V1) return 0;
    int type = (p[0] >> 4) & 3;
    const uint8_t *q = p + 5, *e = end;
    uint8_t dl = *q++;
    if (dl > 20 || (size_t)(e - q) < (size_t)dl + 1) return 0;
    int ours = dl == QUIC_SCID_LEN && !memcmp(q, c->scid, QUIC_SCID_LEN);
    int odcid = !c->client && dl == c->idcid_len && !memcmp(q, c->idcid, dl);
    if (!ours && !(type <= 1 && odcid)) return 0; /* Initials and 0-RTT may still use the original DCID */
    q += dl;
    uint8_t sl = *q++;
    if (sl > 20 || (size_t)(e - q) < sl) return 0;
    pscid = q, pscid_len = sl;
    q += sl;
    if (type == 3) return c->client ? quic__on_retry(c, p, end, pscid, pscid_len, q) : 0;
    if (type == 0) { /* Initial: token */
      uint64_t tl;
      if (quic__vi(&q, e, &tl) || (uint64_t)(e - q) < tl) return 0;
      q += tl;
    }
    uint64_t len;
    if (quic__vi(&q, e, &len) || (uint64_t)(e - q) < len) return 0;
    pkt_end = (uint8_t *)q + len;
    if (type == 1 && (c->client || !c->have_zrtt)) return (size_t)(pkt_end - p); /* 0-RTT: a server's, with keys */
    zrtt = type == 1;
    space = type == 0 ? QUIC_SP_INITIAL : type == 1 ? QUIC_SP_APP : QUIC_SP_HANDSHAKE;
    pn_off = (size_t)(q - p);
  } else {
    if (avail < 1 + QUIC_SCID_LEN + 20 || memcmp(p + 1, c->scid, QUIC_SCID_LEN)) return 0;
    space = QUIC_SP_APP, pn_off = 1 + QUIC_SCID_LEN, pkt_end = end;
  }
  quic_space *sp = &c->sp[space];
  size_t plen = (size_t)(pkt_end - p);
  if (!(zrtt ? c->have_zrtt : sp->have_rx) || plen < pn_off + 4 + 16) return plen; /* no keys (yet, or now) */
  /* header protection (RFC 9001 §5.4) */
  uint8_t mask[16], hdr[QUIC_MAX_UDP]; /* a long header with an Initial token can be long */
  const quic_key *k = zrtt ? &c->zrtt : &sp->rx;
  quic__mask(k, p + pn_off + 4, mask);
  uint8_t first = (uint8_t)(p[0] ^ (mask[0] & (p[0] & 0x80 ? 0x0f : 0x1f)));
  int pnl = (first & 3) + 1;
  uint64_t tpn = 0;
  for (int i = 0; i < pnl; i++) tpn = tpn << 8 | (uint8_t)(p[pn_off + i] ^ mask[1 + i]);
  uint64_t pn = quic__decode_pn(sp->nrcv ? quic__largest_rcv(sp) : 0, tpn, 8 * pnl);
  size_t hl = pn_off + (size_t)pnl;
  if (hl > sizeof hdr) return plen;
  memcpy(hdr, p, hl), hdr[0] = first;
  for (int i = 0; i < pnl; i++) hdr[pn_off + i] = (uint8_t)(tpn >> (8 * (pnl - 1 - i)));
  /* key phase (short header): a different phase bit is the next phase, or (for packets older than
   * the current phase's first one) a late packet of the previous phase */
  int phase_flip = !zrtt && space == QUIC_SP_APP && ((first >> 2) & 1) != c->key_phase;
  int late = phase_flip && c->have_prev_rx && pn < c->phase_first_pn;
  if (c->have_prev_rx && now >= c->prev_rx_until) quic__key_free(&c->prev_rx), c->have_prev_rx = 0;
  ptls_aead_context_t *aead = late         ? c->prev_rx.aead
                              : phase_flip ? (c->have_next_rx ? c->next_rx.aead : NULL)
                                           : k->aead;
  if (!aead) return plen;
  uint8_t pt[QUIC_MAX_UDP + 64];
  size_t ctl = plen - hl;
  if (ctl > sizeof pt) return plen;
  size_t ptl = ptls_aead_decrypt(aead, pt, p + hl, ctl, pn, hdr, hl);
  /* not ours or corrupted: drop the packet only */
  if (ptl == SIZE_MAX) {
    c->undecryptable++;
    return plen;
  }
  c->got_packet = 1;
  if (zrtt) c->zrtt_recv++;
  /* reserved bits */
  if ((p[0] & 0x80 ? first & 0x0c : first & 0x18)) {
    quic__error(c, QUIC_PROTOCOL_VIOLATION, 0);
    return 0;
  }
  /* the server's connection ID, from the first Initial that decrypts (RFC 9000 §7.2) */
  if (c->client && !c->got_server_cid && space == QUIC_SP_INITIAL && pscid) {
    memcpy(c->dcid, pscid, pscid_len), c->dcid_len = pscid_len, c->got_server_cid = 1;
    quic__pcid_first(c);
    if (c->has_tp_token) memcpy(c->pcid[0].token, c->tp_token, 16), c->pcid[0].has_token = 1;
  }
  if (phase_flip && !late) { /* the peer updated keys: rotate ours (RFC 9001 §6) */
    quic__key_free(&c->prev_rx);
    c->prev_rx = sp->rx, c->have_prev_rx = 1, c->prev_rx_until = now + 3 * quic__pto(c, QUIC_SP_APP);
    sp->rx = c->next_rx, memset(&c->next_rx, 0, sizeof c->next_rx), c->have_next_rx = 0; /* same hp key */
    c->key_phase ^= 1, c->phase_first_pn = pn;
    if (!quic__next_secret(c->cs, c->app_secret_tx)) quic__key_update(&sp->tx, &sp->tx, c->cs, 1, c->app_secret_tx);
    if (!quic__next_secret(c->cs, c->app_secret_rx) &&
        !quic__key_update(&c->next_rx, &sp->rx, c->cs, 0, c->app_secret_rx))
      c->have_next_rx = 1;
  }
  if (quic__rcv_pn(sp, pn)) return plen;                  /* duplicate */
  if (space == QUIC_SP_HANDSHAKE && !c->addr_validated) { /* RFC 9001 §4.9.1, RFC 9000 §8.1 */
    c->addr_validated = 1;
    quic__discard_space(c, QUIC_SP_INITIAL);
  }
  if (!sp->nrcv || pn == quic__largest_rcv(sp)) sp->largest_rcv_at = now;
  c->idle_deadline = now + QUIC_IDLE_MS;
  int ae;
  int r = quic__frames(c, space, pt, pt + ptl, now, &ae);
  if (ae && !c->sp[space].discarded) {
    sp->ack_eliciting_unacked++;
    if (space != QUIC_SP_APP || sp->ack_eliciting_unacked >= 2) sp->ack_deadline = now;
    else if (!sp->ack_deadline) sp->ack_deadline = now + QUIC_MAX_ACK_DELAY;
  }
  return r < 0 ? 0 : plen;
}

static inline int quic_recv(quic_conn *c, uint8_t *d, size_t len, int64_t now) {
  if (c->draining) return QUIC_E_CLOSED;
  c->bytes_recv += len;
  /* answer with CONNECTION_CLOSE again */
  if (c->closing) {
    c->close_sent_once = 0;
    return QUIC_E_CLOSED;
  }
  c->got_packet = 0;
  for (uint8_t *p = d, *end = d + len; p < end;) {
    size_t n = quic__packet(c, p, end, now);
    if (!n) break;
    p += n;
  }
  if (!c->got_packet && !c->closing && !c->draining && quic__is_reset(c, d, len))
    c->draining = c->reset = 1, c->close_code = 0, c->close_deadline = now; /* no CONNECTION_CLOSE back */
  return c->closing || c->draining ? QUIC_E_CLOSED : 0;
}

/* ---------------------------------------------- accept ---------------------------------------------- */
/* Version Negotiation for a long-header datagram with another version (RFC 9000 §17.2.1) */
static inline size_t quic_version_negotiation(uint8_t *out, size_t cap, const uint8_t *d, size_t len) {
  if (len < 7 || !(d[0] & 0x80)) return 0;
  uint8_t dl = d[5];
  if (len < 6u + dl + 1) return 0;
  uint8_t sl = d[6 + dl];
  if (len < 7u + dl + sl || cap < 11u + dl + sl) return 0;
  uint8_t *p = out;
  *p++ = 0x80 | (uint8_t)(d[0] & 0x7f);
  memset(p, 0, 4), p += 4;
  *p++ = sl, memcpy(p, d + 7 + dl, sl), p += sl; /* their SCID becomes our DCID */
  *p++ = dl, memcpy(p, d + 6, dl), p += dl;
  *p++ = 0, *p++ = 0, *p++ = 0, *p++ = 1; /* we support v1 */
  return (size_t)(p - out);
}

/* address validation tokens (a server's, RFC 9000 §8.1.3): a type byte, 'R' for a Retry's (with the client's
 * original DCID, bound to the Retry's SCID, valid for seconds) or 'N' for NEW_TOKEN's (valid for a day), then
 * AES-128-GCM under the context's key over a timestamp and the DCID, bound to the client's address and the type */
#define QUIC_TOKEN_MAX      58
#define QUIC_TOKEN_LIFE     10000    /* ms: a Retry's */
#define QUIC_NEW_TOKEN_LIFE 86400000 /* ms: a NEW_TOKEN's */
static inline size_t quic__token_seal(quic_ctx *x, uint8_t *out, uint8_t type, const uint8_t *odcid, size_t odl,
                                      const void *addr, size_t alen, const uint8_t *rscid, size_t rsl, int64_t now) {
  extern ptls_aead_algorithm_t ptls_openssl_aes128gcm;
  uint8_t pt[29], aad[1 + 128 + 20];
  if (alen > 128 || odl > 20 || rsl > 20) return 0;
  for (int i = 0; i < 8; i++) pt[i] = (uint8_t)((uint64_t)now >> (56 - 8 * i));
  pt[8] = (uint8_t)odl;
  if (odl) memcpy(pt + 9, odcid, odl);
  aad[0] = type;
  if (alen) memcpy(aad + 1, addr, alen);
  if (rsl) memcpy(aad + 1 + alen, rscid, rsl);
  out[0] = type, x->tls->random_bytes(out + 1, 12);
  ptls_aead_context_t *a = ptls_aead_new_direct(&ptls_openssl_aes128gcm, 1, x->token_key, out + 1);
  if (!a) return 0;
  ptls_aead_encrypt(a, out + 13, pt, 9 + odl, 0, aad, 1 + alen + rsl);
  ptls_aead_free(a);
  return 13 + 9 + odl + 16;
}
/* 0 and the original DCID, or -1: not ours, tampered with, for another address or Retry, or expired */
static inline int quic__token_open(quic_ctx *x, const uint8_t *tok, size_t tl, const void *addr, size_t alen,
                                   const uint8_t *rscid, size_t rsl, int64_t now, uint8_t *odcid, uint8_t *odl) {
  extern ptls_aead_algorithm_t ptls_openssl_aes128gcm;
  uint8_t pt[64], aad[1 + 128 + 20];
  if (tl < 13 + 9 + 16 || tl > QUIC_TOKEN_MAX || alen > 128 || rsl > 20) return -1;
  aad[0] = tok[0];
  if (alen) memcpy(aad + 1, addr, alen);
  if (rsl) memcpy(aad + 1 + alen, rscid, rsl);
  ptls_aead_context_t *a = ptls_aead_new_direct(&ptls_openssl_aes128gcm, 0, x->token_key, tok + 1);
  if (!a) return -1;
  size_t n = ptls_aead_decrypt(a, pt, tok + 13, tl - 13, 0, aad, 1 + alen + rsl);
  ptls_aead_free(a);
  if (n == SIZE_MAX || n < 9 || pt[8] > 20 || n != 9u + pt[8]) return -1;
  int64_t ts = 0;
  for (int i = 0; i < 8; i++) ts = ts << 8 | pt[i];
  if (now < ts || now - ts > (tok[0] == 'R' ? QUIC_TOKEN_LIFE : QUIC_NEW_TOKEN_LIFE)) return -1;
  *odl = pt[8], memcpy(odcid, pt + 9, pt[8]);
  return 0;
}
/* a server's Retry for the client Initial d (from addr): its length in out, or 0 (not an Initial, or no room).
 * Validate addresses this way when under load: answer an Initial without a token with quic_retry, accept one with
 * a token through quic_accept_from (same addr), which checks it */
static inline size_t quic_retry(quic_ctx *x, const uint8_t *d, size_t len, const void *addr, size_t alen, int64_t now,
                                uint8_t *out, size_t cap) {
  /* (an Initial in a datagram under 1200 bytes is dropped, RFC 9000 §14.1: else a Retry is a reflection amplifier) */
  if (len < QUIC_MIN_INITIAL || !(d[0] & 0x80) || quic__be32(d + 1) != QUIC_V1 || ((d[0] >> 4) & 3) != 0) return 0;
  uint8_t dl = d[5];
  if (dl < 8 || dl > 20 || len < 7u + dl) return 0;
  uint8_t sl = d[6 + dl];
  if (sl > 20 || len < 7u + dl + sl || cap < 7 + 20 + 20 + QUIC_TOKEN_MAX + 16) return 0;
  uint8_t *p = out, rscid[QUIC_SCID_LEN];
  x->tls->random_bytes(rscid, QUIC_SCID_LEN);
  *p++ = 0xf0, p[0] = 0, p[1] = 0, p[2] = 0, p[3] = 1, p += 4;
  *p++ = sl, memcpy(p, d + 7 + dl, sl), p += sl;                             /* to the client's SCID */
  *p++ = QUIC_SCID_LEN, memcpy(p, rscid, QUIC_SCID_LEN), p += QUIC_SCID_LEN; /* from a new one */
  size_t tl = quic__token_seal(x, p, 'R', d + 6, dl, addr, alen, rscid, QUIC_SCID_LEN, now);
  if (!tl) return 0;
  p += tl;
  if (quic__retry_tag(d + 6, dl, out, (size_t)(p - out), p)) return 0;
  return (size_t)(p - out) + 16;
}
/* a server connection from a client's first Initial d (RFC 9000 §7): QUIC_E_VN (send Version Negotiation),
 * QUIC_E_DROP, or 0. addr (alen bytes, any form, NULL for none): the client's address, which a Retry token must
 * have been issued to; an Initial with a token that does not check out is dropped */
static inline int quic_accept_from(quic_conn *c, quic_ctx *x, uint8_t *d, size_t len, const void *addr, size_t alen,
                                   int64_t now, const quic_callbacks *cb, void *user) {
  if (len < QUIC_MIN_INITIAL || !(d[0] & 0x80) || len < 7) return QUIC_E_DROP;
  if (quic__be32(d + 1) != QUIC_V1) return QUIC_E_VN;
  if (((d[0] >> 4) & 3) != 0) return QUIC_E_DROP; /* not an Initial */
  uint8_t dl = d[5];
  if (dl < 8 || dl > 20 || len < 7u + dl) return QUIC_E_DROP;
  uint8_t sl = d[6 + dl];
  if (sl > 20 || len < 7u + dl + sl) return QUIC_E_DROP;
  const uint8_t *q = d + 7 + dl + sl;
  uint64_t tl;
  if (quic__vi(&q, d + len, &tl) || tl > (uint64_t)(d + len - q)) return QUIC_E_DROP;
  uint8_t odcid[20], odl = dl;
  memcpy(odcid, d + 6, dl);
  int retried = 0;
  int validated = 0;
  if (tl && q[0] == 'R') { /* after our Retry: the token names the original DCID; a bad one is dropped */
    if (quic__token_open(x, q, (size_t)tl, addr, alen, d + 6, dl, now, odcid, &odl)) return QUIC_E_DROP;
    retried = validated = 1;
  } else if (tl && addr) { /* NEW_TOKEN's, from an earlier connection: valid, the address is; else ignored */
    uint8_t none[20], nl;
    validated = !quic__token_open(x, q, (size_t)tl, addr, alen, NULL, 0, now, none, &nl) && q[0] == 'N';
  }
  memset(c, 0, sizeof *c);
  c->ctx = x, c->cb = *cb, c->user = user;
  memcpy(c->odcid, odcid, odl), c->odcid_len = odl;
  memcpy(c->idcid, d + 6, dl), c->idcid_len = dl;
  if (retried) c->retried = 1, memcpy(c->rscid, d + 6, dl), c->rscid_len = dl;
  if (validated) c->addr_validated = 1;
  if (addr) /* a NEW_TOKEN for its next connection, sent once the handshake completes */
    c->new_token_len = (uint8_t)quic__token_seal(x, c->new_token, 'N', NULL, 0, addr, alen, NULL, 0, now);
  memcpy(c->dcid, d + 7 + dl, sl), c->dcid_len = sl;
  quic__pcid_first(c);
  x->tls->random_bytes(c->scid, QUIC_SCID_LEN);
  if (!x->tls->on_client_hello) x->tls->on_client_hello = &quic__och;
  extern ptls_cipher_suite_t ptls_openssl_aes128gcmsha256;
  if (quic__initial_keys(&c->sp[0].rx, &c->sp[0].tx, c->idcid, dl, &ptls_openssl_aes128gcmsha256)) return QUIC_E_NOMEM;
  c->sp[0].have_rx = c->sp[0].have_tx = 1;
  for (int i = 0; i < QUIC_NSP; i++) {
    quic__rb_init(&c->sp[i].crypto_in);
    c->sp[i].sent = x->alloc(NULL, sizeof(quic_sent) * QUIC_SENT_MAX);
    if (!c->sp[i].sent) return QUIC_E_NOMEM;
  }
  if (!(c->tls = ptls_new(x->tls, 1))) return QUIC_E_NOMEM;
  *ptls_get_data_ptr(c->tls) = c;
  c->props.collect_extension = quic__collect_ext;
  c->props.collected_extensions = quic__collected_ext;
  quic__settings(c, x);
  c->peer_max_ack_delay = 25, c->peer_ack_delay_exp = 3;
  c->next_uni_id = 3, c->next_bidi_id = 1;
  c->cwnd = 10 * QUIC_SEND_MAX, c->ssthresh = UINT64_MAX, c->recovery_start = INT64_MIN;
  c->mtu = QUIC_SEND_MAX, c->peer_max_udp = 65527;
  c->pkt_thresh = 3, c->time_thresh_8 = 9; /* RFC 9002 §6.1: 3 packets, 9/8 RTT, adapted on spurious losses */
  c->idle_deadline = now + QUIC_IDLE_MS;
  return quic_recv(c, d, len, now) == QUIC_E_CLOSED && c->draining ? QUIC_E_CLOSED : 0;
}
static inline int quic_accept(quic_conn *c, quic_ctx *x, uint8_t *d, size_t len, int64_t now, const quic_callbacks *cb,
                              void *user) {
  return quic_accept_from(c, x, d, len, NULL, 0, now, cb, user);
}

/* a client connection to server_name (SNI and the certificate check; NULL for neither): Initial keys from a random
 * Destination Connection ID, the ClientHello (ALPN "h3", our transport parameters) queued for quic_send */
/* the same, resuming with what an earlier connection left in r (quic_ctx_resumption on the context): its NEW_TOKEN
 * token goes in our Initials, its ticket resumes the TLS session, and when the ticket allows early data, the
 * application starts at once (on_established is called before this returns): what it sends goes in 0-RTT
 * packets, within the transport parameters the server had, and again in 1-RTT if the server refuses it.
 * resume_out (set after this) receives what the next connection resumes with */
static inline int quic_connect_resume(quic_conn *c, quic_ctx *x, const char *server_name, int64_t now,
                                      const quic_callbacks *cb, void *user, const quic_resume *res) {
  memset(c, 0, sizeof *c);
  c->ctx = x, c->cb = *cb, c->user = user;
  c->client = 1, c->addr_validated = 1; /* a client has no anti-amplification limit */
  quic__settings(c, x);
  c->odcid_len = 16, x->tls->random_bytes(c->odcid, 16);
  memcpy(c->dcid, c->odcid, 16), c->dcid_len = 16;
  x->tls->random_bytes(c->scid, QUIC_SCID_LEN);
  extern ptls_cipher_suite_t ptls_openssl_aes128gcmsha256;
  if (quic__initial_keys_role(&c->sp[0].rx, &c->sp[0].tx, c->odcid, 16, &ptls_openssl_aes128gcmsha256, 1))
    return QUIC_E_NOMEM;
  c->sp[0].have_rx = c->sp[0].have_tx = 1;
  for (int i = 0; i < QUIC_NSP; i++) {
    quic__rb_init(&c->sp[i].crypto_in);
    c->sp[i].sent = x->alloc(NULL, sizeof(quic_sent) * QUIC_SENT_MAX);
    if (!c->sp[i].sent) return QUIC_E_NOMEM;
  }
  if (!(c->tls = ptls_new(x->tls, 0))) return QUIC_E_NOMEM;
  *ptls_get_data_ptr(c->tls) = c;
  if (server_name && ptls_set_server_name(c->tls, server_name, 0)) return QUIC_E_NOMEM;
  /* our transport parameters, in the ClientHello */
  uint8_t tp[96], *p = tp;
  p = quic__tp_int(p, 0x01, QUIC_IDLE_MS);
  p = quic__tp_int(p, 0x03, QUIC_MAX_UDP);
  p = quic__tp_int(p, 0x04, c->conn_win);
  p = quic__tp_int(p, 0x05, c->stream_win); /* bidi_local: the response side of our request streams */
  p = quic__tp_int(p, 0x06, c->stream_win); /* bidi_remote: streams the server opens */
  p = quic__tp_int(p, 0x07, c->stream_win);
  p = quic__tp_int(p, 0x08, c->max_streams_bidi_local); /* (HTTP/3: 0, its servers open none) */
  p = quic__tp_int(p, 0x09, c->max_streams_uni_local);
  p = quic__put_vi(p, 0x0c), p = quic__put_vi(p, 0); /* disable_active_migration */
  p = quic__put_vi(p, 0x0f), p = quic__put_vi(p, QUIC_SCID_LEN), memcpy(p, c->scid, QUIC_SCID_LEN), p += QUIC_SCID_LEN;
  p = quic__tp_int(p, 0x0e, QUIC_PEER_CIDS); /* active_connection_id_limit */
  ptls_buffer_init(&c->tpbuf, "", 0);
  if (ptls_buffer_reserve(&c->tpbuf, (size_t)(p - tp))) return QUIC_E_NOMEM;
  memcpy(c->tpbuf.base, tp, (size_t)(p - tp)), c->tpbuf.off = (size_t)(p - tp);
  c->tpext[0] = (ptls_raw_extension_t){ 0x39, { c->tpbuf.base, c->tpbuf.off } };
  c->tpext[1] = (ptls_raw_extension_t){ UINT16_MAX, { NULL, 0 } };
  size_t na = x->nalpn ? (x->nalpn < 8 ? x->nalpn : 8) : 1;
  for (size_t i = 0; i < na; i++) {
    const char *a = x->nalpn ? x->alpn[i] : "h3";
    c->alpn_iov[i] = ptls_iovec_init(a, strlen(a));
  }
  c->props.client.negotiated_protocols.list = c->alpn_iov, c->props.client.negotiated_protocols.count = na;
  if (res && res->ticket_len) { /* resume: the ticket, maybe 0-RTT, with the limits the server gave last time */
    c->props.client.session_ticket = ptls_iovec_init(res->ticket, res->ticket_len);
    if (res->early) c->props.client.max_early_data_size = &c->early_max;
  }
  if (res && res->token_len && (c->token = x->alloc(NULL, res->token_len)))
    memcpy(c->token, res->token, res->token_len), c->token_len = res->token_len;
  c->props.additional_extensions = c->tpext;
  c->props.collect_extension = quic__collect_ext;
  c->props.collected_extensions = quic__collected_ext;
  c->peer_max_ack_delay = 25, c->peer_ack_delay_exp = 3;
  c->next_uni_id = 2, c->next_bidi_id = 0;
  c->cwnd = 10 * QUIC_SEND_MAX, c->ssthresh = UINT64_MAX, c->recovery_start = INT64_MIN;
  c->mtu = QUIC_SEND_MAX, c->peer_max_udp = 65527;
  c->pkt_thresh = 3, c->time_thresh_8 = 9;
  c->idle_deadline = now + QUIC_IDLE_MS;
  /* the ClientHello: TLS's first flight, into the Initial space's crypto stream */
  ptls_buffer_t out;
  size_t eo[5] = { 0 };
  ptls_buffer_init(&out, "", 0);
  int r = ptls_handle_message(c->tls, &out, eo, 0, NULL, 0, &c->props);
  if (r != PTLS_ERROR_IN_PROGRESS || eo[1] == 0) {
    ptls_buffer_dispose(&out);
    return QUIC_E_NOMEM;
  }
  uint8_t *w = quic__sb_reserve(x, &c->sp[QUIC_SP_INITIAL].crypto_out, eo[1]);
  if (!w) {
    ptls_buffer_dispose(&out);
    return QUIC_E_NOMEM;
  }
  memcpy(w, out.base, eo[1]), c->sp[QUIC_SP_INITIAL].crypto_out.len += eo[1];
  ptls_buffer_dispose(&out);
  if (res && res->ticket_len && c->have_zrtt && c->early_max) { /* 0-RTT: the server's limits as remembered */
    c->max_data_peer = res->max_data, c->peer_bidi_local = res->bidi_local, c->peer_bidi_remote = res->bidi_remote;
    c->peer_init_stream_data_uni = res->uni, c->peer_max_streams_bidi = res->max_streams_bidi;
    c->peer_max_streams_uni = res->max_streams_uni;
    c->early_open = 1;
    if (c->cb.on_established) c->cb.on_established(c, c->user);
  }
  return 0;
}
static inline int quic_connect(quic_conn *c, quic_ctx *x, const char *server_name, int64_t now,
                               const quic_callbacks *cb, void *user) {
  return quic_connect_resume(c, x, server_name, now, cb, user, NULL);
}

/* a new bidirectional stream (a client's request; a server's too, if the client allows them), or -1 at the peer's
 * initial_max_streams_bidi / MAX_STREAMS */
static inline int64_t quic_open_bidi(quic_conn *c) {
  if (!(c->established || c->early_open) || c->closing || c->draining) return -1; /* (a client's in 0-RTT too) */
  if ((c->next_bidi_id >> 2) >= c->peer_max_streams_bidi) return -1;
  quic_stream *s = quic__stream_new(c, c->next_bidi_id);
  if (!s) return -1;
  c->next_bidi_id += 4;
  return (int64_t)s->id;
}

static inline void quic_free(quic_conn *c) {
  for (int i = 0; i < QUIC_NSP; i++) {
    quic__key_free(&c->sp[i].rx), quic__key_free(&c->sp[i].tx);
    if (c->sp[i].sent) c->ctx->alloc(c->sp[i].sent, 0);
    if (c->sp[i].crypto_in.buf) c->ctx->alloc(c->sp[i].crypto_in.buf, 0);
    quic__rs_free(c->ctx, &c->sp[i].crypto_in.have);
    quic__sb_free(c->ctx, &c->sp[i].crypto_out);
  }
  quic__key_free(&c->next_rx), quic__key_free(&c->prev_rx);
  if (c->token) c->ctx->alloc(c->token, 0), c->token = NULL;
  if (c->have_zrtt) quic__key_free(&c->zrtt), c->have_zrtt = 0;
  for (int i = 0; i < QUIC_MAX_STREAMS; i++)
    if (c->s[i].used) quic__stream_free(c, &c->s[i]);
  quic__rs_free(c->ctx, &c->closed[0]), quic__rs_free(c->ctx, &c->closed[1]);
  if (c->tls) ptls_free(c->tls);
  if (c->tpbuf.base) ptls_buffer_dispose(&c->tpbuf);
  memset(c, 0, sizeof *c);
}

/* server-initiated unidirectional stream (HTTP/3 control and QPACK streams) */
/* offer a stream's buffered bytes to on_stream again (e.g. after HTTP/3's h3_unblocked); 0, or -1 if the
 * connection closed meanwhile */
static inline int quic_stream_redeliver(quic_conn *c, uint64_t sid) {
  quic_stream *s = quic__stream(c, sid);
  return s ? quic__stream_deliver(c, s) : 0;
}
static inline int64_t quic_open_uni(quic_conn *c) {
  uint64_t idx = c->next_uni_id >> 2;
  if (idx >= c->peer_max_streams_uni) return -1;
  quic_stream *s = quic__stream_new(c, c->next_uni_id);
  if (!s) return -1;
  s->recv_done = 1, s->max_send = c->peer_init_stream_data_uni;
  c->next_uni_id += 4;
  return (int64_t)s->id;
}
/* abort both directions of a stream with an application error code */
static inline void quic_reset_stream(quic_conn *c, uint64_t sid, uint64_t code) {
  quic_stream *s = quic__stream(c, sid);
  if (!s) return;
  if (!s->send_done && !s->reset_sent) s->send_reset = 1, s->reset_code = code;
  if (!s->recv_done) s->send_stop = 1, s->stop_code = code; /* our send-only uni streams are recv_done */
}

/* ---------------------------------------------- send ---------------------------------------------- */
typedef struct {
  int space, zrtt; /* zrtt: a 0-RTT packet (App space, long header, the early keys) */
  size_t hdr_off, pn_off, len_off, payload_off, payload_len; /* within the datagram buffer */
  uint64_t pn;
  int ack_eliciting;
  quic_sent rec;
} quic__pkt;

static inline uint8_t *quic__ack_frame(quic_conn *c, quic_space *sp, int space, uint8_t *p, uint8_t *e, int64_t now,
                                       uint64_t *largest) {
  if (!sp->nrcv || e - p < 32) return p;
  uint64_t delay = space == QUIC_SP_APP ? (uint64_t)((now - sp->largest_rcv_at) * 1000) >> 3 : 0;
  *largest = sp->rcv[0].hi;
  int n = sp->nrcv;
  while (n > 1 && (size_t)(e - p) < (size_t)(16 + 16 * n)) n--;
  *p++ = 0x02;
  p = quic__put_vi(p, sp->rcv[0].hi), p = quic__put_vi(p, delay), p = quic__put_vi(p, (uint64_t)(n - 1));
  p = quic__put_vi(p, sp->rcv[0].hi - sp->rcv[0].lo);
  for (int i = 1; i < n; i++) {
    p = quic__put_vi(p, sp->rcv[i - 1].lo - sp->rcv[i].hi - 2);
    p = quic__put_vi(p, sp->rcv[i].hi - sp->rcv[i].lo);
  }
  sp->ack_eliciting_unacked = 0, sp->ack_deadline = 0;
  (void)c;
  return p;
}
static inline int quic__rec(quic_sent *r, uint8_t type, uint64_t a, uint64_t b, uint64_t cc, int fin) {
  if (r->nf == QUIC_FREC_MAX) return 0;
  r->f[r->nf++] = (quic_frec){ type, (uint8_t)fin, a, b, cc };
  return 1;
}
/* STREAM or CRYPTO bytes [off, off+n) from a send buffer */
static inline uint8_t *quic__data_frame(uint8_t *p, int crypto, uint64_t sid, uint64_t off, const uint8_t *d, size_t n,
                                        int fin) {
  if (crypto) *p++ = 0x06;
  else {
    *p++ = (uint8_t)(0x08 | (off ? 0x04 : 0) | 0x02 | (fin ? 0x01 : 0));
    p = quic__put_vi(p, sid);
  }
  if (crypto || off) p = quic__put_vi(p, off);
  p = quic__put_vi2(p, n);
  memcpy(p, d, n);
  return p + n;
}
/* resend lost bytes or send new bytes of b; returns the new write position */
static inline uint8_t *quic__sb_emit(quic_sbuf *b, int crypto, uint64_t sid, uint8_t *p, uint8_t *e, quic_sent *r,
                                     uint64_t new_limit, uint64_t *new_bytes) {
  *new_bytes = 0;
  size_t over = crypto ? 1 + 8 + 2 : 1 + 8 + 8 + 2;
  while (b->lost.n && (size_t)(e - p) > over + 1 && r->nf < QUIC_FREC_MAX) {
    uint64_t lo = b->lost.r[0].lo, hi = b->lost.r[0].hi;
    size_t n = (size_t)(hi - lo);
    if (n > (size_t)(e - p) - over) n = (size_t)(e - p) - over;
    p = quic__data_frame(p, crypto, sid, lo, b->buf + (lo - b->base), n, 0);
    quic__rec(r, crypto ? QF_CRYPTO : QF_STREAM, sid, lo, n, 0);
    quic__rs_trim(&b->lost, lo + n);
  }
  uint64_t unsent = b->base + b->len - b->sent;
  int fin_due = b->fin && (!b->fin_sent || b->fin_lost) && b->sent == b->base + b->len;
  if ((unsent || fin_due || (b->fin && b->sent + unsent == b->base + b->len && !b->fin_sent)) &&
      (size_t)(e - p) > over && r->nf < QUIC_FREC_MAX) {
    size_t n = (size_t)unsent;
    if (n > (size_t)(e - p) - over) n = (size_t)(e - p) - over;
    if (n > new_limit) n = (size_t)new_limit;
    int fin = b->fin && b->sent + n == b->base + b->len;
    if (n || fin) {
      p = quic__data_frame(p, crypto, sid, b->sent, b->buf + (b->sent - b->base), n, fin);
      quic__rec(r, crypto ? QF_CRYPTO : QF_STREAM, sid, b->sent, n, fin);
      b->sent += n, *new_bytes = n;
      if (fin) b->fin_sent = 1, b->fin_lost = 0;
    }
  }
  return p;
}

static inline int quic__space_wants(quic_conn *c, int space, int64_t now) {
  quic_space *sp = &c->sp[space];
  int zrtt = space == QUIC_SP_APP && c->client && !sp->have_tx && c->have_zrtt && c->early_open;
  if ((!sp->have_tx && !zrtt) || sp->discarded) return 0;
  if (sp->ack_eliciting_unacked && sp->ack_deadline && sp->ack_deadline <= now) return 1;
  if (sp->crypto_out.lost.n || sp->crypto_out.sent < sp->crypto_out.base + sp->crypto_out.len) return 1;
  if (c->probes_due && !zrtt) return 1;
  if (space != QUIC_SP_APP || !(c->established || zrtt || c->early_open)) return 0;
  if (c->handshake_done_pending || c->path_response_pending || c->send_max_data || c->send_max_streams_bidi ||
      c->nretire || c->send_max_streams_uni || c->send_new_token)
    return 1;
  for (int i = 0; i < QUIC_MAX_STREAMS; i++) {
    quic_stream *s = &c->s[i];
    if (!s->used) continue;
    if (s->send_max_stream_data || s->send_reset || s->send_stop || s->out.lost.n ||
        (s->out.fin_lost && !s->out.fin_acked))
      return 1;
    if (s->send_done || s->reset_sent) continue;
    if (s->out.fin && !s->out.fin_sent && s->out.sent == s->out.base + s->out.len) return 1; /* a bare fin */
    int room = s->max_send > s->out.sent && c->max_data_peer > c->data_sent;                 /* flow control */
    if (room && (s->out.sent < s->out.base + s->out.len ||
                 (!s->out.fin && c->cb.stream_wants && c->cb.stream_wants(c, s->id, c->user))))
      return 1;
  }
  return 0;
}

/* frames of an App-space packet beyond ACK */
static inline uint8_t *quic__app_frames(quic_conn *c, uint8_t *p, uint8_t *e, quic_sent *r, int cc_ok) {
  if (c->handshake_done_pending && e - p > 1)
    *p++ = 0x1e, quic__rec(r, QF_HANDSHAKE_DONE, 0, 0, 0, 0), c->handshake_done_pending = 0;
  if (c->path_response_pending && e - p > 9)
    *p++ = 0x1b, memcpy(p, c->path_response, 8), p += 8, c->path_response_pending = 0;
  if (c->send_max_data && e - p > 9)
    *p++ = 0x10, p = quic__put_vi(p, c->max_data_local), quic__rec(r, QF_MAX_DATA, 0, 0, 0, 0), c->send_max_data = 0;
  if (c->send_max_streams_bidi && e - p > 9)
    *p++ = 0x12, p = quic__put_vi(p, c->max_streams_bidi_local), quic__rec(r, QF_MAX_STREAMS_BIDI, 0, 0, 0, 0),
    c->send_max_streams_bidi = 0;
  if (c->send_max_streams_uni && e - p > 9)
    *p++ = 0x13, p = quic__put_vi(p, c->max_streams_uni_local), quic__rec(r, QF_MAX_STREAMS_UNI, 0, 0, 0, 0),
    c->send_max_streams_uni = 0;
  while (c->nretire && e - p > 9 && r->nf < QUIC_FREC_MAX) { /* RETIRE_CONNECTION_ID */
    uint64_t seq = c->retire_q[--c->nretire];
    *p++ = 0x19, p = quic__put_vi(p, seq), quic__rec(r, QF_RETIRE_CID, seq, 0, 0, 0);
  }
  if (c->send_new_token && e - p > 2 + c->new_token_len) { /* NEW_TOKEN */
    *p++ = 0x07, p = quic__put_vi(p, c->new_token_len), memcpy(p, c->new_token, c->new_token_len);
    p += c->new_token_len, quic__rec(r, QF_NEW_TOKEN, 0, 0, 0, 0), c->send_new_token = 0;
  }
  /* the order: our unidirectional streams first (HTTP/3's control and QPACK streams: small, and what the peer
   * needs to read the rest), then the others by the application's priority (stream_priority: urgency << 1 |
   * incremental, RFC 9218): lower urgency first; at the same, the non-incremental in stream order, then the
   * incremental round-robin. Without stream_priority, round-robin */
  uint16_t ord[QUIC_MAX_STREAMS];
  uint64_t key[QUIC_MAX_STREAMS];
  int no = 0;
  for (int k = 0; k < QUIC_MAX_STREAMS; k++) {
    uint32_t slot = (c->rr + (uint32_t)k) % QUIC_MAX_STREAMS;
    quic_stream *s = &c->s[slot];
    if (!s->used) continue;
    uint64_t kk;
    if ((s->id & 2) && QUIC__OURS(c, s->id)) kk = (uint64_t)k;
    else if (c->cb.stream_priority) {
      int pr = c->cb.stream_priority(c, s->id, c->user), inc = pr & 1;
      kk = 1ull << 50 | (uint64_t)(pr >> 1 & 7) << 42 | (uint64_t)inc << 41 | (inc ? (uint64_t)k : s->id >> 2);
    } else kk = 1ull << 50 | (uint64_t)k;
    int i = no++;
    while (i > 0 && key[i - 1] > kk) key[i] = key[i - 1], ord[i] = ord[i - 1], i--;
    key[i] = kk, ord[i] = (uint16_t)slot;
  }
  for (int k = 0; k < no && r->nf < QUIC_FREC_MAX; k++) {
    quic_stream *s = &c->s[ord[k]];
    if (!s->used) continue;
    if (s->send_max_stream_data && e - p > 18)
      *p++ = 0x11, p = quic__put_vi(p, s->id), p = quic__put_vi(p, s->max_recv),
      quic__rec(r, QF_MAX_STREAM_DATA, s->id, 0, 0, 0), s->send_max_stream_data = 0;
    if (s->send_stop && e - p > 18)
      *p++ = 0x05, p = quic__put_vi(p, s->id), p = quic__put_vi(p, s->stop_code), quic__rec(r, QF_STOP, s->id, 0, 0, 0),
      s->send_stop = 0, s->stop_sent = 1;
    if (s->send_reset && e - p > 27) {
      *p++ = 0x04, p = quic__put_vi(p, s->id), p = quic__put_vi(p, s->reset_code), p = quic__put_vi(p, s->out.sent);
      quic__rec(r, QF_RESET, s->id, 0, 0, 0), s->send_reset = 0, s->reset_sent = 1, s->send_done = 1;
      s->out.lost.n = 0, s->out.fin_lost = 0; /* nothing more goes out on a reset stream */
      quic__stream_maybe_free(c, s);
      continue;
    }
    if (s->send_done || s->reset_sent || !cc_ok) continue;
    /* new data from the application, within flow control */
    uint64_t sw = s->max_send > s->out.sent ? s->max_send - s->out.sent : 0;
    uint64_t cw = c->max_data_peer > c->data_sent ? c->max_data_peer - c->data_sent : 0;
    uint64_t limit = sw < cw ? sw : cw, buffered = s->out.base + s->out.len - s->out.sent;
    if (!s->out.fin && buffered < limit && c->cb.stream_send && (e - p) > 24) {
      size_t want = (size_t)(limit - buffered);
      if (want > (size_t)(e - p) - 20) want = (size_t)(e - p) - 20;
      uint8_t *w = quic__sb_reserve(c->ctx, &s->out, want);
      if (w) {
        int fin = 0;
        size_t got = c->cb.stream_send(c, s->id, w, want, &fin, c->user);
        s->out.len += got;
        if (fin) s->out.fin = 1;
      }
    }
    uint64_t nb;
    p = quic__sb_emit(&s->out, 0, s->id, p, e, r, limit, &nb);
    c->data_sent += nb;
  }
  c->rr++;
  return p;
}

/* pacing: a bucket of bytes refilled at 1.25 (2 in slow start) cwnd / smoothed RTT, holding at most QUIC_PACE_BURST or 2 ms at the rate; new data
 * waits while it is short of a packet (ACKs and probes never do) */
#ifndef QUIC_PACE_BURST
#define QUIC_PACE_BURST (10 * QUIC_SEND_MAX)
#endif
static inline double quic__pace_rate(const quic_conn *c) { /* bytes per ms: 2x cwnd per RTT in slow start, which
                                                             * doubles cwnd every RTT (as Linux paces), else 1.25x */
  int64_t rtt = c->rtt_sampled ? c->smoothed_rtt : 333;
  return (c->cwnd < c->ssthresh ? 2.0 : 1.25) * (double)c->cwnd / (double)(rtt > 1 ? rtt : 1);
}
static inline void quic__pace_refill(quic_conn *c, int64_t now) {
  if (!c->pace_at) c->pace_tokens = QUIC_PACE_BURST, c->pace_at = now;
  else if (now > c->pace_at) {
    double rate = quic__pace_rate(c), cap = 2 * rate > QUIC_PACE_BURST ? 2 * rate : QUIC_PACE_BURST;
    c->pace_tokens += (double)(now - c->pace_at) * rate; /* clocks tick in ms: hold 2 ms at the rate, at least */
    if (c->pace_tokens > cap) c->pace_tokens = cap;
    c->pace_at = now;
  }
}

/* the next size to probe: 1350 (tunnels), 1452 (IPv6 over 1500), 1472 (IPv4 over 1500); within what the peer
 * takes and we accept */
static inline uint16_t quic__pmtu_next(const quic_conn *c) {
  static const uint16_t sizes[3] = { 1350, 1452, 1472 };
  for (int i = 0; i < 3; i++)
    if (sizes[i] > c->mtu && sizes[i] <= QUIC_MAX_UDP && sizes[i] <= c->peer_max_udp) return sizes[i];
  return 0;
}
/* a probe: a 1-RTT packet of PING and PADDING, exactly the size to try (RFC 9000 §14.4); in flight, but its loss
 * is no congestion signal. 0 when nothing to probe or no room */
static inline size_t quic__pmtu_probe(quic_conn *c, uint8_t *out, size_t cap, int64_t now) {
  uint16_t size = quic__pmtu_next(c);
  quic_space *sp = &c->sp[QUIC_SP_APP];
  if (!size) {
    c->pmtu_done = 1;
    return 0;
  }
  if (cap < size || !sp->have_tx || sp->nsent >= QUIC_SENT_MAX || c->bytes_in_flight + size > c->cwnd) return 0;
  uint8_t pl[QUIC_MAX_UDP], *p = out;
  size_t hl = 1 + c->dcid_len + 2, pll = size - hl - 16;
  memset(pl, 0, pll), pl[0] = 0x01; /* PING, then PADDING */
  uint64_t pn = sp->next_pn++;
  *p++ = (uint8_t)(0x40 | (c->key_phase << 2) | 1);
  memcpy(p, c->dcid, c->dcid_len), p += c->dcid_len;
  *p++ = (uint8_t)(pn >> 8), *p++ = (uint8_t)pn;
  size_t ct = ptls_aead_encrypt(sp->tx.aead, p, pl, pll, pn, out, hl);
  uint8_t mask[16];
  quic__mask(&sp->tx, out + hl - 2 + 4, mask);
  out[0] ^= mask[0] & 0x1f, out[hl - 2] ^= mask[1], out[hl - 1] ^= mask[2];
  quic_sent r = { 0 };
  r.pn = pn, r.sent_at = now, r.size = (uint16_t)(hl + ct), r.ack_eliciting = r.in_flight = 1;
  quic__rec(&r, QF_PMTU, size, 0, 0, 0);
  *quic__sent_at(sp, sp->nsent) = r, sp->nsent++;
  c->bytes_in_flight += r.size, sp->last_ack_eliciting_at = now, c->bytes_sent += r.size;
  c->pmtu_probe = size, c->pmtu_next_at = now + 2 * (c->rtt_sampled ? c->smoothed_rtt : 333);
  return hl + ct;
}

/* build and protect one datagram */
static inline size_t quic_send(quic_conn *c, uint8_t *out, size_t cap, int64_t now) {
  if (c->draining) return 0;
  size_t limit = cap < c->mtu ? cap : c->mtu;
  if (!c->addr_validated) { /* anti-amplification: 3x what we received (RFC 9000 §8.1) */
    uint64_t room = 3 * c->bytes_recv > c->bytes_sent ? 3 * c->bytes_recv - c->bytes_sent : 0;
    if (room < limit) limit = (size_t)room;
  }
  if (limit < 64) return 0;
  if (c->closing) { /* CONNECTION_CLOSE in the highest space with keys */
    if (c->close_sent_once) return 0;
    int space = c->sp[QUIC_SP_APP].have_tx && c->established                              ? QUIC_SP_APP
                : c->sp[QUIC_SP_HANDSHAKE].have_tx && !c->sp[QUIC_SP_HANDSHAKE].discarded ? QUIC_SP_HANDSHAKE
                                                                                          : QUIC_SP_INITIAL;
    if (!c->sp[space].have_tx) return 0;
    c->close_sent_once = 1;
    if (!c->close_deadline) c->close_deadline = now + 3 * quic__pto(c, space);
    uint8_t pl[32], *q = pl;
    int app = c->close_app && space == QUIC_SP_APP;
    *q++ = app ? 0x1d : 0x1c;
    q = quic__put_vi(q, app || !c->close_app ? c->close_code : 0x0c /* APPLICATION_ERROR before 1-RTT */);
    if (!app) q = quic__put_vi(q, c->close_frame);
    *q++ = 0; /* no reason phrase */
    /* fall through to the common path with only these frames */
    quic__pkt pk = { 0 };
    pk.space = space;
    uint8_t *p = out, *e = out + limit;
    (void)e;
    quic_space *sp = &c->sp[space];
    pk.pn = sp->next_pn++;
    if (space == QUIC_SP_APP) {
      *p++ = (uint8_t)(0x40 | (c->key_phase << 2) | 1);
      memcpy(p, c->dcid, c->dcid_len), p += c->dcid_len;
    } else {
      *p++ = (uint8_t)(0xc0 | (space == QUIC_SP_HANDSHAKE ? 0x20 : 0) | 1);
      *p++ = 0, *p++ = 0, *p++ = 0, *p++ = 1;
      *p++ = c->dcid_len, memcpy(p, c->dcid, c->dcid_len), p += c->dcid_len;
      *p++ = QUIC_SCID_LEN, memcpy(p, c->scid, QUIC_SCID_LEN), p += QUIC_SCID_LEN;
      if (space == QUIC_SP_INITIAL) *p++ = 0;
      pk.len_off = (size_t)(p - out), p += 2;
    }
    pk.pn_off = (size_t)(p - out);
    *p++ = (uint8_t)(pk.pn >> 8), *p++ = (uint8_t)pk.pn;
    size_t pll = (size_t)(q - pl);
    while (pll < 4) pl[pll++] = 0; /* the sample needs 4 bytes after a 2-byte pn: pad */
    if (space != QUIC_SP_APP) {
      size_t l = 2 + pll + 16;
      out[pk.len_off] = (uint8_t)(0x40 | l >> 8), out[pk.len_off + 1] = (uint8_t)l;
    }
    size_t hl = (size_t)(p - out);
    size_t ct = ptls_aead_encrypt(sp->tx.aead, p, pl, pll, pk.pn, out, hl);
    uint8_t mask[16];
    quic__mask(&sp->tx, out + pk.pn_off + 4, mask);
    out[0] ^= mask[0] & (out[0] & 0x80 ? 0x0f : 0x1f);
    out[pk.pn_off] ^= mask[1], out[pk.pn_off + 1] ^= mask[2];
    c->bytes_sent += hl + ct;
    return hl + ct;
  }
  quic__pkt pk[QUIC_NSP];
  int np = 0;
  uint8_t plain[QUIC_MAX_UDP];
  size_t w = 0, poff = 0; /* datagram bytes used / plaintext bytes used */
  int has_initial_ae = 0;
  quic__pace_refill(c, now);
  if (!c->closing && (c->client ? c->confirmed : c->established) && !c->pmtu_done && !c->pmtu_probe &&
      now >= c->pmtu_next_at && c->addr_validated) { /* a path MTU probe, when one is due */
    size_t n = quic__pmtu_probe(c, out, cap, now);
    if (n) return n;
  }
  int cwnd_ok = c->bytes_in_flight + c->mtu <= c->cwnd, paced = c->pace_tokens >= c->mtu;
  int cc_ok = (cwnd_ok && paced) || c->probes_due;
  c->pace_blocked = cwnd_ok && !paced && !c->probes_due;
  for (int space = 0; space < QUIC_NSP; space++) {
    if (!quic__space_wants(c, space, now)) continue;
    quic_space *sp = &c->sp[space];
    int zrtt = space == QUIC_SP_APP && !sp->have_tx; /* (wanted: then a client's 0-RTT) */
    size_t hdr = zrtt                   ? (size_t)1 + 4 + 1 + c->dcid_len + 1 + QUIC_SCID_LEN + 2 + 2
                 : space == QUIC_SP_APP ? (size_t)1 + c->dcid_len + 2
                                        : (size_t)1 + 4 + 1 + c->dcid_len + 1 + QUIC_SCID_LEN +
                                              (space == 0) * (quic__vi_len(c->token_len) + c->token_len) + 2 + 2;
    if (w + hdr + 16 + 24 > limit) break;
    quic__pkt *k = &pk[np];
    memset(k, 0, sizeof *k);
    k->space = space, k->pn = sp->next_pn, k->zrtt = zrtt;
    k->rec.pn = k->pn, k->rec.sent_at = now;
    uint8_t *p = plain + poff, *e = plain + poff + (limit - w - hdr - 16);
    uint64_t largest = 0;
    uint8_t *before_ack = p;
    int ack_due = sp->ack_eliciting_unacked && (space != QUIC_SP_APP || (sp->ack_deadline && sp->ack_deadline <= now));
    if (ack_due) p = quic__ack_frame(c, sp, space, p, e, now, &largest);
    if (p != before_ack) quic__rec(&k->rec, QF_ACK, largest, 0, 0, 0), k->rec.largest_ack = largest;
    uint8_t *after_ack = p;
    /* a full record ring would forget this packet, and what it carries would never be resent if it were
     * lost: only an ACK or a probe goes out until acks (or losses) free records */
    int rec_ok = sp->nsent < QUIC_SENT_MAX;
    if (rec_ok && (cc_ok || sp->crypto_out.lost.n || space != QUIC_SP_APP)) {
      uint64_t nb;
      p = quic__sb_emit(&sp->crypto_out, 1, 0, p, e, &k->rec, UINT64_MAX, &nb);
    }
    if (rec_ok && space == QUIC_SP_APP && (c->established || zrtt || c->early_open))
      p = quic__app_frames(c, p, e, &k->rec, cc_ok);
    if (zrtt && p != after_ack && c->zrtt_sent < 255) c->zrtt_sent++;
    if (c->probes_due && p == after_ack && e - p > 1) *p++ = 0x01, quic__rec(&k->rec, QF_PING, 0, 0, 0, 0); /* probe */
    if (p == plain + poff) continue; /* nothing after all */
    k->ack_eliciting = p != after_ack;
    if (k->ack_eliciting && c->probes_due) c->probes_due--;
    if (k->ack_eliciting && space == QUIC_SP_INITIAL) has_initial_ae = 1;
    while (p - (plain + poff) < 4) *p++ = 0; /* the HP sample needs 4 payload bytes after a 2-byte pn */
    k->payload_off = poff, k->payload_len = (size_t)(p - (plain + poff));
    sp->next_pn++;
    poff += k->payload_len;
    w += hdr + k->payload_len + 16;
    np++;
  }
  if (!np) return 0;
  /* a datagram with an ack-eliciting Initial is padded to 1200 bytes (RFC 9000 §14.1): PADDING in
   * the last packet */
  if (has_initial_ae && w < QUIC_MIN_INITIAL && limit >= QUIC_MIN_INITIAL) {
    size_t pad = QUIC_MIN_INITIAL - w;
    quic__pkt *k = &pk[np - 1];
    memmove(plain + k->payload_off + k->payload_len + pad, plain + k->payload_off + k->payload_len, 0);
    memset(plain + k->payload_off + k->payload_len, 0, pad), k->payload_len += pad, w += pad;
  }
  /* headers, encryption, header protection */
  uint8_t *o = out;
  for (int i = 0; i < np; i++) {
    quic__pkt *k = &pk[i];
    quic_space *sp = &c->sp[k->space];
    uint8_t *h = o;
    const quic_key *key = k->zrtt ? &c->zrtt : &sp->tx;
    if (k->zrtt) { /* 0-RTT: a long header, type 1 */
      *o++ = 0xd1, *o++ = 0, *o++ = 0, *o++ = 0, *o++ = 1;
      *o++ = c->dcid_len, memcpy(o, c->dcid, c->dcid_len), o += c->dcid_len;
      *o++ = QUIC_SCID_LEN, memcpy(o, c->scid, QUIC_SCID_LEN), o += QUIC_SCID_LEN;
      o = quic__put_vi2(o, 2 + k->payload_len + 16);
    } else if (k->space == QUIC_SP_APP) {
      *o++ = (uint8_t)(0x40 | (c->key_phase << 2) | 1);
      memcpy(o, c->dcid, c->dcid_len), o += c->dcid_len;
    } else {
      *o++ = (uint8_t)(0xc0 | (k->space == QUIC_SP_HANDSHAKE ? 0x20 : 0) | 1);
      *o++ = 0, *o++ = 0, *o++ = 0, *o++ = 1;
      *o++ = c->dcid_len, memcpy(o, c->dcid, c->dcid_len), o += c->dcid_len;
      *o++ = QUIC_SCID_LEN, memcpy(o, c->scid, QUIC_SCID_LEN), o += QUIC_SCID_LEN;
      if (k->space == QUIC_SP_INITIAL) /* a client's Retry token, else none */
        o = quic__put_vi(o, c->token_len),
        o = c->token_len ? (uint8_t *)memcpy(o, c->token, c->token_len) + c->token_len : o;
      o = quic__put_vi2(o, 2 + k->payload_len + 16);
    }
    k->pn_off = (size_t)(o - h);
    *o++ = (uint8_t)(k->pn >> 8), *o++ = (uint8_t)k->pn;
    size_t hl = (size_t)(o - h);
    size_t ct = ptls_aead_encrypt(key->aead, o, plain + k->payload_off, k->payload_len, k->pn, h, hl);
    uint8_t mask[16];
    quic__mask(key, h + k->pn_off + 4, mask);
    h[0] ^= mask[0] & (h[0] & 0x80 ? 0x0f : 0x1f);
    h[k->pn_off] ^= mask[1], h[k->pn_off + 1] ^= mask[2];
    o += ct;
    /* remember it */
    k->rec.size = (uint16_t)(hl + ct), k->rec.ack_eliciting = (uint8_t)k->ack_eliciting,
    k->rec.in_flight = (uint8_t)k->ack_eliciting;
    if (sp->nsent < QUIC_SENT_MAX) {
      *quic__sent_at(sp, sp->nsent) = k->rec, sp->nsent++;
      if (k->ack_eliciting) c->bytes_in_flight += k->rec.size, sp->last_ack_eliciting_at = now;
      if (k->ack_eliciting) c->pace_tokens -= k->rec.size;
    }
  }
  c->bytes_sent += (uint64_t)(o - out), c->last_send_at = now;
  /* a client discards its Initial keys once it sends a Handshake packet (RFC 9001 §4.9.1) */
  if (c->client && !c->sp[QUIC_SP_INITIAL].discarded)
    for (int i = 0; i < np; i++)
      if (pk[i].space == QUIC_SP_HANDSHAKE) {
        quic__discard_space(c, QUIC_SP_INITIAL);
        break;
      }
  return (size_t)(o - out);
}

/* ---------------------------------------------- timers ---------------------------------------------- */
static inline int64_t quic_timeout(const quic_conn *c) {
  if (c->draining || c->closing) return c->close_deadline ? c->close_deadline : INT64_MAX;
  int64_t t = c->idle_deadline;
  for (int i = 0; i < QUIC_NSP; i++) {
    const quic_space *sp = &c->sp[i];
    if (sp->discarded || !sp->have_tx) continue;
    if (sp->loss_time && sp->loss_time < t) t = sp->loss_time;
    if (sp->ack_eliciting_unacked && sp->ack_deadline && sp->ack_deadline < t) t = sp->ack_deadline;
    int inflight = 0;
    for (uint32_t k = 0; k < sp->nsent && !inflight; k++) inflight = quic__sent_at((quic_space *)sp, k)->ack_eliciting;
    if (inflight && !sp->loss_time) {
      int64_t pto = sp->last_ack_eliciting_at + quic__pto(c, i);
      if (pto < t) t = pto;
    }
  }
  /* a client before confirmation probes even with nothing in flight: the server may be blocked by its
   * anti-amplification limit until it hears from us (RFC 9002 §6.2.2.1) */
  if (c->client && !c->confirmed && !c->bytes_in_flight && c->last_send_at) {
    int64_t pto = c->last_send_at + quic__pto(c, QUIC_SP_HANDSHAKE);
    if (pto < t) t = pto;
  }
  if (c->pace_blocked) { /* the time the bucket holds a packet again: then quic_send */
    double need = c->mtu - c->pace_tokens, rate = quic__pace_rate(c);
    int64_t pt = c->pace_at + (int64_t)(need / rate) + 1;
    if (pt < t) t = pt;
  }
  return t;
}
static inline void quic_on_timeout(quic_conn *c, int64_t now) {
  if (c->draining || c->closing) return;
  /* idle: close silently */
  if (now >= c->idle_deadline) {
    c->draining = 1, c->close_deadline = now;
    return;
  }
  int fired = 0;
  for (int i = 0; i < QUIC_NSP; i++) {
    quic_space *sp = &c->sp[i];
    if (sp->loss_time && sp->loss_time <= now) quic__detect_lost(c, i, now), fired = 1;
  }
  if (fired) return;
  for (int i = 0; i < QUIC_NSP; i++) {
    quic_space *sp = &c->sp[i];
    if (sp->discarded || !sp->have_tx || !sp->nsent) continue;
    int inflight = 0;
    for (uint32_t k = 0; k < sp->nsent && !inflight; k++)
      inflight = quic__sent_at(sp, k)->ack_eliciting && !quic__sent_at(sp, k)->acked;
    if (inflight && sp->last_ack_eliciting_at + quic__pto(c, i) <= now) {
      fired = 1;
      c->pto_count++, c->probes_due = 2;
      if (c->pto_count >= 3 && c->mtu > QUIC_SEND_MAX) /* the bigger datagrams may be black-holed: back down */
        c->mtu = QUIC_SEND_MAX, c->pmtu_done = 1;
      /* resend what is outstanding in that space as the probe's payload */
      for (uint32_t k = 0; k < sp->nsent; k++) {
        quic_sent *p = quic__sent_at(sp, k);
        if (p->acked || p->lost || !p->ack_eliciting) continue;
        for (int f = 0; f < p->nf; f++) quic__frame_lost(c, sp, &p->f[f]);
      }
      break;
    }
  }
  if (!fired && c->client && !c->confirmed && !c->bytes_in_flight && c->last_send_at &&
      c->last_send_at + quic__pto(c, QUIC_SP_HANDSHAKE) <= now)
    c->pto_count++, c->probes_due = 1; /* a PING (padded in an Initial) in the spaces we have keys for */
}
#endif
