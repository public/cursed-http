#!/usr/bin/env python3
"""Planted bugs in include/h2.h / hpack.h: `make mutants-h2` builds tests/test_h2.c and test_hpack.c
against each and expects every one to fail. Usage: python3 -I scripts/mutants_h2.py include OUTDIR"""
import os, shutil, sys
src, out = sys.argv[1], sys.argv[2]
shutil.rmtree(out, ignore_errors=True)
M = [
 ("h2.h", ", c->conn_send_win -= (int64_t)m;", ";"),                                 # no connection flow control
 ("h2.h", "s->send_win -= (int32_t)m,", ""),                                          # no stream flow control
 ("h2.h", "uint8_t fl = last && fin_flag && !trl ? H2_FL_END_STREAM : 0;", "uint8_t fl = 0;"),  # END_STREAM lost
 ("h2.h", "    if (x->nclass != HP_N_OK) return 0; /* uppercase or invalid name */", "    if (x->nclass == HP_N_BAD) return 0;"),
 ("h2.h", "    if (!(fl & H2_FL_ACK)) h2__ctrl(c, H2F_PING, H2_FL_ACK, 0, pl, 8);", "    ;"),       # no PING ack
 ("h2.h", "    if (s->content_length >= 0 && (s->data_seen > s->content_length || (end && s->data_seen != s->content_length))) {", "    if (0) {"),
 ("h2.h", "    else if (s->recv_unacked >= 32768) h2__window_update(c, sid, s->recv_unacked), s->recv_unacked = 0;", "    ;"),
 ("h2.h", "    if (c->conn_recv_unacked >= H2_CONN_WINDOW / 2) h2__window_update(c, 0, c->conn_recv_unacked), c->conn_recv_unacked = 0;", "    ;"),
 ("h2.h", "        int64_t delta = (int64_t)v - c->peer_initial_window;", "        int64_t delta = 0;"),
 ("h2.h", "    if (q[3] != H2F_CONTINUATION || (h2__be32(q + 5) & 0x7fffffff) != sid) return h2__fail(c, H2_PROTOCOL_ERROR);", "    if (q[3] != H2F_CONTINUATION) return h2__fail(c, H2_PROTOCOL_ERROR);"),
 ("h2.h", "    size_t m = bl - off < c->peer_max_frame ? bl - off : c->peer_max_frame;", "    size_t m = bl - off;"),
 ("hpack.h", "  if (d->used + nl + vl > sizeof d->store) { /* compact: live strings total <= max - 32n */", "  if (d->used + nl + vl > sizeof d->store + 64) {"),
 ("hpack.h", "  while (d->n && d->size + want > d->max) {", "  while (d->n && d->size + want > d->max + 32) {"),
]
for i, (f, a, b) in enumerate(M, 1):
    d = f"{out}/{i}"; os.makedirs(d)
    for x in os.listdir(src):
        if x.endswith(".h"): shutil.copy(f"{src}/{x}", d)
    s = open(f"{d}/{f}").read(); assert a in s, (i, a)
    open(f"{d}/{f}", "w").write(s.replace(a, b, 1))
print(len(M))
