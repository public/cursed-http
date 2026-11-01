#!/usr/bin/env python3
"""Planted bugs in include/quic.h: `make mutants-quic` builds tests/test_quic.c and
tests/test_quic_interop.c against each and expects every one to fail.
    python3 -I scripts/mutants_quic.py include OUTDIR"""
import os, shutil, sys
src, out = sys.argv[1], sys.argv[2]
shutil.rmtree(out, ignore_errors=True)
M = [
 ("quic.h", "0x38, 0x76, 0x2c, 0xf7", "0x38, 0x76, 0x2c, 0xf8"),                                   # Initial salt
 ("quic.h", "  uint8_t first = (uint8_t)(p[0] ^ (mask[0] & (p[0] & 0x80 ? 0x0f : 0x1f)));", "  uint8_t first = (uint8_t)(p[0] ^ (mask[0] & 0x1f));"),
 ("quic.h", "  if (cand + hwin <= expected && cand < (1ull << 62) - win) return cand + win;", "  if (cand + hwin < expected && cand < (1ull << 62) - win) return cand + win;"),
 ("quic.h", "          if (c->data_recv > c->max_data_local) { quic__error(c, QUIC_FLOW_CONTROL_ERROR, type); return -1; }", ""),
 ("quic.h", "  c->bytes_in_flight -= p->size;\n  if (p->sent_at <= c->recovery_start) return; /* in recovery */", "  if (p->sent_at <= c->recovery_start) return; /* in recovery */"),
 ("quic.h", "    if (uni) c->max_streams_uni_local++, c->send_max_streams_uni = 1;\n    else c->max_streams_bidi_local++, c->send_max_streams_bidi = 1;", "    ;"),
 ("quic.h", "    if (room < limit) limit = (size_t)room;", ";"),
 ("quic.h", "    c->key_phase ^= 1;", ";"),
]
for i, (f, a, b) in enumerate(M, 1):
    d = f"{out}/{i}"; os.makedirs(d)
    for x in os.listdir(src):
        if x.endswith(".h"): shutil.copy(f"{src}/{x}", d)
    s = open(f"{d}/{f}").read(); assert a in s, (i, a)
    open(f"{d}/{f}", "w").write(s.replace(a, b, 1))
print(len(M))
