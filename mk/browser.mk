# ---- real browsers (tests/browser/): Chromium, Firefox and WebKit over loopback HTTP/1.1, via Playwright ----
#   make real-browsers      drive each browser through tests/browser/page.html; every request it sends is checked live
#                           (tests/browser/check.h) and then replayed under every backend. Needs python3-venv; the
#                           first run fetches Playwright (pinned in tests/browser/requirements.txt) and its browsers
#                           into the user cache. Their system libraries: PW_WITH_DEPS=1 (CI) runs
#                           `playwright install --with-deps` (sudo apt). BROWSERS="chromium firefox webkit" by default.
#                           BROWSER_SAVE=1 also refreshes the committed corpus, tests/browser/captures/.
#   make browser-replay     the committed corpus under every backend (no browser needed; part of make test). Strict (-s):
#                           every request answered the same by the fast path and fb_parse_req, no relaxed accepts
BR_DEPS := tests/browser/check.h $(HDRS) $(B)/pico.o
BR_INC := -Itests/browser
BR_T := native scalar emu512 emuzmm
BR_FLAGS_native :=
BR_FLAGS_scalar := -DFP_FORCE_SCALAR
BR_FLAGS_emu512 := -DFP_AVX512_EMU
BR_FLAGS_emuzmm := -DFP_AVX512_EMU -DFP_USE_ZMM
ifeq ($(ARCH),x86_64)
  BR_T += sse2
endif
BR_REPLAY := $(foreach t,$(BR_T),$(B)/browser_replay_$(t))
BR_CAPTURES := $(sort $(wildcard tests/browser/captures/*/*.http))
$(B)/browser_server: tests/browser/server.c $(BR_DEPS)
	$(CC_T) $(BR_INC) $< $(B)/pico.o -o $@
$(B)/browser_replay_sse2: tests/browser/replay.c tests/browser/check.h $(HDRS) $(B)/pico_base.o
	$(CC) $(CFLAGS) $(WARN) $(CHP_BASE) $(INC) $(BR_INC) $< $(B)/pico_base.o -o $@
$(B)/browser_replay_%: tests/browser/replay.c $(BR_DEPS)
	$(CC_T) $(BR_FLAGS_$*) $(BR_INC) $< $(B)/pico.o -o $@
browser-replay: $(BR_REPLAY)
	@set -e; for t in $(BR_REPLAY); do ./$$t -s $(BR_CAPTURES); done
real-browsers: $(B)/browser_server $(BR_REPLAY)
	BROWSERS="$(BROWSERS)" BROWSER_SAVE="$(BROWSER_SAVE)" PW_WITH_DEPS="$(PW_WITH_DEPS)" bash tests/real_browsers.sh
.PHONY: browser-replay real-browsers

# ---- the Tranco top-1k sites' requests (tests/top1k/, from scripts/top1k_crawl.py; see tests/top1k/README.md) ----
#   make top1k-replay   the corpus under every backend at the lengths next to a line end (part of make test, ~2 s each)
#   make top1k-focused  ... at every length where a decision can change (line ends, ':', SP, block edges)
#   make top1k-full     ... at every length, both paddings, both header-array sizes (~3 min per backend)
TOP1K := tests/top1k/requests.dat.gz
TOP1K_IX := tests/top1k/index.tsv
$(B)/top1k.dat: $(TOP1K) | $(B)
	gzip -dc $< > $@
top1k-replay: $(BR_REPLAY) $(B)/top1k.dat
	@set -e; for t in $(BR_REPLAY); do ./$$t -s -l -c $(B)/top1k.dat $(TOP1K_IX); done
top1k-focused: $(BR_REPLAY) $(B)/top1k.dat
	@set -e; for t in $(BR_REPLAY); do ./$$t -f -c $(B)/top1k.dat $(TOP1K_IX); done
top1k-full: $(BR_REPLAY) $(B)/top1k.dat
	@set -e; for t in $(BR_REPLAY); do ./$$t -c $(B)/top1k.dat $(TOP1K_IX); done
.PHONY: top1k-replay top1k-focused top1k-full
