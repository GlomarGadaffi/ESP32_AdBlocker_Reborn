# Firmware Audit — Findings & Status

Full-stack review of the ESP32-S3 DNS sinkhole firmware (ESP-IDF v6.0.1),
covering memory safety, concurrency, resource leaks, DNS protocol correctness,
robustness, and security. Each item below records the finding, the fix, and the
commit. Severity: Critical / High / Medium / Low.

Status legend: ✅ fixed · 🟡 mitigated (follow-up noted) · ⬜ open · ☑️ verified-correct (no bug)

---

## Critical

### C1 — Data race on custom-rules array ✅
`blocklist.c` — `custom_parse()` (httpd task) zeroed `s_custom_count` then
refilled `s_custom_entries[]` while `blocklist_custom_is_blocked()` read them
from the dns_task on every query. A concurrent reader could see a half-populated
table or run `strlen()` off a partially-written entry.
**Fix:** the custom-rules array now shares `s_wl_mutex` with the whitelist. The
reader takes it with a bounded 2 ms wait and fails open (forwards) on
contention; writers (`blocklist_custom_set`, `custom_load_nvs`) hold it across
`custom_parse`.

### C2 — DoT blocks the entire DNS task per query ✅
`dot.c` / `dns_server.cpp` — `dot_resolve()` did a synchronous TLS handshake +
round-trip inline in the single-threaded dns_task loop. While it ran, no other
query was serviced and upstream UDP replies weren't drained.
**Fix (`e85f61a`, #5):** a dedicated worker task (8 KB stack, Core 0) owns one
persistent RFC 7858 session. `dns_task` enqueues raw queries
(`dot_enqueue`) and drains raw replies (`dot_reply_get`) in its `select()`
loop without blocking. Replies flow through the same
validation/delivery/cache code as plain-UDP upstream replies
(`process_reply()`, factored out of the UDP drain), so H2's qname/qtype checks,
TCP handback, `refresh_only`, and caching apply identically to both
transports. On TLS failure the worker echoes the query back flagged failed and
`dns_task` re-sends it over plain UDP (same fallback contract as before, 3 s
table eviction as the outer net); first failure after idle is treated as a
server-closed session and retried once after reconnect. The old inline
1500 ms-timeout mitigation and the synchronous `dot_resolve()` are both gone.
DoT remains opt-in and off by default.

---

## High

### H1 — `handle_status` snprintf accumulator underflow ✅
`web_ui.cpp` — `n += snprintf(page+n, sizeof(page)-n, …)` repeated ~12×. Once
`n >= 8192`, `sizeof(page)-n` (size_t) underflows to a huge value and `page+n`
points past the buffer — same crash class as the httpd stack overflow fixed in
`c42662b`.
**Fix:** added a bounded `page_appendf(buf, cap, &pos, fmt, …)` helper that
clamps `pos` to `cap-1` on truncation, making every later call a safe no-op.
Converted all accumulator call sites in `handle_status`, `handle_log`,
`handle_top`.

### H2 — Upstream UDP replies not validated against the question ✅
`dns_server.cpp` — replies were matched only on a 16-bit txid that was handed
out *sequentially* (`s_txid_counter++`), making cache poisoning by an off-path
attacker feasible within the timeout window.
**Fix:** (1) txids are now drawn from the hardware RNG (`esp_random()`), re-rolled
on the rare in-flight collision; (2) on each upstream reply we extract the
reply's question and require its `qname` hash **and** `qtype` to match the
pending entry before delivering or caching — mismatches are ignored without
freeing the slot, so the genuine reply can still arrive.

### H3 — ACL / rewrite state mutated from httpd, read from dns_task ✅
`acl.c`, `rewrite.c` — swap-remove (`s_ips[i]=s_ips[--count]`) could let a
concurrent reader skip an entry, read a duplicate, or read a torn 64-byte
struct.
**Fix:** added a mutex to each module. The reader hot paths (`acl_permits`,
`rewrite_lookup`) keep a **lock-free fast path** for the common empty-table case
and otherwise take a bounded 2 ms lock; removals now shift-down instead of
swap-remove; NVS writes happen **outside** the lock so the reader never blocks on
flash. On lock contention `acl_permits` allows the query through (avoids
wrongly denying every client during a config edit).

---

## Medium

### M3 — query_log top-N / ring read without sync ☑️
`query_log.c` — torn reads are possible but every `key[64]` is NUL-terminated by
snprintf and HTML-escaped before display, so the worst case is a cosmetic wrong
row in the UI, not a safety issue. Acceptable for a telemetry path. No change.

### M4 — radix_sort reuses the live buffer as scratch ☑️
`blocklist.c` — guarded by nulling `s_live` + a 2 ms RCU quiescence delay before
the old buffer is reused. A binary search over the list is microseconds, so 2 ms
is generous; during the window queries fail open (forward upstream). Timing
assumption documented; no change.

### M5 — esp_tls handle lifecycle ☑️
`dot.c` — every error path calls `esp_tls_conn_destroy(tls)`. Verified no leak.

---

## Low

### L1 — CSRF check used substring match ✅
`web_ui.cpp` — `strstr(origin, host)` accepted `http://<host>.evil.com`.
**Fix:** new `origin_host_matches()` requires the host to appear immediately
after `://` and be terminated by `:`, `/`, or end-of-string. Empty-Origin +
empty-Referer still passes (plain same-origin form with no Origin sent) — a
documented LAN-device tradeoff.

### L2 — `handle_rw_set` ignored sscanf result ✅
`web_ui.cpp` — a malformed IP could yield a bogus-but-nonzero rule.
**Fix:** require `sscanf(...) == 4` and each octet ≤ 255.

### L4 — dead empty constructor in dot.c ✅
Removed the no-op `__attribute__((constructor)) dot_load_nvs()`.

### L5 — compression pointer accepted in question QNAME ✅
`dns_server.cpp` — `extract_qname()` tolerated a compression pointer in the
question section (malformed per RFC 1035). Now rejected, matching the stricter
L2 fast-path parser.

### L3 — daily reload clock drift ✅
`dns_sink.cpp` — the old "sleep 24h then reload" loop drifted later each day by
the download/sort duration.
**Fix:** the daily reload now uses an absolute monotonic deadline advanced by
exactly one interval each cycle (`next_us += interval`), so reload duration no
longer pushes the schedule; a manual `/reload` fires immediately without
shifting the daily deadline.

---

## Verified correct during the audit (no change needed)
- DNS wire parsing bounds — `extract_qname`, `l2_qname`, `skip_name` validate
  label lengths, reserved bits (#42), compression-pointer 2nd-byte bounds (#27),
  and `raw[256]` overflow; `skip_name` cannot loop infinitely.
- TC/truncation handling, and truncated responses excluded from caching (#36).
- PSRAM alloc failure paths (`blocklist_init`, cache init, `query_log_init`).
- murmur3 / domain_normalize / radix_sort bounds.
- Task stack sizing — dns_task 12288 (HWM ~7.7 KB free), httpd 16384.

---

## Feature: L2 fast-path for cache hits ✅
Forward-cache hits previously went through the lwIP socket path (dns_task),
capping cached throughput at ~600 qps. Extended the L2 eth-RX hook to replay
forward-cache hits directly (build frame + esp_eth_transmit), bypassing lwIP
entirely — like blocked queries already did. Cross-task safety via a seqlock
(`dns_cache_l2_get`): the dns_task is the only writer, the eth-RX task reads
through the seqlock and bails to lwIP on any write-race. New `/metrics` field
`l2_cached`. Verified on hardware: cached throughput ~600 → **~2,100 qps**
(matching the blocked path), 26,586 concurrent L2 reads vs cache writes with
ZERO corruption, c=1 latency unchanged (SPI-bound). See also the release-build
perf pass (-O2 + NDEBUG, 32KB I-cache) which halved CPU-bound lookup
(128→64 us) and lifted blocked throughput ~1,200 → ~2,200 qps.

## Feature: NTP wall-clock timestamps ✅
Query-log entries previously carried only seconds-since-boot, useless for
reconciling logs to real dates after a reboot.
**Added:** a `timesync` module using the built-in lwIP SNTP client (one UDP
socket, ~1 KB — the lightweight Espressif-native path) against `time.nist.gov`
+ `pool.ntp.org` (`CONFIG_LWIP_SNTP_MAX_SERVERS=2`). `QLogEntry` now stores a
wall-clock `epoch_s` (0 until synced) alongside the monotonic `ts_s`; `/log`
renders real `MM-DD HH:MM:SS` UTC times (falling back to uptime until synced),
and the dashboard shows clock status. The per-minute history graph stays keyed
on the monotonic clock so it's unaffected when NTP first sets the time.
Verified on hardware: clock synced to NIST within seconds of boot; log shows
dated entries (2026-06-24 14:20 UTC).

## Feature: blocklist reload cadence 24h → 4h ✅
Daily reload meant up to 24h of drift against upstream list updates (relevant
given the live OISD list already grew past a board's SD-cached snapshot by
~170k domains — see the apex-ad-domain investigation above).
**Changed:** `download_task`'s reload interval from 24h to 4h. Scheduling
itself stays on the monotonic `esp_timer` deadline (unaffected by NTP
re-sync jumps — the same reason L3's absolute-wall-clock loop was replaced);
`timesync_epoch()` is used only to log a real UTC timestamp on each reload,
once the clock has synced.

## Feature: runtime network configuration + tabbed web UI ✅ (#52)
Wi-Fi credentials, interface addressing, and network selection were all
build-time constants; changing any of them meant a reflash.
**Added:** (a) Wi-Fi credentials moved from Kconfig to NVS, with Kconfig kept
only as a first-boot seed (#54); (b) in-browser AP scan and connect, so the
device can be moved between networks without a toolchain (#54); (c) per-
interface DHCP vs static IP with its own DNS field, persisted in NVS and
applied at boot (#55); (d) the single long status page split into tabs
(Dashboard / Blocklist / Network / Access / Upstream DNS), with the active tab
kept in `location.hash` so the 10s auto-refresh doesn't bounce you back to the
first one. mDNS (`esp32adblock.local`) already worked and needed no changes.

## Audit round 2 — findings on the #52 work ✅
Review of the above before it landed; all five fixed in the same commit.

### R1 — static IP published before the link is up ✅ (#56)
`dns_sink.cpp` — `ETH_GOT_IP_BIT`/`WIFI_GOT_IP_BIT` were raised at *config*
time, before `esp_eth_start()`/`esp_wifi_start()`. A static netif never fires
`IP_EVENT_*_GOT_IP`, so the bit does have to be raised by hand — but doing it
that early made `app_main` declare the network ready and point upstream DNS at
the static gateway while the link was still down. Reproduced on hardware with
the Ethernet port empty: `Upstream re-pointed to 192.168.50.1`, `Network ready
— Ethernet: 192.168.50.10`. Wi-Fi coming up 2.3 s later masked it; on an
Ethernet-only build upstream stays pinned to an unreachable gateway and every
forwarded query times out — the same dead-end class as the CGNAT gateway bug.
**Fix:** `publish_static_eth()`/`publish_static_wifi()`, called from the
`ETHERNET_EVENT_CONNECTED`/`WIFI_EVENT_STA_CONNECTED` handlers; the addresses
are also cleared again on link loss. Verified: same config now reports
`Ethernet: (down)` and waits for a real interface.

### R2 — boot blocklist download failure never retried ✅ (#57)
`dns_sink.cpp` — `download_task` discarded `blocklist_load()`'s return (a
domain count, 0 = failure), so a failed boot download left the sinkhole
answering everything as ALLOWED until the 4h reload, silently. R1 made this
materially easier to hit by starting the download against a dead interface.
**Fix:** 15 s / 60 s / 300 s backoff retries, plus an explicit `ESP_LOGE` if
the list is still empty afterwards.

### R3 — reconfigure guard cleared before the disconnect event ✅ (#58)
`dns_sink.cpp` — `s_wifi_reconfiguring` was cleared synchronously after
`esp_wifi_set_config()`, but `esp_wifi_disconnect()` is asynchronous, so the
`STA_DISCONNECTED` handler could see it already false and fire a duplicate
`esp_wifi_connect()`. Benign (the new config had already been applied) but the
flag wasn't doing what its comment claimed. **Fix:** held until
`WIFI_EVENT_STA_CONNECTED`, with a 15 s deadline so a bad SSID can't suppress
auto-retry permanently.

### R4 — `/wifi/scan` was an unauthenticated GET with a radio side effect ✅ (#59)
`web_ui.cpp` — driving the radio from a GET bypassed `csrf_ok()` and was
triggerable cross-origin; IDF warns a long scan can knock the STA off its AP.
**Fix:** moved to POST behind `csrf_ok()`, client `fetch` updated to match.

### R5 — status-page buffer headroom after tabs ✅ (#60)
`web_ui.cpp` — the tabbed markup took the page to ~8.4 KB with every user table
still empty; `page_appendf` clamps silently (H1), so a fully-populated device
would truncate mid-markup and leave unbalanced `<div>`s, presenting as dead
tabs rather than an error. **Fix:** `page[]` 12288 → 16384 and an `ESP_LOGW`
when the cap is actually hit, so it fails loudly next time.

## Concurrency: multiple simultaneous web-UI viewers ☑️ / ✅ (#61)
Checked whether the dashboard is safe with several people watching it at once.

`esp_http_server` runs a **single** task — one `select()` loop walking sessions
sequentially — so requests are serialised, never parallel. That is what makes
the `static char page[16384]` render buffer (and the `static` buffers in
`/metrics`, `/log`, `/top`, `/wifi/scan`) safe: **this is load-bearing**, and
adding a worker pool would turn them into a cross-viewer data race.

Measured on hardware: 12 simultaneous page loads all returned byte-identical,
well-formed pages; 6 viewers hammering `/` produced 186 loads with **0**
corrupt. Critically, DNS service is unaffected by web load — **0/150 queries
lost**, p50 5.98 ms → 6.96 ms (that delta is Wi-Fi airtime, not board CPU;
on-device processing stays in the microseconds).

Two limits followed from the single-task design; the first is now fixed
(see #62 below), the second is a deliberate trade:
* **Head-of-line blocking.** Anything slow stalls every viewer. A Wi-Fi scan
  measured 3.16 s, and a page load issued during it took 2.63 s vs 0.50 s idle.
  With 6 viewers page p99 reached 1.08 s. **Fixed in #62.**
* **Socket ceiling.** `max_open_sockets` stays at the default 7 —
  `CONFIG_LWIP_MAX_SOCKETS` is 16 and httpd already claims ~9, so raising it
  risks starving the DNS server's own sockets, a far worse failure than a slow
  dashboard.

**Fixed:** `lru_purge_enable = true`, so a client that disappears mid-request
gets its slot recycled instead of refusing new connections until the timeout
expires. Verified no regression (10 half-open sockets: 200 OK in 0.21 s, vs
0.25 s before). Note this hardens against stuck clients, not against a
deliberate flood: 15 concurrent half-open sockets still failed 2 of 6 requests,
recovering fully afterwards.

## Fix: Wi-Fi scan no longer blocks the web UI ✅ (#62)
The blocking `esp_wifi_scan_start()` ran inside the httpd task, and since that
server is single-tasked (above), one scan stalled *every* viewer for its whole
duration.

**Fixed:** a one-shot worker task does the scan and publishes rendered JSON to
a cached buffer. `POST /wifi/scan` only triggers and returns immediately;
`GET /wifi/scan` reads the cache — a pure read, so no CSRF and no radio work,
which also lets the page repopulate results after the 10 s meta-refresh instead
of losing them on every reload.

**This buffer is the one exception to the single-task rule.** It's written by
the worker and read by httpd, so it is genuinely cross-task and is
mutex-protected; the lock is held only for the render and the read, never
across the scan itself. A second viewer pressing Scan joins the scan already in
flight rather than stacking radio work, and scans are refused while a
reassociation is in progress.

Verified on hardware:

| | before | after |
| --- | --- | --- |
| page load during a scan | 2.63 s | **0.21–0.29 s** (idle is 0.23 s) |
| `POST /wifi/scan` returns in | 3.16 s | **0.35 s** |
| page p99, 6 concurrent viewers | 1.08 s | **0.26 s** |
| 12 parallel loads well-formed | 12/12 | 12/12 |

DNS is unaffected: **0/60 queries dropped** before, during *and* after a scan.
Query p99 does rise to ~367 ms while a scan is running — that's the radio
channel-hopping off the home channel, not a firmware stall — and it returns to
~50 ms as soon as the scan finishes.

## Fix: tabs reset to Dashboard every 10s ✅ (#63)
Reported from actual use: a tab would hold for only a second or two before the
page snapped back to Dashboard. The `<meta http-equiv="refresh" content="10">`
reload dropped the URL fragment, losing the tab selection — and on the config
tabs the same reload discarded anything half-typed into a form (Wi-Fi password,
static IP, custom rules), which was the more damaging half of the bug.

**Fixed:** meta refresh removed. Refresh is JS-driven via `location.reload()`
(which *does* keep the fragment) and is armed **only while the Dashboard is
showing** — that's the only tab with live counters, so the config tabs now
never auto-reload out from under an edit. The selected tab is also mirrored
into `sessionStorage`, so it survives even a navigation that drops the
fragment; the fix therefore doesn't depend on fragment-preservation behaviour
at all. The Dashboard states the behaviour inline so it isn't surprising.

Worth noting the original tabs shipped believing hash-preservation worked
across a meta refresh — it doesn't, and that only surfaced in real use. Markup
that validates structurally can still behave wrong in a browser.

## Roadmap: generic ESP32-S3 build (Wi-Fi only) ⬜
A variant for any plain ESP32-S3 dev board — drops the W5500/Ethernet + SD-card
dependencies and runs the same sinkhole over built-in Wi-Fi (STA + DHCP). The
DNS engine, blocklist, forward cache, web UI, DoT, NTP, and query log are all
hardware-agnostic and carry over unchanged. Changes: Wi-Fi bring-up replaces the
W5500 init; the L2 Ethernet fast-path (esp_eth RX hook) has no Wi-Fi equivalent,
so blocked/cached queries take the normal lwIP socket path (~1.8 ms) instead of
the L2 bypass; blocklist capacity may shrink on quad-PSRAM boards. Tracked on the
GitHub issue tracker.

## Investigated: apex ad domains resolve ALLOWED ☑️ (not a bug)
Some headline ad domains (doubleclick.net, google-analytics.com,
googleadservices.com, adservice.google.com) resolve as ALLOWED while other
trackers (ssl.google-analytics.com, ads.youtube.com, analytics.tiktok.com) are
correctly BLOCKED. Originally logged as an open observation suspecting a
stale/partial SD cache or a source-format parsing bug.

**Root cause: none — this is the OISD list's own design, not a firmware bug.**
Fetched `https://big.oisd.nl/domainswild2` directly (494,654 entries) and
confirmed the bare apex domains (`doubleclick.net`, `ads.google.com`,
`googleadservices.com`, `adservice.google.com`) are **not present as their own
entries** in the current, live source — only specific subdomains are (e.g.
`accounts.doubleclick.net`, `ad-ace.doubleclick.net`, ~129 doubleclick.net
subdomains total). The list's own documented semantics ("entry `example.com`
blocks `example.com` and its subdomains") only flow downward from a listed
entry; a listed subdomain implies nothing about its parent. OISD's curators
deliberately don't blocklist these apex domains, likely because they also
carry legitimate traffic.

Verified the firmware's matcher is correct in both directions on-device:
`ad-ace.doubleclick.net` (genuinely listed) resolves `0.0.0.0`/`::`
(sinkholed); `doubleclick.net` itself correctly returns ALLOWED via
`POST /check`, consistent with never being a list entry. `on_domain_line` /
`domain_normalize` need no changes.

Separately (not the cause of this symptom, but worth noting): the board's
SD-cached list had 325,919 domains vs. 494,654 in the current live source —
a genuinely stale cache. A `/reload` (or the new 4h reload cadence) picks up
the newer list.

## Earlier fixes this cycle (pre-audit)
- `c42662b` — httpd stack overflow in `handle_status` (8 KB non-static local).
- `67114b9` — DNS timeout under load: `CONFIG_LWIP_SO_RCVBUF=y` + 32 KB
  SO_RCVBUF, dns_task stack 8192→12288, whitelist mutex `portMAX_DELAY`→2 ms.

---

## Architecture Review Feedback

Based on an external review of the audit findings, the architectural approach aligns closely with embedded C and ESP-IDF best practices:

* **Concurrency (C1 & H3):** Excellent use of bounded lock waits (e.g., 2 ms) and failing open (forward upstream). This prevents priority inversion and system stalls. **Caveat (H3):** Ensure the lock-free fast path uses proper atomic barriers (e.g., `__atomic_load_n` or `std::atomic`) if state is mutated from another core.
* **DNS Validation (H2):** Using hardware RNG (`esp_random()`) for TXIDs and validating `qname`/`qtype` effectively mitigates Kaminsky-style off-path cache poisoning.
* **String Handling (H1 & L1):** Replacing `snprintf` accumulators with a clamped wrapper prevents buffer overflows. **Caveat (H1):** Ensure `page_appendf` guarantees strict null-termination on truncation.
* **L2 Fast-Path Seqlock:** The seqlock is an advanced and correct primitive here, protecting high-frequency lock-free reads without thrashing cache lines with atomic writes.
* **Blocking DoT (C2):** The 1.5s timeout prevents a total DoS, but blocking the main `dns_task` for a TLS handshake remains an anti-pattern. The documented follow-up (moving it to a dedicated worker task fed by a queue) is the correct architectural fix. **Done — see C2 above (`e85f61a`, #5).**


---

## 2026-08-26 — silent capacity truncation (fixed, `c85bdcc`)

`on_domain_line` skipped every entry past `BLOCKLIST_CAPACITY` with no
counter, no log, no metric — a feed mix over capacity reported a healthy
domain count while silently not loading the tail (the same failure shape as
the wave-1 silent-corruption bug: the number looks fine, the blocking isn't).
With OISD + AdGuard + hagezi Ultimate + TIF-medium the raw union is ~1.04M
against a 780k buffer, so ~260k entries were being dropped invisibly.

Fix, three parts:
1. **Dedup-aware loading** — after the primary's fetch it is qsort'd + deduped
   in place (no O(n) scratch; the live buffer must keep serving during the
   fetch), and each extra-list entry binary-searches that prefix before being
   appended. Capacity now binds on the union, not the sum: the four-source mix
   peaked at 778,569 and went live as 711,780 domains, dropped = 0.
2. **Dropped counter** — anything past capacity increments a counter surfaced
   in the UI (warning banner), the log (`CAPACITY EXCEEDED`), and `/metrics`
   (`blocklist_dropped`).
3. **Capacity 780k → 820k** — margin over the measured peak; the +320 KB PSRAM
   came from a measured 1.45 MB free (mbedTLS also allocs there since the TLS
   fix), leaving ~1.13 MB.

Also removed the UI's suggested `domains/tif.txt` feed: ~2.1M lines, could
never fit, and would have exercised exactly this silent truncation. Two
different things were previously conflated here (fixed, F12): the
`domains/` → `wildcard/` switch is a lossless FORMAT change — identical
coverage under suffix-walk matching, just a smaller encoding of the same
list — while `tif` → `tif.medium` is a deliberately REDUCED TIER of hagezi's
TIF feed, not full TIF in a cheaper encoding. The new presets use the
`wildcard/` variants throughout, and `tif.medium` (≈326k) specifically for
the threat-intel preset, labeled as "TIF medium" so the distinction is
visible in the UI.

---

## 2026-08-27 — pause-blocking toggle (feature parity vs upstream), plus two bugs found while adding it (flashed + verified on hardware, uncommitted)

**Feature: global pause/resume switch (closes the whole-device half of #48).**
Upstream s60sc/ESP32_AdBlocker has always had a single "Enable AdBlocker"
checkbox; Reborn had no equivalent — every query was either blocked or
forwarded, with no way to suspend blocking without clearing the whole
blocklist. `blocklist_set_paused()`/`blocklist_is_paused()` (`blocklist.c`)
add an `_Atomic bool` gate checked at the top of `is_blocked_impl()` (shared
by `blocklist_is_blocked`/`_nb`, so both the socket path and the L2 Ethernet
fast path honor it identically — no chance of it silently working on one
path and not the other) and at the top of `blocklist_custom_is_blocked()`
(a separate function, not routed through `is_blocked_impl`, so it needs its
own check to make "paused" mean *all* blocking off, matching upstream's
single global switch rather than leaving custom rules still enforced).
NVS-persisted (`paused` key, `dns_sink` namespace), survives reboot —
verified: paused, hard-rebooted via `/reboot`, `/metrics` still read
`blocklist_paused:true` after boot. Dashboard gets a `Pause blocking` /
`Resume blocking` button next to Reload, and the status chip shows "Paused"
(ranked above "Degraded" — a deliberate user action shouldn't be masked by an
incidental one, both below the transient "Reloading"). `/metrics` gains
`blocklist_paused`. Verified end-to-end over HTTP and with real DNS queries:
`ssl.google-analytics.com` BLOCKED → paused → ALLOWED (`/check` and live
resolution both) → resumed → BLOCKED again.

**Bug found while adding it, fixed: `wl_save_nvs()` erased the ENTIRE
`dns_sink` NVS namespace on every whitelist add/remove — blast radius is
larger than first recorded here.** `blocklist.c` — whitelist, extra
blocklist-source URLs (`bl_url_%d`), custom block rules (`custom_blk`), and
now `paused` all share the `dns_sink` NVS namespace in `blocklist.c`.
**Correction:** so does `dns_sink.cpp` (`#define NVS_NS "dns_sink"`, same
literal) — Wi-Fi SSID/password, per-interface static-IP config, and the
upstream-interface selection all live in the *same* namespace. `wl_save_nvs()`
called `nvs_erase_all(h)` before rewriting the `wl%d` keys, wiping every
other key in the namespace — so adding or removing a single whitelist entry
silently deleted any configured extra blocklist-source URLs, saved custom
block rules, **and the board's saved Wi-Fi credentials and static-IP/upstream
config**, falling back to the Kconfig-seeded defaults on next boot. Also
DoT's `dot_en`/`dot_srv`/`dot_sni` (`dot.c`, same namespace). Reproduced the
narrower case: set an extra URL, added a whitelist entry, extra URL was gone.
Every headline multi-source/config feature in this codebase sharing one
namespace with the whitelist made this reachable in completely ordinary use,
not an edge case. **Fix:** erase only the `wl0`..`wl{WHITELIST_MAX-1}` key
range via `nvs_erase_key()` before rewriting, so a shrinking whitelist still
drops its stale tail without touching unrelated keys. Verified: added an
extra URL + a whitelist entry, both survived; had this been the old code, the
URL would have vanished (and, per the wider radius above, Wi-Fi credentials
would have too, in the field).

**Bug found while adding it, fixed: `POST /check` never consulted custom
block rules.** `web_ui.cpp` `handle_check()` computed `blocked` from
`blocklist_is_blocked()` alone; the real verdict path in `dns_server.cpp`
always checks `blocklist_is_blocked() || blocklist_custom_is_blocked()`. A
domain blocked only via a custom rule (not the main list) genuinely
sinkholed on the wire but showed **ALLOWED** on `/check` — the tool meant to
verify a rule couldn't verify its own kind of rule. Caught because pausing
made a custom-rule domain read ALLOWED for the wrong reason (pause hadn't
shipped yet in that check), which led to testing the *unpaused* case and
finding it was already wrong. **Fix:** `handle_check` now OR's in
`blocklist_custom_is_blocked()`, matching `dns_server.cpp` exactly. Verified:
added a custom rule for a domain not on any list, `/check` now says BLOCKED,
and a real `nslookup` against the board resolves it to `0.0.0.0`/`::`.

Also updated stale docs found in the same pass: README/ISSUES both still
described DoT as running synchronously in `dns_task` with a 1.5 s inline
timeout (C2 "mitigated, follow-up open") — that follow-up shipped weeks ago
(`e85f61a`, worker task + persistent TLS session, closes C2). Marked ✅ in
both files; the code was already correct, only the docs had drifted.

---

## 2026-08-27 (session 2) — closing the rest of feature parity: auth, setup AP, OTA, stop-load (flashed + verified on hardware, uncommitted)

Continuation of the same-day parity pass above. A reviewer correctly pushed
back that closing one gap (pause/resume) while explicitly listing the rest as
deferred didn't satisfy "feature parity" — so the rest got built, not argued
away. See the README's new **Feature parity with upstream** table for the
full checklist; this entry has the implementation and verification detail.

**Optional web UI login (`web_ui.cpp`).** HTTP Basic Auth behind a single
`auth_wrap()` trampoline — every `httpd_uri_t` now routes through it with the
real handler stashed in `user_ctx`, so login is enforced in one place rather
than duplicated at the top of ~26 handlers (same "policy in shared code, not
per-call-site" reasoning as the blocklist verdict path). Empty username (the
default) disables it entirely, matching upstream's optional Auth_Name/
Auth_Pass. NVS-persisted in the same `dns_sink` namespace, new keys
`http_user`/`http_pass`. **Verified on hardware, deliberately including the
lockout-risk path:** enabled it, confirmed unauthenticated requests 401 and
wrong credentials 401, confirmed correct credentials 200, confirmed it
survives a real `/reboot`, then disabled it again with the (still-live)
credentials and confirmed the board was left open. No recovery path if
forgotten short of an NVS erase — noted in the README, same as upstream which
has none either.

**Setup AP for zero-touch first-boot Wi-Fi (`dns_sink.cpp`).** Found while
implementing this: `app_main`'s wait for a network link used
`xEventGroupWaitBits(..., portMAX_DELAY)` — a board with no Ethernet cable
AND no working Wi-Fi credentials (blank first boot, or a changed home
network) hung there **forever**, before `web_ui_start()` ever ran. The only
recovery was the USB serial console's `wifi` command, which needs physical
access — Reborn had no equivalent to upstream's AP-mode bootstrap at all.
**Fix:** the wait is now bounded (`WIFI_SETUP_AP_TIMEOUT_MS`, 30s, close to
upstream's own `wifiTimeoutSecs` default); on timeout, `start_setup_ap()`
brings up an open SoftAP (`WIFI_MODE_APSTA`, so STA keeps retrying and
Ethernet is untouched) at the esp-netif default 192.168.4.1. No separate
captive-portal page was built: `esp_http_server` already listens on all
interfaces, so a phone joining the AP reaches the *same* dashboard and can
enter real credentials via the existing Network tab (#54). Torn down
automatically (`stop_setup_ap_if_active()`) the moment any interface gets a
real IP — wired into `ip_event_handler`'s `IP_EVENT_ETH_GOT_IP` and
`IP_EVENT_STA_GOT_IP` branches. **Verification gap, disclosed rather than
hidden:** the board is PoE-powered over the same cable that carries its only
Ethernet link (see the poetest.sh section above), so pulling the cable to
exercise the "no link at all" path also cuts power and would have taken the
household's live DNS resolution down for an extended, uncontrolled test.
Verified instead by (a) code review against documented ESP-IDF APSTA
semantics, (b) confirming a *normal* boot with Ethernet present shows no
setup-AP banner and behaves identically to before (dashboard reachable
immediately, DNS working, no regression) — the common-case path this change
could most easily have broken. The AP-fallback branch itself remains
untested on real hardware; flagged here rather than claimed.

**Firmware update via the browser + dual OTA partitions (`web_ui.cpp`,
`dns_sink.cpp`, `sdkconfig`/`sdkconfig.defaults`, `main/CMakeLists.txt`).**
The single biggest-blast-radius change of the day: switched
`CONFIG_PARTITION_TABLE_SINGLE_APP_LARGE` → `CONFIG_PARTITION_TABLE_TWO_OTA_LARGE`
(ota_0/ota_1 @ 1700K each, replacing the old single 1500K app partition) and
enabled `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE`. `POST /ota/update` streams a
raw firmware binary (the UI sends the picked `File` object directly via
`fetch`, not multipart — no parsing needed) straight into
`esp_ota_write()`/`esp_ota_end()`, then `esp_ota_set_boot_partition()` +
reboot. Needed `app_update` added to `main`'s `CMakeLists.txt` `REQUIRES`
(missing this produced `fatal error: esp_ota_ops.h: No such file or
directory` — the header is provided by that component, not pulled in
transitively).
- **Rollback is the load-bearing safety net** for a device with no display
  and (this session) no physical access to recover it if an OTA image fails
  to boot. `app_main` calls `esp_ota_mark_app_valid_cancel_rollback()` once
  DNS serving and the web UI are both confirmed up — as good a health signal
  as this device has. Reviewed pre-flight (external check, not just
  self-review) surfaced a real gap: the two `for(;;) vTaskDelay(portMAX_DELAY)`
  halt-loops on init failure (PSRAM/blocklist init, DNS server start) would
  have **defeated** rollback — it only fires on the *next reset*, and a
  halted board never resets. Fixed with `halt_or_rollback()`: if the running
  partition is still `ESP_OTA_IMG_PENDING_VERIFY` (an unconfirmed OTA image),
  it calls `esp_ota_mark_app_invalid_rollback_and_reboot()` instead of
  halting; on an already-confirmed partition (hardware fault unrelated to
  OTA) it still just halts, since there's nothing safe to roll back to.
- **NVS survives the partition migration.** `nvs` is the first entry with no
  explicit offset in both the old and new partition CSVs, and
  `CONFIG_PARTITION_TABLE_OFFSET` (0x8000) didn't change, so it computes to
  the same address either way — verified, not assumed: ran
  `gen_esp32part.py` against the freshly built table and confirmed `nvs @
  0x9000 / 24K` before flashing anything. The one-time migration flash writes
  bootloader + partition-table + `ota_data_initial.bin` (0xf000) + app
  (0x20000, the new ota_0 offset) — four explicit regions, never touching
  0x9000–0xf000. Old single-app-layout files (`bootloader.bin`,
  `partition-table.bin`, `dns-sink.bin`, `dns-sink-known-good.bin`,
  `flash.sh`) were backed up to `~/firmware/pre-ota-backup/` on glolab
  *before* migrating, as the one-command full-rollback path.
- **`flash.sh`'s `app` mode would have corrupted the board on its next
  ordinary use.** It wrote to `0x10000`, which is now inside `otadata`
  (0xf000–0x10fff) and the head of `ota_0` — a habitual app-only re-flash
  after this migration would have corrupted otadata *and* the start of
  ota_0, boot-looping the board until a manual esptool rescue. Fixed before
  ever using it again: `app` mode now writes `ota_data_initial.bin @ 0xf000`
  **and** the app `@ 0x20000` every time. Rewriting otadata on every
  app-only flash is deliberate, not incidental — it makes esptool app-flashes
  deterministic (always boot the image just written) regardless of whatever
  OTA state the board's own `/ota/update` had last left behind.
- **Verified end-to-end on hardware, including the actual rollback
  confirmation, not just a happy-path upload:** full 4-region migration
  flash → `/metrics` up, blocklist count unchanged (715,057, SD warm-boot
  intact), Wi-Fi SSID/upstream-iface/extra-blocklist-URLs all survived in
  NVS, real DNS query resolved → uploaded the running binary via
  `/ota/update` → running partition flipped `ota_0` → `ota_1` → **`POST
  /reboot` and confirmed it stayed on `ota_1`** (the test that actually
  proves `mark_app_valid_cancel_rollback` ran — if it hadn't, the bootloader
  would have reverted to `ota_0` on this second boot) → uploaded the final
  build (with the stop-load fix below) the same way, flipped back to `ota_0`,
  confirmed it too survives a reboot.

**Stop an in-progress blocklist load (`blocklist.c`, upstream's `xStop`).**
`on_domain_line` checks a `s_stop_requested` flag and returns `false` on the
next line, which `http_fetch_lines` (and everything downstream of it in
`blocklist_load()`) already treats exactly like a dead feed — no new
"stopped" state needed, the old list keeps serving either way, same as any
other reload path.
- **Bug found in the FIRST version of this, before it ever shipped:**
  `blocklist_stop_load()` unconditionally set the flag, and
  `blocklist_load()` reset it to `false` at its own entry. `download_task`
  (`dns_sink.cpp`) only checks its "reload requested" flag once per second
  (`vTaskDelay(1000ms)` between checks), so a stop request landing in that
  ≤1s window — plausible for a human clicking Reload then Stop in quick
  succession, and exactly what happened testing this via curl 0.5s apart —
  got silently cleared by `blocklist_load()`'s own reset before the download
  even started, and the reload ran to completion uninterrupted. **Fix:**
  `blocklist_stop_load()` is now a no-op (logged, not silently dropped) if
  `blocklist_is_loading()` is false, turning the race into a well-defined
  "nothing to stop yet" instead of a request that looks accepted but quietly
  evaporates. **Verified against a GENUINELY in-progress reload** (not a
  synthetic one): triggered `/reload`, waited for `blocklist_loading:true`,
  called `/blocklist/stop`, watched it flip to `false` ~10-13s later with
  `blocklist_count` unchanged (715,057 — old list still serving) and DNS
  resolution unaffected throughout.

**How this session was different from the first:** an external review
(advisor) was consulted before touching the live board's partition table,
specifically because the blast radius (a device serving live household DNS,
reachable only over the network this session, no physical recovery access)
warranted a second opinion over solo judgment. Its three pre-flight items —
verify the generated partition table rather than trust the offset reasoning,
keep an untouched rollback kit before migrating, and fix `flash.sh` before
using it again — are the reason this landed without an outage.
