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

### C2 — DoT blocks the entire DNS task per query 🟡
`dot.c` / `dns_server.cpp` — `dot_resolve()` does a synchronous TLS handshake +
round-trip inline in the single-threaded dns_task loop. While it runs, no other
query is serviced and upstream UDP replies aren't drained.
**Mitigation:** inline DoT timeout cut from 3000 ms → **1500 ms**, bounding the
worst-case stall while still allowing a first handshake to complete; on timeout
the query falls through to plain-UDP upstream (slot draining resumes next loop).
**Follow-up (open):** move DoT to a dedicated worker task fed by a queue, or
keep a persistent/reused TLS session, so a slow DoT query can't stall other
clients at all. DoT is opt-in and **off by default**, so this is deferred rather
than blocking. Tracked here as the remaining half of C2.

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

## Open observation (separate from the audit) ⬜
Some headline ad domains (doubleclick.net, google-analytics.com,
googleadservices.com, adservice.google.com) resolve as ALLOWED while other
trackers (ssl.google-analytics.com, ads.youtube.com, analytics.tiktok.com) are
correctly BLOCKED. Blocking itself works (333,795 domains loaded, L2 + dns_task
block paths both active). The pattern (a subdomain blocks but its parent does
not) indicates those roots aren't wildcard entries in the currently SD-cached
list — likely a stale/partial cache or a source-format question, NOT a code
regression. Suggested next step: trigger a fresh `/reload` (bypasses SD cache)
and re-check; if still allowed, inspect the OISD source line format in
`on_domain_line`/`domain_normalize`.

## Earlier fixes this cycle (pre-audit)
- `c42662b` — httpd stack overflow in `handle_status` (8 KB non-static local).
- `67114b9` — DNS timeout under load: `CONFIG_LWIP_SO_RCVBUF=y` + 32 KB
  SO_RCVBUF, dns_task stack 8192→12288, whitelist mutex `portMAX_DELAY`→2 ms.
