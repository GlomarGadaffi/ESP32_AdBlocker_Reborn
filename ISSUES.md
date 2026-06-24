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

### L3 — daily reload clock drift ⬜
`dns_sink.cpp` — the 24×60 fixed-60 s reload loop drifts later each day.
Functional, cosmetic; left as-is (use absolute time if precision is wanted).

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

## Earlier fixes this cycle (pre-audit)
- `c42662b` — httpd stack overflow in `handle_status` (8 KB non-static local).
- `67114b9` — DNS timeout under load: `CONFIG_LWIP_SO_RCVBUF=y` + 32 KB
  SO_RCVBUF, dns_task stack 8192→12288, whitelist mutex `portMAX_DELAY`→2 ms.
