# Contributing

Small repo, no ceremony: read the constraints below before touching the query
path, keep comments factual, and don't leave a number in a doc you can't point
at in source. Findings and fixes are tracked in GitHub Issues — open one
there rather than starting a tracking file in the repo.

Build and flash instructions are in the README. ESP-IDF v6.0.x, native
Windows, PowerShell `export.ps1` (Git Bash / MSYS is not a supported build
shell for this project).

## Architecture constraints

These four are the ones that have actually bitten. They are invariants, not
style preferences.

### 1. Two verdict paths that must agree

A query can be answered from either of two places, in different tasks:

* the **socket path** — `dns_task` in `main/dns_server.cpp`, and
* the **L2 fast path** — `l2_input_cb` in `main/dns_sink.cpp`, registered via
  `esp_eth_update_input_path_info()` and running in the Ethernet RX task.

The asymmetry that makes this safe is that **the L2 hook may only answer a query
it can classify exactly as the socket path would, and must otherwise hand the
frame over**. It answers in exactly two cases — a proven verdict from
`blocklist_verdict_nb()`, or a live forward-cache hit from
`dns_cache_l2_get()` — and *every other outcome falls through* to
`esp_netif_receive()`, where the socket path runs the full ladder
(ACL, rewrites, `blocklist_verdict()`, upstream forward). So the hook's cheaper
check set is not a divergence: it is a short-circuit that only fires where the
full ladder would agree.

**`blocklist_verdict{,_nb}()` (#117) is *the* verdict call, both paths.** It
resolves the feed block table, the NVS whitelist, and custom rules — including
`@@` exceptions and `$important` — into one rank-ordered answer instead of a
hand-copied boolean OR; there is no second ladder left to drift out of sync.
The `_nb` variant never blocks: it returns a proven verdict, or one of two
distinct defer signals (`BL_DEFER_LOCK_BUSY`, `BL_DEFER_SNAPSHOT` —
`dns_sink.cpp`'s `l2_defer_lock_busy` / `l2_defer_snapshot` counters, surfaced
in `/metrics`) that fold into the same `break`-to-lwIP rule as everything else
in this hook.

Everything the hook cannot vouch for `break`s, and every `break` means "let lwIP
have it" — never "drop it". That covers a header it will not trust, a lock it
cannot take without waiting, and a rule it must not render itself. Concretely,
before it will answer anything the hook requires: the frame to be a whole,
unfragmented IPv4/UDP datagram addressed to *our own* Ethernet address from a
source that could receive a unicast reply; lengths taken from the IP and UDP
headers rather than the (padded) frame; a single class-IN A/AAAA question; a
provable ACL pass from `acl_permits_nb()`; and no matching entry in
`rewrite_lookup_nb()`. The last two are tri-state on purpose — "denied" and
"lock busy" both defer, so a config edit in flight can never produce a wrong
answer, only a slower one.

If you add a rule that can turn a BLOCK into an ALLOW — a new whitelist-like
exemption — it must be visible to `blocklist_verdict_nb()`, or the L2 hook
will sinkhole something the socket path would have let through. A rule that
*changes* the answer rather than allowing it (rewrites) must make the hook
defer, not answer. **A custom or feed rule that only ever creates *more*
blocking is safe to leave off the hook — that half is still true — but it stops
being the whole story the moment the same table can also carry an ALLOW
(`@@`).** A BLOCK-kind entry costs the fast path nothing extra; an ALLOW-kind
entry rides the whitelist's single zero-wait take (`s_wl_mutex`, one take for
the whole suffix walk that also covers the custom-rule table — an empty
custom table just means a zero-iteration probe once that take succeeds) and,
if the take is busy, the hook defers unconditionally rather than trust an
unlocked read of whether an exception exists — see `blocklist_verdict_nb()`'s
own comment for why.

The ACL gap this file used to document — a non-ACL client still getting
sinkhole replies and cache hits over Ethernet — was #87, and is fixed.

### 2. Shared-cache coherence

The forward cache in `dns_server.cpp` is **global**. Anything transient or
per-client that gets consulted *inside* a function whose result is cached will
leak into every later client's answer. Two rules follow:

* **Global state → bump the generation.** `blocklist_generation_bump()` in
  `blocklist.c` increments `s_blocklist_gen`; every cache entry is stamped with
  the generation live at store time, and a lookup under a newer generation is
  treated as a miss. A reload that swaps in a new live list (#85), a pause
  flip (#86), and every whitelist/custom-rule mutation
  (`blocklist_whitelist_add()`/`_remove()`, `blocklist_custom_set()`, #88)
  all bump it, since `blocklist_verdict{,_nb}()` consults both tables inside
  the cached verdict. If you add a new source of state that
  `blocklist_verdict()` reads, this is the bump it needs.

* **Per-client state → never cache it.** A verdict that depends on the source
  address (ACL is the live example) must be evaluated outside the cached
  function, or split so the cacheable half carries no client identity.

### 3. Single-task httpd

`web_ui.cpp` starts one HTTPS httpd instance and all UI handlers run on it,
serially. `max_open_sockets` stays at the TLS default 4 with
`lru_purge_enable` on (#61): raising it competes with the DNS server for
`CONFIG_LWIP_MAX_SOCKETS`. Anything slow in a handler blocks every other
viewer — which is why the Wi-Fi scan was moved to a worker task (#62). Long or
blocking work belongs on a worker, with the handler polling for the result.

The `:80` redirect listener is a second httpd instance but not an exception
to the rule: it renders nothing, reads nothing, holds no state. The rule
exists so UI state has one writer — a server with no state has none.

Because there is one request in flight at a time, `auth_wrap` parses the
session cookie once into a file-static (`s_req_sid`) that handlers and
`csrf_ok()` read. That shortcut is only valid on a single-task httpd; if the
UI ever gets a second worker task, it becomes a race.

Security gates live in `auth_wrap` (setup wizard, session) and `csrf_ok()`
(origin + per-session token); see `docs/http-api.md`. Anything that proves
identity (passwords, the session cookie) only ever travels over the TLS
listener — never add a handler to the `:80` instance.

### 3a. Internal RAM is the scarce resource

The S3 has 8 MB of PSRAM and ~170 KB of usable internal heap after Wi-Fi,
lwIP, and the DNS server's hot-path state take theirs. `libmain`'s internal
`.bss` was 130 KB before #89. Anything internal that a TLS handshake or a
DMA driver can't get is a live outage (the W5500 driver logs
`Failed to allocate priv TX buffer` and Ethernet stalls). Rules:

- Cold, task-private buffers (page renderers, scan tables, one-shot work
  areas) get `EXT_RAM_BSS_ATTR` → PSRAM.
- Hot-path DNS state (`s_upstream`, cache, the L2 hook's scratch) stays
  internal.
- Measure with the USB console `heap` command before and after; `min-ever`
  is the number that matters.

### 4. `IRAM_ATTR` on definitions only

Tag the *definition*, never the declaration in the header. The L2 hook must
never fault to flash, so `l2_input_cb`, `l2_qname`, `blocklist_verdict_nb`,
`dns_cache_l2_get` and `blocklist_generation` carry `IRAM_ATTR` at their
definitions (#78, #117). `CONFIG_LWIP_IRAM_OPTIMIZATION` covers lwIP's own
sources only — it does not reach this callback, which `esp_eth` invokes
through a stored function pointer.

`bl_rank_resolve()`, its three rank-source probes (`feed_probe`,
`wl_probe_locked`, `custom_probe_locked`), `wl_contains_locked()`, and
`domain_is_bare_tld()` all sit on this path and carry `IRAM_ATTR` too
(#117) — this list is meant to be exhaustive for what the L2 hook can
reach; if you add a new probe or a function one calls, tag it here.

## Cross-task reads

`dns_task` is the only writer of the forward cache; the L2 RX task reads it
through a seqlock (`s_cache_seq`, odd during a write). A reader that sees an
odd or changed counter must treat it as a miss and fall through — never
retry-spin in the RX hook.

The RX hook takes the whitelist mutex non-blocking; the socket path uses a
bounded 2 ms take (#37). NVS commits always happen outside the lock.

## Docs

Every claim in `README.md`, `CHANGELOG.md`, and `docs/` should be checkable
against source, Kconfig, `sdkconfig.defaults`, or the build's own
`flash_args` — not against another doc. `docs/http-api.md` is generated by
hand from the `uris[]` table and `dns_server_metrics_json()`; if you add a
route or a metrics field, update it in the same commit.

Runtime numbers that depend on which feeds are loaded (domain counts) should
carry the feed set and a date, or be left out.
