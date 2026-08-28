# Contributing

Small repo, no ceremony: read the constraints below before touching the query
path, keep comments factual, and don't leave a number in a doc you can't point
at in source. `ISSUES.md` is the running, code-grounded record of findings and
fixes — add to it rather than starting a new file.

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

The asymmetry that makes this safe is that **the L2 hook may only answer, never
allow**. It answers a query in exactly two cases — a BLOCK verdict from
`blocklist_is_blocked_nb()`, or a live forward-cache hit from
`dns_cache_l2_get()` — and *every other outcome falls through* to
`esp_netif_receive()`, where the socket path runs the full ladder
(`blocklist_is_blocked() || blocklist_custom_is_blocked()`, rewrites, ACL,
upstream forward). So the hook's cheaper check set is not a divergence: it is a
short-circuit that only fires where the full ladder would agree.

If you add a rule that can turn a BLOCK into an ALLOW — a new whitelist-like
exemption — it must be visible to `blocklist_is_blocked_nb()`, or the L2 hook
will sinkhole something the socket path would have let through. Adding a rule
that only ever creates *more* blocking (like the custom inline rules) is safe
to leave off the hook; it just doesn't get the fast path.

**Known gap, documented not fixed:** the L2 hook does not consult
`acl_permits()`, which appears only on the socket path. On the Ethernet
segment, a client not on the ACL still receives sinkhole replies and
forward-cache hits; only its cold queries reach the ACL gate. Wi-Fi clients
have no L2 hook and are always gated. Whether that is intended has not been
established — treat it as unverified rather than as sanctioned behavior.

### 2. Shared-cache coherence

The forward cache in `dns_server.cpp` is **global**. Anything transient or
per-client that gets consulted *inside* a function whose result is cached will
leak into every later client's answer. Two rules follow:

* **Global state → bump the generation.** `blocklist_generation_bump()` in
  `blocklist.c` increments `s_blocklist_gen`; every cache entry is stamped with
  the generation live at store time, and a lookup under a newer generation is
  treated as a miss. Today exactly two events bump it: a reload that swaps in a
  new live list (#85) and a pause flip (#86).

  Note that `blocklist_whitelist_add()` / `_remove()` and
  `blocklist_custom_set()` do **not** bump, even though `is_blocked_impl()`
  consults the whitelist inside the cached verdict. A cached BLOCK therefore
  survives a whitelist add, and a cached ALLOW survives a custom-rule add,
  until the entry's TTL expires. If you touch these paths, that is the bump
  they are missing.

* **Per-client state → never cache it.** A verdict that depends on the source
  address (ACL is the live example) must be evaluated outside the cached
  function, or split so the cacheable half carries no client identity.

### 3. Single-task httpd

`web_ui.cpp` starts one httpd instance and all 30 handlers run on it, serially.
`max_open_sockets` stays at the default 7 with `lru_purge_enable` on (#61):
raising it competes with the DNS server for `CONFIG_LWIP_MAX_SOCKETS`. Anything
slow in a handler blocks every other viewer — which is why the Wi-Fi scan was
moved to a worker task (#62). Long or blocking work belongs on a worker, with
the handler polling for the result.

### 4. `IRAM_ATTR` on definitions only

Tag the *definition*, never the declaration in the header. The L2 hook must
never fault to flash, so `l2_input_cb`, `l2_qname`, `is_blocked_impl`,
`dns_cache_l2_get` and `blocklist_generation` carry `IRAM_ATTR` at their
definitions (#78). `CONFIG_LWIP_IRAM_OPTIMIZATION` covers lwIP's own sources
only — it does not reach this callback, which `esp_eth` invokes through a
stored function pointer.

`domain_is_bare_tld()` and the whitelist callbacks reached from
`is_blocked_impl()` are *not* tagged. That is a known incomplete edge, not a
claim of full coverage.

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
