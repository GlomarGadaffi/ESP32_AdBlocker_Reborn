# HTTP API reference

Every route below is served by the HTTPS httpd instance in `main/web_ui.cpp`
on **port 443** (self-signed cert from `main/web_tls.c`; port 80 is a
separate 2-socket listener that only 301s to `https://`). Every route
(including `GET /`) passes through `auth_wrap` first, which applies, in order:

1. **Setup gate** — while no admin account exists (`web_auth_setup_needed()`),
   every GET redirects to `/setup` and every POST gets 403, except `/setup`
   itself.
2. **Session gate** — without a valid `sid` cookie, GET → 303 `/login`,
   POST → 401. `/login` is exempt; `/setup` bounces to `/` once an account
   exists.
3. Security headers on every response: `Cache-Control: no-store`,
   `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
   `Referrer-Policy: same-origin`, and a CSP that allows only inline
   script/style and same-origin fetch/form targets. No HSTS (a self-signed
   cert plus HSTS would turn `cert-reset` into a year-long browser lockout).

CSRF is *not* in `auth_wrap`: each mutating handler calls `csrf_ok()` itself.
It requires **both** a same-origin `Origin`/`Referer` (when present) **and**
the session's CSRF token — `?csrf=<token>` in the query string (the page's JS
appends it to every form action on submit) or an `X-CSRF: <token>` header
(the page wraps `fetch()` to add it). The token is in the page as
`var CSRF='…'`. `/setup` and `/login` POSTs run before a session exists, so
they check Origin only (case-insensitive, port ignored; `Origin: null` falls
back to Referer). All mutating routes are covered — `/net/eth/set` and
`/net/wifi/set` inherit the check from the shared `handle_net_static_set()`
helper rather than calling it directly, so a naive per-handler grep
undercounts. If you add a POST handler, add the `csrf_ok()` call.

Scripting it: `curl -k -c jar -X POST -d 'user=U&pass=P' https://HOST/login`,
then `curl -k -b jar https://HOST/` and pull the token out of `var CSRF=`.

This is a trusted-LAN interface; don't expose it to the internet.

The route list is generated from the `uris[]` table in `web_ui.cpp`; the
metrics fields from `dns_server_metrics_json()` in `dns_server.cpp`.

## Routes

| method | path | purpose |
| --- | --- | --- |
| GET | `/setup` | First-boot wizard: certificate fingerprint + admin account form. Only while no account exists. |
| POST | `/setup` | Create the admin account (`user`, `pass`, `pass2`); opens a session. |
| GET | `/login` | Sign-in form. |
| POST | `/login` | Verify `user`/`pass`; sets the `sid` cookie. 5 failures → 60 s lockout. |
| POST | `/logout` | Destroy the current session and clear the cookie. |
| GET | `/` | Status page (Dashboard + tabs). Polls `GET /metrics` every 10 s and patches the stat chips, the pause-countdown table, and the clock line in place — no full-page reload, so in-progress typing in the Check-domain / Whitelist boxes survives a tick (#105, #108, PR #134). |
| GET | `/metrics` | JSON counters and latency histograms — see below. |
| GET | `/metrics/view` | Rendered dashboard over `/metrics` (#126). Static page; the grouping lives in its JS and it polls `/metrics` every 10 s, pausing while the tab is hidden. Fields the grouping does not claim are still shown, under "Other (ungrouped)". |
| GET | `/lastwords` | JSON crash flight recorder (#71) — see below. |
| POST | `/metrics/reset` | Zero the counters and histograms. |
| POST | `/reload` | Reload the blocklist now (does not shift the 4 h timer). |
| POST | `/blocklist/stop` | Abort an in-progress download/reload; the previously loaded list keeps serving. |
| POST | `/pause` | Set global pause to `on=1` (allow every query without unloading anything) or `on=0`. An absolute set, not a toggle — a body without `on=` un-pauses. NVS-persisted, survives reboot. |
| POST | `/pause/timed` | Suspend blocking for `min` minutes (1–1440, enforced server-side). `scope=me` (default) applies to the requesting connection's own IP, `scope=host` with `ip=<IPv4>` to another host, `scope=all` to every client. A global pause renders a confirmation page unless `confirm=1` is also sent. Never persisted: a reboot resumes blocking. |
| POST | `/pause/resume` | End a timed pause early. `ip=<IPv4>` for one host, `ip=all` for the every-client entry, `ip=every` to clear the table. |
| POST | `/check` | Test one domain against the current verdict ladder. |
| POST | `/auth/set` | Change the admin account (`cur` = current password, `user`, `pass`). Drops every session. |
| POST | `/whitelist/add` | Add a domain to the whitelist. |
| POST | `/whitelist/remove` | Remove a whitelist entry. |
| POST | `/blocklist/url/set` | Set one of the 4 extra feed URL slots. `https://` only (#90). |
| POST | `/blocklist/url/clear` | Clear one extra feed slot. |
| POST | `/blocklist/url/toggle` | Enable/disable one extra feed without clearing its URL. |
| POST | `/rewrite/set` | Add a static host / rewrite (bare hostname or domain → fixed IPv4; a domain also matches its subdomains; up to 48). |
| POST | `/rewrite/clear` | Remove one rewrite entry, given `domain=<name>` (the name it was set on). Despite the name, this does not clear the whole table — there is no whole-table-clear route; remove entries one at a time. A body without `domain=` 400s. |
| GET | `/log` | Recent query log (512-entry ring, wall-clock timestamps). |
| GET | `/top` | Top domains/clients plus the 60-bucket per-minute CSS bar graph. |
| GET | `/census` | Passive L2 census (#73): every client seen via ARP, DHCP, or a DNS query, up to 64 MAC-keyed entries. Flags a client "suspected bypass" if it's been on the LAN over 2 minutes but has never sent this board a DNS query — a signal, not proof; it may simply be using another resolver. IP and hostname are last-writer-wins across sighting kinds, so either can briefly show a stale value after a lease change. |
| POST | `/custom/rules` | Save the custom block-rules textarea (hosts format or bare domains). |
| POST | `/acl/add` | Add a client IP to the ACL. |
| POST | `/acl/remove` | Remove one ACL entry. |
| POST | `/acl/clear` | Empty the ACL (empty = allow all). |
| POST | `/bypass/add` | Add a client IP to the per-client bypass list (#74 Part 2) — that client always resolves unfiltered. |
| POST | `/bypass/remove` | Remove one bypass entry. |
| POST | `/bypass/clear` | Empty the bypass list. |
| POST | `/dot/zones` | Save the comma-separated local-zone suffixes (names forwarded to the router in plain DNS, never over DoT; single-label names always are). |
| POST | `/dot/set` | Configure the DNS-over-TLS upstream (server + SNI), or turn it off. |
| POST | `/net/upstream` | Choose which interface egresses upstream queries. Applied live. |
| POST | `/wifi/scan` | Start a Wi-Fi scan on a worker task. |
| GET | `/wifi/scan` | Fetch the results of the last scan. |
| POST | `/wifi/connect` | Join a Wi-Fi network (credentials stored in NVS). |
| POST | `/net/eth/set` | Ethernet DHCP/static IP config. Takes effect on reboot. |
| POST | `/net/wifi/set` | Wi-Fi DHCP/static IP config. Takes effect on reboot. |
| POST | `/reboot` | Reboot the device. |
| POST | `/ota/update` | Upload a merged firmware `.bin` as the raw request body. |

`/wifi/scan` is registered twice on purpose: `POST` has the radio side effect
(it starts a scan), `GET` only reads the result, so the side-effecting half
sits behind the same CSRF check as every other mutation.

## `GET /metrics`

A single JSON object. Field names are exactly as emitted.

| field | type | meaning |
| --- | --- | --- |
| `upstream` | string | Dotted-quad of the resolver actually being forwarded to. |
| `clock` | string | `synced`, `floored`, or `unset`. |
| `clock_src` | string | How the clock got its boot value: `rtc`, `nvs`, `build`, or `unset`. Latched at boot. |
| `clock_epoch` | int | Unix epoch seconds off the system clock, unconditionally — populated even before NTP sync completes. Not a validity signal by itself; pair with `clock` for that (PR #134). |
| `uptime_s` | int | Seconds since boot (`esp_timer`). |
| `queries_total` | int | Queries seen by the socket path. |
| `blocked` | int | Sinkholed on the socket path. |
| `forwarded` | int | Sent upstream. |
| `tcp_queries` | int | Queries that arrived on the TCP/53 listener. |
| `l2_blocked` | int | Blocked replies sent straight from the Ethernet RX hook. |
| `l2_cached` | int | Forward-cache hits sent straight from the Ethernet RX hook. |
| `l2_tx_fail` | int | Fast-path replies `esp_eth_transmit()` refused (#101). |
| `l2_fallthrough` | int | Frames the L2 hook handed to lwIP unanswered — DNS or not. Proof the link is alive, independent of whether `dns_task`'s own sockets are progressing (#77). |
| `l2_dns_fallthrough` | int | Subset of `l2_fallthrough`: only confirmed, well-formed DNS queries the hook deferred to lwIP, not ARP/DHCP/other link noise. This, not `l2_fallthrough`, is what the #77 watchdog (#128) checks against `queries_total` for progress. |
| `wd_restarts` | int | Times the socket-path watchdog (#77) recreated `csock`/`usock` because wire traffic was arriving with no query progress for ~2s. Not reset by `/metrics/reset` (same convention as the `l2_*` counters). |
| `case_mismatch` | int | DNS 0x20 (#72): replies whose question section didn't echo the exact case we sent. Observability only — never rejected; see `process_reply()`'s H2 check for why a hard reject isn't safe without first proving this stays ~0 against the real configured upstream. |
| `l2_log_dropped` | int | L2 query-log staging ring (#124) overflows: entries the L2 hook couldn't hand to `dns_task` before the next tick because the 32-slot ring was still full. Dropped, not blocked — the L2 hook never waits on the log. A nonzero count means a burst outran the drain rate for that window, not a bug; which specific queries were lost isn't recorded, only the count. |
| `census_dropped` | int | Passive L2 census staging ring (#73) overflows — same shape and same caveat as `l2_log_dropped`, for ARP/DHCP/DNS-query sightings instead of the query log. |
| `cache_probes` | int | Forward-cache lookups. |
| `cache_hits` | int | Forward-cache hits. |
| `cache_hit_rate` | float | `cache_hits / cache_probes` as a percentage, one decimal. |
| `cache_evictions` | int | Live entries displaced by a set collision — the sizing gauge. |
| `cache_too_big` | int | Responses over the 512 B per-entry cap, never cached. |
| `stale_served` | int | Expired entries replayed under serve-stale (RFC 8767). |
| `coalesced` | int | Duplicate in-flight queries folded into one upstream request. |
| `hedges_sent` | int | Hedged retransmits issued. |
| `hedged_completions` | int | Answers that came back from a hedge rather than the original. |
| `dropped.table_full` | int | Queries dropped because the upstream table had no free slot. |
| `dropped.mbox_pressure` | int | Queries dropped at the UDP receive mailbox drain cap. |
| `upstream_timeouts` | int | Upstream requests that never got an answer. |
| `upstream_inflight` | int | Upstream slots currently in use. |
| `upstream_max` | int | Upstream table size (compile-time). |
| `blocklist_count` | int | Unique hashes in the live list. |
| `blocklist_loading` | bool | A reload is in progress. |
| `blocklist_paused` | bool | Global pause (the persistent on/off switch) is on. |
| `pause_active` | int | Timed pause entries currently in force, across all scopes. Expired entries are not counted. |
| `pause_list` | array | One object per currently active timed pause: `{"ip":"a.b.c.d","remaining_s":N}`, or `{"ip":"all","remaining_s":N}` for the "pause every device" scope. Powers the Dashboard's pause-countdown table (PR #134); see `pause_active` for the count. |
| `bypass_count` | int | Entries on the standing per-client bypass list (#74 Part 2). |
| `blocklist_dropped` | int | Entries lost to `BLOCKLIST_CAPACITY` on the last reload. |
| `blocklist_feed_failures` | int | Extra feeds that hard-failed on the last publishing reload. Non-zero means the live list is missing whole sources, and the SD snapshot is vetoed. |
| `sd_status` | string | SD-snapshot state: `unknown`, `absent` (no file — no card, or nothing written yet), `bad-magic`, `format-mismatch`, `bad-count`, `short-read`, `invalid-index`, `loaded`, `saved`, `open-failed`, `short-write`. On a board with no card fitted the steady state is `open-failed`: the boot load sets `absent`, then the post-download save fails to open the path. |
| `sd_bytes` | int | Size of the SD snapshot seen at boot, bytes; 0 if there was none. |
| `flash_status` | string | Flash-slot persistence state (#70): `unknown`, `absent` (partitions missing — pre-#70 image), `empty` (never written), `bad-count`, `short-read`, `invalid-index`, `loaded`, `saved`, `too-big`, `erase-failed`, `write-failed`. |
| `heap_free` | int | Free internal heap, bytes. |
| `heap_largest` | int | Largest *contiguous* internal block. This, not `heap_free`, is what TLS setup fails on. |
| `psram_free` | int | Free PSRAM, bytes. |
| `dns_task_stack_hwm` | int | `dns_task` stack headroom, **bytes** — ESP-IDF's `uxTaskGetStackHighWaterMark()` returns bytes, not the words stock FreeRTOS documents (`freertos/task.h`). It is a minimum-ever, so a freshly booted board reads high until the task has been exercised. |
| `latency_us` | object | See below. |

`dropped` is a nested object: `"dropped":{"table_full":N,"mbox_pressure":N}`.

`latency_us` is an object of seven categories — `blocked`, `cached`,
`forwarded_total`, `forwarded_ourovh`, `forwarded_rtt`, `lookup`, `sendto` —
each `{"p50":N,"p99":N,"max":N,"count":N}` in microseconds.

The whole response is built into a fixed 2048 B buffer and clamped to it;
worst case today is roughly 1,750 B (`pause_list` can add up to `PAUSE_MAX`
(8) entries at ~50 B each — see the `F15` comment in `dns_server.cpp`).

## `GET /lastwords`

The crash flight recorder (#71) — whatever `main/crashlog.c`'s `RTC_NOINIT_ATTR`
struct held at the moment of the *previous* boot's reset, snapshotted by
`crashlog_init()` before the live struct keeps recording for the current boot.

| field | type | meaning |
| --- | --- | --- |
| `available` | bool | `false` on the first boot ever, or if the last reset was power-on/brownout (RTC memory doesn't survive those) — nothing else below is meaningful when this is `false`. |
| `reset_reason` | string | `poweron`, `ext`, `sw`, `panic`, `int_wdt`, `task_wdt`, `wdt`, `deepsleep`, `brownout`, `sdio`, or `unknown`. Always present, even when `available` is `false`. |
| `queries_total` | int | Queries recorded since the RTC struct was last reinitialized (not since this boot — it survives resets). |
| `heap_free_min` | int | `esp_get_minimum_free_heap_size()` as of the last recorded query before the reset. |
| `queries` | array | Up to 8 entries, newest first: `{"domain":"...","qtype":N,"blocked":bool,"ts_s":N}`. `domain` is truncated to 31 characters. `ts_s` is uptime seconds at record time, from the boot that crashed — not wall-clock. |

Built into a fixed 1024 B buffer.
