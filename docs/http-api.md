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
| POST | `/setup` | Create the admin account (`user`, `pass`, `pass2`); opens a session, then redirects to `/setup/network`. |
| GET | `/setup/network` | Onboarding step 2: Ethernet DHCP/Static and/or Wi-Fi scan/connect, whichever this board has. A normal logged-in page (not setup-only) — same backend endpoints as the dashboard's Network tab, just a focused view onto them. |
| GET | `/login` | Sign-in form. |
| POST | `/login` | Verify `user`/`pass`; sets the `sid` cookie. 5 failures → 60 s lockout. |
| POST | `/logout` | Destroy the current session and clear the cookie. |
| GET | `/` | Status page (Dashboard + tabs). Polls `GET /metrics` every 10 s and patches the stat chips, the pause-countdown table, and the clock line in place — no full-page reload, so in-progress typing in the Check-domain / Whitelist boxes survives a tick (#105, #108, PR #134). |
| GET | `/metrics` | JSON counters and latency histograms — see below. |
| GET | `/metrics/prom` | The same metrics as Prometheus text exposition, for a scraper — see below. Same session requirement as `/metrics`. |
| GET | `/metrics/view` | Rendered dashboard over `/metrics` (#126). Static page; the grouping lives in its JS and it polls `/metrics` every 10 s, pausing while the tab is hidden. Fields the grouping does not claim are still shown, under "Other (ungrouped)". |
| GET | `/lastwords` | JSON crash flight recorder (#71) — see below. |
| POST | `/metrics/reset` | Zero the counters and histograms. |
| POST | `/reload` | Reload the blocklist now (does not shift the 4 h timer). |
| POST | `/blocklist/stop` | Abort an in-progress download/reload; the previously loaded list keeps serving. |
| POST | `/pause` | Set global pause to `on=1` (allow every query without unloading anything) or `on=0`. An absolute set, not a toggle — a body without `on=` un-pauses. NVS-persisted, survives reboot. |
| POST | `/pause/timed` | Suspend blocking for `min` minutes (1–1440, enforced server-side). `scope=me` (default) applies to the requesting connection's own IP, `scope=host` with `ip=<IPv4>` to another host, `scope=all` to every client. A global pause renders a confirmation page unless `confirm=1` is also sent. Never persisted: a reboot resumes blocking. |
| POST | `/pause/resume` | End a timed pause early. `ip=<IPv4>` for one host, `ip=all` for the every-client entry, `ip=every` to clear the table. |
| GET | `/pause/schedule` | The recurring pause schedule as JSON: `{"utc_offset_min":N,"clock_synced":bool,"effective":"none\|manual\|schedule","windows":[{"slot":0,"enabled":true,"spec":"mon,tue 22:00-06:30"}, …]}` — always four `windows` entries, `spec` is `""` for an unset slot. `effective` is why blocking is suspended for everyone right now (`manual` wins over `schedule`). `clock_synced` is false until NTP has set the clock, and schedules stay inactive until then. |
| POST | `/pause/schedule` | Edit the schedule (NVS-persisted). Either `slot` (0–3) with `spec` (`mon,tue 22:00-06:30`, or `daily` / `weekdays` / `weekends` in place of day names; an empty `spec` clears the slot), or `utc_offset_min` (−720 to 840, fixed offset, no DST) — not both. Success answers 200 with the same JSON as the GET. Anything else (including a repeated field or an encoded NUL) is a 400 with a short `text/plain` reason; a failed NVS write is a 500. CSRF as for every POST. |
| POST | `/check` | Test one domain against the shared verdict (#117): reports `BLOCKED`/`ALLOWED` plus which source decided it (`feed`, `whitelist`, `custom`), or `REWRITE -> ip` if a rewrite matched first (#103). |
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
| POST | `/custom/rules` | Save the custom rules textarea: hosts format, bare domains, `\|\|`/`\|` anchors, `@@` exceptions, and `$important` (#117). Validated as a whole before saving — a rule count over 256, or any single entry 64 characters or longer, is refused (400) with no partial save; an unsupported line (regex, wildcard, an unhandled `$` modifier, ...) is skipped rather than stored, and does not fail the save. |
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
| POST | `/wifi/connect` | Join a Wi-Fi network (credentials stored in NVS). Normally 303s to `/#network`; if the setup AP is active, instead returns a 200 HTML interstitial telling the client to rejoin its own network, since the setup AP — and the response's own connection — drops out from under it the moment the new network associates. |
| POST | `/net/eth/set` | Ethernet DHCP/static IP config. Takes effect on reboot. |
| POST | `/net/wifi/set` | Wi-Fi DHCP/static IP config. Takes effect on reboot. |
| POST | `/net/wifi/enable` | Toggle whether Wi-Fi STA is brought up at boot (dual-WAN alongside Ethernet). NVS-only — takes effect on reboot, does not touch the running radio. Rejected on the Wi-Fi-only board, which has no Ethernet to fall back to. |
| POST | `/reboot` | Reboot the device. |
| POST | `/ota/update` | Upload a merged firmware `.bin` as the raw request body. The image must carry a valid RSA-3072 signature from the project key (`CONFIG_SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT`); an unsigned or foreign-signed image is rejected at `esp_ota_end` with a 500 and the running firmware is untouched. |

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
| `tcp_queries` | int | Queries that arrived on the TCP/53 listener (up to 4 concurrent connections since #154; one query per connection). |
| `l2_blocked` | int | Blocked replies sent straight from the Ethernet RX hook. |
| `l2_cached` | int | Forward-cache hits sent straight from the Ethernet RX hook. |
| `l2_tx_fail` | int | Fast-path replies `esp_eth_transmit()` refused (#101). |
| `l2_fallthrough` | int | Frames the L2 hook handed to lwIP unanswered — DNS or not. Proof the link is alive, independent of whether `dns_task`'s own sockets are progressing (#77). |
| `l2_dns_fallthrough` | int | Subset of `l2_fallthrough`: only confirmed, well-formed DNS queries the hook deferred to lwIP, not ARP/DHCP/other link noise. This, not `l2_fallthrough`, is what the #77 watchdog (#128) checks against `queries_total` for progress. |
| `l2_defer_lock_busy` | int | L2-hook queries that deferred to the socket path because the shared verdict's zero-wait small-table take failed (#117) — an admin write to the whitelist or custom rules was in flight. Flat in steady state. |
| `l2_defer_snapshot` | int | L2-hook queries that deferred because a blocklist reload published underneath the verdict walk (#117). Flat outside a reload window. |
| `wd_restarts` | int | Times the socket-path watchdog (#77) recreated `csock`/`usock` because wire traffic was arriving with no query progress for ~2s. Not reset by `/metrics/reset` (same convention as the `l2_*` counters). |
| `select_errors` | int | `select()` failures `dns_task` has survived (#152). Before this the first one ended the task for good — DNS dead, web UI up, no reboot. Not reset by `/metrics/reset`. |
| `dns_health.probe_ok` | int | DNS self-check probes (the board resolving a name through its own DNS port) that were answered, since boot. |
| `dns_health.probe_fail` | int | Self-check probes that got no valid answer, since boot. |
| `dns_health.probe_skipped` | int | Probe cycles that stood down (blocklist reloading, OTA upload in progress, no address yet, or the client ACL excludes the board's own address). |
| `dns_health.last_action` | int | The latest self-check decision: `0` none, `1` warn, `2` reboot. |
| `dns_task_alive` | bool | `false` means `dns_task` has exited (#153); `dns_task_stack_hwm` reads 0 in that state and means nothing. |
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
| `up_rotations` | int | Upstream source-port rotations completed: a fresh UDP socket swapped in for the upstream queries while the old one drains. |
| `up_rotate_failures` | int | Rotations abandoned because no socket or no free port could be had. Non-zero means the upstream source port is not rotating. |
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
| `rejected.regex` | int | Feed lines rejected as a `/regex/` pattern on the last reload (#117). No regex support on this board. |
| `rejected.wildcard` | int | Feed lines rejected for a mid-pattern wildcard (`ex*.com`) on the last reload — distinct from the `*.domain` prefix shorthand, which is accepted and collapsed to the parent. |
| `rejected.modifier` | int | Feed lines rejected for an unsupported `$` modifier (`$dnstype`, `$dnsrewrite`, `$denyallow`, `$badfilter`, an empty or duplicate modifier list, ...) on the last reload. |
| `rejected.cosmetic` | int | Feed lines rejected as a `##` cosmetic/element-hiding rule on the last reload. |
| `rejected.cidr` | int | Feed lines rejected as an IP/CIDR pattern on the last reload — this firmware filters names, not answers. |
| `rejected.too_wide` | int | Feed lines rejected as too generic to mean anything (under 3 characters, or made only of `.` and `*`) on the last reload. |
| `rejected.important_block` | int | Feed lines rejected because they combined `$important` with a plain block rule on the last reload — the feed block-table entry has no spare bit to carry the flag, so it's rejected and counted rather than silently accepted and then losing precedence fights it was written to win. `$important` is accepted on custom rules (see the `/custom/rules` row above). |
| `exceptions_skipped` | int | `@@` exception lines seen in a feed on the last reload. Parsed and counted, but not yet stored anywhere — feed-level exceptions need a second table that doesn't exist yet, so these currently have no effect on any verdict. Non-zero here is a real, visible gap, not a bug. |
| `sd_status` | string | SD-snapshot state: `unknown`, `absent` (no file — no card, or nothing written yet), `bad-magic`, `format-mismatch`, `bad-count`, `short-read`, `invalid-index`, `loaded`, `saved`, `open-failed`, `short-write`. On a board with no card fitted the steady state is `open-failed`: the boot load sets `absent`, then the post-download save fails to open the path. |
| `sd_bytes` | int | Size of the SD snapshot seen at boot, bytes; 0 if there was none. |
| `flash_status` | string | Flash-slot persistence state (#70): `unknown`, `absent` (partitions missing — pre-#70 image), `empty` (never written), `bad-count`, `short-read`, `invalid-index`, `loaded`, `saved`, `too-big`, `erase-failed`, `write-failed`. |
| `heap_free` | int | Free internal heap, bytes. |
| `heap_largest` | int | Largest *contiguous* internal block. This, not `heap_free`, is what TLS setup fails on. |
| `psram_free` | int | Free PSRAM, bytes. |
| `dns_task_stack_hwm` | int | `dns_task` stack headroom, **bytes** — ESP-IDF's `uxTaskGetStackHighWaterMark()` returns bytes, not the words stock FreeRTOS documents (`freertos/task.h`). It is a minimum-ever, so a freshly booted board reads high until the task has been exercised. |
| `latency_us` | object | See below. |

`dns_health` is a nested object: `"dns_health":{"probe_ok":N,"probe_fail":N,"probe_skipped":N,"last_action":N}`.

`dropped` is a nested object: `"dropped":{"table_full":N,"mbox_pressure":N}`.

`latency_us` is an object of seven categories — `blocked`, `cached`,
`forwarded_total`, `forwarded_ourovh`, `forwarded_rtt`, `lookup`, `sendto` —
each `{"p50":N,"p99":N,"max":N,"count":N}` in microseconds.

The whole response is built into a fixed 3072 B buffer and clamped to it;
the strict worst case is roughly 2,860 B (`pause_list` can add up to
`PAUSE_MAX` (8) entries at ~50 B each — see the `F15` comment in
`dns_server.cpp`), and real values are far smaller.

## `GET /metrics/prom`

The `/metrics` document rendered as Prometheus text exposition format 0.0.4
(`Content-Type: text/plain; version=0.0.4`). It is converted from the same
JSON by `main/metrics_prom.c`, so every numeric field above is here with no
separate list to maintain:

- A number becomes `adblock_<name>`, with nested keys joined by `_`:
  `queries_total` → `adblock_queries_total`, `dropped.table_full` →
  `adblock_dropped_table_full`, `latency_us.blocked.p99` →
  `adblock_latency_us_blocked_p99`. The number text is passed through as is.
- A bool becomes `1` or `0` (`adblock_dns_task_alive`).
- An array of numbers becomes `adblock_<name>{idx="N"}`. None exists today.
- Strings are not metrics and are dropped, except four identity strings that
  become labels on one line, `adblock_info{version="…",board="…",upstream="…",clock_src="…"} 1`.
  Only the ones present in `/metrics` appear; today that is `upstream` and
  `clock_src`. `pause_list` (an array of objects) is dropped.
- No `# HELP` or `# TYPE` lines: every series is untyped. Counters that
  `/metrics/reset` zeroes will look like a counter reset to `rate()`, which
  handles that.

If the metrics JSON was clamped to its buffer, or the text does not fit its
6 KB buffer (a saturated worst-case document renders to about 3.4 KB), the route answers `500 metrics unavailable` rather than send a
partial page.

**What a scraper must send.** The route is behind the same `auth_wrap`
session gate as every other route, and there is no token or basic-auth
alternative: without a valid `sid` cookie it answers `303` to `/login`, which
a scraper sees as a failed scrape. The session is a login cookie that expires
after 30 minutes idle or 12 hours absolute, and the device keeps at most 4
sessions at once, so the scraper must (1) `POST /login` with `user` and `pass`
once, keep the `sid` cookie, (2) scrape at least every 30 minutes so it never
idles out, and (3) log in again when it gets the `303`, no more often than
that (every login takes a session slot a browser may need, and 5 failed logins
lock out for 60 s). The certificate is self-signed, so the scraper must
either trust it or skip verification. Stock Prometheus has no login step, so
the usual arrangement is a small sidecar that holds the session and serves
the text, or a cron job that fetches it with curl into a file for
`node_exporter`'s textfile collector:

```sh
curl -sk -c jar -X POST -d 'user=U&pass=P' https://HOST/login -o /dev/null
curl -sk -b jar https://HOST/metrics/prom
```

If your Prometheus supports sending a static `Cookie` header on scrapes, it
could carry the session cookie itself. Check your version's documentation
for the exact option name and syntax before relying on it: this has not been
verified against a Prometheus release. The cookie value must be copied from
the login by hand and replaced whenever it expires (30 min idle, 12 h
absolute), so a sidecar or the textfile arrangement above is the more
robust choice.

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
