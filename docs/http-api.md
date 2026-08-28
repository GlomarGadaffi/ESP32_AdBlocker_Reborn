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
   `Referrer-Policy: no-referrer`, HSTS, and a CSP that allows only inline
   script/style and same-origin fetch/form targets.

CSRF is *not* in `auth_wrap`: each mutating handler calls `csrf_ok()` itself.
It requires **both** a same-origin `Origin`/`Referer` (when present) **and**
the session's CSRF token — `?csrf=<token>` in the query string (the page's JS
appends it to every form action on submit) or an `X-CSRF: <token>` header
(the page wraps `fetch()` to add it). The token is in the page as
`var CSRF='…'`. `/setup` and `/login` POSTs run before a session exists, so
they check Origin only. All mutating routes are covered — `/net/eth/set` and
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
| GET | `/` | Status page (Dashboard + tabs). Auto-refreshes every 10 s. |
| GET | `/metrics` | JSON counters and latency histograms — see below. |
| POST | `/metrics/reset` | Zero the counters and histograms. |
| POST | `/reload` | Reload the blocklist now (does not shift the 4 h timer). |
| POST | `/blocklist/stop` | Abort an in-progress download/reload; the previously loaded list keeps serving. |
| POST | `/pause` | Toggle global pause (allow every query without unloading anything). |
| POST | `/check` | Test one domain against the current verdict ladder. |
| POST | `/auth/set` | Change the admin account (`cur` = current password, `user`, `pass`). Drops every session. |
| POST | `/whitelist/add` | Add a domain to the whitelist. |
| POST | `/whitelist/remove` | Remove a whitelist entry. |
| POST | `/blocklist/url/set` | Set one of the 4 extra feed URL slots. `https://` only (#90). |
| POST | `/blocklist/url/clear` | Clear one extra feed slot. |
| POST | `/blocklist/url/toggle` | Enable/disable one extra feed without clearing its URL. |
| POST | `/rewrite/set` | Add a DNS rewrite rule (domain → fixed IP). |
| POST | `/rewrite/clear` | Clear the rewrite table. |
| GET | `/log` | Recent query log (512-entry ring, wall-clock timestamps). |
| GET | `/top` | Top domains/clients plus the 60-bucket per-minute CSS bar graph. |
| POST | `/custom/rules` | Save the custom block-rules textarea (hosts format or bare domains). |
| POST | `/acl/add` | Add a client IP to the ACL. |
| POST | `/acl/remove` | Remove one ACL entry. |
| POST | `/acl/clear` | Empty the ACL (empty = allow all). |
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
| `uptime_s` | int | Seconds since boot (`esp_timer`). |
| `queries_total` | int | Queries seen by the socket path. |
| `blocked` | int | Sinkholed on the socket path. |
| `forwarded` | int | Sent upstream. |
| `tcp_queries` | int | Queries that arrived on the TCP/53 listener. |
| `l2_blocked` | int | Blocked replies sent straight from the Ethernet RX hook. |
| `l2_cached` | int | Forward-cache hits sent straight from the Ethernet RX hook. |
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
| `blocklist_paused` | bool | Global pause is on. |
| `blocklist_dropped` | int | Entries lost to `BLOCKLIST_CAPACITY` on the last reload. |
| `blocklist_feed_failures` | int | Extra feeds that hard-failed on the last publishing reload. Non-zero means the live list is missing whole sources, and the SD snapshot is vetoed. |
| `heap_free` | int | Free internal heap, bytes. |
| `heap_largest` | int | Largest *contiguous* internal block. This, not `heap_free`, is what TLS setup fails on. |
| `psram_free` | int | Free PSRAM, bytes. |
| `dns_task_stack_hwm` | int | `dns_task` stack headroom, as reported by `uxTaskGetStackHighWaterMark()`. |
| `latency_us` | object | See below. |

`dropped` is a nested object: `"dropped":{"table_full":N,"mbox_pressure":N}`.

`latency_us` is an object of seven categories — `blocked`, `cached`,
`forwarded_total`, `forwarded_ourovh`, `forwarded_rtt`, `lookup`, `sendto` —
each `{"p50":N,"p99":N,"max":N,"count":N}` in microseconds.

The whole response is built into a fixed 2048 B buffer and clamped to it;
worst case today is roughly 1.3 KB.
