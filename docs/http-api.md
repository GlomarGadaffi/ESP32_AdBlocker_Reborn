# HTTP API reference

Every route below is served by the single httpd instance in `main/web_ui.cpp`
on **port 80**, and every one of them (including `GET /`) passes through
`auth_wrap` first — so if a web UI username is set, HTTP Basic Auth gates the
whole surface. CSRF is *not* in `auth_wrap`: each mutating handler calls
`csrf_ok()` itself (`Origin`/`Referer` host must match `Host`, absent-both
allowed for plain form posts). All 25 `POST` routes are covered — `/net/eth/set`
and `/net/wifi/set` inherit the check from the shared `handle_net_static_set()`
helper rather than calling it directly, so a naive per-handler grep undercounts.
If you add a POST handler, add the `csrf_ok()` call.

This is a trusted-LAN interface; don't expose port 80 to the internet.

The route list is generated from the `uris[]` table in `web_ui.cpp`; the
metrics fields from `dns_server_metrics_json()` in `dns_server.cpp`.

## Routes

| method | path | purpose |
| --- | --- | --- |
| GET | `/` | Status page (Dashboard + tabs). Auto-refreshes every 10 s. |
| GET | `/metrics` | JSON counters and latency histograms — see below. |
| POST | `/metrics/reset` | Zero the counters and histograms. |
| POST | `/reload` | Reload the blocklist now (does not shift the 4 h timer). |
| POST | `/blocklist/stop` | Abort an in-progress download/reload; the previously loaded list keeps serving. |
| POST | `/pause` | Toggle global pause (allow every query without unloading anything). |
| POST | `/check` | Test one domain against the current verdict ladder. |
| POST | `/auth/set` | Set/clear the web UI Basic Auth username and password. |
| POST | `/whitelist/add` | Add a domain to the whitelist. |
| POST | `/whitelist/remove` | Remove a whitelist entry. |
| POST | `/blocklist/url/set` | Set one of the 4 extra feed URL slots. |
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
