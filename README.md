# ESP32_AdBlocker_Reborn

A native ESP-IDF DNS sinkhole for the LilyGO T-ETH-Elite (ESP32-S3 + W5500 SPI
Ethernet). It hosts the full OISD "big" wildcard blocklist, sinkholes ad and
tracker domains at the network layer, and forwards and caches everything else.
Pure ESP-IDF 6.0.1, no Arduino.

The name is a nod to s60sc/ESP32_AdBlocker, which inspired it. This is a
ground-up rewrite: hash-based blocklist storage so the whole list fits in PSRAM,
wildcard subdomain matching, an SD-cached instant boot, a forward cache, and an
L2 fast path that answers blocked queries without going through lwIP.

## What it does

* Full OISD big list (domainswild2, ~333k wildcard domains) stored as 32-bit
  MurmurHash3 in two PSRAM buffers, radix-sorted and binary-searched, with full
  subdomain suffix-walk matching.
* SD instant boot. The sorted hash table is written to the MicroSD card and
  reloaded in about a second on reboot, instead of a multi-minute HTTPS
  download. The daily refresh runs in the background with the old list still
  serving, so there is no blocking gap.
* L2 fast path. Blocked queries are answered directly in the Ethernet RX hook
  (esp_eth_update_input_path_info): the reply frame is built and sent with
  esp_eth_transmit, never entering lwIP or the socket layer. Everything else
  (DHCP, the HTTP UI, upstream forwarding, the cache) passes through to lwIP
  unchanged.
* Forward cache. Allowed responses are cached as raw bytes in PSRAM with TTLs
  parsed from the answer records, then replayed on repeat. CNAME chains and
  non-A records are preserved. A ~40 ms gateway round trip becomes a ~1.8 ms
  local hit.
* HTTP telemetry and control. GET /metrics returns JSON counters and
  per-category microsecond latency histograms. GET / is a status page with live
  stat boxes and a clock-sync indicator. GET /log shows the recent query log
  (dated, see below); GET /top shows top domains/clients and a per-minute
  CSS bar graph. POST endpoints cover blocklist reload, domain check, whitelist
  add/remove, custom rules, DNS rewrites, client ACL, extra blocklist URLs, DoT
  config, and metrics reset.

## Feature set

Beyond the core sinkhole, the device is a fairly complete Pi-hole-class
appliance — these are all live and verified on hardware:

* **mDNS** — reachable at `esp32adblock.local`, no IP needed.
* **Multiple blocklist sources** — the built-in OISD primary plus up to four
  extra URL feeds (malware/phishing, adult, etc.), each NVS-persisted.
* **Custom block rules** — an inline textarea (hosts format or bare domains,
  `#` comments), wildcard-style suffix matching, NVS-backed.
* **Whitelist** — exempt domains from blocking, NVS-backed.
* **DNS rewrites** — map a local domain to a fixed IP (local-zone / split-horizon),
  exact + subdomain match, up to 16 rules.
* **Client ACL** — restrict which client IPs may use the resolver (empty = allow
  all), enforced before any lookup.
* **Query log + analytics** — a 512-entry PSRAM ring with real wall-clock
  timestamps (NTP, below), approximate top-N domains and clients, and a 60-bucket
  per-minute history graph rendered as pure CSS (no JavaScript).
* **NTP wall-clock time** — built-in lwIP SNTP against `time.nist.gov` +
  `pool.ntp.org` (UTC), so log entries carry real dates that survive reboots
  rather than seconds-since-boot.
* **DNS-over-TLS upstream (opt-in)** — forward to an encrypted upstream
  (RFC 7858, e.g. 1.1.1.1 / one.one.one.one) with automatic fallback to plain
  UDP on failure.
* **Cache-poisoning hardening** — randomized transaction IDs plus question
  (qname + qtype) validation on every upstream reply before it is cached.

## Measured performance

LAN client to board. The latency columns are measured at one query in flight
(c=1), which is the uncontended per-query cost and also what a home network sees
at its low query rate; throughput is the saturation figure at high concurrency.

| path | p50 | min | throughput |
| --- | --- | --- | --- |
| blocked (L2 fast path) | 1.8 ms | 0.8 ms (rare) | ~1,200 qps |
| allowed, cached | ~1.8 ms | ~0.9 ms | ~600 qps |
| allowed, cold (forward) | ~40 ms (gateway RTT) | — | — |

Both fast paths (blocked and cached) sit in a single smooth mode at ~1.8 ms with
a thin tail down to the ~0.8 ms floor (two SPI frames, RX + TX); the min is a
rare jitter-alignment, not the typical case, so ~1.8 ms is the honest deployment
number, not 0.8 ms. The distribution has no bimodality and no tick artifact,
confirmed across two client OSes (Windows and WSL) at 5k samples each per path.
Under saturation the single SPI bus serializes and latency grows with offered
load (tens of ms at 20+ concurrent), which is well beyond a home query rate.

Notes on the ceiling, for anyone optimizing further. The blocklist lookup is
~128 us, a small fraction of the cost. Raw esp_eth_transmit on this board runs
at about 405 us per frame (2,469 fps), so the W5500-over-SPI bus is the hard
limit, not the CPU. Before the L2 fast path the same blocked query took 2.9 ms
at 527 qps; the L2 bypass plus the Tier-1 stack wins (240 MHz CPU, lwIP in IRAM)
brought both the blocked and cached paths down to ~1.8 ms. A leak gate over ~60k
mixed queries shows the internal heap flat — no leak or double-free in the L2
path. The SPI clock stays at 40 MHz: 80 MHz fails the W5500 reset (the chip sits
on GPIO-matrix pins, not the fast IO_MUX pins, which the SD card uses), and
60 MHz works but gives no speedup because the per-query cost is SPI transaction
overhead, not clock rate.

For comparison, ~1.8 ms typical is about 2.5x dnsmasq's ~0.7 ms — and that gap
is the Ethernet-over-SPI hardware (the ~405 us/frame SPI floor, two frames per
query), not software.

## Status and known issues

Two full-codebase reviews (June 2026) audited the firmware. The first round's
findings have since been fixed and verified on hardware; see `ISSUES.md` for the
per-item record. Resolved since the original audit:

* **Forward cache now isolates A and AAAA.** The slot index folds the query type
  in (`(h ^ (qtype<<1)) & 0xFF`) and a hit requires a matching `qtype`, so the
  A and AAAA records for a name occupy separate slots and both cache-hit on
  repeat — verified live (a repeat A+AAAA pair scores two cache hits). (#43)
* **L2 fast path no longer stalls on whitelist edits.** The RX hook uses a
  non-blocking mutex take and the blocking path a bounded 2 ms take, and NVS
  commits run outside the lock. (#37)
* **Upstream truncation sets the TC bit** and truncated replies are excluded from
  the cache, so clients correctly retry over TCP. (#36)
* **HTTP control UI hardened.** CSRF origin/host checking on all POSTs, HTML
  escaping of reflected/stored input, client ACL, and upstream replies validated
  by source address *and* by matching question (qname+qtype) with randomized
  txids. It is still intended for trusted-LAN use — don't expose port 80 to the
  internet. (#22, #23, #24, #28, #35, #44)
* **Concurrency races fixed.** The custom-rules, ACL, and rewrite tables are now
  synchronized between the httpd writer and the dns_task reader.

Remaining open items:

* **DoT runs synchronously in the DNS task.** With DoT enabled, a slow query can
  briefly stall other queries; the inline timeout is capped (1.5 s) and falls
  back to UDP, but the proper fix is a worker task / persistent session. DoT is
  opt-in and off by default. (ISSUES.md C2)
* **The "about a second" SD reload is not independently re-measured.** (#38)
* **Some headline ad roots aren't in the loaded list.** e.g. `doubleclick.net`
  resolves while `analytics.tiktok.com` is blocked — a blocklist-content/cache
  freshness question (the matching engine works on 333k domains), not a code
  bug. Try a fresh `/reload` and re-check.

See the issue tracker and `ISSUES.md` for the full, code-grounded analysis.

## Hardware

LilyGO T-ETH-Elite: ESP32-S3-WROOM-1 (16 MB flash, 8 MB OPI PSRAM) plus a W5500.

| function | pins |
| --- | --- |
| W5500 (SPI2) | SCLK 48, MISO 47, MOSI 21, CS 45, INT 14, 40 MHz |
| MicroSD (SPI3) | SCLK 10, MISO 9, MOSI 11, CS 12 |

## Build and flash

```sh
idf.py set-target esp32s3
idf.py build
idf.py -p PORT flash monitor
```

First boot downloads the blocklist over HTTPS and writes it to SD. Later boots
load from SD in about a second. Point your router's DNS at the board's DHCP
address.

## Layout

```
main/
  dns_sink.cpp     entry: W5500 + SD bringup, L2 fast-path RX hook, download task, SNTP
  dns_server.cpp   UDP :53 server, result cache, upstream forward table, DoT path, /metrics
  blocklist.c      PSRAM hash table, radix sort, SD persistence, NVS whitelist + custom rules
  rewrite.c        DNS rewrite rules (local-zone / domain->IP)
  acl.c            client IP allowlist
  dot.c            DNS-over-TLS upstream (RFC 7858, esp-tls)
  query_log.c      query-log ring, top-N tables, per-minute history
  timesync.c       SNTP wall-clock time (NIST + NTP pool)
  http_fetch.c     streaming HTTPS line fetcher
  domain.c         shared domain normalization and TLD detection
  murmur3.c        MurmurHash3_x86_32
  web_ui.cpp       HTTP status UI, JSON metrics, control endpoints
```
