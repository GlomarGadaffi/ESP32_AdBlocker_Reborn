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
* HTTP telemetry. GET /metrics returns JSON counters and per-category
  microsecond latency histograms. GET / is a status page. POST endpoints:
  /reload, /check, /whitelist/add, /whitelist/remove, /metrics/reset.

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

A full-codebase review (June 2026) audited the firmware and filed the results to
the issue tracker. The figures above are real bench measurements, but a few of
the advertised wins are currently undercut by open bugs — worth knowing before
you rely on them:

* **Forward-cache hit rate is low for dual-stack clients.** Cache slots are
  indexed by domain hash only, with the query type not folded into the slot, so
  the A and AAAA records for the same name share one slot and evict each other.
  Modern stub resolvers (glibc `getaddrinfo`, browsers) issue A+AAAA in
  parallel, so the ~1.8 ms cached-hit path rarely triggers on repeat lookups until
  this is fixed. The hit *latency* is accurate; the hit *rate* is not yet. (#43)
* **The L2 fast path stalls briefly during whitelist edits.** The Ethernet RX
  hook takes the whitelist mutex, which the writer holds across an NVS commit
  (~10–100 ms of flash work), so adding or removing a whitelist entry pauses the
  fast path and frame intake for the commit. Steady-state latency is
  unaffected. (#37)
* **The "about a second" SD reload is not independently re-measured.** The load
  path reads PSRAM directly through FATFS where the save path deliberately
  bounces through a DRAM buffer, so real cold-boot time may be higher. (#38)
* **Large upstream responses are truncated.** Replies over 512 bytes are cut to
  512 with no TC bit set, which breaks DNSSEC, large TXT (SPF/DKIM), and HTTPS
  RRs for forwarded queries. (#36)
* **Security: the HTTP control UI is LAN-trust-only.** It has no CSRF protection
  and reflects/stores user input without escaping, and upstream replies are
  accepted without source-address validation. Do not expose the board's HTTP
  port; treat the device as trusted-LAN only. (#22, #23, #24, #28, #35, #44)

See the issue tracker for the full list and the code-grounded analysis on each.

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
  dns_sink.cpp     entry: W5500 + SD bringup, L2 fast-path RX hook, download task
  dns_server.cpp   UDP :53 server, result cache, upstream forward table, /metrics
  blocklist.c      PSRAM hash table, radix sort, SD persistence, NVS whitelist
  http_fetch.c     streaming HTTPS line fetcher
  domain.c         shared domain normalization and TLD detection
  murmur3.c        MurmurHash3_x86_32
  web_ui.cpp       HTTP status UI, JSON metrics, control endpoints
```
