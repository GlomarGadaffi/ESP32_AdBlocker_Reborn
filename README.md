# dns-sink — a native ESP-IDF DNS sinkhole for the LilyGO T-ETH-Elite

A Pi-hole-class DNS sinkhole that runs entirely on an **ESP32-S3 + W5500 SPI
Ethernet** board (LilyGO T-ETH-Elite). Pure ESP-IDF 6.0.1 — no Arduino. Hosts
the full OISD "big" wildcard blocklist (~333k domains), blocks at wire speed,
forwards and caches everything else.

## Highlights

- **Full OISD big list** (`domainswild2`, ~333k wildcard domains) stored as
  32-bit MurmurHash3 in two PSRAM ping-pong buffers (1.96 MB each), sorted,
  binary-searched, with full subdomain suffix-walk wildcard matching.
- **Instant boot**: the sorted hash table is cached to the MicroSD card and
  reloaded in ~1 s on reboot, instead of a ~4-minute HTTPS download. The daily
  refresh runs in the background with the old list staying live (no blocking gap).
- **L2 fast-path**: blocked queries are answered directly in the Ethernet RX
  hook (`esp_eth_update_input_path_info`) — the response frame is crafted and
  `esp_eth_transmit`'d without ever entering lwIP/sockets. Everything else
  (DHCP, the HTTP UI, upstream forwarding, the cache) passes through to lwIP
  untouched.
- **Full-fidelity forward cache**: allowed responses are cached as raw bytes in
  PSRAM (TTL parsed from the answer RRs) and replayed on repeat — preserving
  CNAME chains, multiple records, and non-A types. ~40 ms gateway round-trips
  become ~2 ms local hits.
- **HTTP telemetry**: `GET /metrics` returns JSON counters + per-category µs
  latency histograms (p50/p99); `GET /` is a status UI; `POST /reload`,
  `/check`, `/whitelist/add|remove`, `/metrics/reset`.

## Measured performance (LAN client → board)

| path | latency p50 | min | throughput |
|---|---|---|---|
| blocked (L2 fast-path) | **1.8 ms** | **0.8 ms** | **~1,200 qps** |
| allowed, cached | ~2 ms | — | ~600 qps |
| allowed, cold (forward) | gateway RTT (~40 ms) | — | — |

The optimization journey, in order of impact: streaming HTTPS download +
SD-cache instant boot → lwIP mailbox sizing (kill burst drops) → drain-loop
(one `select` wakeup drains all ready packets, +37%) → lwIP core-locking →
forward cache → **L2 fast-path bypass of lwIP for the hot path** (the big one:
2.9 ms→1.8 ms, 527→1,200 qps). The raw `esp_eth_transmit` floor on this board
is ~400 µs/frame (2,469 fps), so the W5500-over-SPI bus — not the CPU — is the
remaining ceiling.

## Hardware

LilyGO T-ETH-Elite: ESP32-S3-WROOM-1 (16 MB flash, 8 MB OPI PSRAM) + W5500.

| function | pins |
|---|---|
| W5500 (SPI2) | SCLK 48, MISO 47, MOSI 21, CS 45, INT 14 @ 40 MHz |
| MicroSD (SPI3) | SCLK 10, MISO 9, MOSI 11, CS 12 |

## Build & flash

```sh
idf.py set-target esp32s3
idf.py build
idf.py -p <PORT> flash monitor
```

First boot downloads the blocklist over HTTPS and caches it to SD; subsequent
boots load from SD in ~1 s. Point your router's DNS at the board's DHCP address.

## Layout

```
main/
  dns_sink.cpp     entry: W5500 + SD bringup, L2 fast-path RX hook, download task
  dns_server.cpp   UDP :53 server, result cache, upstream forward table, /metrics
  blocklist.c      PSRAM hash table, radix sort, SD persistence, NVS whitelist
  http_fetch.c     streaming HTTPS line fetcher
  domain.c         shared domain normalization + TLD detection
  murmur3.c        MurmurHash3_x86_32
  web_ui.cpp       HTTP status UI + JSON metrics + control endpoints
```
