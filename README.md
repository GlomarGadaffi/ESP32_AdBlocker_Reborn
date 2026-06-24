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
  non-A records are preserved. A ~40 ms gateway round trip becomes a ~2 ms
  local hit.
* HTTP telemetry. GET /metrics returns JSON counters and per-category
  microsecond latency histograms. GET / is a status page. POST endpoints:
  /reload, /check, /whitelist/add, /whitelist/remove, /metrics/reset.

## Measured performance

LAN client to board, blocked queries served by the L2 fast path:

| path | p50 | min | throughput |
| --- | --- | --- | --- |
| blocked (L2 fast path) | 1.8 ms | 0.8 ms | ~1,200 qps |
| allowed, cached | ~2 ms | | ~600 qps |
| allowed, cold (forward) | gateway RTT (~40 ms) | | |

Notes on the ceiling, for anyone optimizing further. The blocklist lookup is
~128 us, a small fraction of the cost. Raw esp_eth_transmit on this board runs
at about 405 us per frame (2,469 fps), so the W5500-over-SPI bus is the limit,
not the CPU. Before the L2 fast path the same blocked query took 2.9 ms at 527
qps, and almost all of that was lwIP socket overhead rather than the bus. The
SPI clock stays at 40 MHz: 80 MHz fails the W5500 reset (the chip sits on
GPIO-matrix pins, not the fast IO_MUX pins, which the SD card uses), and 60 MHz
works but gives no speedup because the per-query cost is SPI transaction
overhead, not clock rate.

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
