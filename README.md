# ESP32_AdBlocker_Reborn

A native ESP-IDF DNS sinkhole for ESP32-S3 + W5500 SPI Ethernet boards — the
LilyGO T-ETH-Elite and the Waveshare ESP32-S3-ETH (see Hardware for the
per-board pin maps). It hosts the full OISD "big" wildcard blocklist plus up to four
extra feeds (hagezi ad tiers and threat-intelligence presets built in — 700k+
domains total), sinkholes ad, tracker, and malware domains at the network
layer, and forwards and caches everything else. Pure ESP-IDF 6.0.1, no
Arduino.

The name is a nod to s60sc/ESP32_AdBlocker, which inspired it. This is a
ground-up rewrite: hash-based blocklist storage so the whole list fits in PSRAM,
wildcard subdomain matching, an SD-cached instant boot, a forward cache, and an
L2 fast path that answers blocked queries without going through lwIP.

## What it does

* Full OISD big list (domainswild2, ~266k wildcard domains) plus extra feeds,
  stored as 32-bit MurmurHash3 in two 820k-entry PSRAM buffers, radix-sorted
  and binary-searched, with full subdomain suffix-walk matching. Extra-list
  entries are deduplicated against the sorted primary as they stream in, so
  buffer capacity binds on the union of all sources, not their sum.
* SD instant boot. The sorted hash table is written to the MicroSD card and
  reloaded in about a second on reboot, instead of a multi-minute HTTPS
  download. The daily refresh runs in the background with the old list still
  serving, so there is no blocking gap.
* L2 fast path. Both blocked queries AND forward-cache hits are answered
  directly in the Ethernet RX hook (esp_eth_update_input_path_info): the reply
  frame is built and sent with esp_eth_transmit, never entering lwIP or the
  socket layer. Only cold (uncached, non-blocked) queries fall through to lwIP
  for upstream forwarding. A cross-task seqlock lets the RX hook read the cache
  safely while the DNS task writes it.
* Forward cache. Allowed responses are cached as raw bytes in PSRAM (4-way
  set-associative, 512 sets = 2048 entries; qtype folded into the key so A and
  AAAA never evict each other, and two hot domains hashing together no longer
  evict each other either) with TTLs parsed from the answer records, then
  replayed on repeat — from the L2 fast path. CNAME chains and non-A records
  are preserved. A ~40 ms gateway round trip becomes a ~1.8 ms local hit at
  ~2,100 qps. `/metrics` reports `cache_evictions` (live entries displaced by
  collisions — the sizing gauge) and `cache_too_big` (responses over the 512 B
  entry cap that were never cached).
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
  extra URL feeds, each NVS-persisted, with one-click presets for the
  [hagezi](https://github.com/hagezi/dns-blocklists) wildcard lists (ad tiers
  Light through Ultimate, the TIF-medium threat-intelligence tier — a
  deliberately reduced tier of hagezi's TIF feed, not full TIF, which is too
  large to fit — and OISD's NSFW adult-content list). Extra-list
  entries are deduplicated against the sorted primary at load time, so
  capacity binds on the *union*, not the sum; entries dropped at capacity are
  counted and surfaced in the UI and `/metrics` (`blocklist_dropped`) instead
  of vanishing silently.
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
* **Pause blocking** — a one-click Dashboard toggle (mirroring upstream
  s60sc/ESP32_AdBlocker's "Enable AdBlocker" switch) that allows every query
  through without touching the loaded blocklist, whitelist, custom rules, or
  ACL. NVS-persisted, survives reboot. `/metrics` reports `blocklist_paused`.
* **Stop an in-progress reload** (mirrors upstream's Stop Load button) — abort
  the current blocklist download/reload; the previously-loaded list keeps
  serving throughout, same as any other reload.
* **Optional web UI login** (mirrors upstream's Auth_Name/Auth_Pass) — HTTP
  Basic Auth gating every page and endpoint, off by default (empty username).
  NVS-persisted. No recovery path short of an NVS erase if forgotten — same
  as upstream, which has none either.
* **Setup AP for zero-touch first-boot Wi-Fi config** (mirrors upstream's
  AP-mode bootstrap) — if neither Ethernet nor Wi-Fi comes up within 30s of
  boot, an open SoftAP ("ESP32AdBlock-Setup") comes up at 192.168.4.1 serving
  the same web UI, so a phone can join it and enter real Wi-Fi credentials
  with no serial cable. Shuts off automatically once any interface gets an
  IP. It's unauthenticated by design (nothing is configured yet to
  authenticate against) and can appear during any boot-time link outage
  longer than 30s, not just a true first boot — same trusted-LAN threat
  model as upstream's own AP mode.
* **Browser-driven firmware update** (mirrors upstream's OTA Upload tab) —
  upload a merged `.bin` from the Network tab, no toolchain or serial cable
  needed. Dual OTA partitions with automatic rollback
  (`CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE`): if a new image fails to bring up
  DNS serving and the web UI, the next boot reverts to the previous slot
  automatically — the load-bearing safety net for a device with no display.

## Feature parity with upstream s60sc/ESP32_AdBlocker

| upstream feature | Reborn | notes |
| --- | --- | --- |
| DNS sinkhole, external DNS forward | ✅ | ground-up rewrite — hash-based blocklist, forward cache, L2 fast path, TXID hardening; see Measured performance |
| Enable AdBlocker (on/off) | ✅ | Pause blocking, above |
| Stop Blocklist Load | ✅ | Stop an in-progress reload, above |
| Add/Del/Check domain | ✅ | Whitelist + Custom block rules + `/check`, all NVS-backed |
| Clear custom blocklist | ✅ | Custom Block Rules textarea, save empty to clear |
| Single blocklist URL, daily reload | ✅ (exceeded) | up to 4 extra sources with dedup-aware capacity, hagezi presets, 4h reload |
| Auth_Name / Auth_Pass (optional login) | ✅ | Optional web UI login, above |
| AP-mode first-boot Wi-Fi setup | ✅ | Setup AP, above |
| OTA Upload tab | ✅ | Browser-driven firmware update, above, plus auto-rollback upstream doesn't have |
| Verbose per-query logging | ✅ (superseded) | `/log` query-log ring with real timestamps + `/top` analytics, more structured than a verbose toggle |
| Eth+AP / Ethernet-only / Wi-Fi network modes | ✅ (different model) | Ethernet always up, Wi-Fi optionally alongside (`CONFIG_ADBLOCK_NET_WIFI`) rather than one replacing the other — a deliberate design choice, not a gap |
| maxDomains / minMemory / maxDomLen tuning | N/A by design | fixed PSRAM ping-pong buffers sized to fit full modern lists (`BLOCKLIST_CAPACITY`); this is a from-scratch storage design, not the same knobs upstream needs for its linear array |
| WebDAV `/data` sync | N/A | upstream needs this because its web UI lives on a separate SD `/data` filesystem; Reborn's UI is compiled into firmware, so there's no equivalent filesystem to sync |
| Static-IP / router-IP config | ✅ (different UI) | per-interface DHCP/static in the Network tab, not a single global router-IP field |

## Measured performance

LAN client to board. The latency columns are measured at one query in flight
(c=1), which is the uncontended per-query cost and also what a home network sees
at its low query rate; throughput is the saturation figure at high concurrency.

| path | p50 (c=1) | min | throughput (saturated) |
| --- | --- | --- | --- |
| blocked (L2 fast path) | 1.8 ms | 0.66 ms | **~2,200 qps** |
| allowed, cached (L2 fast path) | 1.8 ms | 0.67 ms | **~2,100 qps** |
| allowed, cold (forward) | ~40 ms (gateway RTT) | — | — |

Both fast paths sit in a single smooth mode at ~1.8 ms with a thin tail to a
~0.66 ms floor (two SPI frames, RX + TX); ~1.8 ms is the honest deployment
number, not the min. Throughput is the saturation figure under multithreaded
load from a WSL (Linux) client — both L2 paths plateau near **~2,200 qps with
zero drops**, latency growing linearly with offered load past that (the single
SPI bus serializing), which is far beyond any home query rate.

Two things lifted these numbers. (1) **The cached path is now an L2 fast path
too**: a forward-cache hit is answered straight from the Ethernet RX hook
(seqlock-guarded cross-task read of the cache), never entering lwIP — so cached
throughput went from ~600 qps (old socket path) to ~2,100 qps, matching the
blocked path. (2) **A real release build** (-O2, assertions off) halved the
CPU-bound work — the blocklist binary search dropped from 128 us to 64 us — which
let the blocked path climb from ~1,200 qps (previously CPU-limited) up to the
W5500 SPI ceiling.

Notes on the ceiling, for anyone optimizing further. The blocklist lookup is
~64 us, a small fraction of the cost; the W5500-over-SPI bus is now the hard
limit, not the CPU. A leak gate over ~60k mixed queries shows the internal heap
flat — no leak or double-free in the L2 path, and a 26k-query soak with
concurrent cache writes confirmed the cache seqlock never yields a torn read.
The SPI clock stays at 40 MHz (80 MHz fails the W5500 reset — the chip is on
GPIO-matrix pins, not the IO_MUX pins the SD card uses; 60 MHz gives no speedup,
the cost is per-transaction overhead). Flash stays DIO@80MHz: the module's 8 MB
octal (OPI) PSRAM contends with QIO flash on the S3 MSPI controller, so QIO
isn't usable here.

For comparison, ~1.8 ms typical is about 2.5x dnsmasq's ~0.7 ms — and that gap
is the Ethernet-over-SPI hardware (the ~405 us/frame SPI floor, two frames per
query), not software.

## Status and known issues

Two full-codebase reviews (June 2026) audited the firmware. The first round's
findings have since been fixed and verified on hardware; see `ISSUES.md` for the
per-item record. Resolved since the original audit:

* **Forward cache now isolates A and AAAA.** The set index folds the query type
  in (`(h ^ (qtype<<1)) & (CACHE_SETS-1)`) and a hit requires a matching
  `qtype`, so the A and AAAA records for a name occupy separate sets and both
  cache-hit on repeat — verified live (a repeat A+AAAA pair scores two cache
  hits). Originally 1024 direct-mapped slots (a warm pass over 100 distinct
  domains scored 92/100 hits); now 4-way × 512 sets (~1.1 MB PSRAM), so a
  colliding pair of hot domains costs a way, not the slot. (#43)
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
* **DoT no longer runs synchronously in the DNS task.** A dedicated worker
  task owns one persistent RFC 7858 session; dns_task enqueues and drains it
  without blocking, so a slow DoT handshake can no longer stall other
  queries. DoT is still opt-in and off by default. (closes C2, #5)

Remaining open items:

* **The "about a second" SD reload is not independently re-measured.** (#38)
* ~~Some headline ad roots aren't in the loaded list.~~ Resolved by the
  multi-source setup: with hagezi Ultimate + TIF loaded (711k domains),
  `doubleclick.net`, `ad.doubleclick.net`, and `analytics.tiktok.com` all
  sinkhole (verified 2026-08-26). It was blocklist content, not a code bug.

See the issue tracker and `ISSUES.md` for the full, code-grounded analysis.

## Hardware

Two boards are supported, selected by the `ADBLOCK_BOARD` Kconfig choice.
Both are ESP32-S3 with 16 MB flash and 8 MB octal PSRAM plus a W5500, so the
whole feature set is identical; only the pin maps and the mDNS hostname
differ. (Don't OTA-upload one board's image to the other — Ethernet comes up
dead and the rollback watchdog has to revert it.)

**LilyGO T-ETH-Elite** (default) — ESP32-S3-WROOM-1 N16R8, `esp32adblock.local`:

| function | pins |
| --- | --- |
| W5500 (SPI2) | SCLK 48, MISO 47, MOSI 21, CS 45, INT 14, 40 MHz |
| MicroSD (SPI3) | SCLK 10, MISO 9, MOSI 11, CS 12 |

**Waveshare ESP32-S3-ETH** — ESP32-S3R8, `esp32adblock2.local`:

| function | pins |
| --- | --- |
| W5500 (SPI2) | SCLK 13, MISO 12, MOSI 11, CS 14, INT 10, RST 9, 40 MHz |
| TF slot (SPI3) | SCLK 7, MISO 5, MOSI 6, CS 4 |

The SD card is optional on both boards: with no card, boot falls back to the
HTTPS blocklist download every time instead of the ~1 s SD cache reload.

## Build and flash

The default build (`sdkconfig`, `build/`) targets the **LilyGO T-ETH-Elite**.
The **Waveshare ESP32-S3-ETH** builds into its own directory with its own
sdkconfig, so the two builds never fight over the board choice:

```sh
idf.py -B build-waveshare "-DSDKCONFIG=sdkconfig.waveshare" \
  "-DSDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.board.waveshare-s3-eth" build
idf.py -B build-waveshare -p PORT flash
```

(The `-D` values are cached in the build dir after the first configure, so
later runs only need `-B build-waveshare`.)

Dual OTA partitions
(`ota_0`/`ota_1`, 1700K each) — a first flash needs all four regions from the
build's own `flash_args` (never hand-type offsets):

```sh
esptool.py --chip esp32s3 -p PORT -b 460800 write-flash \
  --flash-mode dio --flash-freq 80m --flash-size 16MB \
  0x0     bootloader.bin \
  0x8000  partition-table.bin \
  0xf000  ota_data_initial.bin \
  0x20000 dns-sink.bin
```

After that first flash, updates don't need a toolchain or serial cable at
all — use the web UI's **Network → Firmware Update** upload (see Feature set
above); it auto-reverts if the new image doesn't come up cleanly.

Or build from source (ESP-IDF v6.0.x):

```sh
idf.py set-target esp32s3
idf.py build
idf.py -p PORT flash monitor
```

First boot downloads the blocklist over HTTPS and writes it to SD. Later boots
load from SD in about a second. Point your router's DNS at the board's DHCP
address.

## Networking

Reachable via mDNS from boot, so you don't need to hunt for the DHCP lease:
**`esp32adblock.local`** on the T-ETH-Elite, **`esp32adblock2.local`** on the
Waveshare (distinct names so both boards can share a LAN).

Ethernet (W5500) is always brought up. Wi-Fi STA can run **alongside** it by
enabling `CONFIG_ADBLOCK_NET_WIFI` — both stay up together, and either link
can be down without blocking startup (Wi-Fi-only, no cable attached, is a
supported configuration). The web UI's **Network** tab controls:

| setting | notes |
| --- | --- |
| Upstream interface | Which link egresses upstream resolver queries. Lets you answer LAN queries on one ISP and resolve out the other. Applied live, no restart. |
| DHCP / static IP | Per interface. Static **must** include its DNS field — under static there is no DHCP option 6 to learn from, and falling back to the gateway breaks on CGNAT links whose gateway runs no resolver. Applied at boot; use **Reboot now**. |
| Wi-Fi network | Scan nearby APs and switch networks from the browser. Credentials live in NVS; the Kconfig SSID/password are only a first-boot seed. |

Upstream defaults to the interface's **DHCP-provided DNS server**, not its
gateway. On a normal home router those are the same box; on a mobile-hotspot
or CGNAT connection the gateway is a bare NAT hop that answers nothing on :53.

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

## Roadmap

* **Generic ESP32-S3 build (Wi-Fi only) — mostly done.** Wi-Fi STA bring-up
  runs *alongside* the W5500 (`CONFIG_ADBLOCK_NET_WIFI`, see Networking above),
  a second board is now supported via the `ADBLOCK_BOARD` pin-map choice (see
  Hardware — the Waveshare ESP32-S3-ETH port is verified on hardware, including
  a browser-OTA cutover with no serial cable attached), and the SD card is
  proven optional at runtime (a cardless Waveshare unit runs in production off
  the HTTPS download path). What's left for a truly *generic* board is making
  the W5500 itself optional so it builds with no Ethernet hardware at all.
  Note the L2 Ethernet fast-path has no Wi-Fi equivalent (no esp_eth RX
  hook), so Wi-Fi-served queries take the ~1.8 ms lwIP socket path rather than
  the L2 bypass, and blocklist storage may shrink on quad (vs octal) PSRAM.
  Tracked in #49.
* DoH/DoT *server* (serve secure DNS to clients).
* Per-list enable/disable toggle (#48 — the whole-device "pause blocking"
  half of this is now done; see Feature set above).
