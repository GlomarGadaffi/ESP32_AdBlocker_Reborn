# ESP32_AdBlocker_Reborn

A native ESP-IDF DNS sinkhole for ESP32-S3 + W5500 SPI Ethernet boards — the
LilyGO T-ETH-Elite and the Waveshare ESP32-S3-ETH (see Hardware for the
per-board pin maps). It hosts the full OISD "big" wildcard blocklist plus up to
four extra feeds (hagezi ad tiers and threat-intelligence presets built in),
sinkholes ad, tracker, and malware domains at the network layer, and forwards
and caches everything else. Pure ESP-IDF v6.0.x, no Arduino.

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
  download. The 4-hourly refresh runs in the background with the old list still
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
  CSS bar graph. POST endpoints cover blocklist reload and stop-load, pause,
  domain check, whitelist add/remove, custom rules, DNS rewrites, client ACL,
  extra blocklist URLs (set/clear/toggle), DoT config, UI auth, network and
  Wi-Fi configuration, metrics reset, reboot, and firmware upload. Full route
  and field reference: [`docs/http-api.md`](docs/http-api.md).

## Feature set

Beyond the core sinkhole, the device is a fairly complete Pi-hole-class
appliance — these are all live and verified on hardware:

* **mDNS** — reachable at `esp32adblock.local` (T-ETH-Elite) or
  `esp32adblock2.local` (Waveshare), no IP needed.
* **Multiple blocklist sources** — the built-in OISD primary plus up to four
  extra URL feeds, each NVS-persisted and each individually enable/disable-able
  without clearing its URL, with one-click presets for the
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
* **Client ACL** — restrict which client IPs may use the resolver (up to 8
  entries; empty = allow all), enforced on the socket path before any lookup.
  Note the L2 fast path does not consult it: on Ethernet, a non-permitted
  client still gets sinkhole replies and forward-cache hits, and only its cold
  queries reach the gate. Wi-Fi clients have no L2 hook and are always gated.
  See [`CONTRIBUTING.md`](CONTRIBUTING.md).
* **Query log + analytics** — a 512-entry PSRAM ring with real wall-clock
  timestamps (NTP, below), approximate top-N domains and clients, and a 60-bucket
  per-minute history graph rendered as pure CSS (no JavaScript).
* **NTP wall-clock time** — built-in lwIP SNTP against `time.nist.gov` +
  `pool.ntp.org` (UTC), so log entries carry real dates that survive reboots
  rather than seconds-since-boot.
* **DNS-over-TLS upstream (opt-in)** — forward to an encrypted upstream
  (RFC 7858, e.g. 1.1.1.1 / one.one.one.one) with automatic fallback to plain
  UDP on failure.
* **TCP/53 listener** — a client that retries over TCP after a TC=1 truncation
  lands on the device instead of an RST. TCP-origin queries forwarded upstream
  over UDP get a bare EDNS0 OPT RR appended so the upstream returns the full
  answer rather than a truncated one; truncated upstream replies are never
  cached.
* **Serve-stale with background refresh** — an expired allowed entry is
  replayed immediately (RFC 8767 / "optimistic cache", TTLs clamped to 30 s,
  stale window capped at 24 h) while a refresh goes upstream, so a repeat
  visitor never eats the cold path for a name already resolved once.
  `/metrics` reports `stale_served`.
* **Single-flight coalescing** — duplicate in-flight queries for the same
  question share one upstream request (`coalesced`).
* **Hedged upstream retransmit** — a second copy of a slow query is sent based
  on the observed p95 (`hedges_sent` / `hedged_completions`).
* **Forward-cache warm boot** — the cache is snapshotted to SD (first at
  +2 min, then every 20 min) and restored on reboot, so a power blip doesn't
  cost the working set.
* **CNAME-cloaking inspection** — a tracker hiding behind a CNAME to a
  first-party-looking name is caught by walking every answer RR's owner name
  and, for CNAMEs, their target, through the same verdict ladder as the query.
* **Cache-poisoning hardening** — randomized transaction IDs plus question
  (qname + qtype) validation on every upstream reply before it is cached.
* **USB recovery console** — a serial console over the S3's native
  USB-Serial-JTAG, for recovering a box whose network config is wrong or
  whose admin password is lost: `wifi`, `status`, `heap`, `admin-reset`,
  `cert-reset`, `cert`, `setup-psk`. Physical access is the only auth.
* **Pause blocking** — a one-click Dashboard toggle (mirroring upstream
  s60sc/ESP32_AdBlocker's "Enable AdBlocker" switch) that allows every query
  through without touching the loaded blocklist, whitelist, custom rules, or
  ACL. NVS-persisted, survives reboot. `/metrics` reports `blocklist_paused`.
* **Stop an in-progress reload** (mirrors upstream's Stop Load button) — abort
  the current blocklist download/reload; the previously-loaded list keeps
  serving throughout, same as any other reload.
* **HTTPS-only web UI with a first-boot setup wizard** (#89) — the UI is
  served only on **:443** behind a self-signed ECDSA P-256 certificate the
  device mints on first boot and keeps in NVS (`:80` just redirects). Until an
  admin account exists every route lands on `/setup`, which shows the
  certificate's SHA-256 fingerprint (also printed on the USB console, so the
  browser warning can be checked against something the device itself said)
  and creates the account. After that: login form → session cookie
  (`HttpOnly; Secure; SameSite=Strict`, 30 min idle / 12 h absolute), password
  stored only as a salted PBKDF2-HMAC-SHA256 hash, 5 failed logins → 60 s
  lockout, per-session CSRF token on every POST on top of the Origin/Referer
  check, and `Strict-Transport-Security` / CSP / `X-Frame-Options: DENY` /
  `nosniff` on every response. Changing the password needs the current one and
  signs every session out. Lost it? USB console `admin-reset` brings the
  wizard back — that needs the cable, not the network. Nothing that proves who
  you are ever crosses the wire in the clear, which is the point: this box
  holds your Wi-Fi password, the admin password, and every client's DNS
  history.
* **Blocklist sources must be `https://`** (#90) — rejected at the form and
  again at fetch time for anything left in NVS from before, so an on-path
  attacker can't rewrite the list the sinkhole trusts.
* **Setup AP for zero-touch first-boot Wi-Fi config** (mirrors upstream's
  AP-mode bootstrap) — if neither Ethernet nor Wi-Fi comes up within 30s of
  boot, a WPA2 SoftAP ("ESP32AdBlock-Setup") comes up at 192.168.4.1 serving
  the same web UI at `https://192.168.4.1`, so a phone can join it and enter
  real Wi-Fi credentials with no serial cable. Its passphrase is random,
  minted once, kept in NVS, and printed on the USB console (`setup-psk`) —
  so reaching the setup wizard over the AP takes the same physical access as
  `admin-reset`, and nobody nearby can race you to become admin. Shuts off
  automatically once any interface gets an IP. It can appear during any
  boot-time link outage longer than 30s, not just a true first boot.
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
| Auth_Name / Auth_Pass (optional login) | ✅ | Mandatory admin account + HTTPS, above (stricter than upstream) |
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
  txids. (#22, #23, #24, #28, #35, #44) Since 1.2 the UI is HTTPS-only with
  a mandatory admin account — see the feature list above. Still don't expose
  it to the internet: a self-signed cert and one password are a LAN-grade
  bar, not an internet-grade one.
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
HTTPS blocklist download every time instead of the ~1 s SD cache reload. The
Waveshare TF-slot pin map comes from that board's CircuitPython definition and
has not been tested with a card in place — a wrong pin there just fails the
mount and takes the download path.

## Build and flash

### Flash from your browser

The quickest way onto a board, and the one that needs no toolchain at all:

**<https://glomargadaffi.github.io/ESP32_AdBlocker_Reborn/flasher/>**

Plug the board into USB, click **Connect**, pick the port. The page reads the
board's flash to work out which of the two supported boards it is (the firmware
tags its version string with the board, e.g. `1.1.0+waveshare-s3-eth`) and pulls
the matching images from the latest release. You can override the detection, and
if the chip is blank or running something else you just pick the board from a
list.

Two modes: **Full flash** writes the bootloader, partition table, OTA data, and
app; **App only** writes just the OTA data and app, like an over-the-air update.
Neither erases the whole chip, so settings, Wi-Fi credentials, and blocklists in
NVS survive both.

Requirements and caveats:

* **Chrome, Edge, or Opera on desktop.** It uses the Web Serial API, which
  Firefox, Safari, and mobile browsers don't implement.
* **Close any serial monitor first** — `idf.py monitor`, PuTTY, the Arduino IDE,
  or a VS Code serial terminal will be holding the COM port, and the browser
  can't open it while they do.
* Firmware is fetched from this repo's GitHub Release and written by your own
  browser; nothing is uploaded anywhere.

There's a "flash your own build" file picker on the same page if you've built
locally and would rather not install esptool. See
[`docs/flasher/README.md`](docs/flasher/README.md) for how detection and the
release manifest work.

### Build from source

The default build (`sdkconfig`, `build/`) targets the **LilyGO T-ETH-Elite**.
The **Waveshare ESP32-S3-ETH** builds into its own directory with its own
sdkconfig, so the two builds never fight over the board choice:

```powershell
idf.py -B build-waveshare "-DSDKCONFIG=sdkconfig.waveshare" "-DSDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.board.waveshare-s3-eth" build
idf.py -B build-waveshare -p PORT flash
```

(The `-D` values are cached in the build dir after the first configure, so
later runs only need `-B build-waveshare`.)

The partition table is IDF's `two_ota_large` (`CONFIG_PARTITION_TABLE_TWO_OTA_LARGE`):
`nvs` 24K, `otadata` 8K, `phy_init` 4K, then `ota_0` and `ota_1` at 1700K
each — comfortable headroom over the current ~1.16 MB image, and well under
the board's 16 MB flash. There is no `partitions.csv` in this repo.

`idf.py -p PORT flash` flashes all four regions for you. If you need to drive
the flasher directly, take the offsets from the build's own `flash_args`
rather than hand-typing them — for the default build they are:

```powershell
python -m esptool --chip esp32s3 -p PORT -b 460800 write-flash --flash-mode dio --flash-size 16MB --flash-freq 80m 0x0 build\bootloader\bootloader.bin 0x8000 build\partition_table\partition-table.bin 0xf000 build\ota_data_initial.bin 0x20000 build\dns-sink.bin
```

That is the command `idf.py build` itself prints. ESP-IDF v6.0 ships esptool
v5: invoke it as `esptool` or `python -m esptool` (the old `esptool.py` is a
deprecation shim), and subcommands are hyphenated — `write-flash`. From inside
`build/` you can skip the offsets entirely with
`python -m esptool --chip esp32s3 write-flash "@flash_args"`.

After that first flash, updates don't need a toolchain or serial cable at
all — use the web UI's **Network → Firmware Update** upload (see Feature set
above); it auto-reverts if the new image doesn't come up cleanly.

Toolchain: **ESP-IDF v6.0.x**, natively on Windows, with the environment sourced
from PowerShell — `. $HOME\esp\esp-idf\export.ps1`. Git Bash / MSYS is not a
supported build shell for this project.

```powershell
idf.py set-target esp32s3
idf.py build
idf.py -p PORT flash monitor
```

### Cutting a release

Build both boards, then package the artifacts and publish them — this is what
feeds the browser flasher, which always reads whichever release is *latest*:

```powershell
.\tools\make-release.ps1
gh release create v1.1.0 (Get-ChildItem release\* | ForEach-Object FullName) --title "v1.1.0" --generate-notes
```

`make-release.ps1` reads the version from `version.txt`, copies the four images
per board out of `build/` and `build-waveshare/` into `release/` under board- and
version-qualified names, and writes `release/manifest.json` — taking the offsets
and the flash mode/frequency/size from each build's own `flash_args` rather than
hardcoding them. It prints the `gh` command and does not run it. `release/` is
gitignored.

(The argument list is expanded explicitly because PowerShell doesn't glob-expand
arguments to native executables, and `gh` doesn't expand them itself.)

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
  console.c        USB-Serial-JTAG recovery console
  web_tls.c        self-signed TLS identity (generate, store, fingerprint)
  web_auth.c       admin account (PBKDF2 hash), sessions, login lockout
  web_ui.cpp       HTTP status UI, JSON metrics, control endpoints
```

```
docs/http-api.md              every HTTP route + every /metrics field
docs/simd-acceleration-notes.md   SIMD/PIE acceleration study (verdict: no)
CONTRIBUTING.md               architecture constraints before touching the query path
ISSUES.md                     running, code-grounded record of findings and fixes
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
* Make `acl_permits()` reachable from the L2 fast path, or document the
  Ethernet-segment bypass as intended — see Client ACL above.

## License

MIT — see [`LICENSE`](LICENSE).
