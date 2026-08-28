# Changelog

All notable changes to ESP32_AdBlocker_Reborn. Versions follow SemVer; the
firmware's `esp_app_desc` version string comes from `version.txt`.

## [Unreleased] — 1.2.0

### Security

- **HTTPS-only web UI with first-boot onboarding** (#89). Self-signed ECDSA
  P-256 certificate generated on the device and kept in NVS; `:80` only
  redirects. A setup wizard gates every route until an admin account exists
  and shows the certificate fingerprint for pinning. Basic Auth replaced by
  a login form + `HttpOnly; Secure; SameSite=Strict` session cookie (30 min
  idle / 12 h absolute, 4 concurrent sessions); the password is stored as a
  salted PBKDF2-HMAC-SHA256 hash (a legacy plaintext one is hashed on first
  boot and erased). 5 failed logins → 60 s lockout. Per-session CSRF token on
  every POST in addition to the Origin/Referer check. HSTS, CSP,
  `X-Frame-Options: DENY`, `nosniff`, `no-referrer` on every response.
  Password change requires the current password and signs everyone out.
- **Blocklist sources must be `https://`** (#90), enforced at the form and at
  fetch time.
- **Setup AP is WPA2** with a random NVS-kept passphrase printed on the USB
  console, instead of open — nobody nearby can reach the setup wizard before
  the owner does.
- **USB console** gained `admin-reset`, `cert-reset`, `cert`, `setup-psk`,
  `heap`.

**Upgrading from 1.1:** the device comes up in setup mode — browse to it
right after the OTA and create the admin account, because until you do, the
first host on the LAN to open the page can. A 1.1 web password ≥ 10
characters is migrated (hashed, plaintext erased); a shorter one is dropped
and the wizard appears. The login lockout is global (one counter for the
device), so a LAN host can keep you locked out of `/login` with five bad
guesses a minute — acceptable for a LAN appliance, and `admin-reset` over
USB always works.

### Changed

- Web-page render buffers and the Wi-Fi scan table moved from internal .bss
  to PSRAM (`CONFIG_SPIRAM_ALLOW_BSS_SEG_EXTERNAL_MEMORY`), freeing ~40 KB of
  internal RAM — needed for TLS session setup to coexist with the W5500's DMA
  buffers on the Waveshare board.
- mDNS now advertises `_https._tcp` on 443.

## [1.1.0] — 2026-08-28

Everything from the "roadmap wave 1–3" work: the speed/resilience roadmap,
dual-WAN networking, the runtime-configurable web UI, and Waveshare board
support. Verified on both the LilyGO T-ETH-Elite and the Waveshare
ESP32-S3-ETH.

### Added

- **Waveshare ESP32-S3-ETH board support** via the `ADBLOCK_BOARD` Kconfig
  choice and the `sdkconfig.board.waveshare-s3-eth` overlay (separate
  `build-waveshare/` build dir).
- **Dual-WAN**: Wi-Fi STA alongside W5500 Ethernet, with the DHCP-advertised
  DNS server usable as upstream (#53, #54, #55).
- **Runtime network configuration + tabbed web UI**: per-interface DHCP/static
  IP, Wi-Fi scan + connect from the browser, static-IP form prefilled from the
  live lease (#52).
- **Upstream-parity wave**: global pause, stop-load, web UI auth, browser OTA
  firmware upload (no toolchain needed after the first flash).
- **TCP/53 listener** so TC=1 retries land on the device instead of an RST;
  TCP-origin forwards get a real answer and truncated upstream replies are
  never cached (#66).
- **DNS-over-TLS worker task** with a persistent TLS session; mbedTLS buffers
  moved to PSRAM so TLS can actually allocate (#5).
- **Clock floor + real certificate date validation** for TLS (#75).
- **Serve-stale with background refresh** — RFC 8767 optimistic cache (#68).
- **SD warm-boot for the forward cache** — RFC 8767 restore on reboot (#79).
- **Single-flight coalescing** for the upstream table (#76).
- **Hedged upstream retransmit** on the observed p95 latency (#69).
- **Dedup-aware blocklist loading**, hagezi ad-tier and threat-intel presets,
  capacity telemetry, and a per-extra-list enable/disable toggle (#48 part 1).
- **Reload diff report**: logs the exact blocklist delta vs the previous SD
  snapshot (#67).
- **CNAME-cloaking inspection** (#74, part 1 of 2).
- **UDP mailbox drain-cap pressure counter** in `/metrics` so bursts past
  `LWIP_UDP_RECVMBOX_SIZE` are no longer invisible (#81).
- **USB recovery console** over native USB-Serial-JTAG.
- `docs/simd-acceleration-notes.md`: SIMD/PIE acceleration study (verdict: no;
  three bigger wins identified and since implemented).
- `docs/http-api.md`: complete HTTP route table and `/metrics` field reference,
  checked against `web_ui.cpp`'s `uris[]` and `dns_server_metrics_json()`.
- `CONTRIBUTING.md`: the architecture constraints that have actually bitten —
  the two verdict paths, shared-cache coherence and the generation bump,
  single-task httpd, and `IRAM_ATTR` placement.

### Changed

- **4-way set-associative forward cache** with eviction / too-big telemetry;
  qtype folded into the key so A and AAAA no longer evict each other.
- **IRAM_ATTR on the L2 hot path** (#78).
- Extras are folded via chunk sort + backward merge instead of a whole-array
  qsort.
- Octal PSRAM clock 40 MHz -> 80 MHz; lwIP socket ceiling 16 -> 24.
- Software AES instead of hardware AES, removing the internal-heap DMA
  allocation that killed TLS streams mid-download (#84).
- Flash-size / Wi-Fi / watchdog settings moved into `sdkconfig.defaults` so
  the defaults reproduce the shipped build (#82).
- Wi-Fi scan runs on a worker task so it no longer blocks every web UI viewer
  (#62).
- `managed_components/` is no longer tracked in git; it is regenerated by the
  IDF component manager from `main/idf_component.yml` + `dependencies.lock`.

### Fixed

- Blocklist lines are parsed as hosts/adblock syntax instead of hashing the
  raw text — silent blocklist corruption (#65).
- Forward cache entries stamped under a stale blocklist generation are
  invalidated when a reload completes (#85).
- Pause toggle bumps the blocklist generation so stale ALLOW cache entries
  cannot survive a resume (#86).
- DNS task waits for the selected upstream interface before starting, ending
  the DHCP race for the upstream resolver and advertised LAN IP (#80).
- Hedge-stash EDNS regression.
- httpd recycles the LRU connection instead of refusing new ones (#61).
- The 10 s web UI refresh no longer resets tabs or wipes form input (#63).
- 15 verified review findings: honest telemetry, cross-extra dedup,
  windowless publish.

## [1.0.0] — 2026-06-24

Initial release: DNS sinkhole for the LilyGO T-ETH-Elite.
