# Changelog

All notable changes to ESP32_AdBlocker_Reborn. Versions follow SemVer; the
firmware's `esp_app_desc` version string comes from `version.txt`.

## [1.2.2] — 2026-08-28

Three fixes from the post-1.2.1 review pass (21 findings filed as #91–#111;
the rest are tracked, not blocking).

### Fixed

- **Whitelisting a domain no longer sinkholes it** (#99). Whitelist add/remove
  held the whitelist mutex across the NVS flash write, and both verdict paths
  treated a busy mutex as "not whitelisted" (= block) — so for the duration of
  every whitelist edit a whitelisted-but-blocklisted name answered 0.0.0.0, and
  the socket path cached that for 10 s. NVS writes now happen outside the lock;
  the L2 hook treats a busy mutex as "can't decide" and hands the frame to
  lwIP; the custom-rules check no longer takes the mutex when there are no
  rules (the main source of contention).
- **Setup wizard fails closed on an unidentifiable POST** (#96). `/setup` and
  `/login` refuse requests with neither a usable `Origin` nor a `Referer` —
  the exact shape of a cross-site auto-submitting form under
  referrer-policy no-referrer, which could otherwise have claimed the admin
  account during the setup window.
- **Ethernet transmit serialized** (#101). `CONFIG_ETH_TRANSMIT_MUTEX=y`: the
  L2 fast path and lwIP both transmit through the W5500, whose send sequence
  isn't atomic. The hook now checks `esp_eth_transmit()` and `/metrics` reports
  `l2_tx_fail`.

## [1.2.1] — 2026-08-28

### Added

- **Local zones (split-horizon for DoT)**: names in configurable suffixes
  (default `lan, local, home, home.arpa, internal, localdomain, intranet`) and
  any single-label name are forwarded to the router in plain DNS even when
  DoT is on. Enabling DoT used to make every router-assigned hostname
  NXDOMAIN. Upstream DNS tab → Local zones; `POST /dot/zones`.
- **Static hosts table**: the rewrite table accepts bare hostnames and holds
- `tools/make-release.ps1` refuses to package while either sdkconfig carries a
  non-empty `CONFIG_ADBLOCK_WIFI_SSID/PASSWORD`, and greps the images for the
  values: the first v1.2.0/v1.2.1 T-ETH-Elite app images were built from a
  developer sdkconfig and shipped a Wi-Fi seed — pulled and republished clean.
  48 entries (was 16); relabelled "Local hosts & DNS rewrites".

### Fixed

- Pre-session Origin check (login/setup) is case-insensitive, ignores an
  explicit port, and falls back to Referer on `Origin: null`; Referrer-Policy
  is `same-origin`. A browser login could fail with a bare "CSRF".

## [1.2.0] — 2026-08-28

### Security

- **HTTPS-only web UI with first-boot onboarding** (#89). Self-signed ECDSA
  P-256 certificate generated on the device and kept in NVS; `:80` only
  redirects. A setup wizard gates every route until an admin account exists
  and shows the certificate fingerprint for pinning. Basic Auth replaced by
  a login form + `HttpOnly; Secure; SameSite=Strict` session cookie (30 min
  idle / 12 h absolute, 4 concurrent sessions); the password is stored as a
  salted PBKDF2-HMAC-SHA256 hash (a legacy plaintext one is hashed on first
  boot and erased). 5 failed logins → 60 s lockout. Per-session CSRF token on
  every POST in addition to the Origin/Referer check. CSP,
  `X-Frame-Options: DENY`, `nosniff`, `no-referrer` on every response (no
  HSTS on purpose: with a self-signed cert it would turn `cert-reset` into a
  year-long browser lockout). Password change requires the current password
  and signs everyone out. The certificate carries EKU serverAuth, SAN =
  mDNS name + 192.168.4.1, and a 2-year validity (Apple's trust rules),
  regenerated at boot when expiring; a 3 s TLS handshake timeout keeps a
  silent client from holding the single httpd task. A UI that fails to start
  on an unverified OTA image rolls the image back instead of confirming it.
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

### Added

- **Browser flasher** (`docs/flasher/`, served from GitHub Pages): Web Serial +
  esptool-js, detects the board from the firmware's version tag, fetches the
  matching images from the latest release, flashes them at the right offsets.
  `tools/make-release.ps1` stages the per-board artifacts and `manifest.json`.
- **Board-tagged version**: `esp_app_desc_t.version` is now
  `<version.txt>+<board>` (`t-eth-elite` / `waveshare-s3-eth`).
- USB console `heap` command (internal / PSRAM free, largest, low-water).

### Changed

- Web-page render buffers and the Wi-Fi scan table moved from internal .bss
  to PSRAM (`CONFIG_SPIRAM_ALLOW_BSS_SEG_EXTERNAL_MEMORY`), taking the
  Waveshare from ~23 KB internal free / 7.6 KB largest to ~100 KB / 31 KB —
  needed for TLS session setup to coexist with the W5500's DMA buffers.
- Boot-time crypto runs on its own 12 KB task; `CONFIG_ESP_MAIN_TASK_STACK_SIZE`
  raised to 6144.
- mDNS now advertises `_https._tcp` on 443.
- CMake refuses a `build-waveshare` dir that isn't configured with its own
  `SDKCONFIG` — a shared one silently rewrote the default config with the
  Waveshare pin map.

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
