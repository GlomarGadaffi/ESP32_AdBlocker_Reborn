# ESP32_AdBlocker_Reborn

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![ESP-IDF](https://img.shields.io/badge/ESP--IDF-v6.0.x-red.svg)](https://github.com/espressif/esp-idf)
[![Target](https://img.shields.io/badge/Hardware-ESP32--S3%20%2B%20W5500-green.svg)](#hardware-support)
[![Web Flasher](https://img.shields.io/badge/Web%20Flasher-Browser%20Install-brightgreen.svg)](https://glomargadaffi.github.io/ESP32_AdBlocker_Reborn/flasher/)

A high-performance, native ESP-IDF DNS sinkhole (a dedicated hardware "Pi-hole" alternative) for **ESP32-S3 + W5500 SPI Ethernet** boards. It blocks ads, tracking, and malware at the network layer for your entire home or office while consuming negligible power (~1W).

Unlike typical microcontroller blockers, this is a ground-up rewrite engineered for speed and scale: it holds **800,000+ wildcard domains** in PSRAM, answers blocked and cached queries in **~1.8 ms at ~2,200 qps** via an L2 Ethernet fast path, and boots instantly in **~1 second** from an SD card cache.

---

## ⚡ Quick Start (Up & Running in 5 Minutes)

You don't need to compile any code or install development tools to get started.

### 1. What You Need
* A supported board: **LilyGO T-ETH-Elite** or **Waveshare ESP32-S3-ETH**.
* A USB-C cable for power and flashing.
* An Ethernet cable connecting the board to your home router or network switch.
* *(Recommended)* A MicroSD card (FAT32 formatted, any size $\ge$ 1 GB) for sub-second instant boot after power outages.

---

### 2. Flash From Your Browser
1. Open **[Web Flasher](https://glomargadaffi.github.io/ESP32_AdBlocker_Reborn/flasher/)** in **Google Chrome, Microsoft Edge, or Opera** (Web Serial API required).
2. Plug your ESP32-S3 board into your computer using USB-C.
3. Click **Connect**, select your board's serial COM port, and choose **Full Flash**.
4. The flasher automatically detects your board model, pulls the latest release binaries, and flashes them to the chip.

---

### 3. Connect to Your Network
1. Plug an Ethernet cable from your router/switch into the board's RJ45 port.
2. Power the board via USB-C (or PoE if your board supports it).
3. The board will obtain an IP address via DHCP and announce itself via mDNS:
   * **LilyGO T-ETH-Elite:** `https://esp32adblock.local`
   * **Waveshare ESP32-S3-ETH:** `https://esp32adblock2.local`

*(Optional Wi-Fi Setup: If no Ethernet cable is connected, the board launches a temporary setup Wi-Fi network named `ESP32AdBlock-Setup` at `https://192.168.4.1`. The one-time setup password is printed to the USB serial console).*

---

### 4. First-Boot Security Wizard
1. Open your browser and navigate to **`https://esp32adblock.local`** (or your board's DHCP IP).
2. **Accept the Certificate Warning:** The device generates its own secure, unique ECDSA P-256 TLS certificate on first boot. Compare the SHA-256 fingerprint shown on the screen with your device console if desired, then proceed.
3. **Create Admin Credentials:** Enter an admin username and password. This protects your network configuration, Wi-Fi credentials, and DNS query history.

---

### 5. Protect Your Network
To route your home network's DNS traffic through the sinkhole:
1. Log in to your home router's admin panel.
2. Find the **DHCP / LAN Settings** section.
3. Change the **Primary DNS Server** to the IP address of your ESP32 AdBlocker (found on the dashboard).
4. Save and reboot your router (or disconnect and reconnect your devices to renew their DHCP leases).

---

## 📖 User Guide & Daily Operations

### Managing False Positives (Whitelisting)
Because the blocker stores 800,000+ domains as compact 40-bit hashes in PSRAM, there is a theoretical 1-in-350,000 chance that a legitimate website's hash collides with a blocked entry.

If a site fails to load:
1. Go to the **Dashboard** tab in the web UI.
2. Type the domain in the **Check domain** box (e.g. `example.com`) and click **Check**.
3. If it reports as blocked, paste the domain into the **Whitelist** box and click **Whitelist**.
4. Whitelist entries take precedence immediately—no reboot required.

### Adding Extra Blocklists & Hägezi Presets
The blocker comes preloaded with the **OISD Big** list (~266k wildcard domains). You can add up to 4 additional source URLs:
1. Navigate to the **Blocklist** tab.
2. Select a preset from the **Hägezi preset** dropdown:
   * **TIF Medium:** Threat intelligence & malware protection (~326k entries).
   * **Light / Normal / Pro / Pro++ / Ultimate:** Varying tiers of aggressive ad and tracker blocking.
   * **OISD NSFW:** Adult content blocking.
3. Click **Add preset**, then click **Reload blocklist** on the Dashboard.
4. *Note: When combining multiple feeds, entries are automatically deduplicated in RAM up to the 800,000-entry capacity.*

### Local DNS Rewrites (Static LAN Hosts)
To access local network devices using custom domain names (e.g. `nas.lan` or `printer`):
1. Go to the **Blocklist** tab $\to$ **Local hosts & DNS rewrites**.
2. Enter the domain name and target IPv4 address (e.g., `printer` $\to$ `192.168.1.50`).
3. Click **Add**. The sinkhole will resolve these queries locally in $<1$ ms without forwarding them upstream.

### Encrypted Upstream (DNS-over-TLS)
To encrypt your upstream DNS queries and keep your ISP from tracking your browsing:
1. Go to the **Upstream DNS** tab.
2. Check **Enable DNS-over-TLS (DoT)**.
3. Default providers are pre-configured:
   * Cloudflare: `1.1.1.1` (SNI: `one.one.one.one`)
   * Quad9: `9.9.9.9` (SNI: `dns.quad9.net`)
4. Local network domains (`.lan`, `.local`, `.home.arpa`) are automatically routed to your router in plain DNS so internal devices continue resolving seamlessly.

### Updating Firmware (OTA)
Upgrades do not require a USB cable or toolchain:
1. Download the latest release `.bin` file from the [Releases](https://github.com/GlomarGadaffi/ESP32_AdBlocker_Reborn/releases) page.
2. Open the web UI $\to$ **Network** tab $\to$ **Firmware Update**.
3. Choose the `.bin` file and click **Upload & apply**.
4. The board flashes the new image into its second partition and reboots.
5. **Failsafe Rollback:** If a bad image fails to boot or start the network, the hardware bootloader automatically rolls back to the previous working firmware.

### Emergency USB Recovery Console
If you forget your admin password, lose network access, or enter invalid IP settings:
1. Connect the board to your PC via USB-C.
2. Open any serial terminal (e.g., PuTTY, Arduino Serial Monitor, or Web Serial) at **115200 baud**.
3. Available recovery commands:
   * `admin-reset` — Clears the web UI admin account so you can run the setup wizard again.
   * `cert-reset` — Erases the TLS identity and generates a new certificate on reboot.
   * `wifi "<SSID>" <password>` — Sets new Wi-Fi credentials and reconnects.
   * `status` — Prints board uptime, link status, and IP addresses.
   * `heap` — Displays internal and external PSRAM utilization.

---

## 🛠️ Hardware Support

Both supported boards run the **ESP32-S3** with 16 MB flash, 8 MB Octal PSRAM, and a W5500 SPI Ethernet controller:

| Board | Default Hostname | W5500 Ethernet Pins | MicroSD Slot Pins | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **LilyGO T-ETH-Elite** *(Default)* | `esp32adblock.local` | SCLK 48, MISO 47, MOSI 21, CS 45, INT 14 (40 MHz) | SCLK 10, MISO 9, MOSI 11, CS 12 | Recommended board; full PoE options available |
| **Waveshare ESP32-S3-ETH** | `esp32adblock2.local` | SCLK 13, MISO 12, MOSI 11, CS 14, INT 10, RST 9 (40 MHz) | SCLK 7, MISO 5, MOSI 6, CS 4 | Compact form factor; separate build target |

> **Note on MicroSD Cards:** A MicroSD card is optional but strongly recommended. Without a card, the device will re-download the blocklist over HTTPS on every boot (~2–3 minutes) instead of reloading from SD in ~1 second.

---

## 🔬 How It Works: Technical Architecture

### 1. 40-Bit Bucket-Split Hash Table
Storing 800,000 domain strings directly would require over 25 MB of RAM—far exceeding the ESP32-S3's 8 MB PSRAM. Storing standard 32-bit hashes causes frequent collisions (~1 in 1,500 domains falsely blocked).

**The Solution:** A 40-bit hash is partitioned using hash quotienting:
$$\text{40-bit hash} = \underbrace{\text{Top 16 bits}}_{\text{Bucket Index } (q)} \ + \ \underbrace{\text{Bottom 24 bits}}_{\text{Stored Remainder } (r)}$$

* **Index Array:** A 65,537-slot lookup table ($262\text{ KB}$) maps bucket $q$ directly to its slice in memory.
* **Entries Array:** Only the 3-byte remainder ($r$) is stored per domain.
* **Result:** Total memory is only **$2.54\text{ MB}$** for 800,000 domains (smaller than a 32-bit array), while false-positive collisions drop to **1 in ~350,000**.
* **Search Speed:** Lookups probe only the tiny bucket slice ($\approx 12$ entries), completing in **~4 binary probes** localized within two 32-byte CPU cache lines.

### 2. Layer 2 (L2) Ethernet Fast Path
In standard firmware, incoming DNS UDP packets must traverse:
$$\text{Hardware} \longrightarrow \text{Driver ISR} \longrightarrow \text{lwIP Stack} \longrightarrow \text{Socket Layer} \longrightarrow \text{FreeRTOS Context Switch} \longrightarrow \text{DNS Task}$$

**The Reborn Fast Path:**
* The W5500 driver registers an input hook (`esp_eth_update_input_path_info`).
* Blocked queries and forward-cache hits are parsed and answered **directly inside the L2 Ethernet receive callback**.
* The DNS response packet is synthesized in place and transmitted immediately with `esp_eth_transmit()`.
* **Zero task switching, zero socket allocations, zero lwIP overhead.** Only cold/uncached queries ever reach the socket layer to go upstream.

### 3. PSRAM Forward Cache & Optimistic Stale Serving (RFC 8767)
* **4-Way Set-Associative Cache:** 512 sets (2,048 entries) in PSRAM. Query type is folded into the hash key so `A` and `AAAA` records for the same domain never evict each other.
* **Serve-Stale:** If an allowed domain's TTL has expired, the cached answer is replayed immediately to the client while a refresh query is dispatched in the background. LAN clients never wait for upstream round trips on frequently visited sites.
* **Single-Flight Coalescing & Hedging:** Duplicate concurrent requests for the same un-cached domain share a single upstream socket. If an upstream query exceeds the observed p95 response time, a hedged duplicate query is sent.
* **CNAME Cloaking Defense:** All CNAME targets in upstream replies are recursively inspected against the blocklist to catch third-party trackers disguised as first-party subdomains.

---

## 📊 Measured Performance

Tested LAN client to board over wired Ethernet:

| Query Type | Typical Latency (p50, c=1) | Minimum Latency | Saturated Throughput |
| :--- | :--- | :--- | :--- |
| **Blocked (L2 fast path)** | **1.8 ms** | 0.66 ms | **~2,200 qps** |
| **Allowed, Cached (L2 fast path)** | **1.8 ms** | 0.67 ms | **~2,100 qps** |
| **Allowed, Cold (Upstream Forward)** | ~40 ms (Gateway RTT) | — | Dependent on ISP |

*Note: The ~1.8 ms response time is hardware-bound by the SPI transaction time of the W5500 controller (two SPI transfers per query at 40 MHz). The internal blocklist lookup itself takes only ~64 microseconds.*

---

## 💻 Building from Source

If you prefer building and flashing via the command line:

### Prerequisites
* ESP-IDF **v6.0.x** installed natively on Windows (run inside PowerShell: `. $HOME\esp\esp-idf\export.ps1`).

### LilyGO T-ETH-Elite (Default Build)
```powershell
idf.py set-target esp32s3
idf.py build
idf.py -p COM_PORT flash monitor
```

### Waveshare ESP32-S3-ETH Build
```powershell
idf.py -B build-waveshare "-DSDKCONFIG=sdkconfig.waveshare" "-DSDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.board.waveshare-s3-eth" build
idf.py -B build-waveshare -p COM_PORT flash
```

---

## 📁 Repository Structure

```
├── main/
│   ├── dns_sink.cpp      # W5500 + SD bringup, L2 fast-path RX hook, SNTP time
│   ├── dns_server.cpp    # UDP/TCP :53 server, forward cache, DoT, /metrics
│   ├── blocklist.c       # 40-bit bucket-split hash table, radix sort, SD snapshotting
│   ├── bl_table.c        # Bucket index search and chunk merge algorithms
│   ├── web_ui.cpp        # HTTPS control dashboard, CSS analytics graph, API routes
│   ├── web_tls.c         # Hardware ECDSA P-256 TLS cert generator & fingerprinting
│   ├── web_auth.c        # PBKDF2 authentication, CSRF tokens, session management
│   ├── console.c         # USB-Serial-JTAG out-of-band recovery console
│   ├── dot.c             # DNS-over-TLS upstream client (RFC 7858)
│   ├── query_log.c       # PSRAM query history ring buffer & analytics
│   ├── rewrite.c         # Local DNS rewrite rules & static hosts
│   ├── localzone.c       # Split-horizon local domain forwarding
│   └── acl.c             # Client IP access control list
├── docs/
│   ├── blocklist-format.md          # In-depth mathematical analysis of bucket-split storage
│   ├── http-api.md                  # Complete REST API route and field reference
│   ├── simd-acceleration-notes.md  # ESP32-S3 Xtensa PIE / SIMD performance study
│   └── flasher/                     # Web Serial browser flasher implementation
```

---

## 📜 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for details.
