/*
 * net_bringup.h — network bring-up API, implemented in net_bringup.cpp.
 *
 * Split out of dns_sink.cpp: app_main keeps the boot order and calls these.
 * The dns_sink_* network entry points web_ui.cpp / console.c call (wifi_*,
 * net_*, set_upstream_iface, setup_ap_*, eth_built, lan_ip) are defined in
 * net_bringup.cpp with their original names and signatures; callers keep
 * declaring them themselves, so they are not repeated here.
 */
#pragma once

#include <atomic>
#include <stdint.h>
#include "sdkconfig.h"
#if CONFIG_ADBLOCK_NET_ETH
#include "esp_eth.h"
#endif

class DnsSinkServer;

/* Per-board identity, shared by dns_sink.cpp (mDNS, certificate hostname) and
 * net_bringup.cpp (DHCP option 12 hostname, boot log). */
#if CONFIG_ADBLOCK_BOARD_GENERIC_S3_WIFI

/* ── Generic ESP32-S3 dev board, Wi-Fi only (#49) ─────────────────
 * No W5500, no SD slot: nothing here but the identity. Every Ethernet/SD
 * pin map, the esp_eth bring-up, the L2 RX hook and the SD mount are
 * compiled out under !CONFIG_ADBLOCK_NET_ETH. Same default hostname as
 * the Elite — for a household that has exactly one unit, which is who
 * this target is for — so the README's esp32adblock.local just works. */
#define BOARD_NAME    "Generic ESP32-S3 (Wi-Fi)"
#define MDNS_HOSTNAME "esp32adblock"

#elif CONFIG_ADBLOCK_BOARD_WAVESHARE_S3_ETH

#define BOARD_NAME    "Waveshare ESP32-S3-ETH"
/* Distinct mDNS hostname — a T-ETH-Elite unit on the same LAN already
 * claims esp32adblock.local. */
#define MDNS_HOSTNAME "esp32adblock2"

#else /* CONFIG_ADBLOCK_BOARD_T_ETH_ELITE */

#define BOARD_NAME    "LilyGO T-ETH-Elite"
#define MDNS_HOSTNAME "esp32adblock"

#endif /* board select */

/* (#106) The Ethernet address in binary (network byte order), read by the L2 RX
 * hook against every frame's destination. 0 = no address yet, which makes the
 * hook defer everything to lwIP. Single writer: the IP/Ethernet event handlers
 * in net_bringup.cpp; the atomic is the whole cross-task contract. Exposed (not
 * wrapped in a function) because the hook is IRAM_ATTR and must not call into
 * flash-resident code. */
extern std::atomic<uint32_t> net_eth_ip_nbo;

/* The input-path callback type esp_eth_update_input_path_info() takes
 * (dns_sink.cpp's l2_input_cb). Unused (nullptr) on the Wi-Fi-only board. */
#if CONFIG_ADBLOCK_NET_ETH
typedef esp_err_t (*net_l2_input_cb_t)(esp_eth_handle_t h, uint8_t *buf, uint32_t len,
                                       void *priv, void *info);
#else
typedef void *net_l2_input_cb_t;
#endif

/* app_main's network bring-up, from event-group creation through the bounded
 * link wait, upstream-interface NVS load and the #80 selected-interface wait.
 * Call after esp_event_loop_create_default() and esp_netif_init(), and after
 * bootloader_random_enable() (the matching bootloader_random_disable() runs
 * inside, immediately before esp_wifi_init()). `dns` is the server whose
 * upstream apply_upstream_iface() updates; it must outlive the process. */
void net_bringup_init(DnsSinkServer *dns, net_l2_input_cb_t l2_cb);

/* Resolver the selected interface wants right now; for DnsSinkServer::start(). */
const char *net_initial_upstream(void);

/* Re-derive and push the live upstream; returns what it settled on. */
const char *net_apply_upstream_iface(void);

/* The address DNS clients reach us on: Ethernet if it has one, else Wi-Fi.
 * Network byte order; 0 = none yet. */
uint32_t net_own_ip_nbo(void);

/* The two boot banners that quote live interface state. */
void net_log_sinkhole_active(const char *live_upstream);
void net_log_startup_complete(void);
