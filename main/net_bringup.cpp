/*
 * net_bringup.cpp — network bring-up, split out of dns_sink.cpp.
 *
 * W5500 Ethernet (SPI2, event-group DHCP wait), Wi-Fi STA + runtime enable
 * flag, the setup AP, static-IP/NVS network config, the IP / Wi-Fi / Ethernet
 * event handlers, and upstream-interface selection (pick_upstream /
 * apply_upstream_iface). app_main (dns_sink.cpp) drives it through the small
 * API in net_bringup.h; the dns_sink_* network entry points the web UI and
 * console call live here under their original names.
 *
 * The W5500 pin map is selected per board via the ADBLOCK_BOARD Kconfig
 * choice: LilyGO T-ETH-Elite (default) or Waveshare ESP32-S3-ETH. The Wi-Fi-only
 * generic board has no W5500, so none of the Ethernet code is compiled for it.
 */

#include "net_bringup.h"
#include "nvs_keys.h"     /* every NVS key this project owns, in one place (#111) */
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"

#include "esp_system.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_idf_version.h"
#if CONFIG_ADBLOCK_NET_ETH
#include "esp_eth.h"
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(6, 0, 0)
#include "esp_eth_mac_w5500.h"
#include "esp_eth_phy_w5500.h"
#endif
#endif
#if CONFIG_ADBLOCK_NET_WIFI
#include "esp_wifi.h"
#endif
#include "esp_netif.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_mac.h"
#include "esp_random.h"
#include "bootloader_random.h"
#include "esp_timer.h"
#include "esp_attr.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"

#include "driver/gpio.h"
#include "driver/spi_master.h"

#include <atomic>

#include "dns_server.h"
#include <cstring>
#include <cstdlib>
#include <cstdio>

static const char *TAG = "dns_sink";   /* unchanged from dns_sink.cpp so log lines stay identical */

#if CONFIG_ADBLOCK_BOARD_GENERIC_S3_WIFI

/* Generic ESP32-S3 dev board, Wi-Fi only (#49): no W5500 pin map, nothing
 * Ethernet is compiled out under !CONFIG_ADBLOCK_NET_ETH. */

#elif CONFIG_ADBLOCK_BOARD_WAVESHARE_S3_ETH

/* ── Pin map: Waveshare ESP32-S3-ETH (ESP32-S3R8 + W5500) ──────── */
#define W5500_SCLK_GPIO  13
#define W5500_MISO_GPIO  12
#define W5500_MOSI_GPIO  11
#define W5500_CS_GPIO    14
#define W5500_INT_GPIO   10
#define W5500_RST_GPIO   9   /* real hardware reset line (the Elite has none) */
#define W5500_SPI_HOST   SPI2_HOST
/* Also GPIO-matrix pins (SCLK=13 ≠ FSPICLK=12, so no IO_MUX), same regime the
 * Elite proved 40 MHz in. If w5500_reset aborts at boot, drop to 25. */
#define W5500_SPI_CLOCK  40

#else /* CONFIG_ADBLOCK_BOARD_T_ETH_ELITE */

/* ── W5500 pin map: LilyGO T-ETH-ELITE S3 ──────────────────────── */
#define W5500_SCLK_GPIO  48
#define W5500_MISO_GPIO  47
#define W5500_MOSI_GPIO  21
#define W5500_CS_GPIO    45
#define W5500_INT_GPIO   14
#define W5500_RST_GPIO   -1
#define W5500_SPI_HOST   SPI2_HOST
/* SPI clock (MHz). W5500 is on GPIO-matrix pins (48/47/21/45), not the S3
 * IO_MUX FSPI pins (those are wired to the SD card), so the matrix MISO-sampling
 * delay caps it: 80 hard-fails w5500_reset. 60 is stable but measured IDENTICAL
 * latency/qps to 40 (per-query cost is transaction overhead, not clocking), so
 * we stay at the proven-safe 40 — what survives sustained full-duplex load. */
#define W5500_SPI_CLOCK  40

#endif /* board select */

/* ── Event group ─────────────────────────────────────────────────── */
#define ETH_CONNECTED_BIT   BIT0
#define ETH_GOT_IP_BIT      BIT1
#define WIFI_CONNECTED_BIT  BIT2
#define WIFI_GOT_IP_BIT     BIT3
static EventGroupHandle_t s_eth_eg = nullptr;
/* The DnsSinkServer owned by dns_sink.cpp, handed in by net_bringup_init() before any
 * event handler is registered; apply_upstream_iface() pushes the live upstream into it. */
static DnsSinkServer *s_dns_target = nullptr;
/* (#106) The same Ethernet address as s_ip, kept in binary (network byte
 * order) because the L2 RX hook has to compare it against every frame's
 * destination and must not parse a string there. 0 = no address yet, which
 * makes the hook defer everything to lwIP. */
std::atomic<uint32_t> net_eth_ip_nbo{0};   /* declared in net_bringup.h; sole writer is this file */
static char               s_ip[16] = {};      /* Ethernet IP — the LAN-facing address, reported to clients/mDNS/web UI */
static char               s_nm[16] = {};      /* Ethernet netmask */
static char               s_gw[16] = {};      /* Ethernet DHCP gateway */
static char               s_eth_dns[16] = {}; /* Ethernet DHCP-provided DNS server (option 6) — the real upstream target */
/* (#72) The SECOND resolver from the same option-6 list, when the lease carries
 * one. Empty is the normal, fully-supported case — see set_upstream(). Only
 * DHCP fills this; the static-IP form has a single DNS field and leaves it
 * empty, which is the same as having no secondary. */
static char               s_eth_dns2[16] = {};
#if CONFIG_ADBLOCK_NET_WIFI
static char               s_wifi_ip[16] = {};
static char               s_wifi_nm[16] = {};   /* Wi-Fi netmask */
static char               s_wifi_gw[16] = {};   /* Wi-Fi DHCP gateway */
static char               s_wifi_dns[16] = {};  /* Wi-Fi DHCP-provided DNS server — see s_eth_dns */
static char               s_wifi_dns2[16] = {}; /* (#72) — see s_eth_dns2 */
#endif

/* ── Dual-WAN upstream-interface selection (#53) ──────────────────────────
 * Which interface's gateway egresses upstream resolver queries (persisted in
 * NVS so it survives reboot). Listening on port 53 already happens on every
 * up interface (client socket binds INADDR_ANY) — this only steers the
 * *outbound* forwarding socket, via lwIP's subnet-based routing: sending to
 * a gateway IP that only one netif's subnet contains routes out that netif
 * automatically, no explicit interface binding needed. */
#define NVS_NS       NVS_NS_MAIN
#define NVS_KEY_UPIF NVSK_UPSTREAM_IF
static char s_upstream_iface[8] = "eth";   /* "eth" or "wifi" */

#if CONFIG_ADBLOCK_NET_WIFI
/* Whether Wi-Fi STA is actually brought up this boot. CONFIG_ADBLOCK_NET_WIFI
 * used to be both "compiled in" and "active" at once, which meant disabling
 * dual-WAN needed a reflash. It now only gates compilation; this NVS-backed
 * flag (seeded from Kconfig on first boot — see wifi_enabled_init_nvs) is the
 * runtime switch, toggleable from the web UI's Network tab. */
static bool s_wifi_enabled = false;
#endif

/* #80: how long to let the SELECTED upstream interface finish DHCP before
 * giving up and starting on the fallback resolver. Long enough for a normal
 * lease, short enough that a cable-out boot is not visibly stalled. */
#define UPSTREAM_IFACE_WAIT_MS 5000

/* How long to wait for ANY link (Ethernet or Wi-Fi) before falling back to
 * the setup AP (#1 — see start_setup_ap). Matches upstream ESP32_AdBlocker's
 * own wifiTimeoutSecs default (30s) closely enough; this device also has
 * Ethernet racing in parallel, so most real boots never reach this wait. */
#define WIFI_SETUP_AP_TIMEOUT_MS 30000

extern "C" bool dns_sink_wifi_built(void)
{
#if CONFIG_ADBLOCK_NET_WIFI
    return true;
#else
    return false;
#endif
}

/* Whether Wi-Fi is actually up (or will be, next boot) — distinct from
 * dns_sink_wifi_built(): a build can have Wi-Fi compiled in but currently
 * disabled at runtime. */
extern "C" bool dns_sink_wifi_enabled(void)
{
#if CONFIG_ADBLOCK_NET_WIFI
    return s_wifi_enabled;
#else
    return false;
#endif
}

/* Called from web_ui.cpp POST /net/wifi/enable. Persists to NVS ONLY —
 * deliberately does NOT touch s_wifi_enabled. Same contract as
 * dns_sink_net_set_static: takes effect on next reboot, not live (starting
 * or tearing down esp_wifi on a running system is the same class of risky
 * transition this codebase already avoids for DHCP). Mutating the live flag
 * here would let dns_sink_set_upstream_iface() and dns_sink_wifi_set_creds()
 * act as though the radio were already up when it isn't — see
 * dns_sink_wifi_enabled_pending() for the NVS-only view the web UI checkbox
 * needs instead. Returns false if this board has no Ethernet to fall back to
 * (#49) and the caller tried to turn Wi-Fi off. */
extern "C" bool dns_sink_wifi_set_enabled(bool on)
{
#if !CONFIG_ADBLOCK_NET_WIFI
    (void)on;
    return false;
#else
#if !CONFIG_ADBLOCK_NET_ETH
    if (!on) return false;
#endif
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_u8(h, NVSK_WIFI_EN, on ? 1 : 0);
        nvs_commit(h);
        nvs_close(h);
    }
    return true;
#endif
}

/* The saved-for-next-boot value, for the web UI checkbox — distinct from
 * dns_sink_wifi_enabled()'s live value, which only changes on reboot. Falls
 * back to the live value when NVS has no entry yet (pre-migration boot,
 * between wifi_enabled_init_nvs() seeding it and this being read — in
 * practice never, since app_main seeds it before web_ui_start(), but a
 * missing key must not read as "false" and show the wrong pending state). */
extern "C" bool dns_sink_wifi_enabled_pending(void)
{
#if !CONFIG_ADBLOCK_NET_WIFI
    return false;
#else
#if !CONFIG_ADBLOCK_NET_ETH
    return true;
#else
    nvs_handle_t h;
    uint8_t en;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) == ESP_OK) {
        if (nvs_get_u8(h, NVSK_WIFI_EN, &en) == ESP_OK) {
            nvs_close(h);
            return en != 0;
        }
        nvs_close(h);
    }
    return s_wifi_enabled;
#endif
#endif
}

/* Populate current interface IPs + active upstream selection for the web UI. */
extern "C" void dns_sink_net_status(char *iface, size_t iface_cap,
                                     char *eth_ip, size_t eth_cap,
                                     char *wifi_ip, size_t wifi_cap)
{
    if (iface) snprintf(iface, iface_cap, "%s", s_upstream_iface);
    if (eth_ip) snprintf(eth_ip, eth_cap, "%s", s_ip);
#if CONFIG_ADBLOCK_NET_WIFI
    if (wifi_ip) snprintf(wifi_ip, wifi_cap, "%s", s_wifi_ip);
#else
    if (wifi_ip && wifi_cap) wifi_ip[0] = '\0';
#endif
}

/* Recompute which resolver is the active upstream and push it live — no DNS
 * task restart, in-flight queries are unaffected (see DnsSinkServer::set_upstream).
 *
 * Upstream = the DHCP-provided DNS server (option 6) for the selected
 * interface, NOT its gateway. On a typical home router these are often the
 * same box, but on a mobile-hotspot/CGNAT connection (the Cox link this was
 * built for) they're not: the gateway is a bare NAT hop with no resolver at
 * all, while DHCP still hands out real, working DNS server IPs separately
 * (observed: gw 100.72.0.1 doesn't answer on :53; DNS servers 68.2.16.25/.30
 * do). Falls back to the gateway, then to 1.1.1.1, only if DHCP genuinely
 * didn't provide a DNS server. */
static const char *pick_upstream(const char *dns, const char *gw)
{
    if (dns[0] != '\0') return dns;
    if (gw[0]  != '\0') return gw;
    return "1.1.1.1";
}

/* Returns the upstream it settled on, so a caller can log the value that is
 * actually live rather than one it computed separately (#80). Existing callers
 * ignore the return; nothing else changes for them. */
static const char *apply_upstream_iface(void)
{
    const char *upstream = pick_upstream(s_eth_dns, s_gw);
    /* (#72) Take the secondary from the SELECTED interface's slot, matching
     * the primary: #53's routing argument (a resolver reachable only through
     * one netif's subnet egresses out that netif automatically) holds
     * per-interface, so a secondary belonging to the other WAN would leave via
     * the wrong one. lwIP's global DNS table can still hand us exactly that on
     * a dual-WAN board — see fetch_dhcp_dns for why, and why the cost is one
     * unanswered hedge rather than a wrong answer. The gateway fallback above
     * is deliberately not repeated here: it is the primary's last resort, not
     * a second opinion. */
    const char *upstream2 = s_eth_dns2;
#if CONFIG_ADBLOCK_NET_WIFI
    if (strcmp(s_upstream_iface, "wifi") == 0) {
        upstream  = pick_upstream(s_wifi_dns, s_wifi_gw);
        upstream2 = s_wifi_dns2;
    }
#endif
    /* A secondary identical to the primary is left alone: the hedge then goes
     * to the same resolver it already would have, i.e. exactly pre-#72
     * behaviour, so there is nothing to special-case. */
    if (s_dns_target) s_dns_target->set_upstream(upstream, upstream2);
    return upstream;
}

/* Called from web_ui.cpp POST /net/upstream. Returns false on an invalid or
 * unavailable (not built / not yet connected) interface — caller keeps the
 * previous setting in that case. */
extern "C" bool dns_sink_set_upstream_iface(const char *iface)
{
    if (!iface) return false;
    bool known = false;
#if CONFIG_ADBLOCK_NET_ETH
    if (strcmp(iface, "eth") == 0) known = true;
#endif
#if CONFIG_ADBLOCK_NET_WIFI
    if (strcmp(iface, "wifi") == 0) known = s_wifi_enabled;
#endif
    if (!known) return false;

    snprintf(s_upstream_iface, sizeof(s_upstream_iface), "%s", iface);

    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_str(h, NVS_KEY_UPIF, s_upstream_iface);
        nvs_commit(h);
        nvs_close(h);
    }
    apply_upstream_iface();
    return true;
}

static void upstream_iface_init_nvs(void)
{
#if CONFIG_ADBLOCK_NET_WIFI
    if (s_wifi_enabled)
        snprintf(s_upstream_iface, sizeof(s_upstream_iface), "wifi");  /* default when dual-stack and active */
#endif
#if !CONFIG_ADBLOCK_NET_ETH
    /* (#49) Wi-Fi is the only link: an NVS value of "eth" (left by an
     * Ethernet build that ran on this flash before) would select an
     * interface that does not exist and egress on the fallback resolver. */
    return;
#endif
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) return;
    size_t len = sizeof(s_upstream_iface);
    nvs_get_str(h, NVS_KEY_UPIF, s_upstream_iface, &len);
    nvs_close(h);
#if CONFIG_ADBLOCK_NET_WIFI
    /* A saved "wifi" preference from before Wi-Fi was disabled at runtime
     * would otherwise egress on the 1.1.1.1 fallback with s_wifi_dns empty. */
    if (!s_wifi_enabled && strcmp(s_upstream_iface, "wifi") == 0)
        snprintf(s_upstream_iface, sizeof(s_upstream_iface), "eth");
#endif
}

/* ── Static IP vs DHCP (#55) ────────────────────────────────────────────
 * Applied only at boot — no live DHCP-client-state transition on a running
 * netif, which is the risky part (stopping/starting dhcpc mid-flight can
 * wedge the netif). Changing a form field here just persists to NVS; the
 * web UI's save action tells the user to reboot to apply, same as most
 * router admin panels handle this exact class of change. */
struct NetStaticCfg {
    bool dhcp = true;
    char ip[16]  = {};
    char nm[16]  = {};
    char gw[16]  = {};
    char dns[16] = {};
};

/* Loaded once at bring-up, then read by the link-up handlers to publish the
 * address at the right moment (see publish_static_eth/publish_static_wifi). */
static NetStaticCfg s_eth_static;

static void netcfg_load(const char *prefix, NetStaticCfg *cfg)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) return;
    char key[24];
    uint8_t mode = 1;   /* default: DHCP */
    snprintf(key, sizeof(key), NVSK_NET_MODE_FMT, prefix); nvs_get_u8(h, key, &mode);
    cfg->dhcp = (mode != 0);
    size_t len;
    len = sizeof(cfg->ip);  snprintf(key, sizeof(key), NVSK_NET_IP_FMT,  prefix); nvs_get_str(h, key, cfg->ip,  &len);
    len = sizeof(cfg->nm);  snprintf(key, sizeof(key), NVSK_NET_NM_FMT,  prefix); nvs_get_str(h, key, cfg->nm,  &len);
    len = sizeof(cfg->gw);  snprintf(key, sizeof(key), NVSK_NET_GW_FMT,  prefix); nvs_get_str(h, key, cfg->gw,  &len);
    len = sizeof(cfg->dns); snprintf(key, sizeof(key), NVSK_NET_DNS_FMT, prefix); nvs_get_str(h, key, cfg->dns, &len);
    nvs_close(h);
}

/* Called from web_ui.cpp POST /net/{eth,wifi}/set. iface = "eth" or "wifi". */
extern "C" bool dns_sink_net_set_static(const char *iface, bool dhcp,
                                         const char *ip, const char *nm,
                                         const char *gw, const char *dns_ip)
{
    if (strcmp(iface, "eth") != 0 && strcmp(iface, "wifi") != 0) return false;
    if (!dhcp) {
        struct in_addr a;
        if (!ip || !inet_aton(ip, &a)) return false;
        if (!nm || !inet_aton(nm, &a)) return false;
        if (gw && gw[0] && !inet_aton(gw, &a)) return false;
        if (dns_ip && dns_ip[0] && !inet_aton(dns_ip, &a)) return false;
    }
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) return false;
    char key[24];
    snprintf(key, sizeof(key), NVSK_NET_MODE_FMT, iface); nvs_set_u8(h, key, dhcp ? 1 : 0);
    snprintf(key, sizeof(key), NVSK_NET_IP_FMT,   iface); nvs_set_str(h, key, ip ? ip : "");
    snprintf(key, sizeof(key), NVSK_NET_NM_FMT,   iface); nvs_set_str(h, key, nm ? nm : "");
    snprintf(key, sizeof(key), NVSK_NET_GW_FMT,   iface); nvs_set_str(h, key, gw ? gw : "");
    snprintf(key, sizeof(key), NVSK_NET_DNS_FMT,  iface); nvs_set_str(h, key, dns_ip ? dns_ip : "");
    nvs_commit(h);
    nvs_close(h);
    return true;
}

/* Populate current NVS-stored config for the web UI form (not necessarily
 * what's active right now if it hasn't been rebooted since a change). */
extern "C" void dns_sink_net_get_static(const char *iface, bool *dhcp,
                                         char *ip, size_t ip_cap,
                                         char *nm, size_t nm_cap,
                                         char *gw, size_t gw_cap,
                                         char *dns_ip, size_t dns_cap)
{
    NetStaticCfg cfg;
    netcfg_load(iface, &cfg);
    if (dhcp) *dhcp = cfg.dhcp;
    if (ip)     snprintf(ip,     ip_cap,  "%s", cfg.ip);
    if (nm)     snprintf(nm,     nm_cap,  "%s", cfg.nm);
    if (gw)     snprintf(gw,     gw_cap,  "%s", cfg.gw);
    if (dns_ip) snprintf(dns_ip, dns_cap, "%s", cfg.dns);
}

/* Live addressing for an interface — the DHCP lease as it arrived, or the
 * static config once the link actually came up. The web UI prefills the
 * static-IP form from this when the interface is in DHCP mode, so "go
 * static, keep this address" is just picking the radio and hitting Save.
 * Empty strings while the interface is down. */
extern "C" void dns_sink_net_get_current(const char *iface,
                                          char *ip, size_t ip_cap,
                                          char *nm, size_t nm_cap,
                                          char *gw, size_t gw_cap,
                                          char *dns_ip, size_t dns_cap)
{
    const char *cip = "", *cnm = "", *cgw = "", *cdns = "";
    if (strcmp(iface, "eth") == 0) {
        cip = s_ip; cnm = s_nm; cgw = s_gw; cdns = s_eth_dns;
    }
#if CONFIG_ADBLOCK_NET_WIFI
    else if (strcmp(iface, "wifi") == 0) {
        cip = s_wifi_ip; cnm = s_wifi_nm; cgw = s_wifi_gw; cdns = s_wifi_dns;
    }
#endif
    if (ip)     snprintf(ip,     ip_cap,  "%s", cip);
    if (nm)     snprintf(nm,     nm_cap,  "%s", cnm);
    if (gw)     snprintf(gw,     gw_cap,  "%s", cgw);
    if (dns_ip) snprintf(dns_ip, dns_cap, "%s", cdns);
}

/* Stop the netif's DHCP client and push a static IP/netmask/gateway/DNS.
 * Must run before esp_eth_start()/esp_wifi_connect() — dhcpc_stop() on an
 * already-running client mid-connection is the unsupported transition that
 * risks wedging the netif; doing it here, before the link/radio is even up,
 * avoids that entirely. */
static void apply_static_ip(esp_netif_t *netif, const NetStaticCfg &cfg)
{
    esp_err_t rc = esp_netif_dhcpc_stop(netif);
    if (rc != ESP_OK && rc != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STOPPED)
        ESP_LOGW(TAG, "dhcpc_stop: %s", esp_err_to_name(rc));

    esp_netif_ip_info_t ipinfo = {};
    struct in_addr a;
    inet_aton(cfg.ip, &a); ipinfo.ip.addr = a.s_addr;
    inet_aton(cfg.nm, &a); ipinfo.netmask.addr = a.s_addr;
    if (cfg.gw[0]) { inet_aton(cfg.gw, &a); ipinfo.gw.addr = a.s_addr; }
    ESP_ERROR_CHECK(esp_netif_set_ip_info(netif, &ipinfo));

    if (cfg.dns[0]) {
        esp_netif_dns_info_t dns_info = {};
        dns_info.ip.type = ESP_IPADDR_TYPE_V4;
        inet_aton(cfg.dns, &a); dns_info.ip.u_addr.ip4.addr = a.s_addr;
        esp_netif_set_dns_info(netif, ESP_NETIF_DNS_MAIN, &dns_info);
    }
}

#if CONFIG_ADBLOCK_NET_WIFI
static void stop_setup_ap_if_active(void);   /* defined below wifi_creds_init_nvs (#1) */
#endif

/* Publish a statically-configured interface's address — deferred to the
 * link-up event rather than done at config time (#56). A static netif never
 * fires IP_EVENT_*_GOT_IP, so the "got IP" bit has to be raised by hand; doing
 * it at config time (before esp_eth_start/esp_wifi_start) made app_main declare
 * the network ready and pin upstream DNS to the static gateway while the link
 * was still down — observed answering on 192.168.50.10 with the port empty,
 * which leaves every forwarded query timing out on an Ethernet-only build. */
#if CONFIG_ADBLOCK_NET_ETH
static void publish_static_eth(void)
{
    if (s_eth_static.dhcp) return;
    snprintf(s_ip,      sizeof(s_ip),      "%s", s_eth_static.ip);
    snprintf(s_nm,      sizeof(s_nm),      "%s", s_eth_static.nm);
    snprintf(s_gw,      sizeof(s_gw),      "%s", s_eth_static.gw);
    snprintf(s_eth_dns, sizeof(s_eth_dns), "%s", s_eth_static.dns);
    ESP_LOGI(TAG, "Ethernet link up — static IP: %s  GW: %s  DNS: %s",
             s_ip, s_gw[0] ? s_gw : "(none)", s_eth_dns[0] ? s_eth_dns : "(none)");
    net_eth_ip_nbo.store(inet_addr(s_eth_static.ip), std::memory_order_relaxed);
    xEventGroupSetBits(s_eth_eg, ETH_GOT_IP_BIT);
    apply_upstream_iface();
#if CONFIG_ADBLOCK_NET_WIFI
    stop_setup_ap_if_active();
#endif
}

#endif
/* ── Ethernet event handlers ─────────────────────────────────────── */
#if CONFIG_ADBLOCK_NET_ETH
static void eth_event_handler(void *, esp_event_base_t, int32_t event_id, void *)
{
    if (event_id == ETHERNET_EVENT_CONNECTED) {
        xEventGroupSetBits(s_eth_eg, ETH_CONNECTED_BIT);
        publish_static_eth();      /* no-op under DHCP — the lease drives it instead */
    } else if (event_id == ETHERNET_EVENT_DISCONNECTED) {
        xEventGroupClearBits(s_eth_eg, ETH_CONNECTED_BIT | ETH_GOT_IP_BIT);
        net_eth_ip_nbo.store(0, std::memory_order_relaxed);   /* (#106) hook defers while down */
        if (!s_eth_static.dhcp) { s_ip[0] = '\0'; s_nm[0] = '\0'; s_gw[0] = '\0'; s_eth_dns[0] = '\0'; }
    }
}
#endif

extern "C" bool dns_sink_eth_built(void)
{
#if CONFIG_ADBLOCK_NET_ETH
    return true;
#else
    return false;
#endif
}

/* Read one DHCP-provided DNS server (option 6) for a netif, if any. */
static void fetch_dhcp_dns_one(esp_netif_t *netif, esp_netif_dns_type_t type,
                               char *out, size_t cap)
{
    esp_netif_dns_info_t dns{};
    if (esp_netif_get_dns_info(netif, type, &dns) == ESP_OK
        && dns.ip.type == ESP_IPADDR_TYPE_V4 && dns.ip.u_addr.ip4.addr != 0) {
        esp_ip4addr_ntoa(&dns.ip.u_addr.ip4, out, cap);
    } else {
        out[0] = '\0';
    }
}

/* (#72) Both DHCP-provided resolvers. Routers hand out option 6 as a LIST and
 * lwIP already stores it — dhcp_bind() walks the list into DNS server slots
 * 0..DNS_MAX_SERVERS-1 — so the second address costs a read, not a config
 * field.
 *
 * Known limitation, deliberately not worked around: that table is GLOBAL, not
 * per-netif (CONFIG_ESP_NETIF_SET_DNS_PER_DEFAULT_NETIF is off), and
 * dhcp_bind() writes slot n only for servers the lease actually provided —
 * it never clears the rest. So slot 1 can outlive the lease that wrote it. A
 * dual-WAN board whose eth lease carries two resolvers and whose wifi lease
 * carries one ends up reporting MAIN=wifi's, BACKUP=eth's; likewise a re-lease
 * that shrinks from two servers to one keeps the old secondary until reboot.
 * The blast radius is bounded to one hedged retransmit: a hedge to an
 * unreachable secondary simply gets no answer and the flight keeps waiting on
 * the primary exactly as it did before #69. What it is NOT bounded against is
 * a secondary that answers *differently* — process_reply's H2 gate validates
 * the question, not the answer, so a resolver with a different view can win
 * the race with a wrong answer. Split-horizon names are the case where that is
 * guaranteed rather than hypothetical, and they are pinned to the primary at
 * the hedge sweep (see UpstreamEntry::hedge_local). The real fix for the stale
 * slot itself is per-netif DNS, a build-config change and out of scope here.
 *
 * A lease with only one server leaves *out2 empty; so does a static-IP netif. */
static void fetch_dhcp_dns(esp_netif_t *netif, char *out, size_t cap,
                           char *out2, size_t cap2)
{
    fetch_dhcp_dns_one(netif, ESP_NETIF_DNS_MAIN,   out,  cap);
    fetch_dhcp_dns_one(netif, ESP_NETIF_DNS_BACKUP, out2, cap2);
}

static void ip_event_handler(void *, esp_event_base_t, int32_t event_id, void *event_data)
{
    if (event_id == IP_EVENT_ETH_GOT_IP) {
        auto *ev = static_cast<ip_event_got_ip_t *>(event_data);
        esp_ip4addr_ntoa(&ev->ip_info.ip, s_ip, sizeof(s_ip));
        net_eth_ip_nbo.store(ev->ip_info.ip.addr, std::memory_order_relaxed);   /* (#106) */
        esp_ip4addr_ntoa(&ev->ip_info.netmask, s_nm, sizeof(s_nm));
        esp_ip4addr_ntoa(&ev->ip_info.gw, s_gw, sizeof(s_gw));
        fetch_dhcp_dns(ev->esp_netif, s_eth_dns, sizeof(s_eth_dns),
                       s_eth_dns2, sizeof(s_eth_dns2));
        ESP_LOGI(TAG, "Ethernet IP: %s  GW: %s  DNS: %s  DNS2: %s", s_ip, s_gw,
                 s_eth_dns[0] ? s_eth_dns : "(none)",
                 s_eth_dns2[0] ? s_eth_dns2 : "(none)");
        xEventGroupSetBits(s_eth_eg, ETH_GOT_IP_BIT);
        apply_upstream_iface();
#if CONFIG_ADBLOCK_NET_WIFI
        stop_setup_ap_if_active();
#endif
    }
#if CONFIG_ADBLOCK_NET_WIFI
    else if (event_id == IP_EVENT_STA_GOT_IP) {
        auto *ev = static_cast<ip_event_got_ip_t *>(event_data);
        esp_ip4addr_ntoa(&ev->ip_info.ip, s_wifi_ip, sizeof(s_wifi_ip));
        esp_ip4addr_ntoa(&ev->ip_info.netmask, s_wifi_nm, sizeof(s_wifi_nm));
        esp_ip4addr_ntoa(&ev->ip_info.gw, s_wifi_gw, sizeof(s_wifi_gw));
        fetch_dhcp_dns(ev->esp_netif, s_wifi_dns, sizeof(s_wifi_dns),
                       s_wifi_dns2, sizeof(s_wifi_dns2));
        ESP_LOGI(TAG, "Wi-Fi IP: %s  GW: %s  DNS: %s  DNS2: %s", s_wifi_ip, s_wifi_gw,
                 s_wifi_dns[0] ? s_wifi_dns : "(none)",
                 s_wifi_dns2[0] ? s_wifi_dns2 : "(none)");
        xEventGroupSetBits(s_eth_eg, WIFI_GOT_IP_BIT);
        apply_upstream_iface();
        stop_setup_ap_if_active();
    }
#endif
}

#if CONFIG_ADBLOCK_NET_WIFI
/* ── Wi-Fi credentials: NVS-backed, Kconfig only as first-boot seed ──────
 * CONFIG_ADBLOCK_WIFI_SSID/PASSWORD used to be read directly at connect
 * time, which made the credentials permanently build-time-fixed. Runtime
 * reconfiguration (GUI network picker, #54) needs them in NVS instead; on
 * first boot (NVS empty) we seed from Kconfig once and persist that, so an
 * existing build's behavior is unchanged until someone actually reconfigures. */
static char s_wifi_ssid[33] = {};   /* 32 + NUL, per 802.11 max SSID length */
static char s_wifi_pass[65] = {};   /* 64 + NUL, per WPA2-PSK max */

static void wifi_creds_init_nvs(void)
{
    nvs_handle_t h;
    bool have_ssid = false;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) == ESP_OK) {
        size_t len = sizeof(s_wifi_ssid);
        if (nvs_get_str(h, NVSK_WIFI_SSID, s_wifi_ssid, &len) == ESP_OK && s_wifi_ssid[0] != '\0')
            have_ssid = true;
        len = sizeof(s_wifi_pass);
        nvs_get_str(h, NVSK_WIFI_PASS, s_wifi_pass, &len);
        nvs_close(h);
    }
    if (!have_ssid) {
        ESP_LOGI(TAG, "No Wi-Fi creds in NVS — seeding from Kconfig default");
        snprintf(s_wifi_ssid, sizeof(s_wifi_ssid), "%s", CONFIG_ADBLOCK_WIFI_SSID);
        snprintf(s_wifi_pass, sizeof(s_wifi_pass), "%s", CONFIG_ADBLOCK_WIFI_PASSWORD);
        if (nvs_open(NVS_NS, NVS_READWRITE, &h) == ESP_OK) {
            nvs_set_str(h, NVSK_WIFI_SSID, s_wifi_ssid);
            nvs_set_str(h, NVSK_WIFI_PASS, s_wifi_pass);
            nvs_commit(h);
            nvs_close(h);
        }
    }
}

/* ── Wi-Fi enable: NVS-backed, Kconfig only as first-boot seed ───────────
 * Mirrors wifi_creds_init_nvs above: CONFIG_ADBLOCK_NET_WIFI used to mean
 * both "compiled in" and "bring it up," so disabling dual-WAN needed a
 * reflash. Every deployed sdkconfig already sets it y, so seeding true on
 * first boot (NVS empty) preserves current behavior exactly; from then on
 * the web UI's Network tab flips this flag instead. Always reads the creds
 * too, regardless of enabled state, so the SSID field on the web UI still
 * shows what's configured even while Wi-Fi is off. The Wi-Fi-only board
 * (#49) has no Ethernet to fall back to, so it ignores NVS here entirely —
 * see dns_sink_wifi_set_enabled for the matching refusal to turn it off. */
static void wifi_enabled_init_nvs(void)
{
    wifi_creds_init_nvs();
#if !CONFIG_ADBLOCK_NET_ETH
    s_wifi_enabled = true;
    return;
#else
    nvs_handle_t h;
    uint8_t en;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) == ESP_OK) {
        if (nvs_get_u8(h, NVSK_WIFI_EN, &en) == ESP_OK) {
            nvs_close(h);
            s_wifi_enabled = (en != 0);
            return;
        }
        nvs_close(h);
    }
    ESP_LOGI(TAG, "No Wi-Fi enable flag in NVS — seeding enabled from Kconfig default");
    s_wifi_enabled = true;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_u8(h, NVSK_WIFI_EN, 1);
        nvs_commit(h);
        nvs_close(h);
    }
#endif
}

/* ── Setup AP — zero-touch first-boot Wi-Fi config (#1, mirrors upstream
 * ESP32_AdBlocker's own AP-mode bootstrap) ──────────────────────────────
 * Reborn is Ethernet-first, so most boots never need this: plug in a cable,
 * DHCP hands out an address, the web UI is reachable immediately. The gap is
 * a Wi-Fi-only board with no working credentials yet (blank first boot, or a
 * changed home network) and no Ethernet cable — before this, app_main's
 * xEventGroupWaitBits below used portMAX_DELAY, so that boot hung forever
 * before web_ui_start() ever ran. The only recovery was the USB serial
 * console's `wifi` command, which needs physical access. This starts an open
 * SoftAP (WIFI_MODE_APSTA, so STA keeps retrying and Ethernet is untouched)
 * at the esp-netif default 192.168.4.1 so a phone can join it and reach the
 * SAME httpd server (it listens on all interfaces already) to enter real
 * credentials via the existing Network tab (#54, dns_sink_wifi_set_creds).
 * Torn down automatically the moment ANY interface gets a real IP. */
static bool s_setup_ap_active = false;

/* WPA2 passphrase for the setup AP (#89). Random, minted once and kept in
 * NVS, printed on the USB console whenever the AP comes up. An OPEN setup AP
 * would let whoever is nearest race the owner to the first-boot wizard and
 * become the admin; with this, reaching the wizard over Wi-Fi needs the
 * console (i.e. the cable) — the same physical-access bar as `admin-reset`. */
static void setup_ap_passphrase(char *out, size_t cap)
{
    nvs_handle_t h;
    size_t len = cap;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) { snprintf(out, cap, "%s", "setup-nvs-fail"); return; }
    if (nvs_get_str(h, NVSK_SETUP_PSK, out, &len) != ESP_OK || strlen(out) < 8) {
        static const char alpha[] = "abcdefghjkmnpqrstuvwxyz23456789";   /* no 0/O/1/l/i */
        uint8_t rnd[16]; esp_fill_random(rnd, sizeof(rnd));
        for (int i = 0; i < 16 && i < (int)cap - 1; i++) out[i] = alpha[rnd[i] % (sizeof(alpha) - 1)];
        out[16 < (int)cap - 1 ? 16 : (int)cap - 1] = '\0';
        nvs_set_str(h, NVSK_SETUP_PSK, out);
        nvs_commit(h);
    }
    nvs_close(h);
}

static void start_setup_ap(void)
{
    if (s_setup_ap_active) return;
    esp_netif_create_default_wifi_ap();
    wifi_config_t ap_cfg = {};
    static const char *AP_SSID = "ESP32AdBlock-Setup";
    char psk[24]; setup_ap_passphrase(psk, sizeof(psk));
    snprintf(reinterpret_cast<char *>(ap_cfg.ap.ssid), sizeof(ap_cfg.ap.ssid), "%s", AP_SSID);
    snprintf(reinterpret_cast<char *>(ap_cfg.ap.password), sizeof(ap_cfg.ap.password), "%s", psk);
    ap_cfg.ap.ssid_len = strlen(AP_SSID);
    ap_cfg.ap.channel = 1;
    ap_cfg.ap.max_connection = 4;
    ap_cfg.ap.authmode = WIFI_AUTH_WPA2_PSK;
    if (esp_wifi_set_mode(WIFI_MODE_APSTA) != ESP_OK ||
        esp_wifi_set_config(WIFI_IF_AP, &ap_cfg) != ESP_OK) {
        ESP_LOGE(TAG, "setup AP failed to start");
        return;
    }
    s_setup_ap_active = true;
    ESP_LOGW(TAG, "No network link — setup AP \"%s\" is up at 192.168.4.1, "
                  "WPA2 passphrase: %s  (join it and browse https://192.168.4.1 "
                  "to enter real Wi-Fi credentials; it shuts off automatically "
                  "once any interface gets a real IP)", AP_SSID, psk);
}

static void stop_setup_ap_if_active(void)
{
    if (!s_setup_ap_active) return;
    s_setup_ap_active = false;
    esp_wifi_set_mode(WIFI_MODE_STA);
    ESP_LOGI(TAG, "Network link established — setup AP shut off");
}

static NetStaticCfg s_wifi_static;

/* Wi-Fi counterpart of publish_static_eth — see that comment for why this is
 * deferred to association rather than done at config time (#56). */
static void publish_static_wifi(void)
{
    if (s_wifi_static.dhcp) return;
    snprintf(s_wifi_ip,  sizeof(s_wifi_ip),  "%s", s_wifi_static.ip);
    snprintf(s_wifi_nm,  sizeof(s_wifi_nm),  "%s", s_wifi_static.nm);
    snprintf(s_wifi_gw,  sizeof(s_wifi_gw),  "%s", s_wifi_static.gw);
    snprintf(s_wifi_dns, sizeof(s_wifi_dns), "%s", s_wifi_static.dns);
    ESP_LOGI(TAG, "Wi-Fi associated — static IP: %s  GW: %s  DNS: %s",
             s_wifi_ip, s_wifi_gw[0] ? s_wifi_gw : "(none)",
             s_wifi_dns[0] ? s_wifi_dns : "(none)");
    xEventGroupSetBits(s_eth_eg, WIFI_GOT_IP_BIT);
    apply_upstream_iface();
    stop_setup_ap_if_active();
}

/* Suppresses the STA_DISCONNECTED auto-retry across a deliberate reconfigure
 * (set_creds below), so it can't race the new credentials in with the old.
 * Cleared on association rather than synchronously after set_config: the
 * disconnect is asynchronous, so clearing it inline left the handler free to
 * fire its own connect alongside ours (#58). The deadline is a safety net —
 * if the new network never associates, normal auto-retry must resume rather
 * than stay suppressed forever. */
static volatile bool    s_wifi_reconfiguring   = false;
static volatile int64_t s_wifi_recfg_until_us  = 0;

static bool wifi_reconfig_active(void)
{
    if (!s_wifi_reconfiguring) return false;
    if (esp_timer_get_time() > s_wifi_recfg_until_us) {
        s_wifi_reconfiguring = false;      /* expired — resume normal retries */
        return false;
    }
    return true;
}

/* ── Wi-Fi STA bring-up (roadmap #49 slice, extended for concurrent dual-WAN
 * with Ethernet under #53 — both interfaces stay up together rather than
 * one replacing the other). */
static void wifi_event_handler(void *, esp_event_base_t, int32_t event_id, void *)
{
    if (event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_id == WIFI_EVENT_STA_DISCONNECTED) {
        xEventGroupClearBits(s_eth_eg, WIFI_CONNECTED_BIT | WIFI_GOT_IP_BIT);
        if (!s_wifi_static.dhcp) { s_wifi_ip[0] = '\0'; s_wifi_nm[0] = '\0'; s_wifi_gw[0] = '\0'; s_wifi_dns[0] = '\0'; }
        if (wifi_reconfig_active()) {
            ESP_LOGI(TAG, "Wi-Fi disconnected (reconfiguring — not auto-retrying)");
        } else {
            ESP_LOGW(TAG, "Wi-Fi disconnected — retrying");
            esp_wifi_connect();
        }
    } else if (event_id == WIFI_EVENT_STA_CONNECTED) {
        s_wifi_reconfiguring = false;      /* reconfigure landed */
        xEventGroupSetBits(s_eth_eg, WIFI_CONNECTED_BIT);
        publish_static_wifi();             /* no-op under DHCP — the lease drives it */
    }
}

/* Scan result cache state — declared here because wifi_init_sta() creates the
 * mutex; the worker and the accessors live further down (#62). */
enum ScanState { SCAN_IDLE = 0, SCAN_RUNNING, SCAN_DONE, SCAN_ERROR };
static volatile ScanState  s_scan_state      = SCAN_IDLE;
static SemaphoreHandle_t   s_scan_mutex      = nullptr;
static char                s_scan_json[2560] = "[]";
static int64_t             s_scan_done_us    = 0;
static esp_err_t           s_scan_err        = ESP_OK;

static const char *scan_state_name(ScanState s)
{
    switch (s) {
        case SCAN_RUNNING: return "scanning";
        case SCAN_DONE:    return "done";
        case SCAN_ERROR:   return "error";
        default:           return "idle";
    }
}

static void wifi_init_sta(void)
{
    /* Creds already loaded by wifi_enabled_init_nvs(), called before this
     * from app_main regardless of whether Wi-Fi ends up enabled. */
    s_scan_mutex = xSemaphoreCreateMutex();   /* guards the scan result cache (#62) */
    if (!s_scan_mutex) ESP_LOGE(TAG, "scan mutex alloc failed — scanning disabled");
    ESP_LOGI(TAG, "Wi-Fi STA: connecting to SSID \"%s\"", s_wifi_ssid);

    esp_netif_t *wifi_netif = esp_netif_create_default_wifi_sta();
    /* DHCP option 12 (hostname) — otherwise this reports as the IDF-wide
     * "espressif" default in the router's client list, same name for every
     * ESP32 on the LAN. Matches the mDNS hostname (dns_sink_hostname()) so
     * there's one name to look for either way. */
    esp_netif_set_hostname(wifi_netif, MDNS_HOSTNAME);

    /* Hand entropy over to RF (see app_main in dns_sink.cpp): random.rst requires the SAR ADC
     * source off before the RF subsystem is used. Nothing draws between here
     * and esp_wifi_start() below, after which RF is the entropy source. */
    bootloader_random_disable();
    ESP_LOGI(TAG, "[boot] entropy: SAR ADC source off — RF takes over at esp_wifi_start()");

    wifi_init_config_t init_cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&init_cfg));

    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                               wifi_event_handler, nullptr));

    /* Static IP (#55): the netif has to be configured before the driver starts
     * (see apply_static_ip), but the address is only *published* once the STA
     * actually associates — publish_static_wifi, from the event handler (#56). */
    netcfg_load("wifi", &s_wifi_static);
    if (!s_wifi_static.dhcp)
        apply_static_ip(wifi_netif, s_wifi_static);

    wifi_config_t wifi_cfg = {};
    strlcpy(reinterpret_cast<char *>(wifi_cfg.sta.ssid),
            s_wifi_ssid, sizeof(wifi_cfg.sta.ssid));
    strlcpy(reinterpret_cast<char *>(wifi_cfg.sta.password),
            s_wifi_pass, sizeof(wifi_cfg.sta.password));
    wifi_cfg.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());
}

/* ── Wi-Fi scan + reconfigure from the web UI (#54) ──────────────────── */

extern "C" void dns_sink_wifi_get_ssid(char *out, size_t cap)
{
    snprintf(out, cap, "%s", s_wifi_ssid);
}

/* ── Wi-Fi scan: worker task + cached result (#62) ────────────────────────
 * The scan used to run blocking inside the httpd task, which stalls *every*
 * viewer for its duration — measured at 3.16s, during which an unrelated page
 * load took 2.63s instead of 0.50s. esp_http_server is single-tasked, so one
 * slow handler is head-of-line blocking for the whole UI.
 *
 * Now a one-shot worker does the scan and publishes the rendered JSON; the
 * httpd handlers only ever touch the cached copy, so they never block. That
 * makes the buffer genuinely shared across tasks (worker writes, httpd reads),
 * hence the mutex — the single-task safety that the other static render
 * buffers rely on does NOT apply here. The lock is held only for the render
 * and the read, never across the scan itself. */
#define WIFI_SCAN_MAX 20

static void wifi_scan_task(void *)
{
    static EXT_RAM_BSS_ATTR wifi_ap_record_t recs[WIFI_SCAN_MAX];   /* only this task touches it */
    wifi_scan_config_t scan_cfg = {};
    esp_err_t rc = esp_wifi_scan_start(&scan_cfg, true /* block — we're off the httpd task */);

    uint16_t got = 0;
    if (rc == ESP_OK) {
        uint16_t ap_num = 0;
        esp_wifi_scan_get_ap_num(&ap_num);
        got = (ap_num > WIFI_SCAN_MAX) ? WIFI_SCAN_MAX : ap_num;
        /* Frees the whole internal AP list even when we ask for fewer. */
        esp_wifi_scan_get_ap_records(&got, recs);
    }

    xSemaphoreTake(s_scan_mutex, portMAX_DELAY);
    if (rc != ESP_OK) {
        s_scan_err   = rc;
        s_scan_state = SCAN_ERROR;
        ESP_LOGW(TAG, "Wi-Fi scan failed: %s", esp_err_to_name(rc));
    } else {
        const size_t cap = sizeof(s_scan_json);
        int n = snprintf(s_scan_json, cap, "[");
        for (uint16_t i = 0; i < got && n < (int)cap - 128; i++) {
            /* #104: an SSID is an opaque octet string (802.11), not text — it
             * may legitimately contain bytes < 0x20. RFC 8259 forbids those
             * unescaped in a JSON string; the old loop copied them raw, which
             * broke r.json() client-side and reported as a generic "scan
             * failed" for every viewer for as long as that AP stayed in
             * range. \u00XX is 6 bytes, so the per-iteration bound has to
             * cover the widest escape this loop can emit, not just \" / \\'s
             * 2 bytes — an exotic SSID now truncates instead of overflowing,
             * same truncate-on-overflow policy as before. */
            char ssid[64]; size_t sl = 0;
            for (size_t j = 0; recs[i].ssid[j] != 0 && j < sizeof(recs[i].ssid)
                               && sl < sizeof(ssid) - 6; j++) {
                unsigned char c = (unsigned char)recs[i].ssid[j];
                if (c == '"' || c == '\\') {
                    ssid[sl++] = '\\'; ssid[sl++] = (char)c;
                } else if (c < 0x20 || c == 0x7F) {
                    sl += snprintf(&ssid[sl], 7, "\\u%04x", (unsigned)c);
                } else {
                    ssid[sl++] = (char)c;
                }
            }
            ssid[sl] = '\0';
            n += snprintf(s_scan_json + n, cap - n,
                          "%s{\"ssid\":\"%s\",\"rssi\":%d,\"auth\":%d}",
                          i ? "," : "", ssid, (int)recs[i].rssi, (int)recs[i].authmode);
        }
        snprintf(s_scan_json + n, cap - n, "]");
        s_scan_done_us = esp_timer_get_time();
        s_scan_err     = ESP_OK;
        s_scan_state   = SCAN_DONE;
        ESP_LOGI(TAG, "Wi-Fi scan complete: %u AP(s)", (unsigned)got);
    }
    xSemaphoreGive(s_scan_mutex);
    vTaskDelete(nullptr);
}

/* Kick off a scan. Returns false only if one can't be started right now;
 * an already-running scan is reported as success so a second viewer clicking
 * Scan simply joins the one in flight rather than stacking radio work. */
extern "C" bool dns_sink_wifi_scan_start(void)
{
    if (!s_scan_mutex) return false;
    if (wifi_reconfig_active()) return false;   /* don't scan mid-reassociation */

    xSemaphoreTake(s_scan_mutex, portMAX_DELAY);
    if (s_scan_state == SCAN_RUNNING) { xSemaphoreGive(s_scan_mutex); return true; }
    s_scan_state = SCAN_RUNNING;
    xSemaphoreGive(s_scan_mutex);

    if (xTaskCreate(wifi_scan_task, "wifi_scan", 4096, nullptr, 3, nullptr) != pdPASS) {
        xSemaphoreTake(s_scan_mutex, portMAX_DELAY);
        s_scan_state = SCAN_ERROR;
        s_scan_err   = ESP_ERR_NO_MEM;
        xSemaphoreGive(s_scan_mutex);
        ESP_LOGE(TAG, "Wi-Fi scan task create failed");
        return false;
    }
    return true;
}

/* Read the cached result. Never blocks on the radio; bounded 200ms wait for
 * the (briefly-held) publish lock, reporting "busy" rather than stalling the
 * httpd task if it somehow can't be taken. */
extern "C" int dns_sink_wifi_scan_get(char *out, size_t cap)
{
    if (!s_scan_mutex)
        return snprintf(out, cap, "{\"state\":\"idle\",\"age_s\":-1,\"aps\":[]}");

    if (xSemaphoreTake(s_scan_mutex, pdMS_TO_TICKS(200)) != pdTRUE)
        return snprintf(out, cap, "{\"state\":\"scanning\",\"age_s\":-1,\"aps\":[]}");

    ScanState st = s_scan_state;
    int age = (st == SCAN_DONE && s_scan_done_us)
                ? (int)((esp_timer_get_time() - s_scan_done_us) / 1000000) : -1;
    int n;
    if (st == SCAN_DONE) {
        n = snprintf(out, cap, "{\"state\":\"done\",\"age_s\":%d,\"aps\":%s}", age, s_scan_json);
    } else if (st == SCAN_ERROR) {
        n = snprintf(out, cap, "{\"state\":\"error\",\"age_s\":-1,\"err\":\"%s\",\"aps\":[]}",
                     esp_err_to_name(s_scan_err));
    } else {
        n = snprintf(out, cap, "{\"state\":\"%s\",\"age_s\":-1,\"aps\":[]}", scan_state_name(st));
    }
    xSemaphoreGive(s_scan_mutex);
    return n;
}

/* The actual Wi-Fi teardown/reconnect, deferred a beat (see set_creds below)
 * so the httpd response for the /wifi/connect request that triggered this
 * can flush over the very link we're about to drop — otherwise the client
 * gets a connection reset instead of the redirect (observed on hardware:
 * esp_wifi_disconnect() tears down the TCP session serving that request). */
static void wifi_apply_reconfigure_task(void *)
{
    vTaskDelay(pdMS_TO_TICKS(300));

    ESP_LOGI(TAG, "Wi-Fi reconfigure: SSID -> \"%s\"", s_wifi_ssid);
    s_wifi_recfg_until_us = esp_timer_get_time() + 15LL * 1000000;   /* safety net */
    s_wifi_reconfiguring  = true;
    esp_wifi_disconnect();

    wifi_config_t wifi_cfg = {};
    strlcpy(reinterpret_cast<char *>(wifi_cfg.sta.ssid),
            s_wifi_ssid, sizeof(wifi_cfg.sta.ssid));
    strlcpy(reinterpret_cast<char *>(wifi_cfg.sta.password),
            s_wifi_pass, sizeof(wifi_cfg.sta.password));
    wifi_cfg.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg);

    /* Flag stays set until WIFI_EVENT_STA_CONNECTED clears it (or the deadline
     * expires), so the async disconnect event can't slip past it — see
     * wifi_reconfig_active. */
    esp_wifi_connect();
    vTaskDelete(nullptr);
}

/* Reconfigure to a new SSID/password: persist to NVS and update the in-memory
 * copy synchronously (so it and the web UI agree immediately), then hand the
 * disruptive part (disconnect/reconnect) to a deferred one-shot task. */
extern "C" bool dns_sink_wifi_set_creds(const char *ssid, const char *pass)
{
    if (!ssid || ssid[0] == '\0' || strlen(ssid) >= sizeof(s_wifi_ssid)) return false;
    if (pass && strlen(pass) >= sizeof(s_wifi_pass)) return false;

    snprintf(s_wifi_ssid, sizeof(s_wifi_ssid), "%s", ssid);
    snprintf(s_wifi_pass, sizeof(s_wifi_pass), "%s", pass ? pass : "");

    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_str(h, NVSK_WIFI_SSID, s_wifi_ssid);
        nvs_set_str(h, NVSK_WIFI_PASS, s_wifi_pass);
        nvs_commit(h);
        nvs_close(h);
    }

    if (s_wifi_enabled) {
        xTaskCreate(wifi_apply_reconfigure_task, "wifi_recfg", 3072, nullptr, 3, nullptr);
    } else {
        /* Radio was never started this boot (dns_sink_wifi_set_enabled is
         * off) — nothing to disconnect/reconnect. Creds are saved; they take
         * effect once Wi-Fi is enabled and the board reboots. */
        ESP_LOGI(TAG, "Wi-Fi creds saved — enable Wi-Fi and reboot to connect");
    }
    return true;
}

extern "C" bool dns_sink_setup_ap_active(void) { return s_setup_ap_active; }
extern "C" void dns_sink_setup_ap_passphrase(char *out, size_t cap) { setup_ap_passphrase(out, cap); }
#else
extern "C" void dns_sink_wifi_get_ssid(char *out, size_t cap) { if (cap) out[0] = '\0'; }
extern "C" bool dns_sink_wifi_scan_start(void) { return false; }
extern "C" int  dns_sink_wifi_scan_get(char *out, size_t cap)
{
    return snprintf(out, cap, "{\"state\":\"idle\",\"age_s\":-1,\"aps\":[]}");
}
extern "C" bool dns_sink_wifi_set_creds(const char *, const char *) { return false; }
extern "C" bool dns_sink_setup_ap_active(void) { return false; }
extern "C" void dns_sink_setup_ap_passphrase(char *out, size_t cap) { if (cap) out[0] = '\0'; }
#endif

/* This device's current LAN-facing address, Ethernet preferred (matches the
 * dashboard's own precedence at line ~1407) — used by the :80 redirect
 * handler (#112) to validate the Host header before echoing it back. */
extern "C" const char *dns_sink_lan_ip(void) { return s_ip[0] ? s_ip : s_wifi_ip; }

/* ── W5500 init (board pin map selected above) ───────────────────── */
#if CONFIG_ADBLOCK_NET_ETH
static esp_eth_handle_t eth_init_w5500(void)
{
    ESP_LOGI(TAG, "W5500 %s: SCLK=%d MISO=%d MOSI=%d CS=%d INT=%d RST=%d @ %d MHz",
             BOARD_NAME, W5500_SCLK_GPIO, W5500_MISO_GPIO, W5500_MOSI_GPIO,
             W5500_CS_GPIO, W5500_INT_GPIO, W5500_RST_GPIO, W5500_SPI_CLOCK);

    spi_bus_config_t buscfg = {};
    buscfg.miso_io_num   = W5500_MISO_GPIO;
    buscfg.mosi_io_num   = W5500_MOSI_GPIO;
    buscfg.sclk_io_num   = W5500_SCLK_GPIO;
    buscfg.quadwp_io_num = -1;
    buscfg.quadhd_io_num = -1;
    ESP_ERROR_CHECK(spi_bus_initialize(W5500_SPI_HOST, &buscfg, SPI_DMA_CH_AUTO));

    spi_device_interface_config_t devcfg = {};
    devcfg.command_bits   = 16;  /* W5500: 16-bit address phase */
    devcfg.address_bits   = 8;   /* 8-bit control phase */
    devcfg.mode           = 0;
    devcfg.clock_speed_hz = W5500_SPI_CLOCK * 1000 * 1000;
    devcfg.spics_io_num   = W5500_CS_GPIO;
    devcfg.queue_size     = 20;

#if W5500_INT_GPIO >= 0
    /* GPIO ISR service needed for W5500 interrupt pin (not auto-installed in IDF v6) */
    esp_err_t rc = gpio_install_isr_service(0);
    if (rc != ESP_OK && rc != ESP_ERR_INVALID_STATE) ESP_ERROR_CHECK(rc);
#endif

    eth_w5500_config_t w5500_cfg = ETH_W5500_DEFAULT_CONFIG(W5500_SPI_HOST, &devcfg);
    w5500_cfg.int_gpio_num = static_cast<gpio_num_t>(W5500_INT_GPIO);

    eth_mac_config_t mac_cfg = ETH_MAC_DEFAULT_CONFIG();
    esp_eth_mac_t *mac = esp_eth_mac_new_w5500(&w5500_cfg, &mac_cfg);

    eth_phy_config_t phy_cfg = ETH_PHY_DEFAULT_CONFIG();
    phy_cfg.autonego_timeout_ms = 0;
    phy_cfg.reset_gpio_num      = static_cast<gpio_num_t>(W5500_RST_GPIO);
    esp_eth_phy_t *phy = esp_eth_phy_new_w5500(&phy_cfg);

    esp_eth_config_t eth_cfg = ETH_DEFAULT_CONFIG(mac, phy);
    esp_eth_handle_t handle  = nullptr;
    ESP_ERROR_CHECK(esp_eth_driver_install(&eth_cfg, &handle));

    uint8_t mac_addr[6];
    esp_read_mac(mac_addr, ESP_MAC_ETH);
    ESP_ERROR_CHECK(esp_eth_ioctl(handle, ETH_CMD_S_MAC_ADDR, mac_addr));

    return handle;
}
#endif /* CONFIG_ADBLOCK_NET_ETH — W5500 bring-up */

/* The address DNS clients reach us on: Ethernet if it has one, else Wi-Fi.
 * Network byte order; 0 = none yet. */
uint32_t net_own_ip_nbo(void)
{
    uint32_t ip = net_eth_ip_nbo.load(std::memory_order_relaxed);
#if CONFIG_ADBLOCK_NET_WIFI
    if (ip == 0) {
        char buf[16];
        memcpy(buf, s_wifi_ip, sizeof(buf));
        buf[sizeof(buf) - 1] = '\0';
        if (buf[0] != '\0') {
            struct in_addr a;
            if (inet_aton(buf, &a)) ip = a.s_addr;
        }
    }
#endif
    return ip;
}

/* ── app_main's network bring-up sequence, moved verbatim ───────────────── */
void net_bringup_init(DnsSinkServer *dns, net_l2_input_cb_t l2_cb)
{
    s_dns_target = dns;   /* set before any handler is registered below */
#if !CONFIG_ADBLOCK_NET_ETH
    (void)l2_cb;
#endif

    s_eth_eg = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, ESP_EVENT_ANY_ID,
                                               ip_event_handler, nullptr));

#if CONFIG_ADBLOCK_NET_ETH
    /* Register Ethernet event handler */
    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID,
                                               eth_event_handler, nullptr));

    /* Init W5500 + create default Ethernet netif (DHCP client). Always brought
     * up — the L2 fast-path and LAN-facing IP (mDNS, router DNS target, web UI)
     * live here regardless of whether Wi-Fi is also enabled. */
    esp_eth_handle_t eth_handle = eth_init_w5500();
    esp_netif_config_t netif_cfg = ESP_NETIF_DEFAULT_ETH();
    esp_netif_t *eth_netif = esp_netif_new(&netif_cfg);
    /* DHCP option 12 — see wifi_init_sta()'s matching call for why. */
    esp_netif_set_hostname(eth_netif, MDNS_HOSTNAME);
    esp_netif_attach(eth_netif, esp_eth_new_netif_glue(eth_handle));
    /* Override the glue's input with our L2 fast-path hook (passthrough for now) */
    ESP_ERROR_CHECK(esp_eth_update_input_path_info(eth_handle, l2_cb, eth_netif));

    /* Static IP (#55): the netif has to be configured before the driver starts
     * (see apply_static_ip), but the address is only *published* once the link
     * actually comes up — publish_static_eth, from the event handler (#56). */
    netcfg_load("eth", &s_eth_static);
    if (!s_eth_static.dhcp)
        apply_static_ip(eth_netif, s_eth_static);
    ESP_ERROR_CHECK(esp_eth_start(eth_handle));
#else
    /* (#49) Wi-Fi-only board: no W5500, no L2 hook, no SD. The Wi-Fi STA below
     * is the LAN-facing interface; every query takes the lwIP socket path. */
    ESP_LOGI(TAG, "%s: Wi-Fi is the only link (no Ethernet, no SD card)", BOARD_NAME);
#endif

#if CONFIG_ADBLOCK_NET_WIFI
    /* Load the runtime enable flag (NVS-seeded from Kconfig on first boot —
     * see wifi_enabled_init_nvs) before deciding whether to touch the radio
     * at all. Also loads creds, so the web UI's SSID field is accurate even
     * when Wi-Fi ends up disabled below. */
    wifi_enabled_init_nvs();
    if (s_wifi_enabled) {
        /* Wi-Fi STA bring-up alongside Ethernet (#53: dual-WAN). No L2
         * fast-path here — Wi-Fi queries take the normal lwIP socket path. */
        wifi_init_sta();

        /* Wait for EITHER interface, not both — the Ethernet cable may not be
         * plugged in at all (Wi-Fi-only operation is a supported mode, not just
         * a transient boot state), so blocking on both would hang forever with
         * no cable connected. Whichever interface comes up later still fires its
         * own IP_EVENT and joins in (apply_upstream_iface() re-runs each time).
         *
         * Bounded, not portMAX_DELAY (#1): a board with no Ethernet cable AND no
         * working Wi-Fi credentials (blank first boot, or a changed home network)
         * would otherwise hang HERE forever — nothing past this line ever runs,
         * including web_ui_start(), so the only recovery was the USB serial
         * console. On timeout, bring up the setup AP (start_setup_ap) so the
         * device is reachable over Wi-Fi with zero prior config — mirrors
         * upstream ESP32_AdBlocker's own AP-mode bootstrap — then continue
         * straight on to web_ui_start() etc. below: booting with no upstream
         * reachable yet is already a supported state (see Wi-Fi-only, no-cable
         * above), just newly reachable via the AP instead of USB. There used
         * to be a second bounded wait here "for credentials to arrive," but
         * none can — the httpd that would receive them doesn't exist until
         * web_ui_start() runs, further down past this whole block. That wait
         * was pure dead time: the AP came up, then sat unreachable for up to
         * another WIFI_SETUP_AP_TIMEOUT_MS before the web UI it exists to
         * serve ever started. A cable plugged in during that window doesn't
         * need app_main blocked to notice it either — eth_event_handler runs
         * from the system event task regardless. */
        ESP_LOGI(TAG, "Waiting for Ethernet or Wi-Fi link and DHCP...");
        EventBits_t link_bits = xEventGroupWaitBits(s_eth_eg, ETH_GOT_IP_BIT | WIFI_GOT_IP_BIT,
                            pdFALSE, pdFALSE, pdMS_TO_TICKS(WIFI_SETUP_AP_TIMEOUT_MS));
        if (!(link_bits & (ETH_GOT_IP_BIT | WIFI_GOT_IP_BIT)))
            start_setup_ap();
        ESP_LOGI(TAG, "Network ready — Ethernet: %s  Wi-Fi: %s",
                 s_ip[0] ? s_ip : "(down)", s_wifi_ip[0] ? s_wifi_ip : "(down)");
    } else {
        /* Wi-Fi compiled in but disabled at runtime — no radio brought up at
         * all (esp_wifi_init/start never called), so no setup AP is possible
         * either. Bounded, not portMAX_DELAY (#1 again, one level up): before
         * this was runtime-toggleable, every image with Wi-Fi compiled out
         * was also one nobody actually deployed with Ethernet unplugged, so
         * an infinite wait here never bit anyone. A web UI checkbox makes
         * "Ethernet-only, cable out" reachable for the first time — and
         * console_start() below is the ONLY recovery a Wi-Fi-disabled board
         * has, so it must be reached even with no link. A cable plugged in
         * later still completes the normal way via eth_event_handler. */
        /* Bounded, not portMAX_DELAY — see the branch comment above. */
        ESP_LOGI(TAG, "Wi-Fi disabled (Network tab) — waiting for Ethernet link and DHCP...");
        EventBits_t got = xEventGroupWaitBits(s_eth_eg, ETH_CONNECTED_BIT | ETH_GOT_IP_BIT,
                            pdFALSE, pdTRUE, pdMS_TO_TICKS(WIFI_SETUP_AP_TIMEOUT_MS));
        if ((got & (ETH_CONNECTED_BIT | ETH_GOT_IP_BIT)) != (ETH_CONNECTED_BIT | ETH_GOT_IP_BIT))
            ESP_LOGW(TAG, "No Ethernet link yet — continuing anyway so the USB console "
                          "(wifi-on) stays reachable; a cable plugged in later still comes up");
        ESP_LOGI(TAG, "Network ready — IP: %s", s_ip[0] ? s_ip : "(down)");
    }
#else
    /* Wait for link + DHCP lease. Bounded — see the runtime-disabled branch's
     * comment above; this build has no Wi-Fi at all, so the USB console is
     * the ONLY recovery when no cable is plugged in, and it must be reached. */
    /* Bounded, not portMAX_DELAY — see the runtime-disabled branch's comment
     * above for why. */
    ESP_LOGI(TAG, "Waiting for Ethernet link and DHCP...");
    EventBits_t got = xEventGroupWaitBits(s_eth_eg, ETH_CONNECTED_BIT | ETH_GOT_IP_BIT,
                        pdFALSE, pdTRUE, pdMS_TO_TICKS(WIFI_SETUP_AP_TIMEOUT_MS));
    if ((got & (ETH_CONNECTED_BIT | ETH_GOT_IP_BIT)) != (ETH_CONNECTED_BIT | ETH_GOT_IP_BIT))
        ESP_LOGW(TAG, "No Ethernet link yet — continuing anyway so the USB console "
                      "stays reachable; a cable plugged in later still comes up");
    ESP_LOGI(TAG, "Network ready — IP: %s", s_ip[0] ? s_ip : "(down)");
#endif
    upstream_iface_init_nvs();

#if CONFIG_ADBLOCK_NET_WIFI
    /* #80: the wait above returns as soon as EITHER interface has an IP - that
     * is deliberate, since a cable-out Wi-Fi-only boot is a supported mode, not
     * just a transient. But it means a fast Wi-Fi lease can let us proceed
     * while the interface we actually egress through is still waiting on DHCP,
     * which made the banner below report a fallback resolver and advertise the
     * wrong LAN IP. Give the SELECTED interface a bounded second chance; a
     * genuinely absent link still boots, it just says so out loud. */
    {
        const EventBits_t want = (strcmp(s_upstream_iface, "wifi") == 0)
                               ? WIFI_GOT_IP_BIT : ETH_GOT_IP_BIT;
        if (!(xEventGroupGetBits(s_eth_eg) & want)) {
            ESP_LOGI(TAG, "Upstream interface (%s) has no lease yet - waiting up to %d s",
                     s_upstream_iface, UPSTREAM_IFACE_WAIT_MS / 1000);
            EventBits_t got = xEventGroupWaitBits(s_eth_eg, want, pdFALSE, pdFALSE,
                                                  pdMS_TO_TICKS(UPSTREAM_IFACE_WAIT_MS));
            if (!(got & want))
                ESP_LOGW(TAG, "Upstream interface (%s) still has no lease after %d s - "
                              "starting on the fallback resolver; it re-points "
                              "automatically when DHCP lands",
                         s_upstream_iface, UPSTREAM_IFACE_WAIT_MS / 1000);
        }
    }
#endif
}

/* Initial upstream for DnsSinkServer::start(): the selected interface's
 * resolver (see pick_upstream / apply_upstream_iface — #53). */
const char *net_initial_upstream(void)
{
    const char *upstream = pick_upstream(s_eth_dns, s_gw);
#if CONFIG_ADBLOCK_NET_WIFI
    if (strcmp(s_upstream_iface, "wifi") == 0)
        upstream = pick_upstream(s_wifi_dns, s_wifi_gw);
#endif
    return upstream;
}

const char *net_apply_upstream_iface(void)
{
    return apply_upstream_iface();
}

void net_log_sinkhole_active(const char *live)
{
    const char *lan_ip = "(no IP yet)";
    const char *lan_if = "";
    if (s_ip[0]) { lan_ip = s_ip; lan_if = " (Ethernet)"; }
#if CONFIG_ADBLOCK_NET_WIFI
    else if (s_wifi_ip[0]) { lan_ip = s_wifi_ip; lan_if = " (Wi-Fi)"; }
#endif
    ESP_LOGI(TAG, "DNS sinkhole active (upstream via %s: %s). Point your router's DNS at %s%s",
             s_upstream_iface, live, lan_ip, lan_if);
}

void net_log_startup_complete(void)
{
    ESP_LOGI(TAG, "Startup complete. Ethernet: %s  Wi-Fi: %s — either can be set as your DNS server.",
#if CONFIG_ADBLOCK_NET_ETH
             s_ip[0] ? s_ip : "(down)",
#else
             "(not built)",
#endif
#if CONFIG_ADBLOCK_NET_WIFI
             !s_wifi_enabled ? "(disabled)" : (s_wifi_ip[0] ? s_wifi_ip : "(down)"));
#else
             "(not built)");
#endif
}
