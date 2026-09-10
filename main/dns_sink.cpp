/*
 * dns_sink.cpp — ESP-IDF entry point for the DNS sinkhole.
 *
 * W5500 Ethernet bringup (SPI2, event-group DHCP wait). The W5500 + SD pin
 * map is selected per board via the ADBLOCK_BOARD Kconfig choice: LilyGO
 * T-ETH-Elite (default) or Waveshare ESP32-S3-ETH.
 */

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
#include "esp_ota_ops.h"
#include "esp_mac.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_attr.h"
#include "lwip/inet.h"

#include "driver/gpio.h"
#include "driver/spi_master.h"

#include <atomic>

#include "esp_vfs_fat.h"
#include "sdmmc_cmd.h"
#include "driver/sdspi_host.h"
#include <inttypes.h>

#include "blocklist.h"
#include "domain.h"
#include "rewrite.h"
#include "acl.h"
#include "bypass.h"
#include "pause.h"
#include "dot.h"
#include "localzone.h"
#include "query_log.h"
#include "census.h"
#include "crashlog.h"
#include "timesync.h"
#include "dns_server.h"
#include "web_ui.h"
#include "console.h"
#include "mdns.h"
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <ctime>

static const char *TAG = "dns_sink";

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

/* ── Pin maps: Waveshare ESP32-S3-ETH (ESP32-S3R8 + W5500) ──────── */
#define BOARD_NAME    "Waveshare ESP32-S3-ETH"
/* Distinct mDNS hostname — a T-ETH-Elite unit on the same LAN already
 * claims esp32adblock.local. */
#define MDNS_HOSTNAME "esp32adblock2"

/* TF slot, SPI mode (CS=DAT3, MISO=DAT0, MOSI=CMD). Pins from the
 * CircuitPython board definition; a card has not yet been tested in this
 * slot — a wrong pin here just fails the mount and falls back to download. */
#define SD_MISO_GPIO  5
#define SD_MOSI_GPIO  6
#define SD_SCLK_GPIO  7
#define SD_CS_GPIO    4
#define SD_SPI_HOST   SPI3_HOST
#define SD_MOUNT      "/sdcard"

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

#define BOARD_NAME    "LilyGO T-ETH-Elite"
#define MDNS_HOSTNAME "esp32adblock"

/* ── SD card pin map: LilyGO T-ETH-ELITE S3 ─────────────────────── */
#define SD_MISO_GPIO  9
#define SD_MOSI_GPIO  11
#define SD_SCLK_GPIO  10
#define SD_CS_GPIO    12
#define SD_SPI_HOST   SPI3_HOST
#define SD_MOUNT      "/sdcard"

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
/* (#106) The same Ethernet address as s_ip, kept in binary (network byte
 * order) because the L2 RX hook has to compare it against every frame's
 * destination and must not parse a string there. 0 = no address yet, which
 * makes the hook defer everything to lwIP. */
static std::atomic<uint32_t> s_eth_ip_nbo{0};
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

/* ── Global singletons ───────────────────────────────────────────── */
static DnsSinkServer s_dns;
static volatile bool s_reload_requested = false;

/* Called from web_ui.cpp POST /reload */
extern "C" void dns_sink_trigger_reload(void)
{
    s_reload_requested = true;
}

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
    s_dns.set_upstream(upstream, upstream2);
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
    if (strcmp(iface, "wifi") == 0) known = true;
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
    snprintf(s_upstream_iface, sizeof(s_upstream_iface), "wifi");  /* default when built dual-stack */
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

extern "C" void dns_sink_reboot(void)
{
    esp_restart();
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
    s_eth_ip_nbo.store(inet_addr(s_eth_static.ip), std::memory_order_relaxed);
    xEventGroupSetBits(s_eth_eg, ETH_GOT_IP_BIT);
    apply_upstream_iface();
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
        s_eth_ip_nbo.store(0, std::memory_order_relaxed);   /* (#106) hook defers while down */
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

#if CONFIG_ADBLOCK_NET_WIFI
static void stop_setup_ap_if_active(void);   /* defined below wifi_creds_init_nvs (#1) */
#endif

static void ip_event_handler(void *, esp_event_base_t, int32_t event_id, void *event_data)
{
    if (event_id == IP_EVENT_ETH_GOT_IP) {
        auto *ev = static_cast<ip_event_got_ip_t *>(event_data);
        esp_ip4addr_ntoa(&ev->ip_info.ip, s_ip, sizeof(s_ip));
        s_eth_ip_nbo.store(ev->ip_info.ip.addr, std::memory_order_relaxed);   /* (#106) */
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
    wifi_creds_init_nvs();
    s_scan_mutex = xSemaphoreCreateMutex();   /* guards the scan result cache (#62) */
    if (!s_scan_mutex) ESP_LOGE(TAG, "scan mutex alloc failed — scanning disabled");
    ESP_LOGI(TAG, "Wi-Fi STA: connecting to SSID \"%s\"", s_wifi_ssid);

    esp_netif_t *wifi_netif = esp_netif_create_default_wifi_sta();

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

    xTaskCreate(wifi_apply_reconfigure_task, "wifi_recfg", 3072, nullptr, 3, nullptr);
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

/* Full mDNS name — the TLS certificate's CN/SAN (web_tls.c) and the console's
 * "browse to" hints. */
extern "C" const char *dns_sink_hostname(void) { return MDNS_HOSTNAME ".local"; }

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

/* ── SD card mount (SPI3, separate bus from W5500) ───────────────── */
static sdmmc_card_t *s_sd_card = nullptr;

static void sd_mount(void)
{
    sdmmc_host_t host = SDSPI_HOST_DEFAULT();
    host.slot = SD_SPI_HOST;

    spi_bus_config_t bus = {};
    bus.mosi_io_num   = SD_MOSI_GPIO;
    bus.miso_io_num   = SD_MISO_GPIO;
    bus.sclk_io_num   = SD_SCLK_GPIO;
    bus.quadwp_io_num = -1;
    bus.quadhd_io_num = -1;

    esp_err_t rc = spi_bus_initialize(SD_SPI_HOST, &bus, SDSPI_DEFAULT_DMA);
    if (rc != ESP_OK) { ESP_LOGW(TAG, "SD SPI bus init failed: %d", rc); return; }

    sdspi_device_config_t slot = SDSPI_DEVICE_CONFIG_DEFAULT();
    slot.gpio_cs  = static_cast<gpio_num_t>(SD_CS_GPIO);
    slot.host_id  = SD_SPI_HOST;

    esp_vfs_fat_sdmmc_mount_config_t mcfg = {};
    mcfg.format_if_mount_failed = false;
    mcfg.max_files              = 4;
    mcfg.allocation_unit_size   = 16 * 1024;

    /* SD-over-SPI init is occasionally flaky (ESP_ERR_INVALID_RESPONSE on the
     * probe). Retry a few times before giving up and falling back to download. */
    for (int attempt = 1; attempt <= 4; attempt++) {
        rc = esp_vfs_fat_sdspi_mount(SD_MOUNT, &host, &slot, &mcfg, &s_sd_card);
        if (rc == ESP_OK) {
            ESP_LOGI(TAG, "SD mounted (attempt %d): %lluMB", attempt,
                     (uint64_t)s_sd_card->csd.capacity * s_sd_card->csd.sector_size / (1024*1024));
            return;
        }
        ESP_LOGW(TAG, "SD mount attempt %d/4 failed: %s", attempt, esp_err_to_name(rc));
        vTaskDelay(pdMS_TO_TICKS(250));
    }
    ESP_LOGW(TAG, "SD mount failed after retries — no SD cache");
    spi_bus_free(SD_SPI_HOST);
}
#endif /* CONFIG_ADBLOCK_NET_ETH — W5500 + SD bring-up */

/* ── Blocklist download task (Core 0, priority 2) ────────────────── */
static void download_task(void *)
{
    /* Boot: try flash first (#70 — instant, needs no SD card, works on every
     * board including the Wi-Fi-only #49 target), then SD, before ever
     * downloading. Either hit means DO NOT re-download on every boot — that
     * wastes ~230s of bandwidth and opens a sort null-window. The 4h-reload
     * timer (or manual /reload) refreshes either way. */
    bool from_flash = blocklist_load_flash();
    bool from_sd    = from_flash ? false : blocklist_load_sd();
    if (!from_flash && !from_sd) {
        /* #75: this is the first TLS client on a cold boot, and now that
         * certificate dates are actually checked (CONFIG_MBEDTLS_HAVE_TIME_DATE)
         * it wants real time, not the floor. The floor is a lower bound and can
         * be stale — an image flashed months after it was built floors months
         * back, and a certificate issued since then reads as not-yet-valid.
         * Waiting a few seconds turns that corner from fail-then-retry into
         * simply succeeding. Bounded, and NOT fatal: with no NTP reachable at
         * all we go ahead on the floor, which is exactly what the floor is for.
         * Only the no-SD-cache path pays this; an SD boot skips the fetch. */
        if (!timesync_wait_synced(10000))
            ESP_LOGW(TAG, "Clock still unsynced after 10s — fetching on the %s "
                          "clock floor; a certificate issued since then will be "
                          "rejected until NTP lands", timesync_source());

        ESP_LOGI(TAG, "No cached blocklist (flash or SD) — downloading...");
        /* Retry with backoff (#57). blocklist_load() returns the domain count,
         * so 0 means the fetch failed; that used to be discarded, leaving the
         * sinkhole with an empty list — every query ALLOWED, silently — until
         * the next 4h reload. Most boot failures are just the network not being
         * ready yet, so a few spaced retries recover without waiting hours. */
        static const int retry_delay_s[] = { 15, 60, 300 };
        blocklist_load_with_retry(retry_delay_s,
                                  sizeof(retry_delay_s) / sizeof(retry_delay_s[0]),
                                  "Boot blocklist download");
        if (blocklist_domain_count() == 0)
            ESP_LOGE(TAG, "Blocklist still empty after retries — NOT blocking "
                          "until the next 4h reload or a manual /reload");
    } else {
        ESP_LOGI(TAG, "%s cache active (%" PRIu32 " domains) — skipping boot refresh",
                 from_flash ? "Flash" : "SD", blocklist_domain_count());
    }
    ESP_LOGI(TAG, "download_task stack hwm: %u bytes free",
             (unsigned)uxTaskGetStackHighWaterMark(NULL));

    /* Reload every 4h on a fixed cadence. Scheduling itself stays on the
     * monotonic esp_timer (immune to NTP re-sync jumps — see L3, where an
     * absolute-wall-clock "sleep then reload" loop drifted); NTP wall-clock
     * (timesync_epoch()) is used only to log a real timestamp, once synced.
     * Use an absolute deadline advanced by exactly one interval each cycle
     * (next += interval) so the download/sort duration never pushes the
     * schedule later. A manual /reload fires immediately without shifting it. */
    const int64_t interval_us = 4LL * 60 * 60 * 1000000;  /* 4h */
    int64_t next_us = esp_timer_get_time() + interval_us;

    /* Forward-cache warm-boot snapshots (#79). First save at +2min so a
     * reboot-after-power-blip keeps the working set the box just rebuilt,
     * then every 20min. Deliberately "now + period" rather than an advancing
     * absolute deadline: blocklist_load() can block this task for minutes,
     * and a missed save should simply resume the cadence, not fire the moment
     * the download returns. */
    const int64_t save_first_us  =  2LL * 60 * 1000000;
    const int64_t save_period_us = 20LL * 60 * 1000000;
    int64_t next_save_us = esp_timer_get_time() + save_first_us;
    for (;;) {
        /* #75: persist the clock as the next boot's floor. Self-rate-limiting
         * (~10 min, plus once promptly after each sync) and a no-op until NTP
         * has landed, so calling it every second costs a load and a compare.
         * It lives here rather than in the SNTP callback because it writes
         * flash and that callback runs in the tcpip task. */
        timesync_persist_tick();

        int64_t now_us = esp_timer_get_time();
        if (now_us >= next_us) {
            if (timesync_is_synced()) {
                time_t epoch = (time_t)timesync_epoch();
                char ts[32]; struct tm tmv; gmtime_r(&epoch, &tmv);
                strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S UTC", &tmv);
                ESP_LOGI(TAG, "4h reload (%s)...", ts);
            } else {
                ESP_LOGI(TAG, "4h reload (clock not yet synced)...");
            }
            static const int reload_retry_delay_s[] = { 15, 60 };
            blocklist_load_with_retry(reload_retry_delay_s,
                                      sizeof(reload_retry_delay_s) / sizeof(reload_retry_delay_s[0]),
                                      "Scheduled reload");
            next_us += interval_us;
            if (next_us <= esp_timer_get_time())     /* fell behind — catch up */
                next_us = esp_timer_get_time() + interval_us;
            continue;
        }
        if (s_reload_requested) {
            s_reload_requested = false;
            ESP_LOGI(TAG, "Manual reload...");
            static const int manual_retry_delay_s[] = { 15, 60 };
            blocklist_load_with_retry(manual_retry_delay_s,
                                      sizeof(manual_retry_delay_s) / sizeof(manual_retry_delay_s[0]),
                                      "Manual reload");
            continue;
        }
        if (now_us >= next_save_us) {
            dns_server_cache_save();                                  /* #79 */
            next_save_us = esp_timer_get_time() + save_period_us;
            continue;
        }
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

/* ── L2 fast-path RX hook ────────────────────────────────────────────
 * Overrides the eth driver's stack-input. Blocked DNS A/AAAA queries are
 * answered here (craft frame + esp_eth_transmit) WITHOUT touching lwIP —
 * removing the ~1.5ms socket/stack overhead from the sinkhole hot path.
 * Everything else passes through to lwIP unchanged (DHCP, httpd, forwarding,
 * cache, allowed queries). Runs single-threaded in the eth RX task. */
static uint32_t s_l2_blocked = 0;   /* L2-handled blocked queries (bypassed lwIP) */
static uint32_t s_l2_cached  = 0;   /* L2-handled forward-cache hits (bypassed lwIP) */
static uint32_t s_l2_tx_fail = 0;   /* esp_eth_transmit() refused a fast-path reply (#101) */
/* (#77) Every frame the hook hands to lwIP unanswered — DNS or not. Proof the
 * *link* is alive and frames are arriving, independent of whether dns_task's
 * own sockets are making any progress: the socket-path watchdog in
 * dns_server.cpp compares this counter's movement against its own query
 * counter to tell "link down, nothing to do" apart from "link fine, queries
 * arriving, dns_task's sockets are wedged." Only incremented on Ethernet
 * boards (this hook doesn't exist on the Wi-Fi-only build); the getter below
 * is unconditional so dns_server.cpp needs no #ifdef to call it. */
static uint32_t s_l2_fallthrough = 0;
/* (#128) Same idea as s_l2_fallthrough, but counts only frames confirmed to be
 * a genuine, well-formed, single-question DNS query — not ARP, not DHCP, not
 * any other non-DNS traffic l2_fallthrough also counts. l2_fallthrough moving
 * proves the *link* is alive; this one moving proves DNS *demand* actually
 * reached the hook and needed the socket path (a query L2 answered itself
 * via l2_blocked/l2_cached never reaches this counter either, since those
 * paths return before the common fall-through site). The #77 watchdog uses
 * THIS counter, not l2_fallthrough, so an ARP/mDNS/SSDP broadcast burst can
 * no longer read as "traffic" on a board that simply has no DNS queries to
 * answer right now — see #128. */
static uint32_t s_l2_dns_fallthrough = 0;
/* (#117) blocklist_verdict_nb() returned -1: the hook could not prove an
 * answer without stalling, so it deferred to lwIP rather than guess.
 * l2_defer_lock_busy: the zero-wait s_wl_mutex take failed (an admin write
 * to the whitelist or custom rules is in flight — see blocklist_verdict_nb's
 * own comment for why this defers unconditionally rather than checking
 * table counts first). l2_defer_snapshot: a reload published underneath
 * the walk. Both flat in steady state; nonzero only during the admin
 * action or reload that caused them, never a sign of a stuck hook. */
static uint32_t s_l2_defer_lock_busy = 0;
static uint32_t s_l2_defer_snapshot  = 0;
extern "C" uint32_t dns_sink_l2_tx_fail(void) { return s_l2_tx_fail; }
extern "C" uint32_t dns_sink_l2_blocked(void) { return s_l2_blocked; }
extern "C" uint32_t dns_sink_l2_cached(void)  { return s_l2_cached; }
extern "C" uint32_t dns_sink_l2_fallthrough(void) { return s_l2_fallthrough; }
extern "C" uint32_t dns_sink_l2_dns_fallthrough(void) { return s_l2_dns_fallthrough; }
extern "C" uint32_t dns_sink_l2_defer_lock_busy(void) { return s_l2_defer_lock_busy; }
extern "C" uint32_t dns_sink_l2_defer_snapshot(void)  { return s_l2_defer_snapshot; }

/* Query-log staging ring (feature request, 2026-09-06): l2_input_cb answers
 * most blocked/cached queries on Ethernet boards WITHOUT ever calling
 * query_log_record() — that function lives in flash and isn't IRAM_ATTR, so
 * calling it directly from this hot path would risk exactly the "must never
 * fault to flash" hazard CONTRIBUTING.md §4 warns about. Bypassing it
 * entirely was the original tradeoff (#78's comment: "the hook's cheaper
 * check set is not a divergence"), but it meant the query log, top-lists,
 * per-minute history, and #71's crash-log breadcrumb were all blind to the
 * MAJORITY of blocked traffic on Ethernet boards (measured live on .244:
 * l2_blocked outnumbers the socket path's own blocked count roughly 6:1).
 *
 * Fix: a small lock-free SPSC ring, internal RAM (not PSRAM — this hook's
 * scratch stays internal per CONTRIBUTING.md §3a, for latency, not just
 * flash-safety). l2_input_cb (producer, IRAM_ATTR) stages a raw record with
 * a few atomic ops and a memcpy — no snprintf, no flash. dns_task (consumer,
 * not IRAM-constrained) drains it on its existing per-tick housekeeping and
 * calls the real query_log_record() for each entry, which is where
 * crashlog_record() already lives — so this closes the #71 blind spot too,
 * for free, the same "fix once, reuse everywhere" shape as this session's
 * pause/bypass work. Ring full (a burst beyond what the tick-rate drain can
 * keep up with) drops and counts rather than blocking or overwriting — the
 * L2 hook must never stall waiting on dns_task.
 *
 * Guarded under CONFIG_ADBLOCK_NET_ETH (review, #124 follow-up): unlike the
 * 4-byte scalar counters just above — cheap enough to leave unconditional so
 * dns_server.cpp needs no #ifdef — this ring is ~2.3 KB of internal .bss
 * (L2LOG_RING=32 entries) whose only producer, l2_log_stage(), is only ever
 * called from l2_input_cb below, itself already gated. Leaving the ring
 * unconditional would burn that RAM on the Wi-Fi-only build, which has no L2
 * hook at all, against CONTRIBUTING.md §3a's "internal RAM is the scarce
 * resource" rule. The #else stub keeps dns_server.cpp's drain call
 * unconditional the same way the scalar getters are. */
#if CONFIG_ADBLOCK_NET_ETH
#define L2LOG_RING 32
typedef struct {
    char     domain[64];
    uint32_t client_ip;   /* host byte order */
    uint16_t qtype;
    bool     blocked;     /* false = l2_cached (an allowed answer) */
} L2LogEntry;
static L2LogEntry            s_l2log[L2LOG_RING];
static std::atomic<uint32_t> s_l2log_head{0};   /* producer-owned (eth RX task) */
static std::atomic<uint32_t> s_l2log_tail{0};   /* consumer-owned (dns_task) */
static std::atomic<uint32_t> s_l2log_dropped{0}; /* producer increments, httpd task reads */

static void IRAM_ATTR l2_log_stage(const char *name, size_t nlen, uint16_t qtype,
                                   uint32_t client_ip_hbo, bool blocked)
{
    uint32_t head = s_l2log_head.load(std::memory_order_relaxed);
    uint32_t tail = s_l2log_tail.load(std::memory_order_acquire);
    /* Ring full: drop and count, never block or overwrite — the L2 hook must
     * never stall waiting on dns_task. A nonzero l2_log_dropped means a burst
     * outran the ~100ms drain rate for that window, not a bug; which specific
     * queries were lost isn't recorded, only the count. */
    if (head - tail >= L2LOG_RING) {
        s_l2log_dropped.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    L2LogEntry *e = &s_l2log[head % L2LOG_RING];
    size_t cl = nlen < sizeof(e->domain) - 1 ? nlen : sizeof(e->domain) - 1;
    memcpy(e->domain, name, cl);
    e->domain[cl] = '\0';
    e->client_ip = client_ip_hbo;
    e->qtype = qtype;
    e->blocked = blocked;
    s_l2log_head.store(head + 1, std::memory_order_release);
}

/* Consumer, called from dns_task: pulls one staged entry, if any. Returns
 * false when the ring is empty. Not IRAM_ATTR — dns_task isn't flash-
 * constrained the way the L2 hook is. */
extern "C" bool dns_sink_l2log_drain(char *domain_out, size_t domain_cap,
                                     uint16_t *qtype_out, uint32_t *client_ip_out,
                                     bool *blocked_out)
{
    uint32_t tail = s_l2log_tail.load(std::memory_order_relaxed);
    uint32_t head = s_l2log_head.load(std::memory_order_acquire);
    if (tail == head) return false;
    L2LogEntry *e = &s_l2log[tail % L2LOG_RING];
    size_t cl = strnlen(e->domain, sizeof(e->domain));
    if (cl >= domain_cap) cl = domain_cap - 1;
    memcpy(domain_out, e->domain, cl);
    domain_out[cl] = '\0';
    *qtype_out = e->qtype;
    *client_ip_out = e->client_ip;
    *blocked_out = e->blocked;
    s_l2log_tail.store(tail + 1, std::memory_order_release);
    return true;
}
extern "C" uint32_t dns_sink_l2log_dropped(void) { return s_l2log_dropped.load(std::memory_order_relaxed); }
#else  /* !CONFIG_ADBLOCK_NET_ETH — no L2 hook, so no producer ever stages anything */
extern "C" bool dns_sink_l2log_drain(char *, size_t, uint16_t *, uint32_t *, bool *) { return false; }
extern "C" uint32_t dns_sink_l2log_dropped(void) { return 0; }
#endif /* CONFIG_ADBLOCK_NET_ETH — L2 query-log staging ring */

/* ── Passive L2 census staging ring (#73 foundation) ─────────────────
 * Pi-hole/AGH cannot see any of this without being the DHCP server; this
 * hook already sees every broadcast frame on the wire, DHCP included, which
 * is the capability gap this issue exists to close.
 *
 * Same shape as the query-log ring just above, for the same reason: a
 * lock-free SPSC ring in internal RAM, IRAM_ATTR producer, drained by
 * dns_task (not IRAM-constrained) into the real, PSRAM-resident census
 * table. A sighting is not a verdict — it answers nothing and must never
 * block the eth RX task, so a full ring drops and counts exactly like the
 * query log's.
 *
 * Two producer call sites, both in l2_input_cb below:
 *   1. l2_census_frame(), called as literally the FIRST statement, before
 *      any of that function's own checks. ARP's ethertype (0x0806) fails
 *      l2_input_cb's very first check (IPv4 only); DHCP's destination port
 *      (67, not 53) fails deep in its ladder. Neither frame kind would ever
 *      reach anything that records client identity otherwise — a census
 *      sighting is deliberately NOT gated behind checks that exist to decide
 *      whether this hook may safely ANSWER a query, because a sighting
 *      answers nothing.
 *   2. A one-line census_stage(..., CENSUS_SEEN_QUERY, ...) call once l2_qname
 *      has confirmed a well-formed A/AAAA/IN question — this is the "did
 *      this MAC ever ask us anything" half of bypass-by-absence, and it
 *      falls out of state the ladder already computed (src MAC, src IP),
 *      so it costs nothing new to gather.
 *
 * mDNS/SSDP are NOT parsed by this producer. The W5500's multicast-block bit
 * being open for them was checked empirically (a raw mDNS A-record query sent
 * to 224.0.0.251:5353, board-filtered to rule out a same-subnet false
 * positive, got a matching reply from both `.195` and `.244`'s own IP), so
 * the door is open for a follow-up, but this foundation doesn't rely on it:
 * ARP and DHCP DISCOVER/REQUEST are broadcast, not multicast, and the hook
 * already proves it sees those (they're what moves l2_fallthrough on an idle
 * board with queries_total still 0).
 *
 * Guarded under CONFIG_ADBLOCK_NET_ETH for the same #3a reason as the query
 * log: this ring is internal .bss on a board that may have no L2 hook to
 * feed it at all. */
#if CONFIG_ADBLOCK_NET_ETH
#define CENSUS_RING 32
/* kind is one of census.h's CENSUS_SEEN_* constants — shared with the
 * consumer via that header rather than a second, comment-synced enum here,
 * so the two sides can't drift silently. */
typedef struct {
    uint8_t  mac[6];
    uint32_t ip;            /* host byte order; 0 if this event carries none */
    int      kind;
    char     hostname[32];  /* DHCP option 12 value; empty for ARP/QUERY */
} CensusEvent;
static CensusEvent           s_census_ring[CENSUS_RING];
static std::atomic<uint32_t> s_census_head{0};    /* producer-owned (eth RX task) */
static std::atomic<uint32_t> s_census_tail{0};    /* consumer-owned (dns_task) */
static std::atomic<uint32_t> s_census_dropped{0}; /* producer increments, httpd task reads */

static void IRAM_ATTR census_stage(const uint8_t *mac, uint32_t ip, int kind,
                                   const char *hostname, size_t hostname_len)
{
    uint32_t head = s_census_head.load(std::memory_order_relaxed);
    uint32_t tail = s_census_tail.load(std::memory_order_acquire);
    if (head - tail >= CENSUS_RING) {
        s_census_dropped.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    CensusEvent *e = &s_census_ring[head % CENSUS_RING];
    memcpy(e->mac, mac, 6);
    e->ip = ip;
    e->kind = kind;
    census_copy_hostname(e->hostname, hostname, hostname_len);
    s_census_head.store(head + 1, std::memory_order_release);
}

/* Frame-level producer (call site 1 of 2) — classifies ARP and DHCP client
 * messages and stages a sighting. See the block comment above for why this
 * runs before, and independent of, l2_input_cb's own verdict-path checks. */
static void IRAM_ATTR l2_census_frame(const uint8_t *buf, uint32_t len)
{
    if (len < 14 + 2) return;
    const uint8_t *mac = buf + 6;   /* Ethernet source address */

    if (buf[12] == 0x08 && buf[13] == 0x06) {            /* ARP */
        if (len < 14 + 28) return;                        /* full IPv4-over-Ethernet ARP payload */
        if (buf[14 + 4] != 6 || buf[14 + 5] != 4) return;  /* hwlen=6, prolen=4 only */
        uint32_t spa = ((uint32_t)buf[28] << 24) | ((uint32_t)buf[29] << 16) |
                       ((uint32_t)buf[30] << 8)  |  (uint32_t)buf[31];
        if (spa == 0) return;   /* ARP probe (RFC 5227): sender has no IP yet */
        census_stage(mac, spa, CENSUS_SEEN_ARP, nullptr, 0);
        return;
    }

    if (buf[12] != 0x08 || buf[13] != 0x00) return;   /* IPv4 only below this point */
    if (len < 14 + 20) return;
    if ((buf[14] >> 4) != 4) return;
    int ihl = (buf[14] & 0x0F) * 4;
    if (ihl < 20 || 14 + (uint32_t)ihl + 8 > len) return;
    /* (#106) Length comes from the IP header, never from the frame — Ethernet
     * pads short frames to 60 bytes, so a UDP length that fits within the raw
     * `len` budget can still extend into that padding and get parsed as DHCP
     * option TLVs (including option 12, the hostname). Same cross-check
     * l2_input_cb makes against its own `iptot`. */
    int iptot = (buf[16] << 8) | buf[17];
    if (iptot < ihl + 8 || 14 + iptot > (int)len) return;
    /* A non-first fragment carries no UDP header at this offset at all — the
     * bytes below would be raw payload continuation, not sport/dport, and
     * could coincidentally read as 68/67 and stage a garbage DHCP sighting
     * with a garbage hostname. Same check l2_input_cb makes at buf[20:21]. */
    if (((buf[20] << 8) | buf[21]) & 0x3FFF) return;
    if (buf[14 + 9] != 17) return;                    /* UDP only */
    int udp = 14 + ihl;
    uint16_t sport = (buf[udp] << 8) | buf[udp + 1];
    uint16_t dport = (buf[udp + 2] << 8) | buf[udp + 3];
    if (sport != 68 || dport != 67) return;           /* DHCP client -> server only */
    int udplen = (buf[udp + 4] << 8) | buf[udp + 5];
    if (udplen < 8 + 240 || udp + udplen > 14 + iptot) return;
    const uint8_t *dhcp = buf + udp + 8;
    uint32_t dhcp_len = (uint32_t)udplen - 8;
    /* BOOTP fixed header is 236 bytes (RFC 951/2131), then a 4-byte magic
     * cookie (99.130.83.99), then options as TLV. ciaddr (offset 12) is
     * usually 0 pre-lease, so this doesn't gate on it — a DISCOVER with no
     * address yet is still a sighting worth having. */
    if (dhcp_len < 240 || dhcp[236] != 99 || dhcp[237] != 130 ||
        dhcp[238] != 83 || dhcp[239] != 99) return;
    uint32_t off = 240;
    const char *hostname = nullptr; size_t hostname_len = 0;
    /* Bounded TLV scan, capped at 64 iterations regardless of how many
     * options the frame carries — this is IRAM-resident and must never spin
     * on a malformed or adversarial packet. */
    for (int iter = 0; iter < 64 && off < dhcp_len; iter++) {
        uint8_t opt = dhcp[off];
        if (opt == 0xFF) break;                 /* end option */
        if (opt == 0x00) { off += 1; continue; } /* pad */
        if (off + 1 >= dhcp_len) break;
        uint8_t olen = dhcp[off + 1];
        if (off + 2 + olen > dhcp_len) break;    /* truncated option — stop, don't guess */
        if (opt == 12 && olen > 0) {             /* option 12: host name */
            hostname = (const char *)&dhcp[off + 2];
            hostname_len = olen;
        }
        off += 2 + olen;
    }
    census_stage(mac, 0, CENSUS_SEEN_DHCP, hostname, hostname_len);
}

/* Consumer, called from dns_task: pulls one staged event, if any. Returns
 * false when the ring is empty. Not IRAM_ATTR — dns_task isn't flash-
 * constrained the way the L2 hook is. */
extern "C" bool dns_sink_census_drain(uint8_t mac_out[6], uint32_t *ip_out,
                                      int *kind_out, char *hostname_out, size_t hostname_cap)
{
    uint32_t tail = s_census_tail.load(std::memory_order_relaxed);
    uint32_t head = s_census_head.load(std::memory_order_acquire);
    if (tail == head) return false;
    CensusEvent *e = &s_census_ring[tail % CENSUS_RING];
    memcpy(mac_out, e->mac, 6);
    *ip_out = e->ip;
    *kind_out = (int)e->kind;
    if (hostname_cap > 0) {   /* 0 means the caller wants no hostname — nothing to write */
        size_t cl = strnlen(e->hostname, sizeof(e->hostname));
        if (cl >= hostname_cap) cl = hostname_cap - 1;
        memcpy(hostname_out, e->hostname, cl);
        hostname_out[cl] = '\0';
    }
    s_census_tail.store(tail + 1, std::memory_order_release);
    return true;
}
extern "C" uint32_t dns_sink_census_dropped(void) { return s_census_dropped.load(std::memory_order_relaxed); }
#else  /* !CONFIG_ADBLOCK_NET_ETH — no L2 hook, so no producer ever stages anything */
extern "C" bool dns_sink_census_drain(uint8_t[6], uint32_t *, int *, char *, size_t) { return false; }
extern "C" uint32_t dns_sink_census_dropped(void) { return 0; }
#endif /* CONFIG_ADBLOCK_NET_ETH — passive L2 census staging ring */

/* (#109) The question-qname parser that used to live here (l2_qname) is now
 * dns_extract_qname() in domain.c/.h, shared with dns_server.cpp's socket
 * path — the two copies' bounds checks had already drifted (functionally
 * equivalent, but only by accident) since #42/L5 needed a human to notice
 * and mirror a fix by hand. It stays IRAM_ATTR there for this call site.
 *
 * IRAM_ATTR (#78): makes the "never touch flash from the L2 hook" invariant
 * explicit rather than relying on CONFIG_LWIP_IRAM_OPTIMIZATION to have
 * caught it incidentally — that setting only covers lwIP's own component
 * sources, not this callback, which esp_eth invokes via a stored function
 * pointer (so it can't be inlined into anything already in IRAM). */
#if CONFIG_ADBLOCK_NET_ETH

/* (#109) Shared tail for both l2_input_cb reply paths (cache hit, blocked).
 * Both build their DNS payload directly into tx[dns..], at which point what
 * remains is identical: turn the copied request's Ethernet/IP/UDP headers
 * into a reply addressed back to the sender, patch the two length fields for
 * this payload's size, and redo the IP checksum (zeroed UDP checksum is
 * legal for IPv4 either way).
 *
 * Deliberately does NOT touch the DNS txid: the blocked path's payload was
 * memcpy'd from the original query (buf), so its txid is already correct;
 * the cached path's payload came from the forward cache and needs its own
 * one-line patch (tx[dns]=buf[dns]; tx[dns+1]=buf[dns+1];) BEFORE calling
 * this — folding that in here would mean every future caller either gets an
 * unwanted patch or has to know to undo it. Keeping it caller-side makes the
 * one real hazard in this consolidation (patch the wrong reply's txid, or
 * silently drop the patch) impossible to get wrong by construction. */
static void IRAM_ATTR l2_finish_reply(uint8_t *tx, int ihl, int udp, int payload_len)
{
    uint8_t t6[6];
    memcpy(t6, tx, 6); memcpy(tx, tx + 6, 6); memcpy(tx + 6, t6, 6);              /* swap MAC */
    uint8_t t4[4];
    memcpy(t4, tx+14+12, 4); memcpy(tx+14+12, tx+14+16, 4); memcpy(tx+14+16, t4, 4); /* swap IP */
    uint8_t t2[2];
    memcpy(t2, tx+udp, 2); memcpy(tx+udp, tx+udp+2, 2); memcpy(tx+udp+2, t2, 2);     /* swap ports */
    int iptot = ihl + 8 + payload_len;
    tx[14+2] = (iptot >> 8); tx[14+3] = (iptot & 0xFF);
    int udplen = 8 + payload_len;
    tx[udp+4] = (udplen >> 8); tx[udp+5] = (udplen & 0xFF);
    tx[udp+6] = 0; tx[udp+7] = 0;                     /* zero UDP checksum (legal IPv4) */
    tx[14+10] = 0; tx[14+11] = 0;                     /* IP checksum */
    uint32_t sum = 0;
    for (int i = 0; i < ihl; i += 2) sum += (tx[14+i] << 8) | tx[14+i+1];
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    uint16_t csum = ~sum;
    tx[14+10] = (csum >> 8); tx[14+11] = (csum & 0xFF);
}

static esp_err_t IRAM_ATTR l2_input_cb(esp_eth_handle_t h, uint8_t *buf, uint32_t len,
                             void *priv, void *info)
{
    (void)info;
    static uint8_t  tx[600];
    static char     name[256];
    bool query_confirmed = false;   /* (#128) set true once this is known to be
                                      * a genuine, well-formed DNS query — see
                                      * s_l2_dns_fallthrough's comment above. */
    /* #73: runs unconditionally, before any of the classification below.
     * A census sighting is not a verdict — it never answers anything, so it
     * must not be gated behind checks that exist to decide whether THIS hook
     * may safely answer a DNS query. ARP and DHCP frames fail those checks
     * immediately (wrong ethertype / wrong dst port) and would never reach
     * anything that records client identity otherwise. */
    l2_census_frame(buf, len);
    do {
        /* Every `break` below hands the frame to lwIP unchanged, which is what
         * keeps this hook honest about the two-verdict-path rule: it may only
         * answer a query it can classify exactly as the socket path would, and
         * anything it cannot classify — a header it will not vouch for, a lock
         * it cannot take, a rewrite it must not render — falls through to the
         * socket path rather than being answered on a guess or dropped here. */
        uint32_t our_ip = s_eth_ip_nbo.load(std::memory_order_relaxed);
        if (!our_ip) break;                              /* (#106) no address yet */
        if (len < 14 + 20 + 8 + 13) break;               /* min IPv4/UDP/DNS */
        if (buf[12] != 0x08 || buf[13] != 0x00) break;   /* IPv4 only */
        if ((buf[14] >> 4) != 4) break;                  /* (#106) IP version nibble */
        int ihl = (buf[14] & 0x0F) * 4;
        if (ihl < 20 || buf[14 + 9] != 17) break;        /* UDP only */
        /* (#106) Length comes from the IP header, never from the frame: Ethernet
         * pads short frames to 60 bytes, so `len - dns` counted padding as DNS
         * payload, and an IP total-length larger than the frame was never
         * rejected at all. */
        int iptot = (buf[16] << 8) | buf[17];
        if (iptot < ihl + 8 || 14 + iptot > (int)len) break;
        /* (#106) Fragments: MF set or a non-zero offset means this frame is not
         * a whole datagram, so the bytes at the UDP/DNS offsets are not what
         * they look like. Reassembly is lwIP's job. */
        if (((buf[20] << 8) | buf[21]) & 0x3FFF) break;
        /* (#106) Only answer what is addressed to us. Without this the hook
         * replied to a query sent to the subnet broadcast — and, since it just
         * swaps the addresses back, replied FROM the broadcast address TO
         * whatever the source claimed to be. */
        uint32_t dst_ip;
        memcpy(&dst_ip, buf + 14 + 16, 4);
        if (dst_ip != our_ip) break;
        /* (#106) A source that cannot receive a unicast reply (0.0.0.0, the
         * all-ones broadcast, or 224/4 multicast) is not a client. */
        uint32_t src_hbo = ((uint32_t)buf[26] << 24) | ((uint32_t)buf[27] << 16) |
                           ((uint32_t)buf[28] << 8)  |  (uint32_t)buf[29];
        if (src_hbo == 0 || src_hbo == 0xFFFFFFFFu || (buf[26] & 0xF0) == 0xE0) break;
        /* (#73/#128, moved here on review) Recognize "this is a genuine,
         * well-formed, single-question DNS query" BEFORE the ACL/pause/bypass
         * gates below. Those gates decide whether THIS hook may ANSWER —
         * they say nothing about whether a frame counts as a query. Staging
         * the census sighting and setting query_confirmed only AFTER those
         * gates (their original position) meant an ACL-denied, paused, or
         * bypassed client's ordinary DNS queries never reached this code at
         * all: the ladder above already `break`s for them one line earlier.
         * That produced a false "suspected bypass" flag for exactly the
         * clients an admin explicitly allowed or paused — the category
         * least likely to actually be bypassing this resolver — and made
         * #128's dns_fallthrough undercount real demand from the same
         * clients. `udp`/`dns`/`dns_len` computed here are reused unchanged
         * by the answer-path code below; nothing about which frames end up
         * answered vs. deferred changes — only when a sighting is staged. */
        int udp = 14 + ihl;
        if (((buf[udp + 2] << 8) | buf[udp + 3]) != 53) break;   /* dst port 53 */
        int udplen = (buf[udp + 4] << 8) | buf[udp + 5];         /* (#106) */
        if (udplen < 8 + 12 || udp + udplen > 14 + iptot) break;
        int dns = udp + 8, dns_len = udplen - 8;
        if (buf[dns + 2] & 0x80) break;                  /* must be a query (QR=0) */
        if (((buf[dns + 4] << 8) | buf[dns + 5]) != 1) break;    /* qdcount==1 */
        /* (#128) Reached only for a genuine, well-formed, single-question DNS
         * query — everything that falls through from here on is real DNS
         * demand, not link noise. See s_l2_dns_fallthrough's comment. */
        query_confirmed = true;
        /* #73 (call site 2 of 2): this MAC has now sent us a well-formed
         * single-question DNS query — the "queried us" half of
         * bypass-by-absence. Staged here, before the A/AAAA/IN narrowing
         * further below (which exists to decide whether THIS hook may
         * answer, not whether a question counts as a sighting) AND before
         * the ACL/pause/bypass gates immediately below (which exist to
         * decide whether this hook may answer AT ALL, same reasoning). A
         * client that only ever sends PTR/TXT/type-65 queries, or one under
         * an admin pause/bypass/ACL rule, is not silent — staging after
         * either kind of gate would have missed it and produced a false
         * "suspected bypass". */
        census_stage(buf + 6, src_hbo, CENSUS_SEEN_QUERY, nullptr, 0);
        /* (#87) The ACL guards the socket path but never this one, so a client
         * excluded from DNS still got blocked verdicts and cached answers over
         * Ethernet — the fast path only failed to answer on a cold miss, where
         * it fell through to the ACL-protected socket. Provable permission is
         * required to answer here; denied OR unknown defers to that socket,
         * which drops the query if it really is denied. */
        if (!acl_permits_nb(src_hbo)) break;
        /* (#48/#74) A client under a timed pause, or on the standing bypass
         * list, must get the real answer, which only the socket path can
         * fetch. Deferring here (rather than answering "not blocked") keeps
         * this hook's rule intact: it never forwards, and it never answers
         * on a verdict the socket path would override. The socket path
         * re-derives both from the same tables. */
        if (pause_active_for(src_hbo) || bypass_active_for_nb(src_hbo)) break;
        size_t nlen = 0;
        int qend = dns_extract_qname(buf + dns, dns_len, 12, name, sizeof(name), &nlen);
        if (qend < 0) break;
        uint16_t qtype = (buf[dns + qend - 4] << 8) | buf[dns + qend - 3];
        if (qtype != 1 && qtype != 28) break;            /* A / AAAA only */
        uint16_t qclass = (buf[dns + qend - 2] << 8) | buf[dns + qend - 1];
        if (qclass != 1) break;                          /* (#106) class IN only */
        /* (#102) The socket path consults the rewrite table before the
         * blocklist, so a name that is both rewritten and blocklisted answers
         * with the configured address there — while this path went straight to
         * the blocklist and answered 0.0.0.0, making the verdict depend on
         * which transport the client happened to use. Test the same table here
         * and, on a match, defer: the answer is then built by the one
         * build_rewrite_a() in the socket path instead of a second copy in
         * IRAM. `-1` (table busy) defers too — same fail-to-the-slow-path rule
         * as everywhere else in this hook. */
        if (qtype == 1) {
            uint32_t rw = 0;
            if (rewrite_lookup_nb(name, nlen, &rw) != 0) break;
        }
        /* (#109 item 3) Forward cache probe: replay fresh allowed upstream
         * replies straight from L2, skipping lwIP — the same socket-stack
         * overhead the blocked path already bypasses. On a cache hit, this
         * answers immediately and skips blocklist_verdict_nb() (and its
         * bl_hash40 + s_wl_mutex + PSRAM probe) entirely, de-duplicating the
         * redundant hash call and matching the socket path (dns_server.cpp),
         * where cache_lookup runs before blocklist_verdict. dns_cache_l2_get()
         * only serves allowed entries stamped with the current blocklist
         * generation (#85), so a hit is proven allowed by construction.
         *
         * That proof depends on load_gen being the generation the ALLOW was
         * actually authorised under, which is only true since #144: it used to
         * be read at store time, an upstream RTT after the verdict, so a bump
         * landing in that window stamped a pre-bump ALLOW as current. Probing
         * the cache first is safe only on top of that fix — before it, this
         * hook's verdict-first order was what shielded Ethernet clients from
         * exactly those entries. */
        int clen = dns_cache_l2_get(domain_hash(name, nlen), qtype,
                                    tx + dns, (int)sizeof(tx) - dns);
        if (clen > 0) {
            memcpy(tx, buf, dns);                         /* eth+ip+udp headers */
            tx[dns] = buf[dns]; tx[dns+1] = buf[dns+1];   /* patch txid to this query */
            l2_finish_reply(tx, ihl, udp, clen);
            if (esp_eth_transmit(h, tx, dns + clen) != ESP_OK) s_l2_tx_fail++;
            s_l2_cached++;
            l2_log_stage(name, nlen, qtype, src_hbo, false);
            free(buf);                                    /* consumed (== eth_l2_free) */
            return ESP_OK;
        }

        /* (#117) Shared rank-ordered verdict — feed + whitelist + custom
         * rules, including @@ exceptions and $important — for queries not
         * answered from the forward cache above. A defer (must not guess)
         * falls through to lwIP exactly like every other `break` in this hook.
         * An allowed verdict (not blocked) also falls through to lwIP to be
         * forwarded upstream since the cache missed. */
        bl_verdict_t v;
        int vr = blocklist_verdict_nb(name, nlen, &v);
        if (vr == BL_DEFER_LOCK_BUSY)      { s_l2_defer_lock_busy++; break; }
        if (vr == BL_DEFER_SNAPSHOT)       { s_l2_defer_snapshot++;  break; }
        if (v.state != BL_BLOCK) break;                  /* not blocked → lwIP forwards */

        /* ── craft blocked response in tx ── */
        int rdlen = (qtype == 28) ? 16 : 4;
        int dns_resp = qend + 12 + rdlen;                /* question + answer RR */
        int frame = dns + dns_resp;
        if (frame > (int)sizeof(tx)) break;
        memcpy(tx, buf, dns + qend);                     /* eth+ip+udp+dns(hdr+question) */
        { uint16_t qf = (buf[dns+2] << 8) | buf[dns+3];
          uint16_t rf = dns_resp_flags(qf, 0);
          tx[dns+2] = (rf >> 8); tx[dns+3] = (rf & 0xFF); }
        tx[dns+6] = 0; tx[dns+7] = 1;                    /* ancount=1 */
        tx[dns+8] = 0; tx[dns+9] = 0; tx[dns+10] = 0; tx[dns+11] = 0;  /* ns/ar=0 */
        uint8_t *a = tx + dns + qend;
        a[0]=0xC0; a[1]=0x0C; a[2]=(qtype>>8); a[3]=(qtype&0xFF);
        /* (#109) TTL shared with the socket path's BLOCKED_TTL_S (dns_server.h)
         * rather than a second hardcoded literal — the two verdict paths must
         * agree on how long a client caches a block, not just whether. */
        a[4]=0; a[5]=1;                                              /* class IN */
        a[6]=(BLOCKED_TTL_S>>24)&0xFF; a[7]=(BLOCKED_TTL_S>>16)&0xFF;
        a[8]=(BLOCKED_TTL_S>>8)&0xFF;  a[9]=BLOCKED_TTL_S&0xFF;      /* ttl */
        a[10]=(rdlen>>8); a[11]=(rdlen&0xFF);
        memset(a+12, 0, rdlen);                          /* 0.0.0.0 / :: */
        l2_finish_reply(tx, ihl, udp, dns_resp);

        if (esp_eth_transmit(h, tx, frame) != ESP_OK) s_l2_tx_fail++;
        s_l2_blocked++;
        l2_log_stage(name, nlen, qtype, src_hbo, true);
        free(buf);                                       /* we consumed it (== eth_l2_free) */
        return ESP_OK;
    } while (0);

    s_l2_fallthrough++;   /* (#77) every `break` above lands here — link is alive */
    if (query_confirmed) s_l2_dns_fallthrough++;   /* (#128) — see comment above */
    return esp_netif_receive((esp_netif_t *)priv, buf, len, NULL);
}
#endif /* CONFIG_ADBLOCK_NET_ETH — L2 fast-path hook */

/* Init-failure halt, made OTA-rollback-aware (#1). Plain portMAX_DELAY halt
 * loops here would defeat CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE: rollback
 * only fires on the NEXT reset, and a halted board never resets, so a bad OTA
 * image that fails init would hang forever on the safety net instead of being
 * reverted by it. If the running partition is still ESP_OTA_IMG_PENDING_VERIFY
 * (a freshly-OTA'd image that never reached esp_ota_mark_app_valid_cancel_
 * rollback below), roll back and reboot immediately instead of halting.
 * On an already-confirmed partition (state != PENDING_VERIFY — normal boot,
 * hardware fault unrelated to OTA) there's nothing safe to roll back to, so
 * this still just halts, same as before. */
static void halt_or_rollback(const char *reason)
{
    ESP_LOGE(TAG, "%s — halting", reason);
    esp_ota_img_states_t state;
    const esp_partition_t *running = esp_ota_get_running_partition();
    if (running && esp_ota_get_state_partition(running, &state) == ESP_OK &&
        state == ESP_OTA_IMG_PENDING_VERIFY) {
        ESP_LOGE(TAG, "unconfirmed OTA image — rolling back to the previous slot");
        esp_ota_mark_app_invalid_rollback_and_reboot();   /* does not return on success */
    }
    for (;;) vTaskDelay(portMAX_DELAY);
}

/* ── app_main ────────────────────────────────────────────────────── */
extern "C" void app_main(void)
{
    /* (#71) First thing, before anything else can plausibly reset or reason
     * about the RTC-memory breadcrumb: snapshot whatever the last boot left
     * behind and classify why we're here. Needs no NVS, no PSRAM, no clock. */
    crashlog_init();

    /* NVS */
    esp_err_t r = nvs_flash_init();
    if (r == ESP_ERR_NVS_NO_FREE_PAGES || r == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        r = nvs_flash_init();
    }
    ESP_ERROR_CHECK(r);

    /* #75: seed the clock from max(last-known-good NVS epoch, build stamp)
     * BEFORE anything can open a TLS connection. Certificate not-before /
     * not-after checks read the system clock, and until this ran that clock
     * said 1970 — the earliest possible point after NVS is the only place this
     * belongs. It is a floor, not a sync: timesync_is_synced() stays false, so
     * the query log and web UI still refuse to date anything until NTP lands. */
    timesync_floor_init();

    /* Event loop + netif */
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(esp_netif_init());

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
    esp_netif_attach(eth_netif, esp_eth_new_netif_glue(eth_handle));
    /* Override the glue's input with our L2 fast-path hook (passthrough for now) */
    ESP_ERROR_CHECK(esp_eth_update_input_path_info(eth_handle, l2_input_cb, eth_netif));

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
    /* Wi-Fi STA bring-up alongside Ethernet (#53: dual-WAN). No L2 fast-path
     * here — Wi-Fi queries take the normal lwIP socket path. */
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
     * upstream ESP32_AdBlocker's own AP-mode bootstrap — then give it one
     * more bounded window before continuing regardless: booting with no
     * upstream reachable yet is already a supported state (see Wi-Fi-only,
     * no-cable above), just newly reachable via the AP instead of USB. */
    ESP_LOGI(TAG, "Waiting for Ethernet or Wi-Fi link and DHCP...");
    EventBits_t link_bits = xEventGroupWaitBits(s_eth_eg, ETH_GOT_IP_BIT | WIFI_GOT_IP_BIT,
                        pdFALSE, pdFALSE, pdMS_TO_TICKS(WIFI_SETUP_AP_TIMEOUT_MS));
    if (!(link_bits & (ETH_GOT_IP_BIT | WIFI_GOT_IP_BIT))) {
        start_setup_ap();
        xEventGroupWaitBits(s_eth_eg, ETH_GOT_IP_BIT | WIFI_GOT_IP_BIT,
                            pdFALSE, pdFALSE, pdMS_TO_TICKS(WIFI_SETUP_AP_TIMEOUT_MS));
    }
    ESP_LOGI(TAG, "Network ready — Ethernet: %s  Wi-Fi: %s",
             s_ip[0] ? s_ip : "(down)", s_wifi_ip[0] ? s_wifi_ip : "(down)");
#else
    /* Wait for link + DHCP lease */
    ESP_LOGI(TAG, "Waiting for Ethernet link and DHCP...");
    xEventGroupWaitBits(s_eth_eg, ETH_CONNECTED_BIT | ETH_GOT_IP_BIT,
                        pdFALSE, pdTRUE, portMAX_DELAY);
    ESP_LOGI(TAG, "Network ready — IP: %s", s_ip);
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

    /* (raw W5500 TX floor measured at ~400us/frame, 2497fps — bus has ~5x
     *  headroom over our ~527qps; the gap is the lwIP per-query path.) */

    /* SNTP: get real wall-clock time so the query log carries dated timestamps.
     * Lightweight built-in lwIP SNTP (one UDP socket). Resolves via the board's
     * own DHCP DNS, not our sinkhole, so it works even before the blocklist loads.
     *
     * #75 moved this up from after web_ui_start(): it only needs an IP and the
     * DHCP resolver, both of which are true here, and starting it this early
     * shortens the window in which TLS clients (DoT on the DNS task, the
     * blocklist fetch) are running on the floor rather than on real time. */
    timesync_start();

    /* Allocate PSRAM ping-pong buffers */
    if (!blocklist_init()) {
        halt_or_rollback("PSRAM blocklist init failed");
    }
    rewrite_init();
    localzone_init_nvs();
    dot_init_nvs();
    acl_init();
    bypass_init();
    pause_init();
    query_log_init();
    census_init();

#if CONFIG_ADBLOCK_NET_ETH
    /* Mount SD card (SPI3 — separate bus from W5500) */
    sd_mount();
#endif

    /* Start DNS sinkhole (Core 1, priority 10). Upstream = the DHCP-provided
     * DNS server for whichever interface is selected (see pick_upstream /
     * apply_upstream_iface — #53). Switchable live from the web UI afterwards
     * without restarting this task. */
    const char *upstream = pick_upstream(s_eth_dns, s_gw);
#if CONFIG_ADBLOCK_NET_WIFI
    if (strcmp(s_upstream_iface, "wifi") == 0)
        upstream = pick_upstream(s_wifi_dns, s_wifi_gw);
#endif
    if (!s_dns.start(upstream)) {
        halt_or_rollback("DNS server start failed");
    }
    /* #80: start() unconditionally overwrites _upstream_ip, so an IP event
     * landing between the pick_upstream() read above and start() would have its
     * set_upstream() silently discarded, with nothing left to re-fire it. The
     * window is microseconds - not the failure we observed - but re-applying
     * once here makes the final upstream derive from current interface state
     * regardless of interleaving, and hands the banner the live value instead
     * of one computed before the task existed. */
    {
        const char *live = apply_upstream_iface();

        const char *lan_ip = "(no IP yet)";
        const char *lan_if = "";
        if (s_ip[0]) { lan_ip = s_ip; lan_if = " (Ethernet)"; }
#if CONFIG_ADBLOCK_NET_WIFI
        else if (s_wifi_ip[0]) { lan_ip = s_wifi_ip; lan_if = " (Wi-Fi)"; }
#endif
        ESP_LOGI(TAG, "DNS sinkhole active (upstream via %s: %s). Point your router's DNS at %s%s",
                 s_upstream_iface, live, lan_ip, lan_if);
    }

    /* Start web UI (HTTPS :443, :80 redirects) */
    bool ui_up = web_ui_start(&s_dns);

    /* OTA rollback confirmation (#1): CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE
     * boots a freshly-flashed OTA slot in a "pending verify" state and
     * reverts to the previous slot on the NEXT reset unless something marks
     * it valid first. DNS serving + the web UI both being up is as good a
     * health signal as this device has — no display, no separate healthcheck
     * endpoint to call. If either of them had failed to reach this point
     * (crash, hang, halt-loop above), this line never runs and the next
     * power cycle rolls back automatically.
     *
     * A UI that failed to start (no TLS identity, httpd_ssl_start failure)
     * is a confirmed image with no way to see it from the network, so on an
     * unverified image that's a rollback, not a confirmation. On an already
     * confirmed image DNS keeps serving and the USB console is the way in —
     * never halt_or_rollback() there: a cert problem is not a reason to stop
     * resolving. */
    if (!ui_up) {
        const esp_partition_t *run = esp_ota_get_running_partition();
        esp_ota_img_states_t st;
        if (run && esp_ota_get_state_partition(run, &st) == ESP_OK && st == ESP_OTA_IMG_PENDING_VERIFY) {
            ESP_LOGE(TAG, "web UI failed on an unverified image — rolling back");
            esp_ota_mark_app_invalid_rollback_and_reboot();
        }
        ESP_LOGE(TAG, "web UI failed to start — DNS keeps serving; USB console for recovery");
    } else {
        esp_ota_mark_app_valid_cancel_rollback();
    }

    /* mDNS: advertise the per-board hostname and expose the HTTP service (#20) */
    if (mdns_init() == ESP_OK) {
        mdns_hostname_set(MDNS_HOSTNAME);
        mdns_instance_name_set("ESP32 AdBlocker");
        mdns_service_add(nullptr, "_https", "_tcp", 443, nullptr, 0);
        ESP_LOGI(TAG, "mDNS: reachable at " MDNS_HOSTNAME ".local");
    }

    /* Launch blocklist download + 4h reload (Core 0, priority 2).
     * 24KB stack: mbedTLS (HTTPS fetch) + FATFS (SD save) are both deep. */
    xTaskCreatePinnedToCore(download_task, "bl_download", 24576, nullptr, 2, nullptr, 0);

    /* USB recovery console: rescue a headless board over the flash cable. */
    console_start();

    ESP_LOGI(TAG, "Startup complete. Ethernet: %s  Wi-Fi: %s — either can be set as your DNS server.",
#if CONFIG_ADBLOCK_NET_ETH
             s_ip[0] ? s_ip : "(down)",
#else
             "(not built)",
#endif
#if CONFIG_ADBLOCK_NET_WIFI
             s_wifi_ip[0] ? s_wifi_ip : "(down)");
#else
             "(not built)");
#endif
}
