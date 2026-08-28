/*
 * dns_sink.cpp — ESP-IDF entry point for the DNS sinkhole.
 *
 * W5500 Ethernet bringup (SPI2, event-group DHCP wait). The W5500 + SD pin
 * map is selected per board via the ADBLOCK_BOARD Kconfig choice: LilyGO
 * T-ETH-Elite (default) or Waveshare ESP32-S3-ETH.
 */

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"

#include "esp_system.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_idf_version.h"
#include "esp_eth.h"
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(6, 0, 0)
#include "esp_eth_mac_w5500.h"
#include "esp_eth_phy_w5500.h"
#endif
#if CONFIG_ADBLOCK_NET_WIFI
#include "esp_wifi.h"
#endif
#include "esp_netif.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_ota_ops.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "lwip/inet.h"

#include "driver/gpio.h"
#include "driver/spi_master.h"

#include "esp_vfs_fat.h"
#include "sdmmc_cmd.h"
#include "driver/sdspi_host.h"
#include <inttypes.h>

#include "blocklist.h"
#include "domain.h"
#include "rewrite.h"
#include "acl.h"
#include "dot.h"
#include "query_log.h"
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

#if CONFIG_ADBLOCK_BOARD_WAVESHARE_S3_ETH

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
static char               s_ip[16] = {};      /* Ethernet IP — the LAN-facing address, reported to clients/mDNS/web UI */
static char               s_gw[16] = {};      /* Ethernet DHCP gateway */
static char               s_eth_dns[16] = {}; /* Ethernet DHCP-provided DNS server (option 6) — the real upstream target */
#if CONFIG_ADBLOCK_NET_WIFI
static char               s_wifi_ip[16] = {};
static char               s_wifi_gw[16] = {};   /* Wi-Fi DHCP gateway */
static char               s_wifi_dns[16] = {};  /* Wi-Fi DHCP-provided DNS server — see s_eth_dns */
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
#define NVS_NS       "dns_sink"
#define NVS_KEY_UPIF "up_if"
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
#if CONFIG_ADBLOCK_NET_WIFI
    if (strcmp(s_upstream_iface, "wifi") == 0)
        upstream = pick_upstream(s_wifi_dns, s_wifi_gw);
#endif
    s_dns.set_upstream(upstream);
    return upstream;
}

/* Called from web_ui.cpp POST /net/upstream. Returns false on an invalid or
 * unavailable (not built / not yet connected) interface — caller keeps the
 * previous setting in that case. */
extern "C" bool dns_sink_set_upstream_iface(const char *iface)
{
    if (!iface) return false;
    if (strcmp(iface, "eth") != 0
#if CONFIG_ADBLOCK_NET_WIFI
        && strcmp(iface, "wifi") != 0
#endif
    ) return false;

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
    snprintf(key, sizeof(key), "%s_mode", prefix); nvs_get_u8(h, key, &mode);
    cfg->dhcp = (mode != 0);
    size_t len;
    len = sizeof(cfg->ip);  snprintf(key, sizeof(key), "%s_ip",  prefix); nvs_get_str(h, key, cfg->ip,  &len);
    len = sizeof(cfg->nm);  snprintf(key, sizeof(key), "%s_nm",  prefix); nvs_get_str(h, key, cfg->nm,  &len);
    len = sizeof(cfg->gw);  snprintf(key, sizeof(key), "%s_gw",  prefix); nvs_get_str(h, key, cfg->gw,  &len);
    len = sizeof(cfg->dns); snprintf(key, sizeof(key), "%s_dns", prefix); nvs_get_str(h, key, cfg->dns, &len);
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
    snprintf(key, sizeof(key), "%s_mode", iface); nvs_set_u8(h, key, dhcp ? 1 : 0);
    snprintf(key, sizeof(key), "%s_ip",   iface); nvs_set_str(h, key, ip ? ip : "");
    snprintf(key, sizeof(key), "%s_nm",   iface); nvs_set_str(h, key, nm ? nm : "");
    snprintf(key, sizeof(key), "%s_gw",   iface); nvs_set_str(h, key, gw ? gw : "");
    snprintf(key, sizeof(key), "%s_dns",  iface); nvs_set_str(h, key, dns_ip ? dns_ip : "");
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
static void publish_static_eth(void)
{
    if (s_eth_static.dhcp) return;
    snprintf(s_ip,      sizeof(s_ip),      "%s", s_eth_static.ip);
    snprintf(s_gw,      sizeof(s_gw),      "%s", s_eth_static.gw);
    snprintf(s_eth_dns, sizeof(s_eth_dns), "%s", s_eth_static.dns);
    ESP_LOGI(TAG, "Ethernet link up — static IP: %s  GW: %s  DNS: %s",
             s_ip, s_gw[0] ? s_gw : "(none)", s_eth_dns[0] ? s_eth_dns : "(none)");
    xEventGroupSetBits(s_eth_eg, ETH_GOT_IP_BIT);
    apply_upstream_iface();
}

/* ── Ethernet event handlers ─────────────────────────────────────── */
static void eth_event_handler(void *, esp_event_base_t, int32_t event_id, void *)
{
    if (event_id == ETHERNET_EVENT_CONNECTED) {
        xEventGroupSetBits(s_eth_eg, ETH_CONNECTED_BIT);
        publish_static_eth();      /* no-op under DHCP — the lease drives it instead */
    } else if (event_id == ETHERNET_EVENT_DISCONNECTED) {
        xEventGroupClearBits(s_eth_eg, ETH_CONNECTED_BIT | ETH_GOT_IP_BIT);
        if (!s_eth_static.dhcp) { s_ip[0] = '\0'; s_gw[0] = '\0'; s_eth_dns[0] = '\0'; }
    }
}

/* Read the DHCP-provided DNS server (option 6) for a netif, if any. */
static void fetch_dhcp_dns(esp_netif_t *netif, char *out, size_t cap)
{
    esp_netif_dns_info_t dns{};
    if (esp_netif_get_dns_info(netif, ESP_NETIF_DNS_MAIN, &dns) == ESP_OK
        && dns.ip.type == ESP_IPADDR_TYPE_V4 && dns.ip.u_addr.ip4.addr != 0) {
        esp_ip4addr_ntoa(&dns.ip.u_addr.ip4, out, cap);
    } else {
        out[0] = '\0';
    }
}

#if CONFIG_ADBLOCK_NET_WIFI
static void stop_setup_ap_if_active(void);   /* defined below wifi_creds_init_nvs (#1) */
#endif

static void ip_event_handler(void *, esp_event_base_t, int32_t event_id, void *event_data)
{
    if (event_id == IP_EVENT_ETH_GOT_IP) {
        auto *ev = static_cast<ip_event_got_ip_t *>(event_data);
        esp_ip4addr_ntoa(&ev->ip_info.ip, s_ip, sizeof(s_ip));
        esp_ip4addr_ntoa(&ev->ip_info.gw, s_gw, sizeof(s_gw));
        fetch_dhcp_dns(ev->esp_netif, s_eth_dns, sizeof(s_eth_dns));
        ESP_LOGI(TAG, "Ethernet IP: %s  GW: %s  DNS: %s", s_ip, s_gw, s_eth_dns[0] ? s_eth_dns : "(none)");
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
        esp_ip4addr_ntoa(&ev->ip_info.gw, s_wifi_gw, sizeof(s_wifi_gw));
        fetch_dhcp_dns(ev->esp_netif, s_wifi_dns, sizeof(s_wifi_dns));
        ESP_LOGI(TAG, "Wi-Fi IP: %s  GW: %s  DNS: %s", s_wifi_ip, s_wifi_gw, s_wifi_dns[0] ? s_wifi_dns : "(none)");
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
        if (nvs_get_str(h, "wifi_ssid", s_wifi_ssid, &len) == ESP_OK && s_wifi_ssid[0] != '\0')
            have_ssid = true;
        len = sizeof(s_wifi_pass);
        nvs_get_str(h, "wifi_pass", s_wifi_pass, &len);
        nvs_close(h);
    }
    if (!have_ssid) {
        ESP_LOGI(TAG, "No Wi-Fi creds in NVS — seeding from Kconfig default");
        snprintf(s_wifi_ssid, sizeof(s_wifi_ssid), "%s", CONFIG_ADBLOCK_WIFI_SSID);
        snprintf(s_wifi_pass, sizeof(s_wifi_pass), "%s", CONFIG_ADBLOCK_WIFI_PASSWORD);
        if (nvs_open(NVS_NS, NVS_READWRITE, &h) == ESP_OK) {
            nvs_set_str(h, "wifi_ssid", s_wifi_ssid);
            nvs_set_str(h, "wifi_pass", s_wifi_pass);
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

static void start_setup_ap(void)
{
    if (s_setup_ap_active) return;
    esp_netif_create_default_wifi_ap();
    wifi_config_t ap_cfg = {};
    static const char *AP_SSID = "ESP32AdBlock-Setup";
    snprintf(reinterpret_cast<char *>(ap_cfg.ap.ssid), sizeof(ap_cfg.ap.ssid), "%s", AP_SSID);
    ap_cfg.ap.ssid_len = strlen(AP_SSID);
    ap_cfg.ap.channel = 1;
    ap_cfg.ap.max_connection = 4;
    ap_cfg.ap.authmode = WIFI_AUTH_OPEN;  /* setup-only; see the log line below */
    if (esp_wifi_set_mode(WIFI_MODE_APSTA) != ESP_OK ||
        esp_wifi_set_config(WIFI_IF_AP, &ap_cfg) != ESP_OK) {
        ESP_LOGE(TAG, "setup AP failed to start");
        return;
    }
    s_setup_ap_active = true;
    ESP_LOGW(TAG, "No network link — setup AP \"%s\" is up at 192.168.4.1 "
                  "(open, unauthenticated — join it and browse there to enter "
                  "real Wi-Fi credentials or check status; it shuts off "
                  "automatically once any interface gets a real IP)", AP_SSID);
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
        if (!s_wifi_static.dhcp) { s_wifi_ip[0] = '\0'; s_wifi_gw[0] = '\0'; s_wifi_dns[0] = '\0'; }
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
    static wifi_ap_record_t recs[WIFI_SCAN_MAX];   /* only this task touches it */
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
            char ssid[64]; size_t sl = 0;   /* minimal JSON-string escape */
            for (size_t j = 0; recs[i].ssid[j] != 0 && j < sizeof(recs[i].ssid)
                               && sl < sizeof(ssid) - 2; j++) {
                char c = (char)recs[i].ssid[j];
                if (c == '"' || c == '\\') ssid[sl++] = '\\';
                ssid[sl++] = c;
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
        nvs_set_str(h, "wifi_ssid", s_wifi_ssid);
        nvs_set_str(h, "wifi_pass", s_wifi_pass);
        nvs_commit(h);
        nvs_close(h);
    }

    xTaskCreate(wifi_apply_reconfigure_task, "wifi_recfg", 3072, nullptr, 3, nullptr);
    return true;
}

extern "C" bool dns_sink_setup_ap_active(void) { return s_setup_ap_active; }
#else
extern "C" void dns_sink_wifi_get_ssid(char *out, size_t cap) { if (cap) out[0] = '\0'; }
extern "C" bool dns_sink_wifi_scan_start(void) { return false; }
extern "C" int  dns_sink_wifi_scan_get(char *out, size_t cap)
{
    return snprintf(out, cap, "{\"state\":\"idle\",\"age_s\":-1,\"aps\":[]}");
}
extern "C" bool dns_sink_wifi_set_creds(const char *, const char *) { return false; }
extern "C" bool dns_sink_setup_ap_active(void) { return false; }
#endif

/* ── W5500 init (board pin map selected above) ───────────────────── */
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

/* ── Blocklist download task (Core 0, priority 2) ────────────────── */
static void download_task(void *)
{
    /* Boot: try SD cache first for instant blocking. If present, DO NOT
     * re-download on every boot — it wastes ~230s of bandwidth and opens a
     * sort null-window. The daily-reload timer (or manual /reload) refreshes. */
    bool from_sd = blocklist_load_sd();
    if (!from_sd) {
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

        ESP_LOGI(TAG, "No SD cache — downloading blocklist...");
        /* Retry with backoff (#57). blocklist_load() returns the domain count,
         * so 0 means the fetch failed; that used to be discarded, leaving the
         * sinkhole with an empty list — every query ALLOWED, silently — until
         * the next 4h reload. Most boot failures are just the network not being
         * ready yet, so a few spaced retries recover without waiting hours. */
        static const int retry_delay_s[] = { 15, 60, 300 };
        if (blocklist_load() == 0) {
            for (size_t i = 0; i < sizeof(retry_delay_s) / sizeof(retry_delay_s[0]); i++) {
                ESP_LOGW(TAG, "Boot blocklist download failed — retry %u/%u in %ds",
                         (unsigned)(i + 1),
                         (unsigned)(sizeof(retry_delay_s) / sizeof(retry_delay_s[0])),
                         retry_delay_s[i]);
                vTaskDelay(pdMS_TO_TICKS(retry_delay_s[i] * 1000));
                if (blocklist_load() > 0) break;
            }
            if (blocklist_domain_count() == 0)
                ESP_LOGE(TAG, "Blocklist still empty after retries — NOT blocking "
                              "until the next 4h reload or a manual /reload");
        }
    } else {
        ESP_LOGI(TAG, "SD cache active (%" PRIu32 " domains) — skipping boot refresh",
                 blocklist_domain_count());
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
            blocklist_load();
            next_us += interval_us;
            if (next_us <= esp_timer_get_time())     /* fell behind — catch up */
                next_us = esp_timer_get_time() + interval_us;
            continue;
        }
        if (s_reload_requested) {
            s_reload_requested = false;
            ESP_LOGI(TAG, "Manual reload...");
            blocklist_load();   /* does not shift the daily deadline */
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
extern "C" uint32_t dns_sink_l2_blocked(void) { return s_l2_blocked; }
extern "C" uint32_t dns_sink_l2_cached(void)  { return s_l2_cached; }

/* Parse question qname → normalized name; return qend offset within DNS msg. */
static int l2_qname(const uint8_t *dns, int dns_len, char *out, size_t cap, size_t *outlen)
{
    static char raw[256];
    int off = 12; size_t rl = 0;
    while (off < dns_len && dns[off] != 0) {
        uint8_t l = dns[off];
        if ((l & 0xC0) == 0xC0) return -1;              /* no compression in question */
        if (l & 0xC0) return -1;                        /* #42: reserved label type */
        if (off + 1 + l > dns_len || rl + l + 1 >= sizeof(raw)) return -1;
        if (rl) raw[rl++] = '.';
        memcpy(raw + rl, dns + off + 1, l); rl += l; off += 1 + l;
    }
    if (off >= dns_len) return -1;
    off++;                                               /* null label */
    if (off + 4 > dns_len) return -1;                    /* qtype + qclass */
    size_t nl = domain_normalize(out, cap, raw, rl);
    if (!nl) return -1;
    *outlen = nl;
    return off + 4;
}

static esp_err_t l2_input_cb(esp_eth_handle_t h, uint8_t *buf, uint32_t len,
                             void *priv, void *info)
{
    (void)info;
    static uint8_t  tx[600];
    static char     name[256];
    do {
        if (len < 14 + 20 + 8 + 13) break;               /* min IPv4/UDP/DNS */
        if (buf[12] != 0x08 || buf[13] != 0x00) break;   /* IPv4 only */
        int ihl = (buf[14] & 0x0F) * 4;
        if (ihl < 20 || buf[14 + 9] != 17) break;        /* UDP only */
        int udp = 14 + ihl;
        if (udp + 8 > (int)len) break;
        if (((buf[udp + 2] << 8) | buf[udp + 3]) != 53) break;   /* dst port 53 */
        int dns = udp + 8, dns_len = (int)len - dns;
        if (dns_len < 12) break;
        if (buf[dns + 2] & 0x80) break;                  /* must be a query (QR=0) */
        if (((buf[dns + 4] << 8) | buf[dns + 5]) != 1) break;    /* qdcount==1 */
        size_t nlen = 0;
        int qend = l2_qname(buf + dns, dns_len, name, sizeof(name), &nlen);
        if (qend < 0) break;
        uint16_t qtype = (buf[dns + qend - 4] << 8) | buf[dns + qend - 3];
        if (qtype != 1 && qtype != 28) break;            /* A / AAAA only */
        if (!blocklist_is_blocked_nb(name, nlen)) {      /* not blocked → try L2 cache, else lwIP */
            /* Forward-cache hit answered straight from L2, skipping lwIP — the
             * same socket-stack overhead the blocked path already bypasses. Lay
             * the eth+ip+udp headers into tx, then the seqlock-protected reader
             * copies the cached DNS reply right after them. Miss/race → lwIP. */
            int clen = dns_cache_l2_get(domain_hash(name, nlen), qtype,
                                        tx + dns, (int)sizeof(tx) - dns);
            if (clen <= 0) break;                        /* miss/expired/race → lwIP */
            memcpy(tx, buf, dns);                         /* eth+ip+udp headers */
            uint8_t s6[6]; memcpy(s6,tx,6); memcpy(tx,tx+6,6); memcpy(tx+6,s6,6);            /* swap MAC */
            uint8_t s4[4]; memcpy(s4,tx+14+12,4); memcpy(tx+14+12,tx+14+16,4); memcpy(tx+14+16,s4,4); /* swap IP */
            uint8_t s2[2]; memcpy(s2,tx+udp,2); memcpy(tx+udp,tx+udp+2,2); memcpy(tx+udp+2,s2,2);     /* swap ports */
            tx[dns] = buf[dns]; tx[dns+1] = buf[dns+1];   /* patch txid to this query */
            int iptot_c = ihl + 8 + clen;
            tx[14+2]=(iptot_c>>8); tx[14+3]=(iptot_c&0xFF);
            int udplen_c = 8 + clen;
            tx[udp+4]=(udplen_c>>8); tx[udp+5]=(udplen_c&0xFF);
            tx[udp+6]=0; tx[udp+7]=0;                     /* zero UDP checksum (legal IPv4) */
            tx[14+10]=0; tx[14+11]=0;                     /* IP checksum */
            uint32_t csum=0;
            for (int i=0;i<ihl;i+=2) csum += (tx[14+i]<<8)|tx[14+i+1];
            while (csum>>16) csum=(csum&0xFFFF)+(csum>>16);
            uint16_t cks=~csum; tx[14+10]=(cks>>8); tx[14+11]=(cks&0xFF);
            esp_eth_transmit(h, tx, dns + clen);
            s_l2_cached++;
            free(buf);                                    /* consumed (== eth_l2_free) */
            return ESP_OK;
        }

        /* ── craft blocked response in tx ── */
        int rdlen = (qtype == 28) ? 16 : 4;
        int dns_resp = qend + 12 + rdlen;                /* question + answer RR */
        int frame = dns + dns_resp;
        if (frame > (int)sizeof(tx)) break;
        memcpy(tx, buf, dns + qend);                     /* eth+ip+udp+dns(hdr+question) */
        uint8_t t6[6];
        memcpy(t6, tx, 6); memcpy(tx, tx + 6, 6); memcpy(tx + 6, t6, 6);          /* swap MAC */
        uint8_t t4[4];
        memcpy(t4, tx+14+12, 4); memcpy(tx+14+12, tx+14+16, 4); memcpy(tx+14+16, t4, 4); /* swap IP */
        uint8_t t2[2];
        memcpy(t2, tx+udp, 2); memcpy(tx+udp, tx+udp+2, 2); memcpy(tx+udp+2, t2, 2);     /* swap ports */
        { uint16_t qf = (buf[dns+2] << 8) | buf[dns+3];
          uint16_t rf = dns_resp_flags(qf, 0);
          tx[dns+2] = (rf >> 8); tx[dns+3] = (rf & 0xFF); }
        tx[dns+6] = 0; tx[dns+7] = 1;                    /* ancount=1 */
        tx[dns+8] = 0; tx[dns+9] = 0; tx[dns+10] = 0; tx[dns+11] = 0;  /* ns/ar=0 */
        uint8_t *a = tx + dns + qend;
        a[0]=0xC0; a[1]=0x0C; a[2]=(qtype>>8); a[3]=(qtype&0xFF);
        a[4]=0; a[5]=1; a[6]=0; a[7]=0; a[8]=0; a[9]=10;             /* class IN, ttl 10 */
        a[10]=(rdlen>>8); a[11]=(rdlen&0xFF);
        memset(a+12, 0, rdlen);                          /* 0.0.0.0 / :: */
        int iptot = ihl + 8 + dns_resp;
        tx[14+2]=(iptot>>8); tx[14+3]=(iptot&0xFF);
        int udplen = 8 + dns_resp;
        tx[udp+4]=(udplen>>8); tx[udp+5]=(udplen&0xFF);
        tx[udp+6]=0; tx[udp+7]=0;                        /* zero UDP checksum (legal IPv4) */
        tx[14+10]=0; tx[14+11]=0;                        /* IP checksum */
        uint32_t sum=0;
        for (int i=0;i<ihl;i+=2) sum += (tx[14+i]<<8)|tx[14+i+1];
        while (sum>>16) sum=(sum&0xFFFF)+(sum>>16);
        uint16_t csum=~sum;
        tx[14+10]=(csum>>8); tx[14+11]=(csum&0xFF);

        esp_eth_transmit(h, tx, frame);
        s_l2_blocked++;
        free(buf);                                       /* we consumed it (== eth_l2_free) */
        return ESP_OK;
    } while (0);

    return esp_netif_receive((esp_netif_t *)priv, buf, len, NULL);
}

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
    dot_init_nvs();
    acl_init();
    query_log_init();

    /* Mount SD card (SPI3 — separate bus from W5500) */
    sd_mount();

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

    /* Start web UI on port 80 */
    web_ui_start(&s_dns);

    /* OTA rollback confirmation (#1): CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE
     * boots a freshly-flashed OTA slot in a "pending verify" state and
     * reverts to the previous slot on the NEXT reset unless something marks
     * it valid first. DNS serving + the web UI both being up is as good a
     * health signal as this device has — no display, no separate healthcheck
     * endpoint to call. If either of them had failed to reach this point
     * (crash, hang, halt-loop above), this line never runs and the next
     * power cycle rolls back automatically. */
    esp_ota_mark_app_valid_cancel_rollback();

    /* mDNS: advertise the per-board hostname and expose the HTTP service (#20) */
    if (mdns_init() == ESP_OK) {
        mdns_hostname_set(MDNS_HOSTNAME);
        mdns_instance_name_set("ESP32 AdBlocker");
        mdns_service_add(nullptr, "_http", "_tcp", 80, nullptr, 0);
        ESP_LOGI(TAG, "mDNS: reachable at " MDNS_HOSTNAME ".local");
    }

    /* Launch blocklist download + daily reload (Core 0, priority 2).
     * 24KB stack: mbedTLS (HTTPS fetch) + FATFS (SD save) are both deep. */
    xTaskCreatePinnedToCore(download_task, "bl_download", 24576, nullptr, 2, nullptr, 0);

    /* USB recovery console: rescue a headless board over the flash cable. */
    console_start();

    ESP_LOGI(TAG, "Startup complete. Ethernet: %s  Wi-Fi: %s — either can be set as your DNS server.",
             s_ip[0] ? s_ip : "(down)",
#if CONFIG_ADBLOCK_NET_WIFI
             s_wifi_ip[0] ? s_wifi_ip : "(down)");
#else
             "(not built)");
#endif
}
