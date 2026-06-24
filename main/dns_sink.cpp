/*
 * dns_sink.cpp — ESP-IDF entry point for DNS sinkhole on LilyGO T-ETH-Elite
 *
 * W5500 Ethernet bringup for the T-ETH-Elite pin map (SPI2, event-group DHCP wait).
 */

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_system.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_idf_version.h"
#include "esp_eth.h"
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(6, 0, 0)
#include "esp_eth_mac_w5500.h"
#include "esp_eth_phy_w5500.h"
#endif
#include "esp_netif.h"
#include "nvs_flash.h"
#include "esp_mac.h"
#include "esp_timer.h"

#include "driver/gpio.h"
#include "driver/spi_master.h"

#include "esp_vfs_fat.h"
#include "sdmmc_cmd.h"
#include "driver/sdspi_host.h"
#include <inttypes.h>

#include "blocklist.h"
#include "domain.h"
#include "rewrite.h"
#include "query_log.h"
#include "dns_server.h"
#include "web_ui.h"
#include "mdns.h"
#include <cstring>
#include <cstdlib>

static const char *TAG = "dns_sink";

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

/* ── Event group ─────────────────────────────────────────────────── */
#define ETH_CONNECTED_BIT  BIT0
#define ETH_GOT_IP_BIT     BIT1
static EventGroupHandle_t s_eth_eg = nullptr;
static char               s_ip[16] = {};
static char               s_gw[16] = {};   /* DHCP gateway — default upstream DNS */

/* ── Global singletons ───────────────────────────────────────────── */
static DnsSinkServer s_dns;
static volatile bool s_reload_requested = false;

/* Called from web_ui.cpp POST /reload */
extern "C" void dns_sink_trigger_reload(void)
{
    s_reload_requested = true;
}

/* ── Ethernet event handlers ─────────────────────────────────────── */
static void eth_event_handler(void *, esp_event_base_t, int32_t event_id, void *)
{
    if (event_id == ETHERNET_EVENT_CONNECTED)
        xEventGroupSetBits(s_eth_eg, ETH_CONNECTED_BIT);
    else if (event_id == ETHERNET_EVENT_DISCONNECTED)
        xEventGroupClearBits(s_eth_eg, ETH_CONNECTED_BIT | ETH_GOT_IP_BIT);
}

static void ip_event_handler(void *, esp_event_base_t, int32_t event_id, void *event_data)
{
    if (event_id == IP_EVENT_ETH_GOT_IP) {
        auto *ev = static_cast<ip_event_got_ip_t *>(event_data);
        esp_ip4addr_ntoa(&ev->ip_info.ip, s_ip, sizeof(s_ip));
        esp_ip4addr_ntoa(&ev->ip_info.gw, s_gw, sizeof(s_gw));
        ESP_LOGI(TAG, "IP: %s  GW(upstream DNS): %s", s_ip, s_gw);
        xEventGroupSetBits(s_eth_eg, ETH_GOT_IP_BIT);
    }
}

/* ── W5500 init for T-ETH-Elite ──────────────────────────────────── */
static esp_eth_handle_t eth_init_w5500(void)
{
    ESP_LOGI(TAG, "W5500 T-ETH-ELITE: SCLK=%d MISO=%d MOSI=%d CS=%d INT=%d @ %d MHz",
             W5500_SCLK_GPIO, W5500_MISO_GPIO, W5500_MOSI_GPIO,
             W5500_CS_GPIO, W5500_INT_GPIO, W5500_SPI_CLOCK);

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
        ESP_LOGI(TAG, "No SD cache — downloading blocklist...");
        blocklist_load();
    } else {
        ESP_LOGI(TAG, "SD cache active (%" PRIu32 " domains) — skipping boot refresh",
                 blocklist_domain_count());
    }
    ESP_LOGI(TAG, "download_task stack hwm: %u bytes free",
             (unsigned)uxTaskGetStackHighWaterMark(NULL));

    /* Daily reload */
    for (;;) {
        for (int i = 0; i < 24 * 60; i++) {
            vTaskDelay(pdMS_TO_TICKS(60 * 1000));
            if (s_reload_requested) {
                s_reload_requested = false;
                break;
            }
        }
        ESP_LOGI(TAG, "Reloading blocklist...");
        blocklist_load();
    }
}

/* ── L2 fast-path RX hook ────────────────────────────────────────────
 * Overrides the eth driver's stack-input. Blocked DNS A/AAAA queries are
 * answered here (craft frame + esp_eth_transmit) WITHOUT touching lwIP —
 * removing the ~1.5ms socket/stack overhead from the sinkhole hot path.
 * Everything else passes through to lwIP unchanged (DHCP, httpd, forwarding,
 * cache, allowed queries). Runs single-threaded in the eth RX task. */
static uint32_t s_l2_blocked = 0;   /* L2-handled blocked queries (bypassed lwIP) */
extern "C" uint32_t dns_sink_l2_blocked(void) { return s_l2_blocked; }

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
        if (!blocklist_is_blocked_nb(name, nlen)) break; /* not blocked → lwIP; _nb avoids stalling eth RX on mutex (#37) */

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

    /* Event loop + netif */
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(esp_netif_init());

    s_eth_eg = xEventGroupCreate();

    /* Register Ethernet event handlers */
    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID,
                                               eth_event_handler, nullptr));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP,
                                               ip_event_handler, nullptr));

    /* Init W5500 + create default Ethernet netif (DHCP client) */
    esp_eth_handle_t eth_handle = eth_init_w5500();
    esp_netif_config_t netif_cfg = ESP_NETIF_DEFAULT_ETH();
    esp_netif_t *eth_netif = esp_netif_new(&netif_cfg);
    esp_netif_attach(eth_netif, esp_eth_new_netif_glue(eth_handle));
    /* Override the glue's input with our L2 fast-path hook (passthrough for now) */
    ESP_ERROR_CHECK(esp_eth_update_input_path_info(eth_handle, l2_input_cb, eth_netif));
    ESP_ERROR_CHECK(esp_eth_start(eth_handle));

    /* Wait for link + DHCP lease */
    ESP_LOGI(TAG, "Waiting for Ethernet link and DHCP...");
    xEventGroupWaitBits(s_eth_eg, ETH_CONNECTED_BIT | ETH_GOT_IP_BIT,
                        pdFALSE, pdTRUE, portMAX_DELAY);
    ESP_LOGI(TAG, "Network ready — IP: %s", s_ip);

    /* (raw W5500 TX floor measured at ~400us/frame, 2497fps — bus has ~5x
     *  headroom over our ~527qps; the gap is the lwIP per-query path.) */

    /* Allocate PSRAM ping-pong buffers */
    if (!blocklist_init()) {
        ESP_LOGE(TAG, "PSRAM blocklist init failed — halting");
        for (;;) vTaskDelay(portMAX_DELAY);
    }
    rewrite_init();
    query_log_init();

    /* Mount SD card (SPI3 — separate bus from W5500) */
    sd_mount();

    /* Start DNS sinkhole (Core 1, priority 10).
     * Default upstream = the DHCP-provided gateway (it runs dnsmasq on typical
     * home networks). Config-UI override for other providers comes later.
     * Falls back to 1.1.1.1 only if no gateway was learned. */
    const char *upstream = (s_gw[0] != '\0') ? s_gw : "1.1.1.1";
    if (!s_dns.start(upstream)) {
        ESP_LOGE(TAG, "DNS server start failed — halting");
        for (;;) vTaskDelay(portMAX_DELAY);
    }
    ESP_LOGI(TAG, "DNS sinkhole active. Point your router's DNS at %s", s_ip);

    /* Start web UI on port 80 */
    web_ui_start(&s_dns);

    /* mDNS: advertise as esp32adblock.local and expose the HTTP service (#20) */
    if (mdns_init() == ESP_OK) {
        mdns_hostname_set("esp32adblock");
        mdns_instance_name_set("ESP32 AdBlocker");
        mdns_service_add(nullptr, "_http", "_tcp", 80, nullptr, 0);
        ESP_LOGI(TAG, "mDNS: reachable at esp32adblock.local");
    }

    /* Launch blocklist download + daily reload (Core 0, priority 2).
     * 24KB stack: mbedTLS (HTTPS fetch) + FATFS (SD save) are both deep. */
    xTaskCreatePinnedToCore(download_task, "bl_download", 24576, nullptr, 2, nullptr, 0);

    ESP_LOGI(TAG, "Startup complete. Board IP: %s — Set as router DNS server.", s_ip);
}
