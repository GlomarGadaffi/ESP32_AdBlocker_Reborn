/*
 * dns_sink.cpp — ESP-IDF entry point for the DNS sinkhole.
 *
 * Network bring-up (W5500 Ethernet, Wi-Fi STA, setup AP, static IP, upstream
 * selection) lives in net_bringup.cpp; app_main below drives it. The SD pin
 * map is selected per board via the ADBLOCK_BOARD Kconfig choice: LilyGO
 * T-ETH-Elite (default) or Waveshare ESP32-S3-ETH.
 */

#include "nvs_keys.h"     /* every NVS key this project owns, in one place (#111) */
#include "net_bringup.h"
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
#include "bootloader_random.h"
#include "esp_timer.h"
#include "esp_attr.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "dns_health.h"
#include <errno.h>

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

/* Generic ESP32-S3 dev board, Wi-Fi only (#49): no SD slot, nothing here.
 * BOARD_NAME / MDNS_HOSTNAME come from net_bringup.h. */

#elif CONFIG_ADBLOCK_BOARD_WAVESHARE_S3_ETH

/* ── Pin map: Waveshare ESP32-S3-ETH (ESP32-S3R8 + W5500) ──────── */
/* W5500 pins live in net_bringup.cpp. BOARD_NAME / MDNS_HOSTNAME: net_bringup.h. */

/* TF slot, SPI mode (CS=DAT3, MISO=DAT0, MOSI=CMD). Pins from the
 * CircuitPython board definition; a card has not yet been tested in this
 * slot — a wrong pin here just fails the mount and falls back to download. */
#define SD_MISO_GPIO  5
#define SD_MOSI_GPIO  6
#define SD_SCLK_GPIO  7
#define SD_CS_GPIO    4
#define SD_SPI_HOST   SPI3_HOST
#define SD_MOUNT      "/sdcard"

#else /* CONFIG_ADBLOCK_BOARD_T_ETH_ELITE */

/* ── SD card pin map: LilyGO T-ETH-ELITE S3 ─────────────────────── */
#define SD_MISO_GPIO  9
#define SD_MOSI_GPIO  11
#define SD_SCLK_GPIO  10
#define SD_CS_GPIO    12
#define SD_SPI_HOST   SPI3_HOST
#define SD_MOUNT      "/sdcard"

/* W5500 pin map (LilyGO T-ETH-ELITE S3): net_bringup.cpp. */

#endif /* board select */


/* ── Global singletons ───────────────────────────────────────────── */
static DnsSinkServer s_dns;
static volatile bool s_reload_requested = false;

/* Called from web_ui.cpp POST /reload */
extern "C" void dns_sink_trigger_reload(void)
{
    s_reload_requested = true;
}


extern "C" void dns_sink_reboot(void)
{
    esp_restart();
}


/* Full mDNS name — the TLS certificate's CN/SAN (web_tls.c) and the console's
 * "browse to" hints. */
extern "C" const char *dns_sink_hostname(void) { return MDNS_HOSTNAME ".local"; }

#if CONFIG_ADBLOCK_NET_ETH
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
#endif /* CONFIG_ADBLOCK_NET_ETH — SD bring-up */

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
        uint32_t our_ip = net_eth_ip_nbo.load(std::memory_order_relaxed);
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
                                    buf + dns + 12, qend - 4 - 12,   /* exact wire qname */
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

/* ── DNS self-health probe ───────────────────────────────────────────────
 * After app_main marks the image valid nothing used to check that port 53
 * still answers: the web UI could be up, the L2 watchdog quiet, and every
 * client resolving nothing. This task asks the board's own resolver one real
 * question every DNS_HEALTH_PROBE_INTERVAL_MS and hands the outcome to the
 * pure state machine in dns_health.c, which decides when a reboot is due.
 *
 * Which name: no name is guaranteed to be answered without upstream (a rewrite
 * or a blocklist entry is user data, and "localzone" names are forwarded). So
 * the probe asks for "selfcheck.invalid", which resolvers answer NXDOMAIN
 * themselves; dns_task caches that, and from then on the forward cache's
 * stale-serve path replays it even with the upstream down. For the window
 * before it is first cached, and for a cache that evicted it, an upstream
 * outage is told apart from a dead task by dns_task's own query counter: the
 * counter is bumped when a datagram is read off port 53, before any upstream
 * work, so "no reply AND the counter did not move" is the only timeout that
 * counts as a failure. Any well-formed response with our txid is a pass,
 * including SERVFAIL and REFUSED.
 *
 * The probe goes to 127.0.0.1, not the board's LAN address. dns_task's socket
 * is bound to INADDR_ANY, and lwIP delivers loopback in-stack: sdkconfig has
 * CONFIG_LWIP_NETIF_LOOPBACK=y (components/lwip/Kconfig:569-572, default y),
 * which sets LWIP_HAVE_LOOPIF=1 (port/include/lwipopts.h:804-805) so a real
 * 127.0.0.1 netif exists; ip4_output_if() hands a packet to a netif's own
 * address to netif_loop_output() (ip4.c:1060-1070), which queues it and
 * schedules netif_poll() on the tcpip thread via tcpip_try_callback()
 * (netif.c:1218-1227; LWIP_NETIF_LOOPBACK_MULTITHREADING = !NO_SYS). Using
 * 127.0.0.1 also means the destination never depends on which interface holds
 * the LAN address (Wi-Fi/Ethernet failover, two netifs on one subnet routing
 * the own-address packet out the wrong one) so nothing is re-read mid-probe.
 * LIMIT: a loopback probe exercises lwIP + the UDP socket + dns_task only. It
 * never touches the Ethernet driver or the L2 fast path (l2_input_cb), so a
 * dead W5500 RX path or a broken L2 hook is NOT detected here; the L2
 * watchdog covers the driver side.
 *
 * The probe is an ordinary client (source 127.0.0.1), so it goes through the
 * client ACL like any other. If the ACL would drop it, the probe is SKIPPED
 * (logged once) rather than failed: with an allow-list that omits loopback
 * the self-check is off, which is safer than a reboot loop. Pause and bypass
 * are per client IP and never match 127.0.0.1. Every probe is one more count
 * in queries_total; query_log_record() drops source 127.0.0.1 (host byte
 * order), so the probe leaves no query-log line, history or top-list entry.
 *
 * Reboot gating beyond dns_health.c's streak: never before one OK this boot,
 * and at most DNS_HEALTH_MAX_CONSEC_REBOOTS in a row (RTC counter in
 * crashlog, cleared after 10 consecutive OKs).
 *
 * What a reboot goes through is the same esp_restart() the L2 watchdog and
 * the select() recovery use (dns_sink_reboot); crashlog marks it first so the
 * next boot can say why. */
#define HEALTH_PROBE_TIMEOUT_MS 2000
#define HEALTH_RX_ATTEMPTS      4        /* stray datagrams tolerated per probe */
#define HEALTH_TASK_STACK       4096     /* rx is 64 B on the stack; socket/sendto/recvfrom/ESP_LOG fit well inside */
#define HEALTH_TASK_PRIO        3
/* "\x09selfcheck\x07invalid\x00", QTYPE A, QCLASS IN. */
static const uint8_t HEALTH_QUESTION[] = {
    9, 's','e','l','f','c','h','e','c','k', 7, 'i','n','v','a','l','i','d', 0,
    0x00, 0x01, 0x00, 0x01 };

static std::atomic<bool>     s_health_ota_busy{false};
static std::atomic<uint32_t> s_health_ok{0};
static std::atomic<uint32_t> s_health_fail{0};
static std::atomic<uint32_t> s_health_skipped{0};
static std::atomic<uint32_t> s_health_last_action{0};   /* dns_health_action_t */
static bool                  s_health_acl_logged = false;

/* Called from web_ui.cpp around an OTA upload so the probe stands down. */
extern "C" void dns_sink_health_ota_busy(bool busy)
{
    s_health_ota_busy.store(busy, std::memory_order_relaxed);
}

extern "C" uint32_t dns_sink_health_probe_ok(void)      { return s_health_ok.load(std::memory_order_relaxed); }
extern "C" uint32_t dns_sink_health_probe_fail(void)    { return s_health_fail.load(std::memory_order_relaxed); }
extern "C" uint32_t dns_sink_health_probe_skipped(void) { return s_health_skipped.load(std::memory_order_relaxed); }
/* 0 none, 1 warn, 2 reboot — the dns_health_action_t value of the latest decision. */
extern "C" uint32_t dns_sink_health_last_action(void)   { return s_health_last_action.load(std::memory_order_relaxed); }

/* A response to our question: QR set, standard opcode, our txid. The RCODE is
 * deliberately not checked. */
static bool health_reply_ok(const uint8_t *r, int n, uint16_t txid)
{
    if (n < 12) return false;
    if ((uint16_t)((r[0] << 8) | r[1]) != txid) return false;
    if ((r[2] & 0x80) == 0) return false;
    if ((r[2] & 0x78) != 0) return false;
    return true;
}

static dns_health_result_t health_probe_once(void)
{
    if (s_health_ota_busy.load(std::memory_order_relaxed)) return DNS_HEALTH_SKIPPED;
    if (blocklist_is_loading()) return DNS_HEALTH_SKIPPED;
    const uint32_t ip_nbo = net_own_ip_nbo();
    if (ip_nbo == 0) return DNS_HEALTH_SKIPPED;
    if (!acl_permits(INADDR_LOOPBACK)) {
        if (!s_health_acl_logged) {
            s_health_acl_logged = true;
            ESP_LOGW(TAG, "DNS health probe off: the client ACL does not list 127.0.0.1");
        }
        return DNS_HEALTH_SKIPPED;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        ESP_LOGW(TAG, "DNS health probe: socket() failed (%d), skipping", errno);
        return DNS_HEALTH_SKIPPED;
    }
    struct timeval tv;
    tv.tv_sec  = HEALTH_PROBE_TIMEOUT_MS / 1000;
    tv.tv_usec = (HEALTH_PROBE_TIMEOUT_MS % 1000) * 1000;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) {
        ESP_LOGW(TAG, "DNS health probe: SO_RCVTIMEO failed (%d), skipping", errno);
        close(fd);
        return DNS_HEALTH_SKIPPED;
    }

    uint8_t q[12 + sizeof(HEALTH_QUESTION)];
    const uint16_t txid = (uint16_t)(esp_random() & 0xFFFFu);
    memset(q, 0, 12);
    q[0] = (uint8_t)(txid >> 8);
    q[1] = (uint8_t)(txid & 0xFF);
    q[2] = 0x01;                       /* RD */
    q[5] = 0x01;                       /* QDCOUNT = 1 */
    memcpy(q + 12, HEALTH_QUESTION, sizeof(HEALTH_QUESTION));

    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family      = AF_INET;
    to.sin_port        = htons(53);
    to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    const uint64_t served_before = s_dns.queries_total();
    const int64_t  t_start_us    = esp_timer_get_time();
    if (sendto(fd, q, sizeof(q), 0, (struct sockaddr *)&to, sizeof(to)) != (int)sizeof(q)) {
        ESP_LOGW(TAG, "DNS health probe: sendto failed (%d), skipping", errno);
        close(fd);
        return DNS_HEALTH_SKIPPED;
    }

    dns_health_result_t res = DNS_HEALTH_TIMEOUT;
    bool got_anything = false;
    for (int i = 0; i < HEALTH_RX_ATTEMPTS; i++) {
        uint8_t rx[64];   /* only the header is read; a longer datagram is truncated */
        struct sockaddr_in from;
        socklen_t fl = sizeof(from);
        int n = recvfrom(fd, rx, sizeof(rx), 0, (struct sockaddr *)&from, &fl);
        if (n < 0) break;                       /* timeout or error: nothing more is coming */
        got_anything = true;
        if (from.sin_addr.s_addr == htonl(INADDR_LOOPBACK) && from.sin_port == htons(53) &&
            health_reply_ok(rx, n, txid)) {
            res = DNS_HEALTH_OK;
            break;
        }
        if ((esp_timer_get_time() - t_start_us) >= (int64_t)HEALTH_PROBE_TIMEOUT_MS * 1000) break;
    }
    close(fd);

    if (res == DNS_HEALTH_OK) return res;
    if (got_anything) return DNS_HEALTH_BAD_REPLY;

    /* No reply. If dns_task read anything off port 53 meanwhile it is alive
     * and the silence is upstream's, which must never cause a reboot. */
    if (s_dns.queries_total() != served_before) return DNS_HEALTH_SKIPPED;
    return DNS_HEALTH_TIMEOUT;
}

static void dns_health_task(void *)
{
    dns_health_t hs;
    dns_health_init(&hs, nullptr);
    dns_health_set_prior_reboots(&hs, crashlog_dns_health_reboots());
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(DNS_HEALTH_PROBE_INTERVAL_MS));
        const dns_health_result_t res = health_probe_once();
        switch (res) {
        case DNS_HEALTH_OK:      s_health_ok.fetch_add(1, std::memory_order_relaxed); break;
        case DNS_HEALTH_SKIPPED: s_health_skipped.fetch_add(1, std::memory_order_relaxed); break;
        default:                 s_health_fail.fetch_add(1, std::memory_order_relaxed); break;
        }
        const dns_health_action_t act =
            dns_health_step(&hs, res, (uint32_t)(esp_timer_get_time() / 1000));
        s_health_last_action.store((uint32_t)act, std::memory_order_relaxed);
        if (dns_health_take_clear(&hs)) crashlog_dns_health_reboots_clear();
        const dns_health_note_t note = dns_health_take_note(&hs);
        if (note == DNS_HEALTH_NOTE_NEVER_OK)
            ESP_LOGW(TAG, "DNS health probe has never succeeded this boot: reboots disabled (probe unable to reach port 53?)");
        else if (note == DNS_HEALTH_NOTE_LOOP_GUARD)
            ESP_LOGW(TAG, "DNS health: %u consecutive health reboots without a healthy period: reboots disabled this boot",
                     (unsigned)DNS_HEALTH_MAX_CONSEC_REBOOTS);
        if (act == DNS_HEALTH_ACT_WARN) {
            ESP_LOGW(TAG, "DNS health probe failed (%s), %" PRIu32 " in a row",
                     res == DNS_HEALTH_TIMEOUT ? "no reply" : "bad reply", hs.streak);
        } else if (act == DNS_HEALTH_ACT_REBOOT) {
            ESP_LOGE(TAG, "DNS has not answered for %" PRIu32 " probes in a row — restarting", hs.streak);
            crashlog_mark_dns_health_reboot();
            vTaskDelay(pdMS_TO_TICKS(100));   /* let the log line leave the UART */
            dns_sink_reboot();
        }
    }
}

/* ── app_main ────────────────────────────────────────────────────── */
extern "C" void app_main(void)
{
    /* (#71) First thing, before anything else can plausibly reset or reason
     * about the RTC-memory breadcrumb: snapshot whatever the last boot left
     * behind and classify why we're here. Needs no NVS, no PSRAM, no clock. */
    crashlog_init();

    /* Entropy. esp_random()/esp_fill_random() are only a true RNG while an
     * entropy source runs: the RF subsystem once esp_wifi_start() is called,
     * or the SAR ADC source bootloader_random_enable() turns on (IDF
     * random.rst). The 2nd-stage bootloader turns the ADC source OFF before
     * handing over, so from here until Wi-Fi starts every draw is
     * pseudo-random — and on an Ethernet board booted with Wi-Fi disabled
     * (Network tab / `wifi-off`) Wi-Fi never starts, so that was the whole
     * uptime: the TLS key (web_tls.c), ECDHE and server randoms, session and
     * CSRF tokens (web_auth.c), PBKDF2 salts, DNS txids and 0x20 bits
     * (dns_server.cpp). Enabled BEFORE anything can draw, and left on; the
     * Wi-Fi-on path hands over to RF in wifi_init_sta() (net_bringup.cpp) (the ADC source and
     * RF conflict). Nothing here uses the ADC or the temperature sensor, so
     * leaving it on is otherwise free; whoever adds one must disable it first. */
    bootloader_random_enable();
    ESP_LOGI(TAG, "[boot] entropy: SAR ADC source on — esp_random() is a TRNG until RF takes over");

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

    /* Ethernet / Wi-Fi bring-up and the bounded link waits — net_bringup.cpp.
     * The L2 fast-path hook is registered there on the Ethernet netif. */
#if CONFIG_ADBLOCK_NET_ETH
    net_bringup_init(&s_dns, l2_input_cb);
#else
    net_bringup_init(&s_dns, nullptr);
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
    if (!pause_init()) {
        ESP_LOGE(TAG, "pause_init failed - pause/schedule unavailable, blocking stays on");
    }
    query_log_init();
    census_init();

#if CONFIG_ADBLOCK_NET_ETH
    /* Mount SD card (SPI3 — separate bus from W5500) */
    sd_mount();
#endif

    /* Start DNS sinkhole (Core 1, priority 10). Upstream = the DHCP-provided
     * DNS server for whichever interface is selected (see pick_upstream /
     * apply_upstream_iface (net_bringup.cpp) — #53). Switchable live from the web UI afterwards
     * without restarting this task. */
    const char *upstream = net_initial_upstream();
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
        const char *live = net_apply_upstream_iface();
        net_log_sinkhole_active(live);
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

    /* Self-check of port 53 from here on; created once, fixed stack. Started
     * after the rollback decision above so it can never interfere with it. */
    if (xTaskCreate(dns_health_task, "dns_health", HEALTH_TASK_STACK, nullptr,
                    HEALTH_TASK_PRIO, nullptr) != pdPASS)
        ESP_LOGE(TAG, "dns_health task failed to start — no DNS self-check this boot");

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

    net_log_startup_complete();
}
