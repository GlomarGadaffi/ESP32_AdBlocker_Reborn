#include "timesync.h"
#include "esp_netif_sntp.h"
#include "esp_sntp.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_app_desc.h"
#include "nvs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include <stdlib.h>

/* Uses the built-in lwIP SNTP client (esp_netif_sntp) — the lightweight
 * Espressif-native path: one UDP socket, ~1 KB, no extra component. */

static const char *TAG = "timesync";

#define NVS_NS   "dns_sink"
#define NVS_KEY  "clock_ep"          /* last-known-good epoch, seconds */

/* Persist cadence while synced. 144 writes/day; an NVS page holds ~126 u32
 * entries, so this is roughly one page erase every 21h — nothing against
 * flash rated for 100k cycles. */
#define PERSIST_PERIOD_US  (10LL * 60 * 1000000)

/* __DATE__/__TIME__ are the BUILD MACHINE'S LOCAL time, with no offset
 * recorded. Treating them as UTC can therefore place the floor up to 14h in
 * the future (UTC+14 exists), and a floor in the future is the one direction
 * that breaks things: every certificate issued since the build would fail its
 * not-before check. Back the build stamp off by a full day so it is a floor in
 * the real sense — under-shooting costs nothing, since the floor only has to
 * beat 1970 and only has to last until SNTP lands. */
#define BUILD_EPOCH_SLACK_S  (24 * 60 * 60)

/* Any clock at or beyond this is real time, not a cold-boot zero. 2020-01-01,
 * matching the year floor the build-stamp parser accepts. */
#define CLOCK_SANE_MIN  1577836800L

static volatile bool s_synced = false;

static uint32_t     s_floor_epoch     = 0;       /* 0 = settimeofday never called */
/* How the clock got a usable value at BOOT. Latched by timesync_floor_init()
 * and never rewritten, so the decision stays readable long after SNTP has
 * moved on — the alternative is racing a 1-3s window to observe it. */
static const char  *s_clock_src       = "unset";
static int64_t      s_next_persist_us = 0;       /* 0 = persist on next tick */
static uint32_t     s_persist_count   = 0;

/* ── epoch helpers ───────────────────────────────────────────────── */

/* Howard Hinnant's days_from_civil: days since 1970-01-01 for a proleptic
 * Gregorian y/m/d. Deliberately not strptime/timegm/mktime — the floor runs
 * before anything has established a timezone, and this needs no libc state
 * at all. */
static int64_t days_from_civil(int y, unsigned m, unsigned d)
{
    y -= (m <= 2);
    const int64_t  era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = (unsigned)(y - era * 400);                            /* [0, 399]    */
    const unsigned doy = (153u * (m + (m > 2 ? -3u : 9u)) + 2u) / 5u + d - 1u; /* [0, 365]    */
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;                /* [0, 146096] */
    return era * 146097 + (int64_t)doe - 719468;
}

/* Firmware build time, from the app descriptor Espressif already embeds
 * (CONFIG_APP_COMPILE_TIME_DATE). Returns 0 if the stamp is absent — a
 * reproducible build blanks these — or unparseable; 0 simply drops out of the
 * max() below, it never becomes the floor. */
static uint32_t build_epoch(void)
{
    const esp_app_desc_t *d = esp_app_get_description();
    if (!d) return 0;

    /* __DATE__ is exactly "MMM DD YYYY", day right-justified and SPACE-padded
     * (so "Aug  2 2026"): the year is always at offset 7 and strtoul skips the
     * pad. __TIME__ is exactly "HH:MM:SS". */
    if (strlen(d->date) != 11 || strlen(d->time) != 8) return 0;

    static const char months[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
    char mon[4] = { d->date[0], d->date[1], d->date[2], 0 };
    const char *hit = strstr(months, mon);
    if (!hit) return 0;
    int off = (int)(hit - months);
    if (off % 3) return 0;                       /* matched across a boundary */

    unsigned m   = (unsigned)(off / 3) + 1u;
    unsigned day = (unsigned)strtoul(d->date + 3, NULL, 10);
    int      yr  = (int)strtoul(d->date + 7, NULL, 10);
    unsigned hh  = (unsigned)strtoul(d->time + 0, NULL, 10);
    unsigned mm  = (unsigned)strtoul(d->time + 3, NULL, 10);
    unsigned ss  = (unsigned)strtoul(d->time + 6, NULL, 10);

    if (yr < 2020 || yr > 2200 || day < 1 || day > 31 ||
        hh > 23 || mm > 59 || ss > 60) return 0;

    int64_t e = days_from_civil(yr, m, day) * 86400LL
              + (int64_t)hh * 3600 + (int64_t)mm * 60 + (int64_t)ss
              - BUILD_EPOCH_SLACK_S;
    if (e <= 0 || e >= 0x7FFFFFFFLL) return 0;
    return (uint32_t)e;
}

static uint32_t nvs_epoch_get(void)
{
    nvs_handle_t h;
    uint32_t v = 0;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) return 0;
    if (nvs_get_u32(h, NVS_KEY, &v) != ESP_OK) v = 0;
    nvs_close(h);
    return v;
}

static void nvs_epoch_put(uint32_t v)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) return;
    if (nvs_set_u32(h, NVS_KEY, v) == ESP_OK) nvs_commit(h);
    nvs_close(h);
}

static void fmt_epoch(uint32_t e, char *buf, size_t cap)
{
    time_t t = (time_t)e;
    struct tm tmv;
    gmtime_r(&t, &tmv);
    strftime(buf, cap, "%Y-%m-%d %H:%M:%S", &tmv);
}

/* ── floor ───────────────────────────────────────────────────────── */

void timesync_floor_init(void)
{
    setenv("TZ", "UTC0", 1);
    tzset();

    uint32_t nv = nvs_epoch_get();
    uint32_t bd = build_epoch();
    uint32_t fl = nv > bd ? nv : bd;

    /* Log BOTH candidates, not just the winner. The build-stamp parser only
     * gets to decide the floor on a virgin NVS — one boot in the life of a
     * box — so without this its output would be unobservable exactly when it
     * matters, and a silently broken parse would look identical to a working
     * one. Printing both makes it checkable on any boot. */
    {
        char bn[32], bb[32];
        if (nv) fmt_epoch(nv, bn, sizeof(bn));
        if (bd) fmt_epoch(bd, bb, sizeof(bb));
        ESP_LOGI(TAG, "Clock floor candidates: nvs=%s build=%s (build stamp minus %dh slack)",
                 nv ? bn : "(none)", bd ? bb : "(none)", BUILD_EPOCH_SLACK_S / 3600);
    }

    /* Never move the clock backwards. esp_restart() does NOT clear the RTC, so
     * every reboot that is not a power cut arrives here with the real time
     * already running — measured on this board: a reset at 22:19:14 UTC found
     * the clock already there. A stale floor must not stomp that. */
    time_t now = time(NULL);
    if ((int64_t)now >= (int64_t)CLOCK_SANE_MIN && (int64_t)now >= (int64_t)fl) {
        s_clock_src = "rtc";
        char b[32]; fmt_epoch((uint32_t)now, b, sizeof(b));
        ESP_LOGI(TAG, "Clock already at %s UTC (RTC survived the reset) — floor not applied", b);
        return;
    }

    if (fl == 0) {
        ESP_LOGW(TAG, "No clock floor available (no NVS epoch, no build stamp) "
                      "— TLS is date-checking against 1970 and every handshake "
                      "will fail until SNTP lands");
        return;                                  /* s_clock_src stays "unset" */
    }

    struct timeval tv = { .tv_sec = (time_t)fl, .tv_usec = 0 };
    settimeofday(&tv, NULL);
    s_floor_epoch = fl;
    s_clock_src   = (nv >= bd) ? "nvs" : "build";

    char b[32]; fmt_epoch(fl, b, sizeof(b));
    ESP_LOGI(TAG, "Clock floored to %s UTC (from %s) — TLS cert dates are now "
                  "checked against a plausible clock, not 1970", b, s_clock_src);
}

/* ── SNTP ────────────────────────────────────────────────────────── */

static void on_sync(struct timeval *tv)
{
    (void)tv;
    s_synced = true;
    /* Ask the housekeeping tick to persist promptly rather than up to a full
     * period later. A flag only — this runs in the tcpip task, which has no
     * business blocking on a flash write. */
    s_next_persist_us = 0;

    time_t now = time(NULL);
    char buf[32];
    fmt_epoch((uint32_t)now, buf, sizeof(buf));
    ESP_LOGI(TAG, "Clock synced: %s UTC", buf);
}

void timesync_start(void)
{
    setenv("TZ", "UTC0", 1);
    tzset();

    esp_sntp_config_t cfg = ESP_NETIF_SNTP_DEFAULT_CONFIG_MULTIPLE(
        2, ESP_SNTP_SERVER_LIST("time.nist.gov", "pool.ntp.org"));
    cfg.sync_cb = on_sync;
    cfg.start   = true;

    esp_err_t e = esp_netif_sntp_init(&cfg);
    if (e != ESP_OK) {
        ESP_LOGW(TAG, "SNTP init failed: %s", esp_err_to_name(e));
        return;
    }
    ESP_LOGI(TAG, "SNTP started (time.nist.gov, pool.ntp.org) — UTC");
}

bool timesync_wait_synced(uint32_t timeout_ms)
{
    /* Polls s_synced rather than calling esp_netif_sntp_sync_wait(): that takes
     * a one-shot semaphore which only exists if the config asked for it, and
     * consuming it would race any other waiter. 100 ms granularity is noise
     * against a multi-second budget. */
    for (uint32_t waited = 0; !s_synced && waited < timeout_ms; waited += 100)
        vTaskDelay(pdMS_TO_TICKS(100));
    return s_synced;
}

void timesync_persist_tick(void)
{
    if (!s_synced) return;               /* only a synced value is authoritative */

    int64_t now_us = esp_timer_get_time();
    if (s_next_persist_us && now_us < s_next_persist_us) return;

    /* Written UNCONDITIONALLY, with no "never go backwards" guard. That guard
     * is a trap: one bogus future sample lands in NVS, becomes every later
     * boot's floor, and then refuses every correction — permanently. Gating on
     * s_synced IS the guard, and it lets a poisoned value heal on the first
     * tick after the next real sync. */
    uint32_t e = (uint32_t)time(NULL);
    nvs_epoch_put(e);
    s_persist_count++;
    s_next_persist_us = now_us + PERSIST_PERIOD_US;

    if (s_persist_count == 1) {
        char b[32]; fmt_epoch(e, b, sizeof(b));
        ESP_LOGI(TAG, "Clock floor persisted: %s UTC (every %lld min hereafter)",
                 b, (long long)(PERSIST_PERIOD_US / 60000000));
    }
}

bool timesync_is_synced(void) { return s_synced; }

uint32_t timesync_epoch(void)
{
    if (!s_synced) return 0;
    return (uint32_t)time(NULL);
}

const char *timesync_source(void) { return s_clock_src; }

const char *timesync_state(void)
{
    if (s_synced) return "synced";
    return (strcmp(s_clock_src, "unset") == 0) ? "unset" : "floored";
}
