#include "crashlog.h"
#include "esp_attr.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_log.h"
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

static const char *TAG = "crashlog";

#define CRASHLOG_RING  8
#define CRASHLOG_MAGIC 0x4C574F52u   /* sentinel: "is this RTC memory ours?" */

typedef struct {
    char     domain[32];   /* truncated — a breadcrumb, not the full query log */
    uint16_t qtype;
    bool     blocked;
    uint32_t ts_s;          /* uptime seconds at record time */
} CrashlogEntry;

typedef struct {
    uint32_t      magic;
    uint32_t      queries_total;
    uint32_t      heap_free_min;
    uint32_t      head;           /* next ring slot to write */
    CrashlogEntry ring[CRASHLOG_RING];
} CrashlogState;

/* Survives a software reset, a panic reboot, and a task/interrupt-watchdog
 * reset (ESP-IDF's .rtc_noinit section contract) — cleared only on power-on
 * reset and brownout. Recording continues across boots without a gap; the
 * previous boot's final state is snapshotted into s_prev below before this
 * struct keeps moving. */
static RTC_NOINIT_ATTR CrashlogState s_live;

static CrashlogState       s_prev;
static bool                s_prev_valid = false;
static esp_reset_reason_t  s_prev_reason;

static const char *reason_str(esp_reset_reason_t r)
{
    switch (r) {
    case ESP_RST_POWERON:   return "poweron";
    case ESP_RST_EXT:       return "ext";
    case ESP_RST_SW:        return "sw";
    case ESP_RST_PANIC:     return "panic";
    case ESP_RST_INT_WDT:   return "int_wdt";
    case ESP_RST_TASK_WDT:  return "task_wdt";
    case ESP_RST_WDT:       return "wdt";
    case ESP_RST_DEEPSLEEP: return "deepsleep";
    case ESP_RST_BROWNOUT:  return "brownout";
    case ESP_RST_SDIO:      return "sdio";
    default:                return "unknown";
    }
}

void crashlog_init(void)
{
    s_prev_reason = esp_reset_reason();

    if (s_live.magic == CRASHLOG_MAGIC) {
        s_prev = s_live;   /* small struct copy — captures the pre-reset state */
        s_prev_valid = true;
    } else {
        /* First boot ever, or a power-on/brownout wiped RTC memory: nothing
         * to show, and the live struct needs its sentinel before anything
         * can record into it. */
        memset(&s_live, 0, sizeof(s_live));
        s_live.magic = CRASHLOG_MAGIC;
    }
    ESP_LOGI(TAG, "reset reason: %s (last-words %s)",
             reason_str(s_prev_reason), s_prev_valid ? "available" : "none");
}

void crashlog_record(const char *domain, uint16_t qtype, bool blocked)
{
    if (s_live.magic != CRASHLOG_MAGIC) return;   /* crashlog_init() hasn't run yet */

    CrashlogEntry *e = &s_live.ring[s_live.head % CRASHLOG_RING];
    snprintf(e->domain, sizeof(e->domain), "%s", domain ? domain : "");
    e->qtype   = qtype;
    e->blocked = blocked;
    e->ts_s    = (uint32_t)(esp_timer_get_time() / 1000000ULL);
    s_live.head++;
    s_live.queries_total++;

    /* esp_get_minimum_free_heap_size() already IS the running minimum since
     * boot — no need to track our own, just keep the latest value. */
    s_live.heap_free_min = (uint32_t)esp_get_minimum_free_heap_size();
}

int crashlog_json(char *out, size_t cap)
{
    if (!s_prev_valid) {
        return snprintf(out, cap, "{\"available\":false,\"reset_reason\":\"%s\"}",
                         reason_str(s_prev_reason));
    }

    int n = snprintf(out, cap,
        "{\"available\":true,\"reset_reason\":\"%s\","
        "\"queries_total\":%" PRIu32 ",\"heap_free_min\":%" PRIu32 ",\"queries\":[",
        reason_str(s_prev_reason), s_prev.queries_total, s_prev.heap_free_min);
    if (n < 0) return 0;

    /* Newest first, same convention as query_log_snapshot(). */
    uint32_t count = s_prev.queries_total < CRASHLOG_RING ? s_prev.queries_total : CRASHLOG_RING;
    for (uint32_t i = 0; i < count && n < (int)cap - 96; i++) {
        uint32_t idx = (s_prev.head - 1 - i + CRASHLOG_RING * 2) % CRASHLOG_RING;
        const CrashlogEntry *e = &s_prev.ring[idx];
        n += snprintf(out + n, cap - n,
            "%s{\"domain\":\"%s\",\"qtype\":%u,\"blocked\":%s,\"ts_s\":%" PRIu32 "}",
            i ? "," : "", e->domain, (unsigned)e->qtype,
            e->blocked ? "true" : "false", e->ts_s);
    }
    n += snprintf(out + n, cap - n, "]}");
    return n;
}
