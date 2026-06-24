#include "query_log.h"
#include "timesync.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "esp_log.h"
#include <string.h>
#include <stdatomic.h>

static const char *TAG = "qlog";

/* ── ring buffer ──────────────────────────────────────────────────── */
static QLogEntry *s_ring = NULL;
static _Atomic uint32_t s_head = 0;   /* next write slot (mod QLOG_SIZE) */

/* ── per-minute history (60 buckets) ─────────────────────────────── */
typedef struct { uint32_t total; uint32_t blocked; } HistBucket;
static HistBucket s_hist[QHIST_BUCKETS];
static uint32_t   s_hist_minute = 0;   /* which minute slot we're filling */

/* ── top-domain table (approx LFU: evict on collision by count) ──── */
static QTopEntry *s_top_d = NULL;
static QTopEntry *s_top_c = NULL;

static void top_insert(QTopEntry *tbl, uint32_t n, const char *key, bool blocked)
{
    /* look for existing entry */
    for (uint32_t i = 0; i < n; i++) {
        if (strcmp(tbl[i].key, key) == 0) {
            tbl[i].total++;
            if (blocked) tbl[i].blocked++;
            return;
        }
    }
    /* find minimum-count slot to evict */
    uint32_t min_idx = 0, min_val = tbl[0].total;
    for (uint32_t i = 1; i < n; i++) {
        if (tbl[i].total < min_val) { min_val = tbl[i].total; min_idx = i; }
    }
    /* replace if new entry has implicit count ≥ slot-to-replace (it's always 1) */
    snprintf(tbl[min_idx].key, 64, "%s", key);
    tbl[min_idx].total   = 1;
    tbl[min_idx].blocked = blocked ? 1 : 0;
}

bool query_log_init(void)
{
    s_ring  = heap_caps_calloc(QLOG_SIZE,   sizeof(QLogEntry), MALLOC_CAP_SPIRAM);
    s_top_d = heap_caps_calloc(QTOP_DOMAINS, sizeof(QTopEntry), MALLOC_CAP_SPIRAM);
    s_top_c = heap_caps_calloc(QTOP_CLIENTS, sizeof(QTopEntry), MALLOC_CAP_SPIRAM);
    if (!s_ring || !s_top_d || !s_top_c) {
        ESP_LOGE(TAG, "PSRAM alloc failed");
        return false;
    }
    return true;
}

void query_log_record(const char *domain, uint16_t qtype, uint32_t client_ip_hbo,
                      bool blocked, bool rewritten)
{
    if (!s_ring || !s_top_d || !s_top_c) return;

    uint32_t idx = atomic_fetch_add(&s_head, 1) % QLOG_SIZE;
    QLogEntry *e = &s_ring[idx];
    snprintf(e->domain, sizeof(e->domain), "%s", domain ? domain : "");
    e->client_ip = client_ip_hbo;
    e->ts_s      = (uint32_t)(esp_timer_get_time() / 1000000ULL);  /* uptime */
    e->epoch_s   = timesync_epoch();   /* wall-clock, 0 until NTP syncs */
    e->qtype     = qtype;
    e->blocked   = blocked;
    e->rewritten = rewritten;

    /* Per-minute history bucket — keyed on uptime (ts_s), not wall-clock, so the
     * graph stays monotonic and is unaffected when NTP first sets the clock. */
    uint32_t now_min = e->ts_s / 60;
    if (now_min != s_hist_minute) {
        /* advance to new minute, clear skipped buckets */
        uint32_t skip = now_min - s_hist_minute;
        if (skip > QHIST_BUCKETS) skip = QHIST_BUCKETS;
        for (uint32_t i = 0; i < skip; i++) {
            uint32_t slot = (s_hist_minute + 1 + i) % QHIST_BUCKETS;
            s_hist[slot].total = 0;
            s_hist[slot].blocked = 0;
        }
        s_hist_minute = now_min;
    }
    uint32_t hslot = now_min % QHIST_BUCKETS;
    s_hist[hslot].total++;
    if (blocked) s_hist[hslot].blocked++;

    top_insert(s_top_d, QTOP_DOMAINS, e->domain, blocked);

    char client_str[20];
    snprintf(client_str, sizeof(client_str), "%u.%u.%u.%u",
             (unsigned)((client_ip_hbo>>24)&0xFF),(unsigned)((client_ip_hbo>>16)&0xFF),
             (unsigned)((client_ip_hbo>>8)&0xFF),(unsigned)(client_ip_hbo&0xFF));
    top_insert(s_top_c, QTOP_CLIENTS, client_str, blocked);
}

uint32_t query_log_snapshot(QLogEntry *out, uint32_t cap)
{
    if (!s_ring) return 0;
    uint32_t head = atomic_load(&s_head);
    uint32_t n = head < QLOG_SIZE ? head : QLOG_SIZE;
    if (n > cap) n = cap;
    for (uint32_t i = 0; i < n; i++) {
        /* walk backwards from newest */
        uint32_t src = (head - 1 - i + QLOG_SIZE * 2) % QLOG_SIZE;
        out[i] = s_ring[src];
    }
    return n;
}

uint32_t query_log_top_domains(QTopEntry *out, uint32_t cap)
{
    if (!s_top_d) return 0;
    uint32_t n = cap < QTOP_DOMAINS ? cap : QTOP_DOMAINS;
    memcpy(out, s_top_d, n * sizeof(QTopEntry));
    /* simple insertion sort descending by total */
    for (uint32_t i = 1; i < n; i++) {
        QTopEntry key = out[i]; int j = (int)i - 1;
        while (j >= 0 && out[j].total < key.total) { out[j+1] = out[j]; j--; }
        out[j+1] = key;
    }
    return n;
}

uint32_t query_log_top_clients(QTopEntry *out, uint32_t cap)
{
    if (!s_top_c) return 0;
    uint32_t n = cap < QTOP_CLIENTS ? cap : QTOP_CLIENTS;
    memcpy(out, s_top_c, n * sizeof(QTopEntry));
    for (uint32_t i = 1; i < n; i++) {
        QTopEntry key = out[i]; int j = (int)i - 1;
        while (j >= 0 && out[j].total < key.total) { out[j+1] = out[j]; j--; }
        out[j+1] = key;
    }
    return n;
}

void query_log_stats(uint32_t *total_out, uint32_t *blocked_out)
{
    uint32_t h = atomic_load(&s_head);
    if (total_out)   *total_out   = h;
    if (blocked_out) *blocked_out = 0; /* main counters are in dns_server.cpp */
}

void query_log_history(uint32_t total_out[QHIST_BUCKETS],
                       uint32_t blocked_out[QHIST_BUCKETS],
                       uint32_t *count_out)
{
    /* Walk backwards from most recent bucket, up to QHIST_BUCKETS */
    uint32_t cur = s_hist_minute;
    uint32_t filled = 0;
    for (uint32_t i = 0; i < QHIST_BUCKETS; i++) {
        uint32_t slot = (cur - i + QHIST_BUCKETS * 2) % QHIST_BUCKETS;
        total_out[i]   = s_hist[slot].total;
        blocked_out[i] = s_hist[slot].blocked;
        if (s_hist[slot].total > 0) filled = i + 1;
    }
    *count_out = filled > 0 ? filled : 1;
}
