#include "blocklist.h"
#include "domain.h"
#include "http_fetch.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include <string.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <inttypes.h>
#include <stdio.h>
#include <errno.h>

#define SD_BL_PATH  "/sdcard/blocklist.bin"
#define SD_MAGIC    0xB10C1573u  /* identifies our binary format */

typedef struct {
    uint32_t magic;
    uint32_t count;
    uint32_t reserved[2];
} bl_sd_header_t;

static const char *TAG = "blocklist";
#define NVS_NS  "dns_sink"

/* ── PSRAM ping-pong buffers ─────────────────────────────────────── */
/* Two fixed-size arrays; never freed after boot (no fragmentation). */
static uint32_t *s_buf[2];          /* s_buf[0] and s_buf[1] in PSRAM */
static int       s_active_buf = 0;  /* which buffer is currently live  */

/* Atomic pointer accessed from dns_task (Core 1) and download_task (Core 0).
 * NULL during reload — dns_task forwards all queries upstream. */
static _Atomic(uint32_t *) s_live    = NULL;
static _Atomic uint32_t    s_count   = 0;
static _Atomic bool        s_loading = false;

/* ── Whitelist (SRAM, NVS-backed) ────────────────────────────────── */
static char s_whitelist[WHITELIST_MAX][64];
static uint32_t s_wl_count = 0;
static SemaphoreHandle_t s_wl_mutex = NULL;

/* ── Radix sort (4-pass LSD, in-PSRAM ping-pong) ─────────────────── */
static void radix_sort(uint32_t *a, uint32_t *b, uint32_t n)
{
    for (int shift = 0; shift < 32; shift += 8) {
        uint32_t cnt[256] = {0};
        for (uint32_t i = 0; i < n; i++) cnt[(a[i] >> shift) & 0xFFu]++;
        uint32_t prefix = 0;
        for (int j = 0; j < 256; j++) { uint32_t c = cnt[j]; cnt[j] = prefix; prefix += c; }
        for (uint32_t i = 0; i < n; i++) b[cnt[(a[i] >> shift) & 0xFFu]++] = a[i];
        uint32_t *tmp = a; a = b; b = tmp;
    }
    /* After 4 passes (even), result is back in the original 'a' buffer */
}

/* ── Download callback ───────────────────────────────────────────── */
typedef struct { uint32_t *buf; uint32_t cap; uint32_t n; } load_ctx_t;

static bool on_domain_line(const char *line, size_t len, void *ctx)
{
    load_ctx_t *lc = (load_ctx_t *)ctx;
    if (lc->n >= lc->cap) return true;  /* silently skip if over capacity */

    char norm[256];
    size_t nlen = domain_normalize(norm, sizeof(norm), line, len);
    if (nlen == 0 || domain_is_bare_tld(norm, nlen)) return true;

    lc->buf[lc->n++] = domain_hash(norm, nlen);
    return true;
}

/* ── NVS whitelist persistence ───────────────────────────────────── */
static void wl_load_nvs(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) return;
    for (uint32_t i = 0; i < WHITELIST_MAX && s_wl_count < WHITELIST_MAX; i++) {
        char key[16]; snprintf(key, sizeof(key), "wl%" PRIu32, i);
        size_t len = sizeof(s_whitelist[0]);
        if (nvs_get_str(h, key, s_whitelist[s_wl_count], &len) == ESP_OK)
            s_wl_count++;
        else
            break;
    }
    nvs_close(h);
}

static void wl_save_nvs(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) return;
    nvs_erase_all(h);
    for (uint32_t i = 0; i < s_wl_count; i++) {
        char key[16]; snprintf(key, sizeof(key), "wl%" PRIu32, i);
        nvs_set_str(h, key, s_whitelist[i]);
    }
    nvs_commit(h);
    nvs_close(h);
}

/* ── Public API ──────────────────────────────────────────────────── */

bool blocklist_init(void)
{
    s_wl_mutex = xSemaphoreCreateMutex();
    if (!s_wl_mutex) return false;

    for (int i = 0; i < 2; i++) {
        s_buf[i] = (uint32_t *)heap_caps_malloc(
            BLOCKLIST_CAPACITY * sizeof(uint32_t), MALLOC_CAP_SPIRAM);
        if (!s_buf[i]) {
            ESP_LOGE(TAG, "PSRAM alloc failed for buf[%d] (%" PRIu32 " bytes)",
                     i, (uint32_t)(BLOCKLIST_CAPACITY * sizeof(uint32_t)));
            return false;
        }
    }
    ESP_LOGI(TAG, "PSRAM ping-pong: 2 x %" PRIu32 " KB allocated",
             (uint32_t)(BLOCKLIST_CAPACITY * 4 / 1024));

    wl_load_nvs();
    return true;
}

uint32_t blocklist_load(void)
{
    atomic_store(&s_loading, true);

    /* Point to the buffer NOT currently live. Download into it while the
     * OLD list keeps serving — no null-blocking window during the fetch. */
    int new_buf = 1 - s_active_buf;
    load_ctx_t lc = { .buf = s_buf[new_buf], .cap = BLOCKLIST_CAPACITY, .n = 0 };

    ESP_LOGI(TAG, "Downloading blocklist (old list stays live)...");
    bool ok = http_fetch_lines(BLOCKLIST_URL, on_domain_line, &lc);
    if (!ok || lc.n == 0) {
        ESP_LOGE(TAG, "Download failed or empty; keeping previous list");
        atomic_store(&s_loading, false);
        return 0;
    }
    ESP_LOGI(TAG, "Downloaded %" PRIu32 " domains; sorting...", lc.n);

    /* The sort needs the other buffer as scratch — that's the live one, so we
     * must drop to degraded mode for the ~1-2s sort only (not the whole fetch). */
    atomic_store_explicit(&s_live, NULL, memory_order_release);
    uint32_t *a = s_buf[new_buf];
    uint32_t *b = s_buf[s_active_buf];  /* scratch during sort; live ptr is NULL */
    radix_sort(a, b, lc.n);

    /* Remove duplicates (hash collisions from different domains) */
    uint32_t unique = 0;
    for (uint32_t i = 0; i < lc.n; i++) {
        if (unique == 0 || a[i] != a[unique - 1])
            a[unique++] = a[i];
    }

    /* Atomic swap: publish new array */
    atomic_store_explicit(&s_count, unique, memory_order_relaxed);
    s_active_buf = new_buf;
    atomic_store_explicit(&s_live, s_buf[new_buf], memory_order_release);

    ESP_LOGI(TAG, "Blocklist live: %" PRIu32 " domains (%" PRIu32 " dupes removed)", unique, lc.n - unique);
    atomic_store(&s_loading, false);
    blocklist_save_sd();
    return unique;
}

bool blocklist_is_blocked(const char *domain, size_t len)
{
    uint32_t *arr = atomic_load_explicit(&s_live, memory_order_acquire);
    if (!arr) return false;  /* reload in progress — allow everything */
    uint32_t n = atomic_load_explicit(&s_count, memory_order_relaxed);
    if (n == 0) return false;

    /* Walk suffix components: sub.example.com → example.com → com (stop) */
    const char *p = domain;
    size_t remaining = len;

    while (remaining > 0) {
        if (!domain_is_bare_tld(p, remaining)) {
            if (blocklist_whitelist_contains(p, remaining)) return false;

            uint32_t h = domain_hash(p, remaining);
            /* Binary search in sorted PSRAM array */
            uint32_t lo = 0, hi = n;
            while (lo < hi) {
                uint32_t mid = lo + (hi - lo) / 2;
                if (arr[mid] < h)       lo = mid + 1;
                else if (arr[mid] > h)  hi = mid;
                else                    return true;
            }
        }

        /* Advance to next label */
        const char *dot = (const char *)memchr(p, '.', remaining);
        if (!dot) break;
        remaining -= (size_t)(dot - p) + 1;
        p = dot + 1;
    }
    return false;
}

bool blocklist_whitelist_add(const char *domain)
{
    xSemaphoreTake(s_wl_mutex, portMAX_DELAY);
    bool ok = false;
    if (s_wl_count < WHITELIST_MAX) {
        snprintf(s_whitelist[s_wl_count], sizeof(s_whitelist[0]), "%s", domain);
        s_wl_count++;
        wl_save_nvs();
        ok = true;
    }
    xSemaphoreGive(s_wl_mutex);
    return ok;
}

bool blocklist_whitelist_remove(const char *domain)
{
    xSemaphoreTake(s_wl_mutex, portMAX_DELAY);
    bool found = false;
    for (uint32_t i = 0; i < s_wl_count; i++) {
        if (strcmp(s_whitelist[i], domain) == 0) {
            memmove(s_whitelist[i], s_whitelist[i + 1],
                    (s_wl_count - i - 1) * sizeof(s_whitelist[0]));
            s_wl_count--;
            wl_save_nvs();
            found = true;
            break;
        }
    }
    xSemaphoreGive(s_wl_mutex);
    return found;
}

bool blocklist_whitelist_contains(const char *domain, size_t len)
{
    xSemaphoreTake(s_wl_mutex, portMAX_DELAY);
    bool found = false;
    for (uint32_t i = 0; i < s_wl_count && !found; i++) {
        size_t wlen = strlen(s_whitelist[i]);
        if (wlen == len && memcmp(s_whitelist[i], domain, len) == 0)
            found = true;
    }
    xSemaphoreGive(s_wl_mutex);
    return found;
}

uint32_t blocklist_whitelist_count(void)
{
    xSemaphoreTake(s_wl_mutex, portMAX_DELAY);
    uint32_t n = s_wl_count;
    xSemaphoreGive(s_wl_mutex);
    return n;
}

void blocklist_whitelist_get(char out[][64], uint32_t *count_inout)
{
    xSemaphoreTake(s_wl_mutex, portMAX_DELAY);
    uint32_t n = s_wl_count < *count_inout ? s_wl_count : *count_inout;
    for (uint32_t i = 0; i < n; i++)
        memcpy(out[i], s_whitelist[i], sizeof(s_whitelist[0]));
    *count_inout = n;
    xSemaphoreGive(s_wl_mutex);
}

/* ── SD persistence ──────────────────────────────────────────────── */

bool blocklist_load_sd(void)
{
    FILE *f = fopen(SD_BL_PATH, "rb");
    if (!f) { ESP_LOGI(TAG, "No SD blocklist cache"); return false; }

    bl_sd_header_t hdr;
    if (fread(&hdr, sizeof(hdr), 1, f) != 1 || hdr.magic != SD_MAGIC) {
        ESP_LOGW(TAG, "SD blocklist: bad header");
        fclose(f); return false;
    }
    if (hdr.count == 0 || hdr.count > BLOCKLIST_CAPACITY) {
        ESP_LOGW(TAG, "SD blocklist: bad count %" PRIu32, hdr.count);
        fclose(f); return false;
    }

    size_t got = fread(s_buf[s_active_buf], sizeof(uint32_t), hdr.count, f);
    fclose(f);
    if (got != hdr.count) {
        ESP_LOGW(TAG, "SD blocklist: short read %" PRIu32 "/%" PRIu32, (uint32_t)got, hdr.count);
        return false;
    }

    atomic_store_explicit(&s_count, hdr.count, memory_order_relaxed);
    atomic_store_explicit(&s_live, s_buf[s_active_buf], memory_order_release);
    ESP_LOGI(TAG, "SD blocklist loaded: %" PRIu32 " domains (instant)", hdr.count);
    return true;
}

void blocklist_save_sd(void)
{
    uint32_t n   = atomic_load(&s_count);
    uint32_t *arr = atomic_load_explicit(&s_live, memory_order_acquire);
    if (!arr || n == 0) return;

    ESP_LOGI(TAG, "SD save: opening %s for %" PRIu32 " domains", SD_BL_PATH, n);
    FILE *f = fopen(SD_BL_PATH, "wb");
    if (!f) { ESP_LOGW(TAG, "SD blocklist: can't open for write (errno=%d)", errno); return; }

    bl_sd_header_t hdr = { .magic = SD_MAGIC, .count = n, .reserved = {0, 0} };
    fwrite(&hdr, sizeof(hdr), 1, f);

    /* Write in chunks from a small DRAM bounce buffer — avoids handing the
     * SDSPI/FATFS path a single huge PSRAM-sourced write. */
    static uint32_t chunk[1024];
    size_t written = 0;
    while (written < n) {
        size_t batch = n - written;
        if (batch > 1024) batch = 1024;
        memcpy(chunk, arr + written, batch * sizeof(uint32_t));
        size_t w = fwrite(chunk, sizeof(uint32_t), batch, f);
        if (w != batch) { ESP_LOGW(TAG, "SD write stalled at %u", (unsigned)(written + w)); break; }
        written += batch;
    }
    fflush(f);
    fclose(f);

    if (written == n)
        ESP_LOGI(TAG, "SD blocklist saved: %" PRIu32 " domains (%" PRIu32 " KB)",
                 n, (uint32_t)((n * 4 + 16) / 1024));
    else
        ESP_LOGW(TAG, "SD blocklist: short write %" PRIu32 "/%" PRIu32, (uint32_t)written, n);
}

uint32_t blocklist_domain_count(void) { return atomic_load(&s_count); }
bool     blocklist_is_loading(void)   { return atomic_load(&s_loading); }
