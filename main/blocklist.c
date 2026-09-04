#include "blocklist.h"
#include "bl_table.h"
#include "domain.h"
#include "http_fetch.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_attr.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <inttypes.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>

#define SD_BL_PATH  "/sdcard/blocklist.bin"
/* Bumped from 0xB10C1573 for the bucket-split 40-bit format. The magic MUST
 * change: a 32-bit-era file read as an image, or an image read by 32-bit-era
 * firmware, would be served as a garbage blocklist rather than rejected. Old
 * firmware now rejects a new file and new firmware rejects an old one, both
 * falling back to a download. */
#define SD_MAGIC    0xB10C2840u

/* The file is the live image verbatim: this header, then idx[65537], then the
 * 3-byte entries. That is exactly the byte layout a flash partition would hold,
 * so Wave 2 writes the same image with no further format change. The format
 * parameters are stored rather than assumed, so a future bucket/entry width is
 * detected and rejected precisely instead of needing another magic bump. */
typedef struct {
    uint32_t magic;
    uint32_t count;
    uint8_t  hash_bits;     /* BL_HASH_BITS   */
    uint8_t  bucket_bits;   /* BL_BUCKET_BITS */
    uint8_t  entry_bytes;   /* BL_ENT_BYTES   */
    uint8_t  pad;
    /* Entries dropped to capacity when this snapshot was written. Without it a
     * truncated list comes back from a warm boot looking healthy (dropped=0, no
     * banner) and serves silently incomplete until the next successful reload. */
    uint32_t dropped;
} bl_sd_header_t;

static const char *TAG = "blocklist";

/* See blocklist_sd_status() in the header for why this exists. */
static const char *s_sd_status = "unknown";
static _Atomic uint32_t s_sd_bytes = 0;
const char *blocklist_sd_status(void) { return s_sd_status; }
uint32_t    blocklist_sd_bytes(void)  { return atomic_load(&s_sd_bytes); }
#define NVS_NS  "dns_sink"
/* PSRAM buffers.
 * Not a ping-pong pair any more: the two buffers have different shapes and
 * different jobs, because a staging record (5B, the full 40-bit hash) is wider
 * than a stored entry (3B remainder — the bucket index carries the top 16 bits
 * as position, not as data). Both are allocated once at boot, never freed.
 *
 *   s_stage  BLOCKLIST_CAPACITY * BL_REC_BYTES   build scratch, sorted in place
 *   s_image  BL_IMAGE_BYTES(CAPACITY)            the live [ idx | entries ]
 *
 * docs/blocklist-format.md has the memory budget and why this beats two equal
 * buffers: a zero-copy pointer swap would need 10 * CAPACITY bytes, which caps
 * capacity below the measured 778k peak and would start dropping entries. */
static uint8_t *s_stage = NULL;
static uint8_t *s_image = NULL;

/* Atomic pointer read by dns_task (Core 1) and the L2 hook, written by
 * download_task (Core 0). NULL means every query fails open and forwards
 * upstream — set during the publish window while s_image is rewritten. */
static _Atomic(const uint8_t *) s_live = NULL;
static _Atomic uint32_t    s_count   = 0;
static _Atomic bool        s_loading = false;
/* Bumped every time a reload swaps in a new live list (#85). The forward
 * cache stamps each entry with the generation live when it was stored;
 * a lookup against a stale generation is treated as a miss instead of
 * trusting a verdict made under a blocklist that's no longer current —
 * closes the window where a domain queried while the list was still
 * loading (or under the previous one) stays wrongly cached ALLOW for up
 * to an hour after a reload that would have blocked it. */
static _Atomic uint32_t    s_blocklist_gen = 0;
static _Atomic bool        s_paused  = false;  /* global block/allow-all switch */
static _Atomic bool        s_stop_requested = false;  /* #1: mirrors upstream's xStop */

/* Any event that changes what a query SHOULD resolve to — a reload, a pause
 * flip — must call this so cached verdicts from before the change stop
 * being trusted (#85). */
static inline void blocklist_generation_bump(void)
{
    atomic_fetch_add_explicit(&s_blocklist_gen, 1, memory_order_release);
}
static _Atomic uint32_t    s_dropped = 0;   /* entries lost to capacity on last reload */
/* Extra feeds that hard-failed (404 / timeout / mid-stream death) on the last
 * reload that actually published a list. Non-zero means the live list is
 * missing whole sources — surfaced in /metrics and the UI banner, and it also
 * vetoes the SD snapshot so a degraded list can't become the warm-boot list. */
static _Atomic uint32_t    s_feed_failures = 0;

/* Mutex guarding the whitelist AND custom-rules arrays. Created first thing in
 * blocklist_init(), before any NVS loader runs, so every writer/reader below can
 * rely on it. Serializes the httpd config-writer task against the dns_task
 * reader hot path (C1). */
static SemaphoreHandle_t s_wl_mutex = NULL;

/* ── Custom blocking rules (NVS-backed, inline text blob) (#14) ── */
static char s_custom_entries[CUSTOM_RULES_MAX][64];
static uint32_t s_custom_count = 0;

/* Caller must hold s_wl_mutex. */
static void custom_parse(const char *text)
{
    s_custom_count = 0;
    const char *p = text;
    while (*p && s_custom_count < CUSTOM_RULES_MAX) {
        /* isolate one line */
        const char *line = p;
        while (*p && *p != '\n') p++;
        size_t llen = (size_t)(p - line);
        if (*p) p++;
        while (llen > 0 && (line[llen-1] == '\r' || line[llen-1] == ' ')) llen--;
        if (llen == 0 || line[0] == '#' || line[0] == '!') continue;

        /* same extractor as the URL feeds: hosts prefixes, ||anchors^,
         * digit-leading bare domains all handled in one place */
        const char *start;
        size_t len = domain_extract_token(line, llen, &start);
        if (len == 0 || len >= 64) continue;
        /* strip trailing dot */
        while (len > 0 && start[len-1] == '.') len--;
        if (len == 0) continue;
        for (size_t i = 0; i < len; i++)
            s_custom_entries[s_custom_count][i] = (char)tolower((unsigned char)start[i]);
        s_custom_entries[s_custom_count][len] = '\0';
        s_custom_count++;
    }
}

bool blocklist_custom_set(const char *text)
{
    if (!text) return false;
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) return false;
    nvs_set_str(h, "custom_blk", text);
    nvs_commit(h);
    nvs_close(h);
    xSemaphoreTake(s_wl_mutex, portMAX_DELAY);
    custom_parse(text);
    /* (#88) Custom rules are part of the verdict, so a rules edit has to
     * invalidate answers cached under the previous set rather than wait them
     * out. Bumped under the lock, so the new rules and the new generation
     * become visible to the verdict paths together. */
    blocklist_generation_bump();
    xSemaphoreGive(s_wl_mutex);
    return true;
}

size_t blocklist_custom_get(char *buf, size_t cap)
{
    if (!buf || cap == 0) return 0;
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) { buf[0]='\0'; return 0; }
    size_t len = cap;
    if (nvs_get_str(h, "custom_blk", buf, &len) != ESP_OK) buf[0]='\0', len=0;
    nvs_close(h);
    return len > 0 ? len - 1 : 0;
}

bool blocklist_custom_is_blocked(const char *domain, size_t len)
{
    if (!domain) return false;
    if (atomic_load_explicit(&s_paused, memory_order_relaxed)) return false;
    /* Bounded take: if the writer is mid-rewrite, treat as no-match and forward
     * (fail-open) rather than stall the dns_task hot path. Same contract as
     * blocklist_whitelist_contains (C1). */
    /* (#99) No rules -> no lock: this ran on every uncached query and was the
     * main source of contention against the L2 hook's zero-wait take. */
    if (s_custom_count == 0) return false;
    if (xSemaphoreTake(s_wl_mutex, pdMS_TO_TICKS(2)) != pdTRUE) return false;
    bool blocked = false;
    {
        const char *name = domain;
        while (name < domain + len) {
            size_t rlen = (size_t)((domain + len) - name);
            for (uint32_t i = 0; i < s_custom_count; i++) {
                size_t elen = strlen(s_custom_entries[i]);
                if (rlen == elen && memcmp(name, s_custom_entries[i], rlen) == 0) {
                    blocked = true;
                    break;
                }
            }
            if (blocked) break;
            const char *dot = memchr(name, '.', rlen);
            if (!dot) break;
            name = dot + 1;
        }
    }
    xSemaphoreGive(s_wl_mutex);
    return blocked;
}

static void custom_load_nvs(void)
{
    static char buf[CUSTOM_RULES_CAP + 1];
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) return;
    size_t len = sizeof(buf);
    if (nvs_get_str(h, "custom_blk", buf, &len) == ESP_OK) {
        xSemaphoreTake(s_wl_mutex, portMAX_DELAY);
        custom_parse(buf);
        xSemaphoreGive(s_wl_mutex);
    }
    nvs_close(h);
}

/* ── Extra blocklist URLs (NVS-backed, up to 4) ──────────────────── */
static char s_extra_urls[BLOCKLIST_EXTRA_MAX][BLOCKLIST_URL_CAP];

static void extra_urls_load_nvs(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) return;
    for (int i = 0; i < BLOCKLIST_EXTRA_MAX; i++) {
        char key[12]; snprintf(key, sizeof(key), "bl_url_%d", i);
        size_t len = BLOCKLIST_URL_CAP;
        if (nvs_get_str(h, key, s_extra_urls[i], &len) != ESP_OK)
            s_extra_urls[i][0] = '\0';
    }
    nvs_close(h);
}

bool blocklist_extra_url_set(int idx, const char *url)
{
    if (idx < 0 || idx >= BLOCKLIST_EXTRA_MAX || !url) return false;
    if (strlen(url) >= BLOCKLIST_URL_CAP) return false;
    snprintf(s_extra_urls[idx], BLOCKLIST_URL_CAP, "%s", url);
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) return false;
    char key[12]; snprintf(key, sizeof(key), "bl_url_%d", idx);
    nvs_set_str(h, key, url);
    nvs_commit(h);
    nvs_close(h);
    return true;
}

void blocklist_extra_url_get(int idx, char *buf, size_t cap)
{
    if (idx < 0 || idx >= BLOCKLIST_EXTRA_MAX || !buf || cap == 0) { if (buf && cap) buf[0]='\0'; return; }
    snprintf(buf, cap, "%s", s_extra_urls[idx]);
}

/* Per-slot enable flag (#48). Absent key = enabled (default), so a slot
 * nobody has ever touched behaves exactly as before this feature existed. */
bool blocklist_extra_enabled_get(int idx)
{
    if (idx < 0 || idx >= BLOCKLIST_EXTRA_MAX) return false;
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) return true;
    char key[10]; snprintf(key, sizeof(key), "bl_en_%d", idx);
    uint8_t v = 1;
    esp_err_t err = nvs_get_u8(h, key, &v);
    nvs_close(h);
    return (err != ESP_OK) || (v != 0);
}

bool blocklist_extra_enabled_set(int idx, bool enabled)
{
    if (idx < 0 || idx >= BLOCKLIST_EXTRA_MAX) return false;
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) return false;
    char key[10]; snprintf(key, sizeof(key), "bl_en_%d", idx);
    nvs_set_u8(h, key, enabled ? 1 : 0);
    nvs_commit(h);
    nvs_close(h);
    return true;
}

/* ── Whitelist (SRAM, NVS-backed) ────────────────────────────────── */
static char s_whitelist[WHITELIST_MAX][64];
static uint32_t s_wl_count = 0;
/* s_wl_mutex declared near the top (shared with custom-rules section). */
/* Sorting the 5-byte staging records.
 *
 * The algorithms and their buffer geometry live in bl_table.c so they can be
 * host-tested at a small capacity (tests/bl_table_test.c drives the tail-scratch
 * path, the near-capacity qsort fallback, and the fold's p + 2m' > cap fallback
 * against a reference sort). On the real 4-feed reload the fallback paths are
 * the ones that run, so "it works at 778k on the bench" is not coverage.
 *
 * These wrappers exist only to bind 'cap' to BLOCKLIST_CAPACITY: every caller
 * passes the base of the full staging buffer, which is the precondition the
 * tail-scratch bound rests on. */
static inline uint32_t sort_dedup_records(uint8_t *a, uint32_t n)
{
    return bl_sort_dedup(a, BLOCKLIST_CAPACITY, n);
}

static inline uint32_t fold_sorted_chunk(uint8_t *a, uint32_t p, uint32_t n)
{
    return bl_fold_sorted_chunk(a, BLOCKLIST_CAPACITY, p, n);
}

/* Download callback */
typedef struct {
    uint8_t  *buf;            /* staging records, BL_REC_BYTES each */
    uint32_t  cap;
    uint32_t  n;
    uint32_t  rejected;
    uint32_t  dropped;        /* lost to capacity (surfaced after load) */
    uint32_t  sorted_prefix;  /* buf[0..sorted_prefix) is sorted+deduped - every
                               * feed folded in so far, not just the primary;
                               * extras binary-search it, so a repeat from ANY
                               * earlier feed costs no capacity */
    uint32_t  deduped;        /* extra-list entries skipped as already present */
} load_ctx_t;

static bool on_domain_line(const char *line, size_t len, void *ctx)
{
    load_ctx_t *lc = (load_ctx_t *)ctx;

    /* #1: user-requested abort (upstream's xStop). Returning false here is
     * exactly http_fetch_lines' documented abort signal, so this reuses the
     * same failure path a dead/truncated feed already takes - "keeping
     * previous list" for the primary, feed_failures++ for an extra - rather
     * than needing a distinct stopped state threaded through blocklist_load. */
    if (atomic_load_explicit(&s_stop_requested, memory_order_relaxed)) return false;

    /* Hosts-format prefixes and adblock ||anchors^ must be peeled off, or the
     * whole raw line hashes as one junk entry: the feed then reports a healthy
     * domain count while blocking nothing (silent-corruption bug, wave 1). */
    const char *tok;
    size_t tlen = domain_extract_token(line, len, &tok);
    if (tlen == 0) { lc->rejected++; return true; }

    char norm[256];
    size_t nlen = domain_normalize(norm, sizeof(norm), tok, tlen);
    if (nlen == 0 || domain_is_bare_tld(norm, nlen)) return true;

    uint64_t h = bl_hash40(norm, nlen);
    /* Extra-list entry: binary-search everything already folded into the sorted
     * prefix so a duplicate costs no capacity. Capacity binds near the DEDUPED
     * union instead of the raw one - what makes OISD + Ultimate + TIF fit. */
    if (lc->sorted_prefix && bl_records_contain(lc->buf, lc->sorted_prefix, h)) {
        lc->deduped++;
        return true;
    }
    /* Capacity check belongs HERE, not at entry: everything above can still
     * decide this line stores nothing (junk, bare TLD, already present), and
     * counting those as drops inflated the figure severalfold - a feed of
     * comments read as thousands of "lost domains". Only a genuinely storable
     * new hash that has nowhere to go is a drop. */
    if (lc->n >= lc->cap) { lc->dropped++; return true; }  /* surfaced after load, never silent */
    bl_rec_put(lc->buf + (size_t)lc->n++ * BL_REC_BYTES, h);
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
    /* NOT nvs_erase_all(h): the "dns_sink" namespace also holds bl_url_*,
     * custom_blk and paused, all unrelated to the whitelist — erase_all wiped
     * them on every whitelist add/remove. Erase only the wl* key range instead,
     * so a shrinking list still drops its stale tail. */
    for (uint32_t i = 0; i < WHITELIST_MAX; i++) {
        char key[16]; snprintf(key, sizeof(key), "wl%" PRIu32, i);
        nvs_erase_key(h, key);
    }
    for (uint32_t i = 0; i < s_wl_count; i++) {
        char key[16]; snprintf(key, sizeof(key), "wl%" PRIu32, i);
        nvs_set_str(h, key, s_whitelist[i]);
    }
    nvs_commit(h);
    nvs_close(h);
}

/* ── NVS pause-state persistence ─────────────────────────────────── */
static void paused_load_nvs(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) return;
    uint8_t v = 0;
    if (nvs_get_u8(h, "paused", &v) == ESP_OK)
        atomic_store_explicit(&s_paused, v != 0, memory_order_relaxed);
    nvs_close(h);
}

/* ── Public API ──────────────────────────────────────────────────── */

bool blocklist_init(void)
{
    s_wl_mutex = xSemaphoreCreateMutex();
    if (!s_wl_mutex) return false;

    s_stage = (uint8_t *)heap_caps_malloc(
        (size_t)BLOCKLIST_CAPACITY * BL_REC_BYTES, MALLOC_CAP_SPIRAM);
    s_image = (uint8_t *)heap_caps_malloc(
        BL_IMAGE_BYTES(BLOCKLIST_CAPACITY), MALLOC_CAP_SPIRAM);
    if (!s_stage || !s_image) {
        ESP_LOGE(TAG, "PSRAM alloc failed: stage %" PRIu32 " B, image %" PRIu32 " B",
                 (uint32_t)((size_t)BLOCKLIST_CAPACITY * BL_REC_BYTES),
                 (uint32_t)BL_IMAGE_BYTES(BLOCKLIST_CAPACITY));
        return false;
    }
    /* An image with a zeroed index reads as empty from every bucket, so a
     * lookup landing here before the first list is published returns "not
     * blocked" rather than walking uninitialised offsets. s_live still gates
     * that, but the buffer should not depend on the gate for safety. */
    memset(s_image, 0, BL_IDX_BYTES);
    ESP_LOGI(TAG, "PSRAM: stage %" PRIu32 " KB + image %" PRIu32 " KB (cap %u entries, "
             "%d-bit hashes)",
             (uint32_t)((size_t)BLOCKLIST_CAPACITY * BL_REC_BYTES / 1024),
             (uint32_t)(BL_IMAGE_BYTES(BLOCKLIST_CAPACITY) / 1024),
             (unsigned)BLOCKLIST_CAPACITY, BL_HASH_BITS);

    extra_urls_load_nvs();
    custom_load_nvs();
    wl_load_nvs();
    paused_load_nvs();
    return true;
}

/* Reload diff (#67): exact +added/-removed vs the previous SD snapshot. The
 * old PSRAM buffer is consumed as sort scratch, but the SD file still holds
 * the previously-serving sorted list — stream it in 4KB chunks and merge-walk
 * against the new sorted array (both ascending, single pass). Runs in the
 * download_task once per reload, never on the query path. Would have caught
 * the 170k-domain stale-cache incident at first boot. */
static void reload_diff_vs_sd(const uint8_t *neu, uint32_t n_new)
{
    FILE *f = fopen(SD_BL_PATH, "rb");
    if (!f) return;                       /* no SD / first boot: nothing to diff */
    bl_sd_header_t hdr;
    if (fread(&hdr, sizeof(hdr), 1, f) != 1 || hdr.magic != SD_MAGIC || hdr.count == 0 ||
        hdr.hash_bits != BL_HASH_BITS || hdr.bucket_bits != BL_BUCKET_BITS ||
        hdr.entry_bytes != BL_ENT_BYTES) {
        fclose(f);
        return;
    }
    /* The snapshot stores remainders, not whole hashes, so the bucket has to be
     * rebuilt from the index to compare against the new records. Both sides are
     * globally ascending, so one merge-walk still does it. */
    uint32_t *idx = (uint32_t *)heap_caps_malloc(BL_IDX_BYTES, MALLOC_CAP_SPIRAM);
    uint8_t *chunk = (uint8_t *)heap_caps_malloc(1024 * BL_ENT_BYTES, MALLOC_CAP_SPIRAM);
    if (!idx || !chunk) {
        heap_caps_free(idx); heap_caps_free(chunk); fclose(f);
        return;
    }
    if (fread(idx, 1, BL_IDX_BYTES, f) != BL_IDX_BYTES) {
        heap_caps_free(idx); heap_caps_free(chunk); fclose(f);
        return;
    }
    uint32_t b = 0, k = 0, i = 0, common = 0;
    while (k < hdr.count) {
        size_t take = hdr.count - k;
        if (take > 1024) take = 1024;
        if (fread(chunk, BL_ENT_BYTES, take, f) != take) break;
        for (size_t t = 0; t < take; t++, k++) {
            while (b < BL_BUCKET_COUNT && idx[b + 1] <= k) b++;
            const uint8_t *e = chunk + t * BL_ENT_BYTES;
            uint64_t h = ((uint64_t)b << (BL_HASH_BITS - BL_BUCKET_BITS)) |
                         ((uint32_t)e[0] << 16) | ((uint32_t)e[1] << 8) | e[2];
            while (i < n_new && bl_rec_get(neu + (size_t)i * BL_REC_BYTES) < h) i++;
            if (i < n_new && bl_rec_get(neu + (size_t)i * BL_REC_BYTES) == h) { common++; i++; }
        }
    }
    heap_caps_free(idx);
    heap_caps_free(chunk);
    fclose(f);
    ESP_LOGI(TAG, "Reload diff vs previous snapshot: +%" PRIu32 " added, -%" PRIu32
             " removed (%" PRIu32 " -> %" PRIu32 ")",
             n_new - common, hdr.count - common, hdr.count, n_new);
}

uint32_t blocklist_load(void)
{
    atomic_store(&s_loading, true);
    atomic_store_explicit(&s_stop_requested, false, memory_order_relaxed);

    /* Build in the staging buffer. s_image keeps serving the whole fetch and
     * the whole sort — nothing here touches it until the publish below. */
    load_ctx_t lc = { .buf = s_stage, .cap = BLOCKLIST_CAPACITY, .n = 0, .rejected = 0 };

    /* Accumulated locally and published only where s_dropped is: until then the
     * OLD list is still the live one, and the count that describes it must not
     * be cleared by a reload that may yet bail out (a primary fetch that dies
     * returns below without publishing anything). */
    uint32_t feed_failures = 0;

    ESP_LOGI(TAG, "Downloading primary blocklist (old list stays live)...");
    bool ok = http_fetch_lines(BLOCKLIST_URL, on_domain_line, &lc);
    if (!ok || lc.n == 0) {
        ESP_LOGE(TAG, "Primary download failed or empty; keeping previous list");
        atomic_store(&s_loading, false);
        return 0;
    }
    ESP_LOGI(TAG, "Primary: %" PRIu32 " domains (%" PRIu32 " lines rejected)",
             lc.n, lc.rejected);

    bool have_extras = false;
    for (int i = 0; i < BLOCKLIST_EXTRA_MAX; i++)
        if (s_extra_urls[i][0] != '\0' && blocklist_extra_enabled_get(i)) { have_extras = true; break; }

    /* Dedup-aware extras: sort+dedup the primary IN PLACE first, using its own
     * free tail as scratch — never the other buffer, which is live and must
     * keep serving during the fetch. Extra-list entries then binary-search this
     * prefix in on_domain_line and duplicates are skipped, so capacity binds
     * near the deduped union rather than the raw one.
     * Runs in the download task (Core 0), cold path only. */
    if (have_extras) {
        uint32_t u = sort_dedup_records(lc.buf, lc.n);
        ESP_LOGI(TAG, "Primary sorted+deduped in place: %" PRIu32 " -> %" PRIu32, lc.n, u);
        lc.n = u;
        lc.sorted_prefix = u;
    }

    /* Fetch extra blocklists and append (deduped vs everything already loaded) */
    for (int i = 0; i < BLOCKLIST_EXTRA_MAX; i++) {
        if (s_extra_urls[i][0] == '\0') continue;
        if (!blocklist_extra_enabled_get(i)) {
            ESP_LOGI(TAG, "Extra list %d disabled — skipping", i);
            continue;
        }

        /* Full: every remaining feed would be downloaded, TLS-decrypted and
         * parsed only for on_domain_line to drop it. Stop and name what is
         * missing instead of burning minutes to store nothing. */
        if (lc.n >= lc.cap) {
            char skipped[32] = "";     /* indices only — BLOCKLIST_EXTRA_MAX is single-digit */
            size_t sl = 0;
            for (int j = i; j < BLOCKLIST_EXTRA_MAX && sl + 3 < sizeof(skipped); j++) {
                if (s_extra_urls[j][0] == '\0' || !blocklist_extra_enabled_get(j)) continue;
                if (sl) skipped[sl++] = ',';
                skipped[sl++] = (char)('0' + j);
                skipped[sl] = '\0';
            }
            ESP_LOGE(TAG, "Capacity full at %" PRIu32 " — extra list(s) %s NOT fetched at all; "
                     "dropped=%" PRIu32 " is a LOWER BOUND (a feed never fetched contributes "
                     "nothing to it)", lc.n, skipped, lc.dropped);
            break;
        }

        uint32_t before = lc.n, rej_before = lc.rejected;
        uint32_t dup_before = lc.deduped, drop_before = lc.dropped;
        /* #90: refuse plaintext feeds even if NVS holds one from before the
         * web UI started rejecting them — an http:// list is an on-path
         * attacker's list. Counts as a feed failure so the UI shows it. */
        if (strncasecmp(s_extra_urls[i], "https://", 8) != 0) {
            feed_failures++;
            ESP_LOGE(TAG, "Extra list %d REFUSED — not https:// (%s); this reload is DEGRADED",
                     i, s_extra_urls[i]);
            continue;
        }
        ESP_LOGI(TAG, "Downloading extra list %d: %s", i, s_extra_urls[i]);
        bool feed_ok = http_fetch_lines(s_extra_urls[i], on_domain_line, &lc);
        if (!feed_ok) {
            /* 404, TLS/DNS failure or a stream that died mid-body. Whatever
             * arrived stays (a partial feed still blocks what it named), but the
             * reload is degraded and must not be snapshotted over a good one. */
            feed_failures++;
            ESP_LOGE(TAG, "Extra list %d FAILED (%s) — kept %" PRIu32 " entries from the partial "
                     "stream; this reload is DEGRADED", i, s_extra_urls[i], lc.n - before);
        }

        /* Fold this feed into the sorted prefix so the NEXT one binary-searches
         * against it too. Without this the prefix stays at the primary and
         * extras-vs-extras overlap costs a slot each — 66,789 of them on the
         * measured 4-feed mix. Skipped when nothing was appended: the prefix
         * already covers [0,n) and a re-sort would be a full pass for nothing. */
        uint32_t appended = lc.n - before, self_dupes = 0;
        if (appended > 0) {
            uint32_t merged = fold_sorted_chunk(lc.buf, lc.sorted_prefix, lc.n);
            self_dupes = lc.n - merged;   /* only intra-feed repeats reach here —
                                           * anything the prefix held was already
                                           * caught by the binary search */
            lc.n = merged;
        }
        lc.sorted_prefix = lc.n;

        ESP_LOGI(TAG, "Extra list %d: +%" PRIu32 " new (%" PRIu32 " intra-feed dupes), %" PRIu32
                 " already present, %" PRIu32 " rejected, %" PRIu32 " dropped (full) — total %" PRIu32,
                 i, lc.n - before, self_dupes, lc.deduped - dup_before,
                 lc.rejected - rej_before, lc.dropped - drop_before, lc.n);

        /* Only a feed we actually received, that stored nothing for any reason
         * OTHER than capacity, is a format problem. At capacity every feed
         * reads as "0 new, 0 deduped", which used to fire this warning at the
         * wrong target — or, with rejects at 0, silence it entirely. */
        if (feed_ok && appended == 0 && lc.deduped == dup_before &&
            lc.dropped == drop_before && lc.rejected > rej_before)
            ESP_LOGW(TAG, "Extra list %d contributed nothing usable — wrong format?", i);
    }
    atomic_store(&s_dropped, lc.dropped);
    atomic_store(&s_feed_failures, feed_failures);
    if (feed_failures > 0)
        ESP_LOGE(TAG, "%" PRIu32 " extra feed(s) failed — the live list is missing whole sources",
                 feed_failures);
    if (lc.dropped > 0)
        ESP_LOGW(TAG, "CAPACITY EXCEEDED: %" PRIu32 " entries dropped (cap %u) — the live "
                 "list is incomplete. Remove a source or switch to smaller lists "
                 "(hagezi wildcard/ variants, not domains/).",
                 lc.dropped, (unsigned)BLOCKLIST_CAPACITY);
    /* Publish.
     *
     * The sort happened entirely in s_stage, so the old list served the whole
     * fetch AND the whole sort. What cannot be avoided is the conversion: the
     * 5-byte records have to become 3-byte entries plus a bucket index, and the
     * only buffer that can hold that result is s_image, which is live.
     *
     * So publishing goes degraded for one conversion pass (~50ms at full
     * capacity), once per reload, i.e. every 4 hours. Queries fail OPEN during
     * it — forwarded upstream and answered normally, just unfiltered.
     *
     * Be straight about this: it is a NEW cost. The 4-byte predecessor could
     * pointer-swap two equal ping-pong buffers with no window at all on its
     * common path, and only went degraded in one near-capacity corner. The
     * window is the price of the bucket index — which is also what buys 3-byte
     * entries, 40-bit hashes and ~4 probes. docs/blocklist-format.md has the
     * alternatives and why a zero-copy swap does not fit in PSRAM.
     *
     * The null + yield ahead of the conversion is the same RCU quiescence the
     * old degraded sort used (#45): a Core 1 reader that latched the pointer
     * microseconds ago must finish its bucket search before we overwrite what
     * it is reading. That search is a handful of probes inside one bucket;
     * 2ms is a thousandfold margin. */
    uint32_t unique;
    if (lc.sorted_prefix == lc.n) {
        /* Every feed was folded in as it completed: already sorted and deduped. */
        unique = lc.n;
        ESP_LOGI(TAG, "Total %" PRIu32 " domains, already sorted by the per-feed passes",
                 unique);
    } else {
        ESP_LOGI(TAG, "Total %" PRIu32 " domains before dedup; sorting on staging scratch...",
                 lc.n);
        unique = sort_dedup_records(lc.buf, lc.n);
        ESP_LOGI(TAG, "%" PRIu32 " dupes removed", lc.n - unique);
    }

    atomic_store_explicit(&s_live, NULL, memory_order_release);
    vTaskDelay(pdMS_TO_TICKS(2));
    bl_build_image(s_stage, unique, s_image);
    atomic_store_explicit(&s_count, unique, memory_order_relaxed);
    atomic_store_explicit(&s_live, s_image, memory_order_release);
    blocklist_generation_bump();  /* (#85) */

    ESP_LOGI(TAG, "Blocklist live: %" PRIu32 " domains", unique);
    atomic_store(&s_loading, false);
    reload_diff_vs_sd(s_stage, unique);   /* before the snapshot is overwritten */

    /* A snapshot from a reload with a dead feed would come back at the next warm
     * boot as the list, with no record that a source was missing. Keep the last
     * good one — a slightly stale complete list beats a fresh incomplete one.
     * (Capacity drops DO get saved: those are recorded in the header and
     * restored by blocklist_load_sd, so they stay visible.) */
    if (feed_failures == 0) {
        blocklist_save_sd();
    } else {
        ESP_LOGW(TAG, "SD snapshot SKIPPED: %" PRIu32 " feed(s) failed this reload — keeping "
                 "the previous good snapshot", feed_failures);
    }
    return unique;
}

/* Internal: binary search in sorted PSRAM array + whitelist check.
 * wl_check is either blocklist_whitelist_contains (blocking) or
 * blocklist_whitelist_contains_nb (non-blocking for L2 eth RX task). */
typedef bool (*wl_fn_t)(const char *, size_t);

/* IRAM_ATTR (#78): blocklist_is_blocked_nb() -> here is the verdict call on
 * the L2 fast path (dns_sink.cpp's l2_input_cb), which must never fault to
 * flash. domain_is_bare_tld() and the wl_check callback it invokes are NOT
 * tagged — out of this pass's scope, a real gap if full coverage matters. */
static bool IRAM_ATTR is_blocked_impl(const char *domain, size_t len, wl_fn_t wl_check)
{
    if (atomic_load_explicit(&s_paused, memory_order_relaxed)) return false;
    const uint8_t *img = atomic_load_explicit(&s_live, memory_order_acquire);
    if (!img) return false;
    if (atomic_load_explicit(&s_count, memory_order_relaxed) == 0) return false;

    const char *p = domain;
    size_t remaining = len;

    while (remaining > 0) {
        if (!domain_is_bare_tld(p, remaining)) {
            if (wl_check(p, remaining)) return false;

            /* One index read picks the bucket, then a few probes inside it —
             * against ~20 scattered probes over the whole array before. */
            if (bl_image_contains(img, bl_hash40(p, remaining))) return true;
        }
        const char *dot = (const char *)memchr(p, '.', remaining);
        if (!dot) break;
        remaining -= (size_t)(dot - p) + 1;
        p = dot + 1;
    }
    return false;
}

bool blocklist_is_blocked(const char *domain, size_t len)
{
    return is_blocked_impl(domain, len, blocklist_whitelist_contains);
}

bool blocklist_is_blocked_nb(const char *domain, size_t len)
{
    return is_blocked_impl(domain, len, blocklist_whitelist_contains_nb);
}

bool blocklist_is_paused(void)
{
    return atomic_load_explicit(&s_paused, memory_order_relaxed);
}

/* IRAM_ATTR (#78 in spirit): read from the L2/dns_task hot path's cache
 * lookup on every query (#85), so it needs the same "never touch flash"
 * treatment as the functions #78 named. */
uint32_t IRAM_ATTR blocklist_generation(void)
{
    return atomic_load_explicit(&s_blocklist_gen, memory_order_acquire);
}

void blocklist_set_paused(bool paused)
{
    atomic_store_explicit(&s_paused, paused, memory_order_relaxed);
    /* A query answered ALLOW while paused gets cached with a real TTL like
     * any other forward. Without this, that entry outlives the pause: once
     * resumed, it keeps serving ALLOW to every client (not just whoever
     * queried during the pause) until the TTL expires — the same
     * shared-cache-vs-transient-state hazard #85 fixed for blocklist
     * reloads, just triggered by a pause flip instead. Bumping on both
     * directions (not just resume) is the simpler-to-reason-about choice:
     * "the classification rules changed" covers pausing too, at the cost
     * of one avoidable-but-harmless extra re-check for a handful of
     * queries right after pausing. */
    blocklist_generation_bump();
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_u8(h, "paused", paused ? 1 : 0);
        nvs_commit(h);
        nvs_close(h);
    }
    ESP_LOGW(TAG, "Ad blocking %s", paused ? "PAUSED (all queries allowed)" : "resumed");
}

/* (#99) The NVS write happens AFTER the mutex is released. Holding it across
 * a flash commit (5-100 ms) made every whitelist edit a window in which both
 * verdict paths failed their bounded take and sinkholed whitelisted names —
 * the socket path even cached that wrong BLOCK for 10 s. Same invariant as
 * rewrite.c and blocklist_custom_set: NVS commits always outside the lock. */
bool blocklist_whitelist_add(const char *domain)
{
    if (strlen(domain) >= sizeof(s_whitelist[0])) return false;  /* #41: reject oversized */
    xSemaphoreTake(s_wl_mutex, portMAX_DELAY);
    bool ok = false;
    if (s_wl_count < WHITELIST_MAX) {
        snprintf(s_whitelist[s_wl_count], sizeof(s_whitelist[0]), "%s", domain);
        s_wl_count++;
        ok = true;
        /* (#88) A whitelist add flips the verdict for a name that may already
         * be cached as BLOCKED. Bump the generation so every entry stored under
         * the old rules re-validates, exactly as a blocklist reload does —
         * without it the un-block only took effect when the TTL ran out. */
        blocklist_generation_bump();
    }
    xSemaphoreGive(s_wl_mutex);
    if (ok) wl_save_nvs();
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
            found = true;
            blocklist_generation_bump();   /* (#88) re-block takes effect now */
            break;
        }
    }
    xSemaphoreGive(s_wl_mutex);
    if (found) wl_save_nvs();
    return found;
}

static bool wl_contains_locked(const char *domain, size_t len)
{
    for (uint32_t i = 0; i < s_wl_count; i++) {
        size_t wlen = strlen(s_whitelist[i]);
        if (wlen == len && memcmp(s_whitelist[i], domain, len) == 0)
            return true;
    }
    return false;
}

bool blocklist_whitelist_contains(const char *domain, size_t len)
{
    /* Use a bounded wait so the dns_task hot path can't stall indefinitely if
     * an NVS commit from whitelist_add is holding the mutex (same contract as
     * the _nb non-blocking variant used by the L2 eth RX task). */
    if (xSemaphoreTake(s_wl_mutex, pdMS_TO_TICKS(2)) != pdTRUE)
        return false;  /* mutex busy — treat as not whitelisted; safe fail-closed */
    bool found = wl_contains_locked(domain, len);
    xSemaphoreGive(s_wl_mutex);
    return found;
}

/* Non-blocking: used from the L2 eth RX task where portMAX_DELAY would stall
 * all Ethernet while a whitelist NVS commit is in progress (#37). */
bool blocklist_whitelist_contains_nb(const char *domain, size_t len)
{
    /* (#99) Busy -> report "whitelisted". That makes is_blocked_impl say
     * "not blocked", so the L2 hook doesn't answer and hands the frame to
     * lwIP, where the socket path re-decides with its bounded wait. The old
     * `return false` meant "not whitelisted" = BLOCK, i.e. the exact opposite
     * of the allow-through this comment always claimed. */
    if (xSemaphoreTake(s_wl_mutex, 0) != pdTRUE)
        return true;
    bool found = wl_contains_locked(domain, len);
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
    if (!f) {
        ESP_LOGI(TAG, "No SD blocklist cache (no card, or nothing written yet)");
        s_sd_status = "absent";
        return false;
    }
    if (fseek(f, 0, SEEK_END) == 0) {
        long sz = ftell(f);
        if (sz > 0) atomic_store(&s_sd_bytes, (uint32_t)sz);
        rewind(f);
    }

    bl_sd_header_t hdr;
    if (fread(&hdr, sizeof(hdr), 1, f) != 1 || hdr.magic != SD_MAGIC) {
        ESP_LOGW(TAG, "SD blocklist: bad header (pre-40-bit snapshot? it will be "
                 "replaced by the next reload)");
        s_sd_status = "bad-magic";
        fclose(f); return false;
    }
    if (hdr.hash_bits != BL_HASH_BITS || hdr.bucket_bits != BL_BUCKET_BITS ||
        hdr.entry_bytes != BL_ENT_BYTES) {
        ESP_LOGW(TAG, "SD blocklist: format mismatch (%u/%u/%u, expected %u/%u/%u)",
                 hdr.hash_bits, hdr.bucket_bits, hdr.entry_bytes,
                 BL_HASH_BITS, BL_BUCKET_BITS, BL_ENT_BYTES);
        s_sd_status = "format-mismatch";
        fclose(f); return false;
    }
    if (hdr.count == 0 || hdr.count > BLOCKLIST_CAPACITY) {
        ESP_LOGW(TAG, "SD blocklist: bad count %" PRIu32, hdr.count);
        s_sd_status = "bad-count";
        fclose(f); return false;
    }

    /* Read via a DRAM bounce buffer — same pattern as blocklist_save_sd, avoids
     * handing the SDSPI/FATFS path a single huge PSRAM-destined read. The file
     * body IS the image, so this is a straight copy with no conversion. */
    static EXT_RAM_BSS_ATTR uint8_t chunk[4096];   /* SD path only — cold */
    size_t total = BL_IMAGE_BYTES(hdr.count), done = 0;
    while (done < total) {
        size_t batch = total - done;
        if (batch > sizeof(chunk)) batch = sizeof(chunk);
        size_t r = fread(chunk, 1, batch, f);
        if (r == 0) break;
        memcpy(s_image + done, chunk, r);
        done += r;
    }
    fclose(f);
    if (done != total) {
        ESP_LOGW(TAG, "SD blocklist: short read %" PRIu32 "/%" PRIu32,
                 (uint32_t)done, (uint32_t)total);
        s_sd_status = "short-read";
        return false;
    }
    /* The bounds bl_image_contains uses come out of this file, so a partial
     * write or bit rot that leaves the header intact could hand the L2 RX hook
     * a bucket range of 0..0xFFFFFFFF and send it gigabytes past PSRAM on every
     * query — a crash loop that survives reboots, because the bad file does.
     * The old 32-bit format could not fail this way: its search bounds came
     * from a validated count, so corrupt data only ever meant a wrong verdict.
     * One 65k-comparison pass at boot buys that immunity back. */
    if (!bl_image_valid(s_image, hdr.count)) {
        ESP_LOGW(TAG, "SD blocklist: index failed validation (corrupt snapshot) — "
                 "refusing and falling back to a download");
        s_sd_status = "invalid-index";
        return false;
    }

    /* Restore the truncation state with the data, before the release-store that
     * makes the image visible: a reader that sees this list must also see how
     * incomplete it is. Without this a truncated snapshot came back from a warm
     * boot reading dropped=0 and served silently short until the next reload.
     * s_feed_failures stays 0 by construction — blocklist_load refuses to write
     * a snapshot from a reload where any feed hard-failed. */
    atomic_store_explicit(&s_count, hdr.count, memory_order_relaxed);
    atomic_store(&s_dropped, hdr.dropped);
    atomic_store_explicit(&s_live, s_image, memory_order_release);
    s_sd_status = "loaded";
    ESP_LOGI(TAG, "SD blocklist loaded: %" PRIu32 " domains (instant)", hdr.count);
    if (hdr.dropped > 0)
        ESP_LOGW(TAG, "Snapshot was TRUNCATED when written: %" PRIu32 " entries had been "
                 "dropped — this warm-boot list is INCOMPLETE until the next reload",
                 hdr.dropped);
    return true;
}

void blocklist_save_sd(void)
{
    uint32_t n = atomic_load(&s_count);
    const uint8_t *img = atomic_load_explicit(&s_live, memory_order_acquire);
    if (!img || n == 0) return;

    ESP_LOGI(TAG, "SD save: opening %s for %" PRIu32 " domains", SD_BL_PATH, n);
    FILE *f = fopen(SD_BL_PATH, "wb");
    if (!f) {
        ESP_LOGW(TAG, "SD blocklist: can't open for write (errno=%d) — no card mounted?", errno);
        s_sd_status = "open-failed";
        return;
    }

    /* Carry the drop count into the file: the image alone cannot say whether it
     * is the whole list, and the next warm boot serves this file before any
     * download runs (see blocklist_load_sd). */
    uint32_t dropped = atomic_load(&s_dropped);
    bl_sd_header_t hdr = { .magic = SD_MAGIC, .count = n,
                           .hash_bits = BL_HASH_BITS, .bucket_bits = BL_BUCKET_BITS,
                           .entry_bytes = BL_ENT_BYTES, .pad = 0, .dropped = dropped };
    fwrite(&hdr, sizeof(hdr), 1, f);

    /* Write in chunks from a small bounce buffer — avoids handing the
     * SDSPI/FATFS path a single huge PSRAM-sourced write. */
    static EXT_RAM_BSS_ATTR uint8_t chunk[4096];   /* SD path only — cold */
    size_t total = BL_IMAGE_BYTES(n), written = 0;
    while (written < total) {
        size_t batch = total - written;
        if (batch > sizeof(chunk)) batch = sizeof(chunk);
        memcpy(chunk, img + written, batch);
        size_t w = fwrite(chunk, 1, batch, f);
        if (w != batch) { ESP_LOGW(TAG, "SD write stalled at %u", (unsigned)(written + w)); break; }
        written += batch;
    }
    fflush(f);
    fclose(f);

    if (written == total) {
        s_sd_status = "saved";
        atomic_store(&s_sd_bytes, (uint32_t)(total + sizeof(hdr)));
    } else {
        s_sd_status = "short-write";
    }
    if (written == total)
        ESP_LOGI(TAG, "SD blocklist saved: %" PRIu32 " domains (%" PRIu32 " KB, %" PRIu32
                 " dropped)", n, (uint32_t)((total + sizeof(hdr)) / 1024), dropped);
    else
        ESP_LOGW(TAG, "SD blocklist: short write %" PRIu32 "/%" PRIu32,
                 (uint32_t)written, (uint32_t)total);
}

uint32_t blocklist_domain_count(void)  { return atomic_load(&s_count); }
bool     blocklist_is_loading(void)    { return atomic_load(&s_loading); }
uint32_t blocklist_dropped_count(void) { return atomic_load(&s_dropped); }
uint32_t blocklist_feed_failures(void) { return atomic_load(&s_feed_failures); }

void blocklist_stop_load(void)
{
    /* No-op if nothing is loading: without this guard, a stop that lands in
     * the narrow window between a reload being requested and download_task
     * actually starting blocklist_load() (which polls every 1s — see
     * download_task) would sit as a stale "true" that blocklist_load()'s own
     * reset-at-entry then clears right out from under it, silently. Guarding
     * on s_loading turns that race into a clean, intentional no-op — "there's
     * nothing to stop yet" — instead of a request that looks accepted but
     * quietly evaporates. */
    if (!atomic_load_explicit(&s_loading, memory_order_relaxed)) {
        ESP_LOGW(TAG, "Stop requested but nothing is loading — ignored");
        return;
    }
    atomic_store_explicit(&s_stop_requested, true, memory_order_relaxed);
    ESP_LOGW(TAG, "Blocklist load stop requested");
}
