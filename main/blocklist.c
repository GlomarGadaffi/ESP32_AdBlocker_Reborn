#include "blocklist.h"
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
#include <stdlib.h>
#include <stdatomic.h>
#include <inttypes.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>

#define SD_BL_PATH  "/sdcard/blocklist.bin"
#define SD_MAGIC    0xB10C1573u  /* identifies our binary format */

typedef struct {
    uint32_t magic;
    uint32_t count;
    /* [0] = entries dropped to capacity when this snapshot was written. Without
     * it a truncated list comes back from a warm boot looking healthy
     * (dropped=0, no banner) and serves silently incomplete until the next
     * successful reload. Snapshots written before this field existed read 0,
     * which is exactly the "not truncated" value — no format bump needed.
     * [1] unused. Header stays 16B: old and new files are interchangeable. */
    uint32_t reserved[2];
} bl_sd_header_t;

static const char *TAG = "blocklist";
#define NVS_NS  "dns_sink"

/* ── PSRAM ping-pong buffers ─────────────────────────────────────── */
/* Two fixed-size arrays; never freed after boot (no fragmentation). */
static uint32_t *s_buf[2];          /* s_buf[0] and s_buf[1] in PSRAM */
static int       s_active_buf = 0;  /* which buffer is currently live  */

/* Atomic pointer accessed from dns_task (Core 1) and download_task (Core 0).
 * NULL means dns_task forwards all queries upstream — only ever set during the
 * one publish path that must sort THROUGH this buffer (see blocklist_load). */
static _Atomic(uint32_t *) s_live    = NULL;
static _Atomic uint32_t    s_count   = 0;
static _Atomic bool        s_loading = false;
static _Atomic bool        s_paused  = false;  /* global block/allow-all switch */
static _Atomic bool        s_stop_requested = false;  /* #1: mirrors upstream's xStop */
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
    if (xSemaphoreTake(s_wl_mutex, pdMS_TO_TICKS(2)) != pdTRUE) return false;
    bool blocked = false;
    if (s_custom_count != 0) {
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
typedef struct {
    uint32_t *buf;
    uint32_t  cap;
    uint32_t  n;
    uint32_t  rejected;
    uint32_t  dropped;        /* lost to capacity (surfaced after load) */
    uint32_t  sorted_prefix;  /* buf[0..sorted_prefix) is sorted+deduped — every
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
     * same failure path a dead/truncated feed already takes — "keeping
     * previous list" for the primary, feed_failures++ for an extra — rather
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

    uint32_t h = domain_hash(norm, nlen);
    if (lc->sorted_prefix) {
        /* Extra-list entry: binary-search everything already folded into the
         * sorted prefix so a duplicate costs no capacity. Capacity binds near
         * the DEDUPED union instead of the raw one — what makes OISD +
         * Ultimate + TIF fit. */
        uint32_t lo = 0, hi = lc->sorted_prefix;
        while (lo < hi) {
            uint32_t mid = lo + (hi - lo) / 2;
            if      (lc->buf[mid] < h) lo = mid + 1;
            else if (lc->buf[mid] > h) hi = mid;
            else { lc->deduped++; return true; }
        }
    }
    /* Capacity check belongs HERE, not at entry: everything above can still
     * decide this line stores nothing (junk, bare TLD, already present), and
     * counting those as drops inflated the figure severalfold — a feed of
     * comments read as thousands of "lost domains". Only a genuinely storable
     * new hash that has nowhere to go is a drop. */
    if (lc->n >= lc->cap) { lc->dropped++; return true; }  /* surfaced after load, never silent */
    lc->buf[lc->n++] = h;
    return true;
}

static int cmp_u32(const void *x, const void *y)
{
    uint32_t a = *(const uint32_t *)x, b = *(const uint32_t *)y;
    return (a > b) - (a < b);
}

/* Sort a[0..n) ascending without ever touching the OTHER ping-pong buffer —
 * that one is live and must keep answering queries. radix_sort needs n words of
 * scratch, not CAPACITY: when 2n <= CAPACITY the array's own free tail
 * (a+n .. a+2n) is valid, disjoint scratch, and the 4 passes (even) land the
 * result back in a. qsort is only the fallback for n > CAPACITY/2, where no
 * tail is left — it sorts in place but pays an indirect comparator per compare
 * over PSRAM, 2-4x slower than the radix path.
 * PRECONDITION: 'a' is the base of a full BLOCKLIST_CAPACITY buffer. Passing a
 * sub-array would make the tail-scratch bound a lie and corrupt what follows. */
static void sort_hashes(uint32_t *a, uint32_t n)
{
    if (n < 2) return;
    if (n <= BLOCKLIST_CAPACITY / 2) radix_sort(a, a + n, n);
    else                             qsort(a, n, sizeof(uint32_t), cmp_u32);
}

/* Sort + drop equal neighbours in place; returns the surviving count. Equal
 * hashes are either the same domain from two feeds or a genuine hash collision
 * — both resolve to one slot, which is the whole point of the 32-bit encoding. */
static uint32_t sort_dedup(uint32_t *a, uint32_t n)
{
    sort_hashes(a, n);
    uint32_t u = 0;
    for (uint32_t i = 0; i < n; i++)
        if (u == 0 || a[i] != a[u - 1]) a[u++] = a[i];
    return u;
}

/* Fold the raw chunk a[p..n) into the sorted, deduped prefix a[0..p) and
 * return the new total. Replaces re-sorting the whole array per feed, whose
 * qsort fallback (n > CAPACITY/2) cost an indirect comparator per compare over
 * PSRAM — on the measured 4-feed mix that was two whole-array qsorts per
 * reload. Here only the m-word chunk is sorted, then merged in O(p+m').
 *
 * The chunk arrived through the prefix binary search in on_domain_line, so
 * chunk ∩ prefix = ∅; equals can only be intra-chunk and die in the chunk
 * dedup. The merge is written to tolerate an equal pair anyway (both copies
 * survive, adjacent — one wasted slot, never a corrupt order).
 *
 * A zero-scratch backward merge of ADJACENT runs is not safe: with the chunk
 * at [p, p+m'), the first write at p+m'-1 lands on the chunk's own unread
 * top. So the deduped chunk is first moved to the buffer's far end,
 * b = a+CAPACITY-m', making destination and chunk disjoint: the highest write
 * is p+m'-1 < CAPACITY-m' exactly when p + 2m' <= CAPACITY. On the prefix
 * side, while chunk elements remain w = i+j > i, so a[--w] never touches an
 * unread a[i-1]; once the chunk is exhausted the remaining prefix is already
 * in place. The one geometry that fails the gate — free space smaller than
 * the chunk, only reachable within a whisker of capacity — falls back to the
 * whole-array sort_dedup. */
static uint32_t fold_sorted_chunk(uint32_t *a, uint32_t p, uint32_t n)
{
    uint32_t m = n - p;
    if (m == 0) return p;
    if (p == 0) return sort_dedup(a, n);

    /* Sort the chunk alone: its own tail a[n..n+m) is valid radix scratch
     * whenever it fits under CAPACITY; otherwise qsort just the m words. */
    if (n + m <= BLOCKLIST_CAPACITY) radix_sort(a + p, a + n, m);
    else if (m > 1)                  qsort(a + p, m, sizeof(uint32_t), cmp_u32);

    /* Dedup the chunk in place (intra-feed repeats only). */
    uint32_t mp = 0;
    for (uint32_t i = 0; i < m; i++)
        if (mp == 0 || a[p + i] != a[p + mp - 1]) a[p + mp++] = a[p + i];

    if (p + 2u * mp > BLOCKLIST_CAPACITY)
        return sort_dedup(a, p + mp);   /* near-capacity fallback, see above */

    uint32_t *b = a + BLOCKLIST_CAPACITY - mp;
    memmove(b, a + p, (size_t)mp * sizeof(uint32_t));

    uint32_t i = p, j = mp, w = p + mp;
    while (i > 0 && j > 0)
        a[--w] = (a[i - 1] > b[j - 1]) ? a[--i] : b[--j];
    while (j > 0) a[--w] = b[--j];
    /* i > 0 remainder: already in place (w == i here). */
    return p + mp;
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
static void reload_diff_vs_sd(const uint32_t *neu, uint32_t n_new)
{
    FILE *f = fopen(SD_BL_PATH, "rb");
    if (!f) return;                       /* no SD / first boot: nothing to diff */
    bl_sd_header_t hdr;
    if (fread(&hdr, sizeof(hdr), 1, f) != 1 || hdr.magic != SD_MAGIC || hdr.count == 0) {
        fclose(f);
        return;
    }
    uint32_t *chunk = (uint32_t *)heap_caps_malloc(4096, MALLOC_CAP_SPIRAM);
    if (!chunk) { fclose(f); return; }
    uint32_t remaining = hdr.count, i = 0, common = 0;
    while (remaining > 0) {
        size_t take = remaining > 1024 ? 1024 : remaining;
        if (fread(chunk, sizeof(uint32_t), take, f) != take) break;
        for (size_t k = 0; k < take; k++) {
            uint32_t h = chunk[k];
            while (i < n_new && neu[i] < h) i++;
            if (i < n_new && neu[i] == h) { common++; i++; }
        }
        remaining -= (uint32_t)take;
    }
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

    /* Point to the buffer NOT currently live. Download into it while the
     * OLD list keeps serving — no null-blocking window during the fetch. */
    int new_buf = 1 - s_active_buf;
    load_ctx_t lc = { .buf = s_buf[new_buf], .cap = BLOCKLIST_CAPACITY, .n = 0, .rejected = 0 };

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
        uint32_t u = sort_dedup(lc.buf, lc.n);
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
    /* Which publish path is legal turns on ONE question: was the new buffer
     * sorted THROUGH the live buffer? If it never was, the old array is intact,
     * no reader can observe a torn read of it, and the degraded window buys
     * nothing — the release-store alone orders every write to the new buffer
     * ahead of the pointer the reader acquires.
     * (A Core 1 reader that latched the old pointer microseconds earlier can
     * pair it with the new count. Both counts are <= CAPACITY and both buffers
     * are CAPACITY-sized and permanently allocated, so the worst case is one
     * query answered against a stale tail — bounded, never an OOB read. That
     * race predates this change; the null window never closed it either.) */
    uint32_t unique;
    if (lc.sorted_prefix == lc.n) {
        /* Every feed was folded in as it completed: already sorted and deduped. */
        unique = lc.n;
        ESP_LOGI(TAG, "Total %" PRIu32 " domains, already sorted by the per-feed passes "
                 "— publishing with no degraded window", unique);
    } else if (lc.n <= BLOCKLIST_CAPACITY / 2) {
        /* No extras configured, but the array's own free tail is scratch enough
         * for radix — still no reason to touch the live buffer. */
        ESP_LOGI(TAG, "Total %" PRIu32 " domains before dedup; sorting on tail scratch "
                 "(no degraded window)...", lc.n);
        unique = sort_dedup(lc.buf, lc.n);
        ESP_LOGI(TAG, "%" PRIu32 " dupes removed", lc.n - unique);
    } else {
        /* Over half of capacity with no sorted prefix: the only scratch large
         * enough IS the live buffer, so we must drop to degraded mode for the
         * ~1-2s sort (not the whole fetch). After nulling s_live, yield for 2ms
         * so any Core 1 reader that already latched the old arr pointer
         * completes its binary search before we overwrite that buffer
         * (#45 — RCU quiescence window). */
        ESP_LOGI(TAG, "Total %" PRIu32 " domains before dedup; sorting via the live buffer "
                 "(degraded window)...", lc.n);
        atomic_store_explicit(&s_live, NULL, memory_order_release);
        vTaskDelay(pdMS_TO_TICKS(2));
        uint32_t *a = s_buf[new_buf];
        uint32_t *b = s_buf[s_active_buf];  /* scratch during sort; live ptr is NULL */
        radix_sort(a, b, lc.n);

        /* Remove duplicates (hash collisions from different domains) */
        unique = 0;
        for (uint32_t i = 0; i < lc.n; i++) {
            if (unique == 0 || a[i] != a[unique - 1])
                a[unique++] = a[i];
        }
    }

    /* Atomic swap: publish new array */
    atomic_store_explicit(&s_count, unique, memory_order_relaxed);
    s_active_buf = new_buf;
    atomic_store_explicit(&s_live, s_buf[new_buf], memory_order_release);

    ESP_LOGI(TAG, "Blocklist live: %" PRIu32 " domains", unique);
    atomic_store(&s_loading, false);
    reload_diff_vs_sd(s_buf[new_buf], unique);   /* before the snapshot is overwritten */

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
    uint32_t *arr = atomic_load_explicit(&s_live, memory_order_acquire);
    if (!arr) return false;
    uint32_t n = atomic_load_explicit(&s_count, memory_order_relaxed);
    if (n == 0) return false;

    const char *p = domain;
    size_t remaining = len;

    while (remaining > 0) {
        if (!domain_is_bare_tld(p, remaining)) {
            if (wl_check(p, remaining)) return false;

            uint32_t h = domain_hash(p, remaining);
            uint32_t lo = 0, hi = n;
            while (lo < hi) {
                uint32_t mid = lo + (hi - lo) / 2;
                if (arr[mid] < h)       lo = mid + 1;
                else if (arr[mid] > h)  hi = mid;
                else                    return true;
            }
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

void blocklist_set_paused(bool paused)
{
    atomic_store_explicit(&s_paused, paused, memory_order_relaxed);
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_u8(h, "paused", paused ? 1 : 0);
        nvs_commit(h);
        nvs_close(h);
    }
    ESP_LOGW(TAG, "Ad blocking %s", paused ? "PAUSED (all queries allowed)" : "resumed");
}

bool blocklist_whitelist_add(const char *domain)
{
    if (strlen(domain) >= sizeof(s_whitelist[0])) return false;  /* #41: reject oversized */
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
    if (xSemaphoreTake(s_wl_mutex, 0) != pdTRUE)
        return false;  /* mutex busy — allow-through to avoid stalling eth RX */
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

    /* Read via DRAM bounce buffer — same pattern as blocklist_save_sd, avoids
     * handing the SDSPI/FATFS path a single huge PSRAM-sourced read. */
    static uint32_t chunk[1024];
    uint32_t *dst = s_buf[s_active_buf];
    size_t remaining = hdr.count, total_read = 0;
    while (remaining > 0) {
        size_t batch = remaining < 1024 ? remaining : 1024;
        size_t r = fread(chunk, sizeof(uint32_t), batch, f);
        if (r == 0) break;
        memcpy(dst + total_read, chunk, r * sizeof(uint32_t));
        total_read += r; remaining -= r;
    }
    fclose(f);
    if (total_read != hdr.count) {
        ESP_LOGW(TAG, "SD blocklist: short read %" PRIu32 "/%" PRIu32,
                 (uint32_t)total_read, hdr.count);
        return false;
    }

    /* Restore the truncation state with the data, before the release-store that
     * makes the array visible: a reader that sees this list must also see how
     * incomplete it is. Without this a truncated snapshot came back from a warm
     * boot reading dropped=0 and served silently short until the next reload.
     * s_feed_failures stays 0 by construction — blocklist_load refuses to write
     * a snapshot from a reload where any feed hard-failed. */
    atomic_store_explicit(&s_count, hdr.count, memory_order_relaxed);
    atomic_store(&s_dropped, hdr.reserved[0]);
    atomic_store_explicit(&s_live, s_buf[s_active_buf], memory_order_release);
    ESP_LOGI(TAG, "SD blocklist loaded: %" PRIu32 " domains (instant)", hdr.count);
    if (hdr.reserved[0] > 0)
        ESP_LOGW(TAG, "Snapshot was TRUNCATED when written: %" PRIu32 " entries had been "
                 "dropped — this warm-boot list is INCOMPLETE until the next reload",
                 hdr.reserved[0]);
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

    /* Carry the drop count into the file: the array alone cannot say whether it
     * is the whole list, and the next warm boot serves this file before any
     * download runs (see blocklist_load_sd). */
    uint32_t dropped = atomic_load(&s_dropped);
    bl_sd_header_t hdr = { .magic = SD_MAGIC, .count = n, .reserved = {dropped, 0} };
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
        ESP_LOGI(TAG, "SD blocklist saved: %" PRIu32 " domains (%" PRIu32 " KB, %" PRIu32
                 " dropped)", n, (uint32_t)((n * 4 + 16) / 1024), dropped);
    else
        ESP_LOGW(TAG, "SD blocklist: short write %" PRIu32 "/%" PRIu32, (uint32_t)written, n);
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
