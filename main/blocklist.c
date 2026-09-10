#include "blocklist.h"
#include "bl_table.h"
#include "bl_rank.h"
#include "domain.h"
#include "http_fetch.h"
#include "esp_heap_caps.h"
#include "esp_psram.h"
#include "esp_partition.h"
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
/* Bumped from 0xB10C2840 for feed-level exceptions (#117 stage e-ii). */
#define SD_MAGIC    0xB10C2841u

/* The file is the live image verbatim followed by the feed exception table:
 * this header, then idx[65537], then the 3-byte entries, then exc_count * 5B
 * exception records, then exc_count * 1B exception flags. */
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
    uint32_t exc_count;     /* #117: feed exceptions stored after block image */
    uint32_t exc_dropped;   /* #117: exceptions dropped when BL_EXCEPT_CAPACITY exceeded */
} bl_sd_header_t;

/* ── Flash-resident persistence (#70) ────────────────────────────────
 * Two data partitions, "bl_a"/"bl_b" (see partitions.csv / partitions_wifi.csv),
 * each holding one bl_flash_header_t followed by one complete image — the
 * same [idx|entries] bytes bl_sd_header_t's file holds, so bl_image_valid()
 * and the format-triple check are shared verbatim with the SD path. The two
 * slots exist because NOR flash has no atomic "replace this file": writing
 * always erases-then-writes the OLDER (or invalid) slot, so a power cut
 * mid-write leaves the other slot's last-known-good image intact for the
 * next boot to fall back to. */
#define BL_FLASH_MAGIC 0xB10CF1A6u  /* bumped for feed exceptions (#117 stage e-ii) */
typedef struct {
    uint32_t magic;
    uint32_t seq;           /* monotonic; the higher VALID seq wins at load */
    uint32_t count;
    uint8_t  hash_bits, bucket_bits, entry_bytes, pad;
    uint32_t dropped;
    uint32_t exc_count;     /* #117: feed exceptions stored after block image */
    uint32_t exc_dropped;   /* #117: exceptions dropped when BL_EXCEPT_CAPACITY exceeded */
} bl_flash_header_t;

static const char *TAG = "blocklist";

/* Defined near the other flash-persistence code, below; forward-declared here
 * because blocklist_load()'s publish step (well above that section) calls it. */
static void blocklist_save_flash(void);

/* See blocklist_sd_status() in the header for why this exists. */
static const char *s_sd_status = "unknown";
static _Atomic uint32_t s_sd_bytes = 0;
const char *blocklist_sd_status(void) { return s_sd_status; }
uint32_t    blocklist_sd_bytes(void)  { return atomic_load(&s_sd_bytes); }

/* Same idea as s_sd_status, for the flash slots: "unknown" (never tried),
 * "absent" (partitions not found — old binary on old partition table),
 * "empty" (both slots have an invalid/never-written header), "bad-count",
 * "invalid-index", "loaded", "saved", "too-big" (s_count exceeds what a slot
 * can hold — see capacity_for_flash), "erase-failed", "write-failed". */
static const char *s_flash_status = "unknown";
const char *blocklist_flash_status(void) { return s_flash_status; }
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
 * download_task (Core 0). Points to an immutable snapshot descriptor bundling
 * the block image and exception table (#117 stage e-ii). NULL means every query
 * fails open during the publish window — treated as BL_DEFER_SNAPSHOT by the
 * non-blocking L2 hook and unproven by the socket path. */
static _Atomic(const bl_snapshot_t *) s_live = NULL;
static _Atomic uint32_t    s_count   = 0;
static _Atomic bool        s_loading = false;

/* Ping-pong snapshot descriptors and exception buffers (#117 stage e-ii).
 * Readers walk the currently published descriptor atomically without locks.
 * Reloads/downloads build into the inactive slot and publish by a single
 * atomic store to s_live. */
static bl_snapshot_t s_snap_buf[2];
static uint8_t s_snap_idx = 0;
static uint8_t *s_exc_recs[2] = { NULL, NULL };
static uint8_t *s_exc_flags[2] = { NULL, NULL };

typedef struct __attribute__((packed)) {
    uint8_t rec[BL_REC_BYTES];
    uint8_t flag;
} bl_exc_pair_t;
static bl_exc_pair_t *s_exc_scratch = NULL;

static _Atomic uint32_t s_exc_loaded = 0;
static _Atomic uint32_t s_exc_dropped = 0;

uint32_t blocklist_exceptions_loaded(void)  { return atomic_load(&s_exc_loaded); }
uint32_t blocklist_exceptions_dropped(void) { return atomic_load(&s_exc_dropped); }

static int cmp_exc_pair(const void *a, const void *b)
{
    return memcmp(((const bl_exc_pair_t *)a)->rec,
                  ((const bl_exc_pair_t *)b)->rec,
                  BL_REC_BYTES);
}
/* Bumped every time a reload swaps in a new live list (#85). The forward
 * cache stamps each entry with the generation live when it was stored;
 * a lookup against a stale generation is treated as a miss instead of
 * trusting a verdict made under a blocklist that's no longer current —
 * closes the window where a domain queried while the list was still
 * loading (or under the previous one) stays wrongly cached ALLOW for up
 * to an hour after a reload that would have blocked it. */
static _Atomic uint32_t    s_blocklist_gen = 0;
static _Atomic bool        s_paused  = false;  /* global block/allow-all switch */

/* (#49) Live capacity. BLOCKLIST_CAPACITY is the ceiling the 8 MB boards
 * run at; a board with less PSRAM gets a smaller table sized at init from
 * what is actually fitted, rather than failing the boot-time allocation. */
static uint32_t            s_cap     = BLOCKLIST_CAPACITY;

static uint32_t capacity_for_psram(size_t psram_bytes)
{
    /* Everything else that lives in PSRAM — forward cache, TLS I/O buffers,
     * the EXT_RAM_BSS scratch pages, the hedge stash — is under 1.5 MB on the
     * 8 MB boards (measured ~1.5 MB still free there at the full cap). Below
     * that reserve the table is squeezed, never the rest: a table that fits
     * and a cache that does not is a box that reboots under load. */
    const size_t reserve = 1536u * 1024u;
    const size_t per_entry = BL_REC_BYTES + BL_ENT_BYTES;   /* stage + image */
    if (psram_bytes <= reserve + BL_IDX_BYTES) return 50000u; /* 2 MB parts: still worth running */
    size_t cap = (psram_bytes - reserve - BL_IDX_BYTES) / per_entry;
    if (cap > BLOCKLIST_CAPACITY) cap = BLOCKLIST_CAPACITY;
    if (cap < 50000u) cap = 50000u;
    return (uint32_t)cap;
}

uint32_t blocklist_capacity(void) { return s_cap; }

/* (#70) Mirrors capacity_for_psram()'s shape: how many entries a single flash
 * slot of this many bytes can hold, given the header up front. Used only as a
 * guard — blocklist_save_flash() refuses (logs, skips the write) rather than
 * ever writing past a slot, if a board's actual PSRAM-derived s_cap somehow
 * exceeds what its partitions.csv provisioned for. */
static uint32_t capacity_for_flash(size_t slot_bytes)
{
    size_t reserved = sizeof(bl_flash_header_t) + BL_IDX_BYTES + (size_t)BL_EXCEPT_CAPACITY * (BL_REC_BYTES + 1);
    if (slot_bytes <= reserved) return 0;
    size_t avail = slot_bytes - reserved;
    return (uint32_t)(avail / BL_ENT_BYTES);
}
static _Atomic bool        s_stop_requested = false;  /* #1: mirrors upstream's xStop */

/* True while blocklist_load_with_retry() is sleeping between attempts. A load
 * is still in progress from the operator's point of view even though no
 * blocklist_load() call is on the stack, so Stop has to be accepted here too —
 * see blocklist_stop_load(). */
static _Atomic bool        s_retry_pending = false;

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

/* #117 per-reason reject counts from the last reload, published from
 * load_ctx_t the same way s_dropped is — see on_domain_line(). A list
 * that's mostly regex/wildcard/modifier rules a wave-1 sinkhole can't act
 * on shows up here as such, instead of just as a smaller-than-expected
 * domain count with no explanation. */
static _Atomic uint32_t    s_rejected_regex            = 0;
static _Atomic uint32_t    s_rejected_wildcard         = 0;
static _Atomic uint32_t    s_rejected_modifier         = 0;
static _Atomic uint32_t    s_rejected_cosmetic         = 0;
static _Atomic uint32_t    s_rejected_cidr             = 0;
static _Atomic uint32_t    s_rejected_too_wide         = 0;
static _Atomic uint32_t    s_rejected_important_block  = 0;

/* Mutex guarding the whitelist AND custom-rules arrays. Created first thing in
 * blocklist_init(), before any NVS loader runs, so every writer/reader below can
 * rely on it. Serializes the httpd config-writer task against the dns_task
 * reader hot path (C1). */
static SemaphoreHandle_t s_wl_mutex = NULL;

/* ── Custom blocking rules (NVS-backed, inline text blob) (#14) ── */
static char s_custom_entries[CUSTOM_RULES_MAX][64];
/* Per-entry rank + exactness (#117), parallel to s_custom_entries: bits
 * 0-1 are the rule's rank (rule_rank(), 0..3), bit 2 is RULE_EXACT. Kept
 * as a packed byte rather than a second struct member on s_custom_entries
 * so custom_probe_locked's scan touches only what it needs. */
static uint8_t s_custom_flags[CUSTOM_RULES_MAX];
static uint32_t s_custom_count = 0;
/* Written only in custom_parse() under s_wl_mutex; read via atomic_load
 * (relaxed) by the socket-path probe builder without the lock (the walk
 * itself is what needs the lock, not this one summary byte). */
static _Atomic uint8_t s_custom_max_rank = 0;   /* max rule_rank() over every entry */

/* Caller must hold s_wl_mutex. Mirrors custom_validate() exactly — same
 * parser, same input, same line-splitting — so a text that already passed
 * validate cannot fail here; this pass only stores. */
static void custom_parse(const char *text)
{
    s_custom_count = 0;
    uint8_t max_rank = 0;
    const char *p = text;
    while (*p && s_custom_count < CUSTOM_RULES_MAX) {
        /* isolate one line */
        const char *line = p;
        while (*p && *p != '\n') p++;
        size_t llen = (size_t)(p - line);
        if (*p) p++;
        while (llen > 0 && (line[llen-1] == '\r' || line[llen-1] == ' ')) llen--;

        size_t cursor = 0;
        rule_t r;
        while (s_custom_count < CUSTOM_RULES_MAX && rule_parse_next(line, llen, &cursor, &r)) {
            if (r.kind == RULE_REJECT) continue;   /* unsupported syntax: skip, as today */
            /* custom_validate() already refused the whole text if any token
             * is >= 64 chars; defensive rather than trusting that across a
             * future edit to either function. */
            if (r.len >= sizeof(s_custom_entries[0])) continue;

            for (size_t i = 0; i < r.len; i++)
                s_custom_entries[s_custom_count][i] = (char)tolower((unsigned char)r.tok[i]);
            s_custom_entries[s_custom_count][r.len] = '\0';

            uint8_t rank  = rule_rank(r.kind, r.flags);
            uint8_t exact = (r.flags & RULE_EXACT) ? 1 : 0;
            s_custom_flags[s_custom_count] = (uint8_t)(rank | (exact << 2));
            if (rank > max_rank) max_rank = rank;

            s_custom_count++;
        }
    }
    atomic_store_explicit(&s_custom_max_rank, max_rank, memory_order_relaxed);
}

/* Side-effect-free dry run of custom_parse() over the same text: counts
 * what would be stored and refuses the whole save if it would overflow
 * CUSTOM_RULES_MAX or silently truncate an over-length entry — the #91/#92
 * defect class (a rejected edit that looked like success) applied to the
 * one remaining place it could still happen. Unsupported-syntax lines
 * (regex, wildcard, an unhandled modifier, ...) are NOT a validation
 * failure — those are skipped in the stored set exactly as today; only
 * "this text would silently lose or truncate a rule it should have kept"
 * refuses the save. Returns the rule count on success, or UINT32_MAX. */
static uint32_t custom_validate(const char *text)
{
    uint32_t count = 0;
    const char *p = text;
    while (*p) {
        const char *line = p;
        while (*p && *p != '\n') p++;
        size_t llen = (size_t)(p - line);
        if (*p) p++;
        while (llen > 0 && (line[llen-1] == '\r' || line[llen-1] == ' ')) llen--;

        size_t cursor = 0;
        rule_t r;
        while (rule_parse_next(line, llen, &cursor, &r)) {
            if (r.kind == RULE_REJECT) continue;
            if (r.len >= sizeof(s_custom_entries[0])) return UINT32_MAX;
            count++;
        }
    }
    return count > CUSTOM_RULES_MAX ? UINT32_MAX : count;
}

bool blocklist_custom_set(const char *text)
{
    if (!text) return false;
    if (custom_validate(text) == UINT32_MAX) return false;

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

/* blocklist_custom_is_blocked() is gone (#117): its bool-only contract is
 * exactly the defect this issue exists to close — a custom @@ rule cannot
 * be expressed through a boolean at all. custom_probe_locked() below is
 * its replacement, feeding the shared rank resolver rather than a second
 * standalone verdict. */

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
    return bl_sort_dedup(a, s_cap, n);
}

static inline uint32_t fold_sorted_chunk(uint8_t *a, uint32_t p, uint32_t n)
{
    return bl_fold_sorted_chunk(a, s_cap, p, n);
}

/* Download callback */
typedef struct {
    uint8_t  *buf;            /* staging records, BL_REC_BYTES each */
    uint32_t  cap;
    uint32_t  n;
    uint8_t  *exc_recs;       /* staging exception records: BL_REC_BYTES each */
    uint8_t  *exc_flags;      /* staging exception flags: 1 byte each */
    uint32_t  exc_cap;        /* BL_EXCEPT_CAPACITY */
    uint32_t  exc_n;          /* exceptions collected so far */
    uint32_t  rejected;       /* total, every reason */
    uint32_t  rejected_regex;
    uint32_t  rejected_wildcard;
    uint32_t  rejected_modifier;
    uint32_t  rejected_cosmetic;
    uint32_t  rejected_cidr;
    uint32_t  rejected_too_wide;
    uint32_t  rejected_important_block;  /* #117: $important on a feed BLOCK rule */
    uint32_t  exceptions_dropped;        /* #117: dropped if exc_n exceeds BL_EXCEPT_CAPACITY */
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

    /* #117: a line can now yield more than one rule (hosts-format multi-
     * domain), so this is a loop rather than a single extract-and-store. */
    size_t cursor = 0;
    rule_t r;
    while (rule_parse_next(line, len, &cursor, &r)) {
        /* FEED-only policy: $important can't be honoured on a block entry
         * (the 3-byte table has no spare bit), and RULE_EXACT can't either
         * (same reason) — widened to sub-inclusive, the safe over-block
         * direction, same call as the bare-domain divergence already
         * documented in domain_extract_token(). */
        rule_apply_feed_policy(&r);

        if (r.kind == RULE_REJECT) {
            lc->rejected++;
            switch (r.reject_reason) {
                case RULE_REJECT_REGEX:               lc->rejected_regex++; break;
                case RULE_REJECT_WILDCARD:            lc->rejected_wildcard++; break;
                case RULE_REJECT_MODIFIER:             lc->rejected_modifier++; break;
                case RULE_REJECT_COSMETIC:             lc->rejected_cosmetic++; break;
                case RULE_REJECT_CIDR:                 lc->rejected_cidr++; break;
                case RULE_REJECT_TOO_WIDE:             lc->rejected_too_wide++; break;
                case RULE_REJECT_IMPORTANT_BLOCK_UNSUPPORTED: lc->rejected_important_block++; break;
                default: break;   /* MALFORMED folds into the total only */
            }
            continue;
        }
        if (r.kind == RULE_ALLOW) {
            char norm[256];
            size_t nlen = domain_normalize(norm, sizeof(norm), r.tok, r.len);
            if (nlen == 0 || domain_is_bare_tld(norm, nlen)) continue;

            uint64_t h = bl_hash40(norm, nlen);
            uint8_t key[BL_REC_BYTES];
            bl_rec_put(key, h);

            /* Extra-feed entry: check if already present in this reload's staging.
             * Dedup merges flags: important = OR, exact = AND (#117). */
            bool found = false;
            for (uint32_t i = 0; i < lc->exc_n; i++) {
                if (memcmp(lc->exc_recs + (size_t)i * BL_REC_BYTES, key, BL_REC_BYTES) == 0) {
                    bool imp = (lc->exc_flags[i] & RULE_IMPORTANT) || (r.flags & RULE_IMPORTANT);
                    bool ex  = (lc->exc_flags[i] & RULE_EXACT) && (r.flags & RULE_EXACT);
                    lc->exc_flags[i] = (uint8_t)((imp ? RULE_IMPORTANT : 0) | (ex ? RULE_EXACT : 0));
                    found = true;
                    break;
                }
            }
            if (found) continue;

            if (lc->exc_n >= lc->exc_cap) {
                lc->exceptions_dropped++;
                ESP_LOGE(TAG, "Feed exception capacity exceeded (%" PRIu32 "/%" PRIu32 ") for %.*s",
                         lc->exc_n + lc->exceptions_dropped, lc->exc_cap, (int)nlen, norm);
                continue;
            }

            bl_rec_put(lc->exc_recs + (size_t)lc->exc_n * BL_REC_BYTES, h);
            lc->exc_flags[lc->exc_n] = r.flags;
            lc->exc_n++;
            continue;
        }

        char norm[256];
        size_t nlen = domain_normalize(norm, sizeof(norm), r.tok, r.len);
        if (nlen == 0 || domain_is_bare_tld(norm, nlen)) continue;

        uint64_t h = bl_hash40(norm, nlen);
        /* Extra-list entry: binary-search everything already folded into the sorted
         * prefix so a duplicate costs no capacity. Capacity binds near the DEDUPED
         * union instead of the raw one - what makes OISD + Ultimate + TIF fit. */
        if (lc->sorted_prefix && bl_records_contain(lc->buf, lc->sorted_prefix, h)) {
            lc->deduped++;
            continue;
        }
        /* Capacity check belongs HERE, not at entry: everything above can still
         * decide this line stores nothing (junk, bare TLD, already present), and
         * counting those as drops inflated the figure severalfold - a feed of
         * comments read as thousands of "lost domains". Only a genuinely storable
         * new hash that has nowhere to go is a drop. */
        if (lc->n >= lc->cap) { lc->dropped++; continue; }  /* surfaced after load, never silent */
        bl_rec_put(lc->buf + (size_t)lc->n++ * BL_REC_BYTES, h);
    }
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

    /* (#49) Size the table to the PSRAM actually fitted. esp_psram_get_size()
     * is 0 when PSRAM failed to initialise — keep the default then and let the
     * allocation below report it, rather than silently shrinking to a floor. */
    {
        size_t psram = esp_psram_get_size();
        if (psram > 0) s_cap = capacity_for_psram(psram);
        if (s_cap != BLOCKLIST_CAPACITY)
            ESP_LOGW(TAG, "PSRAM is %u KB: blocklist capacity %u entries (ceiling %u)",
                     (unsigned)(psram / 1024), (unsigned)s_cap, (unsigned)BLOCKLIST_CAPACITY);
    }
    s_stage = (uint8_t *)heap_caps_malloc(
        (size_t)s_cap * BL_REC_BYTES, MALLOC_CAP_SPIRAM);
    s_image = (uint8_t *)heap_caps_malloc(
        BL_IMAGE_BYTES(s_cap), MALLOC_CAP_SPIRAM);
    s_exc_recs[0] = (uint8_t *)heap_caps_malloc(
        (size_t)BL_EXCEPT_CAPACITY * BL_REC_BYTES, MALLOC_CAP_SPIRAM);
    s_exc_recs[1] = (uint8_t *)heap_caps_malloc(
        (size_t)BL_EXCEPT_CAPACITY * BL_REC_BYTES, MALLOC_CAP_SPIRAM);
    s_exc_flags[0] = (uint8_t *)heap_caps_malloc(
        BL_EXCEPT_CAPACITY, MALLOC_CAP_SPIRAM);
    s_exc_flags[1] = (uint8_t *)heap_caps_malloc(
        BL_EXCEPT_CAPACITY, MALLOC_CAP_SPIRAM);
    s_exc_scratch = (bl_exc_pair_t *)heap_caps_malloc(
        BL_EXCEPT_CAPACITY * sizeof(bl_exc_pair_t), MALLOC_CAP_SPIRAM);
    if (!s_stage || !s_image || !s_exc_recs[0] || !s_exc_recs[1] ||
        !s_exc_flags[0] || !s_exc_flags[1] || !s_exc_scratch) {
        ESP_LOGE(TAG, "PSRAM alloc failed: stage %" PRIu32 " B, image %" PRIu32 " B",
                 (uint32_t)((size_t)s_cap * BL_REC_BYTES),
                 (uint32_t)BL_IMAGE_BYTES(s_cap));
        return false;
    }
    memset(s_snap_buf, 0, sizeof(s_snap_buf));
    /* An image with a zeroed index reads as empty from every bucket, so a
     * lookup landing here before the first list is published returns "not
     * blocked" rather than walking uninitialised offsets. s_live still gates
     * that, but the buffer should not depend on the gate for safety. */
    memset(s_image, 0, BL_IDX_BYTES);
    ESP_LOGI(TAG, "PSRAM: stage %" PRIu32 " KB + image %" PRIu32 " KB (cap %u entries, "
             "%d-bit hashes)",
             (uint32_t)((size_t)s_cap * BL_REC_BYTES / 1024),
             (uint32_t)(BL_IMAGE_BYTES(s_cap) / 1024),
             (unsigned)s_cap, BL_HASH_BITS);

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

static bool check_stop_abort(void *ctx)
{
    (void)ctx;
    return blocklist_stop_requested();
}

uint32_t blocklist_load(void)
{
    atomic_store(&s_loading, true);
    atomic_store_explicit(&s_stop_requested, false, memory_order_relaxed);

    uint8_t next_idx = s_snap_idx ^ 1;
    /* Build in the staging buffer. s_image keeps serving the whole fetch and
     * the whole sort — nothing here touches it until the publish below. */
    load_ctx_t lc = {
        .buf = s_stage,
        .cap = s_cap,
        .n = 0,
        .exc_recs = s_exc_recs[next_idx],
        .exc_flags = s_exc_flags[next_idx],
        .exc_cap = BL_EXCEPT_CAPACITY,
        .exc_n = 0,
        .rejected = 0,
        .rejected_regex = 0,
        .rejected_wildcard = 0,
        .rejected_modifier = 0,
        .rejected_cosmetic = 0,
        .rejected_cidr = 0,
        .rejected_too_wide = 0,
        .rejected_important_block = 0,
        .exceptions_dropped = 0,
        .dropped = 0,
        .sorted_prefix = 0,
        .deduped = 0,
    };

    /* Accumulated locally and published only where s_dropped is: until then the
     * OLD list is still the live one, and the count that describes it must not
     * be cleared by a reload that may yet bail out (a primary fetch that dies
     * returns below without publishing anything). */
    uint32_t feed_failures = 0;

    ESP_LOGI(TAG, "Downloading primary blocklist (old list stays live)...");
    bool ok = http_fetch_lines_ex(BLOCKLIST_URL, on_domain_line, &lc, check_stop_abort, 30, 360);
    if (!ok || lc.n == 0) {
        ESP_LOGE(TAG, "Primary download failed or empty; keeping previous list");
        feed_failures++;
        atomic_store(&s_feed_failures, feed_failures);
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
        if (blocklist_stop_requested()) {
            /* Count every feed left, not just this one: the list about to be
             * published is missing all of them, and feed_failures is what
             * decides whether it is safe to snapshot (below) and what the UI
             * reports as degraded. */
            uint32_t skipped = 0;
            for (int j = i; j < BLOCKLIST_EXTRA_MAX; j++)
                if (s_extra_urls[j][0] != '\0' && blocklist_extra_enabled_get(j)) skipped++;
            ESP_LOGW(TAG, "Stop requested, skipping %" PRIu32 " remaining extra feed(s)", skipped);
            feed_failures += skipped;
            break;
        }
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
        bool feed_ok = http_fetch_lines_ex(s_extra_urls[i], on_domain_line, &lc, check_stop_abort, 30, 360);
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
    atomic_store(&s_rejected_regex, lc.rejected_regex);
    atomic_store(&s_rejected_wildcard, lc.rejected_wildcard);
    atomic_store(&s_rejected_modifier, lc.rejected_modifier);
    atomic_store(&s_rejected_cosmetic, lc.rejected_cosmetic);
    atomic_store(&s_rejected_cidr, lc.rejected_cidr);
    atomic_store(&s_rejected_too_wide, lc.rejected_too_wide);
    atomic_store(&s_rejected_important_block, lc.rejected_important_block);
    if (feed_failures > 0)
        ESP_LOGE(TAG, "%" PRIu32 " extra feed(s) failed — the live list is missing whole sources",
                 feed_failures);
    if (lc.dropped > 0)
        ESP_LOGW(TAG, "CAPACITY EXCEEDED: %" PRIu32 " entries dropped (cap %u) — the live "
                 "list is incomplete. Remove a source or switch to smaller lists "
                 "(hagezi wildcard/ variants, not domains/).",
                 lc.dropped, (unsigned)s_cap);
    if (lc.exceptions_dropped > 0)
        ESP_LOGE(TAG, "EXCEPTION CAPACITY EXCEEDED: %" PRIu32 " exceptions dropped (cap %u) — "
                 "affected names fail closed. Vetoing snapshot.",
                 lc.exceptions_dropped, (unsigned)lc.exc_cap);

    uint32_t exc_unique = 0;
    uint8_t feed_max_rank = 0;
    if (lc.exc_n > 0) {
        for (uint32_t i = 0; i < lc.exc_n; i++) {
            memcpy(s_exc_scratch[i].rec, s_exc_recs[next_idx] + (size_t)i * BL_REC_BYTES, BL_REC_BYTES);
            s_exc_scratch[i].flag = s_exc_flags[next_idx][i];
        }
        qsort(s_exc_scratch, lc.exc_n, sizeof(bl_exc_pair_t), cmp_exc_pair);
        for (uint32_t i = 0; i < lc.exc_n; i++) {
            memcpy(s_exc_recs[next_idx] + (size_t)i * BL_REC_BYTES, s_exc_scratch[i].rec, BL_REC_BYTES);
            s_exc_flags[next_idx][i] = s_exc_scratch[i].flag;
        }
        exc_unique = bl_dedup_exceptions(s_exc_recs[next_idx], s_exc_flags[next_idx], lc.exc_n);
        feed_max_rank = 1;
        for (uint32_t i = 0; i < exc_unique; i++) {
            if (s_exc_flags[next_idx][i] & RULE_IMPORTANT) {
                feed_max_rank = 3;
                break;
            }
        }
        ESP_LOGI(TAG, "Feed exceptions: %" PRIu32 " loaded (deduped from %" PRIu32 "), max rank %u",
                 exc_unique, lc.exc_n, (unsigned)feed_max_rank);
    }

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

    s_snap_buf[next_idx] = (bl_snapshot_t){
        .block_img = s_image,
        .block_count = unique,
        .exc_recs = s_exc_recs[next_idx],
        .exc_flags = s_exc_flags[next_idx],
        .exc_count = exc_unique,
        .feed_max_rank = feed_max_rank,
    };

    atomic_store_explicit(&s_live, NULL, memory_order_release);
    vTaskDelay(pdMS_TO_TICKS(2));
    bl_build_image(s_stage, unique, s_image);
    atomic_store_explicit(&s_count, unique, memory_order_relaxed);
    atomic_store(&s_exc_loaded, exc_unique);
    atomic_store(&s_exc_dropped, lc.exceptions_dropped);
    atomic_store_explicit(&s_live, &s_snap_buf[next_idx], memory_order_release);
    s_snap_idx = next_idx;
    blocklist_generation_bump();  /* (#85) */

    ESP_LOGI(TAG, "Blocklist live: %" PRIu32 " domains, %" PRIu32 " exceptions", unique, exc_unique);
    atomic_store(&s_loading, false);
    reload_diff_vs_sd(s_stage, unique);   /* before the snapshot is overwritten */

    /* A snapshot from a reload with a dead feed or overflowed exceptions would
     * come back at the next warm boot as the list. Keep the last good one. (#117) */
    if (feed_failures == 0 && lc.exceptions_dropped == 0) {
        blocklist_save_flash();   /* (#70) — every board; belt-and-suspenders with SD below */
        blocklist_save_sd();
    } else {
        if (feed_failures > 0)
            ESP_LOGW(TAG, "SD snapshot SKIPPED: %" PRIu32 " feed(s) failed this reload — keeping "
                     "the previous good snapshot", feed_failures);
        if (lc.exceptions_dropped > 0)
            ESP_LOGE(TAG, "SD snapshot VETOED: %" PRIu32 " exception(s) dropped to capacity — keeping "
                     "the previous good snapshot", lc.exceptions_dropped);
    }
    return unique;
}

uint32_t blocklist_load_with_retry(const int *delay_s, size_t n, const char *what)
{
    uint32_t count = blocklist_load();
    if (count > 0 || blocklist_stop_requested()) return count;

    /* Keep Stop live across the sleeps. blocklist_load() clears s_stop_requested
     * at entry, so the check after each delay — before the next attempt — is
     * what makes a stop that landed mid-sleep actually stick. */
    atomic_store_explicit(&s_retry_pending, true, memory_order_relaxed);
    for (size_t i = 0; i < n; i++) {
        if (blocklist_stop_requested()) break;
        ESP_LOGW(TAG, "%s failed — retry %u/%u in %ds",
                 what, (unsigned)(i + 1), (unsigned)n, delay_s[i]);
        vTaskDelay(pdMS_TO_TICKS(delay_s[i] * 1000));
        if (blocklist_stop_requested()) break;
        count = blocklist_load();
        if (count > 0) break;
    }
    atomic_store_explicit(&s_retry_pending, false, memory_order_relaxed);

    if (count == 0 && !blocklist_stop_requested())
        ESP_LOGE(TAG, "%s still failing after %u retries — giving up until the "
                      "next scheduled reload", what, (unsigned)n);
    return count;
}

/* is_blocked_impl() is gone (#117): it was a second, independent verdict
 * implementation next to the hand-copied ORs in dns_server.cpp/web_ui.cpp —
 * exactly the "fifth ladder" this issue exists to close. Its suffix walk
 * lives on as bl_rank_resolve()'s (bl_rank.c); blocklist_verdict{,_nb}()
 * below, defined once wl_contains_locked() is in scope, are what replace
 * it and blocklist_is_blocked{,_nb}() are now thin wrappers over those. */

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

static bool IRAM_ATTR wl_contains_locked(const char *domain, size_t len)
{
    for (uint32_t i = 0; i < s_wl_count; i++) {
        size_t wlen = strlen(s_whitelist[i]);
        if (wlen == len && memcmp(s_whitelist[i], domain, len) == 0)
            return true;
    }
    return false;
}

/* ── Rank-ordered verdict (#117) ──────────────────────────────────────
 * The shared resolver every verdict path now goes through: bl_rank.c's
 * pure suffix walk, fed the feed block table + feed exception table +
 * whitelist + custom rules as rank_source_t probes (#117 stage e-ii). */

/* Probe: feed block table. Always rank 0: a FEED block entry has no spare
 * bit for $important (see issue #117 "PSRAM budget"). */
static bool IRAM_ATTR feed_block_probe(void *ctx, const char *suffix, size_t len,
                                       uint8_t depth, uint8_t *rank_out)
{
    (void)depth;
    const uint8_t *img = (const uint8_t *)ctx;
    if (!img) return false;
    if (!bl_image_contains(img, bl_hash40(suffix, len))) return false;
    *rank_out = 0;
    return true;
}

/* Probe: feed exception table (#117 stage e-ii). Binary-searched in PSRAM;
 * returns rank 1 (ALLOW) or rank 3 (ALLOW + $important). Exact-only entries
 * (RULE_EXACT) participate only at depth 0. */
static bool IRAM_ATTR feed_exc_probe(void *ctx, const char *suffix, size_t len,
                                     uint8_t depth, uint8_t *rank_out)
{
    const bl_snapshot_t *snap = (const bl_snapshot_t *)ctx;
    if (!snap || snap->exc_count == 0) return false;
    int32_t idx = bl_records_find(snap->exc_recs, snap->exc_count, bl_hash40(suffix, len));
    if (idx < 0) return false;
    uint8_t flags = snap->exc_flags[idx];
    if (!rank_rule_applies(flags, depth)) return false;
    *rank_out = rule_rank(RULE_ALLOW, flags);
    return true;
}

/* Probe: NVS whitelist. Caller holds s_wl_mutex for the whole walk — this
 * does not take it. Always rank 1 (ALLOW), sub-inclusive. */
static bool IRAM_ATTR wl_probe_locked(void *ctx, const char *suffix, size_t len,
                                       uint8_t depth, uint8_t *rank_out)
{
    (void)ctx; (void)depth;
    if (!s_wl_count) return false;
    if (!wl_contains_locked(suffix, len)) return false;
    *rank_out = 1;
    return true;
}

/* Probe: custom rules. Caller holds s_wl_mutex for the whole walk — this
 * does not take it. s_custom_flags[i] packs rank (bits 0-1) and RULE_EXACT
 * (bit 2), set once at parse time by custom_parse(); rank_rule_applies()
 * gates an exact entry to depth 0 exactly as any other source's would. */
static bool IRAM_ATTR custom_probe_locked(void *ctx, const char *suffix, size_t len,
                                           uint8_t depth, uint8_t *rank_out)
{
    (void)ctx;
    if (!s_custom_count) return false;
    bool found = false;
    uint8_t best = 0;
    for (uint32_t i = 0; i < s_custom_count; i++) {
        size_t elen = strlen(s_custom_entries[i]);
        if (elen != len || memcmp(s_custom_entries[i], suffix, len) != 0) continue;
        uint8_t flagbyte = s_custom_flags[i];
        uint8_t exact_flag = (flagbyte & (1u << 2)) ? RULE_EXACT : 0;
        if (!rank_rule_applies(exact_flag, depth)) continue;
        uint8_t r = flagbyte & 0x3;
        if (!found || r > best) { best = r; found = true; }
    }
    if (!found) return false;
    *rank_out = best;
    return true;
}

/* Socket path: bounded ~2ms take on the small tables. A busy take or NULL
 * snapshot fails open: NO_MATCH with .unproven set, so the caller forwards
 * the query without caching the answer (#117). */
bl_verdict_t blocklist_verdict(const char *name, size_t len)
{
    bl_verdict_t v = { .state = BL_NO_MATCH, .rank = 0, .unproven = 0, .src = 0xFF, .depth = 0 };
    if (!name || len == 0) return v;
    if (atomic_load_explicit(&s_paused, memory_order_relaxed)) return v;

    const bl_snapshot_t *snap = atomic_load_explicit(&s_live, memory_order_acquire);
    if (!snap) {
        /* NULL during the ~2ms republish quiescence: query fails open and forwards
         * upstream, but record unproven = 1 rather than claiming a proven NO_MATCH (#117). */
        v.unproven = 1;
        return v;
    }

    if (xSemaphoreTake(s_wl_mutex, pdMS_TO_TICKS(2)) != pdTRUE) {
        v.unproven = 1;
        return v;   /* fail open: forward, don't cache — caller's job */
    }

    rank_source_t srcs[4];
    srcs[0] = (rank_source_t){ .probe = feed_block_probe, .ctx = (void *)snap->block_img, .max_rank = 0 };
    srcs[1] = (rank_source_t){ .probe = feed_exc_probe,   .ctx = (void *)snap,
                               .max_rank = snap->feed_max_rank };
    srcs[2] = (rank_source_t){ .probe = wl_probe_locked,  .ctx = NULL,
                               .max_rank = s_wl_count ? 1 : 0 };
    srcs[3] = (rank_source_t){ .probe = custom_probe_locked, .ctx = NULL,
                               .max_rank = atomic_load_explicit(&s_custom_max_rank, memory_order_relaxed) };

    v = bl_rank_resolve(name, len, srcs, 4);
    xSemaphoreGive(s_wl_mutex);
    return v;
}

/* L2 hook: never blocks. Returns 1 with *out filled (a proven verdict —
 * the hook may act on it); BL_DEFER_LOCK_BUSY or BL_DEFER_SNAPSHOT means
 * the hook must defer (hand the frame to lwIP) because this could not be
 * proven without stalling. */
int IRAM_ATTR blocklist_verdict_nb(const char *name, size_t len, bl_verdict_t *out)
{
    *out = (bl_verdict_t){ .state = BL_NO_MATCH, .rank = 0, .unproven = 0, .src = 0xFF, .depth = 0 };
    if (!name || len == 0) return 1;
    if (atomic_load_explicit(&s_paused, memory_order_relaxed)) return 1;

    const bl_snapshot_t *snap = atomic_load_explicit(&s_live, memory_order_acquire);
    if (!snap) return BL_DEFER_SNAPSHOT;  /* Close NULL-window gap (#117) */

    if (xSemaphoreTake(s_wl_mutex, 0) != pdTRUE) return BL_DEFER_LOCK_BUSY;

    rank_source_t srcs[4];
    srcs[0] = (rank_source_t){ .probe = feed_block_probe, .ctx = (void *)snap->block_img, .max_rank = 0 };
    srcs[1] = (rank_source_t){ .probe = feed_exc_probe,   .ctx = (void *)snap,
                               .max_rank = snap->feed_max_rank };
    srcs[2] = (rank_source_t){ .probe = wl_probe_locked,  .ctx = NULL,
                               .max_rank = s_wl_count ? 1 : 0 };
    srcs[3] = (rank_source_t){ .probe = custom_probe_locked, .ctx = NULL,
                               .max_rank = atomic_load_explicit(&s_custom_max_rank, memory_order_relaxed) };

    *out = bl_rank_resolve(name, len, srcs, 4);
    xSemaphoreGive(s_wl_mutex);

    /* Defer condition 3 (#117 §5): a reload published underneath this
     * walk. The snapshot pointer read above could be stale by the time the
     * walk finished — re-read and compare rather than trust it. */
    if (atomic_load_explicit(&s_live, memory_order_acquire) != snap) return BL_DEFER_SNAPSHOT;
    return 1;
}

/* Human-readable label for a bl_verdict_t.src (#103, #117) — POST /check
 * and the query log, reporting only, never precedence law. Indices match
 * the srcs[] construction order in blocklist_verdict{,_nb}() above
 * (feed block, feed exception, whitelist, custom). */
const char *blocklist_verdict_src_name(uint8_t src)
{
    switch (src) {
        case 0:  return "feed";
        case 1:  return "feed_exception";
        case 2:  return "whitelist";
        case 3:  return "custom";
        default: return "none";
    }
}

/* Thin wrappers (#117): blocklist_is_blocked{,_nb}() stay bool-only,
 * because pause.h and this header's own prose still name them, and a
 * second boolean implementation next to blocklist_verdict{,_nb}() would
 * be exactly the "fifth ladder" defect this issue exists to close. */
bool blocklist_is_blocked(const char *domain, size_t len)
{
    return blocklist_verdict(domain, len).state == BL_BLOCK;
}

bool blocklist_is_blocked_nb(const char *domain, size_t len)
{
    bl_verdict_t v;
    return blocklist_verdict_nb(domain, len, &v) == 1 && v.state == BL_BLOCK;
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
    if (hdr.count == 0 || hdr.count > s_cap) {
        ESP_LOGW(TAG, "SD blocklist: bad count %" PRIu32, hdr.count);
        s_sd_status = "bad-count";
        fclose(f); return false;
    }
    if (hdr.exc_count > BL_EXCEPT_CAPACITY) {
        ESP_LOGW(TAG, "SD blocklist: bad exc_count %" PRIu32, hdr.exc_count);
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
    if (done != total) {
        ESP_LOGW(TAG, "SD blocklist: short read %" PRIu32 "/%" PRIu32,
                 (uint32_t)done, (uint32_t)total);
        s_sd_status = "short-read";
        fclose(f);
        return false;
    }

    if (!bl_image_valid(s_image, hdr.count)) {
        ESP_LOGW(TAG, "SD blocklist: index failed validation (corrupt snapshot) — "
                 "refusing and falling back to a download");
        s_sd_status = "invalid-index";
        fclose(f);
        return false;
    }

    if (hdr.exc_count > 0) {
        size_t recs_bytes = (size_t)hdr.exc_count * BL_REC_BYTES;
        if (fread(s_exc_recs[0], 1, recs_bytes, f) != recs_bytes ||
            fread(s_exc_flags[0], 1, hdr.exc_count, f) != hdr.exc_count) {
            ESP_LOGW(TAG, "SD blocklist: short read on exceptions");
            s_sd_status = "short-read";
            fclose(f);
            return false;
        }
    }
    fclose(f);

    uint8_t feed_max_rank = 0;
    if (hdr.exc_count > 0) {
        feed_max_rank = 1;
        for (uint32_t i = 0; i < hdr.exc_count; i++) {
            if (s_exc_flags[0][i] & RULE_IMPORTANT) {
                feed_max_rank = 3;
                break;
            }
        }
    }

    s_snap_buf[0] = (bl_snapshot_t){
        .block_img = s_image,
        .block_count = hdr.count,
        .exc_recs = s_exc_recs[0],
        .exc_flags = s_exc_flags[0],
        .exc_count = hdr.exc_count,
        .feed_max_rank = feed_max_rank,
    };
    s_snap_idx = 0;

    atomic_store_explicit(&s_count, hdr.count, memory_order_relaxed);
    atomic_store(&s_dropped, hdr.dropped);
    atomic_store(&s_exc_loaded, hdr.exc_count);
    atomic_store(&s_exc_dropped, hdr.exc_dropped);
    atomic_store_explicit(&s_live, &s_snap_buf[0], memory_order_release);
    blocklist_generation_bump();
    s_sd_status = "loaded";
    ESP_LOGI(TAG, "SD blocklist loaded: %" PRIu32 " domains, %" PRIu32 " exceptions (instant)",
             hdr.count, hdr.exc_count);
    if (hdr.dropped > 0)
        ESP_LOGW(TAG, "Snapshot was TRUNCATED when written: %" PRIu32 " entries had been "
                 "dropped — this warm-boot list is INCOMPLETE until the next reload",
                 hdr.dropped);
    return true;
}

void blocklist_save_sd(void)
{
    const bl_snapshot_t *snap = atomic_load_explicit(&s_live, memory_order_acquire);
    if (!snap || snap->block_count == 0) return;
    uint32_t n = snap->block_count;

    ESP_LOGI(TAG, "SD save: opening %s for %" PRIu32 " domains, %" PRIu32 " exceptions",
             SD_BL_PATH, n, snap->exc_count);
    FILE *f = fopen(SD_BL_PATH, "wb");
    if (!f) {
        ESP_LOGW(TAG, "SD blocklist: can't open for write (errno=%d) — no card mounted?", errno);
        s_sd_status = "open-failed";
        return;
    }

    uint32_t dropped = atomic_load(&s_dropped);
    uint32_t exc_dropped = atomic_load(&s_exc_dropped);
    bl_sd_header_t hdr = { .magic = SD_MAGIC, .count = n,
                           .hash_bits = BL_HASH_BITS, .bucket_bits = BL_BUCKET_BITS,
                           .entry_bytes = BL_ENT_BYTES, .pad = 0, .dropped = dropped,
                           .exc_count = snap->exc_count, .exc_dropped = exc_dropped };
    fwrite(&hdr, sizeof(hdr), 1, f);

    /* Write in chunks from a small bounce buffer */
    static EXT_RAM_BSS_ATTR uint8_t chunk[4096];
    size_t total = BL_IMAGE_BYTES(n), written = 0;
    while (written < total) {
        size_t batch = total - written;
        if (batch > sizeof(chunk)) batch = sizeof(chunk);
        memcpy(chunk, snap->block_img + written, batch);
        size_t w = fwrite(chunk, 1, batch, f);
        if (w != batch) { ESP_LOGW(TAG, "SD write stalled at %u", (unsigned)(written + w)); break; }
        written += batch;
    }

    if (written == total && snap->exc_count > 0) {
        size_t recs_bytes = (size_t)snap->exc_count * BL_REC_BYTES;
        size_t w1 = fwrite(snap->exc_recs, 1, recs_bytes, f);
        size_t w2 = fwrite(snap->exc_flags, 1, snap->exc_count, f);
        if (w1 != recs_bytes || w2 != snap->exc_count) {
            ESP_LOGW(TAG, "SD write stalled on exceptions");
        }
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

/* ── Flash persistence (#70) ─────────────────────────────────────── */

static bool flash_partitions_find(const esp_partition_t **out_a, const esp_partition_t **out_b)
{
    *out_a = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, 0x40, "bl_a");
    *out_b = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, 0x40, "bl_b");
    return *out_a && *out_b;
}

/* Caller must have already checked hdr->magic == BL_FLASH_MAGIC. */
static bool flash_header_valid(const bl_flash_header_t *hdr)
{
    return hdr->hash_bits == BL_HASH_BITS && hdr->bucket_bits == BL_BUCKET_BITS &&
           hdr->entry_bytes == BL_ENT_BYTES && hdr->count > 0 && hdr->count <= s_cap &&
           hdr->exc_count <= BL_EXCEPT_CAPACITY;
}

/* Attempt to load and publish from one header-validated slot. Returns false
 * (touching s_image as scratch but never s_live) if the BODY doesn't check
 * out, so the caller can fall back to the other slot instead of giving up —
 * this is the actual power-loss guarantee, not just "trust the newer seq". */
static bool flash_try_load_slot(const esp_partition_t *pick, const bl_flash_header_t *hdr)
{
    static uint8_t chunk[4096];
    size_t total = BL_IMAGE_BYTES(hdr->count), done = 0;
    while (done < total) {
        size_t batch = total - done;
        if (batch > sizeof(chunk)) batch = sizeof(chunk);
        if (esp_partition_read(pick, sizeof(bl_flash_header_t) + done, chunk, batch) != ESP_OK)
            break;
        memcpy(s_image + done, chunk, batch);
        done += batch;
    }
    if (done != total) {
        ESP_LOGW(TAG, "flash blocklist: short read %u/%u from %s",
                 (unsigned)done, (unsigned)total, pick->label);
        s_flash_status = "short-read";
        return false;
    }

    if (!bl_image_valid(s_image, hdr->count)) {
        ESP_LOGW(TAG, "flash blocklist: index failed validation on %s — refusing", pick->label);
        s_flash_status = "invalid-index";
        return false;
    }

    if (hdr->exc_count > 0) {
        size_t recs_bytes = (size_t)hdr->exc_count * BL_REC_BYTES;
        size_t offset_recs = sizeof(bl_flash_header_t) + total;
        size_t offset_flags = offset_recs + recs_bytes;
        if (esp_partition_read(pick, offset_recs, s_exc_recs[0], recs_bytes) != ESP_OK ||
            esp_partition_read(pick, offset_flags, s_exc_flags[0], hdr->exc_count) != ESP_OK) {
            ESP_LOGW(TAG, "flash blocklist: failed reading exceptions from %s", pick->label);
            s_flash_status = "short-read";
            return false;
        }
    }

    uint8_t feed_max_rank = 0;
    if (hdr->exc_count > 0) {
        feed_max_rank = 1;
        for (uint32_t i = 0; i < hdr->exc_count; i++) {
            if (s_exc_flags[0][i] & RULE_IMPORTANT) {
                feed_max_rank = 3;
                break;
            }
        }
    }

    s_snap_buf[0] = (bl_snapshot_t){
        .block_img = s_image,
        .block_count = hdr->count,
        .exc_recs = s_exc_recs[0],
        .exc_flags = s_exc_flags[0],
        .exc_count = hdr->exc_count,
        .feed_max_rank = feed_max_rank,
    };
    s_snap_idx = 0;

    atomic_store_explicit(&s_count, hdr->count, memory_order_relaxed);
    atomic_store(&s_dropped, hdr->dropped);
    atomic_store(&s_exc_loaded, hdr->exc_count);
    atomic_store(&s_exc_dropped, hdr->exc_dropped);
    atomic_store_explicit(&s_live, &s_snap_buf[0], memory_order_release);
    blocklist_generation_bump();   /* (#85) */
    s_flash_status = "loaded";
    ESP_LOGI(TAG, "Flash blocklist loaded from %s: %" PRIu32 " domains, %" PRIu32 " exceptions (seq %" PRIu32 ", instant)",
             pick->label, hdr->count, hdr->exc_count, hdr->seq);
    if (hdr->dropped > 0)
        ESP_LOGW(TAG, "Snapshot was TRUNCATED when written: %" PRIu32 " entries had been "
                 "dropped — this warm-boot list is INCOMPLETE until the next reload",
                 hdr->dropped);
    return true;
}

bool blocklist_load_flash(void)
{
    const esp_partition_t *pa, *pb;
    if (!flash_partitions_find(&pa, &pb)) {
        ESP_LOGI(TAG, "blocklist: bl_a/bl_b partitions not found (pre-#70 partition table?)");
        s_flash_status = "absent";
        return false;
    }

    bl_flash_header_t ha, hb;
    bool a_ok = esp_partition_read(pa, 0, &ha, sizeof(ha)) == ESP_OK &&
                ha.magic == BL_FLASH_MAGIC && flash_header_valid(&ha);
    bool b_ok = esp_partition_read(pb, 0, &hb, sizeof(hb)) == ESP_OK &&
                hb.magic == BL_FLASH_MAGIC && flash_header_valid(&hb);

    if (!a_ok && !b_ok) {
        ESP_LOGI(TAG, "No valid flash blocklist slot (first boot on this partition table, "
                      "or both slots empty/stale)");
        s_flash_status = "empty";
        return false;
    }

    /* Try the higher-seq valid slot first (it's the most recently completed
     * save); if ITS body turns out torn, fall back to the other slot before
     * giving up and falling further back to SD/network. */
    bool a_first = a_ok && (!b_ok || ha.seq >= hb.seq);
    if (a_first) {
        if (flash_try_load_slot(pa, &ha)) return true;
        if (b_ok && flash_try_load_slot(pb, &hb)) return true;
    } else {
        if (flash_try_load_slot(pb, &hb)) return true;
        if (a_ok && flash_try_load_slot(pa, &ha)) return true;
    }
    return false;
}

/* Called from blocklist_load() itself, same feed_failures==0 gate as
 * blocklist_save_sd() — no public entry point, nothing external triggers this. */
static void blocklist_save_flash(void)
{
    const bl_snapshot_t *snap = atomic_load_explicit(&s_live, memory_order_acquire);
    if (!snap || snap->block_count == 0) return;
    uint32_t n = snap->block_count;

    const esp_partition_t *pa, *pb;
    if (!flash_partitions_find(&pa, &pb)) { s_flash_status = "absent"; return; }

    uint32_t slot_cap = capacity_for_flash(pa->size);
    if (n > slot_cap) {
        ESP_LOGE(TAG, "flash blocklist: %" PRIu32 " domains exceeds slot capacity %" PRIu32
                 " entries — SKIPPING flash save (partitions.csv needs a bigger bl_a/bl_b "
                 "for this board's PSRAM)", n, slot_cap);
        s_flash_status = "too-big";
        return;
    }

    bl_flash_header_t ha, hb;
    bool a_ok = esp_partition_read(pa, 0, &ha, sizeof(ha)) == ESP_OK &&
                ha.magic == BL_FLASH_MAGIC && flash_header_valid(&ha);
    bool b_ok = esp_partition_read(pb, 0, &hb, sizeof(hb)) == ESP_OK &&
                hb.magic == BL_FLASH_MAGIC && flash_header_valid(&hb);
    uint32_t next_seq = (a_ok && ha.seq > (b_ok ? hb.seq : 0)) ? ha.seq
                       : (b_ok ? hb.seq : 0);
    next_seq++;

    /* Target the slot load would NOT currently pick — the older or invalid
     * one. The slot untouched by this call is exactly what a power cut during
     * this write falls back to on the next boot. */
    const esp_partition_t *target = (a_ok && (!b_ok || ha.seq >= hb.seq)) ? pb : pa;

    uint32_t dropped = atomic_load(&s_dropped);
    uint32_t exc_dropped = atomic_load(&s_exc_dropped);
    bl_flash_header_t hdr = { .magic = BL_FLASH_MAGIC, .seq = next_seq, .count = n,
                              .hash_bits = BL_HASH_BITS, .bucket_bits = BL_BUCKET_BITS,
                              .entry_bytes = BL_ENT_BYTES, .pad = 0, .dropped = dropped,
                              .exc_count = snap->exc_count, .exc_dropped = exc_dropped };

    /* Erase-then-write is inherently non-atomic on NOR flash — that's exactly
     * why the OTHER slot, never touched by this call, is the fallback a power
     * cut here leaves behind. Erase the whole slot up front (partitions.csv
     * sizes both slots as exact multiples of the 4KB erase sector). */
    if (esp_partition_erase_range(target, 0, target->size) != ESP_OK) {
        ESP_LOGE(TAG, "flash blocklist: erase failed on %s — previous slot is still the "
                 "only valid copy", target->label);
        s_flash_status = "erase-failed";
        return;
    }
    if (esp_partition_write(target, 0, &hdr, sizeof(hdr)) != ESP_OK) {
        ESP_LOGE(TAG, "flash blocklist: header write failed on %s", target->label);
        s_flash_status = "write-failed";
        return;
    }

    /* Chunk from a small INTERNAL-RAM bounce buffer: esp_flash_write bounces a
     * PSRAM source 32 bytes at a time internally (same reason the OTA-upload
     * buffer in web_ui.cpp stays off PSRAM) — sourcing straight from s_image
     * would make this the slowest possible way to do the write. */
    static uint8_t chunk[4096];
    size_t total = BL_IMAGE_BYTES(n), written = 0;
    bool ok = true;
    while (written < total) {
        size_t batch = total - written;
        if (batch > sizeof(chunk)) batch = sizeof(chunk);
        memcpy(chunk, snap->block_img + written, batch);
        if (esp_partition_write(target, sizeof(hdr) + written, chunk, batch) != ESP_OK) {
            ok = false;
            break;
        }
        written += batch;
    }

    if (ok && snap->exc_count > 0) {
        size_t recs_bytes = (size_t)snap->exc_count * BL_REC_BYTES;
        size_t offset_recs = sizeof(bl_flash_header_t) + total;
        size_t offset_flags = offset_recs + recs_bytes;
        if (esp_partition_write(target, offset_recs, snap->exc_recs, recs_bytes) != ESP_OK ||
            esp_partition_write(target, offset_flags, snap->exc_flags, snap->exc_count) != ESP_OK) {
            ok = false;
        }
    }

    if (ok) {
        s_flash_status = "saved";
        ESP_LOGI(TAG, "Flash blocklist saved to %s: %" PRIu32 " domains, %" PRIu32 " exceptions (seq %" PRIu32 ")",
                 target->label, n, snap->exc_count, next_seq);
    } else {
        ESP_LOGW(TAG, "flash blocklist: short write to %s at %u/%u — that slot is now "
                 "suspect, the other slot remains the good copy", target->label,
                 (unsigned)written, (unsigned)total);
        s_flash_status = "write-failed";
    }
}

uint32_t blocklist_domain_count(void)  { return atomic_load(&s_count); }
bool     blocklist_is_loading(void)    { return atomic_load(&s_loading); }
uint32_t blocklist_dropped_count(void) { return atomic_load(&s_dropped); }
uint32_t blocklist_feed_failures(void) { return atomic_load(&s_feed_failures); }

uint32_t blocklist_rejected_regex(void)            { return atomic_load(&s_rejected_regex); }
uint32_t blocklist_rejected_wildcard(void)         { return atomic_load(&s_rejected_wildcard); }
uint32_t blocklist_rejected_modifier(void)         { return atomic_load(&s_rejected_modifier); }
uint32_t blocklist_rejected_cosmetic(void)         { return atomic_load(&s_rejected_cosmetic); }
uint32_t blocklist_rejected_cidr(void)             { return atomic_load(&s_rejected_cidr); }
uint32_t blocklist_rejected_too_wide(void)         { return atomic_load(&s_rejected_too_wide); }
uint32_t blocklist_rejected_important_block(void)  { return atomic_load(&s_rejected_important_block); }

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
    if (!atomic_load_explicit(&s_loading, memory_order_relaxed) &&
        !atomic_load_explicit(&s_retry_pending, memory_order_relaxed)) {
        ESP_LOGW(TAG, "Stop requested but nothing is loading — ignored");
        return;
    }
    atomic_store_explicit(&s_stop_requested, true, memory_order_relaxed);
    ESP_LOGW(TAG, "Blocklist load stop requested");
}

bool blocklist_stop_requested(void)
{
    return atomic_load_explicit(&s_stop_requested, memory_order_relaxed);
}
