#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* OISD big list URL (domainswild2 format) */
#define BLOCKLIST_URL  "https://big.oisd.nl/domainswild2"

/* Capacity must hold the DEDUPED union of every source: each feed is folded
 * into the sorted prefix as it finishes, so a domain carried by any two feeds
 * costs one slot regardless of which feeds or what order.
 * Sized against hagezi's wildcard/ variants (Pro ~226k, Ultimate ~269k,
 * tif.medium ~326k as of 2026-08) — never the domains/ versions. Two separate
 * things are easy to conflate here:
 *   - FORMAT: wildcard/ vs domains/ is the same coverage in fewer entries. Our
 *     suffix-walk matching resolves a wildcard parent, so one entry replaces
 *     every child the domains/ file enumerates. Lossless, purely cheaper.
 *   - TIER: tif.medium is hagezi's deliberately REDUCED threat-intel tier, a
 *     subset — not full TIF in a cheaper encoding. Full wildcard/tif.txt is
 *     ~2.1M entries and cannot fit here at any encoding.
 * OISD big (~266k measured) + AdGuard + Ultimate + tif.medium peaked at 778,569
 * deduped (2026-08-26) — the raw union (~1.04M) would not fit at all. 820k
 * restores real margin over that measured peak; the extra 320KB came out of a
 * measured 1.45MB psram_free, leaving ~1.1MB for mbedTLS (which allocs its TLS
 * buffers from PSRAM since 2e03f2d).
 * Overflow is counted and surfaced via blocklist_dropped_count(), not silent,
 * and once full the remaining feeds are skipped instead of downloaded to be
 * discarded — so dropped is then a lower bound on what is missing.
 * Cost: 2 ping-pong buffers x CAPACITY x 4B in PSRAM (820k -> 6.56MB of ~8MB). */
#define BLOCKLIST_CAPACITY  820000u

/* NVS whitelist — domains that always bypass blocklist (up to 64) */
#define WHITELIST_MAX  64

/*
 * Allocate the two ping-pong PSRAM buffers at boot.
 * Must be called once before any other blocklist function.
 * Returns false if PSRAM allocation fails.
 */
bool blocklist_init(void);

/*
 * Download BLOCKLIST_URL plus every configured extra into the inactive buffer,
 * sort it, then atomically swap it live.
 * The old list serves for the whole fetch. The live pointer only goes NULL
 * (graceful degradation, ~1-2s) when the sort has no scratch but the live
 * buffer — i.e. no extras configured AND more than CAPACITY/2 entries.
 * Safe to call from a background task (Core 0).
 * Returns number of domains loaded, or 0 on failure.
 */
uint32_t blocklist_load(void);

/*
 * Check if domain (already normalized, NUL-terminated) is blocked.
 * Walks all suffix components up to the bare TLD.
 * Returns true if blocked (exact or wildcard parent match).
 * Returns false during a reload's degraded window (live pointer == NULL).
 */
bool blocklist_is_blocked(const char *domain, size_t len);
/* Non-blocking variant for the L2 eth RX task (#37 — see blocklist_whitelist_contains_nb). */
bool blocklist_is_blocked_nb(const char *domain, size_t len);

/* Whitelist management (stored in NVS, survives reboot) */
bool blocklist_whitelist_add(const char *domain);
bool blocklist_whitelist_remove(const char *domain);
bool blocklist_whitelist_contains(const char *domain, size_t len);
/* Non-blocking variant for the L2 RX hook: returns false (allow-through) if
 * the mutex is held rather than stalling the Ethernet receive path (#37). */
bool blocklist_whitelist_contains_nb(const char *domain, size_t len);
uint32_t blocklist_whitelist_count(void);
void blocklist_whitelist_get(char out[][64], uint32_t *count_inout);

/* SD card persistence — call after blocklist_init(), before download_task */
bool     blocklist_load_sd(void);   /* returns true if loaded from /sdcard/blocklist.bin */
void     blocklist_save_sd(void);   /* write sorted array to SD after successful download */

/* Extra blocklist URLs (up to 4, NVS-backed; idx 0-3; empty string = disabled).
 * Merged with BLOCKLIST_URL on each blocklist_load() call. (#4, #9) */
#define BLOCKLIST_EXTRA_MAX  4
#define BLOCKLIST_URL_CAP    256
bool blocklist_extra_url_set(int idx, const char *url);   /* "" to clear */
void blocklist_extra_url_get(int idx, char *buf, size_t cap);

/* Per-slot enable/disable (#48): keeps the URL on a disabled source instead of
 * clearing it, so it can be re-enabled later without retyping. Default true
 * (enabled) for any slot with no stored preference — existing configured URLs
 * stay active with no migration. Takes effect on the next reload. */
bool blocklist_extra_enabled_get(int idx);
bool blocklist_extra_enabled_set(int idx, bool enabled);

/* Custom block rules — domains entered inline in the UI (#14).
 * Newline/space-separated list, stored in NVS as a single blob (max 4000 chars).
 * Supports plain domain names and hosts-file format ("0.0.0.0 domain").
 * Comments (#) are stripped. Applied as an overlay on top of the main blocklist. */
#define CUSTOM_RULES_MAX  256    /* max parsed entries */
#define CUSTOM_RULES_CAP  4000   /* max raw text bytes */
bool   blocklist_custom_set(const char *text);      /* save text, re-parse */
size_t blocklist_custom_get(char *buf, size_t cap); /* retrieve raw text */
bool   blocklist_custom_is_blocked(const char *domain, size_t len);

/* Global pause switch — mirrors upstream ESP32_AdBlocker's "Enable AdBlocker"
 * toggle. While paused, blocklist_is_blocked()/_nb() and
 * blocklist_custom_is_blocked() all return false (every query resolves
 * ALLOWED); whitelist, custom rules, and ACL data are untouched, only the
 * verdict is short-circuited, in the shared verdict path so the L2 hook and
 * the socket path can't diverge. NVS-persisted, survives reboot. */
void blocklist_set_paused(bool paused);
bool blocklist_is_paused(void);

/* Abort an in-progress blocklist download/reload (#1, mirrors upstream's
 * xStop). No-op (logged, not silently dropped) if nothing is loading yet —
 * see blocklist_stop_load()'s own comment for why that guard exists. The
 * current fetch's callback returns false on its next line, which
 * blocklist_load() already treats like a dead feed: "keeping previous list"
 * for the primary, feed_failures++ for an extra — the old list keeps serving
 * either way. */
void blocklist_stop_load(void);

/* Stats */
uint32_t blocklist_domain_count(void);
bool     blocklist_is_loading(void);
/* Entries discarded on the last reload because the union of all sources
 * exceeded BLOCKLIST_CAPACITY. Non-zero means the live list is INCOMPLETE, and
 * it is a LOWER bound: feeds skipped entirely once full are not counted here.
 * Persisted in the SD snapshot, so a truncated warm-boot list stays flagged. */
uint32_t blocklist_dropped_count(void);
/* Extra feeds that hard-failed (404 / TLS / timeout / stream died mid-body) on
 * the last reload that published a list. Non-zero means the live list is
 * missing whole sources — and that reload's SD snapshot was deliberately not
 * written, so the cached list on disk is the last complete one. */
uint32_t blocklist_feed_failures(void);

#ifdef __cplusplus
}
#endif
