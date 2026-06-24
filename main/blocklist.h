#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* OISD big list URL (domainswild2 format) */
#define BLOCKLIST_URL  "https://big.oisd.nl/domainswild2"

/* Capacity: slightly above 489,537 with headroom for list growth */
#define BLOCKLIST_CAPACITY  520000u

/* NVS whitelist — domains that always bypass blocklist (up to 64) */
#define WHITELIST_MAX  64

/*
 * Allocate the two ping-pong PSRAM buffers at boot.
 * Must be called once before any other blocklist function.
 * Returns false if PSRAM allocation fails.
 */
bool blocklist_init(void);

/*
 * Download and load the blocklist from BLOCKLIST_URL into the inactive buffer,
 * sort it, then atomically swap it live.
 * During the download g_blocklist is set to NULL (graceful degradation).
 * Safe to call from a background task (Core 0).
 * Returns number of domains loaded, or 0 on failure.
 */
uint32_t blocklist_load(void);

/*
 * Check if domain (already normalized, NUL-terminated) is blocked.
 * Walks all suffix components up to the bare TLD.
 * Returns true if blocked (exact or wildcard parent match).
 * Returns false during reload window (g_blocklist == NULL).
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

/* Stats */
uint32_t blocklist_domain_count(void);
bool     blocklist_is_loading(void);

#ifdef __cplusplus
}
#endif
