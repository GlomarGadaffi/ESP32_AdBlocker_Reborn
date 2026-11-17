#pragma once
/*
 * The verdict ladder, pure (#117): the four rank sources (feed block table,
 * feed exception table, NVS whitelist, custom rules) and the walk over them.
 *
 * No ESP-IDF, FreeRTOS, NVS or locking in here, on purpose, same reasoning
 * as bl_rank.h and bl_table.h: it is built and tested on the host.
 * blocklist.c owns everything stateful — the pause flag, the live snapshot
 * pointer, s_wl_mutex and how long to wait for it — and hands this file a
 * bl_view_t describing the tables as they are right now. The blocking and
 * the non-blocking entry points both resolve through bl_verdict_resolve();
 * they differ only in how they obtain the view (and so in how they report a
 * missing one), never in what they decide.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "bl_rank.h"
#include "bl_table.h"

/*
 * Live blocklist snapshot descriptor (#117 stage e-ii).
 * Bundles the block image and exception table into one immutable descriptor
 * swapped by a single atomic store, guaranteeing that the block image and
 * exception table published to readers always come from the exact same reload.
 */
typedef struct {
    const uint8_t *block_img;      /* [ idx | 3-byte entries ] */
    uint32_t       block_count;
    const uint8_t *exc_recs;       /* sorted 5-byte records (BL_REC_BYTES each) */
    const uint8_t *exc_flags;      /* parallel flag bytes (RULE_IMPORTANT, RULE_EXACT) */
    uint32_t       exc_count;
    uint8_t        feed_max_rank;  /* 0 if no exceptions loaded, else max rank (1 or 3) */
} bl_snapshot_t;

/* Width of one whitelist / custom-rule entry, NUL-terminated within it. */
#define BL_ENTRY_BYTES  64u

/* blocklist_verdict_nb()'s two "must defer" outcomes, distinguished so the
 * caller can count each separately (dns_sink.cpp's l2_defer_lock_busy /
 * l2_defer_snapshot). Both negative — a caller that only needs "must I
 * defer" can just test the return value `< 0`. */
#define BL_DEFER_LOCK_BUSY  (-1)   /* the zero-wait small-table take failed */
#define BL_DEFER_SNAPSHOT   (-2)   /* a reload published underneath the walk */

/*
 * Everything one verdict reads, captured by the caller under whatever lock
 * it holds. Pointers are borrowed for the duration of the call. A NULL
 * snap means "no live snapshot" (the republish quiescence window).
 * custom_flags[i] packs rank (bits 0-1) and RULE_EXACT (bit 2), exactly as
 * custom_parse() stores it. Counts of 0 make the pointers irrelevant.
 */
typedef struct {
    const bl_snapshot_t *snap;
    const char         (*wl)[BL_ENTRY_BYTES];
    uint32_t             wl_count;
    const char         (*custom)[BL_ENTRY_BYTES];
    const uint8_t       *custom_flags;
    uint32_t             custom_count;
    uint8_t              custom_max_rank;
} bl_view_t;

/* The one ladder. Requires view != NULL && view->snap != NULL. A NULL or
 * empty name yields a proven NO_MATCH. Source indices in .src: 0 feed,
 * 1 feed exception, 2 whitelist, 3 custom. */
bl_verdict_t bl_verdict_resolve(const bl_view_t *view, const char *name, size_t len);

/* Blocking-path flavour: a NULL view->snap fails open as NO_MATCH with
 * .unproven set (forward, do not cache). */
bl_verdict_t bl_verdict_socket(const bl_view_t *view, const char *name, size_t len);

/* Non-blocking flavour: returns 1 with *out filled, or BL_DEFER_SNAPSHOT
 * when view->snap is NULL. *out is always written. */
int bl_verdict_nb(const bl_view_t *view, const char *name, size_t len, bl_verdict_t *out);

#ifdef __cplusplus
}
#endif
