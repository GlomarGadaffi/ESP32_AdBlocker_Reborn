#include "bl_verdict.h"
#include <string.h>

/* IRAM_ATTR on definitions only (same rule as bl_rank.c): the probes and
 * bl_verdict_resolve() are reached from the L2 RX hook. */

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

/* Probe: whitelist. Always rank 1 (ALLOW), sub-inclusive. */
static bool IRAM_ATTR wl_probe(void *ctx, const char *suffix, size_t len,
                               uint8_t depth, uint8_t *rank_out)
{
    (void)depth;
    const bl_view_t *view = (const bl_view_t *)ctx;
    if (!view->wl_count) return false;
    for (uint32_t i = 0; i < view->wl_count; i++) {
        size_t wlen = strlen(view->wl[i]);
        if (wlen == len && memcmp(view->wl[i], suffix, len) == 0) {
            *rank_out = 1;
            return true;
        }
    }
    return false;
}

/* Probe: custom rules. custom_flags[i] packs rank (bits 0-1) and RULE_EXACT
 * (bit 2); rank_rule_applies() gates an exact entry to depth 0 exactly as
 * any other source's would. */
static bool IRAM_ATTR custom_probe(void *ctx, const char *suffix, size_t len,
                                   uint8_t depth, uint8_t *rank_out)
{
    const bl_view_t *view = (const bl_view_t *)ctx;
    if (!view->custom_count) return false;
    bool found = false;
    uint8_t best = 0;
    for (uint32_t i = 0; i < view->custom_count; i++) {
        size_t elen = strlen(view->custom[i]);
        if (elen != len || memcmp(view->custom[i], suffix, len) != 0) continue;
        uint8_t flagbyte = view->custom_flags[i];
        uint8_t exact_flag = (flagbyte & (1u << 2)) ? RULE_EXACT : 0;
        if (!rank_rule_applies(exact_flag, depth)) continue;
        uint8_t r = flagbyte & 0x3;
        if (!found || r > best) { best = r; found = true; }
    }
    if (!found) return false;
    *rank_out = best;
    return true;
}

bl_verdict_t IRAM_ATTR bl_verdict_resolve(const bl_view_t *view, const char *name, size_t len)
{
    bl_verdict_t v = { .state = BL_NO_MATCH, .rank = 0, .unproven = 0, .src = 0xFF, .depth = 0 };
    if (!view || !view->snap || !name || len == 0) return v;

    rank_source_t srcs[4];
    srcs[0] = (rank_source_t){ .probe = feed_block_probe, .ctx = (void *)view->snap->block_img, .max_rank = 0 };
    srcs[1] = (rank_source_t){ .probe = feed_exc_probe,   .ctx = (void *)view->snap,
                               .max_rank = view->snap->feed_max_rank };
    srcs[2] = (rank_source_t){ .probe = wl_probe,         .ctx = (void *)view,
                               .max_rank = view->wl_count ? 1 : 0 };
    srcs[3] = (rank_source_t){ .probe = custom_probe,     .ctx = (void *)view,
                               .max_rank = view->custom_max_rank };
    return bl_rank_resolve(name, len, srcs, 4);
}

bl_verdict_t IRAM_ATTR bl_verdict_socket(const bl_view_t *view, const char *name, size_t len)
{
    bl_verdict_t v = { .state = BL_NO_MATCH, .rank = 0, .unproven = 0, .src = 0xFF, .depth = 0 };
    if (!name || len == 0) return v;
    if (!view || !view->snap) {
        /* NULL during the ~2ms republish quiescence: query fails open and forwards
         * upstream, but record unproven = 1 rather than claiming a proven NO_MATCH (#117). */
        v.unproven = 1;
        return v;
    }
    return bl_verdict_resolve(view, name, len);
}

int IRAM_ATTR bl_verdict_nb(const bl_view_t *view, const char *name, size_t len, bl_verdict_t *out)
{
    *out = (bl_verdict_t){ .state = BL_NO_MATCH, .rank = 0, .unproven = 0, .src = 0xFF, .depth = 0 };
    if (!name || len == 0) return 1;
    if (!view || !view->snap) return BL_DEFER_SNAPSHOT;  /* Close NULL-window gap (#117) */
    *out = bl_verdict_resolve(view, name, len);
    return 1;
}
