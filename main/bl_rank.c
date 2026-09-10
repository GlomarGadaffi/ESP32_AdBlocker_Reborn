#include "bl_rank.h"
#include <string.h>

/* IRAM_ATTR (#117, following #78's precedent on bl_image_contains and the
 * old is_blocked_impl): this is the L2 fast-path verdict call, reached via
 * blocklist_verdict_nb()'s probe walk (stage e-i, blocklist.c). On the
 * definition only — see bl_rank.h's comment and bl_table.h's bl_hash40 for
 * why repeating it on the declaration fails under -Werror=attributes. */
bl_verdict_t IRAM_ATTR bl_rank_resolve(const char *name, size_t len,
                                        const rank_source_t *srcs, size_t nsrcs)
{
    bl_verdict_t v = { .state = BL_NO_MATCH, .rank = 0, .unproven = 0, .src = 0xFF, .depth = 0 };
    bool found = false;
    uint8_t best = 0;

    uint8_t max_rank_present = 0;
    for (size_t i = 0; i < nsrcs; i++)
        if (srcs[i].max_rank > max_rank_present) max_rank_present = srcs[i].max_rank;

    const char *p = name;
    size_t remaining = len;
    uint8_t depth = 0;

    while (remaining > 0) {
        if (!domain_is_bare_tld(p, remaining)) {
            for (size_t i = 0; i < nsrcs; i++) {
                if (found && best >= max_rank_present) goto done;
                if (found && best >= srcs[i].max_rank) continue;
                uint8_t r;
                if (srcs[i].probe(srcs[i].ctx, p, remaining, depth, &r)) {
                    if (!found || r > best) {
                        best = r;
                        found = true;
                        v.src = (uint8_t)i;
                        v.depth = depth;
                    }
                }
            }
            if (found && best >= max_rank_present) goto done;
        }
        const char *dot = (const char *)memchr(p, '.', remaining);
        if (!dot) break;
        remaining -= (size_t)(dot - p) + 1;
        p = dot + 1;
        depth++;
    }

done:
    if (!found) return v;   /* state already BL_NO_MATCH, src == 0xFF */
    v.rank = best;
    v.state = (best & 1) ? BL_ALLOW : BL_BLOCK;
    return v;
}
