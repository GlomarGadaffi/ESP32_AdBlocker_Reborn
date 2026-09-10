#pragma once
/*
 * Rank-ordered verdict resolver — pure algorithmic core (#117).
 *
 * No ESP-IDF, FreeRTOS, NVS or locking in here, on purpose, same reasoning
 * as bl_table.h: this is the part with the precedence bugs, so it is built
 * and tested on the host. blocklist.c owns everything stateful — which
 * concrete tables exist, taking s_wl_mutex, the pause short-circuit,
 * unproven/fail-open on a busy mutex — and wires them to this file as an
 * array of rank_source_t probes.
 *
 * The ordering this resolves (see issue #117 "Precedence"):
 *   rank = (important << 1) | exception,   0..3
 *   rank & 1 tells ALLOW (odd) from BLOCK (even); higher rank always wins,
 *   regardless of which source or how deep the matching suffix was.
 * RULE_EXACT is the one thing rank does NOT capture: an exact rule (a bare
 * "@@example.com", "|example.com^", or a custom/exception entry written as
 * either) only ever participates when the walk is looking at the full
 * queried name — depth 0 — never at a parent suffix.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include "domain.h"   /* RULE_BLOCK/RULE_ALLOW, RULE_EXACT/RULE_IMPORTANT, IRAM_ATTR shim */

/*
 * One source's answer for one suffix at one depth. Returns true and fills
 * *rank_out with the BEST applicable rank this source can produce for
 * exactly this suffix — "applicable" meaning the source has already
 * applied rank_rule_applies() itself (an exact-only entry must not answer
 * for depth > 0). Returns false if this source has nothing that applies
 * at this suffix/depth. Must not block on the socket path beyond whatever
 * bounded wait the caller's own contract allows, and must never block at
 * all when used on the L2 path — that discipline lives in the concrete
 * probe blocklist.c hands in, not here.
 */
typedef bool (*rank_probe_fn)(void *ctx, const char *suffix, size_t len,
                               uint8_t depth, uint8_t *rank_out);

typedef struct {
    rank_probe_fn probe;
    void         *ctx;
    uint8_t       max_rank;   /* highest rank this source can ever produce —
                                * 0 for the feed block table (no spare bit),
                                * 1 for the whitelist (exception only), etc.
                                * Lets the walk stop re-probing a source that
                                * already gave its best possible answer. */
} rank_source_t;

typedef enum { BL_NO_MATCH = 0, BL_ALLOW = 1, BL_BLOCK = 2 } bl_state_t;

typedef struct {
    uint8_t state;     /* bl_state_t */
    uint8_t rank;       /* 0..3; meaningful only when state != BL_NO_MATCH.
                         * state == (rank & 1) ? BL_ALLOW : BL_BLOCK always —
                         * callers should treat state as the authoritative
                         * field and rank as the reporting detail behind it. */
    uint8_t unproven;   /* always 0 here. A caller whose own probe had to
                         * fail-open on a busy lock ORs this in itself after
                         * the call — seeing it requires knowing WHICH probe
                         * timed out, which this resolver does not track. */
    uint8_t src;        /* index into the srcs[] array of the winning
                         * source, or UINT8_MAX if state == BL_NO_MATCH.
                         * Reporting only (POST /check, query log) — never
                         * precedence law. */
    uint8_t depth;      /* suffix depth of the winning match. Reporting only. */
} bl_verdict_t;

/* An entry with RULE_EXACT participates only at depth 0 — the full queried
 * name — never at a parent suffix. Every probe must apply this itself
 * before answering; the resolver does not see per-entry flags, only the
 * rank a probe already decided is admissible. */
static inline bool rank_rule_applies(uint8_t flags, uint8_t depth)
{
    return !(flags & RULE_EXACT) || depth == 0;
}

/* rank = (important << 1) | exception. A rule's kind and flags map onto it
 * directly: rule_apply_feed_policy() has already downgraded any FEED block
 * that can't honour $important to REJECT before this is ever called on it. */
static inline uint8_t rule_rank(uint8_t kind, uint8_t flags)
{
    return (uint8_t)(((flags & RULE_IMPORTANT) ? 2 : 0) | (kind == RULE_ALLOW ? 1 : 0));
}

/*
 * Walk suffixes of name[0..len), longest first, skipping the bare TLD at
 * every level (same invariant as domain_is_bare_tld() everywhere else in
 * this codebase — a TLD is never a match, for any source). At each level,
 * consult every source in srcs[0..nsrcs) and keep the highest rank seen.
 *
 * The best-possible rank across every source is derived HERE, from
 * max(srcs[i].max_rank) — never taken as a caller-supplied parameter.
 * That used to be an argument, and it was a footgun: pass a stale or
 * merely-wrong 0 for a source that can actually produce 1 (say, "the
 * whitelist happens to be empty right now" computed once and cached), and
 * the walk stops at a shallower BLOCK before ever reaching a deeper ALLOW
 * that source could have produced — a silently wrong verdict, in the
 * ALLOW-suppressing direction. A caller expressing "this source is
 * currently empty" does so by constructing that source's rank_source_t
 * with max_rank == 0 for this call (or simply omitting an empty source
 * from srcs[] entirely) — never by touching the resolver's stopping
 * bound directly.
 *
 * Stops early once the derived best-possible rank has been reached; also
 * skips re-probing an individual source once it has already given the
 * best rank it is capable of (srcs[i].max_rank). In the default
 * configuration — no feed exceptions, empty whitelist (max_rank == 0),
 * no custom allow rules — the walk is byte-for-byte the cost
 * blocklist_is_blocked() is today: one probe per suffix level, stopping
 * at the first hit.
 * IRAM_ATTR is on the DEFINITION in bl_rank.c only, never here (same rule,
 * same reason, as bl_table.h's bl_hash40): this is the L2 fast-path target
 * once (e) wires blocklist.c's _nb probes through it. Every probe passed
 * in must itself be safe for whichever path calls this — that contract
 * lives with the caller.
 */
bl_verdict_t bl_rank_resolve(const char *name, size_t len,
                              const rank_source_t *srcs, size_t nsrcs);

#ifdef __cplusplus
}
#endif
