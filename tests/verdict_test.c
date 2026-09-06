/*
 * Host tests for the rank-ordered verdict resolver (main/bl_rank.c), #117.
 *
 * Build + run:
 *   gcc -O2 -I main -o verdict_test tests/verdict_test.c main/bl_rank.c main/domain.c && ./verdict_test
 *
 * Rows are transcribed from issue #117's "Tests" section (verdict_test.c
 * table): single-source sanity, every cross-source row, and the
 * exact-scoping rows. Sources here are synthetic (name, rank, flags)
 * tables with a tiny linear-scan probe — bl_rank_resolve doesn't know or
 * care that the real feed block/exception tables, custom rules, and
 * whitelist are the concrete sources; that wiring is stage (e)'s job.
 *
 * Explicitly OUT OF SCOPE for this file (per issue #117, deferred to (e)):
 *   - global pause (a caller-side short-circuit in blocklist.c, before
 *     bl_rank_resolve is ever called — not something the resolver itself
 *     can express)
 *   - the exception-table flag-merge dedup (a bl_table.c concern, belongs
 *     in tests/bl_table_test.c)
 *   - the rewrite/CNAME ladder ordering (dns_server.cpp) and the overflow
 *     rows (blocklist.c) — both need real stateful tables this pure
 *     resolver doesn't have.
 */
#include "bl_rank.h"
#include <stdio.h>
#include <string.h>

static int g_fail = 0;
#define CHECK(cond, ...) do { if (!(cond)) { \
    printf("  FAIL: "); printf(__VA_ARGS__); printf("\n"); g_fail++; } } while (0)

typedef struct {
    const char *domain;
    uint8_t     rank;
    uint8_t     flags;   /* 0 or RULE_EXACT */
} synth_entry_t;

typedef struct {
    const synth_entry_t *entries;
    size_t                count;
    uint32_t              probe_calls;
} synth_ctx_t;

static bool synth_probe(void *vctx, const char *suffix, size_t len, uint8_t depth, uint8_t *rank_out)
{
    synth_ctx_t *ctx = (synth_ctx_t *)vctx;
    ctx->probe_calls++;
    bool found = false;
    uint8_t best = 0;
    for (size_t i = 0; i < ctx->count; i++) {
        const synth_entry_t *e = &ctx->entries[i];
        size_t elen = strlen(e->domain);
        if (elen != len || memcmp(e->domain, suffix, len) != 0) continue;
        if (!rank_rule_applies(e->flags, depth)) continue;
        if (!found || e->rank > best) { best = e->rank; found = true; }
    }
    if (!found) return false;
    *rank_out = best;
    return true;
}

static rank_source_t mk_src(synth_ctx_t *ctx, uint8_t max_rank)
{
    rank_source_t s = { .probe = synth_probe, .ctx = ctx, .max_rank = max_rank };
    return s;
}

static const char *state_name(uint8_t s)
{
    switch (s) {
        case BL_NO_MATCH: return "NO_MATCH";
        case BL_ALLOW:     return "ALLOW";
        case BL_BLOCK:     return "BLOCK";
        default:           return "?";
    }
}

static void expect_state(const char *label, bl_verdict_t v, uint8_t expect)
{
    CHECK(v.state == expect, "%s: expected %s, got %s (rank=%d)",
          label, state_name(expect), state_name(v.state), v.rank);
}

/* ── 1. single-source sanity ──────────────────────────────────────── */
static void test_single_source(void)
{
    printf("single-source sanity\n");

    /* feed BLOCK example.com -> a.example.com BLOCKED */
    {
        synth_entry_t feed_e[] = { { "example.com", 0, 0 } };
        synth_ctx_t feed = { feed_e, 1, 0 };
        rank_source_t srcs[] = { mk_src(&feed, 0) };
        bl_verdict_t v = bl_rank_resolve("a.example.com", strlen("a.example.com"), srcs, 1, 0);
        expect_state("feed BLOCK example.com -> a.example.com", v, BL_BLOCK);
    }

    /* feed EXCEPTION @@||a.example.com^ + feed BLOCK example.com
     *   -> b.example.com BLOCKED, x.a.example.com ALLOWED */
    {
        synth_entry_t block_e[] = { { "example.com", 0, 0 } };
        synth_entry_t exc_e[]   = { { "a.example.com", 1, 0 } };
        synth_ctx_t block = { block_e, 1, 0 }, exc = { exc_e, 1, 0 };
        rank_source_t srcs[] = { mk_src(&block, 0), mk_src(&exc, 1) };
        uint8_t maxp = 1;

        bl_verdict_t v1 = bl_rank_resolve("b.example.com", strlen("b.example.com"), srcs, 2, maxp);
        expect_state("feed exception a.example.com, block example.com -> b.example.com", v1, BL_BLOCK);

        bl_verdict_t v2 = bl_rank_resolve("x.a.example.com", strlen("x.a.example.com"), srcs, 2, maxp);
        expect_state("feed exception a.example.com, block example.com -> x.a.example.com", v2, BL_ALLOW);
    }
}

/* ── 2. cross-source — none of these pass under a plain boolean OR ──── */
static void test_cross_source(void)
{
    printf("cross-source (the point of this issue)\n");

    /* feed BLOCK example.com + custom @@||example.com^ -> ALLOWED */
    {
        synth_entry_t feed_e[]   = { { "example.com", 0, 0 } };
        synth_entry_t custom_e[] = { { "example.com", 1, 0 } };
        synth_ctx_t feed = { feed_e, 1, 0 }, custom = { custom_e, 1, 0 };
        rank_source_t srcs[] = { mk_src(&feed, 0), mk_src(&custom, 3) };
        bl_verdict_t v = bl_rank_resolve("example.com", strlen("example.com"), srcs, 2, 3);
        expect_state("feed BLOCK + custom @@||", v, BL_ALLOW);
    }

    /* feed BLOCK example.com + custom @@||example.com^$important -> ALLOWED */
    {
        synth_entry_t feed_e[]   = { { "example.com", 0, 0 } };
        synth_entry_t custom_e[] = { { "example.com", 3, 0 } };
        synth_ctx_t feed = { feed_e, 1, 0 }, custom = { custom_e, 1, 0 };
        rank_source_t srcs[] = { mk_src(&feed, 0), mk_src(&custom, 3) };
        bl_verdict_t v = bl_rank_resolve("example.com", strlen("example.com"), srcs, 2, 3);
        expect_state("feed BLOCK + custom @@||...$important", v, BL_ALLOW);
    }

    /* feed BLOCK example.com + custom ||example.com^$important -> BLOCKED */
    {
        synth_entry_t feed_e[]   = { { "example.com", 0, 0 } };
        synth_entry_t custom_e[] = { { "example.com", 2, 0 } };
        synth_ctx_t feed = { feed_e, 1, 0 }, custom = { custom_e, 1, 0 };
        rank_source_t srcs[] = { mk_src(&feed, 0), mk_src(&custom, 3) };
        bl_verdict_t v = bl_rank_resolve("example.com", strlen("example.com"), srcs, 2, 3);
        expect_state("feed BLOCK + custom ||...$important", v, BL_BLOCK);
    }

    /* feed EXCEPTION @@||example.com^ + custom ||example.com^$important -> BLOCKED */
    {
        synth_entry_t exc_e[]    = { { "example.com", 1, 0 } };
        synth_entry_t custom_e[] = { { "example.com", 2, 0 } };
        synth_ctx_t exc = { exc_e, 1, 0 }, custom = { custom_e, 1, 0 };
        rank_source_t srcs[] = { mk_src(&exc, 3), mk_src(&custom, 3) };
        bl_verdict_t v = bl_rank_resolve("example.com", strlen("example.com"), srcs, 2, 3);
        expect_state("feed EXCEPTION + custom ||...$important", v, BL_BLOCK);
    }

    /* feed EXCEPTION @@||example.com^$important + custom ||example.com^$important
     *   -> ALLOWED (rank 3 > 2) */
    {
        synth_entry_t exc_e[]    = { { "example.com", 3, 0 } };
        synth_entry_t custom_e[] = { { "example.com", 2, 0 } };
        synth_ctx_t exc = { exc_e, 1, 0 }, custom = { custom_e, 1, 0 };
        rank_source_t srcs[] = { mk_src(&exc, 3), mk_src(&custom, 3) };
        bl_verdict_t v = bl_rank_resolve("example.com", strlen("example.com"), srcs, 2, 3);
        expect_state("feed EXCEPTION $important + custom ||...$important", v, BL_ALLOW);
        CHECK(v.rank == 3, "expected rank 3 to win, got %d", v.rank);
    }

    /* custom @@||example.com^ + custom ||ads.example.com^
     *   -> ads.example.com ALLOWED (rank 1 > 0, depth loses) */
    {
        synth_entry_t custom_e[] = {
            { "example.com", 1, 0 },
            { "ads.example.com", 0, 0 },
        };
        synth_ctx_t custom = { custom_e, 2, 0 };
        rank_source_t srcs[] = { mk_src(&custom, 3) };
        bl_verdict_t v = bl_rank_resolve("ads.example.com", strlen("ads.example.com"), srcs, 1, 3);
        expect_state("custom @@|| + custom || deeper block -> rank beats depth", v, BL_ALLOW);
    }

    /* custom @@||example.com^ + custom ||ads.example.com^$important
     *   -> ads.example.com BLOCKED */
    {
        synth_entry_t custom_e[] = {
            { "example.com", 1, 0 },
            { "ads.example.com", 2, 0 },
        };
        synth_ctx_t custom = { custom_e, 2, 0 };
        rank_source_t srcs[] = { mk_src(&custom, 3) };
        bl_verdict_t v = bl_rank_resolve("ads.example.com", strlen("ads.example.com"), srcs, 1, 3);
        expect_state("custom @@|| + custom ||...$important deeper -> important wins", v, BL_BLOCK);
    }

    /* whitelist example.com + feed BLOCK ads.example.com
     *   -> ads.example.com ALLOWED  *** BEHAVIOUR CHANGE *** */
    {
        synth_entry_t wl_e[]   = { { "example.com", 1, 0 } };
        synth_entry_t feed_e[] = { { "ads.example.com", 0, 0 } };
        synth_ctx_t wl = { wl_e, 1, 0 }, feed = { feed_e, 1, 0 };
        rank_source_t srcs[] = { mk_src(&feed, 0), mk_src(&wl, 1) };
        bl_verdict_t v = bl_rank_resolve("ads.example.com", strlen("ads.example.com"), srcs, 2, 1);
        expect_state("whitelist example.com + feed BLOCK ads.example.com (behaviour change)", v, BL_ALLOW);
    }

    /* whitelist example.com + custom ||ads.example.com^$important
     *   -> ads.example.com BLOCKED (the escape hatch) */
    {
        synth_entry_t wl_e[]     = { { "example.com", 1, 0 } };
        synth_entry_t custom_e[] = { { "ads.example.com", 2, 0 } };
        synth_ctx_t wl = { wl_e, 1, 0 }, custom = { custom_e, 1, 0 };
        rank_source_t srcs[] = { mk_src(&wl, 1), mk_src(&custom, 3) };
        bl_verdict_t v = bl_rank_resolve("ads.example.com", strlen("ads.example.com"), srcs, 2, 3);
        expect_state("whitelist example.com + custom escape hatch $important", v, BL_BLOCK);
    }
}

/* ── 3. exact-scoping: RULE_EXACT participates only at depth 0 ──────── */
static void test_exact_scoping(void)
{
    printf("exact-match scoping\n");

    /* feed BLOCK example.com + custom @@example.com
     *   -> example.com ALLOWED, a.example.com BLOCKED */
    {
        synth_entry_t feed_e[]   = { { "example.com", 0, 0 } };
        synth_entry_t custom_e[] = { { "example.com", 1, RULE_EXACT } };
        synth_ctx_t feed = { feed_e, 1, 0 }, custom = { custom_e, 1, 0 };
        rank_source_t srcs[] = { mk_src(&feed, 0), mk_src(&custom, 3) };

        bl_verdict_t v1 = bl_rank_resolve("example.com", strlen("example.com"), srcs, 2, 3);
        expect_state("feed BLOCK + custom @@example.com (exact) -> example.com", v1, BL_ALLOW);

        bl_verdict_t v2 = bl_rank_resolve("a.example.com", strlen("a.example.com"), srcs, 2, 3);
        expect_state("feed BLOCK + custom @@example.com (exact) -> a.example.com", v2, BL_BLOCK);
    }

    /* feed BLOCK example.com + custom @@||example.com^ -> a.example.com ALLOWED */
    {
        synth_entry_t feed_e[]   = { { "example.com", 0, 0 } };
        synth_entry_t custom_e[] = { { "example.com", 1, 0 } };   /* sub-inclusive, not exact */
        synth_ctx_t feed = { feed_e, 1, 0 }, custom = { custom_e, 1, 0 };
        rank_source_t srcs[] = { mk_src(&feed, 0), mk_src(&custom, 3) };
        bl_verdict_t v = bl_rank_resolve("a.example.com", strlen("a.example.com"), srcs, 2, 3);
        expect_state("feed BLOCK + custom @@||example.com^ (sub) -> a.example.com", v, BL_ALLOW);
    }

    /* custom |ads.example.com^ (exact BLOCK)
     *   -> ads.example.com BLOCKED, x.ads.example.com NOT blocked by this rule */
    {
        synth_entry_t custom_e[] = { { "ads.example.com", 0, RULE_EXACT } };
        synth_ctx_t custom = { custom_e, 1, 0 };
        rank_source_t srcs[] = { mk_src(&custom, 3) };

        bl_verdict_t v1 = bl_rank_resolve("ads.example.com", strlen("ads.example.com"), srcs, 1, 3);
        expect_state("custom |ads.example.com^ (exact) -> ads.example.com", v1, BL_BLOCK);

        bl_verdict_t v2 = bl_rank_resolve("x.ads.example.com", strlen("x.ads.example.com"), srcs, 1, 3);
        expect_state("custom |ads.example.com^ (exact) -> x.ads.example.com not matched by this rule", v2, BL_NO_MATCH);
    }
}

/* ── 4. walk-cost bounds (issue #117 "Walk cost", bounds 1-3) ───────── */
static void test_walk_cost(void)
{
    printf("walk-cost bounds\n");

    /* Default configuration: single feed source, hit at depth 0 -> exactly
     * one probe. This is the "byte-for-byte today's cost" claim. */
    {
        synth_entry_t feed_e[] = { { "example.com", 0, 0 } };
        synth_ctx_t feed = { feed_e, 1, 0 };
        rank_source_t srcs[] = { mk_src(&feed, 0) };
        bl_verdict_t v = bl_rank_resolve("example.com", strlen("example.com"), srcs, 1, 0);
        expect_state("feed-only depth-0 hit", v, BL_BLOCK);
        CHECK(feed.probe_calls == 1, "expected exactly 1 probe, got %u", feed.probe_calls);
    }

    /* Feed hits at depth 0; an empty whitelist keeps getting probed at
     * every remaining non-bare-TLD level (it might still match there),
     * but the feed table itself is never probed again once it has already
     * produced the best rank it is capable of (bound 3). */
    {
        synth_entry_t feed_e[] = { { "a.example.com", 0, 0 } };
        synth_ctx_t feed = { feed_e, 1, 0 };
        synth_ctx_t wl   = { NULL, 0, 0 };   /* empty: never matches */
        rank_source_t srcs[] = { mk_src(&feed, 0), mk_src(&wl, 1) };
        bl_verdict_t v = bl_rank_resolve("a.example.com", strlen("a.example.com"), srcs, 2, 1);
        expect_state("feed depth-0 hit, empty whitelist walks on", v, BL_BLOCK);
        CHECK(feed.probe_calls == 1, "feed: expected exactly 1 probe (bound 3), got %u", feed.probe_calls);
        /* two non-bare-TLD suffixes in "a.example.com": itself, and "example.com" */
        CHECK(wl.probe_calls == 2, "whitelist: expected 2 probes (one per remaining level), got %u", wl.probe_calls);
    }
}

int main(void)
{
    printf("verdict (rank resolver) host tests\n\n");
    test_single_source();
    test_cross_source();
    test_exact_scoping();
    test_walk_cost();
    printf("\n%s (%d failure%s)\n", g_fail ? "FAILED" : "PASSED", g_fail, g_fail == 1 ? "" : "s");
    return g_fail != 0;
}
