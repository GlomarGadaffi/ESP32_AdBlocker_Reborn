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
#include "blocklist.h"
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
    if (!ctx) return false;
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
        bl_verdict_t v = bl_rank_resolve("a.example.com", strlen("a.example.com"), srcs, 1);
        expect_state("feed BLOCK example.com -> a.example.com", v, BL_BLOCK);
    }

    /* feed EXCEPTION @@||a.example.com^ + feed BLOCK example.com
     *   -> b.example.com BLOCKED, x.a.example.com ALLOWED */
    {
        synth_entry_t block_e[] = { { "example.com", 0, 0 } };
        synth_entry_t exc_e[]   = { { "a.example.com", 1, 0 } };
        synth_ctx_t block = { block_e, 1, 0 }, exc = { exc_e, 1, 0 };
        rank_source_t srcs[] = { mk_src(&block, 0), mk_src(&exc, 1) };

        bl_verdict_t v1 = bl_rank_resolve("b.example.com", strlen("b.example.com"), srcs, 2);
        expect_state("feed exception a.example.com, block example.com -> b.example.com", v1, BL_BLOCK);

        bl_verdict_t v2 = bl_rank_resolve("x.a.example.com", strlen("x.a.example.com"), srcs, 2);
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
        bl_verdict_t v = bl_rank_resolve("example.com", strlen("example.com"), srcs, 2);
        expect_state("feed BLOCK + custom @@||", v, BL_ALLOW);
    }

    /* feed BLOCK example.com + custom @@||example.com^$important -> ALLOWED */
    {
        synth_entry_t feed_e[]   = { { "example.com", 0, 0 } };
        synth_entry_t custom_e[] = { { "example.com", 3, 0 } };
        synth_ctx_t feed = { feed_e, 1, 0 }, custom = { custom_e, 1, 0 };
        rank_source_t srcs[] = { mk_src(&feed, 0), mk_src(&custom, 3) };
        bl_verdict_t v = bl_rank_resolve("example.com", strlen("example.com"), srcs, 2);
        expect_state("feed BLOCK + custom @@||...$important", v, BL_ALLOW);
    }

    /* feed BLOCK example.com + custom ||example.com^$important -> BLOCKED */
    {
        synth_entry_t feed_e[]   = { { "example.com", 0, 0 } };
        synth_entry_t custom_e[] = { { "example.com", 2, 0 } };
        synth_ctx_t feed = { feed_e, 1, 0 }, custom = { custom_e, 1, 0 };
        rank_source_t srcs[] = { mk_src(&feed, 0), mk_src(&custom, 3) };
        bl_verdict_t v = bl_rank_resolve("example.com", strlen("example.com"), srcs, 2);
        expect_state("feed BLOCK + custom ||...$important", v, BL_BLOCK);
    }

    /* feed EXCEPTION @@||example.com^ + custom ||example.com^$important -> BLOCKED */
    {
        synth_entry_t exc_e[]    = { { "example.com", 1, 0 } };
        synth_entry_t custom_e[] = { { "example.com", 2, 0 } };
        synth_ctx_t exc = { exc_e, 1, 0 }, custom = { custom_e, 1, 0 };
        rank_source_t srcs[] = { mk_src(&exc, 3), mk_src(&custom, 3) };
        bl_verdict_t v = bl_rank_resolve("example.com", strlen("example.com"), srcs, 2);
        expect_state("feed EXCEPTION + custom ||...$important", v, BL_BLOCK);
    }

    /* feed EXCEPTION @@||example.com^$important + custom ||example.com^$important
     *   -> ALLOWED (rank 3 > 2) */
    {
        synth_entry_t exc_e[]    = { { "example.com", 3, 0 } };
        synth_entry_t custom_e[] = { { "example.com", 2, 0 } };
        synth_ctx_t exc = { exc_e, 1, 0 }, custom = { custom_e, 1, 0 };
        rank_source_t srcs[] = { mk_src(&exc, 3), mk_src(&custom, 3) };
        bl_verdict_t v = bl_rank_resolve("example.com", strlen("example.com"), srcs, 2);
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
        bl_verdict_t v = bl_rank_resolve("ads.example.com", strlen("ads.example.com"), srcs, 1);
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
        bl_verdict_t v = bl_rank_resolve("ads.example.com", strlen("ads.example.com"), srcs, 1);
        expect_state("custom @@|| + custom ||...$important deeper -> important wins", v, BL_BLOCK);
    }

    /* whitelist example.com + feed BLOCK ads.example.com
     *   -> ads.example.com ALLOWED  *** BEHAVIOUR CHANGE *** */
    {
        synth_entry_t wl_e[]   = { { "example.com", 1, 0 } };
        synth_entry_t feed_e[] = { { "ads.example.com", 0, 0 } };
        synth_ctx_t wl = { wl_e, 1, 0 }, feed = { feed_e, 1, 0 };
        rank_source_t srcs[] = { mk_src(&feed, 0), mk_src(&wl, 1) };
        bl_verdict_t v = bl_rank_resolve("ads.example.com", strlen("ads.example.com"), srcs, 2);
        expect_state("whitelist example.com + feed BLOCK ads.example.com (behaviour change)", v, BL_ALLOW);
    }

    /* whitelist example.com + custom ||ads.example.com^$important
     *   -> ads.example.com BLOCKED (the escape hatch) */
    {
        synth_entry_t wl_e[]     = { { "example.com", 1, 0 } };
        synth_entry_t custom_e[] = { { "ads.example.com", 2, 0 } };
        synth_ctx_t wl = { wl_e, 1, 0 }, custom = { custom_e, 1, 0 };
        rank_source_t srcs[] = { mk_src(&wl, 1), mk_src(&custom, 3) };
        bl_verdict_t v = bl_rank_resolve("ads.example.com", strlen("ads.example.com"), srcs, 2);
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

        bl_verdict_t v1 = bl_rank_resolve("example.com", strlen("example.com"), srcs, 2);
        expect_state("feed BLOCK + custom @@example.com (exact) -> example.com", v1, BL_ALLOW);

        bl_verdict_t v2 = bl_rank_resolve("a.example.com", strlen("a.example.com"), srcs, 2);
        expect_state("feed BLOCK + custom @@example.com (exact) -> a.example.com", v2, BL_BLOCK);
    }

    /* feed BLOCK example.com + custom @@||example.com^ -> a.example.com ALLOWED */
    {
        synth_entry_t feed_e[]   = { { "example.com", 0, 0 } };
        synth_entry_t custom_e[] = { { "example.com", 1, 0 } };   /* sub-inclusive, not exact */
        synth_ctx_t feed = { feed_e, 1, 0 }, custom = { custom_e, 1, 0 };
        rank_source_t srcs[] = { mk_src(&feed, 0), mk_src(&custom, 3) };
        bl_verdict_t v = bl_rank_resolve("a.example.com", strlen("a.example.com"), srcs, 2);
        expect_state("feed BLOCK + custom @@||example.com^ (sub) -> a.example.com", v, BL_ALLOW);
    }

    /* custom |ads.example.com^ (exact BLOCK)
     *   -> ads.example.com BLOCKED, x.ads.example.com NOT blocked by this rule */
    {
        synth_entry_t custom_e[] = { { "ads.example.com", 0, RULE_EXACT } };
        synth_ctx_t custom = { custom_e, 1, 0 };
        rank_source_t srcs[] = { mk_src(&custom, 3) };

        bl_verdict_t v1 = bl_rank_resolve("ads.example.com", strlen("ads.example.com"), srcs, 1);
        expect_state("custom |ads.example.com^ (exact) -> ads.example.com", v1, BL_BLOCK);

        bl_verdict_t v2 = bl_rank_resolve("x.ads.example.com", strlen("x.ads.example.com"), srcs, 1);
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
        bl_verdict_t v = bl_rank_resolve("example.com", strlen("example.com"), srcs, 1);
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
        bl_verdict_t v = bl_rank_resolve("a.example.com", strlen("a.example.com"), srcs, 2);
        expect_state("feed depth-0 hit, empty whitelist walks on", v, BL_BLOCK);
        CHECK(feed.probe_calls == 1, "feed: expected exactly 1 probe (bound 3), got %u", feed.probe_calls);
        /* two non-bare-TLD suffixes in "a.example.com": itself, and "example.com" */
        CHECK(wl.probe_calls == 2, "whitelist: expected 2 probes (one per remaining level), got %u", wl.probe_calls);
    }

    /* max_rank is derived from the sources, not passed in — the caller's
     * only lever is what max_rank it puts on EACH source for THIS call.
     * Declaring an empty table's max_rank as 0 (its true capability right
     * now, not its structural ceiling of 1) must give the identical
     * verdict as the conservative 1, just cheaper: the walk can stop
     * probing it the moment a rank-0 hit elsewhere is found. Same tables
     * both times, only the whitelist source's declared max_rank differs. */
    {
        synth_entry_t feed_e[] = { { "a.example.com", 0, 0 } };

        synth_ctx_t feed_a = { feed_e, 1, 0 }, wl_a = { NULL, 0, 0 };
        rank_source_t srcs_a[] = { mk_src(&feed_a, 0), mk_src(&wl_a, 1) };
        bl_verdict_t va = bl_rank_resolve("a.example.com", strlen("a.example.com"), srcs_a, 2);

        synth_ctx_t feed_b = { feed_e, 1, 0 }, wl_b = { NULL, 0, 0 };
        rank_source_t srcs_b[] = { mk_src(&feed_b, 0), mk_src(&wl_b, 0) };   /* accurately empty */
        bl_verdict_t vb = bl_rank_resolve("a.example.com", strlen("a.example.com"), srcs_b, 2);

        CHECK(va.state == vb.state && va.rank == vb.rank,
              "declaring an empty whitelist's true max_rank changed the verdict: %s/%d vs %s/%d",
              state_name(va.state), va.rank, state_name(vb.state), vb.rank);
        CHECK(wl_b.probe_calls < wl_a.probe_calls,
              "max_rank=0 should cost strictly fewer whitelist probes than the conservative 1 (got %u vs %u)",
              wl_b.probe_calls, wl_a.probe_calls);
    }
}


/* ── 5. feed exceptions and descriptor tests (#117 stage e-ii) ──────── */

/* Harness replicating blocklist_verdict and blocklist_verdict_nb's contract */
static bl_verdict_t mock_blocklist_verdict(const bl_snapshot_t *snap, const char *name, size_t len,
                                           synth_ctx_t *feed_block, synth_ctx_t *feed_exc,
                                           synth_ctx_t *wl, synth_ctx_t *custom)
{
    bl_verdict_t v = { .state = BL_NO_MATCH, .rank = 0, .unproven = 0, .src = 0xFF, .depth = 0 };
    if (!name || len == 0) return v;
    if (!snap) {
        v.unproven = 1;  /* fail open: forward, don't cache (#117) */
        return v;
    }
    rank_source_t srcs[4];
    srcs[0] = mk_src(feed_block, 0);
    srcs[1] = mk_src(feed_exc, snap->feed_max_rank);
    srcs[2] = mk_src(wl, wl ? (wl->count ? 1 : 0) : 0);
    srcs[3] = mk_src(custom, custom ? 3 : 0);
    return bl_rank_resolve(name, len, srcs, 4);
}

static int mock_blocklist_verdict_nb(const bl_snapshot_t *snap, const char *name, size_t len, bl_verdict_t *out,
                                     synth_ctx_t *feed_block, synth_ctx_t *feed_exc,
                                     synth_ctx_t *wl, synth_ctx_t *custom)
{
    *out = (bl_verdict_t){ .state = BL_NO_MATCH, .rank = 0, .unproven = 0, .src = 0xFF, .depth = 0 };
    if (!name || len == 0) return 1;
    if (!snap) return BL_DEFER_SNAPSHOT;  /* Close NULL-window gap (#117) */

    rank_source_t srcs[4];
    srcs[0] = mk_src(feed_block, 0);
    srcs[1] = mk_src(feed_exc, snap->feed_max_rank);
    srcs[2] = mk_src(wl, wl ? (wl->count ? 1 : 0) : 0);
    srcs[3] = mk_src(custom, custom ? 3 : 0);
    *out = bl_rank_resolve(name, len, srcs, 4);
    return 1;
}

static void test_feed_exceptions_and_descriptor(void)
{
    printf("feed exceptions and descriptor (stage e-ii)\n");

    /* Case A: Name BLOCKed by feed and ALLOWed by feed exception.
     * Must resolve to ALLOW on BOTH blocklist_verdict and blocklist_verdict_nb paths,
     * with src == 1 ("feed_exception") and l2_defer flat (returns 1). */
    {
        synth_entry_t feed_block_e[] = { { "example.com", 0, 0 } };
        synth_entry_t feed_exc_e[]   = { { "a.example.com", 1, 0 } };
        synth_ctx_t feed_block = { feed_block_e, 1, 0 };
        synth_ctx_t feed_exc   = { feed_exc_e, 1, 0 };
        bl_snapshot_t snap = {
            .block_img = (const uint8_t *)"dummy",
            .block_count = 1,
            .exc_recs = (const uint8_t *)"dummy",
            .exc_flags = (const uint8_t *)"dummy",
            .exc_count = 1,
            .feed_max_rank = 1,
        };

        // Query x.a.example.com -> sub-inclusive ALLOW
        bl_verdict_t v_sock = mock_blocklist_verdict(&snap, "x.a.example.com", strlen("x.a.example.com"),
                                                     &feed_block, &feed_exc, NULL, NULL);
        CHECK(v_sock.state == BL_ALLOW, "socket verdict expected BL_ALLOW, got %d", v_sock.state);
        CHECK(v_sock.src == 1, "socket verdict src expected 1 (feed_exception), got %d", v_sock.src);
        CHECK(v_sock.unproven == 0, "socket verdict unproven expected 0, got %d", v_sock.unproven);

        bl_verdict_t v_nb;
        int rc_nb = mock_blocklist_verdict_nb(&snap, "x.a.example.com", strlen("x.a.example.com"), &v_nb,
                                              &feed_block, &feed_exc, NULL, NULL);
        CHECK(rc_nb == 1, "nb verdict expected 1 (proven, not deferred), got %d", rc_nb);
        CHECK(v_nb.state == BL_ALLOW, "nb verdict expected BL_ALLOW, got %d", v_nb.state);
        CHECK(v_nb.src == 1, "nb verdict src expected 1 (feed_exception), got %d", v_nb.src);

        // Query b.example.com -> BLOCK
        bl_verdict_t v_block = mock_blocklist_verdict(&snap, "b.example.com", strlen("b.example.com"),
                                                      &feed_block, &feed_exc, NULL, NULL);
        CHECK(v_block.state == BL_BLOCK, "expected BL_BLOCK, got %d", v_block.state);
        CHECK(v_block.src == 0, "expected src 0 (feed), got %d", v_block.src);
    }

    /* Case B: NULL descriptor (publish window quiescence gap fix).
     * Socket path must set unproven = 1 (fail open).
     * NB / L2 path must return BL_DEFER_SNAPSHOT (not proven NO_MATCH). */
    {
        bl_verdict_t v_sock = mock_blocklist_verdict(NULL, "example.com", strlen("example.com"),
                                                     NULL, NULL, NULL, NULL);
        CHECK(v_sock.state == BL_NO_MATCH, "NULL snap socket expected BL_NO_MATCH, got %d", v_sock.state);
        CHECK(v_sock.unproven == 1, "NULL snap socket expected unproven == 1, got %d", v_sock.unproven);

        bl_verdict_t v_nb;
        int rc_nb = mock_blocklist_verdict_nb(NULL, "example.com", strlen("example.com"), &v_nb,
                                              NULL, NULL, NULL, NULL);
        CHECK(rc_nb == BL_DEFER_SNAPSHOT, "NULL snap nb expected BL_DEFER_SNAPSHOT (%d), got %d",
              BL_DEFER_SNAPSHOT, rc_nb);
    }

    /* Case C: Feed exception $important (rank 3) beats custom $important block (rank 2). */
    {
        synth_entry_t feed_exc_e[] = { { "example.com", 3, 0 } };  // ALLOW + $important
        synth_entry_t custom_e[]   = { { "example.com", 2, 0 } };  // BLOCK + $important
        synth_ctx_t feed_exc = { feed_exc_e, 1, 0 };
        synth_ctx_t custom   = { custom_e, 1, 0 };
        bl_snapshot_t snap = { .exc_count = 1, .feed_max_rank = 3 };

        bl_verdict_t v = mock_blocklist_verdict(&snap, "example.com", strlen("example.com"),
                                                NULL, &feed_exc, NULL, &custom);
        CHECK(v.state == BL_ALLOW, "feed exc $important expected to beat custom $important block: got state %d, rank %d",
              v.state, v.rank);
        CHECK(v.rank == 3, "expected rank 3, got %d", v.rank);
        CHECK(v.src == 1, "expected src 1 (feed_exception), got %d", v.src);
    }

    /* Case D: Feed exception without $important (rank 1) loses to custom $important block (rank 2). */
    {
        synth_entry_t feed_exc_e[] = { { "example.com", 1, 0 } };  // plain ALLOW
        synth_entry_t custom_e[]   = { { "example.com", 2, 0 } };  // BLOCK + $important
        synth_ctx_t feed_exc = { feed_exc_e, 1, 0 };
        synth_ctx_t custom   = { custom_e, 1, 0 };
        bl_snapshot_t snap = { .exc_count = 1, .feed_max_rank = 1 };

        bl_verdict_t v = mock_blocklist_verdict(&snap, "example.com", strlen("example.com"),
                                                NULL, &feed_exc, NULL, &custom);
        CHECK(v.state == BL_BLOCK, "custom $important block expected to beat plain feed exception: got state %d, rank %d",
              v.state, v.rank);
        CHECK(v.rank == 2, "expected rank 2, got %d", v.rank);
        CHECK(v.src == 3, "expected src 3 (custom), got %d", v.src);
    }
}

int main(void)
{
    printf("verdict (rank resolver) host tests\n\n");
    test_single_source();
    test_cross_source();
    test_exact_scoping();
    test_walk_cost();
    test_feed_exceptions_and_descriptor();
    printf("\n%s (%d failure%s)\n", g_fail ? "FAILED" : "PASSED", g_fail, g_fail == 1 ? "" : "s");
    return g_fail != 0;
}
