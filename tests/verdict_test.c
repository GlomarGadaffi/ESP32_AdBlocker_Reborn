/*
 * Host tests for the rank-ordered verdict resolver (main/bl_rank.c) and the
 * real verdict ladder (main/bl_verdict.c), #117.
 *
 * Build + run:
 *   gcc -O2 -I main -o verdict_test tests/verdict_test.c main/bl_verdict.c main/bl_rank.c main/bl_table.c main/domain.c && ./verdict_test
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
#include "bl_verdict.h"
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


/* ── 5. the real ladder (bl_verdict.c): feed block/exception tables, whitelist
 * and custom rules, through both entry styles (#117 stage e-ii) ───────────
 *
 * Fixtures build REAL block images and exception record tables with bl_table.c
 * and hand them to bl_verdict_socket() / bl_verdict_nb() — the same functions
 * blocklist_verdict() / blocklist_verdict_nb() call once they hold the lock.
 * What stays untested here is only blocklist.c's own state: the pause flag,
 * the mutex and the post-walk snapshot re-read. */
#include <stdlib.h>

#define FIX_MAX 8

typedef struct {
    const char *name;
    uint8_t     flags;   /* feed exceptions: RULE_IMPORTANT / RULE_EXACT; custom: packed byte */
} fix_rule_t;

typedef struct {
    uint8_t       *img;                       /* NULL when no feed blocks */
    uint8_t        exc_recs[FIX_MAX * BL_REC_BYTES];
    uint8_t        exc_flags[FIX_MAX];
    bl_snapshot_t  snap;
    char           wl[FIX_MAX][BL_ENTRY_BYTES];
    char           cust[FIX_MAX][BL_ENTRY_BYTES];
    uint8_t        cust_flags[FIX_MAX];
    bl_view_t      view;
} fixture_t;

static void fix_free(fixture_t *f) { free(f->img); f->img = NULL; }

static void fix_put(char dst[][BL_ENTRY_BYTES], uint32_t i, const char *s)
{
    snprintf(dst[i], BL_ENTRY_BYTES, "%s", s);
}

/* feed_block / exc / wl / custom are NULL-terminated-by-count lists. */
static void fix_build(fixture_t *f,
                      const char *const *feed_block, size_t nblock,
                      const fix_rule_t *exc, size_t nexc,
                      const char *const *wl, size_t nwl,
                      const fix_rule_t *custom, size_t ncustom)
{
    memset(f, 0, sizeof *f);

    if (nblock) {
        uint8_t recs[FIX_MAX * BL_REC_BYTES], scratch[FIX_MAX * BL_REC_BYTES];
        for (size_t i = 0; i < nblock; i++)
            bl_rec_put(recs + i * BL_REC_BYTES, bl_hash40(feed_block[i], strlen(feed_block[i])));
        uint8_t *sorted = bl_sort_records(recs, scratch, (uint32_t)nblock);
        uint32_t n = bl_dedup_records(sorted, (uint32_t)nblock);
        f->img = (uint8_t *)malloc(BL_IMAGE_BYTES(n));
        if (!f->img || bl_build_image(sorted, n, f->img) != n) { CHECK(0, "image build failed"); return; }
        f->snap.block_img = f->img;
        f->snap.block_count = n;
    }

    /* Exceptions: insertion-sort by hash, flags riding along. */
    uint8_t max_rank = 0;
    for (size_t i = 0; i < nexc; i++) {
        uint64_t h = bl_hash40(exc[i].name, strlen(exc[i].name));
        size_t j = i;
        while (j > 0 && bl_rec_get(f->exc_recs + (j - 1) * BL_REC_BYTES) > h) {
            memcpy(f->exc_recs + j * BL_REC_BYTES, f->exc_recs + (j - 1) * BL_REC_BYTES, BL_REC_BYTES);
            f->exc_flags[j] = f->exc_flags[j - 1];
            j--;
        }
        bl_rec_put(f->exc_recs + j * BL_REC_BYTES, h);
        f->exc_flags[j] = exc[i].flags;
        uint8_t r = rule_rank(RULE_ALLOW, exc[i].flags);
        if (r > max_rank) max_rank = r;
    }
    f->snap.exc_recs = f->exc_recs;
    f->snap.exc_flags = f->exc_flags;
    f->snap.exc_count = (uint32_t)nexc;
    f->snap.feed_max_rank = max_rank;

    for (size_t i = 0; i < nwl; i++) fix_put(f->wl, (uint32_t)i, wl[i]);
    uint8_t cmax = 0;
    for (size_t i = 0; i < ncustom; i++) {
        fix_put(f->cust, (uint32_t)i, custom[i].name);
        f->cust_flags[i] = custom[i].flags;
        if ((custom[i].flags & 3u) > cmax) cmax = custom[i].flags & 3u;
    }

    f->view = (bl_view_t){
        .snap = &f->snap,
        .wl = (const char (*)[BL_ENTRY_BYTES])f->wl, .wl_count = (uint32_t)nwl,
        .custom = (const char (*)[BL_ENTRY_BYTES])f->cust, .custom_flags = f->cust_flags,
        .custom_count = (uint32_t)ncustom, .custom_max_rank = cmax,
    };
}

/* Run both entry styles; they must agree field for field, and match the
 * expectation. expect_src is ignored for NO_MATCH. */
static void expect_both(const char *label, const bl_view_t *view,
                        const char *name, size_t len, uint8_t expect, uint8_t expect_src)
{
    bl_verdict_t vs = bl_verdict_socket(view, name, len);
    bl_verdict_t vn;
    int rc = bl_verdict_nb(view, name, len, &vn);
    CHECK(rc == 1, "%s: nb expected proven (1), got %d", label, rc);
    CHECK(vs.state == expect, "%s: socket expected %s, got %s (rank=%d)",
          label, state_name(expect), state_name(vs.state), vs.rank);
    CHECK(vn.state == expect, "%s: nb expected %s, got %s (rank=%d)",
          label, state_name(expect), state_name(vn.state), vn.rank);
    CHECK(vs.state == vn.state && vs.rank == vn.rank && vs.src == vn.src &&
          vs.depth == vn.depth && vs.unproven == vn.unproven,
          "%s: entry styles disagree (socket %d/%d/src%d/d%d/u%d, nb %d/%d/src%d/d%d/u%d)", label,
          vs.state, vs.rank, vs.src, vs.depth, vs.unproven,
          vn.state, vn.rank, vn.src, vn.depth, vn.unproven);
    CHECK(vs.unproven == 0, "%s: unproven expected 0, got %d", label, vs.unproven);
    if (expect != BL_NO_MATCH)
        CHECK(vs.src == expect_src, "%s: expected src %d, got %d", label, expect_src, vs.src);
}

static void test_feed_exceptions_and_descriptor(void)
{
    printf("real ladder: feed exceptions and descriptor (stage e-ii)\n");

    /* Case A: Name BLOCKed by feed and ALLOWed by feed exception.
     * Must resolve to ALLOW on BOTH entry styles, with src == 1
     * ("feed_exception") and the nb path proven (returns 1). */
    {
        const char *blk[] = { "example.com" };
        fix_rule_t exc[]  = { { "a.example.com", 0 } };
        fixture_t f;
        fix_build(&f, blk, 1, exc, 1, NULL, 0, NULL, 0);
        expect_both("A x.a.example.com (feed exception)", &f.view,
                    "x.a.example.com", strlen("x.a.example.com"), BL_ALLOW, 1);
        expect_both("A b.example.com (feed block)", &f.view,
                    "b.example.com", strlen("b.example.com"), BL_BLOCK, 0);
        fix_free(&f);
    }

    /* Case B: NULL descriptor (publish window quiescence gap fix).
     * Socket path must set unproven = 1 (fail open).
     * NB / L2 path must return BL_DEFER_SNAPSHOT (not proven NO_MATCH). */
    {
        bl_view_t none = { .snap = NULL };
        bl_verdict_t v_sock = bl_verdict_socket(&none, "example.com", strlen("example.com"));
        CHECK(v_sock.state == BL_NO_MATCH, "NULL snap socket expected BL_NO_MATCH, got %d", v_sock.state);
        CHECK(v_sock.unproven == 1, "NULL snap socket expected unproven == 1, got %d", v_sock.unproven);

        bl_verdict_t v_nb;
        int rc_nb = bl_verdict_nb(&none, "example.com", strlen("example.com"), &v_nb);
        CHECK(rc_nb == BL_DEFER_SNAPSHOT, "NULL snap nb expected BL_DEFER_SNAPSHOT (%d), got %d",
              BL_DEFER_SNAPSHOT, rc_nb);
        CHECK(v_nb.state == BL_NO_MATCH, "NULL snap nb must not claim a verdict, got %d", v_nb.state);
    }

    /* Case C: Feed exception $important (rank 3) beats custom $important block (rank 2). */
    {
        fix_rule_t exc[]  = { { "example.com", RULE_IMPORTANT } };   /* ALLOW + $important */
        fix_rule_t cust[] = { { "example.com", 2 } };                /* BLOCK + $important */
        fixture_t f;
        fix_build(&f, NULL, 0, exc, 1, NULL, 0, cust, 1);
        bl_verdict_t v = bl_verdict_socket(&f.view, "example.com", strlen("example.com"));
        CHECK(v.state == BL_ALLOW, "feed exc $important expected to beat custom $important block: got state %d, rank %d",
              v.state, v.rank);
        CHECK(v.rank == 3, "expected rank 3, got %d", v.rank);
        CHECK(v.src == 1, "expected src 1 (feed_exception), got %d", v.src);
        expect_both("C both styles", &f.view, "example.com", strlen("example.com"), BL_ALLOW, 1);
        fix_free(&f);
    }

    /* Case D: Feed exception without $important (rank 1) loses to custom $important block (rank 2). */
    {
        fix_rule_t exc[]  = { { "example.com", 0 } };   /* plain ALLOW */
        fix_rule_t cust[] = { { "example.com", 2 } };   /* BLOCK + $important */
        fixture_t f;
        fix_build(&f, NULL, 0, exc, 1, NULL, 0, cust, 1);
        bl_verdict_t v = bl_verdict_socket(&f.view, "example.com", strlen("example.com"));
        CHECK(v.state == BL_BLOCK, "custom $important block expected to beat plain feed exception: got state %d, rank %d",
              v.state, v.rank);
        CHECK(v.rank == 2, "expected rank 2, got %d", v.rank);
        CHECK(v.src == 3, "expected src 3 (custom), got %d", v.src);
        expect_both("D both styles", &f.view, "example.com", strlen("example.com"), BL_BLOCK, 3);
        fix_free(&f);
    }
}

static void test_real_ladder_new_cases(void)
{
    printf("real ladder: parent/child, exception rank, bounds\n");

    /* Blocked parent + whitelisted child: the child whitelist (rank 1)
     * beats the parent feed block (rank 0) for the child and anything
     * under it; siblings stay blocked. */
    {
        const char *blk[] = { "example.com" };
        const char *wl[]  = { "ok.example.com" };
        fixture_t f;
        fix_build(&f, blk, 1, NULL, 0, wl, 1, NULL, 0);
        expect_both("parent block + whitelisted child: child", &f.view,
                    "ok.example.com", strlen("ok.example.com"), BL_ALLOW, 2);
        expect_both("parent block + whitelisted child: grandchild", &f.view,
                    "x.ok.example.com", strlen("x.ok.example.com"), BL_ALLOW, 2);
        expect_both("parent block + whitelisted child: sibling", &f.view,
                    "ads.example.com", strlen("ads.example.com"), BL_BLOCK, 0);
        expect_both("parent block + whitelisted child: parent", &f.view,
                    "example.com", strlen("example.com"), BL_BLOCK, 0);
        fix_free(&f);
    }

    /* Exception beats a block at the same suffix, plain and $important. */
    {
        const char *blk[] = { "example.com" };
        fix_rule_t exc[]  = { { "example.com", 0 } };
        fixture_t f;
        fix_build(&f, blk, 1, exc, 1, NULL, 0, NULL, 0);
        expect_both("feed exception vs feed block, same suffix", &f.view,
                    "example.com", strlen("example.com"), BL_ALLOW, 1);
        fix_free(&f);

        fix_rule_t exc_imp[] = { { "example.com", RULE_IMPORTANT } };
        fix_rule_t cust[]    = { { "example.com", 2 } };   /* BLOCK $important */
        fix_build(&f, blk, 1, exc_imp, 1, NULL, 0, cust, 1);
        expect_both("$important exception vs $important block, same suffix", &f.view,
                    "example.com", strlen("example.com"), BL_ALLOW, 1);
        fix_free(&f);

        const char *wl[]    = { "example.com" };
        fix_rule_t cplain[] = { { "example.com", 0 } };    /* plain custom block */
        fix_build(&f, NULL, 0, NULL, 0, wl, 1, cplain, 1);
        expect_both("whitelist vs plain custom block, same suffix", &f.view,
                    "example.com", strlen("example.com"), BL_ALLOW, 2);
        fix_free(&f);
    }

    /* Name longer than any legal DNS name: heap buffer of EXACTLY len bytes
     * with no terminator, so ASan flags any read past it. */
    {
        const char *blk[] = { "example.com" };
        const char *wl[]  = { "ok.example.com" };
        fix_rule_t cust[] = { { "exact.example.com", 4 }  /* RULE_EXACT bit */ };
        fixture_t f;
        fix_build(&f, blk, 1, NULL, 0, wl, 1, cust, 1);

        const size_t n_lab = 70, lab = 8;   /* "abcdefg." x70 + "example.com" */
        const size_t long_len = n_lab * lab + strlen("example.com");
        char *buf = (char *)malloc(long_len);
        CHECK(buf != NULL, "alloc");
        if (buf) {
            for (size_t i = 0; i < n_lab; i++) memcpy(buf + i * lab, "abcdefg.", lab);
            memcpy(buf + n_lab * lab, "example.com", strlen("example.com"));
            expect_both("over-long name under blocked parent", &f.view, buf, long_len, BL_BLOCK, 0);
            free(buf);
        }

        /* One 600-byte label, no dots, no match anywhere. */
        char *one = (char *)malloc(600);
        CHECK(one != NULL, "alloc");
        if (one) {
            memset(one, 'z', 600);
            expect_both("over-long single label", &f.view, one, 600, BL_NO_MATCH, 0);
            free(one);
        }

        /* Name longer than the 64-byte entry width must never match an
         * entry that is a 64-byte-truncated prefix of it. */
        char *l64 = (char *)malloc(BL_ENTRY_BYTES + 10);
        CHECK(l64 != NULL, "alloc");
        if (l64) {
            memset(l64, 'q', BL_ENTRY_BYTES + 10);
            expect_both("name just over the entry width", &f.view, l64, BL_ENTRY_BYTES + 10, BL_NO_MATCH, 0);
            free(l64);
        }
        fix_free(&f);
    }

    /* Empty name: a proven NO_MATCH on both styles, even with no snapshot,
     * and a NULL pointer with len 0 or len > 0 is not dereferenced. */
    {
        const char *blk[] = { "example.com" };
        fixture_t f;
        fix_build(&f, blk, 1, NULL, 0, NULL, 0, NULL, 0);
        expect_both("empty name", &f.view, "", 0, BL_NO_MATCH, 0);
        expect_both("NULL name", &f.view, NULL, 0, BL_NO_MATCH, 0);
        expect_both("NULL name, len > 0", &f.view, NULL, 5, BL_NO_MATCH, 0);
        bl_view_t none = { .snap = NULL };
        expect_both("empty name, no snapshot", &none, "", 0, BL_NO_MATCH, 0);
        fix_free(&f);
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
    test_real_ladder_new_cases();
    printf("\n%s (%d failure%s)\n", g_fail ? "FAILED" : "PASSED", g_fail, g_fail == 1 ? "" : "s");
    return g_fail != 0;
}
