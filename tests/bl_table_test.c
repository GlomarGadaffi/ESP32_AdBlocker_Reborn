/*
 * Host tests for the bucket-split 40-bit blocklist core (main/bl_table.c).
 *
 * Build + run:
 *   gcc -O2 -I main -o bl_table_test tests/bl_table_test.c main/bl_table.c && ./bl_table_test
 *
 * Covers the parts that are miserable to debug on hardware: the odd-pass radix
 * landing buffer, the near-capacity fallback, bucket occupancy, and the actual
 * false-positive rate measured against theory.
 */
#include "bl_table.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

static int g_fail = 0;
#define CHECK(cond, ...) do { if (!(cond)) { \
    printf("  FAIL: "); printf(__VA_ARGS__); printf("\n"); g_fail++; } } while (0)

/* Deterministic domain generator — same sequence every run. */
static uint64_t rng_state = 0x123456789abcdefULL;
static uint64_t rng(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}
static void gen_domain(char *buf, size_t cap, uint64_t id, const char *suffix)
{
    snprintf(buf, cap, "n%016" PRIx64 "-host.%s", id, suffix);
}

/* ── 1. hash + record round-trip ─────────────────────────────────── */
static void test_records(void)
{
    printf("records + hash\n");
    for (int i = 0; i < 10000; i++) {
        char d[64];
        gen_domain(d, sizeof(d), rng(), "example.com");
        uint64_t h = bl_hash40(d, strlen(d));
        CHECK(h < (1ULL << BL_HASH_BITS), "hash exceeds 40 bits: %" PRIx64, h);
        uint8_t rec[BL_REC_BYTES];
        bl_rec_put(rec, h);
        CHECK(bl_rec_get(rec) == h, "record round-trip failed");
    }
    /* big-endian => memcmp is the numeric comparator; the whole pipeline
     * depends on this, so assert it rather than trusting the layout. */
    for (int i = 0; i < 20000; i++) {
        uint64_t a = rng() & ((1ULL << BL_HASH_BITS) - 1);
        uint64_t b = rng() & ((1ULL << BL_HASH_BITS) - 1);
        uint8_t ra[BL_REC_BYTES], rb[BL_REC_BYTES];
        bl_rec_put(ra, a); bl_rec_put(rb, b);
        int mc = memcmp(ra, rb, BL_REC_BYTES);
        int num = (a > b) - (a < b);
        CHECK((mc > 0) == (num > 0) && (mc < 0) == (num < 0),
              "memcmp disagrees with numeric order");
    }
}

/* ── 2. sort: radix landing buffer + inplace fallback agree ──────── */
static void test_sort(void)
{
    printf("sort (radix landing buffer + inplace fallback)\n");
    const uint32_t n = 200000;
    uint8_t *a  = malloc((size_t)n * BL_REC_BYTES);
    uint8_t *sc = malloc((size_t)n * BL_REC_BYTES);
    uint8_t *ip = malloc((size_t)n * BL_REC_BYTES);
    for (uint32_t i = 0; i < n; i++) {
        uint64_t h = rng() & ((1ULL << BL_HASH_BITS) - 1);
        bl_rec_put(a + (size_t)i * BL_REC_BYTES, h);
    }
    memcpy(ip, a, (size_t)n * BL_REC_BYTES);

    uint8_t *landed = bl_sort_records(a, sc, n);
    CHECK(landed == sc, "5 passes is odd — expected the result in scratch, got %s",
          landed == a ? "a" : "?");
    for (uint32_t i = 1; i < n; i++)
        CHECK(memcmp(landed + (size_t)(i-1) * BL_REC_BYTES,
                     landed + (size_t)i * BL_REC_BYTES, BL_REC_BYTES) <= 0,
              "radix output not sorted at %u", i);

    bl_sort_records_inplace(ip, n);
    CHECK(memcmp(landed, ip, (size_t)n * BL_REC_BYTES) == 0,
          "radix and inplace sorts disagree");

    free(a); free(sc); free(ip);
}

/* ── 3. dedup + prefix search ────────────────────────────────────── */
static void test_dedup(void)
{
    printf("dedup + prefix search\n");
    const uint32_t n = 50000;
    uint8_t *a  = malloc((size_t)n * 2 * BL_REC_BYTES);
    uint8_t *sc = malloc((size_t)n * 2 * BL_REC_BYTES);

    /* every entry duplicated on purpose */
    for (uint32_t i = 0; i < n; i++) {
        uint64_t h = rng() & ((1ULL << BL_HASH_BITS) - 1);
        bl_rec_put(a + (size_t)i * BL_REC_BYTES, h);
        bl_rec_put(a + (size_t)(i + n) * BL_REC_BYTES, h);
    }
    uint8_t *landed = bl_sort_records(a, sc, n * 2);
    uint32_t u = bl_dedup_records(landed, n * 2);
    CHECK(u == n, "dedup expected %u survivors, got %" PRIu32, n, u);

    for (uint32_t i = 0; i < u; i++) {
        uint64_t h = bl_rec_get(landed + (size_t)i * BL_REC_BYTES);
        CHECK(bl_records_contain(landed, u, h), "prefix search missed a present hash");
    }
    free(a); free(sc);
}

/* ── 3b. the two pipeline stages, at a cap small enough that the
 *       near-capacity FALLBACKS actually run.
 *
 * This is the coverage that matters: on the real 4-feed reload at 778k of
 * 800k, it is the fallback paths that execute every time, not the roomy radix
 * path a big-buffer bench test would exercise. Each case is checked against a
 * reference sort of the same union. ─────────────────────────────────────── */
static int cmp5(const void *x, const void *y) { return memcmp(x, y, BL_REC_BYTES); }

/* reference: sort + unique a copy, independent of the code under test */
static uint32_t reference(const uint8_t *src, uint32_t n, uint8_t *out)
{
    memcpy(out, src, (size_t)n * BL_REC_BYTES);
    qsort(out, n, BL_REC_BYTES, cmp5);
    uint32_t u = 0;
    for (uint32_t i = 0; i < n; i++)
        if (u == 0 || memcmp(out + (size_t)(u-1) * BL_REC_BYTES,
                             out + (size_t)i * BL_REC_BYTES, BL_REC_BYTES) != 0)
            memcpy(out + (size_t)u++ * BL_REC_BYTES, out + (size_t)i * BL_REC_BYTES, BL_REC_BYTES);
    return u;
}

static void check_sort_dedup(uint32_t cap, uint32_t n, const char *what)
{
    uint8_t *buf = calloc(cap, BL_REC_BYTES);
    uint8_t *src = malloc((size_t)n * BL_REC_BYTES);
    uint8_t *ref = malloc((size_t)n * BL_REC_BYTES);
    for (uint32_t i = 0; i < n; i++) {
        /* a deliberately small hash space so duplicates really occur */
        uint64_t h = rng() % (n * 2 + 1);
        bl_rec_put(src + (size_t)i * BL_REC_BYTES, h);
    }
    memcpy(buf, src, (size_t)n * BL_REC_BYTES);
    uint32_t got = bl_sort_dedup(buf, cap, n);
    uint32_t want = reference(src, n, ref);
    CHECK(got == want, "%s: sort_dedup count %" PRIu32 " != reference %" PRIu32, what, got, want);
    CHECK(memcmp(buf, ref, (size_t)want * BL_REC_BYTES) == 0, "%s: sort_dedup content differs", what);
    free(buf); free(src); free(ref);
}

static void check_fold(uint32_t cap, uint32_t p_raw, uint32_t m, const char *what)
{
    uint8_t *buf = calloc(cap, BL_REC_BYTES);
    uint8_t *all = malloc((size_t)(p_raw + m) * BL_REC_BYTES);
    uint8_t *ref = malloc((size_t)(p_raw + m) * BL_REC_BYTES);

    /* build a sorted+deduped prefix the way the real loader does */
    for (uint32_t i = 0; i < p_raw; i++)
        bl_rec_put(buf + (size_t)i * BL_REC_BYTES, rng() % (cap * 3 + 1));
    uint32_t p = bl_sort_dedup(buf, cap, p_raw);

    /* append a raw chunk, skipping anything already in the prefix — exactly
     * what on_domain_line's prefix binary search guarantees the fold */
    uint32_t n = p;
    uint32_t added = 0;
    while (added < m && n < cap) {
        uint64_t h = rng() % (cap * 3 + 1);
        if (bl_records_contain(buf, p, h)) continue;
        bl_rec_put(buf + (size_t)n++ * BL_REC_BYTES, h);
        added++;
    }
    memcpy(all, buf, (size_t)n * BL_REC_BYTES);

    uint32_t got = bl_fold_sorted_chunk(buf, cap, p, n);
    uint32_t want = reference(all, n, ref);
    CHECK(got == want, "%s: fold count %" PRIu32 " != reference %" PRIu32, what, got, want);
    CHECK(memcmp(buf, ref, (size_t)want * BL_REC_BYTES) == 0, "%s: fold content differs", what);
    free(buf); free(all); free(ref);
}

static void test_pipeline_bounds(void)
{
    printf("pipeline stages at small cap (fallback paths)\n");
    const uint32_t cap = 1000;

    check_sort_dedup(cap, 400, "sort_dedup: radix, tail scratch (2n <= cap)");
    check_sort_dedup(cap, cap / 2, "sort_dedup: exactly at the 2n == cap boundary");
    check_sort_dedup(cap, 900, "sort_dedup: qsort fallback (n > cap/2)");
    check_sort_dedup(cap, cap, "sort_dedup: full capacity");
    check_sort_dedup(cap, 1, "sort_dedup: single record");
    check_sort_dedup(cap, 0, "sort_dedup: empty");

    check_fold(cap, 100, 100, "fold: roomy, chunk radix + backward merge");
    check_fold(cap, 400, 100, "fold: chunk radix, merge near half");
    check_fold(cap, 600, 300, "fold: p + 2m' > cap -> whole-array fallback");
    check_fold(cap, 800, 150, "fold: deep near-capacity fallback");
    check_fold(cap, 0,   200, "fold: empty prefix -> plain sort_dedup");
    check_fold(cap, 300, 0,   "fold: empty chunk is a no-op");
    /* n + m > cap forces the chunk's own qsort rather than its tail scratch */
    check_fold(cap, 500, 400, "fold: chunk qsort (n + m > cap)");
}

/* ── 4. full build + membership + measured false-positive rate ───── */
static void test_image(uint32_t n)
{
    printf("image build, membership, FP rate (n=%" PRIu32 ")\n", n);

    uint8_t *recs = malloc((size_t)n * BL_REC_BYTES);
    uint8_t *sc   = malloc((size_t)n * BL_REC_BYTES);
    uint64_t *ids = malloc((size_t)n * sizeof(uint64_t));

    for (uint32_t i = 0; i < n; i++) {
        ids[i] = rng();
        char d[64];
        gen_domain(d, sizeof(d), ids[i], "blocked.example");
        bl_rec_put(recs + (size_t)i * BL_REC_BYTES, bl_hash40(d, strlen(d)));
    }
    uint8_t *landed = bl_sort_records(recs, sc, n);
    uint32_t u = bl_dedup_records(landed, n);

    uint8_t *image = malloc(BL_IMAGE_BYTES(u));
    bl_build_image(landed, u, image);

    CHECK(bl_image_count(image) == u, "image count sentinel wrong");
    const uint32_t *idx = (const uint32_t *)image;
    for (uint32_t b = 0; b < BL_BUCKET_COUNT; b++)
        CHECK(idx[b] <= idx[b + 1], "bucket index not monotonic at %" PRIu32, b);

    /* every inserted domain must be found */
    uint32_t missed = 0;
    for (uint32_t i = 0; i < n; i++) {
        char d[64];
        gen_domain(d, sizeof(d), ids[i], "blocked.example");
        if (!bl_image_contains(image, bl_hash40(d, strlen(d)))) missed++;
    }
    CHECK(missed == 0, "%" PRIu32 " inserted domains not found", missed);

    /* false positives on domains that were never inserted */
    const uint32_t probes = 2000000;
    uint32_t fp = 0;
    for (uint32_t i = 0; i < probes; i++) {
        char d[64];
        gen_domain(d, sizeof(d), rng(), "absent.invalid");
        if (bl_image_contains(image, bl_hash40(d, strlen(d)))) fp++;
    }
    double expect = (double)u / (double)(1ULL << BL_HASH_BITS) * (double)probes;
    printf("    FP: %" PRIu32 " in %" PRIu32 " probes (theory ~%.1f)\n", fp, probes, expect);
    CHECK(fp <= expect * 4 + 10, "FP rate %u far above theory %.1f", fp, expect);

    /* bucket occupancy should be tight around n/65536 if the top 16 bits are
     * well mixed — this is what buys the ~4-probe lookup. */
    uint32_t maxocc = 0, empty = 0;
    for (uint32_t b = 0; b < BL_BUCKET_COUNT; b++) {
        uint32_t occ = idx[b + 1] - idx[b];
        if (occ > maxocc) maxocc = occ;
        if (occ == 0) empty++;
    }
    double mean = (double)u / BL_BUCKET_COUNT;
    printf("    buckets: mean %.1f, max %" PRIu32 ", empty %" PRIu32 "\n", mean, maxocc, empty);
    CHECK(maxocc < mean * 4 + 20, "bucket occupancy skewed: max %u vs mean %.1f", maxocc, mean);

    free(recs); free(sc); free(ids); free(image);
}

/* ── 5. large build through the real buffer geometry ─────────────── */
static void test_large(void)
{
    printf("large build through the real buffer geometry\n");
    const uint32_t n = 400000;
    const uint32_t cap = n * 2;

    uint8_t *buf = malloc((size_t)cap * BL_REC_BYTES);
    uint64_t *ids = malloc((size_t)n * sizeof(uint64_t));
    for (uint32_t i = 0; i < n; i++) {
        ids[i] = rng();
        char d[64];
        gen_domain(d, sizeof(d), ids[i], "large.example");
        bl_rec_put(buf + (size_t)i * BL_REC_BYTES, bl_hash40(d, strlen(d)));
    }
    /* mirror sort_dedup_records: records at [0,n), tail scratch at [n,2n) */
    uint8_t *landed = bl_sort_records(buf, buf + (size_t)n * BL_REC_BYTES, n);
    CHECK(landed == buf + (size_t)n * BL_REC_BYTES, "expected landing in the tail half");
    uint32_t u = bl_dedup_records(landed, n);

    uint8_t *image = malloc(BL_IMAGE_BYTES(u));
    bl_build_image(landed, u, image);

    uint32_t missed = 0;
    for (uint32_t i = 0; i < n; i++) {
        char d[64];
        gen_domain(d, sizeof(d), ids[i], "large.example");
        if (!bl_image_contains(image, bl_hash40(d, strlen(d)))) missed++;
    }
    CHECK(missed == 0, "%" PRIu32 " domains lost through the pipeline", missed);

    free(buf); free(ids); free(image);
}

/* ── 5b. image validator rejects corrupt snapshots ───────────────── */
static void test_image_valid(void)
{
    printf("image validator\n");
    const uint32_t n = 5000;
    uint8_t *recs = malloc((size_t)n * BL_REC_BYTES);
    uint8_t *sc   = malloc((size_t)n * BL_REC_BYTES);
    for (uint32_t i = 0; i < n; i++)
        bl_rec_put(recs + (size_t)i * BL_REC_BYTES, rng() & ((1ULL << BL_HASH_BITS) - 1));
    uint8_t *landed = bl_sort_records(recs, sc, n);
    uint32_t u = bl_dedup_records(landed, n);

    uint8_t *image = malloc(BL_IMAGE_BYTES(u));
    bl_build_image(landed, u, image);
    CHECK(bl_image_valid(image, u), "a freshly built image must validate");
    CHECK(!bl_image_valid(image, u + 1), "count mismatch must be rejected");

    uint32_t *idx = (uint32_t *)image;

    /* the failure that mattered: a wild bucket range walks off the buffer */
    uint32_t save = idx[100];
    idx[100] = 0xFFFFFFFFu;
    CHECK(!bl_image_valid(image, u), "out-of-range bucket offset must be rejected");
    idx[100] = save;

    /* non-monotonic index */
    save = idx[200];
    idx[200] = idx[201] + 1;
    CHECK(!bl_image_valid(image, u), "non-monotonic index must be rejected");
    idx[200] = save;

    /* index must start at 0 */
    save = idx[0];
    idx[0] = 1;
    CHECK(!bl_image_valid(image, u), "idx[0] != 0 must be rejected");
    idx[0] = save;

    CHECK(bl_image_valid(image, u), "restoring the index must validate again");
    free(recs); free(sc); free(image);
}

/* ── 6. edge cases ───────────────────────────────────────────────── */
static void test_edges(void)
{
    printf("edge cases\n");
    uint8_t *img = malloc(BL_IMAGE_BYTES(0));
    bl_build_image(NULL, 0, img);
    CHECK(bl_image_count(img) == 0, "empty image count");
    CHECK(!bl_image_contains(img, 0), "empty image must not match");
    CHECK(!bl_image_contains(img, (1ULL << BL_HASH_BITS) - 1), "empty image must not match max");
    free(img);

    /* single entry, and the extreme buckets (0 and 65535) */
    uint64_t extremes[] = { 0, (1ULL << BL_HASH_BITS) - 1, 1, (1ULL << 24) };
    for (size_t k = 0; k < sizeof(extremes)/sizeof(extremes[0]); k++) {
        uint8_t rec[BL_REC_BYTES];
        bl_rec_put(rec, extremes[k]);
        uint8_t *one = malloc(BL_IMAGE_BYTES(1));
        bl_build_image(rec, 1, one);
        CHECK(bl_image_contains(one, extremes[k]), "single-entry lookup failed for %" PRIx64, extremes[k]);
        CHECK(bl_image_count(one) == 1, "single-entry count wrong");
        free(one);
    }

    uint32_t z = bl_dedup_records(NULL, 0);
    CHECK(z == 0, "dedup of empty must be 0");
}

int main(void)
{
    printf("bl_table host tests\n\n");
    test_records();
    test_sort();
    test_dedup();
    test_pipeline_bounds();
    test_image(800000);      /* full capacity, the real operating point */
    test_large();
    test_image_valid();
    test_edges();
    printf("\n%s (%d failure%s)\n", g_fail ? "FAILED" : "PASSED", g_fail, g_fail == 1 ? "" : "s");
    return g_fail != 0;
}
