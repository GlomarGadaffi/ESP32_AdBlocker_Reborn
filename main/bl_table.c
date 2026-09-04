#include "bl_table.h"
#include <string.h>
#include <stdlib.h>

/* ── Hashing ─────────────────────────────────────────────────────── */
/* FNV-1a 64 (one multiply per byte) finished with murmur3's fmix64.
 * The finalizer is not optional: raw FNV-1a's low bits are weakly mixed, and
 * here the TOP 16 bits become the bucket index, so poor avalanche there skews
 * bucket occupancy and with it the probe count the whole design is buying. */
#define FNV64_OFFSET  0xcbf29ce484222325ULL
#define FNV64_PRIME   0x100000001b3ULL

static inline uint64_t fmix64(uint64_t k)
{
    k ^= k >> 33;
    k *= 0xff51afd7ed558ccdULL;
    k ^= k >> 33;
    k *= 0xc4ceb9fe1a85ec53ULL;
    k ^= k >> 33;
    return k;
}

uint64_t IRAM_ATTR bl_hash40(const char *name, size_t len)
{
    uint64_t h = FNV64_OFFSET;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint8_t)name[i];
        h *= FNV64_PRIME;
    }
    return fmix64(h) >> (64 - BL_HASH_BITS);   /* top 40 bits */
}

/* ── 5-byte big-endian records ───────────────────────────────────── */
void bl_rec_put(uint8_t *rec, uint64_t h40)
{
    rec[0] = (uint8_t)(h40 >> 32);
    rec[1] = (uint8_t)(h40 >> 24);
    rec[2] = (uint8_t)(h40 >> 16);
    rec[3] = (uint8_t)(h40 >> 8);
    rec[4] = (uint8_t)(h40);
}

uint64_t bl_rec_get(const uint8_t *rec)
{
    return ((uint64_t)rec[0] << 32) | ((uint64_t)rec[1] << 24) |
           ((uint64_t)rec[2] << 16) | ((uint64_t)rec[3] << 8)  | (uint64_t)rec[4];
}

/* ── Radix sort ──────────────────────────────────────────────────── */
/* LSD over the 5 record bytes, least significant (byte 4) first. Big-endian
 * storage means byte 0 is the most significant, so the pass order is 4,3,2,1,0.
 * FIVE passes is odd: after the final pass the data sits in whichever buffer
 * that pass wrote to, which is NOT 'a'. The old 4-byte/4-pass sort could
 * silently rely on landing back in place; this one cannot, so the landing
 * buffer is returned rather than assumed. */
uint8_t *bl_sort_records(uint8_t *a, uint8_t *scratch, uint32_t n)
{
    if (n < 2) return a;

    uint8_t *src = a, *dst = scratch;
    for (int byte = (int)BL_REC_BYTES - 1; byte >= 0; byte--) {
        uint32_t cnt[256];
        memset(cnt, 0, sizeof(cnt));
        for (uint32_t i = 0; i < n; i++) cnt[src[i * BL_REC_BYTES + byte]]++;
        uint32_t prefix = 0;
        for (int j = 0; j < 256; j++) { uint32_t c = cnt[j]; cnt[j] = prefix; prefix += c; }
        for (uint32_t i = 0; i < n; i++) {
            const uint8_t *r = src + i * BL_REC_BYTES;
            memcpy(dst + (size_t)cnt[r[byte]]++ * BL_REC_BYTES, r, BL_REC_BYTES);
        }
        uint8_t *tmp = src; src = dst; dst = tmp;
    }
    /* After an odd pass count 'src' points at the last write target. */
    return src;
}

static int cmp_rec(const void *x, const void *y)
{
    return memcmp(x, y, BL_REC_BYTES);   /* big-endian -> memcmp is numeric */
}

void bl_sort_records_inplace(uint8_t *a, uint32_t n)
{
    if (n < 2) return;
    qsort(a, n, BL_REC_BYTES, cmp_rec);
}

uint32_t bl_dedup_records(uint8_t *recs, uint32_t n)
{
    if (n == 0) return 0;
    uint32_t u = 1;
    for (uint32_t i = 1; i < n; i++) {
        const uint8_t *cur = recs + (size_t)i * BL_REC_BYTES;
        uint8_t *last = recs + (size_t)(u - 1) * BL_REC_BYTES;
        if (memcmp(cur, last, BL_REC_BYTES) != 0)
            memcpy(recs + (size_t)u++ * BL_REC_BYTES, cur, BL_REC_BYTES);
    }
    return u;
}

bool bl_records_contain(const uint8_t *recs, uint32_t n, uint64_t h40)
{
    uint8_t key[BL_REC_BYTES];
    bl_rec_put(key, h40);
    uint32_t lo = 0, hi = n;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        int c = memcmp(recs + (size_t)mid * BL_REC_BYTES, key, BL_REC_BYTES);
        if      (c < 0) lo = mid + 1;
        else if (c > 0) hi = mid;
        else            return true;
    }
    return false;
}

/* Sort + dedup, with the tail-scratch geometry that keeps the live image
 * untouched. See the header for the precondition on 'a' and 'cap'. */
uint32_t bl_sort_dedup(uint8_t *a, uint32_t cap, uint32_t n)
{
    if (n < 2) return n;
    if (n <= cap / 2) {
        uint8_t *scratch = a + (size_t)n * BL_REC_BYTES;
        uint8_t *landed  = bl_sort_records(a, scratch, n);
        if (landed != a) memcpy(a, landed, (size_t)n * BL_REC_BYTES);  /* disjoint */
    } else {
        bl_sort_records_inplace(a, n);
    }
    return bl_dedup_records(a, n);
}

/* The chunk arrived through the prefix binary search in the caller, so chunk
 * and prefix are disjoint; equals can only be intra-chunk and die in the chunk
 * dedup. The merge tolerates an equal pair anyway (both copies survive,
 * adjacent - one wasted slot, never a corrupt order).
 *
 * A zero-scratch backward merge of ADJACENT runs is not safe: with the chunk at
 * [p, p+m'), the first write at p+m'-1 lands on the chunk's own unread top. So
 * the deduped chunk is first moved to the buffer's far end, b = a+cap-m',
 * making destination and chunk disjoint: the highest write is p+m'-1 < cap-m'
 * exactly when p + 2m' <= cap. On the prefix side, while chunk elements remain
 * w = i+j > i, so a[--w] never touches an unread a[i-1]; once the chunk is
 * exhausted the remaining prefix is already in place. The one geometry that
 * fails the gate - free space smaller than the chunk, reachable only within a
 * whisker of capacity - falls back to the whole-array sort. */
uint32_t bl_fold_sorted_chunk(uint8_t *a, uint32_t cap, uint32_t p, uint32_t n)
{
    uint32_t m = n - p;
    if (m == 0) return p;
    if (p == 0) return bl_sort_dedup(a, cap, n);

    uint8_t *chunk = a + (size_t)p * BL_REC_BYTES;

    /* Sort the chunk alone: its own tail a[n..n+m) is valid radix scratch
     * whenever it fits under cap; otherwise qsort just the m records. */
    if (n + m <= cap) {
        uint8_t *landed = bl_sort_records(chunk, a + (size_t)n * BL_REC_BYTES, m);
        if (landed != chunk) memcpy(chunk, landed, (size_t)m * BL_REC_BYTES);
    } else if (m > 1) {
        bl_sort_records_inplace(chunk, m);
    }

    uint32_t mp = bl_dedup_records(chunk, m);   /* intra-feed repeats only */

    if (p + 2u * mp > cap)
        return bl_sort_dedup(a, cap, p + mp);   /* near-capacity fallback */

    uint8_t *b = a + (size_t)(cap - mp) * BL_REC_BYTES;
    memmove(b, chunk, (size_t)mp * BL_REC_BYTES);

    uint32_t i = p, j = mp, w = p + mp;
    while (i > 0 && j > 0) {
        const uint8_t *ra = a + (size_t)(i - 1) * BL_REC_BYTES;
        const uint8_t *rb = b + (size_t)(j - 1) * BL_REC_BYTES;
        w--;
        if (memcmp(ra, rb, BL_REC_BYTES) > 0) { memcpy(a + (size_t)w * BL_REC_BYTES, ra, BL_REC_BYTES); i--; }
        else                                  { memcpy(a + (size_t)w * BL_REC_BYTES, rb, BL_REC_BYTES); j--; }
    }
    while (j > 0) {
        w--; j--;
        memcpy(a + (size_t)w * BL_REC_BYTES, b + (size_t)j * BL_REC_BYTES, BL_REC_BYTES);
    }
    /* i > 0 remainder: already in place (w == i here). */
    return p + mp;
}

/* ── Sorted records -> live image ────────────────────────────────── */
uint32_t bl_build_image(const uint8_t *sorted, uint32_t n, uint8_t *image)
{
    uint32_t *idx = (uint32_t *)image;
    uint8_t  *ent = image + BL_IDX_BYTES;

    /* One forward pass: emit the 3-byte remainder and, on each bucket change,
     * close every bucket up to and including the one just left. Records are
     * sorted on the full 40 bits, so buckets appear in ascending order and
     * each is contiguous — no counting pass needed. */
    uint32_t bucket_cursor = 0;
    for (uint32_t i = 0; i < n; i++) {
        uint64_t h = bl_rec_get(sorted + (size_t)i * BL_REC_BYTES);
        uint32_t b = (uint32_t)(h >> (BL_HASH_BITS - BL_BUCKET_BITS));
        while (bucket_cursor <= b) idx[bucket_cursor++] = i;
        uint8_t *e = ent + (size_t)i * BL_ENT_BYTES;
        e[0] = (uint8_t)(h >> 16);
        e[1] = (uint8_t)(h >> 8);
        e[2] = (uint8_t)(h);
    }
    while (bucket_cursor < BL_IDX_WORDS) idx[bucket_cursor++] = n;
    return n;
}

uint32_t bl_image_count(const uint8_t *image)
{
    return ((const uint32_t *)image)[BL_BUCKET_COUNT];
}

bool IRAM_ATTR bl_image_contains(const uint8_t *image, uint64_t h40)
{
    const uint32_t *idx = (const uint32_t *)image;
    const uint8_t  *ent = image + BL_IDX_BYTES;

    uint32_t b = (uint32_t)(h40 >> (BL_HASH_BITS - BL_BUCKET_BITS));
    uint32_t lo = idx[b], hi = idx[b + 1];

    uint8_t key[BL_ENT_BYTES];
    key[0] = (uint8_t)(h40 >> 16);
    key[1] = (uint8_t)(h40 >> 8);
    key[2] = (uint8_t)(h40);

    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        int c = memcmp(ent + (size_t)mid * BL_ENT_BYTES, key, BL_ENT_BYTES);
        if      (c < 0) lo = mid + 1;
        else if (c > 0) hi = mid;
        else            return true;
    }
    return false;
}

bool bl_image_valid(const uint8_t *image, uint32_t count)
{
    const uint32_t *idx = (const uint32_t *)image;
    if (idx[0] != 0) return false;
    for (uint32_t b = 0; b < BL_BUCKET_COUNT; b++)
        if (idx[b] > idx[b + 1] || idx[b + 1] > count) return false;
    return idx[BL_BUCKET_COUNT] == count;
}
