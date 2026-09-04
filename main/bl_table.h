#pragma once
/*
 * Bucket-split 40-bit blocklist table — pure algorithmic core.
 *
 * No ESP-IDF, FreeRTOS, NVS or logging dependencies, on purpose: this is the
 * part that is painful to debug on hardware (radix sort landing buffers,
 * near-capacity merge bounds, the 5-byte -> 3-byte conversion), so it
 * builds and is tested on the host. blocklist.c owns everything stateful —
 * buffers, atomics, publish, NVS, SD; this file owns only the format.
 *
 * Format and the reasoning behind it: docs/blocklist-format.md
 *
 *   h40    = fmix64(fnv1a64(domain)) >> 24     40 bits
 *   bucket = h40 >> 24                         16 bits -> index slot
 *   rem    = h40 & 0xFFFFFF                    24 bits -> 3 stored bytes
 *
 * Everything is BIG-ENDIAN so that memcmp() is the numeric comparator for
 * every comparison in the pipeline, and so bytes 0-1 of a build record are the
 * bucket with no shifting.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef ESP_PLATFORM
#include "esp_attr.h"
#else
#ifndef IRAM_ATTR
#define IRAM_ATTR
#endif
#endif

#define BL_HASH_BITS     40
#define BL_BUCKET_BITS   16
#define BL_BUCKET_COUNT  (1u << BL_BUCKET_BITS)          /* 65536 */
#define BL_IDX_WORDS     (BL_BUCKET_COUNT + 1u)          /* +1 = end sentinel */
#define BL_IDX_BYTES     (BL_IDX_WORDS * 4u)             /* 262,148 */
#define BL_REC_BYTES     5u   /* build-staging record: full 40-bit hash, BE */
#define BL_ENT_BYTES     3u   /* live entry: 24-bit remainder, BE */
#define BL_REM_MASK      0xFFFFFFu

/* Live image is a single allocation so one atomic pointer publishes the index
 * and the entries together:  [ uint32_t idx[65537] ][ 3-byte entries ] */
#define BL_IMAGE_BYTES(n)  (BL_IDX_BYTES + (size_t)(n) * BL_ENT_BYTES)

/* Hash a normalized domain to 40 bits. Caller must normalize first.
 * IRAM_ATTR is on the DEFINITION in bl_table.c only, never here: repeating it
 * gives GCC two different generated section names for one symbol and fails
 * under -Werror=attributes. Same rule, same reason, as murmur3.h.
 * Deliberately NOT domain_hash(): that 32-bit murmur also keys the forward
 * cache, the L2 cache lookup and the in-flight upstream table, and widening it
 * there would be an unrelated format change to unrelated structures. */
uint64_t bl_hash40(const char *name, size_t len);

/* ── 5-byte build records ────────────────────────────────────────── */
void     bl_rec_put(uint8_t *rec, uint64_t h40);
uint64_t bl_rec_get(const uint8_t *rec);

/*
 * LSD radix sort of n 5-byte records, ascending.
 *
 * 5 record bytes = 5 passes = ODD, so the result does NOT land back in 'a' the
 * way the old 4-pass/4-byte sort did. Returns the buffer the sorted data
 * actually landed in — always use the return value, never 'a'.
 * 'scratch' must be n records wide and must not overlap 'a'.
 */
uint8_t *bl_sort_records(uint8_t *a, uint8_t *scratch, uint32_t n);

/* In-place sort for the near-capacity case where no scratch is available.
 * Slower (qsort with a memcmp comparator); result is always in 'a'. */
void bl_sort_records_inplace(uint8_t *a, uint32_t n);

/* Drop equal neighbours from a sorted record array in place; returns the
 * surviving count. Equal hashes are the same domain from two feeds, or a
 * genuine collision — both collapse to one entry either way. */
uint32_t bl_dedup_records(uint8_t *recs, uint32_t n);

/* Binary-search a sorted record array. Used for the extra-feed dedup against
 * the sorted prefix, so an entry carried by two feeds costs no capacity. */
bool bl_records_contain(const uint8_t *recs, uint32_t n, uint64_t h40);

/*
 * Sort a[0..n) ascending and drop duplicates; returns the surviving count.
 * The result is always at a[0..count).
 *
 * 'cap' is the record capacity of the whole buffer a[] belongs to, and the
 * scratch geometry turns on it: when 2n <= cap the array's own free tail
 * (a+n .. a+2n) is disjoint scratch for the radix sort; beyond that there is no
 * tail left and the slower in-place qsort runs. Because the radix pass count is
 * odd the sorted data lands in the scratch half, and this moves it back to the
 * front so callers can always treat a[0..count) as the answer.
 *
 * PRECONDITION: 'a' is the BASE of a cap-record buffer. Passing a sub-array
 * makes the tail-scratch bound a lie and corrupts whatever follows.
 */
uint32_t bl_sort_dedup(uint8_t *a, uint32_t cap, uint32_t n);

/*
 * Fold the raw chunk a[p..n) into the sorted, deduped prefix a[0..p) and return
 * the new total. Sorts only the chunk, then merges in O(p+m'), instead of
 * re-sorting the whole array once per feed.
 *
 * All bounds are in RECORDS, and 'cap' is the buffer's record capacity.
 * Re-deriving any of this in bytes is the easy way to corrupt the function.
 */
uint32_t bl_fold_sorted_chunk(uint8_t *a, uint32_t cap, uint32_t p, uint32_t n);

/*
 * Convert a sorted, deduped record array into a live image.
 *
 * Reads n records from 'sorted' and writes BL_IMAGE_BYTES(n) to 'image'.
 * Wave 1 always calls this with disjoint buffers (staging -> image), which is
 * why there is no aliasing contract here to get wrong. Returns n.
 */
uint32_t bl_build_image(const uint8_t *sorted, uint32_t n, uint8_t *image);

/* ── Live-image lookup ───────────────────────────────────────────── */
/* The verdict call on the L2 fast path; IRAM_ATTR is on the definition. */
bool bl_image_contains(const uint8_t *image, uint64_t h40);

/* Entry count recorded in an image's index sentinel. */
uint32_t bl_image_count(const uint8_t *image);

/*
 * Structural check on an image loaded from untrusted bytes (the SD snapshot).
 *
 * This is not paranoia about the format, it is about where the bounds now come
 * from. The predecessor derived its binary-search bounds from a validated
 * count, so corrupt DATA could only ever produce a wrong verdict. Here the
 * bounds are idx[b]/idx[b+1], read straight out of the file: a partial write or
 * bit rot that leaves the header intact can hand bl_image_contains a range of
 * 0..0xFFFFFFFF, and it will probe gigabytes past the buffer -- from the L2 RX
 * hook, on every query, i.e. a crash loop that survives reboots because the bad
 * file does. So the index is checked once, at load, before anything can read it.
 */
bool bl_image_valid(const uint8_t *image, uint32_t count);

#ifdef __cplusplus
}
#endif
