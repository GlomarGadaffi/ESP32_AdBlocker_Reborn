#pragma once
/*
 * Forward (result) cache with zero ESP-IDF dependencies.
 *
 * Moved out of dns_server.cpp so the key compare, set/way choice, TTL / stale
 * decisions, eviction, seqlock read and the SD snapshot record codec can be
 * compiled and tested on the host. This is a MOVE: behaviour is exactly what
 * dns_server.cpp had. Storage is caller-supplied (zeroed, e.g. PSRAM
 * heap_caps_calloc), time is an argument, and the blocklist generation is an
 * argument too (callers read blocklist_generation() once and pass it in).
 *
 * Threading is unchanged: the dns_task is the only writer; the L2 RX task
 * reads through fwd_cache_l2_get() under a seqlock (seq odd = write in
 * progress). The seqlock is a plain uint32_t accessed with __atomic builtins
 * (relaxed load/store + explicit release/acquire fences) - the same orderings
 * the std::atomic<uint32_t> + std::atomic_thread_fence code used, without
 * dragging <stdatomic.h> into C++ translation units.
 *
 * IRAM_ATTR is on the DEFINITIONS in fwd_cache.c only (CONTRIBUTING.md §4).
 */
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FWD_CACHE_WAYS     4
#define FWD_CACHE_SETS     512    /* power of two; 4x512 = 2048 entries ~ 1.1MB PSRAM */
#define FWD_CACHE_ENTRIES  (FWD_CACHE_WAYS * FWD_CACHE_SETS)
#define FWD_RESP_MAX       512
#define FWD_TTL_MIN_S      10u
#define FWD_TTL_MAX_S      3600u
/* Serve-stale (#68, RFC 8767): window past expiry, and the TTL answers are
 * clamped to when replayed stale. */
#define FWD_STALE_MAX_S    86400u
#define FWD_STALE_TTL_S    30u

#define FWD_DNS_HDR_LEN    12

/* SD warm-boot snapshot (#79): header then count x (record + resp[]). */
#define FWD_SNAP_MAGIC     0xFDCACE01u
#define FWD_SNAP_HDR_SZ    12   /* magic u32 | count u32 | entry_max u16 | rsv u16 */
#define FWD_SNAP_REC_SZ    8    /* key_hash u32 | qtype u16 | resp_len u16 | resp[] */

typedef struct fwd_entry {
    uint32_t   key_hash;
    uint64_t   ttl_deadline_ms;       /* monotonic ms, 64-bit, no 49-day wrap (#30) */
    bool       valid;
    bool       blocked;
    uint16_t   qtype;
    uint16_t   resp_len;              /* allowed: cached raw response length (0 = blocked) */
    uint16_t   qn_len;                /* wire length of the question name at resp[12..].
                                         key_hash only picks the set: a hit also has to be
                                         this exact name (dns_qname_wire_eq). Blocked entries
                                         (resp_len 0) store just the name there. */
    uint64_t   refresh_after_ms;      /* stale-refresh rate gate; dns_task only, not read by
                                         the L2 path so no seqlock needed */
    uint32_t   load_gen;              /* blocklist generation as of the VERDICT that
                                         authorised this entry (#85); a lookup under a newer
                                         generation is a miss. Passed in by the store's
                                         caller, never re-read at store time. */
    bool       restored;              /* came from the SD snapshot and no live store has
                                         replaced it since. Its load_gen is only as good as
                                         the last fwd_cache_restored_adopt(); see there. */
    uint8_t    resp[FWD_RESP_MAX];    /* allowed: raw upstream response */
} fwd_entry_t;

typedef struct fwd_cache {
    fwd_entry_t *e;          /* caller-supplied, zero-filled, `entries` long */
    uint32_t     entries;    /* FWD_CACHE_WAYS x power-of-two sets */
    uint32_t     set_mask;   /* sets - 1 */
    uint32_t     seq;        /* seqlock; odd during a write. __atomic access only */
    uint32_t     evict;      /* still-useful entries evicted by a colliding store */
    uint32_t     toobig;     /* responses skipped: len > FWD_RESP_MAX */
} fwd_cache_t;

/* buf must be zero-filled. entries must be FWD_CACHE_WAYS x a power of two.
 * Counters are zeroed. Returns false (cache left unusable) on bad arguments. */
bool fwd_cache_init(fwd_cache_t *c, fwd_entry_t *buf, uint32_t entries);

/* Seqlock write bracket. Stores call these themselves; the warm-boot load
 * wraps its whole loop in one bracket (boot only - see dns_server.cpp). */
void fwd_cache_write_begin(fwd_cache_t *c);
void fwd_cache_write_end(fwd_cache_t *c);

/* Fresh hit: valid, same key, deadline > now_ms, load_gen == gen. */
fwd_entry_t *fwd_cache_lookup(fwd_cache_t *c, uint32_t h, uint16_t qtype,
                              const uint8_t *qn, int qn_len, uint64_t now_ms, uint32_t gen);
/* Expired ALLOWED entry still inside FWD_STALE_MAX_S, same generation. */
fwd_entry_t *fwd_cache_lookup_stale(fwd_cache_t *c, uint32_t h, uint16_t qtype,
                                    const uint8_t *qn, int qn_len, uint64_t now_ms, uint32_t gen);
/* The way a store for the key must write (own way > invalid > earliest end);
 * bumps c->evict when it displaces a still-useful entry. */
fwd_entry_t *fwd_cache_victim(fwd_cache_t *c, uint32_t h, uint16_t qtype,
                              const uint8_t *qn, int qn_len, uint64_t now_ms);

void fwd_cache_store_blocked(fwd_cache_t *c, uint32_t h, uint16_t qtype,
                             const uint8_t *qn, int qn_len,
                             uint32_t ttl_s, uint64_t now_ms, uint32_t load_gen);
/* Rejects len <= 0 silently, len > FWD_RESP_MAX (counts c->toobig) and a
 * response whose question name does not parse. */
void fwd_cache_store_resp(fwd_cache_t *c, uint32_t h, uint16_t qtype,
                          const uint8_t *resp, int len,
                          uint32_t ttl_s, uint64_t now_ms, uint32_t load_gen);

/* L2 fast-path read (eth-RX task). Copies the fresh ALLOWED response into out
 * and returns its length, or -1 on miss / expired / blocked / generation
 * mismatch / writer mid-update / raced. Never retries. */
int fwd_cache_l2_get(fwd_cache_t *c, uint32_t h, uint16_t qtype,
                     const uint8_t *qn, int qn_len, uint64_t now_ms, uint32_t gen,
                     uint8_t *out, int out_cap);

/* Stale-refresh rate gate. arm: true (and gate pushed to now+hold_ms) when
 * now_ms >= refresh_after_ms. disarm: reopen the gate (table full -> retry
 * on the next hit). */
bool fwd_cache_refresh_arm(fwd_entry_t *e, uint64_t now_ms, uint32_t hold_ms);
void fwd_cache_refresh_disarm(fwd_entry_t *e);

/* ── SD snapshot ─────────────────────────────────────────────────── */
/* Read entry idx under the seqlock for saving (any task). True and the
 * outputs filled only for a valid ALLOWED entry whose copy was not raced and
 * whose stale window has not ended. snap must hold FWD_RESP_MAX bytes. */
bool fwd_cache_snap_read(fwd_cache_t *c, uint32_t idx, uint64_t now_ms, uint8_t *snap,
                         uint32_t *h, uint16_t *qtype, uint16_t *resp_len);
/* Warm-boot insert of one restored response: stored expired-but-inside-the-
 * stale-window (deadline 1), gate open, marked restored and stamped with a
 * generation that is NOT gen_now, so no lookup serves it until the caller has
 * taken a verdict for it (below). False when the question name does not
 * parse (caller skips it). Caller holds the write bracket. */
bool fwd_cache_load_insert(fwd_cache_t *c, uint32_t h, uint16_t qtype,
                           const uint8_t *resp, uint16_t resp_len, uint64_t now_ms,
                           uint32_t gen_now);

/* Restored entries carry no verdict: the snapshot was taken under another
 * boot's blocklist. Serve-stale trusts load_gen instead of asking the
 * blocklist, so the caller must ask on the entry's behalf before the lookup:
 *   e = fwd_cache_restored_pending(..., gen)   - restored, inside the stale
 *       window, and not yet adopted under gen (NULL otherwise);
 *   take the verdict for the name (and the stored answer's CNAME chain);
 *   allowed -> fwd_cache_restored_adopt(c, e, gen)  (gen read BEFORE the verdict)
 *   blocked -> fwd_cache_restored_drop(c, e).
 * A generation bump makes the entry pending again, so it is re-checked, not
 * lost: that is what keeps the warm set alive across the boot-time blocklist
 * load. Any live store to the way clears `restored`. dns_task only. */
fwd_entry_t *fwd_cache_restored_pending(fwd_cache_t *c, uint32_t h, uint16_t qtype,
                                        const uint8_t *qn, int qn_len, uint64_t now_ms,
                                        uint32_t gen);
void fwd_cache_restored_adopt(fwd_cache_t *c, fwd_entry_t *e, uint32_t gen);
void fwd_cache_restored_drop(fwd_cache_t *c, fwd_entry_t *e);

void fwd_cache_hdr_encode(uint8_t hdr[FWD_SNAP_HDR_SZ], uint32_t count);
void fwd_cache_count_encode(uint8_t out[4], uint32_t count);
/* False when truncated, wrong magic, wrong entry_max or count > max_entries.
 * The decoded fields are reported through the out-params whenever avail is
 * large enough, so the caller can log a rejection. */
bool fwd_cache_hdr_decode(const uint8_t *hdr, size_t avail, uint32_t max_entries,
                          uint32_t *count, uint32_t *magic, uint16_t *entry_max);
void fwd_cache_rec_encode(uint8_t rec[FWD_SNAP_REC_SZ], uint32_t h, uint16_t qtype, uint16_t resp_len);
/* False when truncated or resp_len is 0 or > FWD_RESP_MAX. */
bool fwd_cache_rec_decode(const uint8_t *rec, size_t avail,
                          uint32_t *h, uint16_t *qtype, uint16_t *resp_len);

#ifdef __cplusplus
}
#endif
