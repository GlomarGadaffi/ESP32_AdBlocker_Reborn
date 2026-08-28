#include "dns_server.h"
#include "blocklist.h"
#include "domain.h"
#include "rewrite.h"
#include "acl.h"
#include "dot.h"
#include "query_log.h"
#include "timesync.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "esp_random.h"
#include "esp_attr.h"
#include "lwip/sockets.h"
#include <fcntl.h>
#include <cstring>
#include <cstdio>
#include <cerrno>
#include <cinttypes>
#include <atomic>
#include <sys/select.h>

static const char *TAG = "dns_server";

/* ── Metrics: lock-free counters + power-of-2 µs histograms ───────── */
/* Single dns_task writes; httpd task reads. 32-bit aligned reads are
 * atomic enough on Xtensa for monitoring purposes (no tearing concern). */
struct Hist {
    uint32_t bucket[48];   /* bucket i ≈ [2^(i-1), 2^i) µs */
    uint32_t count;
    uint32_t max_us;
};
static Hist s_h_blocked, s_h_cached, s_h_fwd_total, s_h_fwd_rtt, s_h_fwd_ourovh;
static Hist s_h_lookup;   /* blocklist_is_blocked() span only (CPU, no SPI/net) */
static Hist s_h_sendto;   /* the blocked-response sendto() call alone (lwIP TX path) */

/* Single writer (dns_task), single reader (httpd). Aligned 32-bit access is
 * atomic on Xtensa; plain uint32_t avoids the C++20 volatile-increment ban. */
static uint32_t s_cnt_total        = 0;
static uint32_t s_cnt_blocked      = 0;
static uint32_t s_cnt_forwarded    = 0;
static volatile bool s_reset_req   = false;  /* set by httpd; cleared+executed by dns_task */
static uint32_t s_cnt_drop_table   = 0;  /* upstream table full */
static uint32_t s_cnt_mbox_pressure = 0; /* (#81) client-socket drain loop hit its
                                            per-wakeup cap with recvfrom() still
                                            succeeding — the mailbox had more queued
                                            than one wakeup could drain. lwIP doesn't
                                            expose UDP_RECVMBOX overflow directly; this
                                            is the derived signal the issue proposed.
                                            Undercounts queries actually lost past the
                                            mailbox depth (those never reach dns_task
                                            at all) but turns total silence into a
                                            visible pressure gauge. */
static uint32_t s_cnt_upstream_to  = 0;  /* upstream timeouts (evicted in_use) */
static uint32_t s_cnt_cache_probe  = 0;  /* result-cache lookups */
static uint32_t s_cnt_cache_hit    = 0;  /* result-cache hits */
static uint32_t s_cnt_cache_evict  = 0;  /* still-useful entries evicted by a colliding
                                            store — the set-associativity pressure gauge:
                                            near zero means WAYS×SETS is big enough */
static uint32_t s_cnt_cache_toobig = 0;  /* responses skipped: len > FWD_RESP_MAX. The
                                            evidence for (or against) a bigger resp[] */
static uint32_t s_cnt_stale        = 0;  /* serve-stale replays (#68) */
static uint32_t s_cnt_coalesced    = 0;  /* upstream queries avoided by single-flight (#76):
                                            waiters attached + refreshes suppressed */
static uint32_t s_cnt_hedges_sent  = 0;  /* hedged retransmits fired (#69) */
static uint32_t s_cnt_hedged_done  = 0;  /* flights completed after a hedge went out (#69).
                                            NOT "hedge wins": both copies carry the same
                                            txid, so which packet answered is unknowable
                                            by construction — rescues and wasted hedges
                                            count alike */
static TaskHandle_t      s_dns_task_handle  = nullptr;

static inline int hist_bucket(uint32_t us)
{
    if (us == 0) return 0;
    int b = 32 - __builtin_clz(us);   /* floor(log2)+1; us=1→1, 2..3→2, 4..7→3 ... */
    return (b < 48) ? b : 47;
}
static inline void hist_record(Hist *h, int64_t us)
{
    uint32_t v = (us < 0) ? 0 : (us > 0xFFFFFFFFLL ? 0xFFFFFFFFu : (uint32_t)us);
    h->bucket[hist_bucket(v)]++;
    h->count++;
    if (v > h->max_us) h->max_us = v;
}
static uint32_t hist_pctl(const Hist *h, double p)
{
    uint32_t tot = h->count;
    if (!tot) return 0;
    uint32_t target = (uint32_t)(tot * p);
    uint32_t cum = 0;
    for (int i = 0; i < 48; i++) {
        cum += h->bucket[i];
        if (cum >= target) return (i == 0) ? 0u : (1u << i);  /* upper edge µs */
    }
    return h->max_us;
}

/* ── DNS wire format structs (RFC 1035) ──────────────────────────── */
#pragma pack(push, 1)
struct DnsHeader {
    uint16_t id, flags, qdcount, ancount, nscount, arcount;
};
struct DnsAnswerHeader {
    uint16_t name_ptr, type, class_type;
    uint32_t ttl;
    uint16_t rdlength;
};
#pragma pack(pop)

static constexpr uint16_t DNS_FLAGS_RESPONSE   = 0x8400; /* QR=1 AA=1 */
static constexpr uint16_t DNS_FLAGS_NXDOMAIN   = 0x8403; /* QR=1 AA=1 RCODE=3 */
static constexpr uint32_t BLOCKED_TTL_S        = 10;
static constexpr int      UPSTREAM_PORT        = 53;
static constexpr uint32_t UPSTREAM_TIMEOUT_MS  = 3000;
static constexpr int      UPSTREAM_TABLE_SIZE  = 64;

/* TCP/53 (RFC 7766): required so a TC=1 answer has somewhere to land — without
 * it the client's mandated TCP retry hits RST and resolution either fails or
 * escapes to an unfiltered secondary resolver (completes #36 / #66). One
 * listener + one active connection (+2 against the lwIP socket budget), one
 * query per connection, everything non-blocking inside the dns_task loop. */
static constexpr uint32_t TCP_CONN_IDLE_MS = 3000;
static constexpr int      TCP_QUERY_MAX    = 768;

/* ── Result cache (PSRAM): blocked verdicts + full forwarded responses ─
 * 4-way set-associative. Blocked entries regenerate 0.0.0.0/::; allowed
 * entries store the raw upstream response and replay it (txid rewritten) so
 * repeat allowed queries are served locally instead of re-forwarding.
 *
 * Why associative: direct-mapped meant two hot domains landing on one slot
 * evicted each other forever — a hit-rate ceiling no slot count fixes for the
 * colliding pair. Four ways per set ends that, and 512 sets doubles capacity
 * on top (256 direct slots gave ~4% on diverse home traffic; 1024 was better).
 * Budget: 2048 × 544 B leaves ~490 KB PSRAM free measured post-boot — the old
 * "4 MB free" note here was stale. Every other PSRAM consumer allocates at
 * boot, so that headroom is steady-state; don't grow WAYS/SETS/FWD_RESP_MAX
 * without re-measuring. Storing raw wire bytes per entry — rather than parsed
 * records — is the layout Cloudflare's 1.1.1.1 cache rework converged on
 * (56% smaller, faster inserts/lookups), so the entry format stays as is. */
#define CACHE_WAYS     4
#define CACHE_SETS     512    /* power of two; 4×512 = 2048 entries ≈ 1.1MB PSRAM */
#define CACHE_ENTRIES  (CACHE_WAYS * CACHE_SETS)
#define FWD_RESP_MAX   512
#define FWD_TTL_MIN_S  10u
#define FWD_TTL_MAX_S  3600u

/* Serve-stale (#68, RFC 8767 / AdGuard "optimistic cache"): an expired allowed
 * entry is replayed immediately (answer TTLs clamped to STALE_TTL_S) and a
 * background refresh is forwarded upstream, so a repeat visitor never eats the
 * ~40ms cold path for a name we've resolved before. Stale window capped at
 * STALE_MAX_S past expiry; refresh launches are rate-limited per entry. */
#define STALE_MAX_S    86400u
#define STALE_TTL_S    30u
struct CacheEntry {
    uint32_t   key_hash;
    uint64_t   ttl_deadline_ms;       /* esp_timer ms — 64-bit, no 49-day wrap (#30) */
    bool       valid;
    bool       blocked;
    uint16_t   qtype;
    uint16_t   resp_len;              /* allowed: cached raw response length (0 = blocked) */
    uint64_t   refresh_after_ms;      /* stale-refresh rate gate; dns_task only, not
                                         read by the L2 path so no seqlock needed */
    uint8_t    resp[FWD_RESP_MAX];    /* allowed: raw upstream response */
};
static CacheEntry *s_cache = nullptr; /* CACHE_ENTRIES entries in PSRAM */

/* Seqlock for cross-task cache reads. The dns_task is the only writer; the L2
 * eth-RX task reads the cache from dns_cache_l2_get() (a different task/core).
 * Writers bump the counter odd→write→even; a reader that sees an odd value or a
 * changed value bails (treats it as a miss → passthrough to lwIP). The dns_task's
 * own cache_lookup() needs no seqlock — it never races itself. */
static std::atomic<uint32_t> s_cache_seq{0};

/* Live upstream address, published for /metrics (#80). The forwarding path
 * reads DnsSinkServer::_upstream_addr; this mirrors it so the httpd task can
 * report the value WITHOUT touching _upstream_ip, which set_upstream() writes
 * from other tasks and would be a torn read. Updated at exactly the two sites
 * that store _upstream_addr - keep them together. */
static std::atomic<uint32_t> s_upstream_addr_pub{0};

static inline void cache_write_begin(void)
{
    s_cache_seq.store(s_cache_seq.load(std::memory_order_relaxed) + 1, std::memory_order_relaxed);
    std::atomic_thread_fence(std::memory_order_release);
}
static inline void cache_write_end(void)
{
    std::atomic_thread_fence(std::memory_order_release);
    s_cache_seq.store(s_cache_seq.load(std::memory_order_relaxed) + 1, std::memory_order_relaxed);
}

static bool cache_init(void)
{
    s_cache = (CacheEntry *)heap_caps_calloc(CACHE_ENTRIES, sizeof(CacheEntry), MALLOC_CAP_SPIRAM);
    return s_cache != nullptr;
}
/* First entry of the set that (h, qtype) maps to; its CACHE_WAYS ways are
 * contiguous. qtype folded in as before, so A and AAAA live in separate sets. */
static inline CacheEntry *cache_set(uint32_t h, uint16_t qtype)
{
    return &s_cache[((h ^ ((uint32_t)qtype << 1)) & (CACHE_SETS - 1)) * CACHE_WAYS];
}
static CacheEntry *cache_lookup(uint32_t h, uint16_t qtype, uint64_t now_ms)
{
    CacheEntry *set = cache_set(h, qtype);
    for (int w = 0; w < CACHE_WAYS; w++) {
        CacheEntry *e = &set[w];
        if (e->valid && e->key_hash == h && e->qtype == qtype && e->ttl_deadline_ms > now_ms)
            return e;
    }
    return nullptr;
}
/* The way a store for (h, qtype) must write. Priority: the key's OWN way if it
 * already has one — writing anywhere else would leave two live entries for one
 * key, and lookups could keep returning the outdated twin — then an invalid
 * way, then the way whose usefulness ends soonest. "Usefulness" is not the TTL
 * deadline alone: an expired BLOCKED entry is already worthless (re-blocking
 * is microseconds; cache_lookup_stale never serves them) while an expired
 * allowed entry still answers through the serve-stale window (#68), so blocked
 * entries compare at their deadline and allowed ones at deadline + STALE_MAX_S.
 * Evicting a still-useful entry bumps s_cnt_cache_evict — the gauge that says
 * whether WAYS×SETS is actually big enough for the traffic. */
static CacheEntry *cache_victim(uint32_t h, uint16_t qtype, uint64_t now_ms)
{
    CacheEntry *set = cache_set(h, qtype);
    CacheEntry *victim = &set[0];
    uint64_t victim_end = UINT64_MAX;
    for (int w = 0; w < CACHE_WAYS; w++) {
        CacheEntry *e = &set[w];
        if (e->valid && e->key_hash == h && e->qtype == qtype)
            return e;                          /* overwrite in place */
        uint64_t end = !e->valid ? 0
            : e->ttl_deadline_ms + (e->blocked ? 0 : (uint64_t)STALE_MAX_S * 1000u);
        if (end < victim_end) { victim = e; victim_end = end; }
    }
    if (victim->valid && victim_end > now_ms)
        s_cnt_cache_evict++;
    return victim;
}
static void cache_store_blocked(uint32_t h, uint16_t qtype, uint32_t ttl_s, uint64_t now_ms)
{
    CacheEntry *e = cache_victim(h, qtype, now_ms);
    cache_write_begin();
    e->key_hash = h; e->qtype = qtype; e->blocked = true; e->valid = true;
    e->resp_len = 0;
    e->ttl_deadline_ms = now_ms + (uint64_t)ttl_s * 1000u;
    cache_write_end();
}
static void cache_store_resp(uint32_t h, uint16_t qtype, const uint8_t *resp, int len,
                             uint32_t ttl_s, uint64_t now_ms)
{
    if (len <= 0) return;
    if (len > FWD_RESP_MAX) { s_cnt_cache_toobig++; return; }
    CacheEntry *e = cache_victim(h, qtype, now_ms);
    cache_write_begin();
    e->key_hash = h; e->qtype = qtype; e->blocked = false; e->valid = true;
    e->resp_len = (uint16_t)len;
    memcpy(e->resp, resp, len);
    e->ttl_deadline_ms   = now_ms + (uint64_t)ttl_s * 1000u;
    e->refresh_after_ms  = 0;
    cache_write_end();
}

/* Serve-stale lookup (#68): expired ALLOWED entry within the stale window.
 * Fresh entries are cache_lookup()'s job; expired blocked entries stay misses
 * (re-blocking via the blocklist is microseconds — no staleness needed). */
static CacheEntry *cache_lookup_stale(uint32_t h, uint16_t qtype, uint64_t now_ms)
{
    CacheEntry *set = cache_set(h, qtype);
    for (int w = 0; w < CACHE_WAYS; w++) {
        CacheEntry *e = &set[w];
        if (e->valid && !e->blocked && e->resp_len > 0 &&
            e->key_hash == h && e->qtype == qtype &&
            e->ttl_deadline_ms <= now_ms &&
            e->ttl_deadline_ms + (uint64_t)STALE_MAX_S * 1000u > now_ms)
            return e;
    }
    return nullptr;
}

static bool skip_name(const uint8_t *pkt, int len, int *off);   /* defined below */

/* Rewrite every RR TTL in a response to ttl_s (RFC 8767: serve stale data
 * with a short TTL so clients re-ask soon). Walks an+ns+ar like
 * dns_resp_min_ttl; on any malformed step it stops, leaving later TTLs
 * untouched — harmless, the response was already served as-is before. */
static void rewrite_answer_ttls(uint8_t *pkt, int len, uint32_t ttl_s)
{
    if (len < 12) return;
    int rrs = ((pkt[6] << 8) | pkt[7]) + ((pkt[8] << 8) | pkt[9]) +
              ((pkt[10] << 8) | pkt[11]);
    int off = 12;
    if (!skip_name(pkt, len, &off)) return;
    off += 4;                                   /* qtype + qclass */
    for (int i = 0; i < rrs; i++) {
        if (off > len || !skip_name(pkt, len, &off)) return;
        if (off + 10 > len) return;
        pkt[off + 4] = (uint8_t)(ttl_s >> 24);
        pkt[off + 5] = (uint8_t)(ttl_s >> 16);
        pkt[off + 6] = (uint8_t)(ttl_s >> 8);
        pkt[off + 7] = (uint8_t)(ttl_s);
        uint16_t rdlen = ((uint16_t)pkt[off + 8] << 8) | pkt[off + 9];
        off += 10 + rdlen;
    }
}

/* L2 fast-path cache read (called from the eth-RX task). Seqlock-protected.
 * Copies the cached ALLOWED response for (qhash,qtype) into out (caller patches
 * the txid + builds the frame). Returns the DNS length, or -1 on miss / expired /
 * blocked-entry / write-race. Blocked domains are handled by the blocklist check
 * in the L2 hook, so we only replay allowed (forward-cached) responses here. */
extern "C" int IRAM_ATTR dns_cache_l2_get(uint32_t qhash, uint16_t qtype, uint8_t *out, int out_cap)
{
    if (!s_cache || !out) return -1;
    uint64_t now_ms = (uint64_t)(esp_timer_get_time() / 1000);
    CacheEntry *set = cache_set(qhash, qtype);

    uint32_t s1 = s_cache_seq.load(std::memory_order_relaxed);
    if (s1 & 1u) return -1;                       /* writer mid-update */
    std::atomic_thread_fence(std::memory_order_acquire);

    /* Scan the whole set inside ONE seqlock window: a mid-scan write would
     * invalidate any way we matched, and the single end check catches it. */
    int len = -1;
    for (int w = 0; w < CACHE_WAYS; w++) {
        CacheEntry *e = &set[w];
        if (!e->valid || e->blocked || e->key_hash != qhash || e->qtype != qtype) continue;
        if (e->ttl_deadline_ms <= now_ms) continue;  /* expired */
        int l = e->resp_len;
        if (l <= 0 || l > out_cap || l > FWD_RESP_MAX) continue;
        memcpy(out, e->resp, (size_t)l);
        len = l;
        break;
    }
    if (len < 0) return -1;

    std::atomic_thread_fence(std::memory_order_acquire);
    if (s_cache_seq.load(std::memory_order_relaxed) != s1) return -1; /* raced */
    return len;
}

/* --- SD warm-boot for the forward cache (#79) -------------------------
 * TTL deadlines are esp_timer monotonic milliseconds and are meaningless
 * across a reset, so they are deliberately NOT persisted. Restored entries
 * come back marked expired-but-inside-the-stale-window, which hands the
 * whole job to the serve-stale machinery (#68): the first touch of a
 * remembered domain answers in ~2ms with TTLs clamped to STALE_TTL_S and
 * fires the normal background refresh. No new delivery path, and the worst
 * case is exactly what RFC 8767 already permits. */
#define FWDCACHE_PATH   "/sdcard/fwdcache.bin"
#define FWDCACHE_TMP    "/sdcard/fwdcache.tmp"
#define FWDCACHE_MAGIC  0xFDCACE01u
#define FWDCACHE_HDR_SZ 12   /* magic u32 | count u32 | entry_max u16 | rsv u16 */
#define FWDCACHE_REC_SZ 8    /* key_hash u32 | qtype u16 | resp_len u16 | resp[] */

/* Explicit little-endian field IO. The struct layouts happen to be
 * padding-free on ILP32 Xtensa, but an on-disk format should not lean on it. */
static inline void fc_put_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
}
static inline void fc_put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;         p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static inline uint16_t fc_get_u16(const uint8_t *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}
static inline uint32_t fc_get_u32(const uint8_t *p)
{
    return (uint32_t)p[0]         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Restore the snapshot. Called from run_loop() immediately after cache_init(),
 * by which point sd_mount() has already run (dns_sink.cpp mounts the card
 * before starting this task). A missing file is the normal cold-boot path. */
static void cache_load_sd(void)
{
    FILE *f = fopen(FWDCACHE_PATH, "rb");
    if (!f) return;

    uint8_t hdr[FWDCACHE_HDR_SZ];
    if (fread(hdr, 1, sizeof(hdr), f) != sizeof(hdr)) { fclose(f); return; }

    uint32_t magic = fc_get_u32(hdr);
    uint32_t count = fc_get_u32(hdr + 4);
    uint16_t emax  = fc_get_u16(hdr + 8);
    /* count > CACHE_ENTRIES is impossible from a good save (at most one record
     * per entry), so it means corruption or a format change. A pre-associative
     * snapshot (≤1024 records, same entry_max) still loads fine: records carry
     * their own key_hash and are re-inserted through cache_victim below. */
    if (magic != FWDCACHE_MAGIC || emax != FWD_RESP_MAX || count > CACHE_ENTRIES) {
        ESP_LOGW(TAG, "warm boot: snapshot rejected (magic %08" PRIx32 ", count %" PRIu32
                      ", entry_max %u)", magic, count, (unsigned)emax);
        fclose(f);
        return;
    }

    /* One seqlock bracket for the entire load. Safe ONLY because this runs at
     * boot against a freshly calloc-ed cache: an L2 reader seeing the odd
     * counter bails to lwIP, and there is nothing servable to bail out of yet.
     * Do NOT reuse this shape for a mid-life reload. */
    cache_write_begin();
    uint32_t loaded = 0;
    const uint64_t now_ms = (uint64_t)(esp_timer_get_time() / 1000);
    for (uint32_t i = 0; i < count; i++) {
        uint8_t rec[FWDCACHE_REC_SZ];
        if (fread(rec, 1, sizeof(rec), f) != sizeof(rec)) break;   /* truncated */

        uint32_t h        = fc_get_u32(rec);
        uint16_t qtype    = fc_get_u16(rec + 4);
        uint16_t resp_len = fc_get_u16(rec + 6);
        if (resp_len == 0 || resp_len > FWD_RESP_MAX) break;       /* corrupt */

        /* Freshly calloc-ed cache → this lands on an invalid way (a good save
         * has at most CACHE_WAYS records per set; an old direct-mapped one at
         * most 2). Only a corrupt file can force a real eviction here. */
        CacheEntry *e = cache_victim(h, qtype, now_ms);
        if (fread(e->resp, 1, resp_len, f) != resp_len) {
            e->valid = false;      /* partial read - do not leave a torn slot live */
            break;
        }
        e->key_hash         = h;
        e->qtype            = qtype;
        e->resp_len         = resp_len;
        e->blocked          = false;
        e->valid            = true;
        e->ttl_deadline_ms  = 1;   /* expired, but inside the STALE_MAX_S window */
        e->refresh_after_ms = 0;   /* first touch is free to refresh at once */
        loaded++;
    }
    cache_write_end();
    fclose(f);

    ESP_LOGI(TAG, "warm boot: %" PRIu32 " cached responses loaded stale from SD", loaded);
}

extern "C" void dns_server_cache_save(void)
{
    if (!s_cache) return;

    FILE *f = fopen(FWDCACHE_TMP, "wb");
    if (!f) { ESP_LOGW(TAG, "cache save: open %s failed (%d)", FWDCACHE_TMP, errno); return; }

    uint8_t hdr[FWDCACHE_HDR_SZ];
    fc_put_u32(hdr, FWDCACHE_MAGIC);
    fc_put_u32(hdr + 4, 0);                  /* count patched in at the end */
    fc_put_u16(hdr + 8, FWD_RESP_MAX);
    fc_put_u16(hdr + 10, 0);
    if (fwrite(hdr, 1, sizeof(hdr), f) != sizeof(hdr)) {
        fclose(f); remove(FWDCACHE_TMP); return;
    }

    /* This runs in download_task while dns_task may be writing, so each entry
     * is copied under the same seqlock protocol as dns_cache_l2_get() and
     * written to SD OUTSIDE the window - an fwrite inside it would race on
     * essentially every entry. Static buffer: single caller, not re-entrant. */
    static uint8_t s_snap[FWD_RESP_MAX];
    const uint64_t now_ms = (uint64_t)(esp_timer_get_time() / 1000);
    uint32_t saved = 0;

    for (int i = 0; i < CACHE_ENTRIES; i++) {
        CacheEntry *e = &s_cache[i];

        uint32_t s1 = s_cache_seq.load(std::memory_order_relaxed);
        if (s1 & 1u) continue;                        /* writer mid-update */
        std::atomic_thread_fence(std::memory_order_acquire);

        if (!e->valid || e->blocked) continue;
        uint32_t h        = e->key_hash;
        uint16_t qtype    = e->qtype;
        uint16_t resp_len = e->resp_len;
        uint64_t deadline = e->ttl_deadline_ms;
        if (resp_len == 0 || resp_len > FWD_RESP_MAX) continue;
        memcpy(s_snap, e->resp, resp_len);

        std::atomic_thread_fence(std::memory_order_acquire);
        if (s_cache_seq.load(std::memory_order_relaxed) != s1) continue;   /* raced */

        /* Drop entries already past their stale window: restoring one would
         * serve data older than the STALE_MAX_S contract the runtime enforces
         * everywhere else. (Not in the written #79 design - added here.) */
        if (deadline + (uint64_t)STALE_MAX_S * 1000u <= now_ms) continue;

        uint8_t rec[FWDCACHE_REC_SZ];
        fc_put_u32(rec, h);
        fc_put_u16(rec + 4, qtype);
        fc_put_u16(rec + 6, resp_len);
        if (fwrite(rec, 1, sizeof(rec), f) != sizeof(rec)) break;
        if (fwrite(s_snap, 1, resp_len, f) != resp_len)     break;
        saved++;
    }

    /* Patch the real count in last, so a crash mid-write leaves a tmp file
     * that either never gets renamed or still reads as count 0. */
    if (fseek(f, 4, SEEK_SET) == 0) {
        uint8_t cnt[4];
        fc_put_u32(cnt, saved);
        fwrite(cnt, 1, sizeof(cnt), f);
    }
    fclose(f);

    /* FatFs f_rename() returns FR_EXIST when the destination exists - unlike
     * POSIX rename(), and the ESP-IDF vfs_fat_rename() wrapper passes that
     * straight through. Without this remove(), the FIRST save succeeds and
     * every save after it fails. Losing the old snapshot in the gap costs one
     * cold boot, which is exactly the pre-#79 status quo. */
    remove(FWDCACHE_PATH);
    if (rename(FWDCACHE_TMP, FWDCACHE_PATH) != 0) {
        ESP_LOGW(TAG, "cache save: rename failed (%d) - snapshot dropped", errno);
        remove(FWDCACHE_TMP);
        return;
    }
    ESP_LOGI(TAG, "cache saved: %" PRIu32 " responses to SD", saved);
}

/* Skip a DNS name (label walk + compression pointer) at *off; advance *off past it.
 * Returns false if the packet is malformed. */
static bool skip_name(const uint8_t *pkt, int len, int *off)
{
    while (*off < len) {
        uint8_t b = pkt[*off];
        if (b == 0)          { (*off)++;        return true; }
        if ((b & 0xC0) == 0xC0) { (*off) += 2; return true; }
        if ((b & 0xC0) != 0) return false;     /* reserved label length */
        *off += 1 + b;
    }
    return false;
}

/* Parse the minimum TTL for caching:
 * - NOERROR with answers: min TTL across all answer RRs.
 * - NXDOMAIN (ancount=0): SOA minimum from authority section (RFC 2308 §5). */
static uint32_t dns_resp_min_ttl(const uint8_t *pkt, int len, uint32_t deflt)
{
    if (len < 12) return deflt;
    int ancount = (pkt[6] << 8) | pkt[7];
    int nscount = (pkt[8] << 8) | pkt[9];

    /* Skip question section */
    int off = 12;
    if (!skip_name(pkt, len, &off)) return deflt;
    if (off + 4 > len) return deflt;
    off += 4;  /* qtype + qclass */

    uint32_t minttl = 0xFFFFFFFFu;

    if (ancount > 0) {
        /* NOERROR: collect min TTL across answer RRs */
        for (int i = 0; i < ancount; i++) {
            if (!skip_name(pkt, len, &off)) break;
            if (off + 10 > len) break;
            uint32_t ttl = ((uint32_t)pkt[off+4] << 24) | ((uint32_t)pkt[off+5] << 16)
                         | ((uint32_t)pkt[off+6] << 8)  |  (uint32_t)pkt[off+7];
            uint16_t rdlen = ((uint16_t)pkt[off+8] << 8) | pkt[off+9];
            if (ttl < minttl) minttl = ttl;
            off += 10 + rdlen;
        }
    } else if (nscount > 0) {
        /* NXDOMAIN: look for SOA in authority section (RFC 2308 §5) */
        for (int i = 0; i < nscount; i++) {
            if (!skip_name(pkt, len, &off)) break;
            if (off + 10 > len) break;
            uint16_t rtype = ((uint16_t)pkt[off+0] << 8) | pkt[off+1];
            uint32_t rttl  = ((uint32_t)pkt[off+4] << 24) | ((uint32_t)pkt[off+5] << 16)
                           | ((uint32_t)pkt[off+6] << 8)  |  (uint32_t)pkt[off+7];
            uint16_t rdlen = ((uint16_t)pkt[off+8] << 8) | pkt[off+9];
            off += 10;
            if (rtype == 6 && rdlen >= 20) {  /* SOA: skip MNAME+RNAME then read minimum */
                int roff = off;
                if (skip_name(pkt, len, &roff) && skip_name(pkt, len, &roff) &&
                    roff + 20 <= off + rdlen) {
                    /* SOA RDATA: serial(4) refresh(4) retry(4) expire(4) minimum(4) */
                    uint32_t soa_min = ((uint32_t)pkt[roff+16] << 24) | ((uint32_t)pkt[roff+17] << 16)
                                     | ((uint32_t)pkt[roff+18] << 8)  |  (uint32_t)pkt[roff+19];
                    uint32_t neg_ttl = rttl < soa_min ? rttl : soa_min;
                    if (neg_ttl < minttl) minttl = neg_ttl;
                }
            }
            off += rdlen;
        }
    }

    if (minttl == 0xFFFFFFFFu) return deflt;
    if (minttl < FWD_TTL_MIN_S) minttl = FWD_TTL_MIN_S;
    if (minttl > FWD_TTL_MAX_S) minttl = FWD_TTL_MAX_S;
    return minttl;
}

/* ── Upstream concurrent query table ─────────────────────────────── */
/* Single-flight coalescing (#76): N identical in-flight misses used to burn N
 * of the 64 slots, so a client retry loop or a LAN-wide burst on one cold name
 * exhausted the table and dropped unrelated queries. A duplicate now attaches
 * to the in-flight entry as a waiter and is answered from its one reply.
 * Waiters stay in internal RAM (no PSRAM): dns_task walks them on the hot path.
 * 4 rather than 6 keeps the added .bss at 8 KB. */
static constexpr int UPSTREAM_WAITERS_MAX = 4;
/* A join sends nothing upstream and inherits the entry's deadline, so only a
 * genuinely simultaneous burst may ride one. A client retry IS the recovery
 * path for a lost upstream datagram — one entry means one packet, and nothing
 * here retransmits — so a retry (stubs re-ask at ~1s) must still re-probe
 * upstream on its own slot the way it did before #76, rather than attach to a
 * flight that is already most of the way to its 3s eviction. */
static constexpr uint32_t UPSTREAM_JOIN_MAX_AGE_MS = 250;
struct UpstreamWaiter {
    struct sockaddr_in client_addr;
    int64_t          recv_us;        /* this waiter's own arrival — its own latency */
    uint32_t         tcp_gen;        /* s_tcp.gen when THIS waiter joined, not when
                                        the entry forwarded — see upstream_join */
    uint16_t         client_txid;
    bool             via_tcp;
};
struct UpstreamEntry {
    uint16_t         our_txid;
    uint16_t         client_txid;
    struct sockaddr_in client_addr;
    uint32_t         sent_ms;
    int64_t          recv_us;        /* esp_timer µs when client query received */
    int64_t          upstream_us;    /* esp_timer µs when forwarded upstream */
    uint32_t         qhash;          /* domain hash — to key the forward cache on reply */
    uint16_t         qtype;
    bool             in_use;
    bool             via_tcp;        /* reply goes to the TCP conn, not client_addr */
    bool             refresh_only;   /* stale-refresh (#68): cache the reply, deliver to no one */
    uint8_t          n_wait;         /* coalesced waiters (#76) */
    bool             hedged;         /* (#69) retransmit already fired — at most one per flight */
    uint16_t         hedge_qlen;     /* (#69) stashed wire bytes in s_hedge_q; 0 = not
                                        hedge-eligible (refresh_only, DoT flight, oversize
                                        query, or no stash RAM) */
    uint32_t         hedge_deadline_ms; /* (#69) absolute esp_timer ms; compared wrap-safe */
    uint32_t         env_hash;       /* (#76) the forwarded query's reply-shaping envelope —
                                        see query_env_hash; unset on refresh_only entries */
    uint32_t         tcp_gen;        /* s_tcp.gen at forward time — stale-conn detector */
    UpstreamWaiter   waiters[UPSTREAM_WAITERS_MAX];
};
static UpstreamEntry s_upstream[UPSTREAM_TABLE_SIZE];

/* ── TCP/53 connection state (dns_task only) ─────────────────────── */
struct TcpConn {
    int      fd;
    uint32_t gen;          /* bumped on every close; upstream entries snapshot it */
    int      have;
    bool     awaiting;     /* query forwarded upstream; conn held for the reply */
    uint64_t deadline_ms;
    uint32_t peer_ip;      /* host order, for ACL + query log */
    uint8_t  buf[2 + TCP_QUERY_MAX];
};
static TcpConn  s_tcp = { -1, 0, 0, false, 0, 0, {0} };
static uint32_t s_cnt_tcp = 0;

static void tcp_conn_close(void)
{
    if (s_tcp.fd != -1) { close(s_tcp.fd); s_tcp.fd = -1; }
    s_tcp.gen++;
    s_tcp.have = 0;
    s_tcp.awaiting = false;
}

/* Length-prefix + message assembled into one send (dns_task is the only
 * caller). A partial non-blocking send of ≤1502 B on a fresh connection
 * means the peer is wedged — treat it as failure; the caller closes. */
static bool tcp_send_dns(int fd, const uint8_t *msg, int len)
{
    static uint8_t frame[2 + 1500];
    if (len <= 0 || len > 1500) return false;
    frame[0] = (uint8_t)(len >> 8); frame[1] = (uint8_t)(len & 0xFF);
    memcpy(frame + 2, msg, len);
    return send(fd, frame, len + 2, MSG_DONTWAIT) == len + 2;
}

static bool txid_in_use(uint16_t t)
{
    for (int i = 0; i < UPSTREAM_TABLE_SIZE; i++)
        if (s_upstream[i].in_use && s_upstream[i].our_txid == t) return true;
    return false;
}

static UpstreamEntry *upstream_alloc(uint16_t *our_txid_out)
{
    for (int i = 0; i < UPSTREAM_TABLE_SIZE; i++) {
        if (!s_upstream[i].in_use) {
            /* Random txid (H2): a predictable sequential counter lets an
             * off-path attacker guess the in-flight txid and forge a cached
             * reply. esp_random() is the hardware RNG. Re-roll on the rare
             * collision with another in-flight query. */
            uint16_t t;
            do { t = (uint16_t)(esp_random() & 0xFFFFu); } while (t == 0 || txid_in_use(t));
            s_upstream[i].in_use       = true;
            s_upstream[i].our_txid     = t;
            s_upstream[i].via_tcp      = false;
            s_upstream[i].refresh_only = false;
            s_upstream[i].n_wait       = 0;   /* (#76) a recycled slot must not
                                                 fan out to its predecessor's waiters */
            s_upstream[i].hedged       = false; /* (#69) hedge state is per-flight: a stale
                                                   flag would suppress this flight's hedge,
                                                   a stale deadline+qlen would retransmit
                                                   the predecessor's question */
            s_upstream[i].hedge_qlen   = 0;
            s_upstream[i].hedge_deadline_ms = 0;
            *our_txid_out = t;
            return &s_upstream[i];
        }
    }
    return nullptr;  /* table full */
}
static UpstreamEntry *upstream_find(uint16_t our_txid)
{
    for (int i = 0; i < UPSTREAM_TABLE_SIZE; i++)
        if (s_upstream[i].in_use && s_upstream[i].our_txid == our_txid)
            return &s_upstream[i];
    return nullptr;
}
/* Is a real query for this question already in flight? Used only by #68's
 * stale-refresh suppression, which asks nothing more than that: any live entry
 * repopulates the cache slot, so the refresh has nothing left to do. The key is
 * (qhash, qtype) — identical to the forward cache's key, so a hash collision
 * mixes answers exactly as it already can there: no new failure class.
 * refresh_only entries stay excluded — refresh-vs-refresh is already
 * rate-limited by the caller's own refresh_after_ms gate. A requester looking
 * for an entry to RIDE wants upstream_find_joinable() below instead: riding
 * carries obligations to the joiner that mere suppression does not. */
static UpstreamEntry *upstream_find_inflight(uint32_t qhash, uint16_t qtype)
{
    for (int i = 0; i < UPSTREAM_TABLE_SIZE; i++)
        if (s_upstream[i].in_use && !s_upstream[i].refresh_only &&
            s_upstream[i].qhash == qhash && s_upstream[i].qtype == qtype)
            return &s_upstream[i];
    return nullptr;
}
/* (#76) Everything in a query that shapes the reply but is absent from the
 * (qhash, qtype) key: the header flags (RD/AD/CD) and the additional section
 * verbatim — the EDNS0 OPT RR with its advertised UDP payload size, the DO
 * bit, and any options (cookie, ECS). Upstream sizes and shapes its answer
 * against the query WE forwarded, and the fan-out hands that one packet to
 * every waiter with only the txid restamped, so two queries may share a flight
 * only when these bytes match. Without the check a >512 B reply built for an
 * EDNS0 primary reaches a waiter that advertised nothing above the RFC 1035
 * 512 B default (RFC 6891 §6.2.5) — a delivery the forward cache could never
 * make, since cache_store_resp rejects anything over FWD_RESP_MAX. */
static inline uint32_t query_env_hash(const uint8_t *q, int qlen, int qend)
{
    uint32_t seed = DOMAIN_HASH_SEED ^ (((uint32_t)q[2] << 8) | q[3]);
    return murmur3_32(q + qend, (size_t)(qlen - qend), seed);
}
/* The entry a duplicate may actually ride (#76). Three conditions beyond
 * upstream_find_inflight's, all of which matter only to a requester about to
 * attach itself — which is why #68's "is anything already in flight" question
 * keeps using the plainer helper above: a full, old or differently-enveloped
 * entry still repopulates the cache entry, so the refresh is still redundant.
 *   - Room in the waiter array. Returning a FULL entry let it shadow every
 *     joinable one for the same question: both scans start at index 0, so the
 *     first entry keeps the lowest index for its whole life and every further
 *     duplicate re-found it, failed to join, and burned a fresh slot — the
 *     table exhaustion #76 exists to stop, arriving four queries later.
 *   - Age, so a retry re-probes upstream instead of inheriting a nearly
 *     expired flight's silence (see UPSTREAM_JOIN_MAX_AGE_MS).
 *   - A matching reply-shaping envelope (see query_env_hash).
 * A miss is never a drop: the caller allocates its own slot exactly as it did
 * before the patch. */
static UpstreamEntry *upstream_find_joinable(uint32_t qhash, uint16_t qtype,
                                             uint32_t env_hash, uint32_t now_ms)
{
    for (int i = 0; i < UPSTREAM_TABLE_SIZE; i++)
        if (s_upstream[i].in_use && !s_upstream[i].refresh_only &&
            s_upstream[i].qhash == qhash && s_upstream[i].qtype == qtype &&
            s_upstream[i].env_hash == env_hash &&
            s_upstream[i].n_wait < UPSTREAM_WAITERS_MAX &&
            (now_ms - s_upstream[i].sent_ms) < UPSTREAM_JOIN_MAX_AGE_MS)
            return &s_upstream[i];
    return nullptr;
}
/* Attach a requester to an in-flight entry, to be served by the fan-out in
 * process_reply. False when the waiter array is full — the caller then
 * allocates a fresh slot exactly as before, so a full array degrades to
 * today's behaviour and never turns into a drop. tcp_gen is snapshotted here,
 * at the moment this requester is recorded, so a waiter that joined on a later
 * connection than the entry's own can never be delivered to the wrong one. */
static bool upstream_join(UpstreamEntry *ue, uint16_t client_txid,
                          const struct sockaddr_in *client_addr, int64_t recv_us,
                          bool via_tcp, uint32_t tcp_gen)
{
    if (ue->n_wait >= UPSTREAM_WAITERS_MAX) return false;
    UpstreamWaiter *w = &ue->waiters[ue->n_wait];
    if (client_addr) w->client_addr = *client_addr;
    else             memset(&w->client_addr, 0, sizeof(w->client_addr));
    w->recv_us     = recv_us;
    w->tcp_gen     = tcp_gen;
    w->client_txid = client_txid;
    w->via_tcp     = via_tcp;
    ue->n_wait++;
    s_cnt_coalesced++;
    return true;
}
static void upstream_evict_expired(uint32_t now_ms)
{
    for (int i = 0; i < UPSTREAM_TABLE_SIZE; i++)
        if (s_upstream[i].in_use && (now_ms - s_upstream[i].sent_ms) > UPSTREAM_TIMEOUT_MS) {
            s_upstream[i].in_use = false;
            s_cnt_upstream_to++;
        }
}
static int upstream_inflight(void)
{
    int n = 0;
    for (int i = 0; i < UPSTREAM_TABLE_SIZE; i++) if (s_upstream[i].in_use) n++;
    return n;
}

/* ── Hedged upstream retransmit (#69) ────────────────────────────── */
/* A lost upstream UDP datagram used to cost the full 3 s eviction unless the
 * client happened to retry — 104 such timeouts measured, every one masked by
 * serve-stale (#68), which is why nobody noticed. Once a flight has outlived
 * the observed p95 of upstream RTT, retransmit the same bytes once and keep
 * waiting. The hedge goes to the SAME upstream by necessity, not preference:
 * the #24 source-address filter in the reply drain rejects any datagram not
 * from _upstream_addr, so a hedge aimed at a second resolver would have its
 * reply silently discarded unless the anti-spoofing surface were widened —
 * which is why true dual-WAN racing stays a stretch goal. A same-upstream
 * hedge is a retransmit: the right medicine for packet loss (the observed
 * failure), useless against a wedged resolver.
 *
 * The stash lives in PSRAM (64 x 512 B = 32 KB): #76 just spent 8 KB of
 * internal .bss and left heap_free at ~35 KB, while psram_free sits at
 * ~1.49 MB. Allocation failure disables hedging and nothing else. */
static constexpr int HEDGE_QMAX = 512;   /* queries are question-sized (cf. DOT_REQ_MAX);
                                            anything bigger simply is not hedged */
static uint8_t *s_hedge_q = nullptr;     /* dns_task-private, like s_upstream — no lock */

/* Delay calibration. hist_pctl returns a bucket's UPPER EDGE, a power of two
 * in MICROSECONDS, while sent_ms and every deadline in this file are
 * MILLISECONDS — the conversion happens exactly once, below, in a variable
 * named for its unit. The result is quantized (…16, 32, 65, 131, 262 ms…),
 * not precise; the clamps bound that coarseness.
 *   - Floor: below the network's own jitter a hedge fires on healthy tail
 *     traffic and doubles upstream load for no rescue; on an upstream fast
 *     enough to hit the floor, anything slower than it is loss-shaped anyway.
 *   - Ceiling: the sweep can fire up to one select() tick (100 ms) late and
 *     eviction still measures its 3 s from the ORIGINAL sent_ms, so this cap
 *     leaves the hedge reply at least 3000 - 1500 - 100 = 1400 ms to land.
 *   - Sample gate: Hist carries a count field; below ~64 samples one straggler
 *     moves p95 a whole bucket (and hist_pctl degenerates toward 0 at tiny
 *     counts), so a fixed default holds until the histogram has substance.
 *     250 ms sits well above any healthy p95 seen on this deployment while
 *     still rescuing >90% of the 3 s budget. */
static constexpr uint32_t HEDGE_DELAY_DEFAULT_MS = 250;
static constexpr uint32_t HEDGE_DELAY_MIN_MS     = 25;
static constexpr uint32_t HEDGE_DELAY_MAX_MS     = 1500;
static constexpr uint32_t HEDGE_MIN_SAMPLES      = 64;
/* Above 3/4 occupancy the table is already reporting systemic trouble — a
 * query storm or a dead upstream — and doubling outbound packets can only
 * amplify exactly then, so hedging stops before it can. */
static constexpr int      HEDGE_INFLIGHT_MAX     = (UPSTREAM_TABLE_SIZE * 3) / 4;

static uint32_t hedge_delay_ms(void)
{
    if (s_h_fwd_rtt.count < HEDGE_MIN_SAMPLES) return HEDGE_DELAY_DEFAULT_MS;
    uint32_t p95_us   = hist_pctl(&s_h_fwd_rtt, 0.95);   /* MICROSECONDS */
    uint32_t delay_ms = p95_us / 1000u;                  /* µs → ms, the one conversion */
    if (delay_ms < HEDGE_DELAY_MIN_MS) delay_ms = HEDGE_DELAY_MIN_MS;
    if (delay_ms > HEDGE_DELAY_MAX_MS) delay_ms = HEDGE_DELAY_MAX_MS;
    return delay_ms;
}

/* Arm a flight for hedging. Called ONLY from the plain-UDP forward branches,
 * AFTER the txid rewrite, so the retransmit is a byte-identical copy of what
 * already went out — no new txid is minted. Both copies therefore resolve to
 * the same table entry: if both come back, the first reply frees the slot and
 * the second finds no entry via upstream_find() and is dropped (the `if (!ue)
 * return` at the top of process_reply). refresh_only entries never get here —
 * nobody is waiting on one, so rescuing it buys nothing and #68's refresh
 * gate simply re-arms on the next stale hit. DoT flights never get here
 * either (see the sweep in run_loop for why). */
static void hedge_stash(UpstreamEntry *ue, const uint8_t *q, int qlen, uint32_t now_ms)
{
    if (!s_hedge_q || qlen <= 0 || qlen > HEDGE_QMAX) return;
    memcpy(s_hedge_q + (size_t)(ue - s_upstream) * HEDGE_QMAX, q, (size_t)qlen);
    ue->hedge_qlen        = (uint16_t)qlen;
    ue->hedge_deadline_ms = now_ms + hedge_delay_ms();
}

/* ── DNS response builders ───────────────────────────────────────── */
static int build_blocked_a(const uint8_t *query, int qlen, uint8_t *out, int out_cap)
{
    if (qlen < (int)sizeof(DnsHeader) || out_cap < qlen + (int)sizeof(DnsAnswerHeader) + 4)
        return -1;
    memcpy(out, query, qlen);
    auto *hdr = reinterpret_cast<DnsHeader *>(out);
    hdr->flags   = htons(dns_resp_flags(ntohs(reinterpret_cast<const DnsHeader *>(query)->flags), 0));
    hdr->ancount = htons(1);
    hdr->nscount = 0;
    hdr->arcount = 0;
    DnsAnswerHeader ans{};
    ans.name_ptr  = htons(0xC00C);
    ans.type      = htons(1);    /* A */
    ans.class_type= htons(1);    /* IN */
    ans.ttl       = htonl(BLOCKED_TTL_S);
    ans.rdlength  = htons(4);
    uint8_t *p = out + qlen;
    memcpy(p, &ans, sizeof(ans)); p += sizeof(ans);
    memset(p, 0, 4);             /* 0.0.0.0 */
    return qlen + (int)sizeof(ans) + 4;
}

static int build_blocked_aaaa(const uint8_t *query, int qlen, uint8_t *out, int out_cap)
{
    if (qlen < (int)sizeof(DnsHeader) || out_cap < qlen + (int)sizeof(DnsAnswerHeader) + 16)
        return -1;
    memcpy(out, query, qlen);
    auto *hdr = reinterpret_cast<DnsHeader *>(out);
    hdr->flags   = htons(dns_resp_flags(ntohs(reinterpret_cast<const DnsHeader *>(query)->flags), 0));
    hdr->ancount = htons(1);
    hdr->nscount = 0;
    hdr->arcount = 0;
    DnsAnswerHeader ans{};
    ans.name_ptr  = htons(0xC00C);
    ans.type      = htons(28);   /* AAAA */
    ans.class_type= htons(1);    /* IN */
    ans.ttl       = htonl(BLOCKED_TTL_S);
    ans.rdlength  = htons(16);
    uint8_t *p = out + qlen;
    memcpy(p, &ans, sizeof(ans)); p += sizeof(ans);
    memset(p, 0, 16);            /* :: */
    return qlen + (int)sizeof(ans) + 16;
}

/* qtype dispatch for a blocked verdict: A → 0.0.0.0, AAAA → ::, else NXDOMAIN
 * with no answer RRs. Shared by the UDP path (cached + fresh verdicts) and the
 * TCP/53 path so all three agree forever. */
static int build_blocked_any(const uint8_t *query, int qend, uint16_t qtype,
                             uint8_t *out, int out_cap)
{
    if (qtype == 1)  return build_blocked_a   (query, qend, out, out_cap);
    if (qtype == 28) return build_blocked_aaaa(query, qend, out, out_cap);
    if (qend < (int)sizeof(DnsHeader) || qend > out_cap) return -1;
    memcpy(out, query, qend);
    auto *hdr = reinterpret_cast<DnsHeader *>(out);
    hdr->flags   = htons(DNS_FLAGS_NXDOMAIN);
    hdr->ancount = 0;
    hdr->nscount = 0;
    hdr->arcount = 0;
    return qend;
}

/* Synthesize the A response for a DNS-rewrite hit (#12): answer RR is a
 * pointer to the question name, IN A, TTL 300, rdata = rw_ip. */
static int build_rewrite_a(const uint8_t *query, int qend, uint32_t rw_ip,
                           uint8_t *out, int out_cap)
{
    if (qend < (int)sizeof(DnsHeader) || qend + 16 > out_cap) return -1;
    memcpy(out, query, qend);
    uint16_t qf = ((uint16_t)query[2] << 8) | query[3];
    uint16_t rf = dns_resp_flags(qf, 0);
    out[2] = rf >> 8; out[3] = rf & 0xFF;
    reinterpret_cast<DnsHeader *>(out)->ancount = htons(1);
    reinterpret_cast<DnsHeader *>(out)->nscount = 0;
    reinterpret_cast<DnsHeader *>(out)->arcount = 0;
    int p = qend;
    out[p++] = 0xC0; out[p++] = 0x0C; /* ptr to question name */
    out[p++] = 0x00; out[p++] = 0x01; /* A */
    out[p++] = 0x00; out[p++] = 0x01; /* IN */
    out[p++] = 0x00; out[p++] = 0x00; out[p++] = 0x01; out[p++] = 0x2C; /* TTL 300 */
    out[p++] = 0x00; out[p++] = 0x04; /* rdlength */
    out[p++] = (rw_ip >> 24) & 0xFF;
    out[p++] = (rw_ip >> 16) & 0xFF;
    out[p++] = (rw_ip >> 8)  & 0xFF;
    out[p++] =  rw_ip        & 0xFF;
    return p;
}


/* ── QNAME extraction from DNS query (label walking) ────────────── */
/* Returns offset past QNAME+QTYPE+QCLASS, or -1 on error.          */
/* Writes normalized domain name to name_out (up to name_cap bytes). */
static int extract_qname(const uint8_t *pkt, int pkt_len,
                          int offset, char *name_out, size_t name_cap,
                          size_t *name_len_out)
{
    char raw[256]; size_t raw_len = 0;
    /* label walk per RFC 1035 §4.1.2 */
    while (offset < pkt_len && pkt[offset] != 0) {
        uint8_t label_len = pkt[offset];
        /* A compression pointer in a question QNAME is malformed per RFC 1035
         * (questions don't use compression). Reject it, matching the L2 fast
         * path's stricter parser (L5). */
        if ((label_len & 0xC0) == 0xC0) return -1;
        if (label_len & 0xC0) return -1;           /* #42: 0x40-0xBF are reserved */
        if (offset + 1 + label_len >= pkt_len) return -1;
        if (raw_len + label_len + 1 >= sizeof(raw)) return -1;
        if (raw_len > 0) raw[raw_len++] = '.';
        memcpy(raw + raw_len, pkt + offset + 1, label_len);
        raw_len += label_len;
        offset  += 1 + label_len;
    }
    if (offset >= pkt_len) return -1;
    offset++;  /* skip null byte */
    if (offset + 4 > pkt_len) return -1;  /* QTYPE + QCLASS */

    size_t nlen = domain_normalize(name_out, name_cap, raw, raw_len);
    if (nlen == 0) return -1;
    *name_len_out = nlen;
    return offset + 4;  /* past QTYPE+QCLASS */
}

/* A TCP-origin query forwarded upstream over plain UDP with no EDNS gets
 * classic-truncated by the upstream resolver at 512 B (RFC 1035) exactly as
 * if it were a UDP client — except this client is already ON TCP, so a TC=1
 * reply is a dead end: nothing left to retry with. Fix: ask upstream for a
 * real answer by appending a bare EDNS0 OPT RR advertising a payload size
 * comfortably inside our own rx[1500] receive buffer, so upstream has no
 * reason to truncate. Only when the query doesn't already carry one — a
 * conservative arcount==0 check, since EDNS is normally the sole additional
 * record. Returns the new length, or the original mlen unchanged if there's
 * no room or the query already looks EDNS-equipped.
 * dst must have at least mlen + 11 bytes of room. */
static int append_bare_edns_opt(uint8_t *dst, const uint8_t *q, int mlen, int cap)
{
    auto *qh = reinterpret_cast<const DnsHeader *>(q);
    if (ntohs(qh->arcount) != 0 || mlen + 11 > cap) {
        memcpy(dst, q, mlen);
        return mlen;
    }
    memcpy(dst, q, mlen);
    uint8_t *opt = dst + mlen;
    opt[0] = 0x00;                                   /* root name */
    opt[1] = 0x00; opt[2] = 0x29;                     /* TYPE = OPT (41) */
    opt[3] = 0x04; opt[4] = 0x00;                     /* CLASS = UDP payload size 1024 */
    opt[5] = 0x00; opt[6] = 0x00; opt[7] = 0x00; opt[8] = 0x00; /* TTL: ext-rcode/version/flags = 0 */
    opt[9] = 0x00; opt[10] = 0x00;                    /* RDLENGTH = 0 */
    reinterpret_cast<DnsHeader *>(dst)->arcount = htons(1);
    return mlen + 11;
}

/* ── Main loop ───────────────────────────────────────────────────── */
DnsSinkServer::DnsSinkServer() : _exitSem(xSemaphoreCreateBinary()) {}

DnsSinkServer::~DnsSinkServer() {
    stop();
    if (_exitSem) { vSemaphoreDelete(_exitSem); _exitSem = nullptr; }
}

bool DnsSinkServer::start(const char *upstream_ip) {
    if (_running.load(std::memory_order_acquire)) return true;
    snprintf(_upstream_ip, sizeof(_upstream_ip), "%s", upstream_ip);
    _running.store(true, std::memory_order_release);
    if (_exitSem) xSemaphoreTake(_exitSem, 0);
    BaseType_t r = xTaskCreatePinnedToCore(dns_task, "dns_task", 12288, this, 10, &_taskHandle, 1);
    if (r != pdPASS) {
        ESP_LOGE(TAG, "task create failed");
        _running.store(false, std::memory_order_release);
        return false;
    }
    _taskStarted = true;
    return true;
}

void DnsSinkServer::set_upstream(const char *upstream_ip) {
    struct in_addr a{};
    if (!inet_aton(upstream_ip, &a)) return;
    snprintf(_upstream_ip, sizeof(_upstream_ip), "%s", upstream_ip);
    _upstream_addr.store(a.s_addr, std::memory_order_release);
    s_upstream_addr_pub.store(a.s_addr, std::memory_order_release);   /* #80 */
    ESP_LOGI(TAG, "Upstream re-pointed to %s", _upstream_ip);
}

void DnsSinkServer::upstream_ip(char *out, size_t cap) const {
    snprintf(out, cap, "%s", _upstream_ip);
}

void DnsSinkServer::stop() {
    _running.exchange(false, std::memory_order_acq_rel);
    int fd = _client_fd.exchange(-1, std::memory_order_acq_rel);
    if (fd != -1) { shutdown(fd, SHUT_RDWR); close(fd); }
    fd = _upstream_fd.exchange(-1, std::memory_order_acq_rel);
    if (fd != -1) { shutdown(fd, SHUT_RDWR); close(fd); }
    if (_taskStarted && _exitSem) {
        xSemaphoreTake(_exitSem, pdMS_TO_TICKS(1500));
        _taskStarted = false;
    }
    _taskHandle = nullptr;
}

static void do_metrics_reset(void);   /* forward decl — defined near metrics_reset */

void DnsSinkServer::dns_task(void *pv) {
    static_cast<DnsSinkServer *>(pv)->run_loop();
}

void DnsSinkServer::run_loop()
{
    s_dns_task_handle = xTaskGetCurrentTaskHandle();

    if (!cache_init()) {
        ESP_LOGE(TAG, "PSRAM result cache alloc failed");
        _running.store(false, std::memory_order_release);
        if (_exitSem) xSemaphoreGive(_exitSem);
        vTaskDelete(nullptr);
        return;
    }
    ESP_LOGI(TAG, "Result cache: %d-way x %d sets x %d B in PSRAM (%u KB)",
             CACHE_WAYS, CACHE_SETS, (int)sizeof(CacheEntry),
             (unsigned)(CACHE_ENTRIES * sizeof(CacheEntry) / 1024));

    /* #69 hedge stash: same shape as the forward cache above — PSRAM, one
     * boot-time allocation, dns_task-private. Failure is deliberately
     * NON-fatal, unlike the cache: hedging quietly disables itself (every
     * hedge_qlen stays 0) and every other path behaves exactly as before.
     * Guarded so a task restart re-entering run_loop does not leak. */
    if (!s_hedge_q)
        s_hedge_q = (uint8_t *)heap_caps_calloc(UPSTREAM_TABLE_SIZE, HEDGE_QMAX,
                                                MALLOC_CAP_SPIRAM);
    if (!s_hedge_q)
        ESP_LOGW(TAG, "hedge stash alloc failed — hedged retransmits disabled (#69)");

    cache_load_sd();   /* #79: restore the previous working set, all stale */

    /* ── Open client socket ─────────────────────────────────────── */
    int lsock = -1;   /* TCP/53 listener; created below, -1 = UDP-only */
    int csock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (csock < 0) { ESP_LOGE(TAG, "socket: %d", errno); goto done; }
    {
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(53);
        if (bind(csock, (sockaddr *)&addr, sizeof(addr)) < 0) {
            ESP_LOGE(TAG, "bind port 53: %d", errno); close(csock); goto done;
        }
    }
    /* Enlarge the socket receive buffer so bursts of concurrent queries from
     * multiple clients don't overflow before dns_task drains them.  Without
     * CONFIG_LWIP_SO_RCVBUF=y this call is a no-op; with it lwIP honours the
     * request and uses it to grow the UDP mbox watermark. */
    {
        int rcvbuf = 32768;
        if (setsockopt(csock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0)
            ESP_LOGW(TAG, "SO_RCVBUF: %d (ignored)", errno);
        else
            ESP_LOGI(TAG, "SO_RCVBUF set to %d", rcvbuf);
    }
    _client_fd.store(csock, std::memory_order_release);

    /* ── Open upstream socket ───────────────────────────────────── */
    {
        int usock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
        if (usock < 0) { ESP_LOGE(TAG, "upstream socket: %d", errno); goto done; }
        /* SO_REUSEADDR: lets the task restart without waiting for TIME_WAIT.
         * Non-blocking receive is via MSG_DONTWAIT on each recvfrom() call. */
        {
            int flags = 1;
            setsockopt(usock, SOL_SOCKET, SO_REUSEADDR, &flags, sizeof(flags));
        }
        _upstream_fd.store(usock, std::memory_order_release);

        /* resolve upstream IP once; _upstream_addr may change at runtime via
         * set_upstream() (#53), so re-read it each time it's needed below
         * rather than trusting this snapshot beyond the initial log line. */
        struct sockaddr_in upstream_addr{};
        upstream_addr.sin_family = AF_INET;
        upstream_addr.sin_port   = htons(UPSTREAM_PORT);
        inet_aton(_upstream_ip, &upstream_addr.sin_addr);
        _upstream_addr.store(upstream_addr.sin_addr.s_addr, std::memory_order_release);
        s_upstream_addr_pub.store(upstream_addr.sin_addr.s_addr, std::memory_order_release); /* #80 */

        /* ── Open TCP/53 listener (RFC 7766) ────────────────────── */
        lsock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        if (lsock >= 0) {
            int one = 1;
            setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
            struct sockaddr_in la{};
            la.sin_family = AF_INET;
            la.sin_addr.s_addr = INADDR_ANY;
            la.sin_port = htons(53);
            if (bind(lsock, (sockaddr *)&la, sizeof(la)) < 0 || listen(lsock, 1) < 0) {
                ESP_LOGW(TAG, "TCP/53 unavailable (bind/listen: %d) — UDP-only", errno);
                close(lsock); lsock = -1;
            }
        } else {
            ESP_LOGW(TAG, "TCP/53 unavailable (socket: %d) — UDP-only", errno);
        }

        uint8_t rx[1500], tx[512 + sizeof(DnsAnswerHeader) + 16];
        struct sockaddr_in client_addr{};
        socklen_t clen = sizeof(client_addr);

        ESP_LOGI(TAG, "DNS sinkhole running on port 53 (UDP%s), upstream %s",
                 lsock >= 0 ? "+TCP" : " only", _upstream_ip);

        /* Shared upstream-reply processing: validation (H2), delivery
         * (UDP client / TCP conn / refresh-only), histograms, cache store.
         * Used for plain-UDP replies from usock AND raw DoT-worker replies —
         * the transports differ, the trust and delivery logic must not. */
        auto process_reply = [&](uint8_t *pkt, int plen, int64_t t_ureply,
                                 uint64_t now_ms_) {
            uint16_t our_txid = ntohs(reinterpret_cast<DnsHeader *>(pkt)->id);
            UpstreamEntry *ue = upstream_find(our_txid);
            if (!ue) return;
            /* Anti-spoofing (H2): even with a matching txid, verify the
             * reply's question matches what we actually asked. An attacker
             * who guesses the txid would have to also match the qname+qtype.
             * On mismatch, ignore the packet WITHOUT freeing the slot so the
             * genuine reply can still be accepted (or the slot times out). */
            {
                char rname[256]; size_t rnlen = 0;
                int rqend = extract_qname(pkt, plen, sizeof(DnsHeader),
                                          rname, sizeof(rname), &rnlen);
                if (rqend < 0) return;
                uint16_t rqtype = ntohs(*reinterpret_cast<uint16_t *>(pkt + rqend - 4));
                if (rqtype != ue->qtype || domain_hash(rname, rnlen) != ue->qhash)
                    return;
            }
            /* rewrite transaction ID back to client's original */
            reinterpret_cast<DnsHeader *>(pkt)->id = htons(ue->client_txid);
            /* If the receive filled the buffer exactly, the datagram was larger —
             * we silently truncated it. Set TC=1 so the client knows to retry
             * over TCP, and skip caching this incomplete response (#36). Also
             * treat a reply the UPSTREAM resolver already truncated (TC=1,
             * typically an empty answer section from a no-EDNS forward) the
             * same way for caching purposes: it's just as incomplete as one we
             * cut ourselves, and caching it would serve that empty stub to
             * every later query for the domain — over UDP or TCP, EDNS or not
             * — until the entry expires. Found forwarding TCP-origin queries
             * upstream over plain UDP (#66): the stub cached from one client's
             * no-EDNS query silently poisoned the answer for every other. */
            bool our_truncation = (plen == (int)sizeof(rx));
            if (our_truncation) pkt[2] |= 0x02;  /* TC bit in flags high byte */
            bool truncated = our_truncation || ((pkt[2] & 0x02) != 0);
            if (ue->refresh_only) {
                /* Stale-refresh (#68): nobody is waiting — just cache below.
                 * Only the upstream RTT is a real latency measurement here. */
                hist_record(&s_h_fwd_rtt, t_ureply - ue->upstream_us);
            } else {
                /* Single-flight fan-out (#76): the requester that caused the
                 * forward (w == -1) plus every coalesced waiter, all served by
                 * this one upstream round trip. The txid is stamped per
                 * deliveree because pkt is the shared rx buffer — one stamp for
                 * everyone would hand N-1 clients a reply whose ID matches no
                 * query of theirs, which a conforming resolver discards as
                 * unsolicited and the failure would look like packet loss. */
                for (int w = -1; w < (int)ue->n_wait; w++) {
                    const UpstreamWaiter *wt = (w < 0) ? nullptr : &ue->waiters[w];
                    uint16_t w_txid = wt ? wt->client_txid : ue->client_txid;
                    bool     w_tcp  = wt ? wt->via_tcp     : ue->via_tcp;
                    uint32_t w_gen  = wt ? wt->tcp_gen     : ue->tcp_gen;
                    int64_t  w_recv = wt ? wt->recv_us     : ue->recv_us;
                    const struct sockaddr_in *w_addr = wt ? &wt->client_addr
                                                          : &ue->client_addr;
                    reinterpret_cast<DnsHeader *>(pkt)->id = htons(w_txid);
                    if (w_tcp) {
                        /* Deliver over the TCP conn that asked — if it's still the
                         * same connection (gen match) and still waiting. A closed
                         * conn just means we cache the answer for the retry.
                         * The guard is re-evaluated per deliveree and the close
                         * lives inside it, which is what makes at most one TCP
                         * delivery possible: the send clears awaiting and bumps
                         * gen, so every later TCP deliveree fails the guard. A
                         * second close would bump gen out from under the NEXT
                         * connection's in-flight entry and strand its answer. */
                        if (s_tcp.fd != -1 && s_tcp.awaiting && w_gen == s_tcp.gen) {
                            if (our_truncation)
                                ESP_LOGW(TAG, "upstream reply exceeded %d B — relayed TC over TCP",
                                         (int)sizeof(rx));
                            else if (truncated)
                                ESP_LOGW(TAG, "upstream truncated its own reply (TC=1) — "
                                              "relayed as-is over TCP, not cached");
                            tcp_send_dns(s_tcp.fd, pkt, plen);
                            tcp_conn_close();
                        }
                    } else {
                        sendto(csock, pkt, plen, 0,
                               (sockaddr *)w_addr, sizeof(*w_addr));
                    }
                    int64_t t_csent = esp_timer_get_time();
                    /* Latency split: (a) recv→upstream-send, (b) upstream RTT,
                     * (c) upstream-recv→client-send. Parity overhead = (a)+(c).
                     * (a) only exists for the requester that caused the forward:
                     * a waiter arrived after it, so its (a) is negative and would
                     * only pile up in the ourovh floor bucket (#76). */
                    if (!wt)
                        hist_record(&s_h_fwd_ourovh,
                                    (ue->upstream_us - w_recv) + (t_csent - t_ureply));
                    hist_record(&s_h_fwd_total, t_csent - w_recv);
                }
                /* One upstream round trip, whatever the number of deliverees. */
                hist_record(&s_h_fwd_rtt, t_ureply - ue->upstream_us);
            }

            /* Forward cache: stash the response so a repeat identical query
             * is answered locally. Only NOERROR/NXDOMAIN; TTL from the RRs
             * (NXDOMAIN → short negative TTL). Skip truncated responses. */
            uint8_t rcode = pkt[3] & 0x0F;
            if (!truncated && (rcode == 0 || rcode == 3))
                cache_store_resp(ue->qhash, ue->qtype, pkt, plen,
                                 dns_resp_min_ttl(pkt, plen, 30), now_ms_);
            if (ue->hedged) s_cnt_hedged_done++;   /* (#69) see the counter's caveat */
            ue->in_use = false;
        };

        while (_running.load(std::memory_order_acquire)) {
            /* select() on all sockets with 100ms timeout */
            fd_set rset;
            FD_ZERO(&rset);
            FD_SET(csock, &rset);
            FD_SET(usock, &rset);
            int nfds = (csock > usock ? csock : usock);
            if (lsock >= 0)     { FD_SET(lsock, &rset);    if (lsock    > nfds) nfds = lsock; }
            if (s_tcp.fd != -1) { FD_SET(s_tcp.fd, &rset); if (s_tcp.fd > nfds) nfds = s_tcp.fd; }
            nfds += 1;
            struct timeval tv{ .tv_sec = 0, .tv_usec = 100000 };
            int sel = select(nfds, &rset, nullptr, nullptr, &tv);
            if (sel < 0 && errno != EINTR) break;

            uint64_t now_ms = (uint64_t)(esp_timer_get_time() / 1000);
            upstream_evict_expired((uint32_t)now_ms);   /* upstream table uses uint32_t; 49d ok for 3s timeout */
            if (s_reset_req) { s_reset_req = false; do_metrics_reset(); }
            if (s_tcp.fd != -1 && now_ms > s_tcp.deadline_ms)
                tcp_conn_close();   /* idle/stuck client can't hold the slot */

            (void)sel;  /* select() is just the wait; we drain non-blocking below */

            /* ── Drain ALL upstream replies first (frees table slots) ── */
            for (int dn = 0; dn < 64; dn++) {
                struct sockaddr_in from{}; socklen_t fromlen = sizeof(from);
                int rlen = recvfrom(usock, rx, sizeof(rx), MSG_DONTWAIT,
                                    (sockaddr *)&from, &fromlen);
                if (rlen < 0) break;                           /* EWOULDBLOCK: drained */
                if (rlen < (int)sizeof(DnsHeader)) continue;
                /* Reject replies not from our configured upstream (#24).
                 * Address is re-read live so set_upstream() takes effect without
                 * dropping in-flight queries sent to the previous upstream. */
                if (from.sin_addr.s_addr != _upstream_addr.load(std::memory_order_acquire) ||
                    from.sin_port        != upstream_addr.sin_port) continue;
                process_reply(rx, rlen, esp_timer_get_time(), now_ms);
            }

            /* ── Drain DoT worker results (replies + failed-query echoes) ──
             * Replies arrived over an authenticated TLS session, so the
             * source-address check above has no equivalent here; everything
             * else (H2 question match, delivery, caching) is identical. */
            for (int dn = 0; dn < 8; dn++) {
                bool dot_failed = false;
                int rlen = dot_reply_get(rx, sizeof(rx), &dot_failed);
                if (rlen <= 0) break;
                if (!dot_failed) {
                    process_reply(rx, rlen, esp_timer_get_time(), now_ms);
                } else if (rlen >= (int)sizeof(DnsHeader)) {
                    /* rx holds the original query (txid = our table txid):
                     * fall back to plain UDP for this one, same entry. */
                    uint16_t t = ntohs(reinterpret_cast<DnsHeader *>(rx)->id);
                    UpstreamEntry *ue = upstream_find(t);
                    if (ue) {
                        upstream_addr.sin_addr.s_addr =
                            _upstream_addr.load(std::memory_order_acquire);
                        ue->upstream_us = esp_timer_get_time();
                        sendto(usock, rx, rlen, 0,
                               (sockaddr *)&upstream_addr, sizeof(upstream_addr));
                        ESP_LOGW(TAG, "DoT failed — query re-sent over plain UDP");
                    }
                }
            }

            /* ── Hedged retransmits (#69): flights past their p95 deadline ──
             * Deliberately AFTER the reply drains rather than literally beside
             * upstream_evict_expired(): any reply that was already sitting in
             * the socket buffer at wakeup has freed its slot by now, so a
             * query whose answer is in hand can never trigger a retransmit.
             * The deadline is still checked only once per select() wake, so a
             * hedge fires 0-100 ms late; accepted, because the delay is
             * already quantized to power-of-two bucket edges and shortening
             * the tick would tax every idle wake to speed up only the rare
             * loss path (the ceiling arithmetic at HEDGE_DELAY_MAX_MS budgets
             * for the lateness). The dot_is_enabled() gate here, paired with
             * the one at stash time, makes the plaintext story one sentence:
             * a hedge is only ever sent while DoT is off, for a flight that
             * was forwarded while DoT was off. Hedging via a second
             * dot_enqueue would be pointless anyway: DoT rides TCP, where
             * datagram loss — the failure hedging targets — does not exist,
             * and the single worker session would serialize the copy behind
             * the very request it is meant to rescue. sent_ms and upstream_us
             * stay untouched: eviction keeps measuring its 3 s from the
             * original send, and forwarded_rtt keeps measuring client-visible
             * latency — a hedge-rescued query really did take that long,
             * which is what keeps the p95 delay self-limiting. */
            if (s_hedge_q && !dot_is_enabled() &&
                upstream_inflight() < HEDGE_INFLIGHT_MAX) {
                for (int i = 0; i < UPSTREAM_TABLE_SIZE; i++) {
                    UpstreamEntry *he = &s_upstream[i];
                    if (!he->in_use || he->hedged || he->hedge_qlen == 0) continue;
                    if ((int32_t)((uint32_t)now_ms - he->hedge_deadline_ms) < 0)
                        continue;   /* wrap-safe, like eviction's subtraction */
                    upstream_addr.sin_addr.s_addr =
                        _upstream_addr.load(std::memory_order_acquire);
                    sendto(usock, s_hedge_q + (size_t)i * HEDGE_QMAX,
                           he->hedge_qlen, 0,
                           (sockaddr *)&upstream_addr, sizeof(upstream_addr));
                    he->hedged = true;
                    s_cnt_hedges_sent++;
                }
            }

            /* ── Drain client queries (cap per wakeup so upstream stays serviced) ── */
            bool mbox_drained = false;
            for (int dn = 0; dn < 48; dn++) {
                clen = sizeof(client_addr);
                int rlen = recvfrom(csock, rx, sizeof(rx), MSG_DONTWAIT,
                                    (sockaddr *)&client_addr, &clen);
                if (rlen < 0) { mbox_drained = true; break; }   /* EWOULDBLOCK: drained */
                if (rlen < (int)sizeof(DnsHeader)) continue;

                /* ACL check (#10) — drop queries from unlisted clients */
                if (!acl_permits(ntohl(client_addr.sin_addr.s_addr))) continue;

                auto *hdr = reinterpret_cast<DnsHeader *>(rx);
                if ((ntohs(hdr->flags) & 0x8000) || ntohs(hdr->qdcount) == 0) continue;

                int64_t t_recv = esp_timer_get_time();
                s_cnt_total++;

                /* parse QNAME */
                char name[256]; size_t nlen = 0;
                int qend = extract_qname(rx, rlen, sizeof(DnsHeader), name, sizeof(name), &nlen);
                if (qend < 0) continue;

                uint16_t qtype  = ntohs(*reinterpret_cast<uint16_t *>(rx + qend - 4));
                /* uint16_t qclass = ntohs(...) -- always IN(1), skip check */

                uint32_t h = domain_hash(name, nlen);

                /* ── cache hit? ─────────────────────────────── */
                s_cnt_cache_probe++;
                CacheEntry *ce = cache_lookup(h, qtype, now_ms);
                if (ce) {
                    s_cnt_cache_hit++;
                    if (ce->blocked) {
                        int tlen = build_blocked_any(rx, qend, qtype, tx, sizeof(tx));
                        if (tlen > 0)
                            sendto(csock, tx, tlen, 0, (sockaddr *)&client_addr, clen);
                        s_cnt_blocked++;
                        hist_record(&s_h_cached, esp_timer_get_time() - t_recv);
                    } else if (ce->resp_len > 0 && ce->resp_len <= (int)sizeof(tx)) {
                        /* allowed: replay the cached raw upstream response */
                        memcpy(tx, ce->resp, ce->resp_len);
                        tx[0] = rx[0]; tx[1] = rx[1];      /* keep client's txid (wire bytes) */
                        sendto(csock, tx, ce->resp_len, 0, (sockaddr *)&client_addr, clen);
                        hist_record(&s_h_cached, esp_timer_get_time() - t_recv);
                    } else {
                        s_cnt_cache_hit--;       /* stale/empty — treat as miss */
                        goto forward;
                    }
                    continue;
                }

                /* ── serve-stale (#68): replay an expired allowed entry now,
                 * refresh it upstream in the background (over the DoT worker
                 * when enabled — same transport choice as a cold forward).
                 * The L2 path stays fresh-only: its miss falls through to
                 * here at ~1.8 ms, still invisible. */
                {
                    CacheEntry *se = cache_lookup_stale(h, qtype, now_ms);
                    if (se && se->resp_len <= (int)sizeof(tx)) {
                        memcpy(tx, se->resp, se->resp_len);
                        tx[0] = rx[0]; tx[1] = rx[1];
                        rewrite_answer_ttls(tx, se->resp_len, STALE_TTL_S);
                        sendto(csock, tx, se->resp_len, 0, (sockaddr *)&client_addr, clen);
                        s_cnt_stale++;
                        hist_record(&s_h_cached, esp_timer_get_time() - t_recv);
                        if (now_ms >= se->refresh_after_ms) {
                            se->refresh_after_ms = now_ms + UPSTREAM_TIMEOUT_MS;
                            /* Single-flight (#76): a real query for the same
                             * question is already in flight and its reply
                             * repopulates this entry, so the refresh has nothing
                             * left to do — suppress it outright, no slot and no
                             * packet. The gate above stays armed on purpose:
                             * unlike the table-full case below there is nothing
                             * to retry. A refresh has no deliveree, so it never
                             * becomes a waiter either. */
                            if (upstream_find_inflight(h, qtype)) {
                                s_cnt_coalesced++;
                                continue;
                            }
                            uint16_t our_txid;
                            UpstreamEntry *ue = upstream_alloc(&our_txid);
                            if (ue) {
                                ue->client_txid  = ntohs(hdr->id);   /* unused: no deliveree */
                                ue->sent_ms      = (uint32_t)now_ms;
                                ue->recv_us      = t_recv;
                                ue->qhash        = h;
                                ue->qtype        = qtype;
                                ue->refresh_only = true;
                                /* env_hash deliberately left unset: a
                                 * refresh_only entry is never a coalescing
                                 * target, so nobody can ride its envelope. */
                                hdr->id = htons(our_txid);
                                ue->upstream_us = esp_timer_get_time();
                                if (!(dot_is_enabled() && dot_enqueue(rx, rlen))) {
                                    upstream_addr.sin_addr.s_addr =
                                        _upstream_addr.load(std::memory_order_acquire);
                                    sendto(usock, rx, rlen, 0,
                                           (sockaddr *)&upstream_addr, sizeof(upstream_addr));
                                }
                            } else {
                                se->refresh_after_ms = 0;  /* table full — retry next hit */
                            }
                        }
                        continue;
                    }
                }

                /* ── DNS rewrite check (#12): local zone / domain→IP ── */
                if (qtype == 1 /* A */) {
                    uint32_t rw_ip = rewrite_lookup(name);
                    if (rw_ip) {
                        int tlen = build_rewrite_a(rx, qend, rw_ip, tx, sizeof(tx));
                        if (tlen > 0) {
                            sendto(csock, tx, tlen, 0, (sockaddr *)&client_addr, clen);
                            hist_record(&s_h_cached, esp_timer_get_time() - t_recv);
                            query_log_record(name, qtype,
                                ntohl(client_addr.sin_addr.s_addr), false, true);
                        }
                        continue;
                    }
                }

                /* ── blocklist check (measure CPU-only lookup span) ──
                 * Scoped block so the 'goto forward' above never crosses these
                 * local initializations (illegal in C++). */
                {
                    int64_t t_lk = esp_timer_get_time();
                    bool is_blk = blocklist_is_blocked(name, nlen) ||
                                  blocklist_custom_is_blocked(name, nlen);
                    hist_record(&s_h_lookup, esp_timer_get_time() - t_lk);
                    if (is_blk) {
                        s_cnt_blocked++;
                        int tlen = build_blocked_any(rx, qend, qtype, tx, sizeof(tx));
                        if (tlen > 0) {
                            int64_t t_s0 = esp_timer_get_time();
                            sendto(csock, tx, tlen, 0, (sockaddr *)&client_addr, clen);
                            hist_record(&s_h_sendto, esp_timer_get_time() - t_s0);
                        }
                        cache_store_blocked(h, qtype, BLOCKED_TTL_S, now_ms);
                        hist_record(&s_h_blocked, esp_timer_get_time() - t_recv);
                        query_log_record(name, qtype,
                            ntohl(client_addr.sin_addr.s_addr), true, false);
                        continue;
                    }
                    /* allowed: record before forwarding */
                    query_log_record(name, qtype,
                        ntohl(client_addr.sin_addr.s_addr), false, false);
                }

                /* ── forward to upstream: DoT worker if enabled, else UDP ── */
                forward: {
                    uint16_t our_txid;
                    /* Single-flight (#76): this exact question may already be in
                     * flight — ride that reply instead of burning a second slot.
                     * The simultaneous burst that used to exhaust the table and
                     * drop unrelated queries now costs one waiter. No joinable
                     * entry: fall through and allocate normally. */
                    uint32_t eh = query_env_hash(rx, rlen, qend);
                    UpstreamEntry *fl = upstream_find_joinable(h, qtype, eh,
                                                               (uint32_t)now_ms);
                    if (fl && upstream_join(fl, ntohs(hdr->id), &client_addr,
                                            t_recv, false, 0))
                        continue;
                    UpstreamEntry *ue = upstream_alloc(&our_txid);
                    if (!ue) {
                        /* table full — drop this query; client will retry */
                        s_cnt_drop_table++;
                        ESP_LOGW(TAG, "upstream table full, dropping query for %s", name);
                        continue;
                    }
                    ue->client_txid = ntohs(hdr->id);
                    ue->client_addr = client_addr;
                    ue->sent_ms     = (uint32_t)now_ms;
                    ue->recv_us     = t_recv;
                    ue->qhash       = h;
                    ue->qtype       = qtype;
                    ue->env_hash    = eh;

                    /* rewrite txid and forward — read the live upstream address
                     * so an in-flight query batch can straddle a set_upstream() */
                    hdr->id = htons(our_txid);
                    ue->upstream_us = esp_timer_get_time();
                    if (!(dot_is_enabled() && dot_enqueue(rx, rlen))) {
                        upstream_addr.sin_addr.s_addr = _upstream_addr.load(std::memory_order_acquire);
                        sendto(usock, rx, rlen, 0,
                               (sockaddr *)&upstream_addr, sizeof(upstream_addr));
                        /* (#69) Arm the hedge only when DoT is OFF outright.
                         * Reaching this branch with DoT on means its queue
                         * overflowed and this flight fell back to plain UDP —
                         * a system already under DoT pressure, where adding
                         * retransmits is the wrong reflex, and skipping keeps
                         * the no-plaintext-hedge-under-DoT proof one line. */
                        if (!dot_is_enabled())
                            hedge_stash(ue, rx, rlen, (uint32_t)now_ms);
                    }
                    s_cnt_forwarded++;
                }
            }
            /* (#81) Ran the full 48-iteration cap without ever seeing EWOULDBLOCK:
             * every slot had a real datagram waiting, so the mailbox was still
             * non-empty when we stopped voluntarily. Some of what arrived between
             * now and the next wakeup may already have missed the mailbox
             * entirely — this can't see that part, only that we were at the edge
             * of it. */
            if (!mbox_drained) s_cnt_mbox_pressure++;

            /* ── TCP/53: accept + read + serve (one conn, one query) ──
             * Same verdict ladder as the UDP path above; contained duplication
             * until the shared-verdict-helper refactor (roadmap wave 4). */
            if (lsock >= 0 && FD_ISSET(lsock, &rset)) {
                struct sockaddr_in pa{}; socklen_t pl = sizeof(pa);
                int nfd = accept(lsock, (sockaddr *)&pa, &pl);
                if (nfd >= 0) {
                    if (s_tcp.fd != -1 || !acl_permits(ntohl(pa.sin_addr.s_addr))) {
                        close(nfd);   /* busy (client retries) or unlisted client */
                    } else {
                        int fl = fcntl(nfd, F_GETFL, 0);
                        fcntl(nfd, F_SETFL, fl | O_NONBLOCK);
                        s_tcp.fd = nfd;
                        s_tcp.have = 0;
                        s_tcp.awaiting = false;
                        s_tcp.peer_ip = ntohl(pa.sin_addr.s_addr);
                        s_tcp.deadline_ms = now_ms + TCP_CONN_IDLE_MS;
                    }
                }
            }
            if (s_tcp.fd != -1 && !s_tcp.awaiting) {
                int r = recv(s_tcp.fd, s_tcp.buf + s_tcp.have,
                             sizeof(s_tcp.buf) - s_tcp.have, MSG_DONTWAIT);
                if (r == 0 || (r < 0 && errno != EWOULDBLOCK && errno != EAGAIN)) {
                    tcp_conn_close();
                } else if (r > 0) {
                    s_tcp.have += r;
                    s_tcp.deadline_ms = now_ms + TCP_CONN_IDLE_MS;
                }
            }
            if (s_tcp.fd != -1 && !s_tcp.awaiting && s_tcp.have >= 2) {
                int mlen = ((int)s_tcp.buf[0] << 8) | s_tcp.buf[1];
                if (mlen < (int)sizeof(DnsHeader) || mlen > TCP_QUERY_MAX) {
                    tcp_conn_close();               /* oversize or garbage framing */
                } else if (s_tcp.have >= 2 + mlen) {
                    uint8_t *q = s_tcp.buf + 2;
                    auto *qh = reinterpret_cast<DnsHeader *>(q);
                    int64_t t_recv = esp_timer_get_time();
                    char name[256]; size_t nlen = 0;
                    int qend = -1;
                    if (!(ntohs(qh->flags) & 0x8000) && ntohs(qh->qdcount) != 0)
                        qend = extract_qname(q, mlen, sizeof(DnsHeader),
                                             name, sizeof(name), &nlen);
                    if (qend < 0) {
                        tcp_conn_close();
                    } else {
                        s_cnt_total++; s_cnt_tcp++;
                        uint16_t qtype = ntohs(*reinterpret_cast<uint16_t *>(q + qend - 4));
                        uint32_t h = domain_hash(name, nlen);
                        int tlen = 0;    /* >0: answer in tx; 0: forwarded, conn held */

                        s_cnt_cache_probe++;
                        CacheEntry *ce = cache_lookup(h, qtype, now_ms);
                        if (ce && (ce->blocked ||
                                   (ce->resp_len > 0 && ce->resp_len <= (int)sizeof(tx)))) {
                            s_cnt_cache_hit++;
                            if (ce->blocked) {
                                s_cnt_blocked++;
                                tlen = build_blocked_any(q, qend, qtype, tx, sizeof(tx));
                                hist_record(&s_h_blocked, esp_timer_get_time() - t_recv);
                            } else {
                                memcpy(tx, ce->resp, ce->resp_len);
                                tx[0] = q[0]; tx[1] = q[1];   /* client's txid */
                                tlen = ce->resp_len;
                                hist_record(&s_h_cached, esp_timer_get_time() - t_recv);
                            }
                        } else {
                            uint32_t rw_ip = (qtype == 1) ? rewrite_lookup(name) : 0;
                            if (rw_ip) {
                                tlen = build_rewrite_a(q, qend, rw_ip, tx, sizeof(tx));
                                query_log_record(name, qtype, s_tcp.peer_ip, false, true);
                            } else if (blocklist_is_blocked(name, nlen) ||
                                       blocklist_custom_is_blocked(name, nlen)) {
                                s_cnt_blocked++;
                                tlen = build_blocked_any(q, qend, qtype, tx, sizeof(tx));
                                cache_store_blocked(h, qtype, BLOCKED_TTL_S, now_ms);
                                query_log_record(name, qtype, s_tcp.peer_ip, true, false);
                                hist_record(&s_h_blocked, esp_timer_get_time() - t_recv);
                            } else {
                                query_log_record(name, qtype, s_tcp.peer_ip, false, false);
                                uint16_t our_txid;
                                UpstreamEntry *ue = nullptr;
                                /* Single-flight (#76): ride an identical query
                                 * already in flight. The waiter snapshots gen
                                 * now, so it can only ever be delivered to the
                                 * conn it joined on; awaiting holds that conn
                                 * open for the fan-out exactly as a real forward
                                 * does, and the fan-out closes it. If the reply
                                 * never comes the idle reaper frees the conn,
                                 * same as an entry that times out today — and
                                 * the age gate keeps that wait from outliving
                                 * the entry by more than a fraction of it. */
                                uint32_t eh = query_env_hash(q, mlen, qend);
                                UpstreamEntry *fl = upstream_find_joinable(h, qtype, eh,
                                                                           (uint32_t)now_ms);
                                if (fl && upstream_join(fl, ntohs(qh->id), nullptr,
                                                        t_recv, true, s_tcp.gen)) {
                                    s_tcp.awaiting = true;
                                } else if (!(ue = upstream_alloc(&our_txid))) {
                                    s_cnt_drop_table++;
                                    /* SERVFAIL: fail fast instead of hanging the conn */
                                    memcpy(tx, q, qend);
                                    uint16_t qf = ((uint16_t)q[2] << 8) | q[3];
                                    uint16_t rf = dns_resp_flags(qf, 2);
                                    tx[2] = rf >> 8; tx[3] = rf & 0xFF;
                                    reinterpret_cast<DnsHeader *>(tx)->ancount = 0;
                                    reinterpret_cast<DnsHeader *>(tx)->nscount = 0;
                                    reinterpret_cast<DnsHeader *>(tx)->arcount = 0;
                                    tlen = qend;
                                } else {
                                    ue->client_txid = ntohs(qh->id);
                                    memset(&ue->client_addr, 0, sizeof(ue->client_addr));
                                    ue->sent_ms  = (uint32_t)now_ms;
                                    ue->recv_us  = t_recv;
                                    ue->qhash    = h;
                                    ue->qtype    = qtype;
                                    ue->env_hash = eh;
                                    ue->via_tcp  = true;
                                    ue->tcp_gen  = s_tcp.gen;
                                    qh->id = htons(our_txid);
                                    ue->upstream_us = esp_timer_get_time();
                                    if (!(dot_is_enabled() && dot_enqueue(q, mlen))) {
                                        /* (#66) forwarding the client's own EDNS-less
                                         * query gets it classic-truncated at 512 B by
                                         * the upstream resolver — a dead end, since
                                         * this client is already on TCP with nowhere
                                         * left to retry. Ask upstream for a real
                                         * answer instead. */
                                        static uint8_t edns_q[TCP_QUERY_MAX + 11];
                                        int elen = append_bare_edns_opt(edns_q, q, mlen,
                                                                        sizeof(edns_q));
                                        upstream_addr.sin_addr.s_addr =
                                            _upstream_addr.load(std::memory_order_acquire);
                                        sendto(usock, edns_q, elen, 0,
                                               (sockaddr *)&upstream_addr, sizeof(upstream_addr));
                                        /* (#69) same DoT gate as the UDP path;
                                         * a TCP-origin flight still goes
                                         * upstream over UDP, so it hedges the
                                         * same way. Stash edns_q, not q: a
                                         * hedge retransmit of the ORIGINAL
                                         * EDNS-less query would undo the #66
                                         * fix above for that copy — same
                                         * txid, so whichever reply lands
                                         * first wins, and an EDNS-less
                                         * retransmit can still land a
                                         * truncated dead end over TCP. elen
                                         * may exceed HEDGE_QMAX (512; TCP_QUERY_MAX
                                         * is 768, +11 for the OPT) — hedge_stash
                                         * then leaves the flight un-hedged,
                                         * same graceful no-op as before. */
                                        if (!dot_is_enabled())
                                            hedge_stash(ue, edns_q, elen, (uint32_t)now_ms);
                                    }
                                    s_cnt_forwarded++;
                                    s_tcp.awaiting = true;
                                }
                            }
                        }
                        if (!s_tcp.awaiting) {
                            /* direct answer (or builder failure) — send and close */
                            if (tlen > 0) tcp_send_dns(s_tcp.fd, tx, tlen);
                            tcp_conn_close();
                        }
                    }
                }
            }
        }  /* while running */
    }

done:
    tcp_conn_close();
    if (lsock >= 0) close(lsock);
    int fd = _client_fd.exchange(-1, std::memory_order_acq_rel);
    if (fd != -1) close(fd);
    fd = _upstream_fd.exchange(-1, std::memory_order_acq_rel);
    if (fd != -1) close(fd);
    _running.store(false, std::memory_order_release);
    ESP_LOGI(TAG, "dns_task exited");
    if (_exitSem) xSemaphoreGive(_exitSem);
    vTaskDelete(nullptr);
}

uint64_t DnsSinkServer::queries_total()   const { return s_cnt_total; }
uint64_t DnsSinkServer::queries_blocked() const { return s_cnt_blocked; }

extern "C" uint32_t dns_sink_l2_blocked(void);  /* L2 fast-path counters (dns_sink.cpp) */
extern "C" uint32_t dns_sink_l2_cached(void);

static void do_metrics_reset(void)
{
    s_cnt_total = s_cnt_blocked = s_cnt_forwarded = s_cnt_tcp = s_cnt_stale = 0;
    s_cnt_drop_table = s_cnt_mbox_pressure = s_cnt_upstream_to = 0;
    s_cnt_cache_probe = s_cnt_cache_hit = 0;
    s_cnt_cache_evict = s_cnt_cache_toobig = 0;
    s_cnt_coalesced = 0;
    s_cnt_hedges_sent = s_cnt_hedged_done = 0;   /* (#69); note the reset also empties
                                                    s_h_fwd_rtt, so the hedge delay falls
                                                    back to HEDGE_DELAY_DEFAULT_MS until
                                                    the p95 is re-learned — intended */
    memset(&s_h_blocked,    0, sizeof(s_h_blocked));
    memset(&s_h_cached,     0, sizeof(s_h_cached));
    memset(&s_h_fwd_total,  0, sizeof(s_h_fwd_total));
    memset(&s_h_fwd_rtt,    0, sizeof(s_h_fwd_rtt));
    memset(&s_h_fwd_ourovh, 0, sizeof(s_h_fwd_ourovh));
    memset(&s_h_lookup,     0, sizeof(s_h_lookup));
    memset(&s_h_sendto,     0, sizeof(s_h_sendto));
}

void dns_server_metrics_reset(void)
{
    s_reset_req = true;  /* picked up by dns_task on its next select() wakeup */
}

/* ── /metrics JSON ───────────────────────────────────────────────── */
int dns_server_metrics_json(char *out, size_t cap)
{
    uint32_t probes = s_cnt_cache_probe;
    uint32_t hits   = s_cnt_cache_hit;
    float hitrate   = probes ? (100.0f * (float)hits / (float)probes) : 0.0f;

    size_t free_int  = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    /* Largest CONTIGUOUS internal block. heap_free alone hid a live failure:
     * mbedtls_ssl_setup() wants one ~16.9 KB run for its in_buf, so a fetch can
     * die with PSA_ERROR_INSUFFICIENT_MEMORY while heap_free still reads a
     * comfortable ~38 KB. The total is not the number that decides. */
    size_t big_int   = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
    size_t free_psr  = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    UBaseType_t hwm  = s_dns_task_handle ? uxTaskGetStackHighWaterMark(s_dns_task_handle) : 0;

    /* #80: the resolver we are actually forwarding to. Previously unobservable
     * anywhere - no metric, no UI - which is why a boot-time misselection went
     * unnoticed. Network byte order, so the low byte is the first octet. */
    uint32_t ua = s_upstream_addr_pub.load(std::memory_order_acquire);
    char upstream_s[16];
    snprintf(upstream_s, sizeof(upstream_s), "%u.%u.%u.%u",
             (unsigned)(ua & 0xFFu), (unsigned)((ua >> 8) & 0xFFu),
             (unsigned)((ua >> 16) & 0xFFu), (unsigned)((ua >> 24) & 0xFFu));

    int n = snprintf(out, cap,
        "{"
        "\"upstream\":\"%s\","
        /* #75: how the system clock got its value, and where it stands now.
         * clock_src is LATCHED at boot - the floor decision is only visible
         * for the 1-3 s before SNTP lands, which is too short to catch by
         * polling, and it gates every TLS handshake on the box. */
        "\"clock\":\"%s\",\"clock_src\":\"%s\","
        "\"uptime_s\":%lld,"
        "\"queries_total\":%" PRIu32 ",\"blocked\":%" PRIu32 ",\"forwarded\":%" PRIu32 ","
        "\"tcp_queries\":%" PRIu32 ","
        "\"l2_blocked\":%" PRIu32 ",\"l2_cached\":%" PRIu32 ","
        "\"cache_probes\":%" PRIu32 ",\"cache_hits\":%" PRIu32 ",\"cache_hit_rate\":%.1f,"
        "\"cache_evictions\":%" PRIu32 ",\"cache_too_big\":%" PRIu32 ","
        "\"stale_served\":%" PRIu32 ","
        "\"coalesced\":%" PRIu32 ","
        "\"hedges_sent\":%" PRIu32 ",\"hedged_completions\":%" PRIu32 ","
        "\"dropped\":{\"table_full\":%" PRIu32 ",\"mbox_pressure\":%" PRIu32 "},"
        "\"upstream_timeouts\":%" PRIu32 ","
        "\"upstream_inflight\":%d,\"upstream_max\":%d,"
        "\"blocklist_count\":%" PRIu32 ",\"blocklist_loading\":%s,"
        "\"blocklist_paused\":%s,"
        "\"blocklist_dropped\":%" PRIu32 ","
        "\"blocklist_feed_failures\":%" PRIu32 ","
        "\"heap_free\":%u,\"heap_largest\":%u,\"psram_free\":%u,\"dns_task_stack_hwm\":%u,",
        upstream_s,
        timesync_state(), timesync_source(),
        (long long)(esp_timer_get_time() / 1000000),
        s_cnt_total, s_cnt_blocked, s_cnt_forwarded,
        s_cnt_tcp,
        dns_sink_l2_blocked(), dns_sink_l2_cached(),
        probes, hits, hitrate,
        s_cnt_cache_evict, s_cnt_cache_toobig,
        s_cnt_stale,
        s_cnt_coalesced,
        s_cnt_hedges_sent, s_cnt_hedged_done,
        s_cnt_drop_table, s_cnt_mbox_pressure, s_cnt_upstream_to,
        upstream_inflight(), UPSTREAM_TABLE_SIZE,
        blocklist_domain_count(), blocklist_is_loading() ? "true" : "false",
        blocklist_is_paused() ? "true" : "false",
        blocklist_dropped_count(),
        blocklist_feed_failures(),
        (unsigned)free_int, (unsigned)big_int, (unsigned)free_psr, (unsigned)hwm);

    struct { const char *name; const Hist *h; } cats[] = {
        {"blocked",          &s_h_blocked},
        {"cached",           &s_h_cached},
        {"forwarded_total",  &s_h_fwd_total},
        {"forwarded_ourovh", &s_h_fwd_ourovh},
        {"forwarded_rtt",    &s_h_fwd_rtt},
        {"lookup",           &s_h_lookup},
        {"sendto",           &s_h_sendto},
    };
    if ((size_t)n < cap) n += snprintf(out + n, cap - (size_t)n, "\"latency_us\":{");
    for (size_t i = 0; i < sizeof(cats)/sizeof(cats[0]); i++) {
        if ((size_t)n >= cap) break;
        n += snprintf(out + n, cap - (size_t)n,
            "%s\"%s\":{\"p50\":%" PRIu32 ",\"p99\":%" PRIu32 ",\"max\":%" PRIu32 ",\"count\":%" PRIu32 "}",
            i ? "," : "", cats[i].name,
            hist_pctl(cats[i].h, 0.50), hist_pctl(cats[i].h, 0.99),
            cats[i].h->max_us, cats[i].h->count);
    }
    if ((size_t)n < cap) n += snprintf(out + n, cap - (size_t)n, "}}");
    /* F15: n accumulates snprintf's WOULD-BE length, not bytes actually
     * written. Every append above is guarded (`if ((size_t)n < cap) ...`) so
     * none of them overflow `out`, but that guard only stops FURTHER growth —
     * it never pulls n back under cap once an earlier call has already pushed
     * it there (or past it, from the very first unguarded snprintf() above).
     * handle_metrics() then does httpd_resp_send(r, json, n) against a fixed
     * 2048 B buffer, so an unclamped n ships whatever .bss sits after json[]
     * to an unauthenticated client as unterminated JSON. Unreachable today
     * (worst case ~1,323 B) but one line of insurance against future growth. */
    if (n > (int)cap - 1) n = (int)cap - 1;
    return n;
}
