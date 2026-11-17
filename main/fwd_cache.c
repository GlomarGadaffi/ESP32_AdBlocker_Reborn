#include "fwd_cache.h"
#include "domain.h"      /* dns_qname_wire_eq/_len, DNS_QNAME_WIRE_MAX, IRAM_ATTR shim */
#include <string.h>

/* See fwd_cache.h. Every function body below is the dns_server.cpp original
 * with the file-statics (s_cache, s_cache_seq, s_cnt_cache_*) replaced by the
 * fwd_cache_t fields and blocklist_generation() / esp_timer reads replaced by
 * arguments. Do not "improve" any of it here; this is a move. */

bool fwd_cache_init(fwd_cache_t *c, fwd_entry_t *buf, uint32_t entries)
{
    if (!c) return false;
    c->e = NULL; c->entries = 0; c->set_mask = 0;
    c->seq = 0; c->evict = 0; c->toobig = 0;
    if (!buf || entries == 0 || entries % FWD_CACHE_WAYS != 0) return false;
    uint32_t sets = entries / FWD_CACHE_WAYS;
    if ((sets & (sets - 1u)) != 0) return false;
    c->e = buf; c->entries = entries; c->set_mask = sets - 1u;
    return true;
}

/* Seqlock writer: odd -> write -> even. std::atomic relaxed load/store plus
 * std::atomic_thread_fence(release) mapped 1:1 onto the GCC __atomic builtins. */
void fwd_cache_write_begin(fwd_cache_t *c)
{
    __atomic_store_n(&c->seq, __atomic_load_n(&c->seq, __ATOMIC_RELAXED) + 1, __ATOMIC_RELAXED);
    __atomic_thread_fence(__ATOMIC_RELEASE);
}
void fwd_cache_write_end(fwd_cache_t *c)
{
    __atomic_thread_fence(__ATOMIC_RELEASE);
    __atomic_store_n(&c->seq, __atomic_load_n(&c->seq, __ATOMIC_RELAXED) + 1, __ATOMIC_RELAXED);
}

/* First entry of the set that (h, qtype) maps to; its WAYS are contiguous.
 * qtype folded in as before, so A and AAAA live in separate sets. */
static inline IRAM_ATTR fwd_entry_t *fwd_set(const fwd_cache_t *c, uint32_t h, uint16_t qtype)
{
    return &c->e[((h ^ ((uint32_t)qtype << 1)) & c->set_mask) * FWD_CACHE_WAYS];
}

/* The full cache key: (hash, qtype) plus the exact question name; case is
 * ignored, as it is by domain_hash. IRAM: fwd_cache_l2_get uses it. */
static inline IRAM_ATTR bool fwd_key_eq(const fwd_entry_t *e, uint32_t h, uint16_t qtype,
                                        const uint8_t *qn, int qn_len)
{
    return e->key_hash == h && e->qtype == qtype && e->qn_len == qn_len &&
           dns_qname_wire_eq(e->resp + FWD_DNS_HDR_LEN, qn, qn_len);
}

fwd_entry_t *fwd_cache_lookup(fwd_cache_t *c, uint32_t h, uint16_t qtype,
                              const uint8_t *qn, int qn_len, uint64_t now_ms, uint32_t gen)
{
    fwd_entry_t *set = fwd_set(c, h, qtype);
    for (int w = 0; w < FWD_CACHE_WAYS; w++) {
        fwd_entry_t *e = &set[w];
        if (e->valid && fwd_key_eq(e, h, qtype, qn, qn_len) && e->ttl_deadline_ms > now_ms
            && e->load_gen == gen)
            return e;
    }
    return NULL;
}

/* The way a store for (h, qtype) must write. Priority: the key's OWN way if it
 * already has one, then an invalid way, then the way whose usefulness ends
 * soonest: blocked entries compare at their deadline, allowed ones at
 * deadline + stale window (they still answer through serve-stale, #68). */
fwd_entry_t *fwd_cache_victim(fwd_cache_t *c, uint32_t h, uint16_t qtype,
                              const uint8_t *qn, int qn_len, uint64_t now_ms)
{
    fwd_entry_t *set = fwd_set(c, h, qtype);
    fwd_entry_t *victim = &set[0];
    uint64_t victim_end = UINT64_MAX;
    for (int w = 0; w < FWD_CACHE_WAYS; w++) {
        fwd_entry_t *e = &set[w];
        if (e->valid && fwd_key_eq(e, h, qtype, qn, qn_len))
            return e;                          /* overwrite in place */
        uint64_t end = !e->valid ? 0
            : e->ttl_deadline_ms + (e->blocked ? 0 : (uint64_t)FWD_STALE_MAX_S * 1000u);
        if (end < victim_end) { victim = e; victim_end = end; }
    }
    if (victim->valid && victim_end > now_ms)
        c->evict++;
    return victim;
}

void fwd_cache_store_blocked(fwd_cache_t *c, uint32_t h, uint16_t qtype,
                             const uint8_t *qn, int qn_len,
                             uint32_t ttl_s, uint64_t now_ms, uint32_t load_gen)
{
    if (qn_len <= 0 || qn_len > DNS_QNAME_WIRE_MAX) return;
    fwd_entry_t *e = fwd_cache_victim(c, h, qtype, qn, qn_len, now_ms);
    fwd_cache_write_begin(c);
    e->key_hash = h; e->qtype = qtype; e->blocked = true; e->valid = true;
    e->resp_len = 0;
    memcpy(e->resp + FWD_DNS_HDR_LEN, qn, (size_t)qn_len);
    e->qn_len = (uint16_t)qn_len;
    e->ttl_deadline_ms = now_ms + (uint64_t)ttl_s * 1000u;
    e->load_gen = load_gen;  /* (#85) */
    e->restored = false;
    fwd_cache_write_end(c);
}

void fwd_cache_store_resp(fwd_cache_t *c, uint32_t h, uint16_t qtype,
                          const uint8_t *resp, int len,
                          uint32_t ttl_s, uint64_t now_ms, uint32_t load_gen)
{
    if (len <= 0) return;
    if (len > FWD_RESP_MAX) { c->toobig++; return; }
    int qn_len = dns_qname_wire_len(resp, len, FWD_DNS_HDR_LEN);
    if (qn_len < 0) return;
    fwd_entry_t *e = fwd_cache_victim(c, h, qtype, resp + FWD_DNS_HDR_LEN, qn_len, now_ms);
    fwd_cache_write_begin(c);
    e->key_hash = h; e->qtype = qtype; e->blocked = false; e->valid = true;
    e->resp_len = (uint16_t)len;
    memcpy(e->resp, resp, (size_t)len);
    e->qn_len = (uint16_t)qn_len;
    e->ttl_deadline_ms   = now_ms + (uint64_t)ttl_s * 1000u;
    e->refresh_after_ms  = 0;
    e->load_gen          = load_gen;  /* (#85) */
    e->restored          = false;
    fwd_cache_write_end(c);
}

/* Serve-stale lookup (#68): expired ALLOWED entry within the stale window.
 * Fresh entries are fwd_cache_lookup()'s job; expired blocked entries stay
 * misses (re-blocking via the blocklist is microseconds). */
fwd_entry_t *fwd_cache_lookup_stale(fwd_cache_t *c, uint32_t h, uint16_t qtype,
                                    const uint8_t *qn, int qn_len, uint64_t now_ms, uint32_t gen)
{
    fwd_entry_t *set = fwd_set(c, h, qtype);
    for (int w = 0; w < FWD_CACHE_WAYS; w++) {
        fwd_entry_t *e = &set[w];
        if (e->valid && !e->blocked && e->resp_len > 0 &&
            fwd_key_eq(e, h, qtype, qn, qn_len) &&
            e->ttl_deadline_ms <= now_ms &&
            e->ttl_deadline_ms + (uint64_t)FWD_STALE_MAX_S * 1000u > now_ms &&
            e->load_gen == gen)
            return e;
    }
    return NULL;
}

/* L2 fast-path cache read (eth-RX task). Seqlock-protected; see header. */
int IRAM_ATTR fwd_cache_l2_get(fwd_cache_t *c, uint32_t h, uint16_t qtype,
                               const uint8_t *qn, int qn_len, uint64_t now_ms, uint32_t gen,
                               uint8_t *out, int out_cap)
{
    if (!c || !c->e || !out) return -1;
    fwd_entry_t *set = fwd_set(c, h, qtype);

    uint32_t s1 = __atomic_load_n(&c->seq, __ATOMIC_RELAXED);
    if (s1 & 1u) return -1;                       /* writer mid-update */
    __atomic_thread_fence(__ATOMIC_ACQUIRE);

    /* Scan the whole set inside ONE seqlock window: a mid-scan write would
     * invalidate any way we matched, and the single end check catches it. */
    int len = -1;
    for (int w = 0; w < FWD_CACHE_WAYS; w++) {
        fwd_entry_t *e = &set[w];
        if (!e->valid || e->blocked || !fwd_key_eq(e, h, qtype, qn, qn_len)) continue;
        if (e->ttl_deadline_ms <= now_ms) continue;  /* expired */
        if (e->load_gen != gen) continue;            /* (#85) stale verdict */
        int l = e->resp_len;
        if (l <= 0 || l > out_cap || l > FWD_RESP_MAX) continue;
        memcpy(out, e->resp, (size_t)l);
        len = l;
        break;
    }
    if (len < 0) return -1;

    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    if (__atomic_load_n(&c->seq, __ATOMIC_RELAXED) != s1) return -1; /* raced */
    return len;
}

bool fwd_cache_refresh_arm(fwd_entry_t *e, uint64_t now_ms, uint32_t hold_ms)
{
    if (now_ms >= e->refresh_after_ms) {
        e->refresh_after_ms = now_ms + hold_ms;
        return true;
    }
    return false;
}
void fwd_cache_refresh_disarm(fwd_entry_t *e)
{
    e->refresh_after_ms = 0;
}

/* ── SD snapshot ─────────────────────────────────────────────────── */
/* Explicit little-endian field IO: an on-disk format should not lean on
 * struct layout. */
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

bool fwd_cache_snap_read(fwd_cache_t *c, uint32_t idx, uint64_t now_ms, uint8_t *snap,
                         uint32_t *h, uint16_t *qtype, uint16_t *resp_len)
{
    if (!c || !c->e || idx >= c->entries) return false;
    fwd_entry_t *e = &c->e[idx];

    uint32_t s1 = __atomic_load_n(&c->seq, __ATOMIC_RELAXED);
    if (s1 & 1u) return false;                    /* writer mid-update */
    __atomic_thread_fence(__ATOMIC_ACQUIRE);

    if (!e->valid || e->blocked) return false;
    uint32_t eh        = e->key_hash;
    uint16_t eq        = e->qtype;
    uint16_t el        = e->resp_len;
    uint64_t deadline  = e->ttl_deadline_ms;
    if (el == 0 || el > FWD_RESP_MAX) return false;
    memcpy(snap, e->resp, el);

    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    if (__atomic_load_n(&c->seq, __ATOMIC_RELAXED) != s1) return false;   /* raced */

    /* Drop entries already past their stale window: restoring one would
     * serve data older than the stale-window contract the runtime enforces. */
    if (deadline + (uint64_t)FWD_STALE_MAX_S * 1000u <= now_ms) return false;

    *h = eh; *qtype = eq; *resp_len = el;
    return true;
}

bool fwd_cache_load_insert(fwd_cache_t *c, uint32_t h, uint16_t qtype,
                           const uint8_t *resp, uint16_t resp_len, uint64_t now_ms,
                           uint32_t gen_now)
{
    int qn_len = dns_qname_wire_len(resp, resp_len, FWD_DNS_HDR_LEN);
    if (qn_len < 0) return false;
    fwd_entry_t *e = fwd_cache_victim(c, h, qtype, resp + FWD_DNS_HDR_LEN, qn_len, now_ms);
    memcpy(e->resp, resp, resp_len);
    e->qn_len           = (uint16_t)qn_len;
    e->key_hash         = h;
    e->qtype            = qtype;
    e->resp_len         = resp_len;
    e->blocked          = false;
    e->valid            = true;
    e->ttl_deadline_ms  = 1;   /* expired, but inside the stale window */
    e->refresh_after_ms = 0;   /* first touch is free to refresh at once */
    e->load_gen         = gen_now - 1u;   /* never the current generation: unverified */
    e->restored         = true;
    return true;
}

fwd_entry_t *fwd_cache_restored_pending(fwd_cache_t *c, uint32_t h, uint16_t qtype,
                                        const uint8_t *qn, int qn_len, uint64_t now_ms,
                                        uint32_t gen)
{
    fwd_entry_t *set = fwd_set(c, h, qtype);
    for (int w = 0; w < FWD_CACHE_WAYS; w++) {
        fwd_entry_t *e = &set[w];
        if (e->valid && e->restored && !e->blocked && e->resp_len > 0 &&
            e->load_gen != gen &&
            fwd_key_eq(e, h, qtype, qn, qn_len) &&
            e->ttl_deadline_ms + (uint64_t)FWD_STALE_MAX_S * 1000u > now_ms)
            return e;
    }
    return NULL;
}

void fwd_cache_restored_adopt(fwd_cache_t *c, fwd_entry_t *e, uint32_t gen)
{
    fwd_cache_write_begin(c);
    e->load_gen = gen;
    fwd_cache_write_end(c);
}

void fwd_cache_restored_drop(fwd_cache_t *c, fwd_entry_t *e)
{
    fwd_cache_write_begin(c);
    e->valid    = false;
    e->restored = false;
    fwd_cache_write_end(c);
}

void fwd_cache_hdr_encode(uint8_t hdr[FWD_SNAP_HDR_SZ], uint32_t count)
{
    fc_put_u32(hdr, FWD_SNAP_MAGIC);
    fc_put_u32(hdr + 4, count);
    fc_put_u16(hdr + 8, FWD_RESP_MAX);
    fc_put_u16(hdr + 10, 0);
}
void fwd_cache_count_encode(uint8_t out[4], uint32_t count)
{
    fc_put_u32(out, count);
}
bool fwd_cache_hdr_decode(const uint8_t *hdr, size_t avail, uint32_t max_entries,
                          uint32_t *count, uint32_t *magic, uint16_t *entry_max)
{
    if (!hdr || avail < FWD_SNAP_HDR_SZ) return false;
    *magic     = fc_get_u32(hdr);
    *count     = fc_get_u32(hdr + 4);
    *entry_max = fc_get_u16(hdr + 8);
    /* count > max is impossible from a good save (one record per entry), so
     * it means corruption or a format change. */
    if (*magic != FWD_SNAP_MAGIC || *entry_max != FWD_RESP_MAX || *count > max_entries)
        return false;
    return true;
}
void fwd_cache_rec_encode(uint8_t rec[FWD_SNAP_REC_SZ], uint32_t h, uint16_t qtype, uint16_t resp_len)
{
    fc_put_u32(rec, h);
    fc_put_u16(rec + 4, qtype);
    fc_put_u16(rec + 6, resp_len);
}
bool fwd_cache_rec_decode(const uint8_t *rec, size_t avail,
                          uint32_t *h, uint16_t *qtype, uint16_t *resp_len)
{
    if (!rec || avail < FWD_SNAP_REC_SZ) return false;
    *h        = fc_get_u32(rec);
    *qtype    = fc_get_u16(rec + 4);
    *resp_len = fc_get_u16(rec + 6);
    if (*resp_len == 0 || *resp_len > FWD_RESP_MAX) return false;
    return true;
}
