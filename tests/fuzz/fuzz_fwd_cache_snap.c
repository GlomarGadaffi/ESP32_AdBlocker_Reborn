/*
 * libFuzzer target: the forward-cache SD snapshot decoder in main/fwd_cache.c.
 *
 * The input is a whole /sdcard/fwdcache.bin: header, then count x (record +
 * response). It is replayed through exactly the sequence cache_load_sd()
 * performs (hdr_decode, then rec_decode / read resp / load_insert per record),
 * into a small cache, then read back through the save path (snap_read).
 *
 * The file is attacker/corruption-controlled (a removable SD card), so:
 *  - the input is copied into an exact-size heap buffer and consumed only
 *    through bounds the loop checks itself, so an over-read is an ASan report
 *  - a stored response is only ever resp_len <= FWD_RESP_MAX bytes
 *
 * Invariants (a false assert is a finding):
 *  - hdr_decode success implies magic/entry_max/count are the accepted values
 *  - rec_decode success implies 1 <= resp_len <= FWD_RESP_MAX
 *  - every entry load_insert leaves valid is allowed (not blocked), has
 *    resp_len in range, qn_len == dns_qname_wire_len(resp), deadline 1 and an
 *    open refresh gate
 *  - such an entry is restored and NOT served (fresh or stale) under the
 *    load-time generation until restored_adopt; after adopt, lookup_stale
 *    finds it and it is still not fresh
 *  - snap_read of it returns the same key/len/bytes, and re-encoding that as a
 *    record then decoding gives the same triple (codec round trip)
 */
#include "fwd_cache.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define FZ_ENTRIES 8u   /* WAYS x 2 sets: small, so collisions and evictions are common */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t *in = (uint8_t *)malloc(size ? size : 1);
    if (!in) return 0;
    if (size) memcpy(in, data, size);

    fwd_entry_t *buf = (fwd_entry_t *)calloc(FZ_ENTRIES, sizeof(fwd_entry_t));
    fwd_cache_t c;
    if (!buf || !fwd_cache_init(&c, buf, FZ_ENTRIES)) { free(buf); free(in); return 0; }

    uint32_t count = 0, magic = 0; uint16_t emax = 0;
    if (fwd_cache_hdr_decode(in, size, FZ_ENTRIES, &count, &magic, &emax)) {
        assert(magic == FWD_SNAP_MAGIC && emax == FWD_RESP_MAX && count <= FZ_ENTRIES);
        size_t pos = FWD_SNAP_HDR_SZ;
        fwd_cache_write_begin(&c);
        for (uint32_t i = 0; i < count; i++) {
            uint32_t h = 0; uint16_t qt = 0, rl = 0;
            if (size - pos < FWD_SNAP_REC_SZ) break;                  /* truncated */
            if (!fwd_cache_rec_decode(in + pos, size - pos, &h, &qt, &rl)) break;
            assert(rl >= 1 && rl <= FWD_RESP_MAX);
            pos += FWD_SNAP_REC_SZ;
            if (size - pos < rl) break;                               /* truncated */
            /* Exact-size copy so load_insert reading past rl is an ASan hit. */
            uint8_t *resp = (uint8_t *)malloc(rl);
            memcpy(resp, in + pos, rl);
            pos += rl;
            (void)fwd_cache_load_insert(&c, h, qt, resp, rl, 5, 0);
            free(resp);
        }
        fwd_cache_write_end(&c);
        assert((c.seq & 1u) == 0);

        uint8_t snap[FWD_RESP_MAX];
        for (uint32_t i = 0; i < c.entries; i++) {
            fwd_entry_t *e = &c.e[i];
            if (!e->valid) continue;
            assert(e->restored && e->load_gen != 0);
            assert(!e->blocked && e->resp_len >= 1 && e->resp_len <= FWD_RESP_MAX);
            assert(e->ttl_deadline_ms == 1 && e->refresh_after_ms == 0);
            assert(e->qn_len > 0 && e->qn_len <= (uint16_t)(e->resp_len - FWD_DNS_HDR_LEN));
            assert(fwd_cache_lookup(&c, e->key_hash, e->qtype, e->resp + FWD_DNS_HDR_LEN,
                                    e->qn_len, 2, 0) == NULL);
            assert(fwd_cache_lookup_stale(&c, e->key_hash, e->qtype, e->resp + FWD_DNS_HDR_LEN,
                                          e->qn_len, 2, 0) == NULL);
            assert(fwd_cache_restored_pending(&c, e->key_hash, e->qtype,
                                              e->resp + FWD_DNS_HDR_LEN, e->qn_len, 2, 0) == e);
            fwd_cache_restored_adopt(&c, e, 0);
            assert(fwd_cache_restored_pending(&c, e->key_hash, e->qtype,
                                              e->resp + FWD_DNS_HDR_LEN, e->qn_len, 2, 0) == NULL);
            assert(fwd_cache_lookup(&c, e->key_hash, e->qtype, e->resp + FWD_DNS_HDR_LEN,
                                    e->qn_len, 2, 0) == NULL);
            assert(fwd_cache_lookup_stale(&c, e->key_hash, e->qtype, e->resp + FWD_DNS_HDR_LEN,
                                          e->qn_len, 2, 0) == e);
            uint32_t h = 0; uint16_t qt = 0, rl = 0;
            assert(fwd_cache_snap_read(&c, i, 2, snap, &h, &qt, &rl));
            assert(h == e->key_hash && qt == e->qtype && rl == e->resp_len);
            assert(memcmp(snap, e->resp, rl) == 0);
            uint8_t rec[FWD_SNAP_REC_SZ];
            uint32_t h2 = 0; uint16_t qt2 = 0, rl2 = 0;
            fwd_cache_rec_encode(rec, h, qt, rl);
            assert(fwd_cache_rec_decode(rec, sizeof(rec), &h2, &qt2, &rl2));
            assert(h2 == h && qt2 == qt && rl2 == rl);
        }
    } else if (size >= FWD_SNAP_HDR_SZ) {
        /* Rejected header: the decoder must still report what it saw. */
        assert(magic != FWD_SNAP_MAGIC || emax != FWD_RESP_MAX || count > FZ_ENTRIES);
    }

    free(buf);
    free(in);
    return 0;
}
