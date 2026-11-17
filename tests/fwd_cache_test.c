/*
 * Host tests for main/fwd_cache.c - the forward (result) cache moved out of
 * dns_server.cpp. Every expectation below was read off the pre-extraction
 * code, not designed: if one fails, the move changed behaviour.
 *
 * Build + run:
 *   gcc -O2 -fsanitize=address,undefined -I main -o fwd_cache_test \
 *       tests/fwd_cache_test.c main/fwd_cache.c main/domain.c && ./fwd_cache_test
 */
#include "fwd_cache.h"
#include "domain.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail = 0;
#define CHECK(cond, ...) do { if (!(cond)) { \
    printf("  FAIL: "); printf(__VA_ARGS__); printf("\n"); g_fail++; } } while (0)

static fwd_cache_t C;

static void fresh(void)
{
    free(C.e);
    memset(&C, 0, sizeof(C));
    fwd_entry_t *buf = calloc(FWD_CACHE_ENTRIES, sizeof(fwd_entry_t));
    if (!buf || !fwd_cache_init(&C, buf, FWD_CACHE_ENTRIES)) { printf("init failed\n"); exit(2); }
}

/* Response for `name` (dotted, <=63-byte labels), padded with 0x5A to `len`
 * total bytes. Returns the wire QNAME length via *qn_len; qname sits at [12]. */
static int mk_resp(uint8_t *out, int len, const char *name, int *qn_len)
{
    memset(out, 0x5A, (size_t)len);
    memset(out, 0, FWD_DNS_HDR_LEN);
    out[0] = 0x12; out[1] = 0x34; out[2] = 0x81; out[3] = 0x80; out[5] = 1;
    int p = FWD_DNS_HDR_LEN;
    const char *s = name;
    while (*s) {
        const char *d = strchr(s, '.');
        int l = d ? (int)(d - s) : (int)strlen(s);
        out[p++] = (uint8_t)l;
        memcpy(out + p, s, (size_t)l);
        p += l;
        s += l + (d ? 1 : 0);
        if (!d) break;
    }
    out[p++] = 0;
    *qn_len = p - FWD_DNS_HDR_LEN;
    out[p] = 0; out[p + 1] = 1; out[p + 2] = 0; out[p + 3] = 1;
    return len;
}

#define H 0xC0FFEE11u

static void test_store_get_identical(void)
{
    printf("store then get returns identical bytes\n");
    fresh();
    uint8_t r[200], out[600]; int qn;
    mk_resp(r, 200, "example.com", &qn);
    fwd_cache_store_resp(&C, H, 1, r, 200, 60, 1000, 7);
    fwd_entry_t *e = fwd_cache_lookup(&C, H, 1, r + 12, qn, 1500, 7);
    CHECK(e && !e->blocked && e->resp_len == 200 && memcmp(e->resp, r, 200) == 0, "lookup bytes");
    int n = fwd_cache_l2_get(&C, H, 1, r + 12, qn, 1500, 7, out, sizeof(out));
    CHECK(n == 200 && memcmp(out, r, 200) == 0, "l2 get bytes n=%d", n);
    CHECK(fwd_cache_l2_get(&C, H, 1, r + 12, qn, 1500, 7, out, 199) == -1, "out_cap too small -> miss");
    CHECK(fwd_cache_l2_get(&C, H, 1, r + 12, qn, 1500, 7, NULL, 600) == -1, "null out -> miss");
    CHECK(fwd_cache_lookup(&C, H, 1, r + 12, qn, 1500, 8) == NULL, "newer generation -> miss");
    CHECK(fwd_cache_l2_get(&C, H, 1, r + 12, qn, 1500, 8, out, sizeof(out)) == -1, "l2 newer gen -> miss");
}

static void test_qtype_separate(void)
{
    printf("same name, different qtype is a different entry\n");
    fresh();
    uint8_t a[100], b[120]; int qn;
    mk_resp(a, 100, "example.com", &qn);
    mk_resp(b, 120, "example.com", &qn);
    fwd_cache_store_resp(&C, H, 1, a, 100, 60, 0, 0);
    CHECK(fwd_cache_lookup(&C, H, 28, a + 12, qn, 1, 0) == NULL, "AAAA must miss before store");
    fwd_cache_store_resp(&C, H, 28, b, 120, 60, 0, 0);
    fwd_entry_t *ea = fwd_cache_lookup(&C, H, 1, a + 12, qn, 1, 0);
    fwd_entry_t *eb = fwd_cache_lookup(&C, H, 28, a + 12, qn, 1, 0);
    CHECK(ea && eb && ea != eb && ea->resp_len == 100 && eb->resp_len == 120, "both live");
}

static void test_case_insensitive_key_hit(void)
{
    printf("qname case is ignored by the key (dns_qname_wire_eq folds ASCII case)\n");
    fresh();
    uint8_t a[100], q[64]; int qn, qn2;
    mk_resp(a, 100, "Example.COM", &qn);
    mk_resp(q, 40, "eXAMple.com", &qn2);
    fwd_cache_store_resp(&C, H, 1, a, 100, 60, 0, 0);
    fwd_entry_t *e = fwd_cache_lookup(&C, H, 1, q + 12, qn2, 1, 0);
    CHECK(e != NULL, "differently-cased name hits");
    CHECK(e && memcmp(e->resp + 12, "\x07" "Example", 8) == 0, "stored bytes keep the original case");
    /* storing the other casing overwrites in place (own way), no twin */
    uint8_t b[100]; mk_resp(b, 100, "EXAMPLE.com", &qn);
    fwd_cache_store_resp(&C, H, 1, b, 100, 60, 0, 0);
    int live = 0;
    for (uint32_t i = 0; i < C.entries; i++) live += C.e[i].valid;
    CHECK(live == 1, "one live entry, got %d", live);
    /* a different name with the same hash is a different key */
    uint8_t d[100]; int qnd; mk_resp(d, 100, "example.org", &qnd);
    CHECK(fwd_cache_lookup(&C, H, 1, d + 12, qnd, 1, 0) == NULL, "colliding hash, other name -> miss");
}

static void test_oversize_rejected(void)
{
    printf("response one byte over FWD_RESP_MAX is rejected, old entry intact\n");
    fresh();
    uint8_t a[FWD_RESP_MAX + 1], big[FWD_RESP_MAX + 1]; int qn;
    mk_resp(a, 100, "example.com", &qn);
    fwd_cache_store_resp(&C, H, 1, a, 100, 60, 0, 0);
    mk_resp(big, FWD_RESP_MAX + 1, "example.com", &qn);
    uint32_t seq0 = C.seq;
    fwd_cache_store_resp(&C, H, 1, big, FWD_RESP_MAX + 1, 60, 5, 9);
    fwd_entry_t *e = fwd_cache_lookup(&C, H, 1, a + 12, qn, 1, 0);
    CHECK(e && e->resp_len == 100 && e->load_gen == 0, "old entry untouched");
    CHECK(C.toobig == 1, "toobig=%u", (unsigned)C.toobig);
    CHECK(C.seq == seq0, "seqlock not touched by a rejected store");
    fwd_cache_store_resp(&C, H, 1, big, 0, 60, 0, 0);
    fwd_cache_store_resp(&C, H, 1, big, -5, 60, 0, 0);
    CHECK(C.toobig == 1, "len<=0 is a silent no-op, not toobig");
    mk_resp(big, FWD_RESP_MAX, "example.com", &qn);
    fwd_cache_store_resp(&C, H, 1, big, FWD_RESP_MAX, 60, 0, 0);
    e = fwd_cache_lookup(&C, H, 1, a + 12, qn, 1, 0);
    CHECK(e && e->resp_len == FWD_RESP_MAX, "exactly FWD_RESP_MAX accepted");
    /* unparsable question name: silently dropped */
    uint8_t bad[40]; memset(bad, 0, sizeof(bad)); bad[12] = 0xC0; bad[13] = 0x0C;
    fwd_cache_store_resp(&C, 0x1234, 1, bad, 40, 60, 0, 0);
    CHECK(C.toobig == 1 && fwd_cache_lookup(&C, 0x1234, 1, bad + 12, 2, 1, 0) == NULL, "bad qname dropped");
}

static void test_stale_window(void)
{
    printf("expired inside the stale window = stale; past it = miss\n");
    fresh();
    uint8_t r[100]; int qn;
    mk_resp(r, 100, "example.com", &qn);
    const uint64_t t0 = 5000, dl = t0 + 10 * 1000ull, win = (uint64_t)FWD_STALE_MAX_S * 1000u;
    fwd_cache_store_resp(&C, H, 1, r, 100, 10, t0, 3);
    CHECK(fwd_cache_lookup(&C, H, 1, r + 12, qn, dl - 1, 3) != NULL, "fresh one ms before deadline");
    CHECK(fwd_cache_lookup_stale(&C, H, 1, r + 12, qn, dl - 1, 3) == NULL, "not stale while fresh");
    CHECK(fwd_cache_lookup(&C, H, 1, r + 12, qn, dl, 3) == NULL, "deadline == now is expired (strict >)");
    fwd_entry_t *s = fwd_cache_lookup_stale(&C, H, 1, r + 12, qn, dl, 3);
    CHECK(s != NULL, "stale at deadline");
    CHECK(fwd_cache_lookup_stale(&C, H, 1, r + 12, qn, dl + win - 1, 3) != NULL, "stale last ms of window");
    CHECK(fwd_cache_lookup_stale(&C, H, 1, r + 12, qn, dl + win, 3) == NULL, "miss at window end");
    CHECK(fwd_cache_lookup_stale(&C, H, 1, r + 12, qn, dl, 4) == NULL, "stale entry under a newer generation -> miss");
    /* blocked entries are never served stale */
    fwd_cache_store_blocked(&C, 0x77, 1, r + 12, qn, 10, t0, 3);
    CHECK(fwd_cache_lookup(&C, 0x77, 1, r + 12, qn, t0 + 1, 3) != NULL, "blocked fresh hit");
    CHECK(fwd_cache_lookup_stale(&C, 0x77, 1, r + 12, qn, dl, 3) == NULL, "blocked never stale");
}

static void test_refresh_gate(void)
{
    printf("stale refresh gate: armed once per hold interval\n");
    fresh();
    uint8_t r[100]; int qn;
    mk_resp(r, 100, "example.com", &qn);
    fwd_cache_store_resp(&C, H, 1, r, 100, 10, 0, 0);
    fwd_entry_t *e = fwd_cache_lookup(&C, H, 1, r + 12, qn, 1, 0);
    CHECK(e && e->refresh_after_ms == 0, "fresh store leaves the gate open");
    e = fwd_cache_lookup_stale(&C, H, 1, r + 12, qn, 20000, 0);
    CHECK(e != NULL, "stale");
    CHECK(fwd_cache_refresh_arm(e, 20000, 3000), "first stale touch: refresh wanted");
    CHECK(e->refresh_after_ms == 23000, "gate = now + hold");
    CHECK(!fwd_cache_refresh_arm(e, 20000, 3000), "second touch same ms: no refresh");
    CHECK(!fwd_cache_refresh_arm(e, 22999, 3000), "inside hold: no refresh");
    CHECK(fwd_cache_refresh_arm(e, 23000, 3000), "gate reached (>=): refresh wanted");
    fwd_cache_refresh_disarm(e);
    CHECK(e->refresh_after_ms == 0 && fwd_cache_refresh_arm(e, 23001, 3000), "disarm reopens the gate");
    /* re-store (the refresh landing) resets the gate and the deadline */
    fwd_cache_store_resp(&C, H, 1, r, 100, 10, 24000, 0);
    e = fwd_cache_lookup(&C, H, 1, r + 12, qn, 24001, 0);
    CHECK(e && e->refresh_after_ms == 0, "store resets the gate");
}

/* Four names that all map to one (H, qtype) set. */
static void fill_names(uint8_t names[4][40], int lens[4])
{
    static const char *n[4] = { "a.example", "b.example", "c.example", "d.example" };
    for (int i = 0; i < 4; i++) { uint8_t r[60]; mk_resp(r, 40, n[i], &lens[i]); memcpy(names[i], r + 12, 28); }
}

static void test_eviction_choice(void)
{
    printf("victim: own way, then invalid way, then earliest usefulness end\n");
    fresh();
    uint8_t nm[4][40]; int ln[4]; fill_names(nm, ln);
    uint8_t r[100]; int qn;
    fwd_entry_t *set0 = &C.e[((H ^ (1u << 1)) & (C.set_mask)) * FWD_CACHE_WAYS];
    mk_resp(r, 100, "a.example", &qn);
    fwd_entry_t *v = fwd_cache_victim(&C, H, 1, nm[0], ln[0], 100);
    CHECK(v == &set0[0] && C.evict == 0, "empty set: way 0, no evict count");
    fwd_cache_store_resp(&C, H, 1, r, 100, 100, 0, 0);        /* way 0: allowed, dl 100 s */
    v = fwd_cache_victim(&C, H, 1, nm[1], ln[1], 100);
    CHECK(v == &set0[1] && C.evict == 0, "next invalid way is first with end 0 after way0");
    /* fill ways 1..3: blocked dl 200 s, blocked dl 50 s, allowed dl 1 s */
    fwd_cache_store_blocked(&C, H, 1, nm[1], ln[1], 200, 0, 0);
    fwd_cache_store_blocked(&C, H, 1, nm[2], ln[2], 50, 0, 0);
    mk_resp(r, 100, "d.example", &qn);
    fwd_cache_store_resp(&C, H, 1, r, 100, 1, 0, 0);
    CHECK(set0[0].valid && set0[1].valid && set0[2].valid && set0[3].valid, "set full");
    CHECK(set0[1].blocked && set0[2].blocked && !set0[3].blocked, "layout as built");
    /* ends: w0 allowed 100s+86400s, w1 blocked 200s, w2 blocked 50s, w3 allowed 1s+86400s.
     * Earliest end = way 2 (blocked, 50 s). */
    uint8_t e5[40]; int l5; { uint8_t t[60]; mk_resp(t, 40, "e.example", &l5); memcpy(e5, t + 12, 28); }
    v = fwd_cache_victim(&C, H, 1, e5, l5, 10000);
    CHECK(v == &set0[2], "blocked entry that ends soonest is the victim");
    CHECK(C.evict == 1, "still-useful (end > now) eviction counted, evict=%u", (unsigned)C.evict);
    v = fwd_cache_victim(&C, H, 1, e5, l5, 60000);          /* way 2 already worthless */
    CHECK(v == &set0[2] && C.evict == 1, "expired blocked victim is not counted");
    /* equal ends: first way wins (strict <) */
    v = fwd_cache_victim(&C, H, 1, nm[3], ln[3], 100);
    CHECK(v == &set0[3], "own way wins over a lower-end way");
    /* tie -> lowest index: expire everything equally */
    fresh();
    set0 = &C.e[((H ^ (1u << 1)) & (C.set_mask)) * FWD_CACHE_WAYS];
    for (int i = 0; i < 4; i++) fwd_cache_store_blocked(&C, H, 1, nm[i], ln[i], 10, 0, 0);
    v = fwd_cache_victim(&C, H, 1, e5, l5, 0);
    CHECK(v == &set0[0] && C.evict == 1, "tie goes to way 0");
}

static void test_ms_wrap(void)
{
    printf("deadlines are 64-bit ms: no wrap at 2^32\n");
    fresh();
    uint8_t r[100]; int qn;
    mk_resp(r, 100, "example.com", &qn);
    const uint64_t t0 = 0xFFFFFF00ull;                    /* 256 ms before 2^32 */
    fwd_cache_store_resp(&C, H, 1, r, 100, 10, t0, 0);
    CHECK(C.e[0].valid || 1, "stored");
    uint64_t past = 0x100000000ull + 5;                   /* 2^32 + 5, inside the 10 s TTL */
    CHECK(fwd_cache_lookup(&C, H, 1, r + 12, qn, past, 0) != NULL, "still fresh past 2^32");
    CHECK(fwd_cache_lookup(&C, H, 1, r + 12, qn, t0 + 10000, 0) == NULL, "expires on the 64-bit deadline");
    CHECK(fwd_cache_lookup_stale(&C, H, 1, r + 12, qn, t0 + 10000, 0) != NULL, "then stale");
    /* a 32-bit-truncated 'now' would look like the distant past and read fresh: it must not matter */
    CHECK(fwd_cache_lookup(&C, H, 1, r + 12, qn, (uint32_t)(t0 + 10000), 0) != NULL,
          "truncated now (caller bug) reads fresh - documents that now_ms must stay 64-bit");
}

static void test_seqlock(void)
{
    printf("seqlock: odd = writer mid-update = miss; counter bumps by 2 per store\n");
    fresh();
    uint8_t r[100], out[600]; int qn;
    mk_resp(r, 100, "example.com", &qn);
    fwd_cache_store_resp(&C, H, 1, r, 100, 60, 0, 0);
    CHECK(C.seq == 2, "one store = two bumps, seq=%u", (unsigned)C.seq);
    CHECK((C.seq & 1u) == 0, "even at rest");
    CHECK(fwd_cache_l2_get(&C, H, 1, r + 12, qn, 1, 0, out, sizeof(out)) == 100, "reader sees old entry");
    fwd_cache_write_begin(&C);
    CHECK((C.seq & 1u) == 1, "odd inside a write");
    CHECK(fwd_cache_l2_get(&C, H, 1, r + 12, qn, 1, 0, out, sizeof(out)) == -1, "reader during write -> retry (miss)");
    uint32_t h2; uint16_t q2, l2; uint8_t snap[FWD_RESP_MAX];
    int hits = 0;
    for (uint32_t i = 0; i < C.entries; i++)
        hits += fwd_cache_snap_read(&C, i, 1, snap, &h2, &q2, &l2);
    CHECK(hits == 0, "snapshot reader during write skips everything");
    fwd_cache_write_end(&C);
    CHECK(C.seq == 4, "even again after the write, seq=%u", (unsigned)C.seq);
    uint8_t r2[130]; mk_resp(r2, 130, "example.com", &qn);
    fwd_cache_store_resp(&C, H, 1, r2, 130, 60, 0, 0);
    CHECK(fwd_cache_l2_get(&C, H, 1, r + 12, qn, 1, 0, out, sizeof(out)) == 130, "reader sees the new entry");
    CHECK(fwd_cache_l2_get(NULL, H, 1, r + 12, qn, 1, 0, out, sizeof(out)) == -1, "null cache -> miss");
    fwd_cache_store_blocked(&C, 0x99, 1, r + 12, qn, 60, 0, 0);
    CHECK(fwd_cache_l2_get(&C, 0x99, 1, r + 12, qn, 1, 0, out, sizeof(out)) == -1, "L2 never replays blocked entries");
}

static void test_snap_and_load(void)
{
    printf("snapshot read + warm-boot insert\n");
    fresh();
    uint8_t r[100], snap[FWD_RESP_MAX]; int qn;
    mk_resp(r, 100, "example.com", &qn);
    const uint64_t win = (uint64_t)FWD_STALE_MAX_S * 1000u;
    fwd_cache_store_resp(&C, H, 1, r, 100, 10, 1000, 0);
    int found = 0; uint32_t h = 0; uint16_t qt = 0, rl = 0;
    for (uint32_t i = 0; i < C.entries; i++)
        if (fwd_cache_snap_read(&C, i, 2000, snap, &h, &qt, &rl)) found++;
    CHECK(found == 1 && h == H && qt == 1 && rl == 100 && memcmp(snap, r, 100) == 0, "allowed entry read back");
    found = 0;
    for (uint32_t i = 0; i < C.entries; i++)
        if (fwd_cache_snap_read(&C, i, 11000 + win, snap, &h, &qt, &rl)) found++;
    CHECK(found == 0, "entry past its stale window is dropped (deadline+window <= now)");
    found = 0;
    for (uint32_t i = 0; i < C.entries; i++)
        if (fwd_cache_snap_read(&C, i, 11000 + win - 1, snap, &h, &qt, &rl)) found++;
    CHECK(found == 1, "one ms inside the window is kept");
    fwd_cache_store_blocked(&C, 0x55, 1, r + 12, qn, 10, 1000, 0);
    found = 0;
    for (uint32_t i = 0; i < C.entries; i++)
        if (fwd_cache_snap_read(&C, i, 2000, snap, &h, &qt, &rl)) found++;
    CHECK(found == 1, "blocked entries are not snapshotted");

    fresh();
    CHECK(fwd_cache_load_insert(&C, H, 1, r, 100, 777), "load insert ok");
    CHECK(fwd_cache_lookup(&C, H, 1, r + 12, qn, 778, 0) == NULL, "restored entry is not fresh");
    fwd_entry_t *e = fwd_cache_lookup_stale(&C, H, 1, r + 12, qn, 778, 0);
    CHECK(e && e->ttl_deadline_ms == 1 && e->refresh_after_ms == 0 && e->resp_len == 100 &&
          !e->blocked && e->load_gen == 0, "restored stale, gate open, generation 0");
    uint8_t bad[40]; memset(bad, 0, sizeof(bad)); bad[12] = 0xC0;
    CHECK(!fwd_cache_load_insert(&C, 0x1, 1, bad, 40, 777), "unparsable qname skipped");
}

static void test_codec(void)
{
    printf("snapshot header/record codec\n");
    uint8_t hdr[FWD_SNAP_HDR_SZ], rec[FWD_SNAP_REC_SZ];
    uint32_t count = 0, magic = 0; uint16_t emax = 0;
    fwd_cache_hdr_encode(hdr, 0);
    CHECK(hdr[0] == 0x01 && hdr[1] == 0xCE && hdr[2] == 0xCA && hdr[3] == 0xFD, "magic bytes LE 0xFDCACE01");
    CHECK(hdr[8] == (FWD_RESP_MAX & 0xFF) && hdr[9] == (FWD_RESP_MAX >> 8) && hdr[10] == 0 && hdr[11] == 0, "emax + rsv");
    uint8_t cnt[4]; fwd_cache_count_encode(cnt, 0x01020304u);
    CHECK(cnt[0] == 4 && cnt[1] == 3 && cnt[2] == 2 && cnt[3] == 1, "count LE");
    memcpy(hdr + 4, cnt, 4);
    CHECK(fwd_cache_hdr_decode(hdr, sizeof(hdr), 0x01020304u, &count, &magic, &emax) && count == 0x01020304u, "round trip");
    CHECK(!fwd_cache_hdr_decode(hdr, sizeof(hdr), 0x01020303u, &count, &magic, &emax), "count > entries rejected");
    CHECK(count == 0x01020304u && magic == FWD_SNAP_MAGIC && emax == FWD_RESP_MAX, "fields reported even on reject (for the log)");
    fwd_cache_hdr_encode(hdr, 5);
    uint8_t t[FWD_SNAP_HDR_SZ];
    memcpy(t, hdr, sizeof(t)); t[0] ^= 1;
    CHECK(!fwd_cache_hdr_decode(t, sizeof(t), FWD_CACHE_ENTRIES, &count, &magic, &emax), "wrong magic");
    memcpy(t, hdr, sizeof(t)); t[8] ^= 1;
    CHECK(!fwd_cache_hdr_decode(t, sizeof(t), FWD_CACHE_ENTRIES, &count, &magic, &emax), "wrong entry_max");
    CHECK(!fwd_cache_hdr_decode(hdr, sizeof(hdr) - 1, FWD_CACHE_ENTRIES, &count, &magic, &emax), "truncated header");
    CHECK(fwd_cache_hdr_decode(hdr, sizeof(hdr), FWD_CACHE_ENTRIES, &count, &magic, &emax) && count == 5, "good header");
    CHECK(fwd_cache_hdr_decode(hdr, sizeof(hdr), 5, &count, &magic, &emax), "count == entries accepted");

    uint32_t h = 0; uint16_t qt = 0, rl = 0;
    fwd_cache_rec_encode(rec, 0xA1B2C3D4u, 28, 321);
    CHECK(rec[0] == 0xD4 && rec[3] == 0xA1 && rec[4] == 28 && rec[5] == 0 && rec[6] == (321 & 0xFF) && rec[7] == (321 >> 8), "record LE layout");
    CHECK(fwd_cache_rec_decode(rec, sizeof(rec), &h, &qt, &rl) && h == 0xA1B2C3D4u && qt == 28 && rl == 321, "record round trip");
    CHECK(!fwd_cache_rec_decode(rec, sizeof(rec) - 1, &h, &qt, &rl), "truncated record");
    fwd_cache_rec_encode(rec, 1, 1, 0);
    CHECK(!fwd_cache_rec_decode(rec, sizeof(rec), &h, &qt, &rl), "resp_len 0 rejected");
    fwd_cache_rec_encode(rec, 1, 1, FWD_RESP_MAX + 1);
    CHECK(!fwd_cache_rec_decode(rec, sizeof(rec), &h, &qt, &rl), "resp_len > max rejected");
    fwd_cache_rec_encode(rec, 1, 1, FWD_RESP_MAX);
    CHECK(fwd_cache_rec_decode(rec, sizeof(rec), &h, &qt, &rl) && rl == FWD_RESP_MAX, "resp_len == max accepted");
}

int main(void)
{
    test_store_get_identical();
    test_qtype_separate();
    test_case_insensitive_key_hit();
    test_oversize_rejected();
    test_stale_window();
    test_refresh_gate();
    test_eviction_choice();
    test_ms_wrap();
    test_seqlock();
    test_snap_and_load();
    test_codec();
    free(C.e);
    if (g_fail) { printf("%d FAILED\n", g_fail); return 1; }
    printf("all fwd_cache tests passed\n");
    return 0;
}
