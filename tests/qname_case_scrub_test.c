/*
 * Host tests for #72's reply-side case scrub (main/dns_server.cpp):
 * normalize_qname_case() + normalize_answer_owner_names(), which lowercase
 * the 0x20 pattern out of an upstream reply before it is delivered/cached.
 *
 * Build + run:
 *   gcc -O2 -I main -o qname_case_scrub_test tests/qname_case_scrub_test.c main/domain.c && ./qname_case_scrub_test
 *
 * The functions under test are file-static in dns_server.cpp, which drags in
 * the whole IDF tree, so they (and decompress_name()) are copied verbatim
 * below — same approach as l2_finish_reply_test.c. If the real ones change,
 * re-sync these copies by eye; this test can't detect drift.
 *
 * The regression this pins: the first version lowercased every byte from an
 * RR's owner-name start to the end of the name, which includes the 2-byte
 * compression pointer when the owner name is compressed. A pointer whose low
 * byte is 0x41-0x5A reads as 'A'-'Z' and got OR-ed with 0x20, re-aiming it
 * 32 bytes forward — e.g. a CNAME chain whose second answer points at the
 * first answer's target at offset 0x44. The pre-fix copy is kept below as
 * old_normalize_answer_owner_names() so the test proves it detects that.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "domain.h"

static int g_fail = 0;
#define CHECK(cond, ...) do { if (!(cond)) { \
    printf("  FAIL: "); printf(__VA_ARGS__); printf("\n"); g_fail++; } } while (0)

#define DNS_HDR_LEN 12   /* sizeof(DnsHeader) */

/* ── verbatim copies from dns_server.cpp ─────────────────────────────── */
static bool decompress_name(const uint8_t *pkt, int len, int *off,
                            char *name_out, size_t name_cap, size_t *nlen_out)
{
    char raw[256]; size_t rl = 0;
    int read_off = *off;
    bool advanced = false;
    int jumps = 0;
    while (read_off < len) {
        uint8_t b = pkt[read_off];
        if (b == 0) {
            if (!advanced) *off = read_off + 1;
            size_t nl = domain_normalize(name_out, name_cap, raw, rl);
            if (!nl) return false;
            *nlen_out = nl;
            return true;
        }
        if ((b & 0xC0) == 0xC0) {
            if (read_off + 1 >= len) return false;
            if (!advanced) { *off = read_off + 2; advanced = true; }
            int target = ((b & 0x3F) << 8) | pkt[read_off + 1];
            if (target >= read_off || ++jumps > 20) return false;
            read_off = target;
            continue;
        }
        if (b & 0xC0) return false;                       /* reserved label length */
        if (read_off + 1 + b > len) return false;
        if (rl + (size_t)b + 1 >= sizeof(raw)) return false;
        if (rl) raw[rl++] = '.';
        memcpy(raw + rl, pkt + read_off + 1, b);
        rl += b;
        read_off += 1 + b;
    }
    return false;
}

static inline void normalize_qname_case(uint8_t *pkt, int qend)
{
    for (int i = DNS_HDR_LEN; i < qend - 4; i++) {
        uint8_t c = pkt[i];
        if ((c | 0x20) < 'a' || (c | 0x20) > 'z') continue;   /* label-length byte or the null label */
        pkt[i] = c | 0x20;
    }
}

static void normalize_answer_owner_names(uint8_t *pkt, int len, int qend)
{
    if (len < 12) return;
    int ancount = (pkt[6]  << 8) | pkt[7];
    int nscount = (pkt[8]  << 8) | pkt[9];
    int arcount = (pkt[10] << 8) | pkt[11];
    int off = qend;
    for (int i = 0; i < ancount + nscount + arcount; i++) {
        int start = off;
        char name[256]; size_t nlen = 0;
        if (!decompress_name(pkt, len, &off, name, sizeof(name), &nlen)) return;
        for (int j = start; j < off; ) {
            uint8_t b = pkt[j];
            if (b == 0 || (b & 0xC0)) break;
            for (int k = j + 1; k <= j + b && k < off; k++) {
                uint8_t c = pkt[k];
                if ((c | 0x20) < 'a' || (c | 0x20) > 'z') continue;
                pkt[k] = c | 0x20;
            }
            j += 1 + b;
        }
        if (off + 10 > len) return;
        uint16_t rdlen = ((uint16_t)pkt[off + 8] << 8) | pkt[off + 9];
        off += 10 + rdlen;
        if (off > len) return;
    }
}

/* ── the pre-fix version (byte-flat scan over [start, off)) ──────────── */
static void old_normalize_answer_owner_names(uint8_t *pkt, int len, int qend)
{
    if (len < 12) return;
    int ancount = (pkt[6]  << 8) | pkt[7];
    int nscount = (pkt[8]  << 8) | pkt[9];
    int arcount = (pkt[10] << 8) | pkt[11];
    int off = qend;
    for (int i = 0; i < ancount + nscount + arcount; i++) {
        int start = off;
        char name[256]; size_t nlen = 0;
        if (!decompress_name(pkt, len, &off, name, sizeof(name), &nlen)) return;
        for (int j = start; j < off; j++) {
            uint8_t c = pkt[j];
            if ((c | 0x20) < 'a' || (c | 0x20) > 'z') continue;
            pkt[j] = c | 0x20;
        }
        if (off + 10 > len) return;
        uint16_t rdlen = ((uint16_t)pkt[off + 8] << 8) | pkt[off + 9];
        off += 10 + rdlen;
        if (off > len) return;
    }
}

/* ── packet builder ──────────────────────────────────────────────────── */
typedef struct { uint8_t b[1024]; int n; } Pkt;

static void put8(Pkt *p, uint8_t v)   { p->b[p->n++] = v; }
static void put16(Pkt *p, uint16_t v) { put8(p, v >> 8); put8(p, v & 0xFF); }
static void put_name(Pkt *p, const char *dotted)   /* raw labels, root-terminated */
{
    while (*dotted) {
        const char *dot = strchr(dotted, '.');
        int l = dot ? (int)(dot - dotted) : (int)strlen(dotted);
        put8(p, (uint8_t)l);
        memcpy(p->b + p->n, dotted, l); p->n += l;
        dotted += l + (dot ? 1 : 0);
    }
    put8(p, 0);
}
static void put_ptr(Pkt *p, int target) { put16(p, 0xC000 | target); }
static void put_rr_fixed(Pkt *p, uint16_t type, uint16_t rdlen)
{
    put16(p, type); put16(p, 1); put16(p, 0); put16(p, 300); put16(p, rdlen);
}

/* A CNAME-chain reply: question <qname>; answer 1 = <qname-ptr> CNAME <target>
 * (raw, mixed case); answer 2 = <ptr to target> A 192.0.2.1; authority =
 * <raw mixed-case owner> SOA-ish opaque rdata. Returns qend; fills offsets. */
typedef struct { int qend, cname_rdata, ans2_owner, auth_owner; } Layout;

static Layout build_chain(Pkt *p, const char *qname, const char *target, const char *auth)
{
    Layout L;
    memset(p, 0, sizeof(*p));
    put16(p, 0x1234); put16(p, 0x8180); put16(p, 1); put16(p, 2); put16(p, 1); put16(p, 0);
    put_name(p, qname); put16(p, 1); put16(p, 1);
    L.qend = p->n;
    put_ptr(p, DNS_HDR_LEN);
    put_rr_fixed(p, 5, (uint16_t)(strlen(target) + 2));
    L.cname_rdata = p->n;
    put_name(p, target);
    L.ans2_owner = p->n;
    put_ptr(p, L.cname_rdata);
    put_rr_fixed(p, 1, 4);
    put8(p, 192); put8(p, 0); put8(p, 2); put8(p, 1);
    L.auth_owner = p->n;
    put_name(p, auth);
    put_rr_fixed(p, 6, 4);
    put8(p, 0xAA); put8(p, 0xBB); put8(p, 0xCC); put8(p, 0xDD);
    return L;
}

/* Decompress the name at `at`, 0 on failure. */
static int name_at(const Pkt *p, int at, char *out, size_t cap)
{
    size_t nl = 0; int off = at;
    return decompress_name(p->b, p->n, &off, out, cap, &nl) ? 1 : 0;
}

/* A qname of exactly `wire_len` wire bytes, mixed case. */
static void make_qname(char *out, int wire_len)
{
    /* wire = strlen + 2 for a name with no empty labels */
    int chars = wire_len - 2;
    static const char pat[] = "WwWxYzAbCdEfGhIjKlMnOpQrStUvWx";
    int i = 0, lab = 0;
    while (i < chars) {
        if (lab == 20 && i < chars - 1) { out[i++] = '.'; lab = 0; continue; }
        out[i] = pat[i % (sizeof(pat) - 1)]; i++; lab++;
    }
    out[i] = 0;
}

/* ── tests ───────────────────────────────────────────────────────────── */

static void test_pointer_at_0x44(void)
{
    printf("CNAME chain, answer-2 owner pointer targets 0x44\n");
    /* qend = 16 + qname_wire; cname_rdata = qend + 12  ->  qname_wire = 40 */
    char qn[64]; make_qname(qn, 40);
    Pkt p; Layout L = build_chain(&p, qn, "CdN.EdGe.NeT", "NeT");
    CHECK(L.cname_rdata == 0x44, "fixture drifted: cname rdata at 0x%x", L.cname_rdata);

    char before[256], after[256];
    CHECK(name_at(&p, L.ans2_owner, before, sizeof before), "fixture ans2 owner doesn't parse");

    Pkt old = p;
    normalize_qname_case(old.b, L.qend);
    old_normalize_answer_owner_names(old.b, old.n, L.qend);
    CHECK(old.b[L.ans2_owner + 1] != 0x44,
          "pre-fix version expected to corrupt the pointer, didn't (test can't see the bug)");

    normalize_qname_case(p.b, L.qend);
    normalize_answer_owner_names(p.b, p.n, L.qend);
    CHECK(p.b[L.ans2_owner] == 0xC0 && p.b[L.ans2_owner + 1] == 0x44,
          "pointer rewritten: %02x %02x", p.b[L.ans2_owner], p.b[L.ans2_owner + 1]);
    CHECK(name_at(&p, L.ans2_owner, after, sizeof after) && strcmp(before, after) == 0,
          "ans2 owner now resolves to '%s', want '%s'", after, before);
}

static void test_sweep_every_target(void)
{
    printf("sweep: CNAME target at every offset 0x2c..0x10c\n");
    int old_broken = 0, old_broken_expected = 0;
    for (int wire = 16; wire <= 240; wire++) {
        char qn[256]; make_qname(qn, wire);
        Pkt p; Layout L = build_chain(&p, qn, "CdN.EdGe.NeT", "ExAmPlE.CoM");
        uint8_t lo = (uint8_t)(L.cname_rdata & 0xFF);
        Pkt orig = p, old = p;

        normalize_qname_case(p.b, L.qend);
        normalize_answer_owner_names(p.b, p.n, L.qend);

        /* question: lowercase, same labels */
        for (int i = DNS_HDR_LEN; i < L.qend - 4; i++) {
            uint8_t o = orig.b[i];
            uint8_t want = ((o | 0x20) >= 'a' && (o | 0x20) <= 'z') ? (o | 0x20) : o;
            if (p.b[i] != want) { CHECK(0, "wire=%d question byte %d: %02x want %02x", wire, i, p.b[i], want); break; }
        }
        /* CNAME rdata untouched — out of scope on purpose */
        CHECK(memcmp(p.b + L.cname_rdata, orig.b + L.cname_rdata, L.ans2_owner - L.cname_rdata) == 0,
              "wire=%d CNAME rdata was modified", wire);
        /* both pointers intact */
        CHECK(memcmp(p.b + L.qend, orig.b + L.qend, 2) == 0, "wire=%d answer-1 pointer changed", wire);
        CHECK(memcmp(p.b + L.ans2_owner, orig.b + L.ans2_owner, 2) == 0,
              "wire=%d answer-2 pointer (lo=0x%02x) changed", wire, lo);
        /* raw authority owner lowercased */
        char an[256];
        CHECK(name_at(&p, L.auth_owner, an, sizeof an) && strcmp(an, "example.com") == 0,
              "wire=%d auth owner = '%s'", wire, an);
        CHECK(memcmp(p.b + L.auth_owner, "\x07" "example" "\x03" "com", 13) == 0,
              "wire=%d auth owner bytes not lowercased", wire);
        /* nothing else moved: everything after the auth owner name is byte-identical */
        CHECK(memcmp(p.b + L.auth_owner + 13, orig.b + L.auth_owner + 13, p.n - L.auth_owner - 13) == 0,
              "wire=%d bytes after auth owner changed", wire);

        normalize_qname_case(old.b, L.qend);
        old_normalize_answer_owner_names(old.b, old.n, L.qend);
        if (lo >= 0x41 && lo <= 0x5A) old_broken_expected++;
        if (memcmp(old.b + L.ans2_owner, orig.b + L.ans2_owner, 2) != 0) old_broken++;
    }
    printf("  pre-fix version corrupted %d pointers (expected %d)\n", old_broken, old_broken_expected);
    CHECK(old_broken_expected > 0, "sweep never hit a 0x41-0x5A low byte");
    CHECK(old_broken == old_broken_expected, "pre-fix corruption count %d, expected %d",
          old_broken, old_broken_expected);
}

static void test_truncation_is_safe(void)
{
    printf("every truncation of a chain reply: no overrun, pointers never rewritten\n");
    char qn[64]; make_qname(qn, 40);
    Pkt full; Layout L = build_chain(&full, qn, "CdN.EdGe.NeT", "NeT");
    for (int n = 0; n <= full.n; n++) {
        Pkt p = full; p.n = n;
        uint8_t guard[sizeof p.b];
        memcpy(guard, p.b, sizeof guard);
        if (n >= L.qend) normalize_qname_case(p.b, L.qend);
        normalize_answer_owner_names(p.b, n, L.qend);
        for (int i = n; i < (int)sizeof p.b; i++)
            if (p.b[i] != guard[i]) { CHECK(0, "len=%d wrote past end at %d", n, i); break; }
        if (n >= L.ans2_owner + 2)
            CHECK(p.b[L.ans2_owner + 1] == 0x44, "len=%d pointer rewritten", n);
    }
}

int main(void)
{
    printf("qname case-scrub host tests (#72)\n\n");
    test_pointer_at_0x44();
    test_sweep_every_target();
    test_truncation_is_safe();
    printf("\n%s (%d failure%s)\n", g_fail ? "FAILED" : "PASSED", g_fail, g_fail == 1 ? "" : "s");
    return g_fail ? 1 : 0;
}
