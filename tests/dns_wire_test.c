/*
 * Host tests for main/dns_wire.c — the DNS wire helpers moved out of
 * dns_server.cpp so they can be compiled (and fuzzed) on the host.
 *
 * Build + run:
 *   gcc -O2 -fsanitize=address,undefined -I main -o dns_wire_test \
 *       tests/dns_wire_test.c main/dns_wire.c main/domain.c main/murmur3.c && ./dns_wire_test
 *
 * The SOA cases pin the first bug tests/fuzz/fuzz_dns_wire found: an
 * NXDOMAIN whose SOA declares an rdlen longer than the packet read the
 * "minimum" field from 20 bytes past the end of the buffer.
 */
#include "dns_wire.h"
#include "domain.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail = 0;
#define CHECK(cond, ...) do { if (!(cond)) { \
    printf("  FAIL: "); printf(__VA_ARGS__); printf("\n"); g_fail++; } } while (0)

/* Exact-size heap copy so ASan sees any read past len. */
static uint8_t *dup(const uint8_t *src, size_t n) {
    uint8_t *p = malloc(n ? n : 1); memcpy(p, src, n); return p;
}

/* NXDOMAIN for www.example.com with an SOA in authority (compressed
 * MNAME/RNAME), minimum = 60. 80 bytes. */
static const uint8_t nx_soa[] = {
    0x12,0x34,0x81,0x83, 0,1, 0,0, 0,1, 0,0,
    3,'w','w','w', 7,'e','x','a','m','p','l','e', 3,'c','o','m', 0, 0,1, 0,1,
    0xC0,0x10, 0,6, 0,1, 0,0,0x03,0x84, 0x00,0x23,          /* SOA, TTL 900, rdlen 35 (bytes 43-44) */
    0xC0,0x10, 10,'h','o','s','t','m','a','s','t','e','r', 0xC0,0x10,
    0,0,0,1, 0,0,0,2, 0,0,0,3, 0,0,1,4, 0,0,0,0x3C,
};

static void test_soa_min_ttl(void)
{
    printf("SOA minimum TTL\n");
    uint8_t *p = dup(nx_soa, sizeof nx_soa);
    CHECK(dns_resp_min_ttl(p, sizeof nx_soa, 30, 10, 3600) == 60, "SOA minimum should win (60)");
    /* the same packet with rdlen inflated to 0x2303 (the fuzzer's find):
     * must not read past len */
    p[43] = 0x23; p[44] = 0x03;
    uint32_t t = dns_resp_min_ttl(p, sizeof nx_soa, 30, 10, 3600);
    CHECK(t == 60, "oversized rdlen but the SOA fields are all present: still 60, got %u", (unsigned)t);
    /* ...and with the packet cut off inside the SOA, the read that used to
     * run 20 bytes past the buffer must instead fall back to the default */
    t = dns_resp_min_ttl(p, sizeof nx_soa - 8, 30, 10, 3600);
    CHECK(t == 30, "oversized rdlen + truncated packet -> default, got %u", (unsigned)t);
    /* rdlen exactly reaching the packet end still works */
    p[43] = 0x00; p[44] = 0x23;
    CHECK(dns_resp_min_ttl(p, sizeof nx_soa, 30, 10, 3600) == 60, "exact rdlen ok");
    /* truncated packet: minimum field cut off */
    CHECK(dns_resp_min_ttl(p, sizeof nx_soa - 4, 30, 10, 3600) == 30, "truncated SOA -> default");
    free(p);
}

static void test_answer_min_ttl_and_rewrite(void)
{
    printf("answer TTLs\n");
    uint8_t pkt[] = {
        0,1,0x81,0x80, 0,1, 0,2, 0,0, 0,0,
        1,'a', 0, 0,1, 0,1,
        0xC0,0x0C, 0,1, 0,1, 0,0,0,5, 0,4, 1,1,1,1,           /* TTL 5 -> clamps to 10 */
        0xC0,0x0C, 0,1, 0,1, 0,0,0x10,0, 0,4, 2,2,2,2,        /* TTL 4096 */
    };
    uint8_t *p = dup(pkt, sizeof pkt);
    CHECK(dns_resp_min_ttl(p, sizeof pkt, 30, 10, 3600) == 10, "min across answers, clamped up");
    dns_rewrite_answer_ttls(p, sizeof pkt, 0x01020304);
    CHECK(p[19+6] == 1 && p[19+7] == 2 && p[19+8] == 3 && p[19+9] == 4, "first TTL rewritten");
    CHECK(p[35+6] == 1 && p[35+9] == 4, "second TTL rewritten");
    /* first RR's rdlen (bytes 29-30) inflated past the end: the walk must
     * rewrite that RR's TTL and then stop — the second RR keeps 0x01020304 */
    p[29] = 0xFF; p[30] = 0xFF;
    dns_rewrite_answer_ttls(p, sizeof pkt, 7);
    CHECK(p[19+9] == 7, "first TTL rewritten again");
    CHECK(p[35+6] == 1 && p[35+9] == 4, "walk stopped before second RR");
    free(p);
}

static void test_skip_and_decompress(void)
{
    printf("skip_name / decompress_name\n");
    uint8_t pkt[] = {
        0,0,0,0, 0,0,0,0, 0,0,0,0,
        3,'w','w','w', 7,'E','x','a','m','p','l','e', 3,'c','o','m', 0,   /* 12..28 */
        3,'c','d','n', 0xC0,0x10,                                           /* 29..34: cdn.example.com */
        0xC0,0x1D,                                                          /* 35..36: -> 29 */
        0xC0,0x25,                                                          /* 37..38: forward pointer (illegal) */
        0xC0,                                                               /* 39: truncated pointer */
    };
    uint8_t *p = dup(pkt, sizeof pkt);
    int off = 12;
    CHECK(dns_skip_name(p, sizeof pkt, &off) && off == 29, "skip plain name -> 29, got %d", off);
    off = 29;
    CHECK(dns_skip_name(p, sizeof pkt, &off) && off == 35, "skip stops after pointer -> 35, got %d", off);
    off = 39;
    CHECK(!dns_skip_name(p, sizeof pkt, &off), "truncated pointer rejected");

    char name[256]; size_t nl = 0;
    off = 29;
    CHECK(dns_decompress_name(p, sizeof pkt, &off, name, sizeof name, &nl), "decompress cdn");
    CHECK(off == 35, "off advanced past pointer only, got %d", off);
    CHECK(nl == 15 && strcmp(name, "cdn.example.com") == 0, "name normalized: '%s'", name);
    off = 35;
    CHECK(dns_decompress_name(p, sizeof pkt, &off, name, sizeof name, &nl) && off == 37 &&
          strcmp(name, "cdn.example.com") == 0, "double hop");
    off = 37;
    CHECK(!dns_decompress_name(p, sizeof pkt, &off, name, sizeof name, &nl), "forward pointer rejected");
    /* pointer loop: 0xC0 0x0C at 12 would point to itself -> rejected */
    p[12] = 0xC0; p[13] = 0x0C; off = 12;
    CHECK(!dns_decompress_name(p, sizeof pkt, &off, name, sizeof name, &nl), "self-pointer rejected");
    char tiny[4]; off = 29; p[12] = 3;
    CHECK(!dns_decompress_name(p, sizeof pkt, &off, tiny, sizeof tiny, &nl), "tiny output cap fails cleanly");
    free(p);
}

int main(void)
{
    test_soa_min_ttl();
    test_answer_min_ttl_and_rewrite();
    test_skip_and_decompress();
    if (g_fail) { printf("%d FAILURE(S)\n", g_fail); return 1; }
    printf("all dns_wire tests passed\n");
    return 0;
}
