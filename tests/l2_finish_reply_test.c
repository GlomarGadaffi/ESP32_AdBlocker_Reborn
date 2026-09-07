/*
 * Byte-equivalence test for #109's l2_finish_reply() consolidation
 * (main/dns_sink.cpp) against the two duplicated code paths it replaced.
 *
 * Build + run:
 *   gcc -O2 -o l2_finish_reply_test tests/l2_finish_reply_test.c && ./l2_finish_reply_test
 *
 * l2_finish_reply() itself has zero ESP-IDF dependencies (pure byte
 * manipulation on a caller-owned buffer), so it's copied verbatim below
 * rather than pulled from dns_sink.cpp, which drags in the whole IDF tree.
 * If the real function in dns_sink.cpp ever changes, re-sync this copy by
 * eye (it's ~15 lines) — this test only proves the NEW shared function
 * reproduces the OLD two-copy behavior byte-for-byte across a range of
 * inputs; it can't detect drift between this file and the real one.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

static int g_fail = 0;
#define CHECK(cond, ...) do { if (!(cond)) { \
    printf("  FAIL: "); printf(__VA_ARGS__); printf("\n"); g_fail++; } } while (0)

/* ── verbatim copy of the new shared helper (dns_sink.cpp) ──────────── */
static void l2_finish_reply(uint8_t *tx, int ihl, int udp, int payload_len)
{
    uint8_t t6[6];
    memcpy(t6, tx, 6); memcpy(tx, tx + 6, 6); memcpy(tx + 6, t6, 6);              /* swap MAC */
    uint8_t t4[4];
    memcpy(t4, tx+14+12, 4); memcpy(tx+14+12, tx+14+16, 4); memcpy(tx+14+16, t4, 4); /* swap IP */
    uint8_t t2[2];
    memcpy(t2, tx+udp, 2); memcpy(tx+udp, tx+udp+2, 2); memcpy(tx+udp+2, t2, 2);     /* swap ports */
    int iptot = ihl + 8 + payload_len;
    tx[14+2] = (iptot >> 8); tx[14+3] = (iptot & 0xFF);
    int udplen = 8 + payload_len;
    tx[udp+4] = (udplen >> 8); tx[udp+5] = (udplen & 0xFF);
    tx[udp+6] = 0; tx[udp+7] = 0;
    tx[14+10] = 0; tx[14+11] = 0;
    uint32_t sum = 0;
    for (int i = 0; i < ihl; i += 2) sum += (tx[14+i] << 8) | tx[14+i+1];
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    uint16_t csum = ~sum;
    tx[14+10] = (csum >> 8); tx[14+11] = (csum & 0xFF);
}

/* ── verbatim copy of the OLD cached-reply path, pre-#109 ────────────
 * (the txid patch is included here since it used to sit inline between the
 * swaps and the length/checksum work — it touches tx[dns]/tx[dns+1], which
 * l2_finish_reply's byte ranges never reach, so its position relative to
 * the shared tail is irrelevant; included for completeness of the
 * comparison, not because it could conflict.) */
static void old_cached_finish(uint8_t *tx, int ihl, int udp, int dns,
                               const uint8_t *buf, int clen)
{
    uint8_t s6[6]; memcpy(s6,tx,6); memcpy(tx,tx+6,6); memcpy(tx+6,s6,6);
    uint8_t s4[4]; memcpy(s4,tx+14+12,4); memcpy(tx+14+12,tx+14+16,4); memcpy(tx+14+16,s4,4);
    uint8_t s2[2]; memcpy(s2,tx+udp,2); memcpy(tx+udp,tx+udp+2,2); memcpy(tx+udp+2,s2,2);
    tx[dns] = buf[dns]; tx[dns+1] = buf[dns+1];
    int iptot_c = ihl + 8 + clen;
    tx[14+2]=(iptot_c>>8); tx[14+3]=(iptot_c&0xFF);
    int udplen_c = 8 + clen;
    tx[udp+4]=(udplen_c>>8); tx[udp+5]=(udplen_c&0xFF);
    tx[udp+6]=0; tx[udp+7]=0;
    tx[14+10]=0; tx[14+11]=0;
    uint32_t csum=0;
    for (int i=0;i<ihl;i+=2) csum += (tx[14+i]<<8)|tx[14+i+1];
    while (csum>>16) csum=(csum&0xFFFF)+(csum>>16);
    uint16_t cks=~csum; tx[14+10]=(cks>>8); tx[14+11]=(cks&0xFF);
}

/* ── verbatim copy of the OLD blocked-reply path's tail, pre-#109 ─── */
static void old_blocked_finish(uint8_t *tx, int ihl, int udp, int dns_resp)
{
    uint8_t t6[6];
    memcpy(t6, tx, 6); memcpy(tx, tx + 6, 6); memcpy(tx + 6, t6, 6);
    uint8_t t4[4];
    memcpy(t4, tx+14+12, 4); memcpy(tx+14+12, tx+14+16, 4); memcpy(tx+14+16, t4, 4);
    uint8_t t2[2];
    memcpy(t2, tx+udp, 2); memcpy(tx+udp, tx+udp+2, 2); memcpy(tx+udp+2, t2, 2);
    int iptot_b = ihl + 8 + dns_resp;
    tx[14+2]=(iptot_b>>8); tx[14+3]=(iptot_b&0xFF);
    int udplen_b = 8 + dns_resp;
    tx[udp+4]=(udplen_b>>8); tx[udp+5]=(udplen_b&0xFF);
    tx[udp+6]=0; tx[udp+7]=0;
    tx[14+10]=0; tx[14+11]=0;
    uint32_t sum=0;
    for (int i=0;i<ihl;i+=2) sum += (tx[14+i]<<8)|tx[14+i+1];
    while (sum>>16) sum=(sum&0xFFFF)+(sum>>16);
    uint16_t csum=~sum;
    tx[14+10]=(csum>>8); tx[14+11]=(csum&0xFF);
}

static uint64_t rng_state = 0xC0FFEE1234ULL;
static uint64_t rng(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}
static void fill_random(uint8_t *buf, int n)
{
    for (int i = 0; i < n; i++) buf[i] = (uint8_t)(rng() & 0xFF);
}

#define BUFSZ 600

static void test_cached_path(void)
{
    printf("cached-reply path vs l2_finish_reply\n");
    int ihls[]   = {20, 24, 28};
    int payloads[] = {1, 2, 12, 63, 200, 511};
    for (size_t hi = 0; hi < sizeof(ihls)/sizeof(ihls[0]); hi++) {
        int ihl = ihls[hi];
        int udp = 14 + ihl;
        int dns = udp + 8;   /* matches the real call sites exactly: DNS header
                               * starts 8 bytes past the UDP header — a FIXED
                               * offset unrelated to udp (as this test had
                               * before) can coincidentally collide with udp
                               * at specific ihl values and corrupt the test,
                               * not the code under test. */
        for (size_t pi = 0; pi < sizeof(payloads)/sizeof(payloads[0]); pi++) {
            int clen = payloads[pi];
            uint8_t buf[BUFSZ], tx_old[BUFSZ], tx_new[BUFSZ];
            fill_random(buf, BUFSZ);
            memcpy(tx_old, buf, BUFSZ);
            memcpy(tx_new, buf, BUFSZ);

            old_cached_finish(tx_old, ihl, udp, dns, buf, clen);

            tx_new[dns] = buf[dns]; tx_new[dns+1] = buf[dns+1];
            l2_finish_reply(tx_new, ihl, udp, clen);

            int diff = memcmp(tx_old, tx_new, BUFSZ);
            CHECK(diff == 0, "ihl=%d clen=%d: output differs (memcmp=%d)", ihl, clen, diff);
        }
    }
}

static void test_blocked_path(void)
{
    printf("blocked-reply path vs l2_finish_reply\n");
    int ihls[]   = {20, 24, 28};
    int dns_resps[] = {1, 2, 12, 63, 200, 511};
    for (size_t hi = 0; hi < sizeof(ihls)/sizeof(ihls[0]); hi++) {
        int ihl = ihls[hi];
        int udp = 14 + ihl;
        for (size_t pi = 0; pi < sizeof(dns_resps)/sizeof(dns_resps[0]); pi++) {
            int dns_resp = dns_resps[pi];
            uint8_t buf[BUFSZ], tx_old[BUFSZ], tx_new[BUFSZ];
            fill_random(buf, BUFSZ);
            memcpy(tx_old, buf, BUFSZ);
            memcpy(tx_new, buf, BUFSZ);

            old_blocked_finish(tx_old, ihl, udp, dns_resp);
            l2_finish_reply(tx_new, ihl, udp, dns_resp);

            int diff = memcmp(tx_old, tx_new, BUFSZ);
            CHECK(diff == 0, "ihl=%d dns_resp=%d: output differs (memcmp=%d)", ihl, dns_resp, diff);
        }
    }
}

int main(void)
{
    test_cached_path();
    test_blocked_path();
    if (g_fail) {
        printf("\n%d CHECK(s) FAILED\n", g_fail);
        return 1;
    }
    printf("\nAll checks passed.\n");
    return 0;
}
