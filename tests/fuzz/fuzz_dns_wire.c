/*
 * libFuzzer target: DNS wire parsing in main/dns_wire.c + main/domain.c.
 *
 * Covers what the forwarder does to bytes an upstream resolver (or anyone
 * who can spoof one) sends back, plus what it does to a client query:
 *
 *   dns_extract_qname       question section of every client query and
 *                           every upstream reply (H2 anti-spoof check)
 *   dns_resp_min_ttl        upstream reply -> cache TTL (SOA walk)
 *   dns_rewrite_answer_ttls in-place TTL rewrite on a cached reply (stale)
 *   dns_decompress_name     CNAME-cloaking walk over answer RRs (#74)
 *   dns_qname_wire_len/_eq  forward-cache name key (collision guard)
 *
 * The packet is copied into an exact-size heap buffer so any read or write
 * one byte past `len` is an ASan report, not silently absorbed by the
 * 512/1500-byte buffers the firmware uses.
 */
#include "dns_wire.h"
#include "domain.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Same as dns_server.cpp's FWD_TTL_MIN_S / FWD_TTL_MAX_S. */
#define TTL_MIN 10u
#define TTL_MAX 3600u

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > 65535) return 0;              /* larger than any DNS message */
    int len = (int)size;
    uint8_t *pkt = (uint8_t *)malloc(size ? size : 1);
    if (!pkt) return 0;
    memcpy(pkt, data, size);

    /* 1. question parse, as the socket path does on every packet */
    char qname[256]; size_t qlen = 0;
    int qend = dns_extract_qname(pkt, len, 12, qname, sizeof(qname), &qlen);
    if (qend >= 0) {
        assert(qend <= len);
        assert(qlen > 0 && qlen < sizeof(qname));
        assert(qname[qlen] == '\0');
        /* a small output buffer must fail or truncate, never overflow */
        char small[16]; size_t sl = 0;
        (void)dns_extract_qname(pkt, len, 12, small, sizeof(small), &sl);
        /* the forward cache's name key must span exactly the parsed QNAME */
        int wl = dns_qname_wire_len(pkt, len, 12);
        assert(wl == qend - 12 - 4 && wl <= DNS_QNAME_WIRE_MAX);
        assert(dns_qname_wire_eq(pkt + 12, pkt + 12, wl));
    }
    /* ...and never read out of bounds on anything, parseable or not */
    for (int start = 0; start < len; start++) {
        int wl = dns_qname_wire_len(pkt, len, start);
        assert(wl < 0 || (wl >= 2 && start + wl <= len && wl <= DNS_QNAME_WIRE_MAX));
    }

    /* 2. TTL extraction as done on every upstream reply */
    uint32_t ttl = dns_resp_min_ttl(pkt, len, 30, TTL_MIN, TTL_MAX);
    assert(ttl == 30 || (ttl >= TTL_MIN && ttl <= TTL_MAX));

    /* 3. skip_name from every offset: must always leave *off within [0,len]
     *    on success and never read past the buffer */
    for (int start = 0; start < len; start++) {
        int off = start;
        if (dns_skip_name(pkt, len, &off)) assert(off > start && off <= len);
    }

    /* 4. CNAME-cloaking walk (mirrors cname_chain_is_blocked's loop shape) */
    if (qend >= 0 && len >= 12) {
        int ancount = (pkt[6] << 8) | pkt[7];
        int off = qend;
        for (int i = 0; i < ancount && i < 64; i++) {
            char name[256]; size_t nlen = 0;
            if (!dns_decompress_name(pkt, len, &off, name, sizeof(name), &nlen)) break;
            assert(off <= len);
            assert(nlen > 0 && nlen < sizeof(name) && name[nlen] == '\0');
            if (off + 10 > len) break;
            uint16_t rtype = ((uint16_t)pkt[off] << 8) | pkt[off + 1];
            uint16_t rdlen = ((uint16_t)pkt[off + 8] << 8) | pkt[off + 9];
            int rdata_off = off + 10;
            if (rtype == 5 && rdata_off + rdlen <= len) {
                char target[256]; size_t tlen = 0; int roff = rdata_off;
                if (dns_decompress_name(pkt, len, &roff, target, sizeof(target), &tlen))
                    assert(roff <= len && tlen > 0 && tlen < sizeof(target));
            }
            off = rdata_off + rdlen;
        }
        /* decompress from every offset too, with a deliberately tiny name cap */
        for (int start = 0; start < len; start++) {
            int off2 = start; char tiny[8]; size_t tl = 0;
            if (dns_decompress_name(pkt, len, &off2, tiny, sizeof(tiny), &tl))
                assert(off2 <= len && tl < sizeof(tiny));
        }
    }

    /* 5. in-place TTL rewrite on the same bytes (mutates pkt — do it last) */
    dns_rewrite_answer_ttls(pkt, len, 30);

    free(pkt);
    return 0;
}
