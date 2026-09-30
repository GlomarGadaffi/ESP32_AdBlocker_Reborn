/*
 * DNS wire-format helpers — see dns_wire.h. No ESP-IDF includes, by design:
 * this file is compiled on the host by tests/fuzz/.
 */
#include "dns_wire.h"
#include "domain.h"
#include <string.h>

bool dns_skip_name(const uint8_t *pkt, int len, int *off)
{
    while (*off < len) {
        uint8_t b = pkt[*off];
        if (b == 0)          { (*off)++;        return true; }
        /* (#113) A compression pointer is 2 bytes; at len-1 only its first
         * byte exists. Advancing by 2 anyway pushed *off one past len — the
         * caller's own `off > len` guards catch that on the next name, but a
         * bare call site (dns_resp_min_ttl) doesn't, so refuse here. */
        if ((b & 0xC0) == 0xC0) {
            if (*off + 1 >= len) return false;
            (*off) += 2; return true;
        }
        if ((b & 0xC0) != 0) return false;     /* reserved label length */
        *off += 1 + b;
    }
    return false;
}

uint32_t dns_resp_min_ttl(const uint8_t *pkt, int len, uint32_t deflt,
                          uint32_t ttl_min, uint32_t ttl_max)
{
    if (len < 12) return deflt;
    int ancount = (pkt[6] << 8) | pkt[7];
    int nscount = (pkt[8] << 8) | pkt[9];

    /* Skip question section */
    int off = 12;
    if (!dns_skip_name(pkt, len, &off)) return deflt;
    if (off + 4 > len) return deflt;
    off += 4;  /* qtype + qclass */

    uint32_t minttl = 0xFFFFFFFFu;

    if (ancount > 0) {
        /* NOERROR: collect min TTL across answer RRs */
        for (int i = 0; i < ancount; i++) {
            if (!dns_skip_name(pkt, len, &off)) break;
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
            if (!dns_skip_name(pkt, len, &off)) break;
            if (off + 10 > len) break;
            uint16_t rtype = ((uint16_t)pkt[off+0] << 8) | pkt[off+1];
            uint32_t rttl  = ((uint32_t)pkt[off+4] << 24) | ((uint32_t)pkt[off+5] << 16)
                           | ((uint32_t)pkt[off+6] << 8)  |  (uint32_t)pkt[off+7];
            uint16_t rdlen = ((uint16_t)pkt[off+8] << 8) | pkt[off+9];
            off += 10;
            if (rtype == 6 && rdlen >= 20) {  /* SOA: skip MNAME+RNAME then read minimum */
                int roff = off;
                /* rdlen is an untrusted 16-bit field: `roff + 20 <= off +
                 * rdlen` alone lets an SOA whose declared rdlen runs past the
                 * end of the packet read 20 bytes beyond len (found by
                 * tests/fuzz/fuzz_dns_wire within seconds of its first run;
                 * regression seed corpus/dns_wire/regress_soa_rdlen_oob). */
                if (dns_skip_name(pkt, len, &roff) && dns_skip_name(pkt, len, &roff) &&
                    roff + 20 <= off + rdlen && roff + 20 <= len) {
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
    if (minttl < ttl_min) minttl = ttl_min;
    if (minttl > ttl_max) minttl = ttl_max;
    return minttl;
}

void dns_rewrite_answer_ttls(uint8_t *pkt, int len, uint32_t ttl_s)
{
    if (len < 12) return;
    int rrs = ((pkt[6] << 8) | pkt[7]) + ((pkt[8] << 8) | pkt[9]) +
              ((pkt[10] << 8) | pkt[11]);
    int off = 12;
    if (!dns_skip_name(pkt, len, &off)) return;
    off += 4;                                   /* qtype + qclass */
    for (int i = 0; i < rrs; i++) {
        if (off > len || !dns_skip_name(pkt, len, &off)) return;
        if (off + 10 > len) return;
        pkt[off + 4] = (uint8_t)(ttl_s >> 24);
        pkt[off + 5] = (uint8_t)(ttl_s >> 16);
        pkt[off + 6] = (uint8_t)(ttl_s >> 8);
        pkt[off + 7] = (uint8_t)(ttl_s);
        uint16_t rdlen = ((uint16_t)pkt[off + 8] << 8) | pkt[off + 9];
        off += 10 + rdlen;
    }
}

bool dns_decompress_name(const uint8_t *pkt, int len, int *off,
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
