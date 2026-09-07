#include "domain.h"
#include <string.h>
#include <ctype.h>

/* IRAM_ATTR (#78): called unconditionally from dns_extract_qname() (this
 * file, below — l2_qname was its pre-#109 name when it lived in dns_sink.cpp)
 * on every packet the L2 fast path parses — confirmed by nm that without
 * this tag it stayed in flash even after that caller moved to IRAM,
 * defeating the "never touch flash from the L2 hook" invariant #78 is about.
 * Not in the issue's original function list, but required to actually
 * deliver it. */
size_t IRAM_ATTR domain_normalize(char *buf, size_t buf_size, const char *src, size_t src_len)
{
    if (!src || !buf || buf_size < 2) return 0;

    /* strip trailing dot */
    while (src_len > 0 && src[src_len - 1] == '.') src_len--;
    if (src_len == 0 || src_len >= buf_size) return 0;

    for (size_t i = 0; i < src_len; i++)
        buf[i] = (char)tolower((unsigned char)src[i]);
    buf[src_len] = '\0';
    return src_len;
}

/* IRAM_ATTR (#109): shared by dns_sink.cpp's L2 hook (IRAM-mandatory) and
 * dns_server.cpp's socket path (flash-resident is fine there, but tagging
 * costs nothing extra and keeps this one definition, not two). */
int IRAM_ATTR dns_extract_qname(const uint8_t *pkt, int pkt_len, int offset,
                                char *name_out, size_t name_cap, size_t *name_len_out)
{
    char raw[256];
    size_t raw_len = 0;
    while (offset < pkt_len && pkt[offset] != 0) {
        uint8_t label_len = pkt[offset];
        /* (#42) A question QNAME never uses compression (0xC0) or a reserved
         * label type (0x40-0xBF) per RFC 1035 — either way the top two bits
         * being set is disqualifying, so one check covers both cases. */
        if (label_len & 0xC0) return -1;
        if (offset + 1 + label_len > pkt_len || raw_len + label_len + 1 >= sizeof(raw))
            return -1;
        if (raw_len > 0) raw[raw_len++] = '.';
        memcpy(raw + raw_len, pkt + offset + 1, label_len);
        raw_len += label_len;
        offset  += 1 + label_len;
    }
    if (offset >= pkt_len) return -1;
    offset++;                              /* skip the null label */
    if (offset + 4 > pkt_len) return -1;   /* QTYPE + QCLASS must both fit */

    size_t nlen = domain_normalize(name_out, name_cap, raw, raw_len);
    if (nlen == 0) return -1;
    *name_len_out = nlen;
    return offset + 4;
}

/* Any single-label name (no dot) is treated as a bare TLD and never blocked. */
bool domain_is_bare_tld(const char *name, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (name[i] == '.') return false;
    }
    return true;
}

static bool tok_char_ok(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
}

/* True if the token reads as an address, not a domain: IPv4 (digits and
 * dots only) or IPv6 (contains ':'). "0emm.com" has letters, so a bare
 * digit-leading domain is NOT mistaken for a hosts-format prefix. */
static bool tok_is_address(const char *p, size_t len)
{
    bool ipv4 = len > 0;
    for (size_t i = 0; i < len; i++) {
        if (p[i] == ':') return true;
        if (!((p[i] >= '0' && p[i] <= '9') || p[i] == '.')) ipv4 = false;
    }
    return ipv4;
}

size_t domain_extract_token(const char *line, size_t len, const char **tok_out)
{
    if (!line || !tok_out) return 0;
    const char *p = line, *end = line + len;

    /* Whole-line rejects: rules that don't mean "block this domain". */
    for (const char *q = p; q < end; q++) {
        if (*q == '/' || *q == '$') return 0;
        if (*q == '#' && q + 1 < end && q[1] == '#') return 0;
    }
    while (p < end && (*p == ' ' || *p == '\t')) p++;
    if (end - p >= 2 && p[0] == '@' && p[1] == '@') return 0;  /* exception rule */

    bool anchored = false;
    if (end - p >= 2 && p[0] == '|' && p[1] == '|') { p += 2; anchored = true; }

    /* Hosts format: a leading address token means the domain is the NEXT
     * token; an address with nothing after it is not a domain at all. */
    if (!anchored) {
        const char *t = p;
        while (t < end && *t != ' ' && *t != '\t') t++;
        if (tok_is_address(p, (size_t)(t - p))) {
            if (t == end) return 0;
            p = t;
            while (p < end && (*p == ' ' || *p == '\t')) p++;
        }
    }
    if (end - p >= 2 && p[0] == '*' && p[1] == '.') p += 2;

    const char *start = p;
    while (p < end && *p != ' ' && *p != '\t' && *p != '#' &&
           !(anchored && *p == '^')) {
        if (!tok_char_ok(*p)) return 0;
        p++;
    }
    if (p == start) return 0;
    *tok_out = start;
    return (size_t)(p - start);
}
