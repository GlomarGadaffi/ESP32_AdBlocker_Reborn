#include "domain.h"
#include <string.h>
#include <strings.h>
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

/* Any single-label name (no dot) is treated as a bare TLD and never blocked.
 * IRAM_ATTR (#117): reached from the L2 fast path via bl_rank_resolve's
 * per-suffix probe walk — closes the gap CONTRIBUTING.md §4 used to name
 * explicitly as untagged. */
bool IRAM_ATTR domain_is_bare_tld(const char *name, size_t len)
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

/* ---- #117: AdGuard rule-grammar subset --------------------------------- */

static bool is_all_digits(const char *p, size_t n)
{
    if (n == 0) return false;
    for (size_t i = 0; i < n; i++) if (!isdigit((unsigned char)p[i])) return false;
    return true;
}

/* Strip a trailing ":<1-5 digits>" port suffix, but only when it can't be
 * confused with IPv6 colons: the token is bracketed ("[addr]:port") or it
 * has exactly the one colon that can only be a port separator. */
static size_t strip_port(const char *tok, size_t toklen)
{
    if (toklen == 0) return toklen;
    size_t colon = toklen, colons = 0;
    for (size_t i = 0; i < toklen; i++) if (tok[i] == ':') { colon = i; colons++; }
    if (colon == toklen) return toklen;
    size_t plen = toklen - colon - 1;
    if (plen == 0 || plen > 5 || !is_all_digits(tok + colon + 1, plen)) return toklen;
    bool bracketed = (colon > 0 && tok[colon - 1] == ']');
    return (bracketed || colons == 1) ? colon : toklen;
}

static void strip_brackets(const char **tok, size_t *toklen)
{
    if (*toklen >= 2 && (*tok)[0] == '[' && (*tok)[*toklen - 1] == ']') {
        *tok += 1; *toklen -= 2;
    }
}

/* is_too_wide_rule (DnsLibs rule_utils.cpp:480-484): a pattern shorter than
 * 3 chars, or made only of '.' and '*', is too generic to mean anything. */
static bool too_wide(const char *tok, size_t len)
{
    if (len < 3) return true;
    for (size_t i = 0; i < len; i++)
        if (tok[i] != '.' && tok[i] != '*') return false;
    return true;
}

/* Comma-separated modifier list after the LAST '$' in the line. The only
 * modifier this subset honours is "important", exactly once — anything
 * else (dnstype=, dnsrewrite=, denyallow=, badfilter, ctag=, client=,
 * unknown text, an empty segment, or a duplicate) rejects the whole line.
 * A hosts-format line calls this only when it already knows to reject
 * (AdGuard hosts syntax carries no modifiers at all), never to accept. */
static bool parse_modifiers(const char *m, size_t mlen, bool *important_out)
{
    *important_out = false;
    if (mlen == 0) return false;
    bool seen = false;
    const char *p = m, *end = m + mlen;
    for (;;) {
        const char *comma = memchr(p, ',', (size_t)(end - p));
        const char *segend = comma ? comma : end;
        size_t seglen = (size_t)(segend - p);
        if (seglen != 9 || memcmp(p, "important", 9) != 0) return false;
        if (seen) return false;   /* duplicate modifier */
        seen = true;
        if (!comma) break;
        p = comma + 1;
    }
    *important_out = seen;
    return seen;
}

static void reject(rule_t *out, size_t *cursor, size_t line_len, uint8_t reason)
{
    out->tok = NULL;
    out->len = 0;
    out->kind = RULE_REJECT;
    out->flags = 0;
    out->reject_reason = reason;
    *cursor = line_len;
}

/* Finish validating a plain domain token — shared by the anchored/bare
 * path and each hosts-format trailing token. Applies the wildcard-prefix
 * collapse, port/bracket stripping, trailing-dot strip, then the
 * too-wide / address / character-set gates. On success fills tok/len only
 * (caller sets kind and flags); on failure calls reject() and returns
 * false. */
static bool finish_token(const char *tstart, size_t toklen, rule_t *out,
                          size_t *cursor, size_t line_len)
{
    if (toklen >= 2 && tstart[0] == '*' && tstart[1] == '.') { tstart += 2; toklen -= 2; }
    /* Any '*' surviving the collapsible prefix above is a genuine wildcard
     * pattern ("ex*.com"), not the "*.domain" shorthand — reject it with
     * its own reason rather than letting the char-set loop below catch it
     * as generic MALFORMED. */
    for (size_t i = 0; i < toklen; i++)
        if (tstart[i] == '*') { reject(out, cursor, line_len, RULE_REJECT_WILDCARD); return false; }
    toklen = strip_port(tstart, toklen);
    strip_brackets(&tstart, &toklen);
    while (toklen > 0 && tstart[toklen - 1] == '.') toklen--;

    if (toklen == 0) { reject(out, cursor, line_len, RULE_REJECT_MALFORMED); return false; }
    if (tok_is_address(tstart, toklen)) { reject(out, cursor, line_len, RULE_REJECT_CIDR); return false; }
    if (too_wide(tstart, toklen)) { reject(out, cursor, line_len, RULE_REJECT_TOO_WIDE); return false; }
    for (size_t i = 0; i < toklen; i++)
        if (!tok_char_ok(tstart[i])) { reject(out, cursor, line_len, RULE_REJECT_MALFORMED); return false; }
    if (toklen > 253) { reject(out, cursor, line_len, RULE_REJECT_MALFORMED); return false; }

    out->tok = tstart;
    out->len = (uint8_t)toklen;
    out->reject_reason = 0;
    return true;
}

/* Walk one whitespace-delimited trailing token starting at *cursor, for
 * hosts-format lines ("0.0.0.0 a.com b.com"). Always RULE_BLOCK, never
 * exact, never important — hosts syntax has no way to express either. */
static bool hosts_token_next(const char *line, size_t len, size_t *cursor, rule_t *out)
{
    const char *p = line + *cursor, *end = line + len;
    while (p < end && (*p == ' ' || *p == '\t')) p++;
    if (p >= end) { *cursor = len; return false; }
    const char *t = p;
    while (t < end && *t != ' ' && *t != '\t') t++;
    size_t resume = (size_t)(t - line);   /* next trailing token, if any */

    out->kind = RULE_BLOCK;
    out->flags = 0;
    /* finish_token() calls reject() on failure, which sets *cursor = len —
     * override back to resume so a bad token doesn't cut off the rest of
     * the hosts line's trailing tokens; either way one rule slot (BLOCK or
     * REJECT) has been produced for this token. */
    finish_token(p, (size_t)(t - p), out, cursor, len);
    *cursor = resume;
    return true;
}

bool rule_parse_next(const char *line, size_t len, size_t *cursor, rule_t *out)
{
    if (!line || !cursor || !out || len == 0) return false;

    if (*cursor != 0) {
        if (*cursor >= len) return false;
        return hosts_token_next(line, len, cursor, out);
    }

    /* Comment lines never emit a rule. */
    if (line[0] == '!') { *cursor = len; return false; }
    if (line[0] == '#' && (len < 2 || line[1] != '#')) { *cursor = len; return false; }

    /* Cosmetic marker, anywhere on the line ("example.com##.ad", or a bare
     * "##selector" with no domain prefix). */
    for (size_t i = 0; i + 1 < len; i++) {
        if (line[i] == '#' && line[i + 1] == '#') {
            reject(out, cursor, len, RULE_REJECT_COSMETIC);
            return true;
        }
    }

    const char *p = line, *end = line + len;
    while (p < end && (*p == ' ' || *p == '\t')) p++;

    uint8_t kind = RULE_BLOCK;
    if (end - p >= 2 && p[0] == '@' && p[1] == '@') { kind = RULE_ALLOW; p += 2; }

    bool anchored = false, exact;
    if (end - p >= 2 && p[0] == '|' && p[1] == '|')      { p += 2; anchored = true;  exact = false; }
    else if (end - p >= 1 && p[0] == '|')                { p += 1; anchored = true;  exact = true;  }
    else                                                  { exact = (kind == RULE_ALLOW); }

    /* Hosts format only applies to a bare BLOCK line (no exception marker,
     * no anchor) whose first token is an address, with something after it. */
    if (kind == RULE_BLOCK && !anchored) {
        const char *t = p;
        while (t < end && *t != ' ' && *t != '\t') t++;
        if (tok_is_address(p, (size_t)(t - p)) && t < end) {
            for (const char *q = t; q < end; q++) {
                if (*q == '$') { reject(out, cursor, len, RULE_REJECT_MODIFIER); return true; }
            }
            *cursor = (size_t)(t - line);
            return hosts_token_next(line, len, cursor, out);
        }
    }

    /* Not hosts format: split modifiers at the LAST '$' in [p, end). */
    const char *dollar = NULL;
    for (const char *q = end; q > p; ) { --q; if (*q == '$') { dollar = q; break; } }
    const char *tokend = dollar ? dollar : end;

    bool important = false;
    if (dollar && !parse_modifiers(dollar + 1, (size_t)(end - dollar - 1), &important)) {
        reject(out, cursor, len, RULE_REJECT_MODIFIER);
        return true;
    }

    /* '^' terminator only recognized when anchored (|.../||...). */
    const char *tend = tokend;
    if (anchored) {
        for (const char *q = p; q < tend; q++) if (*q == '^') { tend = q; break; }
    }
    while (tend > p && (tend[-1] == ' ' || tend[-1] == '\t')) tend--;

    const char *tstart = p;
    size_t toklen = (size_t)(tend - tstart);

    /* A pattern both starting and ending with '/' is a regex, not a domain
     * with a stray slash — check before any scheme/slash stripping below,
     * which would otherwise mangle it into a mid-token-slash MALFORMED. */
    if (toklen >= 2 && tstart[0] == '/' && tstart[toklen - 1] == '/') {
        reject(out, cursor, len, RULE_REJECT_REGEX);
        return true;
    }

    /* Strip a scheme prefix, then a lone trailing '/'; anything else with a
     * '/' left in it isn't a plain domain pattern. */
    static const char *const schemes[] = { "https://", "http://", "://", "//" };
    for (size_t i = 0; i < sizeof(schemes) / sizeof(schemes[0]); i++) {
        size_t sl = strlen(schemes[i]);
        if (toklen >= sl && strncasecmp(tstart, schemes[i], sl) == 0) {
            tstart += sl; toklen -= sl;
            break;
        }
    }
    if (toklen > 0 && tstart[toklen - 1] == '/') toklen--;
    for (size_t i = 0; i < toklen; i++) {
        if (tstart[i] == '/') { reject(out, cursor, len, RULE_REJECT_MALFORMED); return true; }
    }

    out->kind = kind;
    out->flags = (uint8_t)((exact ? RULE_EXACT : 0) | (important ? RULE_IMPORTANT : 0));
    if (!finish_token(tstart, toklen, out, cursor, len)) return true;
    *cursor = len;
    return true;
}

void rule_apply_feed_policy(rule_t *r)
{
    if (r->kind == RULE_BLOCK && (r->flags & RULE_IMPORTANT)) {
        r->kind = RULE_REJECT;
        r->flags = 0;
        r->reject_reason = RULE_REJECT_IMPORTANT_BLOCK_UNSUPPORTED;
        return;
    }
    /* The feed block-table entry has no spare bit for RULE_EXACT either
     * (same reason as $important above): widen a feed "|domain^" to
     * sub-inclusive rather than drop it. Over-blocking is the safe
     * direction here — the same call already made for a bare feed domain
     * (domain_extract_token's "documented divergence"), just extended to
     * the explicit exact-anchor form. */
    if (r->kind == RULE_BLOCK) r->flags &= (uint8_t)~RULE_EXACT;
}
