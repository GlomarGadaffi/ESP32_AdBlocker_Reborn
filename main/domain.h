#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include "murmur3.h"   /* also brings in the IRAM_ATTR portability shim */

#define DOMAIN_HASH_SEED  0xDEADF00Du
#define TLD_MAX_LEN       24  /* longest bare TLD we track */

/*
 * Normalize a DNS name in place: lowercase, strip trailing '.'.
 * Returns the normalized length (excluding NUL), or 0 on error.
 */
size_t domain_normalize(char *buf, size_t buf_size, const char *src, size_t src_len);

/*
 * Parse an RFC 1035 §4.1.2 question QNAME starting at pkt[offset] (no
 * compression allowed — a question section never uses it), normalize it into
 * name_out, and return the offset just past QTYPE+QCLASS, or -1 on any
 * malformed input. (#109) The single parser for both the socket path
 * (dns_server.cpp, flash-resident) and the L2 fast path (dns_sink.cpp,
 * IRAM_ATTR) — they used to be two independent copies whose bounds checks
 * had already drifted (functionally equivalent, but only by accident; #42/L5
 * needed a human to notice and mirror a fix by hand).
 * IRAM_ATTR tag lives on the definition in domain.c only — repeating it here
 * mints a second, conflicting section name for the same symbol and fails the
 * build under -Werror=attributes (see dns_cache_l2_get's declaration in
 * dns_server.h for the same rule, learned there first).
 */
int dns_extract_qname(const uint8_t *pkt, int pkt_len, int offset,
                      char *name_out, size_t name_cap, size_t *name_len_out);

/*
 * Return true if name is a bare TLD (single label with no dots) that we
 * should not block even if it appears in the blocklist.
 */
bool domain_is_bare_tld(const char *name, size_t len);

/*
 * Extract the blockable domain token from one raw blocklist line.
 * Accepts bare domains, hosts format ("0.0.0.0 dom" / "::1 dom"), and
 * adblock anchors ("||dom^"); "*.dom" collapses to "dom" (suffix-walk
 * already covers subdomains — this over-blocks only the apex).
 * Lines that cannot mean "block this whole domain" — exceptions (@@),
 * path rules (/), option rules ($), cosmetic rules (##) — and tokens
 * with characters outside [A-Za-z0-9._-] yield 0.
 * On success *tok_out points into line; the token is NOT normalized.
 */
size_t domain_extract_token(const char *line, size_t len, const char **tok_out);

/* Hash a normalized domain. Caller must normalize first. */
static inline IRAM_ATTR uint32_t domain_hash(const char *name, size_t len)
{
    return murmur3_32(name, len, DOMAIN_HASH_SEED);
}

/* ---- #117: AdGuard rule-grammar subset ----------------------------------
 * Parse-time only (feed load, custom-rule set): never reached from the L2
 * hook, so none of this is IRAM_ATTR. */

typedef enum { RULE_BLOCK, RULE_ALLOW, RULE_REJECT } rule_kind_t;

enum {
    RULE_EXACT     = 1u << 0,  /* participates only at suffix depth 0 */
    RULE_IMPORTANT = 1u << 1,  /* $important */
};

enum {
    RULE_REJECT_REGEX = 1,
    RULE_REJECT_WILDCARD,
    RULE_REJECT_MODIFIER,
    RULE_REJECT_COSMETIC,
    RULE_REJECT_CIDR,
    RULE_REJECT_TOO_WIDE,
    RULE_REJECT_MALFORMED,
    RULE_REJECT_IMPORTANT_BLOCK_UNSUPPORTED,
};

typedef struct {
    const char *tok;            /* domain text, NOT NUL-terminated, points into line */
    uint8_t     len;
    uint8_t     kind;            /* rule_kind_t */
    uint8_t     flags;           /* RULE_EXACT | RULE_IMPORTANT */
    uint8_t     reject_reason;   /* set only when kind == RULE_REJECT */
} rule_t;

/*
 * Iterate the rule(s) on one already-isolated line (no '\n', trailing '\r'
 * and spaces already trimmed by the caller — same contract as
 * domain_extract_token). *cursor must be 0 on the first call for a line;
 * each call that returns true fills *out and advances *cursor so the next
 * call continues where this one left off. Returns false when there is
 * nothing left to parse: either the line was a blank/comment line (zero
 * rules ever emitted — the parser owns comments now, silently), or every
 * rule on the line has already been emitted. A REJECT is exactly one true
 * result (whole-line, first call only), then false. Hosts-format lines
 * ("0.0.0.0 a.com b.com") yield one BLOCK rule per trailing token, which is
 * the only case a single line produces more than one rule.
 * Source-agnostic: $important is accepted and flagged here regardless of
 * whether the caller is a feed or the custom-rules text — whether a FEED
 * block rule is allowed to carry it is caller policy, see
 * rule_apply_feed_policy() below.
 * Allocation-free, single pass over the line (hosts-format tokens are
 * re-scanned from *cursor on each call rather than held in state).
 */
bool rule_parse_next(const char *line, size_t len, size_t *cursor, rule_t *out);

/*
 * FEED-only policy layered on top of the source-agnostic parse above: the
 * feed block-table entry is a bare 3-byte remainder with no spare bit for
 * either flag (see #117). $important: accepting it and silently dropping
 * the flag would make a FEED block rule lose a precedence fight it was
 * explicitly written to win, so this downgrades that case (BLOCK with
 * RULE_IMPORTANT set) to REJECT/IMPORTANT_BLOCK_UNSUPPORTED in place.
 * RULE_EXACT: same problem, opposite direction — there is nowhere to
 * store "exact-only" either, so a feed "|domain^" is widened to
 * sub-inclusive instead (over-blocking is the safe direction, same call
 * already made for a bare feed domain). Every ALLOW rule is untouched —
 * exception/custom rules have somewhere to store both flags, so this
 * must never be called on them. */
void rule_apply_feed_policy(rule_t *r);

#ifdef __cplusplus
}
#endif
