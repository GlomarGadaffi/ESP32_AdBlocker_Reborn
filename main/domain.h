#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdbool.h>
#include "murmur3.h"

#define DOMAIN_HASH_SEED  0xDEADF00Du
#define TLD_MAX_LEN       24  /* longest bare TLD we track */

/*
 * Normalize a DNS name in place: lowercase, strip trailing '.'.
 * Returns the normalized length (excluding NUL), or 0 on error.
 */
size_t domain_normalize(char *buf, size_t buf_size, const char *src, size_t src_len);

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
static inline uint32_t domain_hash(const char *name, size_t len)
{
    return murmur3_32(name, len, DOMAIN_HASH_SEED);
}

#ifdef __cplusplus
}
#endif
