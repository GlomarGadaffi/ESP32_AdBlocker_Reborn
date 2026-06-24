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

/* Hash a normalized domain. Caller must normalize first. */
static inline uint32_t domain_hash(const char *name, size_t len)
{
    return murmur3_32(name, len, DOMAIN_HASH_SEED);
}

#ifdef __cplusplus
}
#endif
