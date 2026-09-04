#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Local DNS rewrite table — maps domain names to IPv4 addresses (#12).
 * Stored in NVS; checked before upstream forwarding.
 * Matches exact name and all subdomains (*.domain). Single-label names
 * ("printer", "glolab") are fine: this doubles as the static hosts table. */
#define REWRITE_MAX 48

bool     rewrite_init(void);

/* Add or update a rewrite rule. ipv4_hbo = host-byte-order IPv4.
 * Set ipv4_hbo = 0 to delete the entry for that domain. */
bool     rewrite_set(const char *domain, uint32_t ipv4_hbo);

/* Return matching IPv4 (host byte order) or 0 if no rule matches. */
uint32_t rewrite_lookup(const char *domain);

/* Non-blocking probe for the L2 Ethernet fast path (#102). The fast path only
 * needs to know whether a rewrite EXISTS — if one does it hands the query to
 * the socket path, so the single build_rewrite_a() there produces the answer.
 * Returns  1 = a rule matches (*out_ip set), 0 = definitely no rule,
 *         -1 = cannot tell (lock busy) — the caller must defer to lwIP. */
int      rewrite_lookup_nb(const char *domain, size_t dlen, uint32_t *out_ip);

/* Populate arrays for display; *count_inout: capacity in, filled count out. */
void     rewrite_list(char out_domains[][64], uint32_t out_ips[], uint32_t *count_inout);
uint32_t rewrite_count(void);

#ifdef __cplusplus
}
#endif
