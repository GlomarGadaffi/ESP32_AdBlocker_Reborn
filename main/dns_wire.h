#pragma once
/*
 * DNS wire-format helpers with zero ESP-IDF dependencies.
 *
 * Moved out of dns_server.cpp so they can be compiled on the host and fuzzed
 * (tests/fuzz/) — the same reason #109 moved dns_extract_qname() into
 * domain.c. Every function here operates on a caller-owned byte buffer and
 * touches nothing else: no logging, no allocation, no globals. Keep it that
 * way; the fuzz harness links this file and domain.c directly with clang
 * -fsanitize=fuzzer, and anything with an IDF include would break that.
 *
 * Behaviour is byte-for-byte what dns_server.cpp had before the move; the
 * only signature change is dns_resp_min_ttl(), whose TTL clamp bounds were
 * file-local #defines in dns_server.cpp and are now parameters.
 */
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Skip a DNS name (label walk + compression pointer) at *off; advance *off past it.
 * Returns false if the packet is malformed. A compression pointer ends the
 * name: *off lands just past the 2-byte pointer, the target is not followed. */
bool dns_skip_name(const uint8_t *pkt, int len, int *off);

/* Parse the minimum TTL for caching:
 * - NOERROR with answers: min TTL across all answer RRs.
 * - NXDOMAIN (ancount=0): SOA minimum from authority section (RFC 2308 §5).
 * Returns deflt when nothing usable was found; otherwise the value clamped to
 * [ttl_min, ttl_max]. */
uint32_t dns_resp_min_ttl(const uint8_t *pkt, int len, uint32_t deflt,
                          uint32_t ttl_min, uint32_t ttl_max);

/* Rewrite every RR TTL in a response to ttl_s (RFC 8767: serve stale data
 * with a short TTL so clients re-ask soon). Walks an+ns+ar like
 * dns_resp_min_ttl; on any malformed step it stops, leaving later TTLs
 * untouched — harmless, the response was already served as-is before. */
void dns_rewrite_answer_ttls(uint8_t *pkt, int len, uint32_t ttl_s);

/* Decompress a name that may use RFC 1035 §4.1.4 message compression —
 * unlike dns_extract_qname (which REJECTS compression in the question
 * section by design), answer-section owner/RDATA names commonly use it. *off is
 * advanced exactly like dns_skip_name() would (stopping at the first
 * terminator or the first compression pointer at the ORIGINAL position,
 * +1 or +2 respectively) regardless of how many pointers are followed
 * internally to decode the actual name — a caller walking subsequent RRs
 * must not be dragged into wherever a jump landed.
 * Jump targets must point strictly backward (target < the offset of the
 * pointer that named it) and are capped at 20 hops — both guard against a
 * malformed or hostile pointer cycle.
 * The decoded name is passed through domain_normalize() into name_out. */
bool dns_decompress_name(const uint8_t *pkt, int len, int *off,
                         char *name_out, size_t name_cap, size_t *nlen_out);

#ifdef __cplusplus
}
#endif
