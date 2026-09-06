#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/* Per-client bypass list (#74 Part 2) — a standing, admin-configured list of
 * client IPs whose queries always resolve unfiltered. Up to 8 entries,
 * NVS-backed: a deliberate choice (unlike #48's scoped pause, which is
 * intentionally NOT persisted — a reboot always comes back blocking).
 *
 * Applied at DELIVERY time, exactly like the scoped pause, and for the same
 * reason: it is NOT checked inside blocklist_is_blocked(), whose answer the
 * shared forward cache stores keyed only by domain. A bypassed client's
 * ALLOW must never leak into that cache, or every other client would get it
 * too until the TTL expired. See pause.h for the fuller version of this
 * argument — bypass and pause are applied at the identical point in
 * dns_server.cpp and dns_sink.cpp for the identical reason. */
#define BYPASS_MAX 8

bool     bypass_init(void);
bool     bypass_add(const char *ip_str);
bool     bypass_remove(const char *ip_str);
bool     bypass_clear(void);
uint32_t bypass_count(void);
void     bypass_list(char out[][20], uint32_t *count_inout);

/* True if this client's queries should resolve unfiltered. */
bool     bypass_active_for(uint32_t client_ip_hbo);

/* Non-blocking variant for the L2 Ethernet fast path (mirrors acl_permits_nb).
 * A busy lock returns false (not proven bypassed) — same accepted, bounded
 * tradeoff pause_active_for's own torn-read case already makes: a bypass-list
 * edit landing in the exact same instant as an L2 lookup can, in that one
 * rare window, have that one query evaluated as if not bypassed. The caller
 * must OR this into the same defer condition pause_active_for already gates
 * in l2_input_cb — never answer BLOCK on unproven state. */
bool     bypass_active_for_nb(uint32_t client_ip_hbo);

#ifdef __cplusplus
}
#endif
