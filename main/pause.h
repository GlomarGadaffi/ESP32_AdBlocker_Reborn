#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/* Timed, scoped "pause blocking" (#48 part 2).
 *
 * A small fixed table of { client IP, expiry } entries. An entry for a
 * specific IP suspends blocking for that one client; the wildcard entry
 * (PAUSE_IP_ALL) suspends it for everyone. Entries expire on their own —
 * the check is made per query against the expiry, so nothing has to fire a
 * timer to resume — and NOTHING here is persisted: a reboot always comes
 * back blocking (fail-safe), unlike the separate manual on/off switch in
 * blocklist.c (blocklist_set_paused), which is NVS-backed by design.
 *
 * Where the check goes matters more than what it does. It is NOT inside
 * blocklist_is_blocked(): that function's answer is what the forward cache
 * stores, and a cache keyed only by domain cannot hold a per-client, per-time
 * verdict — a paused client's ALLOW would be served to every client until
 * the TTL ran out. So the blocklist verdict stays global and cacheable, and
 * the pause is applied at DELIVERY time on each path (dns_server.cpp's UDP
 * and TCP handlers, and the L2 hook in dns_sink.cpp, which defers a paused
 * client's frame to the socket path). A query forwarded because of a pause
 * is marked no_cache so its upstream answer is delivered and forgotten.
 *
 * Readers (the dns_task hot path and the Ethernet L2 RX hook) never take a
 * lock: each slot is a pair of atomics written in an order that lets a reader
 * detect a torn update and treat it as "not paused" — fail closed, i.e. keep
 * blocking — rather than answer on a half-written entry. Writers (the httpd
 * task) serialise on a mutex. */

#define PAUSE_MAX          8
#define PAUSE_MAX_MINUTES  1440u   /* 24 h hard cap — enforced here, not only in the form */
#define PAUSE_IP_ALL       0u      /* wildcard: every client */

typedef struct {
    uint32_t ip;            /* host order; PAUSE_IP_ALL = every client */
    uint32_t remaining_s;   /* seconds until this entry auto-resumes */
} pause_view_t;

bool     pause_init(void);

/* Pause blocking for ip_hbo (PAUSE_IP_ALL = everyone) for `minutes`.
 * Replaces an existing entry for the same IP. False when minutes is 0 or
 * above PAUSE_MAX_MINUTES, or when the table is full of unexpired entries. */
bool     pause_set(uint32_t ip_hbo, uint32_t minutes);

/* Resume now for one entry. False if there was no active entry for that IP. */
bool     pause_clear(uint32_t ip_hbo);

/* Resume everything. Returns the number of entries that were active. */
uint32_t pause_clear_all(void);

/* Snapshot the active (unexpired) entries for display. Returns the count. */
uint32_t pause_list(pause_view_t *out, uint32_t max);
uint32_t pause_count(void);

/* True when an unexpired entry matches this client (its own IP, or the
 * wildcard). Lock-free, IRAM-resident: called on every query from the
 * dns_task and from the L2 RX hook. A concurrent update reads as "not
 * paused" for that one query. */
bool     pause_active_for(uint32_t client_ip_hbo);

#ifdef __cplusplus
}
#endif
