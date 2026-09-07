#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Passive L2 census (#73 foundation) — a MAC-keyed table of LAN clients seen
 * via ARP, DHCP, or a DNS query, built from sightings staged by dns_sink.cpp's
 * l2_census_frame()/l2_input_cb() producer and drained here by dns_task.
 * PSRAM-resident (read from httpd, written from dns_task — neither is the
 * IRAM_ATTR eth-RX hot path, so a plain mutex is enough; no seqlock needed). */
#define CENSUS_MAX 64

/* Must match dns_sink.cpp's internal CensusKind values exactly — the two
 * sides cross an extern "C" int boundary, not a shared enum type. */
#define CENSUS_SEEN_ARP   0
#define CENSUS_SEEN_DHCP  1
#define CENSUS_SEEN_QUERY 2

/* A sighting is not proof of anything on its own — this grace period exists
 * so a device that joined the LAN 5 seconds ago isn't immediately reported as
 * "suspected bypass" just because its first DNS query hasn't landed yet. */
#define CENSUS_GRACE_S 120

typedef struct {
    uint8_t  mac[6];
    uint32_t ip;             /* last-known, host byte order; 0 if never seen with one */
    char     hostname[32];   /* last DHCP option-12 value seen; empty if none */
    uint32_t first_seen_s;   /* uptime seconds */
    uint32_t last_seen_s;
    uint32_t arp_count;
    uint32_t dhcp_count;
    uint32_t query_count;
} CensusClient;

bool census_init(void);

/* Record one sighting (called from dns_task, draining dns_sink's ring). */
void census_observe(const uint8_t mac[6], uint32_t ip, int kind,
                    const char *hostname, size_t hostname_len);

/* Copy up to cap entries (unordered). Returns the number written. */
uint32_t census_snapshot(CensusClient *out, uint32_t cap);

#ifdef __cplusplus
}
#endif
