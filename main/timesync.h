#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

/* SNTP time sync so query-log entries carry real wall-clock timestamps.
 * Servers: NIST (time.nist.gov) + the NTP pool as fallback. The clock starts
 * unset (epoch 0); once the first sync lands, timesync_epoch() returns real
 * UNIX time and the query log records dated entries. Timezone is UTC. */

/* Start SNTP. Call once after the network (DHCP) is up. */
void timesync_start(void);

/* True once the clock has been set from an NTP server at least once. */
bool timesync_is_synced(void);

/* Current wall-clock UNIX epoch seconds, or 0 if not yet synced. */
uint32_t timesync_epoch(void);

#ifdef __cplusplus
}
#endif
