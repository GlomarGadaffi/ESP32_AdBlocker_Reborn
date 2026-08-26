#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

/* SNTP time sync so query-log entries carry real wall-clock timestamps.
 * Servers: NIST (time.nist.gov) + the NTP pool as fallback. Timezone is UTC.
 *
 * Two distinct notions of "the time" live here, and keeping them apart is the
 * whole point of #75:
 *
 *   FLOOR   a lower bound on the real date, from NVS or the build stamp. Good
 *           enough to date-check an X.509 certificate; not good enough to
 *           timestamp anything a human will read. Sets the SYSTEM clock, so
 *           time(NULL)/mbedtls_time() see it — and nothing else does.
 *   SYNCED  the real time, from an NTP server. Only this sets s_synced, so
 *           only this makes timesync_epoch() non-zero, and only this dates a
 *           query-log entry or the web UI clock line.
 */

/* Seed the system clock with max(last-known-good NVS epoch, build epoch).
 * Call ONCE, after nvs_flash_init() and before ANY TLS client can run —
 * app_main's first act after NVS. Never moves the clock backwards, never
 * claims a sync. */
void timesync_floor_init(void);

/* Start SNTP. Call once after the network (DHCP) is up. */
void timesync_start(void);

/* Persist the current epoch as the next boot's floor. Self-rate-limiting
 * (~10 min, plus once promptly after each sync) and a no-op until synced.
 * WRITES FLASH — call from a housekeeping task, never from a network
 * callback or a timer callback. */
void timesync_persist_tick(void);

/* Block until the clock is genuinely NTP-synced, up to timeout_ms.
 * Returns true if synced. Used to keep the first HTTPS fetch of a cold boot
 * off the floor and on real time. */
bool timesync_wait_synced(uint32_t timeout_ms);

/* True once the clock has been set from an NTP server at least once.
 * A floor does NOT make this true. */
bool timesync_is_synced(void);

/* Current wall-clock UNIX epoch seconds, or 0 if not yet synced.
 * Deliberately 0 while running on a floor: callers here are loggers, and a
 * floor timestamp is a plausible-looking lie. */
uint32_t timesync_epoch(void);

/* How the clock got a usable value AT BOOT, latched by timesync_floor_init()
 * and never rewritten:
 *   "nvs"   floored from the last-known-good epoch this box persisted
 *   "build" floored from the firmware build stamp (virgin NVS)
 *   "rtc"   nothing to do - the RTC carried real time through the reset
 *   "unset" no floor was available AND the clock was cold: TLS is checking
 *           certificate dates against 1970 and every handshake will fail
 * Latched rather than derived so a cold boot's decision is still readable
 * minutes later, instead of having to be caught in a 1-3s window. */
const char *timesync_source(void);

/* Current clock state: "synced" (NTP) | "floored" | "unset". */
const char *timesync_state(void);

#ifdef __cplusplus
}
#endif
