#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/*
 * Crash flight recorder (#71) — "last words" diagnostics for an abnormal
 * reboot, without needing PSRAM or a flash partition.
 *
 * The breadcrumb lives in RTC_NOINIT_ATTR memory (crashlog.c), which survives
 * a software reset, a panic reboot, and a task/interrupt-watchdog reset — the
 * exact cases worth diagnosing — but is cleared on power-on and brownout,
 * which need no query history (esp_reset_reason() already says "power
 * cycled"). There is no panic hook: ESP-IDF's esp_panic_handler() has no
 * general user-code extension point (verified against esp-idf's own
 * panic.c — the only hook is CONFIG_ESP_COREDUMP_ENABLE's esp_core_dump_write,
 * which this project does not enable). Instead, the struct is simply always
 * current — updated on the DNS hot path during normal execution — so it
 * happens to already hold the right data whenever a reset of interest occurs.
 */

/* Call once at boot, as early as possible (before anything else could
 * plausibly want to reason about "did we just crash"). Snapshots whatever
 * the RTC struct currently holds (the previous boot's final state) into a
 * regular-RAM copy for crashlog_last_words() to read later, classifies
 * esp_reset_reason(), and leaves the live RTC struct running so recording
 * can continue immediately without a gap. */
void crashlog_init(void);

/* Record one query (called from dns_task; cheap — a few RTC-memory writes,
 * no flash I/O, no allocation). */
void crashlog_record(const char *domain, uint16_t qtype, bool blocked);

/* Render the previous boot's last-words snapshot as JSON, matching the
 * dns_server_metrics_json()/handle_metrics style: flat snprintf, no library.
 * Returns the number of bytes written (0 if there's nothing to show — e.g.
 * this is the first boot ever, or the last reset was power-on/brownout). */
int crashlog_json(char *out, size_t cap);

#ifdef __cplusplus
}
#endif
