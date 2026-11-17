#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Recurring "do not block between these local times" windows. Pure C with no
 * IDF includes so it runs under the host test harness.
 *
 * A window is a weekday set plus a start and end in minutes since local
 * midnight. The end is exclusive. A window whose end is before its start
 * wraps past midnight and belongs to the weekday it STARTS on: Fri 22:00-02:00
 * is active on Saturday 01:00 only when Friday's bit is set. start == end is
 * an empty window and is never active. */

#define PAUSE_SCHED_MAX_WINDOWS  4
#define PAUSE_SCHED_DAY_SUN      0x01u    /* bit0 = Sunday ... bit6 = Saturday */
#define PAUSE_SCHED_DAYS_ALL     0x7Fu
#define PAUSE_SCHED_DAYS_WEEKDAY 0x3Eu    /* Mon-Fri */
#define PAUSE_SCHED_DAYS_WEEKEND 0x41u    /* Sat + Sun */
#define PAUSE_SCHED_SPEC_MAX     48       /* buffer size that always fits a formatted window */
#define PAUSE_SCHED_PARSE_MAX    64       /* longer input is rejected outright */
#define PAUSE_SCHED_UTC_MIN_MIN  (-720)   /* UTC offset limits, minutes */
#define PAUSE_SCHED_UTC_MAX_MIN  840
#define PAUSE_SCHED_BLOB_LEN     27       /* 1 version + 2 offset + 4 * 6 */
#define PAUSE_SCHED_BLOB_VERSION 1

typedef struct {
    bool     enabled;
    uint8_t  days;         /* bitmask, bit0 = Sunday */
    uint16_t start_min;    /* 0-1439 */
    uint16_t end_min;      /* 0-1439, exclusive */
} pause_sched_window_t;

typedef struct {
    pause_sched_window_t win[PAUSE_SCHED_MAX_WINDOWS];
    int16_t              utc_offset_min;   /* local = UTC + offset */
} pause_sched_t;

/* True when any enabled window covers (weekday 0=Sunday..6, minute 0-1439).
 * Out-of-range arguments are never active. NULL is never active. */
bool pause_sched_active(const pause_sched_t *s, int weekday, int minute_of_day);

/* Split a UTC epoch plus an offset in minutes into local weekday and minute of
 * day. Returns 0, or non-zero when an argument is NULL or the offset is out of
 * range. */
int pause_sched_localtime(uint32_t epoch_s, int utc_offset_min, int *weekday, int *minute_of_day);

/* Parse "mon,tue 22:00-06:30", "daily 09:00-17:00", "weekdays ...",
 * "weekends ...". Returns 0 and fills *out (enabled = true) on success;
 * non-zero and *out untouched on any malformed input. */
int pause_sched_parse(const char *text, pause_sched_window_t *out);

/* Write the canonical spec for w into buf. Returns 0, or non-zero when w is
 * invalid or the buffer is too small (buf is then left as an empty string
 * when cap > 0). */
int pause_sched_format(const pause_sched_window_t *w, char *buf, size_t cap);

/* Fixed-size NVS blob. serialise writes exactly PAUSE_SCHED_BLOB_LEN bytes
 * (cap must be at least that) and returns 0. deserialise rejects a wrong
 * length, wrong version, or any out-of-range field, leaving *out untouched. */
int pause_sched_serialise(const pause_sched_t *s, uint8_t *buf, size_t cap);
int pause_sched_deserialise(const uint8_t *buf, size_t len, pause_sched_t *out);

#ifdef __cplusplus
}
#endif
