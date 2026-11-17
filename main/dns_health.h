#pragma once
/*
 * DNS self-health state machine. Pure C, no ESP-IDF includes, so it runs under
 * the host tests (tests/dns_health_test.c).
 *
 * The caller probes the board's own resolver every DNS_HEALTH_PROBE_INTERVAL_MS
 * and feeds each outcome to dns_health_step(), which answers one question: has
 * DNS been dead for long enough that a reboot is the right response? The
 * policy lives here and nowhere else:
 *
 *   - REBOOT only after cfg.fail_threshold consecutive failed probes whose
 *     first and latest are at least cfg.min_span_ms apart (6 failures over
 *     60 s by default; at a 10 s cadence that is the 7th probe).
 *   - Any OK clears the streak.
 *   - Nothing counts during the first cfg.grace_ms after the FIRST step call
 *     (blocklist load, DHCP, slow upstream). A failure inside that window
 *     returns WARN and is not added to the streak.
 *   - SKIPPED (no address yet, OTA running, blocklist reload running, or the
 *     probe could not even be sent) neither counts nor clears the streak.
 *   - Once REBOOT has been returned it is returned for every later call, so a
 *     caller that loses a race with its own restart cannot talk itself out of
 *     it.
 *
 * Time is a free-running uint32_t millisecond counter. Every comparison is an
 * unsigned subtraction, so the counter wrapping at 2^32 mid-streak is fine.
 * Spans longer than 2^31 ms (24 days) between two steps are not meaningful.
 */
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DNS_HEALTH_PROBE_INTERVAL_MS 10000u
#define DNS_HEALTH_FAIL_THRESHOLD    6u
#define DNS_HEALTH_MIN_SPAN_MS       60000u
#define DNS_HEALTH_GRACE_MS          120000u

typedef enum {
    DNS_HEALTH_OK = 0,
    DNS_HEALTH_TIMEOUT,      /* no reply within the probe window */
    DNS_HEALTH_BAD_REPLY,    /* a reply arrived but was malformed or had the wrong txid */
    DNS_HEALTH_SKIPPED       /* probe not attempted or not meaningful: neither counts nor resets */
} dns_health_result_t;

typedef enum {
    DNS_HEALTH_ACT_NONE = 0,
    DNS_HEALTH_ACT_WARN,
    DNS_HEALTH_ACT_REBOOT
} dns_health_action_t;

typedef struct {
    uint32_t fail_threshold;   /* consecutive failures required */
    uint32_t min_span_ms;      /* minimum time from first to latest failure of the streak */
    uint32_t grace_ms;         /* no counting before first_step + grace_ms */
} dns_health_cfg_t;

typedef struct {
    dns_health_cfg_t cfg;
    uint32_t first_step_ms;    /* time of the first step call */
    uint32_t streak_start_ms;  /* time of the first failure in the current streak */
    uint32_t streak;           /* consecutive counted failures */
    bool     started;          /* first_step_ms is valid */
    bool     reboot;           /* sticky */
} dns_health_t;

/* cfg may be NULL, which selects the DNS_HEALTH_* defaults above. */
void dns_health_init(dns_health_t *h, const dns_health_cfg_t *cfg);

dns_health_action_t dns_health_step(dns_health_t *h, dns_health_result_t r, uint32_t now_ms);

#ifdef __cplusplus
}
#endif
