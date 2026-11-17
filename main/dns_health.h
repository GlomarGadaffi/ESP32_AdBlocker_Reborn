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
 *   - Reboots are allowed only after at least one OK probe THIS boot. A probe
 *     that has never once succeeded since boot is more likely a broken probe
 *     (or an address the board cannot reach itself on) than a dead resolver;
 *     the check then stays at WARN and reports it once (DNS_HEALTH_NOTE_NEVER_OK).
 *   - Reboot-loop guard: the caller keeps a count of consecutive health
 *     reboots in RTC memory (dns_health_set_prior_reboots). Once it reaches
 *     DNS_HEALTH_MAX_CONSEC_REBOOTS no further reboot is issued this boot
 *     (action capped at WARN, DNS_HEALTH_NOTE_LOOP_GUARD reported once). The
 *     count is cleared by DNS_HEALTH_HEALTHY_OKS consecutive OK probes
 *     (dns_health_take_clear tells the caller to zero its stored copy).
 *     SKIPPED neither extends nor breaks that run; a failure breaks it.
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

/* Reboot-loop guard. */
#define DNS_HEALTH_MAX_CONSEC_REBOOTS 3u
#define DNS_HEALTH_HEALTHY_OKS        10u

typedef enum {
    DNS_HEALTH_NOTE_NONE = 0,
    DNS_HEALTH_NOTE_LOOP_GUARD,   /* a reboot was due but the consecutive-reboot cap is reached */
    DNS_HEALTH_NOTE_NEVER_OK      /* a reboot was due but no probe has ever succeeded this boot */
} dns_health_note_t;

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
    uint32_t prior_reboots;    /* consecutive health reboots before this boot (validated by the caller) */
    uint32_t ok_run;           /* consecutive OK probes (saturating) */
    bool     ever_ok;          /* an OK probe has been seen this boot */
    bool     clear_pending;    /* healthy period reached; caller should zero its stored count */
    bool     note_loop_given;
    bool     note_never_given;
    dns_health_note_t note;    /* one-shot notice for the caller to log */
} dns_health_t;

/* cfg may be NULL, which selects the DNS_HEALTH_* defaults above. */
void dns_health_init(dns_health_t *h, const dns_health_cfg_t *cfg);

/* Count of consecutive health reboots that preceded this boot. Call once after
 * init. A value >= DNS_HEALTH_MAX_CONSEC_REBOOTS suppresses reboots. */
void dns_health_set_prior_reboots(dns_health_t *h, uint32_t n);

/* One-shot notice: returns each kind at most once per boot, then NONE. */
dns_health_note_t dns_health_take_note(dns_health_t *h);

/* True once after DNS_HEALTH_HEALTHY_OKS consecutive OKs: the caller must
 * zero its stored reboot count. */
bool dns_health_take_clear(dns_health_t *h);

/* RTC-memory encoding of the consecutive-reboot count. The stored pair is
 * (count, count ^ MAGIC); anything else (power-on garbage, an image that never
 * wrote it) decodes as zero. next() saturates at UINT32_MAX, never wraps. */
#define DNS_HEALTH_REBOOT_MAGIC 0x44485243u   /* "DHRC" */
uint32_t dns_health_reboots_decode(uint32_t count, uint32_t check);
uint32_t dns_health_reboots_check(uint32_t count);
uint32_t dns_health_reboots_next(uint32_t count);

dns_health_action_t dns_health_step(dns_health_t *h, dns_health_result_t r, uint32_t now_ms);

#ifdef __cplusplus
}
#endif
