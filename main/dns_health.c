/*
 * dns_health.c - the decision half of the DNS self-check. See dns_health.h for
 * the policy. No I/O, no clock, no allocation: the caller supplies the time.
 */
#include "dns_health.h"
#include <stddef.h>

static void clear_state(dns_health_t *h)
{
    h->first_step_ms   = 0;
    h->streak_start_ms = 0;
    h->streak          = 0;
    h->started         = false;
    h->reboot          = false;
}

void dns_health_init(dns_health_t *h, const dns_health_cfg_t *cfg)
{
    if (h == NULL) return;
    if (cfg != NULL) {
        h->cfg = *cfg;
    } else {
        h->cfg.fail_threshold = DNS_HEALTH_FAIL_THRESHOLD;
        h->cfg.min_span_ms    = DNS_HEALTH_MIN_SPAN_MS;
        h->cfg.grace_ms       = DNS_HEALTH_GRACE_MS;
    }
    clear_state(h);
}

dns_health_action_t dns_health_step(dns_health_t *h, dns_health_result_t r, uint32_t now_ms)
{
    if (h == NULL) return DNS_HEALTH_ACT_NONE;
    if (h->reboot) return DNS_HEALTH_ACT_REBOOT;

    if (!h->started) {
        h->started       = true;
        h->first_step_ms = now_ms;
    }

    if (r == DNS_HEALTH_SKIPPED) return DNS_HEALTH_ACT_NONE;

    if (r == DNS_HEALTH_OK) {
        h->streak = 0;
        return DNS_HEALTH_ACT_NONE;
    }

    /* A failure (TIMEOUT or BAD_REPLY). Unsigned subtraction keeps every
     * comparison correct across the 2^32 ms wrap. */
    if ((uint32_t)(now_ms - h->first_step_ms) < h->cfg.grace_ms)
        return DNS_HEALTH_ACT_WARN;

    if (h->streak == 0) h->streak_start_ms = now_ms;
    if (h->streak < UINT32_MAX) h->streak++;

    if (h->streak >= h->cfg.fail_threshold &&
        (uint32_t)(now_ms - h->streak_start_ms) >= h->cfg.min_span_ms) {
        h->reboot = true;
        return DNS_HEALTH_ACT_REBOOT;
    }
    return DNS_HEALTH_ACT_WARN;
}
