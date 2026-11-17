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
    h->prior_reboots   = 0;
    h->ok_run          = 0;
    h->ever_ok         = false;
    h->clear_pending   = false;
    h->note_loop_given = false;
    h->note_never_given = false;
    h->note            = DNS_HEALTH_NOTE_NONE;
}

void dns_health_set_prior_reboots(dns_health_t *h, uint32_t n)
{
    if (h == NULL) return;
    h->prior_reboots = n;
}

dns_health_note_t dns_health_take_note(dns_health_t *h)
{
    if (h == NULL) return DNS_HEALTH_NOTE_NONE;
    dns_health_note_t n = h->note;
    h->note = DNS_HEALTH_NOTE_NONE;
    return n;
}

bool dns_health_take_clear(dns_health_t *h)
{
    if (h == NULL) return false;
    bool c = h->clear_pending;
    h->clear_pending = false;
    return c;
}

uint32_t dns_health_reboots_check(uint32_t count)
{
    return count ^ DNS_HEALTH_REBOOT_MAGIC;
}

uint32_t dns_health_reboots_decode(uint32_t count, uint32_t check)
{
    return (check == dns_health_reboots_check(count)) ? count : 0;
}

uint32_t dns_health_reboots_next(uint32_t count)
{
    return (count < UINT32_MAX) ? count + 1 : UINT32_MAX;
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
        h->streak  = 0;
        h->ever_ok = true;
        if (h->ok_run < UINT32_MAX) h->ok_run++;
        if (h->ok_run >= DNS_HEALTH_HEALTHY_OKS) {
            if (h->prior_reboots != 0) h->clear_pending = true;
            h->prior_reboots = 0;
        }
        return DNS_HEALTH_ACT_NONE;
    }

    h->ok_run = 0;

    /* A failure (TIMEOUT or BAD_REPLY). Unsigned subtraction keeps every
     * comparison correct across the 2^32 ms wrap. */
    if ((uint32_t)(now_ms - h->first_step_ms) < h->cfg.grace_ms)
        return DNS_HEALTH_ACT_WARN;

    if (h->streak == 0) h->streak_start_ms = now_ms;
    if (h->streak < UINT32_MAX) h->streak++;

    if (h->streak >= h->cfg.fail_threshold &&
        (uint32_t)(now_ms - h->streak_start_ms) >= h->cfg.min_span_ms) {
        if (!h->ever_ok) {
            if (!h->note_never_given) {
                h->note_never_given = true;
                h->note = DNS_HEALTH_NOTE_NEVER_OK;
            }
            return DNS_HEALTH_ACT_WARN;
        }
        if (h->prior_reboots >= DNS_HEALTH_MAX_CONSEC_REBOOTS) {
            if (!h->note_loop_given) {
                h->note_loop_given = true;
                h->note = DNS_HEALTH_NOTE_LOOP_GUARD;
            }
            return DNS_HEALTH_ACT_WARN;
        }
        h->reboot = true;
        return DNS_HEALTH_ACT_REBOOT;
    }
    return DNS_HEALTH_ACT_WARN;
}
