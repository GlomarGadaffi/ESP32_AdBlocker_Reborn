/*
 * Host tests for the DNS health state machine (main/dns_health.c).
 *
 * Build + run:
 *   gcc -O2 -Wall -Wextra -fsanitize=address,undefined -I main -o dns_health_test \
 *       tests/dns_health_test.c main/dns_health.c && ./dns_health_test
 */
#include "dns_health.h"
#include <stdio.h>
#include <stdint.h>

static int g_fail = 0, g_run = 0;

#define CHECK(cond) do { g_run++; if (!(cond)) { g_fail++; \
    printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); } } while (0)

#define STEP 10000u
#define F    DNS_HEALTH_TIMEOUT

static dns_health_t H;

static void fresh(void) { dns_health_init(&H, NULL); }

/* Past the startup grace window, with one good probe seen at t0. */
static uint32_t settle(uint32_t t0)
{
    CHECK(dns_health_step(&H, DNS_HEALTH_OK, t0) == DNS_HEALTH_ACT_NONE);
    return t0 + DNS_HEALTH_GRACE_MS + STEP;
}

static void test_five_failures_then_ok_never_reboots(void)
{
    fresh();
    uint32_t t = settle(0);
    for (int i = 0; i < 5; i++, t += STEP)
        CHECK(dns_health_step(&H, F, t) != DNS_HEALTH_ACT_REBOOT);
    CHECK(dns_health_step(&H, DNS_HEALTH_OK, t) == DNS_HEALTH_ACT_NONE);
    t += STEP;
    /* The streak was cleared: five more failures still do not reboot. */
    for (int i = 0; i < 5; i++, t += STEP)
        CHECK(dns_health_step(&H, F, t) != DNS_HEALTH_ACT_REBOOT);
}

static void test_six_failures_over_50s_not_yet_seventh_at_60s(void)
{
    fresh();
    uint32_t t0 = settle(0);
    for (int i = 0; i < 6; i++)
        CHECK(dns_health_step(&H, F, t0 + (uint32_t)i * STEP) == DNS_HEALTH_ACT_WARN);
    /* Six failures spanning 50 s: threshold met, span not. */
    CHECK(H.streak == 6);
    CHECK(dns_health_step(&H, F, t0 + 6 * STEP) == DNS_HEALTH_ACT_REBOOT);
}

static void test_span_not_count_gates_reboot(void)
{
    /* Many failures packed into under 60 s must not reboot. */
    fresh();
    uint32_t t0 = settle(0);
    for (int i = 0; i < 20; i++)
        CHECK(dns_health_step(&H, F, t0 + (uint32_t)i * 1000u) != DNS_HEALTH_ACT_REBOOT);
    CHECK(dns_health_step(&H, F, t0 + 60000u) == DNS_HEALTH_ACT_REBOOT);
}

static void test_first_120s_never_reboots(void)
{
    fresh();
    CHECK(dns_health_step(&H, DNS_HEALTH_OK, 0) == DNS_HEALTH_ACT_NONE);
    /* Failures right after the first step: WARN only, however many. */
    for (uint32_t t = STEP; t < DNS_HEALTH_GRACE_MS; t += STEP) {
        dns_health_action_t a = dns_health_step(&H, F, t);
        CHECK(a == DNS_HEALTH_ACT_NONE || a == DNS_HEALTH_ACT_WARN);
    }
    /* Grace failures are not banked: the streak starts after the window. */
    CHECK(H.streak == 0);
    uint32_t t = DNS_HEALTH_GRACE_MS;
    for (int i = 0; i < 6; i++, t += STEP)
        CHECK(dns_health_step(&H, F, t) == DNS_HEALTH_ACT_WARN);
    CHECK(dns_health_step(&H, F, t) == DNS_HEALTH_ACT_REBOOT);
}

static void test_skipped_neither_counts_nor_resets(void)
{
    fresh();
    uint32_t t = settle(0);
    for (int i = 0; i < 3; i++, t += STEP)
        CHECK(dns_health_step(&H, F, t) == DNS_HEALTH_ACT_WARN);
    for (int i = 0; i < 40; i++, t += STEP)   /* a long OTA or reload in the middle */
        CHECK(dns_health_step(&H, DNS_HEALTH_SKIPPED, t) == DNS_HEALTH_ACT_NONE);
    CHECK(H.streak == 3);
    /* Failures 4 and 5 and 6 still just warn; the span since failure 1 is
     * already far past 60 s, so failure 6 is the first to reboot. */
    CHECK(dns_health_step(&H, F, t) == DNS_HEALTH_ACT_WARN); t += STEP;
    CHECK(dns_health_step(&H, F, t) == DNS_HEALTH_ACT_WARN); t += STEP;
    CHECK(dns_health_step(&H, F, t) == DNS_HEALTH_ACT_REBOOT);
}

static void test_skipped_alone_never_reboots(void)
{
    fresh();
    uint32_t t = 0;
    for (int i = 0; i < 100; i++, t += STEP)
        CHECK(dns_health_step(&H, DNS_HEALTH_SKIPPED, t) == DNS_HEALTH_ACT_NONE);
}

static void test_bad_reply_counts_like_timeout(void)
{
    fresh();
    uint32_t t0 = settle(0);
    for (int i = 0; i < 6; i++)
        CHECK(dns_health_step(&H, (i & 1) ? DNS_HEALTH_BAD_REPLY : DNS_HEALTH_TIMEOUT,
                              t0 + (uint32_t)i * STEP) == DNS_HEALTH_ACT_WARN);
    CHECK(dns_health_step(&H, DNS_HEALTH_BAD_REPLY, t0 + 6 * STEP) == DNS_HEALTH_ACT_REBOOT);
}

static void test_wrap_mid_streak(void)
{
    fresh();
    /* First step 200 s before the counter wraps, so grace is long over. */
    uint32_t t0 = 0xFFFFFFFFu - 200000u;
    CHECK(dns_health_step(&H, DNS_HEALTH_OK, t0) == DNS_HEALTH_ACT_NONE);
    /* Six failures starting 25 s before the wrap (the 4th lands after it,
     * span 50 s), then the 7th at span 60 s reboots. */
    uint32_t t = 0xFFFFFFFFu - 25000u;
    for (int i = 0; i < 6; i++, t += STEP)
        CHECK(dns_health_step(&H, F, t) == DNS_HEALTH_ACT_WARN);
    CHECK(t < 100000u);   /* we really did wrap */
    CHECK(dns_health_step(&H, F, t) == DNS_HEALTH_ACT_REBOOT);
}

static void test_wrap_then_grace_not_reentered(void)
{
    /* The counter wrapping must not look like a fresh boot: after the wrap
     * now_ms is tiny, and a naive "now_ms < 120000" grace test would suppress
     * a due reboot. */
    fresh();
    uint32_t t0 = 0xFFFFFFFFu - 400000u;
    CHECK(dns_health_step(&H, DNS_HEALTH_OK, t0) == DNS_HEALTH_ACT_NONE);
    uint32_t t = 0xFFFFFFFFu - 5000u;
    for (int i = 0; i < 6; i++, t += STEP)
        CHECK(dns_health_step(&H, F, t) == DNS_HEALTH_ACT_WARN);
    CHECK(dns_health_step(&H, F, t) == DNS_HEALTH_ACT_REBOOT);
}

static void test_reboot_is_sticky(void)
{
    fresh();
    uint32_t t0 = settle(0);
    dns_health_action_t a = DNS_HEALTH_ACT_NONE;
    for (int i = 0; i <= 6; i++) a = dns_health_step(&H, F, t0 + (uint32_t)i * STEP);
    CHECK(a == DNS_HEALTH_ACT_REBOOT);
    uint32_t t = t0 + 7 * STEP;
    CHECK(dns_health_step(&H, DNS_HEALTH_OK, t) == DNS_HEALTH_ACT_REBOOT);
    CHECK(dns_health_step(&H, DNS_HEALTH_SKIPPED, t + STEP) == DNS_HEALTH_ACT_REBOOT);
    CHECK(dns_health_step(&H, F, t + 2 * STEP) == DNS_HEALTH_ACT_REBOOT);
}

static void test_custom_cfg_and_null_safety(void)
{
    dns_health_cfg_t c = { .fail_threshold = 2, .min_span_ms = 5000, .grace_ms = 0 };
    dns_health_init(&H, &c);
    CHECK(dns_health_step(&H, DNS_HEALTH_OK, 0) == DNS_HEALTH_ACT_NONE);
    CHECK(dns_health_step(&H, F, 100) == DNS_HEALTH_ACT_WARN);
    CHECK(dns_health_step(&H, F, 5100) == DNS_HEALTH_ACT_REBOOT);
    CHECK(dns_health_step(NULL, F, 0) == DNS_HEALTH_ACT_NONE);
    dns_health_init(NULL, NULL);
}

/* Drive a full failing streak after a first OK; returns the last action. */
static dns_health_action_t fail_streak(uint32_t t0)
{
    dns_health_action_t a = DNS_HEALTH_ACT_NONE;
    for (int i = 0; i <= 6; i++) a = dns_health_step(&H, F, t0 + (uint32_t)i * STEP);
    return a;
}

static void test_never_ok_never_reboots(void)
{
    fresh();
    uint32_t t = DNS_HEALTH_GRACE_MS + STEP;
    dns_health_action_t a = DNS_HEALTH_ACT_NONE;
    for (int i = 0; i < 50; i++, t += STEP) {
        a = dns_health_step(&H, F, t);
        CHECK(a != DNS_HEALTH_ACT_REBOOT);
    }
    CHECK(a == DNS_HEALTH_ACT_WARN);
    CHECK(dns_health_take_note(&H) == DNS_HEALTH_NOTE_NEVER_OK);
    CHECK(dns_health_take_note(&H) == DNS_HEALTH_NOTE_NONE);   /* once */
    /* One OK arms it. */
    CHECK(dns_health_step(&H, DNS_HEALTH_OK, t) == DNS_HEALTH_ACT_NONE);
    t += STEP;
    CHECK(fail_streak(t) == DNS_HEALTH_ACT_REBOOT);
}

static void test_three_reboots_then_suppressed(void)
{
    for (uint32_t prior = 0; prior < 5; prior++) {
        fresh();
        dns_health_set_prior_reboots(&H, prior);
        uint32_t t0 = settle(0);
        dns_health_action_t a = fail_streak(t0);
        if (prior < DNS_HEALTH_MAX_CONSEC_REBOOTS) {
            CHECK(a == DNS_HEALTH_ACT_REBOOT);
        } else {
            CHECK(a == DNS_HEALTH_ACT_WARN);
            CHECK(dns_health_take_note(&H) == DNS_HEALTH_NOTE_LOOP_GUARD);
            CHECK(dns_health_take_note(&H) == DNS_HEALTH_NOTE_NONE);
            /* Keeps probing and counting, never reboots. */
            for (int i = 7; i < 40; i++)
                CHECK(dns_health_step(&H, F, t0 + (uint32_t)i * STEP) == DNS_HEALTH_ACT_WARN);
            CHECK(H.streak >= 30);
        }
    }
}

static void test_ten_oks_clear_counter(void)
{
    fresh();
    dns_health_set_prior_reboots(&H, 3);
    uint32_t t = settle(0);   /* 1 OK */
    for (int i = 0; i < 8; i++, t += STEP)   /* 9 OKs total */
        CHECK(dns_health_step(&H, DNS_HEALTH_OK, t) == DNS_HEALTH_ACT_NONE);
    CHECK(!dns_health_take_clear(&H));
    CHECK(H.prior_reboots == 3);
    CHECK(dns_health_step(&H, DNS_HEALTH_OK, t) == DNS_HEALTH_ACT_NONE);   /* 10th */
    t += STEP;
    CHECK(dns_health_take_clear(&H));
    CHECK(!dns_health_take_clear(&H));
    CHECK(H.prior_reboots == 0);
    CHECK(fail_streak(t) == DNS_HEALTH_ACT_REBOOT);
}

static void test_ok_run_broken_by_failure_not_by_skip(void)
{
    fresh();
    dns_health_set_prior_reboots(&H, 3);
    uint32_t t = DNS_HEALTH_GRACE_MS + STEP;
    for (int i = 0; i < 9; i++, t += STEP) dns_health_step(&H, DNS_HEALTH_OK, t);
    dns_health_step(&H, DNS_HEALTH_SKIPPED, t); t += STEP;
    CHECK(H.prior_reboots == 3);
    dns_health_step(&H, F, t); t += STEP;          /* breaks the run */
    for (int i = 0; i < 9; i++, t += STEP) dns_health_step(&H, DNS_HEALTH_OK, t);
    CHECK(H.prior_reboots == 3 && !dns_health_take_clear(&H));
    dns_health_step(&H, DNS_HEALTH_SKIPPED, t); t += STEP;
    dns_health_step(&H, DNS_HEALTH_OK, t);          /* 10th since the failure */
    CHECK(H.prior_reboots == 0 && dns_health_take_clear(&H));
}

static void test_rtc_encoding(void)
{
    CHECK(dns_health_reboots_decode(2, dns_health_reboots_check(2)) == 2);
    CHECK(dns_health_reboots_decode(0, dns_health_reboots_check(0)) == 0);
    /* Garbage (power-on RTC contents) reads as zero. */
    CHECK(dns_health_reboots_decode(3, 0) == 0);
    CHECK(dns_health_reboots_decode(0xDEADBEEFu, 0x12345678u) == 0);
    CHECK(dns_health_reboots_decode(0, 0) == 0);             /* all-zero RAM */
    CHECK(dns_health_reboots_decode(0xFFFFFFFFu, 0xFFFFFFFFu) == 0);
    /* Saturates, no wrap. */
    CHECK(dns_health_reboots_next(0) == 1);
    CHECK(dns_health_reboots_next(2) == 3);
    CHECK(dns_health_reboots_next(UINT32_MAX - 1) == UINT32_MAX);
    CHECK(dns_health_reboots_next(UINT32_MAX) == UINT32_MAX);
    /* A saturated count suppresses reboots. */
    fresh();
    dns_health_set_prior_reboots(&H, UINT32_MAX);
    uint32_t t0 = settle(0);
    CHECK(fail_streak(t0) == DNS_HEALTH_ACT_WARN);
}

int main(void)
{
    test_never_ok_never_reboots();
    test_three_reboots_then_suppressed();
    test_ten_oks_clear_counter();
    test_ok_run_broken_by_failure_not_by_skip();
    test_rtc_encoding();
    test_five_failures_then_ok_never_reboots();
    test_six_failures_over_50s_not_yet_seventh_at_60s();
    test_span_not_count_gates_reboot();
    test_first_120s_never_reboots();
    test_skipped_neither_counts_nor_resets();
    test_skipped_alone_never_reboots();
    test_bad_reply_counts_like_timeout();
    test_wrap_mid_streak();
    test_wrap_then_grace_not_reentered();
    test_reboot_is_sticky();
    test_custom_cfg_and_null_safety();
    printf("dns_health_test: %d checks, %d failed\n", g_run, g_fail);
    return g_fail ? 1 : 0;
}
