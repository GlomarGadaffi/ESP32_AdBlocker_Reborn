/*
 * Host tests for the upstream source-port rotation policy (main/upstream_port.c).
 *
 * Build + run:
 *   gcc -O2 -Wall -Wextra -fsanitize=address,undefined -I main -o upstream_port_test \
 *       tests/upstream_port_test.c main/upstream_port.c && ./upstream_port_test
 *
 * Only the policy is tested here; the socket calls live in dns_server.cpp.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "upstream_port.h"

static int g_fail = 0;
#define CHECK(cond, ...) do { if (!(cond)) { \
    printf("  FAIL: "); printf(__VA_ARGS__); printf("\n"); g_fail++; } } while (0)

static void test_query_threshold(void)
{
    up_state_t st;
    up_init(&st, 1000);
    for (uint32_t i = 0; i < UP_ROTATE_QUERIES - 1; i++) up_note_forward(&st);
    CHECK(!up_rotate_due(&st, 1000), "due one query early");
    up_note_forward(&st);
    CHECK(up_rotate_due(&st, 1000), "not due at exactly %u queries", (unsigned)UP_ROTATE_QUERIES);
}

static void test_time_threshold_and_wrap(void)
{
    up_state_t st;
    up_init(&st, 5000);
    CHECK(!up_rotate_due(&st, 5000 + UP_ROTATE_MS - 1), "due 1 ms early");
    CHECK(up_rotate_due(&st, 5000 + UP_ROTATE_MS), "not due at exactly %u ms", (unsigned)UP_ROTATE_MS);

    /* uint32 ms counter wraps in the middle of the interval */
    uint32_t start = 0xFFFFFFFFu - 10000u;
    up_init(&st, start);
    CHECK(!up_rotate_due(&st, start + UP_ROTATE_MS - 1), "wrap: due 1 ms early");
    CHECK(up_rotate_due(&st, start + UP_ROTATE_MS), "wrap: not due at threshold");
    CHECK(!up_rotate_due(&st, start), "wrap: due at t=0");
}

static void test_port_mapping(void)
{
    uint16_t first = up_port_from_random(0);
    bool varied = false;
    uint32_t r = 0x12345678u;
    for (int i = 0; i < 100000; i++) {
        r = r * 1664525u + 1013904223u;
        uint16_t p = up_port_from_random(r);
        CHECK((uint32_t)p >= UP_PORT_MIN, "port %u below range (the uint16 type caps the top)", (unsigned)p);
        if (p != first) varied = true;
    }
    CHECK(varied, "port mapping is constant");
    CHECK(up_port_from_random(0) >= UP_PORT_MIN, "r=0 below range");
    CHECK(up_port_from_random(0xFFFFFFFFu) == UP_PORT_MAX, "r=max not top of range");
    CHECK(up_port_from_random(0xFFFFFFFFu) <= UP_PORT_MAX, "r=max above range");
}

static void test_generation_tag(void)
{
    up_state_t st;
    up_init(&st, 0);
    uint8_t g0 = st.cur_gen;
    CHECK(up_reply_ok(g0, g0), "same-generation reply rejected");
    uint8_t g1;
    CHECK(up_begin_rotate(&st, 100, &g1), "rotate refused");
    CHECK(g1 != g0, "generation did not advance");
    CHECK(st.cur_gen == g1, "cur_gen not the new generation");
    CHECK(!up_reply_ok(g0, g1), "flight g accepted on g+1's socket");
    CHECK(!up_reply_ok(g1, g0), "flight g+1 accepted on g's socket");
    CHECK(up_reply_ok(g0, g0), "flight g rejected on its own (draining) socket");
}

static void test_drain_completes_only_at_zero(void)
{
    up_state_t st;
    up_init(&st, 0);
    uint8_t g1;
    CHECK(!up_draining(&st), "draining before any rotation");
    CHECK(up_begin_rotate(&st, 10, &g1), "rotate refused");
    CHECK(up_draining(&st), "not draining after rotation");
    CHECK(!up_drain_poll(&st, 3), "drain done with 3 flights");
    CHECK(!up_drain_poll(&st, 1), "drain done with 1 flight");
    CHECK(up_draining(&st), "drain flag lost early");
    CHECK(up_drain_poll(&st, 0), "drain not done at zero flights");
    CHECK(!up_draining(&st), "still draining after completion");
    CHECK(!up_drain_poll(&st, 0), "completion reported twice");
}

static void test_no_third_socket(void)
{
    up_state_t st;
    up_init(&st, 0);
    uint8_t g1, g2;
    CHECK(up_begin_rotate(&st, 0, &g1), "first rotate refused");
    uint8_t before = st.cur_gen;
    /* Both thresholds blown while the old socket still drains. */
    for (uint32_t i = 0; i < UP_ROTATE_QUERIES; i++) up_note_forward(&st);
    CHECK(!up_rotate_due(&st, UP_ROTATE_MS * 2), "rotation offered while draining");
    CHECK(!up_begin_rotate(&st, UP_ROTATE_MS * 2, &g2), "third socket allowed");
    CHECK(st.cur_gen == before, "generation moved on a refused rotate");
    /* Deferred, not lost: due again the moment the drain finishes. */
    CHECK(up_drain_poll(&st, 0), "drain should finish");
    CHECK(up_rotate_due(&st, UP_ROTATE_MS * 2), "deferred rotation lost");
    CHECK(up_begin_rotate(&st, UP_ROTATE_MS * 2, &g2), "rotate refused after drain");
    CHECK(g2 != g1, "generation reused");
}

static void test_rotate_resets_and_failure_backoff(void)
{
    up_state_t st;
    up_init(&st, 0);
    for (uint32_t i = 0; i < UP_ROTATE_QUERIES; i++) up_note_forward(&st);
    uint8_t g;
    CHECK(up_begin_rotate(&st, 500, &g), "rotate refused");
    CHECK(st.queries == 0, "query counter not reset");
    CHECK(up_drain_poll(&st, 0), "drain should finish");
    CHECK(!up_rotate_due(&st, 500 + UP_ROTATE_MS - 1), "due early after rotation");
    /* A failed bind restarts both clocks so the task does not retry every tick. */
    for (uint32_t i = 0; i < UP_ROTATE_QUERIES; i++) up_note_forward(&st);
    CHECK(up_rotate_due(&st, 600), "should be due");
    up_rotate_failed(&st, 600);
    CHECK(!up_rotate_due(&st, 601), "failed rotate retried at once");
    CHECK(up_rotate_due(&st, 600 + UP_ROTATE_MS), "failed rotate never retried");
    /* Generation wraps in uint8 without confusing the 2-live-socket rule. */
    up_init(&st, 0);
    for (int i = 0; i < 600; i++) {
        uint8_t prev = st.cur_gen, ng;
        CHECK(up_begin_rotate(&st, 0, &ng), "rotate %d refused", i);
        CHECK(!up_reply_ok(prev, ng), "wrap: old gen accepted on new socket");
        CHECK(up_drain_poll(&st, 0), "wrap: drain stuck");
    }
}

int main(void)
{
    test_query_threshold();
    test_time_threshold_and_wrap();
    test_port_mapping();
    test_generation_tag();
    test_drain_completes_only_at_zero();
    test_no_third_socket();
    test_rotate_resets_and_failure_backoff();
    if (g_fail) { printf("upstream_port_test: %d FAILED\n", g_fail); return 1; }
    printf("upstream_port_test: all passed\n");
    return 0;
}
