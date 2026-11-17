/*
 * Host tests for the POST /pause/schedule form-body conversion
 * (main/web_sched_form.c).
 *
 * Build + run:
 *   gcc -O2 -Wall -Wextra -fsanitize=address,undefined -I main -o web_sched_form_test \
 *       tests/web_sched_form_test.c main/web_sched_form.c main/pause_sched.c main/web_parse.c \
 *       && ./web_sched_form_test
 */
#include "web_sched_form.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail = 0;
#define CHECK(cond, ...) do { if (!(cond)) { \
    printf("  FAIL: "); printf(__VA_ARGS__); printf("\n"); g_fail++; } } while (0)

static void test_set_window(void)
{
    web_sched_form_t f;
    bool ok = web_sched_form_parse("slot=1&spec=weekdays+09%3A00-17%3A00", &f);
    CHECK(ok, "weekdays body accepted");
    CHECK(f.kind == WSF_SET_WINDOW, "kind set-window (%d)", (int)f.kind);
    CHECK(f.slot == 1, "slot 1 (%d)", f.slot);
    CHECK(f.win.enabled, "enabled");
    CHECK(f.win.days == PAUSE_SCHED_DAYS_WEEKDAY, "weekday mask 0x%x", f.win.days);
    CHECK(f.win.start_min == 540 && f.win.end_min == 1020, "09:00-17:00 -> %u-%u",
          f.win.start_min, f.win.end_min);

    /* field order must not matter */
    ok = web_sched_form_parse("spec=mon,tue+22:00-06:30&slot=3", &f);
    CHECK(ok && f.kind == WSF_SET_WINDOW && f.slot == 3, "reordered fields");
    CHECK(ok && f.win.days == 0x06 && f.win.start_min == 1320 && f.win.end_min == 390,
          "mon,tue 22:00-06:30 parsed");
}

static void test_reject_slot(void)
{
    web_sched_form_t f;
    CHECK(!web_sched_form_parse("slot=4&spec=daily+00:00-01:00", &f), "slot 4 rejected");
    CHECK(f.kind == WSF_REJECT && f.err && f.err[0], "reject carries a reason");
    CHECK(!web_sched_form_parse("slot=-1&spec=daily+00:00-01:00", &f), "slot -1 rejected");
    CHECK(!web_sched_form_parse("slot=01&spec=daily+00:00-01:00", &f), "slot 01 rejected");
    CHECK(!web_sched_form_parse("slot=&spec=daily+00:00-01:00", &f), "empty slot rejected");
    CHECK(!web_sched_form_parse("slot=x&spec=daily+00:00-01:00", &f), "non-digit slot rejected");
    CHECK(!web_sched_form_parse("spec=daily+00:00-01:00", &f), "missing slot rejected");
    CHECK(!web_sched_form_parse("", &f), "empty body rejected");
    CHECK(!web_sched_form_parse("slot=1", &f), "missing spec rejected");
}

static void test_clear(void)
{
    web_sched_form_t f;
    bool ok = web_sched_form_parse("slot=0&spec=", &f);
    CHECK(ok && f.kind == WSF_CLEAR_WINDOW && f.slot == 0, "empty spec clears slot 0");
    ok = web_sched_form_parse("slot=2&spec=+", &f);
    CHECK(!ok, "whitespace-only spec is not a clear");
}

static void test_bad_spec(void)
{
    web_sched_form_t f;
    CHECK(!web_sched_form_parse("slot=0&spec=nonsense", &f), "garbage spec rejected");
    CHECK(f.kind == WSF_REJECT, "kind reject");
    CHECK(!web_sched_form_parse("slot=0&spec=daily+25:00-26:00", &f), "out-of-range time rejected");
}

static void test_offset(void)
{
    web_sched_form_t f;
    bool ok = web_sched_form_parse("utc_offset_min=-300", &f);
    CHECK(ok && f.kind == WSF_SET_OFFSET && f.utc_offset_min == -300, "offset -300");
    ok = web_sched_form_parse("utc_offset_min=840", &f);
    CHECK(ok && f.utc_offset_min == 840, "offset 840 upper bound");
    ok = web_sched_form_parse("utc_offset_min=-720", &f);
    CHECK(ok && f.utc_offset_min == -720, "offset -720 lower bound");
    ok = web_sched_form_parse("utc_offset_min=0", &f);
    CHECK(ok && f.utc_offset_min == 0, "offset 0");
    CHECK(!web_sched_form_parse("utc_offset_min=900", &f), "offset 900 rejected");
    CHECK(!web_sched_form_parse("utc_offset_min=841", &f), "offset 841 rejected");
    CHECK(!web_sched_form_parse("utc_offset_min=-721", &f), "offset -721 rejected");
    CHECK(!web_sched_form_parse("utc_offset_min=", &f), "empty offset rejected");
    CHECK(!web_sched_form_parse("utc_offset_min=5x", &f), "trailing junk rejected");
    CHECK(!web_sched_form_parse("utc_offset_min=99999999999999999999", &f), "huge offset rejected");
    CHECK(!web_sched_form_parse("utc_offset_min=60&slot=0&spec=", &f), "offset plus slot rejected");
}

static void test_oversize(void)
{
    /* A 600-byte spec: a valid spec followed by padding. Truncating it to the
     * buffer must not turn it into an accepted one. */
    char *body = malloc(700);
    CHECK(body != NULL, "malloc");
    if (!body) return;
    strcpy(body, "slot=0&spec=daily+09:00-17:00");
    size_t n = strlen(body);
    memset(body + n, '+', 600);
    body[n + 600] = '\0';
    web_sched_form_t f;
    CHECK(!web_sched_form_parse(body, &f), "padded 600-byte spec rejected");
    memset(body, 'a', 600); body[600] = '\0';
    memcpy(body, "slot=0&spec=", 12);
    CHECK(!web_sched_form_parse(body, &f), "600-byte garbage spec rejected");
    free(body);
    CHECK(!web_sched_form_parse(NULL, &f), "NULL body rejected");
    CHECK(!web_sched_form_parse("slot=0&spec=", NULL), "NULL out rejected");
}

int main(void)
{
    test_set_window();
    test_reject_slot();
    test_clear();
    test_bad_spec();
    test_offset();
    test_oversize();
    if (g_fail) { printf("web_sched_form_test: %d FAILED\n", g_fail); return 1; }
    printf("web_sched_form_test: all passed\n");
    return 0;
}
