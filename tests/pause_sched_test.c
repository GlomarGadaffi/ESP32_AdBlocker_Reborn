/*
 * Host tests for the recurring pause schedule (main/pause_sched.c).
 *
 * Build + run:
 *   gcc -O2 -Wall -Wextra -I main -o pause_sched_test tests/pause_sched_test.c main/pause_sched.c && ./pause_sched_test
 */
#include "pause_sched.h"
#include <stdio.h>
#include <string.h>

static int g_fail = 0;
#define CHECK(cond, ...) do { if (!(cond)) { \
    printf("  FAIL: "); printf(__VA_ARGS__); printf("\n"); g_fail++; } } while (0)

enum { SUN, MON, TUE, WED, THU, FRI, SAT };
#define HM(h, m) ((h) * 60 + (m))

static pause_sched_t one(const char *spec)
{
    pause_sched_t s;
    memset(&s, 0, sizeof(s));
    int rc = pause_sched_parse(spec, &s.win[0]);
    CHECK(rc == 0, "parse('%s') rc=%d", spec, rc);
    return s;
}

static void test_active(void)
{
    pause_sched_t s = one("weekdays 09:00-17:00");
    CHECK(pause_sched_active(&s, MON, HM(9, 0)), "mon 09:00 active");
    CHECK(!pause_sched_active(&s, MON, HM(17, 0)), "mon 17:00 end exclusive");
    CHECK(!pause_sched_active(&s, SAT, HM(12, 0)), "sat 12:00 inactive");

    s = one("fri 22:00-02:00");
    CHECK(pause_sched_active(&s, FRI, HM(23, 59)), "fri 23:59");
    CHECK(pause_sched_active(&s, SAT, HM(1, 59)), "sat 01:59");
    CHECK(!pause_sched_active(&s, SAT, HM(2, 0)), "sat 02:00");
    CHECK(!pause_sched_active(&s, FRI, HM(1, 0)), "fri 01:00");
    CHECK(!pause_sched_active(&s, SUN, HM(1, 0)), "sun 01:00 (sat bit unset)");

    s = one("daily 00:00-00:00");
    for (int d = 0; d < 7; d++)
        for (int m = 0; m < 1440; m += 59)
            CHECK(!pause_sched_active(&s, d, m), "empty window active d=%d m=%d", d, m);

    s = one("sun 23:00-01:00");
    CHECK(pause_sched_active(&s, MON, HM(0, 30)), "week wrap sun->mon");
    s = one("sat 23:00-01:00");
    CHECK(pause_sched_active(&s, SUN, HM(0, 30)), "week wrap sat->sun");

    s = one("daily 09:00-17:00");
    s.win[0].enabled = false;
    CHECK(!pause_sched_active(&s, MON, HM(10, 0)), "disabled never active");
    CHECK(!pause_sched_active(NULL, MON, 0), "NULL never active");
    s.win[0].enabled = true;
    CHECK(!pause_sched_active(&s, 7, 600), "weekday 7 rejected");
    CHECK(!pause_sched_active(&s, MON, 1440), "minute 1440 rejected");
    CHECK(!pause_sched_active(&s, -1, 600), "weekday -1 rejected");
}

static void test_parse_reject(void)
{
    const char *bad[] = { "mon 25:00-26:00", "mon 10:00", "funday 10:00-11:00", "",
                          "mon 10:00-11:60", "mon 9:00-10:00", "mon  10:00-11:00",
                          "mon, 10:00-11:00", "mon,,tue 10:00-11:00", "10:00-11:00",
                          "mon 10:00-11:00 x", "mon 10:00-11:00 " };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        pause_sched_window_t w = { true, 0x55, 111, 222 };
        int rc = pause_sched_parse(bad[i], &w);
        CHECK(rc != 0, "'%s' should be rejected", bad[i]);
        CHECK(w.enabled && w.days == 0x55 && w.start_min == 111 && w.end_min == 222,
              "'%s' modified *out", bad[i]);
    }
    char longs[301];
    memset(longs, 'a', 300);
    longs[300] = '\0';
    pause_sched_window_t w = { true, 0x55, 111, 222 };
    CHECK(pause_sched_parse(longs, &w) != 0, "300-char string rejected");
    CHECK(w.days == 0x55, "300-char string modified *out");
    CHECK(pause_sched_parse(NULL, &w) != 0, "NULL text rejected");
    CHECK(pause_sched_parse("mon 10:00-11:00", NULL) != 0, "NULL out rejected");
}

static void test_roundtrip(void)
{
    const char *good[] = { "mon,tue,wed 22:00-06:30", "daily 00:00-00:00", "weekdays 09:00-17:00",
                           "weekends 08:00-23:59", "sun 23:00-01:00", "sun,mon,tue,wed,thu,fri 00:01-00:02",
                           "mon,wed,fri 12:00-13:00" };
    for (size_t i = 0; i < sizeof(good) / sizeof(good[0]); i++) {
        pause_sched_window_t w;
        char buf[PAUSE_SCHED_SPEC_MAX];
        CHECK(pause_sched_parse(good[i], &w) == 0, "parse '%s'", good[i]);
        CHECK(pause_sched_format(&w, buf, sizeof(buf)) == 0, "format '%s'", good[i]);
        CHECK(strcmp(buf, good[i]) == 0, "canonical '%s' got '%s'", good[i], buf);
    }
    /* non-canonical input normalises: order, case, and the 7-day / 5-day sets */
    pause_sched_window_t w;
    char buf[PAUSE_SCHED_SPEC_MAX];
    CHECK(pause_sched_parse("WED,Mon 10:00-11:00", &w) == 0, "mixed case parses");
    CHECK(pause_sched_format(&w, buf, sizeof(buf)) == 0 && strcmp(buf, "mon,wed 10:00-11:00") == 0,
          "normalised: '%s'", buf);
    CHECK(pause_sched_parse("sat,sun,mon,tue,wed,thu,fri 01:00-02:00", &w) == 0 &&
          pause_sched_format(&w, buf, sizeof(buf)) == 0 && strcmp(buf, "daily 01:00-02:00") == 0,
          "all seven days -> daily: '%s'", buf);
    /* small buffer */
    CHECK(pause_sched_parse("mon 10:00-11:00", &w) == 0, "parse");
    char tiny[8];
    CHECK(pause_sched_format(&w, tiny, sizeof(tiny)) != 0, "tiny buffer rejected");
    CHECK(pause_sched_format(&w, tiny, 0) != 0, "zero cap rejected");
    pause_sched_window_t bad = { true, 0, 0, 10 };
    CHECK(pause_sched_format(&bad, buf, sizeof(buf)) != 0, "no days rejected");
}

static void test_blob(void)
{
    pause_sched_t s;
    memset(&s, 0, sizeof(s));
    CHECK(pause_sched_parse("weekdays 09:00-17:00", &s.win[0]) == 0, "parse");
    CHECK(pause_sched_parse("fri 22:00-02:00", &s.win[3]) == 0, "parse");
    s.win[3].enabled = false;
    s.utc_offset_min = -300;

    uint8_t blob[PAUSE_SCHED_BLOB_LEN];
    CHECK(pause_sched_serialise(&s, blob, sizeof(blob)) == 0, "serialise");
    CHECK(pause_sched_serialise(&s, blob, sizeof(blob) - 1) != 0, "serialise short buffer");

    pause_sched_t r;
    memset(&r, 0xAA, sizeof(r));
    CHECK(pause_sched_deserialise(blob, sizeof(blob), &r) == 0, "deserialise");
    CHECK(memcmp(&r.win[0], &s.win[0], sizeof(r.win[0])) == 0, "win0 round-trip");
    CHECK(memcmp(&r.win[3], &s.win[3], sizeof(r.win[3])) == 0, "win3 round-trip");
    CHECK(r.utc_offset_min == -300, "offset round-trip %d", r.utc_offset_min);

    memset(&r, 0xAA, sizeof(r));
    pause_sched_t keep = r;
    CHECK(pause_sched_deserialise(blob, sizeof(blob) - 1, &r) != 0, "truncated rejected");
    CHECK(pause_sched_deserialise(blob, sizeof(blob) + 1, &r) != 0, "oversize rejected");
    CHECK(pause_sched_deserialise(NULL, sizeof(blob), &r) != 0, "NULL rejected");
    uint8_t b2[PAUSE_SCHED_BLOB_LEN];
    memcpy(b2, blob, sizeof(b2));
    b2[0] = 2;
    CHECK(pause_sched_deserialise(b2, sizeof(b2), &r) != 0, "unknown version rejected");
    memcpy(b2, blob, sizeof(b2));
    b2[1 + 2 + 2] = 0xFF; b2[1 + 2 + 3] = 0x7F;      /* win0 start = 32767 */
    CHECK(pause_sched_deserialise(b2, sizeof(b2), &r) != 0, "start out of range rejected");
    memcpy(b2, blob, sizeof(b2));
    b2[1 + 2 + 1] = 0x80;                            /* win0 days bit7 */
    CHECK(pause_sched_deserialise(b2, sizeof(b2), &r) != 0, "days bit7 rejected");
    memcpy(b2, blob, sizeof(b2));
    b2[1 + 2 + 0] = 2;                               /* enabled not 0/1 */
    CHECK(pause_sched_deserialise(b2, sizeof(b2), &r) != 0, "enabled=2 rejected");
    memcpy(b2, blob, sizeof(b2));
    b2[1] = 0x00; b2[2] = 0x40;                      /* offset 16384 */
    CHECK(pause_sched_deserialise(b2, sizeof(b2), &r) != 0, "offset out of range rejected");
    CHECK(memcmp(&r, &keep, sizeof(r)) == 0, "rejects left *out untouched");

    /* all-zero is a valid empty schedule once the version byte is set */
    memset(b2, 0, sizeof(b2));
    b2[0] = PAUSE_SCHED_BLOB_VERSION;
    CHECK(pause_sched_deserialise(b2, sizeof(b2), &r) == 0, "empty schedule valid");
}

static void test_localtime(void)
{
    int wd = -1, mn = -1;
    /* 1970-01-01 00:00 UTC was a Thursday */
    CHECK(pause_sched_localtime(0, 0, &wd, &mn) == 0 && wd == THU && mn == 0, "epoch 0: %d %d", wd, mn);
    /* 2026-11-16 12:34:56 UTC = 1794832496; a Monday */
    CHECK(pause_sched_localtime(1794832496u, 0, &wd, &mn) == 0 && wd == MON && mn == HM(12, 34),
          "known Monday: %d %d", wd, mn);
    /* UTC-5 pushes 02:00 Monday UTC back to 21:00 Sunday */
    CHECK(pause_sched_localtime(1794832496u - HM(12, 34) * 60 + HM(2, 0) * 60, -300, &wd, &mn) == 0 &&
          wd == SUN && mn == HM(21, 0), "negative offset: %d %d", wd, mn);
    /* +14h from Monday 12:34 UTC -> Tuesday 02:34 */
    CHECK(pause_sched_localtime(1794832496u, 840, &wd, &mn) == 0 && wd == TUE && mn == HM(2, 34),
          "positive offset: %d %d", wd, mn);
    CHECK(pause_sched_localtime(5, 0, NULL, &mn) != 0, "NULL weekday");
    CHECK(pause_sched_localtime(5, 5000, &wd, &mn) != 0, "offset range");
    /* a tiny epoch with a negative offset must not underflow */
    CHECK(pause_sched_localtime(60, -720, &wd, &mn) == 0 && wd == WED && mn == HM(12, 1),
          "pre-epoch local: %d %d", wd, mn);
}

int main(void)
{
    test_active();
    test_parse_reject();
    test_roundtrip();
    test_blob();
    test_localtime();
    if (g_fail) { printf("pause_sched_test: %d FAILED\n", g_fail); return 1; }
    printf("pause_sched_test: all passed\n");
    return 0;
}
