#include "pause_sched.h"
#include <string.h>

#define MINUTES_PER_DAY 1440

static const char *const DAY_NAME[7] = { "sun", "mon", "tue", "wed", "thu", "fri", "sat" };

static bool window_valid(const pause_sched_window_t *w)
{
    return (w->days & (uint8_t)~PAUSE_SCHED_DAYS_ALL) == 0 &&
           w->start_min < MINUTES_PER_DAY && w->end_min < MINUTES_PER_DAY;
}

bool pause_sched_active(const pause_sched_t *s, int weekday, int minute_of_day)
{
    if (!s || weekday < 0 || weekday > 6 || minute_of_day < 0 || minute_of_day >= MINUTES_PER_DAY)
        return false;
    int prev = (weekday + 6) % 7;
    for (int i = 0; i < PAUSE_SCHED_MAX_WINDOWS; i++) {
        const pause_sched_window_t *w = &s->win[i];
        if (!w->enabled || w->start_min == w->end_min || !window_valid(w)) continue;
        bool today = (w->days >> weekday) & 1u;
        if (w->start_min < w->end_min) {
            if (today && minute_of_day >= w->start_min && minute_of_day < w->end_min) return true;
        } else {
            /* Wraps midnight: the evening part belongs to the start day, the
             * morning part to the day after it. */
            if (today && minute_of_day >= w->start_min) return true;
            if (((w->days >> prev) & 1u) && minute_of_day < w->end_min) return true;
        }
    }
    return false;
}

int pause_sched_localtime(uint32_t epoch_s, int utc_offset_min, int *weekday, int *minute_of_day)
{
    if (!weekday || !minute_of_day) return 1;
    if (utc_offset_min < PAUSE_SCHED_UTC_MIN_MIN || utc_offset_min > PAUSE_SCHED_UTC_MAX_MIN) return 1;
    int64_t local = (int64_t)epoch_s + (int64_t)utc_offset_min * 60;
    int64_t days = local / 86400;
    int64_t sec  = local % 86400;
    if (sec < 0) { sec += 86400; days -= 1; }
    /* 1970-01-01 was a Thursday (weekday 4 with Sunday = 0). */
    int64_t wd = (days + 4) % 7;
    if (wd < 0) wd += 7;
    *weekday = (int)wd;
    *minute_of_day = (int)(sec / 60);
    return 0;
}

static char lower(char c) { return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c; }

static bool is_digit(char c) { return c >= '0' && c <= '9'; }

/* Match a whole token (case-insensitive) of exactly n characters. */
static bool tok_eq(const char *p, size_t n, const char *word)
{
    if (strlen(word) != n) return false;
    for (size_t i = 0; i < n; i++)
        if (lower(p[i]) != word[i]) return false;
    return true;
}

/* "HH:MM" -> minutes, or -1. Exactly two digits each side. */
static int parse_hhmm(const char *p)
{
    if (!is_digit(p[0]) || !is_digit(p[1]) || p[2] != ':' || !is_digit(p[3]) || !is_digit(p[4]))
        return -1;
    int h = (p[0] - '0') * 10 + (p[1] - '0');
    int m = (p[3] - '0') * 10 + (p[4] - '0');
    if (h > 23 || m > 59) return -1;
    return h * 60 + m;
}

/* Day set text -> bitmask, or 0 when malformed. Mutually exclusive forms:
 * a keyword on its own, or a comma list of three-letter day names. */
static uint8_t parse_days(const char *p, size_t n)
{
    if (tok_eq(p, n, "daily"))    return PAUSE_SCHED_DAYS_ALL;
    if (tok_eq(p, n, "weekdays")) return PAUSE_SCHED_DAYS_WEEKDAY;
    if (tok_eq(p, n, "weekends")) return PAUSE_SCHED_DAYS_WEEKEND;
    uint8_t mask = 0;
    size_t i = 0;
    for (int guard = 0; guard < 16; guard++) {      /* at most 7 names are legal anyway */
        if (i + 3 > n) return 0;
        int day = -1;
        for (int d = 0; d < 7; d++)
            if (tok_eq(p + i, 3, DAY_NAME[d])) { day = d; break; }
        if (day < 0) return 0;
        mask |= (uint8_t)(1u << day);
        i += 3;
        if (i == n) return mask;
        if (p[i] != ',') return 0;
        i++;                                        /* a trailing comma fails the next pass */
    }
    return 0;
}

int pause_sched_parse(const char *text, pause_sched_window_t *out)
{
    if (!text || !out) return 1;
    size_t len = strnlen(text, PAUSE_SCHED_PARSE_MAX);
    if (len >= PAUSE_SCHED_PARSE_MAX || len == 0) return 1;
    const char *sp = memchr(text, ' ', len);
    if (!sp) return 1;
    size_t dn = (size_t)(sp - text);
    if (dn == 0 || len - dn - 1 != 11) return 1;    /* "HH:MM-HH:MM" exactly */
    uint8_t days = parse_days(text, dn);
    if (days == 0) return 1;
    const char *t = sp + 1;
    if (t[5] != '-') return 1;
    int a = parse_hhmm(t), b = parse_hhmm(t + 6);
    if (a < 0 || b < 0) return 1;
    out->enabled = true;
    out->days = days;
    out->start_min = (uint16_t)a;
    out->end_min = (uint16_t)b;
    return 0;
}

int pause_sched_format(const pause_sched_window_t *w, char *buf, size_t cap)
{
    if (!buf || cap == 0) return 1;
    buf[0] = '\0';
    if (!w || w->days == 0 || !window_valid(w)) return 1;
    char tmp[PAUSE_SCHED_SPEC_MAX];
    size_t n = 0;
    if (w->days == PAUSE_SCHED_DAYS_ALL) {
        memcpy(tmp, "daily", 5); n = 5;
    } else if (w->days == PAUSE_SCHED_DAYS_WEEKDAY) {
        memcpy(tmp, "weekdays", 8); n = 8;
    } else if (w->days == PAUSE_SCHED_DAYS_WEEKEND) {
        memcpy(tmp, "weekends", 8); n = 8;
    } else {
        for (int d = 0; d < 7; d++) {
            if (!((w->days >> d) & 1u)) continue;
            if (n) tmp[n++] = ',';
            memcpy(tmp + n, DAY_NAME[d], 3);
            n += 3;
        }
    }
    /* Longest day part is 6 names + 5 commas = 23; plus " HH:MM-HH:MM" = 35. */
    int sh = w->start_min / 60, sm = w->start_min % 60, eh = w->end_min / 60, em = w->end_min % 60;
    tmp[n++] = ' ';
    tmp[n++] = (char)('0' + sh / 10); tmp[n++] = (char)('0' + sh % 10); tmp[n++] = ':';
    tmp[n++] = (char)('0' + sm / 10); tmp[n++] = (char)('0' + sm % 10); tmp[n++] = '-';
    tmp[n++] = (char)('0' + eh / 10); tmp[n++] = (char)('0' + eh % 10); tmp[n++] = ':';
    tmp[n++] = (char)('0' + em / 10); tmp[n++] = (char)('0' + em % 10);
    tmp[n] = '\0';
    if (n + 1 > cap) return 1;
    memcpy(buf, tmp, n + 1);
    return 0;
}

int pause_sched_serialise(const pause_sched_t *s, uint8_t *buf, size_t cap)
{
    if (!s || !buf || cap < PAUSE_SCHED_BLOB_LEN) return 1;
    if (s->utc_offset_min < PAUSE_SCHED_UTC_MIN_MIN || s->utc_offset_min > PAUSE_SCHED_UTC_MAX_MIN) return 1;
    for (int i = 0; i < PAUSE_SCHED_MAX_WINDOWS; i++)
        if (!window_valid(&s->win[i])) return 1;
    uint16_t off = (uint16_t)s->utc_offset_min;
    size_t p = 0;
    buf[p++] = PAUSE_SCHED_BLOB_VERSION;
    buf[p++] = (uint8_t)(off & 0xFF);
    buf[p++] = (uint8_t)(off >> 8);
    for (int i = 0; i < PAUSE_SCHED_MAX_WINDOWS; i++) {
        const pause_sched_window_t *w = &s->win[i];
        buf[p++] = w->enabled ? 1 : 0;
        buf[p++] = w->days;
        buf[p++] = (uint8_t)(w->start_min & 0xFF);
        buf[p++] = (uint8_t)(w->start_min >> 8);
        buf[p++] = (uint8_t)(w->end_min & 0xFF);
        buf[p++] = (uint8_t)(w->end_min >> 8);
    }
    return 0;
}

int pause_sched_deserialise(const uint8_t *buf, size_t len, pause_sched_t *out)
{
    if (!buf || !out || len != PAUSE_SCHED_BLOB_LEN) return 1;
    if (buf[0] != PAUSE_SCHED_BLOB_VERSION) return 1;
    pause_sched_t t;
    memset(&t, 0, sizeof(t));
    int off = (int16_t)(uint16_t)(buf[1] | ((uint16_t)buf[2] << 8));
    if (off < PAUSE_SCHED_UTC_MIN_MIN || off > PAUSE_SCHED_UTC_MAX_MIN) return 1;
    t.utc_offset_min = (int16_t)off;
    size_t p = 3;
    for (int i = 0; i < PAUSE_SCHED_MAX_WINDOWS; i++) {
        if (buf[p] > 1) return 1;
        t.win[i].enabled = buf[p] == 1;
        t.win[i].days = buf[p + 1];
        t.win[i].start_min = (uint16_t)(buf[p + 2] | ((uint16_t)buf[p + 3] << 8));
        t.win[i].end_min = (uint16_t)(buf[p + 4] | ((uint16_t)buf[p + 5] << 8));
        if (!window_valid(&t.win[i])) return 1;
        p += 6;
    }
    *out = t;
    return 0;
}
