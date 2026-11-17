/*
 * POST /pause/schedule form-body conversion — see web_sched_form.h. No
 * ESP-IDF includes, by design: compiled on the host by tests/.
 */
#include "web_sched_form.h"
#include "web_parse.h"
#include <string.h>

/* One byte more than the parser's limit: a spec longer than the limit is
 * truncated by web_url_decode to exactly this many bytes less one, which is
 * still over PAUSE_SCHED_PARSE_MAX, so overflow can never read as a valid
 * shorter spec. */
#define SPEC_BUF (PAUSE_SCHED_PARSE_MAX + 2)

static bool reject(web_sched_form_t *out, const char *why)
{
    out->kind = WSF_REJECT;
    out->err  = why;
    return false;
}

/* Strict decimal: optional leading '-', 1-4 digits, nothing else. */
static bool parse_small_int(const char *s, int *v)
{
    bool neg = false;
    if (*s == '-') { neg = true; s++; }
    int n = 0, digits = 0;
    while (*s >= '0' && *s <= '9') {
        if (++digits > 4) return false;
        n = n * 10 + (*s - '0');
        s++;
    }
    if (digits == 0 || *s != '\0') return false;
    *v = neg ? -n : n;
    return true;
}

bool web_sched_form_parse(const char *body, web_sched_form_t *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    out->kind = WSF_REJECT;
    out->err  = "Bad request";
    if (!body) return false;

    char slot_s[8], spec[SPEC_BUF], off_s[12];
    bool has_slot = web_form_field(body, "slot", slot_s, sizeof(slot_s));
    bool has_spec = web_form_field(body, "spec", spec, sizeof(spec));
    bool has_off  = web_form_field(body, "utc_offset_min", off_s, sizeof(off_s));

    if (has_off) {
        if (has_slot || has_spec) return reject(out, "Send either slot+spec or utc_offset_min, not both");
        int v;
        if (!parse_small_int(off_s, &v) || v < PAUSE_SCHED_UTC_MIN_MIN || v > PAUSE_SCHED_UTC_MAX_MIN)
            return reject(out, "utc_offset_min must be -720 to 840");
        out->kind = WSF_SET_OFFSET;
        out->utc_offset_min = v;
        out->err = NULL;
        return true;
    }

    if (!has_slot || !has_spec) return reject(out, "Need slot and spec, or utc_offset_min");
    int slot;
    if (slot_s[0] == '-' || !parse_small_int(slot_s, &slot) || slot_s[1] != '\0' ||
        slot < 0 || slot >= PAUSE_SCHED_MAX_WINDOWS)
        return reject(out, "slot must be 0 to 3");
    if (strlen(spec) > PAUSE_SCHED_PARSE_MAX)
        return reject(out, "spec is too long");

    out->slot = slot;
    if (spec[0] == '\0') {
        out->kind = WSF_CLEAR_WINDOW;
        out->err = NULL;
        return true;
    }
    if (pause_sched_parse(spec, &out->win) != 0)
        return reject(out, "spec must look like: mon,tue 22:00-06:30 (or daily, weekdays, weekends)");
    out->kind = WSF_SET_WINDOW;
    out->err = NULL;
    return true;
}
