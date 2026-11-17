/*
 * /metrics JSON to Prometheus text. See metrics_prom.h for the mapping.
 *
 * One forward pass over the JSON with a small explicit stack of open
 * containers. Every loop is bounded by the input length or a fixed cap, there
 * is no recursion and no allocation, and nothing is read at or past
 * json[json_len]. Output is written straight into the caller's buffer; any
 * error wipes it, so a caller never sees half a result.
 */
#include "metrics_prom.h"
#include <stdint.h>
#include <string.h>

#define NAME_CAP 160   /* "adblock_" + joined key path + NUL */
#define KEY_CAP   96   /* one decoded key */
#define NUM_CAP   40   /* longest number text accepted */
#define ID_CAP    64   /* one identity label value (truncated, not refused) */
#define N_ID       4

static const char *const ID_KEYS[N_ID] = { "version", "board", "upstream", "clock_src" };

typedef struct {
    int      is_arr;
    int      skip;       /* contents are validated but never emitted */
    size_t   name_len;   /* length of this container's path in name[] */
    uint32_t idx;        /* next element index (arrays) */
} frame_t;

typedef struct {
    const char *s;
    size_t      len, pos;
    char       *out;
    size_t      cap, n;
} ctx_t;

enum { S_ROOT, S_OBJ_FIRST, S_KEY, S_COLON, S_VALUE, S_ARR_FIRST, S_AFTER, S_DONE };

/* Append n bytes, keeping room for the terminating NUL. */
static int put(ctx_t *c, const char *p, size_t n)
{
    if (n >= c->cap - c->n) return METRICS_PROM_ERR_FULL;
    memcpy(c->out + c->n, p, n);
    c->n += n;
    return METRICS_PROM_OK;
}

static int put_z(ctx_t *c, const char *z) { return put(c, z, strlen(z)); }

static void skip_ws(ctx_t *c)
{
    while (c->pos < c->len) {
        char ch = c->s[c->pos];
        if (ch != ' ' && ch != '\t' && ch != '\n' && ch != '\r') break;
        c->pos++;
    }
}

static int hex_val(char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

/*
 * Scan the JSON string at s[pos] (which must be '"'), decoding escapes into
 * dst when dst is non-NULL. A decoded byte below 0x20 other than newline, and
 * any \u above 0x7F, becomes '?'. A result longer than dcap-1 is truncated
 * when `strict` is 0 and refused when it is 1.
 */
static int scan_string(ctx_t *c, char *dst, size_t dcap, int strict)
{
    size_t d = 0;
    c->pos++;   /* opening quote */
    while (c->pos < c->len) {
        unsigned char ch = (unsigned char)c->s[c->pos++];
        if (ch == '"') {
            if (dst) dst[d] = '\0';
            return METRICS_PROM_OK;
        }
        if (ch < 0x20) return METRICS_PROM_ERR_PARSE;
        if (ch == '\\') {
            if (c->pos >= c->len) return METRICS_PROM_ERR_PARSE;
            char e = c->s[c->pos++];
            switch (e) {
            case '"':  ch = '"';  break;
            case '\\': ch = '\\'; break;
            case '/':  ch = '/';  break;
            case 'b':  ch = '\b'; break;
            case 'f':  ch = '\f'; break;
            case 'n':  ch = '\n'; break;
            case 'r':  ch = '\r'; break;
            case 't':  ch = '\t'; break;
            case 'u': {
                if (c->len - c->pos < 4) return METRICS_PROM_ERR_PARSE;
                unsigned v = 0;
                for (int i = 0; i < 4; i++) {
                    int h = hex_val(c->s[c->pos + (size_t)i]);
                    if (h < 0) return METRICS_PROM_ERR_PARSE;
                    v = (v << 4) | (unsigned)h;
                }
                c->pos += 4;
                ch = v < 0x80 ? (unsigned char)v : (unsigned char)'?';
                break;
            }
            default: return METRICS_PROM_ERR_PARSE;
            }
            if (ch < 0x20 && ch != '\n') ch = '?';
        }
        if (dst) {
            if (d + 1 < dcap) dst[d++] = (char)ch;
            else if (strict) return METRICS_PROM_ERR_PARSE;
        }
    }
    return METRICS_PROM_ERR_PARSE;   /* ran off the end: unterminated */
}

static int is_digit(char ch) { return ch >= '0' && ch <= '9'; }

/* Validate a JSON number at s[pos]; report where it starts and how long it is. */
static int scan_number(ctx_t *c, size_t *start, size_t *nlen)
{
    size_t p = c->pos, end = c->len;
    const char *s = c->s;
    *start = p;
    if (p < end && s[p] == '-') p++;
    if (p >= end || !is_digit(s[p])) return METRICS_PROM_ERR_PARSE;
    if (s[p] == '0') p++;
    else while (p < end && is_digit(s[p])) p++;
    if (p < end && s[p] == '.') {
        p++;
        if (p >= end || !is_digit(s[p])) return METRICS_PROM_ERR_PARSE;
        while (p < end && is_digit(s[p])) p++;
    }
    if (p < end && (s[p] == 'e' || s[p] == 'E')) {
        p++;
        if (p < end && (s[p] == '+' || s[p] == '-')) p++;
        if (p >= end || !is_digit(s[p])) return METRICS_PROM_ERR_PARSE;
        while (p < end && is_digit(s[p])) p++;
    }
    if (p - *start > NUM_CAP) return METRICS_PROM_ERR_PARSE;
    *nlen = p - *start;
    c->pos = p;
    return METRICS_PROM_OK;
}

/* Match a bare literal at s[pos]. Returns its length, or 0 if it is not there. */
static size_t scan_literal(const ctx_t *c, const char *lit)
{
    size_t n = strlen(lit);
    if (c->len - c->pos < n) return 0;
    return memcmp(c->s + c->pos, lit, n) == 0 ? n : 0;
}

/* name[0..name_len) then an optional {idx="N"} label, a space, the value, a newline. */
static int emit_sample(ctx_t *c, const char *name, size_t name_len,
                       int is_elem, uint32_t idx, const char *val, size_t val_len)
{
    int rc = put(c, name, name_len);
    if (rc) return rc;
    if (is_elem) {
        char digits[11];
        size_t k = sizeof digits;
        uint32_t v = idx;
        do { digits[--k] = (char)('0' + v % 10u); v /= 10u; } while (v && k > 0);
        if ((rc = put_z(c, "{idx=\"")) != 0) return rc;
        if ((rc = put(c, digits + k, sizeof digits - k)) != 0) return rc;
        if ((rc = put_z(c, "\"}")) != 0) return rc;
    }
    if ((rc = put_z(c, " ")) != 0) return rc;
    if ((rc = put(c, val, val_len)) != 0) return rc;
    return put_z(c, "\n");
}

static int put_label_value(ctx_t *c, const char *v)
{
    for (size_t i = 0; v[i]; i++) {
        int rc;
        if (v[i] == '\\')      rc = put_z(c, "\\\\");
        else if (v[i] == '"')  rc = put_z(c, "\\\"");
        else if (v[i] == '\n') rc = put_z(c, "\\n");
        else                   rc = put(c, &v[i], 1);
        if (rc) return rc;
    }
    return METRICS_PROM_OK;
}

static int emit_info(ctx_t *c, char ids[N_ID][ID_CAP], const int have[N_ID])
{
    int any = 0, rc;
    for (int i = 0; i < N_ID; i++) any |= have[i];
    if (!any) return METRICS_PROM_OK;
    if ((rc = put_z(c, "adblock_info{")) != 0) return rc;
    int first = 1;
    for (int i = 0; i < N_ID; i++) {
        if (!have[i]) continue;
        if (!first && (rc = put_z(c, ",")) != 0) return rc;
        first = 0;
        if ((rc = put_z(c, ID_KEYS[i])) != 0) return rc;
        if ((rc = put_z(c, "=\"")) != 0) return rc;
        if ((rc = put_label_value(c, ids[i])) != 0) return rc;
        if ((rc = put_z(c, "\"")) != 0) return rc;
    }
    return put_z(c, "} 1\n");
}

static int convert(ctx_t *c)
{
    frame_t st[METRICS_PROM_MAX_DEPTH];
    int depth = 0, state = S_ROOT;
    char name[NAME_CAP];
    size_t cur_len = 7;                 /* leaf name of the pending value */
    char key[KEY_CAP];
    char ids[N_ID][ID_CAP];
    int have[N_ID] = { 0, 0, 0, 0 };
    int rc;

    memcpy(name, "adblock", 7);
    memset(ids, 0, sizeof ids);

    while (c->pos < c->len) {
        skip_ws(c);
        if (c->pos >= c->len) break;
        char ch = c->s[c->pos];

        if (state == S_DONE) return METRICS_PROM_ERR_PARSE;   /* trailing bytes */

        if (state == S_ROOT) {
            if (ch != '{') return METRICS_PROM_ERR_PARSE;
            st[0].is_arr = 0; st[0].skip = 0; st[0].name_len = 7; st[0].idx = 0;
            depth = 1;
            state = S_OBJ_FIRST;
            c->pos++;
            continue;
        }

        if (state == S_OBJ_FIRST && ch == '}') {
            c->pos++; depth--;
            state = depth == 0 ? S_DONE : S_AFTER;
            continue;
        }
        if (state == S_ARR_FIRST && ch == ']') {
            c->pos++; depth--;
            state = depth == 0 ? S_DONE : S_AFTER;
            continue;
        }

        if (state == S_OBJ_FIRST || state == S_KEY) {
            if (ch != '"') return METRICS_PROM_ERR_PARSE;
            if ((rc = scan_string(c, key, sizeof key, 1)) != 0) return rc;
            frame_t *f = &st[depth - 1];
            if (!f->skip) {
                size_t kl = strlen(key);
                if (f->name_len + 1 + kl >= sizeof name) return METRICS_PROM_ERR_PARSE;
                name[f->name_len] = '_';
                for (size_t i = 0; i < kl; i++) {
                    char k = key[i];
                    int ok = (k >= 'a' && k <= 'z') || (k >= 'A' && k <= 'Z') ||
                             (k >= '0' && k <= '9') || k == '_';
                    name[f->name_len + 1 + i] = ok ? k : '_';
                }
                cur_len = f->name_len + 1 + kl;
            }
            state = S_COLON;
            continue;
        }

        if (state == S_COLON) {
            if (ch != ':') return METRICS_PROM_ERR_PARSE;
            c->pos++;
            state = S_VALUE;
            continue;
        }

        if (state == S_AFTER) {
            frame_t *f = &st[depth - 1];
            if (ch == ',') {
                c->pos++;
                state = f->is_arr ? S_VALUE : S_KEY;
            } else if ((f->is_arr && ch == ']') || (!f->is_arr && ch == '}')) {
                c->pos++; depth--;
                state = depth == 0 ? S_DONE : S_AFTER;
            } else {
                return METRICS_PROM_ERR_PARSE;
            }
            continue;
        }

        /* S_VALUE or S_ARR_FIRST: one value. */
        frame_t *f = &st[depth - 1];
        uint32_t elem_idx = 0;
        if (f->is_arr) elem_idx = f->idx++;
        int emit = !f->skip;
        size_t leaf = f->is_arr ? f->name_len : cur_len;

        if (ch == '{' || ch == '[') {
            if (depth >= METRICS_PROM_MAX_DEPTH) return METRICS_PROM_ERR_DEPTH;
            frame_t *nf = &st[depth];
            nf->is_arr = (ch == '[');
            nf->skip = f->skip || f->is_arr;
            nf->name_len = leaf;
            nf->idx = 0;
            depth++;
            c->pos++;
            state = nf->is_arr ? S_ARR_FIRST : S_OBJ_FIRST;
            continue;
        }

        if (ch == '"') {
            int id = -1;
            if (emit && !f->is_arr && depth == 1) {
                for (int i = 0; i < N_ID; i++) {
                    size_t kl = strlen(ID_KEYS[i]);
                    if (leaf == 8 + kl && memcmp(name + 8, ID_KEYS[i], kl) == 0) { id = i; break; }
                }
            }
            if (id >= 0) {
                if ((rc = scan_string(c, ids[id], ID_CAP, 0)) != 0) return rc;
                have[id] = 1;
            } else if ((rc = scan_string(c, NULL, 0, 0)) != 0) {
                return rc;
            }
        } else if (ch == '-' || is_digit(ch)) {
            size_t start, nl;
            if ((rc = scan_number(c, &start, &nl)) != 0) return rc;
            if (emit && (rc = emit_sample(c, name, leaf, f->is_arr, elem_idx, c->s + start, nl)) != 0) return rc;
        } else if (ch == 't' || ch == 'f') {
            size_t n = scan_literal(c, ch == 't' ? "true" : "false");
            if (n == 0) return METRICS_PROM_ERR_PARSE;
            c->pos += n;
            if (emit && (rc = emit_sample(c, name, leaf, f->is_arr, elem_idx, ch == 't' ? "1" : "0", 1)) != 0) return rc;
        } else if (ch == 'n') {
            size_t n = scan_literal(c, "null");
            if (n == 0) return METRICS_PROM_ERR_PARSE;
            c->pos += n;
        } else {
            return METRICS_PROM_ERR_PARSE;
        }
        state = S_AFTER;
    }

    if (state != S_DONE) return METRICS_PROM_ERR_PARSE;   /* input ended inside the document */
    return emit_info(c, ids, have);
}

int metrics_json_to_prom(const char *json, size_t json_len,
                         char *out, size_t out_cap, size_t *out_len)
{
    if (!json || !out || !out_len) return METRICS_PROM_ERR_ARG;
    *out_len = 0;
    if (out_cap == 0) return METRICS_PROM_ERR_FULL;
    out[0] = '\0';

    ctx_t c;
    c.s = json; c.len = json_len; c.pos = 0;
    c.out = out; c.cap = out_cap; c.n = 0;

    int rc = convert(&c);
    if (rc != METRICS_PROM_OK) {
        out[0] = '\0';
        return rc;
    }
    out[c.n] = '\0';
    *out_len = c.n;
    return METRICS_PROM_OK;
}
