/*
 * libFuzzer target: the web UI's pre-authentication request parsers in
 * main/web_parse.c.
 *
 * Every function here sees attacker bytes before the session check:
 *   web_form_field / web_url_decode   /setup and /login bodies
 *   web_cookie_sid                    the Cookie header of every request
 *   web_origin_host_matches           Origin/Referer vs Host on every POST
 *   web_html_escape                   every client-chosen string rendered
 *
 * The input is split on the first NUL into two C strings, A and B, so the
 * fuzzer can drive the (url, host) / (body, key) / (cookie) pairs. Outputs
 * go into exact-size heap buffers with a fuzzer-chosen capacity so a write
 * one past cap is an ASan report.
 *
 * Invariants (a false assert is a finding):
 *  - every output is NUL-terminated within cap
 *  - html_escape output contains none of < > & " ' as raw bytes except '&'
 *    starting one of the five entities it emits
 *  - url_decode of the percent-encoding of X returns X (round trip)
 *  - form_field: a key found must be at the start or after '&' and be
 *    followed by '='
 *  - origin_host_matches never accepts url whose host is host + ".x"
 *  - cookie_sid: success means out is exactly sid_len bytes, from the
 *    cookie, and preceded by "sid=" at start or after ';' / ' '
 */
#include "web_parse.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static char *dupz(const uint8_t *p, size_t n) {
    char *s = (char *)malloc(n + 1); memcpy(s, p, n); s[n] = '\0'; return s;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) return 0;
    size_t cap = 1 + (data[0] % 96);            /* 1..96 */
    data++; size--;
    const uint8_t *nul = memchr(data, 0, size);
    size_t alen = nul ? (size_t)(nul - data) : size;
    char *A = dupz(data, alen);
    char *B = nul ? dupz(nul + 1, size - alen - 1) : dupz((const uint8_t *)"", 0);
    char *out = (char *)malloc(cap);

    /* html_escape */
    web_html_escape(out, cap, A);
    assert(strlen(out) < cap);
    for (size_t i = 0; out[i]; i++) {
        assert(out[i] != '<' && out[i] != '>' && out[i] != '"' && out[i] != '\'');
        if (out[i] == '&')
            assert(!strncmp(out + i, "&lt;", 4) || !strncmp(out + i, "&gt;", 4) ||
                   !strncmp(out + i, "&amp;", 5) || !strncmp(out + i, "&quot;", 6) ||
                   !strncmp(out + i, "&#39;", 5));
    }

    /* url_decode: memory safety on raw input, then a round trip */
    web_url_decode(out, cap, A, alen);
    assert(strlen(out) < cap);
    {
        static const char hx[] = "0123456789ABCDEF";
        char *enc = (char *)malloc(alen * 3 + 1); size_t e = 0;
        for (size_t i = 0; i < alen; i++) {
            enc[e++] = '%'; enc[e++] = hx[(uint8_t)A[i] >> 4]; enc[e++] = hx[(uint8_t)A[i] & 15];
        }
        enc[e] = '\0';
        char *big = (char *)malloc(alen + 1);
        web_url_decode(big, alen + 1, enc, e);
        assert(strlen(big) == alen && memcmp(big, A, alen) == 0);
        free(big); free(enc);
    }

    /* form_field: A = body, B = key */
    if (B[0]) {
        bool found = web_form_field(A, B, out, cap);
        assert(strlen(out) < cap);
        if (found) {
            /* the match the function used must exist under the contract */
            size_t kl = strlen(B); bool ok = false;
            for (const char *p = A; (p = strstr(p, B)) != NULL; p += kl)
                if ((p == A || p[-1] == '&') && p[kl] == '=') { ok = true; break; }
            assert(ok);
        } else {
            assert(out[0] == '\0');
        }
    }

    /* origin_host_matches: A = url, B = host, plus the classic bypass shapes */
    (void)web_origin_host_matches(A, B);
    if (B[0] && !strchr(B, ':') && !strchr(B, '/')) {
        size_t bl = strlen(B);
        char *u = (char *)malloc(bl + 16);
        memcpy(u, "https://", 8); memcpy(u + 8, B, bl);
        strcpy(u + 8 + bl, ".x");
        assert(!web_origin_host_matches(u, B));           /* host.x */
        strcpy(u + 8 + bl, "");
        assert(web_origin_host_matches(u, B));            /* exact */
        strcpy(u + 8 + bl, ":8443/p");
        assert(web_origin_host_matches(u, B));            /* with port + path */
        free(u);
    }

    /* cookie_sid: A = Cookie header, sid_len derived from cap */
    {
        size_t sl = cap;                                   /* 1..96 */
        char *sid = (char *)malloc(sl + 1);
        bool got = web_cookie_sid(A, sid, sl);
        if (got) {
            assert(strlen(sid) == sl);
            /* find the occurrence the parser must have used: a "sid=" at the
             * start or after ';'/' ', whose value is exactly sid then end/';' */
            bool ok = false;
            for (const char *q = A; (q = strstr(q, "sid=")) != NULL; q += 4) {
                if (!(q == A || q[-1] == ';' || q[-1] == ' ')) continue;
                if (memcmp(q + 4, sid, sl) == 0 && (q[4 + sl] == '\0' || q[4 + sl] == ';')) { ok = true; break; }
                break;   /* the parser stops at the first well-placed sid= */
            }
            assert(ok);
        } else {
            assert(sid[0] == '\0');
        }
        free(sid);
    }

    free(out); free(A); free(B);
    return 0;
}
