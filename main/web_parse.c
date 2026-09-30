/*
 * Request-parsing helpers — see web_parse.h. No ESP-IDF includes, by design:
 * this file is compiled on the host by tests/fuzz/.
 */
#include "web_parse.h"
#include <string.h>
#include <strings.h>
#include <stdlib.h>

void web_html_escape(char *dst, size_t cap, const char *src)
{
    size_t d = 0;
    for (size_t i = 0; src[i] && d + 1 < cap; i++) {
        const char *ent = NULL;
        switch (src[i]) {
            case '<':  ent = "&lt;";   break;
            case '>':  ent = "&gt;";   break;
            case '&':  ent = "&amp;";  break;
            case '"':  ent = "&quot;"; break;
            case '\'': ent = "&#39;";  break;
            default:   break;
        }
        if (ent) {
            size_t elen = strlen(ent);
            if (d + elen >= cap) break;
            memcpy(dst + d, ent, elen);
            d += elen;
        } else {
            dst[d++] = src[i];
        }
    }
    dst[d] = '\0';
}

void web_url_decode(char *dst, size_t cap, const char *src, size_t src_len)
{
    size_t d = 0;
    for (size_t i = 0; i < src_len && d + 1 < cap; i++) {
        if (src[i] == '%' && i + 2 < src_len) {
            char hex[3] = { src[i+1], src[i+2], '\0' };
            char *end; unsigned long v = strtoul(hex, &end, 16);
            if (end == hex + 2) { dst[d++] = (char)v; i += 2; continue; }
        }
        dst[d++] = (src[i] == '+') ? ' ' : src[i];
    }
    dst[d] = '\0';
}

bool web_form_field(const char *body, const char *key, char *dst, size_t cap)
{
    dst[0] = '\0';
    size_t kl = strlen(key);
    const char *p = body;
    while ((p = strstr(p, key)) != NULL) {
        if ((p == body || p[-1] == '&') && p[kl] == '=') {
            p += kl + 1;
            size_t l = 0;
            while (p[l] && p[l] != '&' && p[l] != '\r' && p[l] != '\n') l++;
            web_url_decode(dst, cap, p, l);
            return true;
        }
        p += kl;
    }
    return false;
}

bool web_origin_host_matches(const char *url, const char *host)
{
    if (host[0] == '\0') return false;
    const char *p = strstr(url, "://");
    if (!p) return false;
    p += 3;
    /* Host may carry an explicit port (":443"); compare host names only,
     * case-insensitively — DNS names are, and browsers are inconsistent about
     * the case they echo back in Origin vs Host. */
    size_t hl = strcspn(host, ":");
    if (strncasecmp(p, host, hl) != 0) return false;
    char after = p[hl];
    return after == '\0' || after == '/' || after == ':';
}

bool web_cookie_sid(const char *cookie, char *out, size_t sid_len)
{
    out[0] = '\0';
    const char *p = cookie;
    while ((p = strstr(p, "sid=")) != NULL) {
        /* must be at start or after "; " so `xsid=` can't match */
        if (p == cookie || p[-1] == ' ' || p[-1] == ';') {
            p += 4;
            size_t l = 0;
            while (p[l] && p[l] != ';' && l < sid_len) l++;
            /* Exactly sid_len chars, then end or ';'. The pre-fuzzing version
             * stopped counting at sid_len and accepted whatever followed, so
             * "sid=<64 hex>junk" passed as the 64-hex prefix — harmless (the
             * prefix still has to match a live session) but not the "exactly"
             * this function promises; tests/fuzz/fuzz_web_parse.c asserts it. */
            if (l == sid_len && (p[l] == '\0' || p[l] == ';')) {
                memcpy(out, p, l); out[l] = '\0'; return true;
            }
            return false;
        }
        p += 4;
    }
    return false;
}
