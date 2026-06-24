#include "domain.h"
#include <string.h>
#include <ctype.h>

/* Bare TLDs — single-label names we never block even if a hash collides. */
static const char *const s_bare_tlds[] = {
    "com", "net", "org", "edu", "gov", "mil", "int",
    "io",  "co",  "uk",  "de",  "fr",  "jp",  "cn",
    "ru",  "br",  "au",  "ca",  "in",  "nl",  "it",
    "es",  "pl",  "se",  "no",  "fi",  "dk",  "be",
    "ch",  "at",  "nz",  "za",  "mx",  "ar",  "cl",
    "kr",  "tw",  "sg",  "hk",  "info","biz", "mobi",
    "name","pro", "aero","coop","museum","tel","travel",
    "xxx", "app", "dev", "web", "ai",  NULL
};

size_t domain_normalize(char *buf, size_t buf_size, const char *src, size_t src_len)
{
    if (!src || !buf || buf_size < 2) return 0;

    /* strip trailing dot */
    while (src_len > 0 && src[src_len - 1] == '.') src_len--;
    if (src_len == 0 || src_len >= buf_size) return 0;

    for (size_t i = 0; i < src_len; i++)
        buf[i] = (char)tolower((unsigned char)src[i]);
    buf[src_len] = '\0';
    return src_len;
}

bool domain_is_bare_tld(const char *name, size_t len)
{
    /* A bare TLD has no dot in it */
    for (size_t i = 0; i < len; i++) {
        if (name[i] == '.') return false;
    }
    for (const char *const *t = s_bare_tlds; *t; t++) {
        size_t tlen = strlen(*t);
        if (tlen == len && memcmp(name, *t, len) == 0) return true;
    }
    /* Even if not in our list, a single-label name is treated as a TLD. */
    return true;
}
