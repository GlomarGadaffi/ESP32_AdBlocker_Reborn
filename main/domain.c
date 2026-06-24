#include "domain.h"
#include <string.h>
#include <ctype.h>

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

/* Any single-label name (no dot) is treated as a bare TLD and never blocked. */
bool domain_is_bare_tld(const char *name, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (name[i] == '.') return false;
    }
    return true;
}
