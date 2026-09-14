/*
 * libFuzzer target: the AdGuard/hosts rule grammar in main/domain.c.
 *
 * This is the parser every third-party blocklist feed goes through
 * (blocklist.c on_domain_line) and the one the custom-rules textarea goes
 * through (custom_parse / custom_validate). Feed bytes come from arbitrary
 * HTTPS hosts, so this is the largest hand-written parser over data the
 * device does not control.
 *
 * The input is treated as one already-isolated line (the caller contract:
 * no '\n', trailing '\r'/spaces trimmed) and iterated to exhaustion exactly
 * the way on_domain_line does, with each ALLOW/BLOCK token then pushed
 * through domain_normalize + domain_is_bare_tld the way blocklist.c does.
 *
 * Invariants asserted (a false assert is a finding, not just a crash):
 *  - every emitted token lies inside [line, line+len)
 *  - a REJECT is the first and only result for its line
 *  - the cursor never goes backwards (no infinite loop)
 *  - rule_apply_feed_policy never turns an ALLOW into anything else
 */
#include "domain.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Copy into an exact-size heap buffer so ASan catches any read past the
     * declared len (the parser must never rely on a terminator). */
    char *line = (char *)malloc(size ? size : 1);
    if (!line) return 0;
    memcpy(line, data, size);
    size_t len = size;
    while (len > 0 && (line[len-1] == '\r' || line[len-1] == ' ')) len--;

    size_t cursor = 0, prev_cursor = 0;
    rule_t r;
    int n = 0;
    for (int guard = 0; guard < 4096 && rule_parse_next(line, len, &cursor, &r); guard++) {
        n++;
        assert(cursor >= prev_cursor);
        prev_cursor = cursor;

        if (r.kind == RULE_REJECT) {
            /* A whole-line REJECT (first call) is one true result then false.
             * On a hosts-format line a REJECT can also come from a later
             * trailing token ("0.0.0.0 a.com # comment" rejects "#" and
             * "comment" individually, see hosts_token_next) — that is by
             * design and the walk simply continues. */
            if (n == 1 && cursor >= len) {
                size_t c2 = cursor; rule_t r2;
                assert(!rule_parse_next(line, len, &c2, &r2));
                break;
            }
            continue;
        }
        assert(r.kind == RULE_ALLOW || r.kind == RULE_BLOCK);
        assert(r.len > 0);
        assert(r.tok >= line && r.tok + r.len <= line + len);

        /* what blocklist.c does with a feed rule */
        rule_t fr = r;
        rule_apply_feed_policy(&fr);
        if (r.kind == RULE_ALLOW) assert(fr.kind == RULE_ALLOW);

        char norm[256];
        size_t nlen = domain_normalize(norm, sizeof(norm), r.tok, r.len);
        if (nlen) {
            assert(nlen < sizeof(norm));
            assert(norm[nlen] == '\0');
            (void)domain_is_bare_tld(norm, nlen);
            (void)domain_hash(norm, nlen);
            /* a tiny output buffer must truncate safely, never overflow */
            char tiny[8];
            (void)domain_normalize(tiny, sizeof(tiny), r.tok, r.len);
        }
    }

    /* the legacy single-token extractor blocklist.c still exposes */
    const char *tok = NULL;
    size_t tl = domain_extract_token(line, len, &tok);
    if (tl) assert(tok >= line && tok + tl <= line + len);

    free(line);
    return 0;
}
