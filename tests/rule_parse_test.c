/*
 * Host tests for the AdGuard rule-grammar subset (#117): main/domain.c's
 * rule_parse_next() and rule_apply_feed_policy().
 *
 * Build + run:
 *   gcc -O2 -I main -o rule_parse_test tests/rule_parse_test.c main/domain.c && ./rule_parse_test
 *
 * Every row is transcribed from issue #117's "Grammar subset to support"
 * table and its rule_parse_test.c test-table section, plus a handful of
 * boundary cases the issue's prose calls out but doesn't table (dup/empty
 * modifiers, bracketed-IPv6-with-port, a hosts line with $, a too-long
 * token) that the parser has to get right for the table's claims to hold.
 */
#include "domain.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

static int g_fail = 0;
#define CHECK(cond, ...) do { if (!(cond)) { \
    printf("  FAIL: "); printf(__VA_ARGS__); printf("\n"); g_fail++; } } while (0)

/* Test convenience only: real callers pass an already-isolated line/len,
 * never a NUL-terminated C string. */
static bool parse_one(const char *line, rule_t *out)
{
    size_t cursor = 0;
    return rule_parse_next(line, strlen(line), &cursor, out);
}

static void expect_skip(const char *line, const char *label)
{
    rule_t r;
    bool got = parse_one(line, &r);
    CHECK(!got, "%s ('%s'): expected no rule (blank/comment), got one (kind=%d)", label, line, r.kind);
}

static void expect_reject(const char *line, uint8_t reason, const char *label)
{
    rule_t r;
    bool got = parse_one(line, &r);
    CHECK(got, "%s ('%s'): expected a REJECT result, got none", label, line);
    if (!got) return;
    CHECK(r.kind == RULE_REJECT, "%s ('%s'): expected REJECT, got kind=%d", label, line, r.kind);
    CHECK(r.reject_reason == reason,
          "%s ('%s'): expected reject_reason=%d, got %d", label, line, reason, r.reject_reason);
}

static void expect_rule(const char *line, uint8_t kind, const char *tok, uint8_t flags, const char *label)
{
    rule_t r;
    bool got = parse_one(line, &r);
    CHECK(got, "%s ('%s'): expected a rule, got none", label, line);
    if (!got) return;
    CHECK(r.kind == kind, "%s ('%s'): expected kind=%d, got %d", label, line, kind, r.kind);
    CHECK(r.len == strlen(tok) && memcmp(r.tok, tok, r.len) == 0,
          "%s ('%s'): expected tok='%s', got '%.*s'", label, line, tok, (int)r.len, r.tok ? r.tok : "");
    CHECK(r.flags == flags, "%s ('%s'): expected flags=0x%x, got 0x%x", label, line, flags, r.flags);
}

/* A whole line reject/skip must be a single result, then exhausted. */
static void expect_terminal(const char *line, const char *label)
{
    size_t cursor = 0;
    rule_t r;
    (void)rule_parse_next(line, strlen(line), &cursor, &r);
    rule_t r2;
    bool got2 = rule_parse_next(line, strlen(line), &cursor, &r2);
    CHECK(!got2, "%s ('%s'): expected exactly one result, got a second", label, line);
}

/* ── 1. grammar subset table ─────────────────────────────────────── */
static void test_grammar(void)
{
    printf("grammar subset\n");

    expect_rule("||example.com^", RULE_BLOCK, "example.com", 0, "double-pipe anchor");
    expect_rule("|example.com^", RULE_BLOCK, "example.com", RULE_EXACT, "single-pipe anchor");
    expect_rule("example.com", RULE_BLOCK, "example.com", 0, "bare domain (documented divergence: sub)");
    expect_rule("@@||example.com^", RULE_ALLOW, "example.com", 0, "exception, sub");
    expect_rule("@@example.com", RULE_ALLOW, "example.com", RULE_EXACT, "bare exception (deliberately exact)");

    expect_rule("||example.com^$important", RULE_BLOCK, "example.com", RULE_IMPORTANT,
                "$important on a block (source-agnostic; feed policy is separate)");
    expect_rule("@@||example.com^$important", RULE_ALLOW, "example.com", RULE_IMPORTANT,
                "$important on an exception");

    expect_reject("||example.com^$dnstype=A", RULE_REJECT_MODIFIER, "unsupported modifier (phase 2)");
    expect_reject("/ads[0-9]+\\.com/", RULE_REJECT_REGEX, "bare regex pattern");
    expect_reject("||ex*.com^", RULE_REJECT_WILDCARD, "mid-pattern wildcard");
    expect_reject("||ex^", RULE_REJECT_TOO_WIDE, "pattern under 3 chars");
    expect_rule("||example.com:443^", RULE_BLOCK, "example.com", 0, "port stripped");
    expect_rule("http://example.com/", RULE_BLOCK, "example.com", 0, "scheme + trailing slash stripped");

    expect_skip("!a plain comment", "'!' comment");
    expect_skip("# a plain comment", "'#' comment");
    expect_reject("##cosmetic", RULE_REJECT_COSMETIC, "bare cosmetic marker");
    expect_reject("example.com##.ad-banner", RULE_REJECT_COSMETIC, "domain-scoped cosmetic rule");
}

/* ── 2. hosts format, including the regression this issue fixes ──── */
static void test_hosts_format(void)
{
    printf("hosts format\n");
    expect_rule("0.0.0.0 example.com", RULE_BLOCK, "example.com", 0, "single hosts entry");

    /* the regression: today only the first trailing token survives */
    {
        const char *line = "0.0.0.0 a.com b.com";
        size_t cursor = 0;
        rule_t r1, r2, r3;
        bool g1 = rule_parse_next(line, strlen(line), &cursor, &r1);
        bool g2 = rule_parse_next(line, strlen(line), &cursor, &r2);
        bool g3 = rule_parse_next(line, strlen(line), &cursor, &r3);
        CHECK(g1 && r1.kind == RULE_BLOCK && r1.len == 5 && memcmp(r1.tok, "a.com", 5) == 0,
              "hosts multi-token: first rule wrong");
        CHECK(g2 && r2.kind == RULE_BLOCK && r2.len == 5 && memcmp(r2.tok, "b.com", 5) == 0,
              "hosts multi-token: second rule wrong");
        CHECK(!g3, "hosts multi-token: expected exactly two rules, got a third");
    }

    /* AdGuard hosts syntax has no modifiers at all — reject, don't ignore */
    expect_reject("0.0.0.0 a.com$important", RULE_REJECT_MODIFIER, "hosts line with a modifier");

    /* a bare address with nothing after it isn't hosts format (no trailing
     * token to be the domain) — falls through to the plain-token path and
     * is correctly counted as CIDR rather than silently dropped, unlike
     * domain_extract_token's silent 0 for this case today. */
    expect_reject("0.0.0.0", RULE_REJECT_CIDR, "bare address, no trailing token");
}

/* ── 3. IP / CIDR patterns — we filter names, not answers ─────────── */
static void test_cidr(void)
{
    printf("CIDR / address patterns\n");
    expect_reject("192.168.1.1", RULE_REJECT_CIDR, "bare IPv4, no trailing token (not hosts format)");
    expect_reject("||192.168.1.1^", RULE_REJECT_CIDR, "anchored IPv4");
    expect_reject("[::1]:53", RULE_REJECT_CIDR, "bracketed IPv6 with port, port strip exposes the address");
}

/* ── 4. modifier list edge cases ──────────────────────────────────── */
static void test_modifiers(void)
{
    printf("modifier list edge cases\n");
    expect_reject("||x^$", RULE_REJECT_MODIFIER, "empty modifier list");
    expect_reject("||example.com^$important,important", RULE_REJECT_MODIFIER, "duplicate modifier");
    expect_reject("||example.com^$important,dnstype=A", RULE_REJECT_MODIFIER, "important plus an unsupported modifier");
    expect_reject("||example.com^$badfilter", RULE_REJECT_MODIFIER, "$badfilter (out of scope, counted as modifier)");
    expect_reject("||example.com^$denyallow=x.com", RULE_REJECT_MODIFIER, "$denyallow (out of scope)");
}

/* ── 5. malformed / boundary tokens ───────────────────────────────── */
static void test_malformed(void)
{
    printf("malformed tokens\n");
    expect_reject("example.com/ads", RULE_REJECT_MALFORMED, "mid-token slash, not a regex");
    expect_reject("exa mple!com", RULE_REJECT_MALFORMED, "invalid character in token");

    {
        char line[300];
        memset(line, 'a', sizeof(line) - 1);
        line[sizeof(line) - 1] = '\0';
        expect_reject(line, RULE_REJECT_MALFORMED, "token over 253 chars");
    }
}

/* ── 6. exactly one result per whole-line outcome ─────────────────── */
static void test_terminal(void)
{
    printf("terminal (single-shot) results are exhausted after one call\n");
    expect_terminal("||example.com^", "block rule");
    expect_terminal("@@example.com", "allow rule");
    expect_terminal("||example.com^$dnstype=A", "modifier reject");
    expect_terminal("##cosmetic", "cosmetic reject");
    expect_terminal("!comment", "comment skip");
    expect_terminal("192.168.1.1", "CIDR reject");
}

/* ── 7b. real $important lines, transcribed from the AdGuard DNS filter
 * census (#117 stage d): all 5 hits across the four configured feeds came
 * from this one feed, and two of the five have no '^' terminator before
 * '$' — a plain "||domain$modifier" without an anchor-close, which the
 * grammar table's synthetic rows never exercise. ─────────────────────── */
static void test_real_important_fixtures(void)
{
    printf("real $important fixtures from the feed census\n");
    expect_rule("||adsrvmedia.adk2.co^$important", RULE_BLOCK, "adsrvmedia.adk2.co", RULE_IMPORTANT, "adguard filter line 960");
    expect_rule("||deloton.com$important", RULE_BLOCK, "deloton.com", RULE_IMPORTANT, "adguard filter line 57831 (no '^')");
    expect_rule("||oclasrv.com$important", RULE_BLOCK, "oclasrv.com", RULE_IMPORTANT, "adguard filter line 57833 (no '^')");
    expect_rule("||pixel.wp.pl^$important", RULE_BLOCK, "pixel.wp.pl", RULE_IMPORTANT, "adguard filter line 159024");
    expect_rule("||bet.championat.com^$important", RULE_BLOCK, "bet.championat.com", RULE_IMPORTANT, "adguard filter line 167248");
}

/* ── 7. FEED-only $important policy (rule_apply_feed_policy) ──────── */
static void test_feed_policy(void)
{
    printf("FEED-only $important policy\n");

    /* the two-row pair from the issue: same line, different verdict
     * depending on which caller applies feed policy afterward */
    rule_t r;
    bool got = parse_one("||example.com^$important", &r);
    CHECK(got && r.kind == RULE_BLOCK && (r.flags & RULE_IMPORTANT),
          "raw parse of a $important block should not itself reject it");
    rule_apply_feed_policy(&r);
    CHECK(r.kind == RULE_REJECT && r.reject_reason == RULE_REJECT_IMPORTANT_BLOCK_UNSUPPORTED,
          "FEED policy must downgrade an important BLOCK to REJECT/IMPORTANT_BLOCK_UNSUPPORTED");

    /* an exception is untouched by feed policy — it has somewhere to store
     * the flag (the exception table carries a flag byte) */
    bool got2 = parse_one("@@||example.com^$important", &r);
    CHECK(got2 && r.kind == RULE_ALLOW && (r.flags & RULE_IMPORTANT), "sanity: parsed as ALLOW+IMPORTANT");
    rule_apply_feed_policy(&r);
    CHECK(r.kind == RULE_ALLOW && (r.flags & RULE_IMPORTANT),
          "FEED policy must not touch an exception rule");

    /* a plain block with no $important is untouched */
    bool got3 = parse_one("||example.com^", &r);
    CHECK(got3 && r.kind == RULE_BLOCK && !(r.flags & RULE_IMPORTANT), "sanity: parsed as plain BLOCK");
    rule_apply_feed_policy(&r);
    CHECK(r.kind == RULE_BLOCK, "FEED policy must not touch a plain block");
}

int main(void)
{
    printf("rule_parse host tests\n\n");
    test_grammar();
    test_hosts_format();
    test_cidr();
    test_modifiers();
    test_malformed();
    test_terminal();
    test_real_important_fixtures();
    test_feed_policy();
    printf("\n%s (%d failure%s)\n", g_fail ? "FAILED" : "PASSED", g_fail, g_fail == 1 ? "" : "s");
    return g_fail != 0;
}
