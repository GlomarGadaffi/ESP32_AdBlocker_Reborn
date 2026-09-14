/*
 * Host tests for main/web_parse.c — the web UI's pre-authentication request
 * parsers, moved out of web_ui.cpp so they compile (and fuzz) on the host.
 *
 * Build + run:
 *   gcc -O2 -fsanitize=address,undefined -I main -o web_parse_test \
 *       tests/web_parse_test.c main/web_parse.c && ./web_parse_test
 */
#include "web_parse.h"
#include <stdio.h>
#include <string.h>

static int g_fail = 0;
#define CHECK(cond, ...) do { if (!(cond)) { \
    printf("  FAIL: "); printf(__VA_ARGS__); printf("\n"); g_fail++; } } while (0)

static void test_form(void)
{
    printf("form_field / url_decode\n");
    char v[32];
    CHECK(web_form_field("user=admin&pass=I+like+tacos%21", "pass", v, sizeof v) && !strcmp(v, "I like tacos!"), "decode + and %%21: '%s'", v);
    CHECK(!web_form_field("xpass=no", "pass", v, sizeof v) && v[0] == '\0', "prefix key must not match");
    CHECK(web_form_field("xpass=no&pass=", "pass", v, sizeof v) && v[0] == '\0', "present-but-empty is found");
    CHECK(!web_form_field("pass", "pass", v, sizeof v), "key without '=' is absent");
    CHECK(web_form_field("v=abc\r\ndef", "v", v, sizeof v) && !strcmp(v, "abc"), "value stops at CR/LF");
    CHECK(web_form_field("x=%4", "x", v, sizeof v) && !strcmp(v, "%4"), "short escape kept literally");
    CHECK(web_form_field("x=%zz", "x", v, sizeof v) && !strcmp(v, "%zz"), "bad hex kept literally");
    char tiny[4];
    CHECK(web_form_field("x=abcdefgh", "x", tiny, sizeof tiny) && !strcmp(tiny, "abc"), "truncates to cap-1");
}

static void test_origin(void)
{
    printf("origin_host_matches\n");
    CHECK(web_origin_host_matches("https://192.168.12.195/login", "192.168.12.195"), "exact with path");
    CHECK(web_origin_host_matches("https://esp32adblock.local:443", "esp32adblock.local:443"), "port on both");
    CHECK(web_origin_host_matches("HTTPS://ESP32ADBLOCK.LOCAL", "esp32adblock.local"), "case-insensitive");
    CHECK(!web_origin_host_matches("https://192.168.12.195.evil.com/", "192.168.12.195"), "host as prefix of evil host");
    CHECK(!web_origin_host_matches("https://evil.com/192.168.12.195", "192.168.12.195"), "host in path");
    CHECK(!web_origin_host_matches("null", "192.168.12.195"), "Origin: null");
    CHECK(!web_origin_host_matches("https://a", ""), "empty Host never matches");
}

static void test_cookie(void)
{
    printf("cookie_sid\n");
    char tok[9];
    CHECK(web_cookie_sid("sid=abcdefgh", tok, 8) && !strcmp(tok, "abcdefgh"), "alone");
    CHECK(web_cookie_sid("theme=dark; xsid=zzz; sid=abcdefgh; o=1", tok, 8) && !strcmp(tok, "abcdefgh"), "after xsid");
    CHECK(!web_cookie_sid("xsid=abcdefgh", tok, 8) && tok[0] == '\0', "xsid alone is not sid");
    CHECK(!web_cookie_sid("sid=abc; sid=abcdefgh", tok, 8), "first well-placed sid= wins even if short");
    CHECK(!web_cookie_sid("sid=abcdefghXYZ", tok, 8), "over-long value rejected (was truncated pre-fuzz)");
    CHECK(web_cookie_sid("sid=abcdefgh;junk", tok, 8) && !strcmp(tok, "abcdefgh"), "terminated by ';'");
}

static void test_html(void)
{
    printf("html_escape\n");
    char out[64];
    web_html_escape(out, sizeof out, "<a href='x'>&\"</a>");
    CHECK(!strcmp(out, "&lt;a href=&#39;x&#39;&gt;&amp;&quot;&lt;/a&gt;"), "all five escaped: '%s'", out);
    char tight[6];
    web_html_escape(tight, sizeof tight, "a<b");
    CHECK(!strcmp(tight, "a&lt;"), "entity that fits: '%s'", tight);
    web_html_escape(tight, sizeof tight, "ab<b");
    CHECK(!strcmp(tight, "ab"), "entity that does not fit is dropped whole: '%s'", tight);
}

int main(void)
{
    test_form(); test_origin(); test_cookie(); test_html();
    if (g_fail) { printf("%d FAILURE(S)\n", g_fail); return 1; }
    printf("all web_parse tests passed\n");
    return 0;
}
