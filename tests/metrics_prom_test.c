/*
 * Host tests for main/metrics_prom.c — the /metrics JSON to Prometheus text
 * converter behind GET /metrics/prom.
 *
 * Build + run:
 *   gcc -O2 -fsanitize=address,undefined -I main -o metrics_prom_test \
 *       tests/metrics_prom_test.c main/metrics_prom.c && ./metrics_prom_test
 */
#include "metrics_prom.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail = 0;
#define CHECK(cond, ...) do { if (!(cond)) { \
    printf("  FAIL: "); printf(__VA_ARGS__); printf("\n"); g_fail++; } } while (0)

/* Run the converter on an exact-size heap copy of the JSON (no NUL, so a
 * one-byte over-read is an ASan report) into an exact-size output buffer.
 * Returns the status; on success the text is left in `got`. */
static int run(const char *json, size_t out_cap, char *got, size_t got_sz, size_t *olen)
{
    size_t jl = strlen(json);
    char *j = (char *)malloc(jl ? jl : 1);
    memcpy(j, json, jl);
    char *out = (char *)malloc(out_cap ? out_cap : 1);
    *olen = 12345;
    int rc = metrics_json_to_prom(j, jl, out, out_cap, olen);
    size_t n = out_cap < got_sz - 1 ? out_cap : got_sz - 1;
    memcpy(got, out, n);
    got[n] = '\0';
    free(j);
    free(out);
    return rc;
}

static void expect_ok(const char *json, const char *want)
{
    char got[4096]; size_t n;
    int rc = run(json, sizeof got, got, sizeof got, &n);
    CHECK(rc == METRICS_PROM_OK, "rc=%d for %s", rc, json);
    CHECK(n == strlen(want), "len %zu != %zu for %s", n, strlen(want), json);
    CHECK(!strcmp(got, want), "output mismatch for %s\n--- got\n%s--- want\n%s", json, got, want);
}

static void expect_err(const char *json, int want_rc)
{
    char got[4096]; size_t n;
    int rc = run(json, sizeof got, got, sizeof got, &n);
    CHECK(rc == want_rc, "rc=%d want %d for '%s'", rc, want_rc, json);
    CHECK(n == 0, "out_len %zu on error for '%s'", n, json);
}

static void test_basic(void)
{
    printf("basic\n");
    expect_ok("{\"a\":1,\"b\":{\"c\":2.5,\"d\":true}}",
              "adblock_a 1\nadblock_b_c 2.5\nadblock_b_d 1\n");
    expect_ok("{\"x\":false}", "adblock_x 0\n");
    expect_ok("{}", "");
    expect_ok("  {\n\"a\" : 1 ,\t\"b\":2 }\n ", "adblock_a 1\nadblock_b 2\n");
    expect_ok("{\"n\":-3,\"e\":1.5e+3,\"f\":-0.5E-2,\"z\":0,\"big\":4294967295}",
              "adblock_n -3\nadblock_e 1.5e+3\nadblock_f -0.5E-2\nadblock_z 0\nadblock_big 4294967295\n");
    expect_ok("{\"a-b.c\":1}", "adblock_a_b_c 1\n");
    /* Strings (not identity ones) and null are skipped, not errors. */
    expect_ok("{\"sd_status\":\"loaded\",\"n\":null,\"k\":7}", "adblock_k 7\n");
    expect_ok("{\"a\":{\"b\":{\"c\":{\"d\":1}}}}", "adblock_a_b_c_d 1\n");
}

static void test_arrays(void)
{
    printf("arrays\n");
    expect_ok("{\"h\":[1,2]}", "adblock_h{idx=\"0\"} 1\nadblock_h{idx=\"1\"} 2\n");
    expect_ok("{\"h\":[]}", "");
    expect_ok("{\"o\":{\"h\":[0.5,true]}}", "adblock_o_h{idx=\"0\"} 0.5\nadblock_o_h{idx=\"1\"} 1\n");
    /* Arrays of objects/strings (pause_list) are skipped, but still validated. */
    expect_ok("{\"pause_list\":[{\"ip\":\"1.2.3.4\",\"remaining_s\":9}],\"k\":1}", "adblock_k 1\n");
    expect_ok("{\"s\":[\"a\",null,3],\"k\":1}", "adblock_s{idx=\"2\"} 3\nadblock_k 1\n");
    expect_err("{\"pause_list\":[{\"ip\":}]}", METRICS_PROM_ERR_PARSE);
}

static void test_info(void)
{
    printf("info labels\n");
    /* decoded value is  a"b<LF>c\d  ; the label escapes all three */
    expect_ok("{\"upstream\":\"a\\\"b\\nc\\\\d\",\"x\":1}",
              "adblock_x 1\nadblock_info{upstream=\"a\\\"b\\nc\\\\d\"} 1\n");
    /* fixed label order, regardless of JSON order; other strings stay out */
    expect_ok("{\"clock_src\":\"rtc\",\"clock\":\"synced\",\"board\":\"w5500\",\"version\":\"1.2\",\"upstream\":\"10.0.0.1\"}",
              "adblock_info{version=\"1.2\",board=\"w5500\",upstream=\"10.0.0.1\",clock_src=\"rtc\"} 1\n");
    /* an identity key nested deeper is an ordinary (skipped) string */
    expect_ok("{\"o\":{\"version\":\"9\"},\"k\":1}", "adblock_k 1\n");
    /* \u escape: ASCII decodes, anything else becomes '?' */
    expect_ok("{\"board\":\"\\u0041\\u00e9\"}", "adblock_info{board=\"A?\"} 1\n");
}

static void test_errors(void)
{
    printf("errors\n");
    /* depth 5 */
    expect_err("{\"a\":{\"b\":{\"c\":{\"d\":{\"e\":1}}}}}", METRICS_PROM_ERR_DEPTH);
    expect_err("{\"a\":[[[[1]]]]}", METRICS_PROM_ERR_DEPTH);
    /* truncated / malformed */
    expect_err("{\"a\":", METRICS_PROM_ERR_PARSE);
    expect_err("{\"a\"", METRICS_PROM_ERR_PARSE);
    expect_err("{", METRICS_PROM_ERR_PARSE);
    expect_err("", METRICS_PROM_ERR_PARSE);
    expect_err("[1]", METRICS_PROM_ERR_PARSE);
    expect_err("1", METRICS_PROM_ERR_PARSE);
    expect_err("{\"a\":}", METRICS_PROM_ERR_PARSE);
    expect_err("{\"a\":1,}", METRICS_PROM_ERR_PARSE);
    expect_err("{\"a\" 1}", METRICS_PROM_ERR_PARSE);
    expect_err("{\"a\":1}x", METRICS_PROM_ERR_PARSE);
    expect_err("{\"a\":1}{", METRICS_PROM_ERR_PARSE);
    expect_err("{\"a\":01}", METRICS_PROM_ERR_PARSE);
    expect_err("{\"a\":1e}", METRICS_PROM_ERR_PARSE);
    expect_err("{\"a\":-}", METRICS_PROM_ERR_PARSE);
    expect_err("{\"a\":1.}", METRICS_PROM_ERR_PARSE);
    expect_err("{\"a\":tru}", METRICS_PROM_ERR_PARSE);
    expect_err("{\"a\":truex}", METRICS_PROM_ERR_PARSE);
    expect_err("{\"a\":\"x}", METRICS_PROM_ERR_PARSE);
    expect_err("{\"a\":\"x\\q\"}", METRICS_PROM_ERR_PARSE);
    expect_err("{\"a\":\"x\\u12\"}", METRICS_PROM_ERR_PARSE);
    expect_err("{\"a\":\"x\ny\"}", METRICS_PROM_ERR_PARSE);
    expect_err("{\"a\":[1 2]}", METRICS_PROM_ERR_PARSE);
    expect_err("{\"a\":[1,]}", METRICS_PROM_ERR_PARSE);
    expect_err("{\"a\":{]}", METRICS_PROM_ERR_PARSE);
    expect_err("{1:2}", METRICS_PROM_ERR_PARSE);
    /* a key too long for the name buffer is refused, not truncated */
    {
        char big[400];
        strcpy(big, "{\"");
        memset(big + 2, 'k', 300);
        strcpy(big + 302, "\":1}");
        expect_err(big, METRICS_PROM_ERR_PARSE);
    }
}

static void test_capacity(void)
{
    printf("capacity\n");
    const char *json = "{\"a\":1,\"b\":{\"c\":2.5}}";
    const char *want = "adblock_a 1\nadblock_b_c 2.5\n";
    size_t need = strlen(want) + 1;   /* text plus the terminator */
    char got[256]; size_t n;
    int rc = run(json, need, got, sizeof got, &n);
    CHECK(rc == METRICS_PROM_OK && n == strlen(want) && !strcmp(got, want), "exact fit rc=%d n=%zu", rc, n);
    for (size_t cap = 0; cap < need; cap++) {
        rc = run(json, cap, got, sizeof got, &n);
        CHECK(rc == METRICS_PROM_ERR_FULL, "cap %zu rc=%d", cap, rc);
        CHECK(n == 0, "cap %zu out_len=%zu", cap, n);
        if (cap > 0) CHECK(got[0] == '\0', "cap %zu: out not emptied", cap);
    }
    /* the info line is all-or-nothing as well */
    const char *ij = "{\"upstream\":\"1.2.3.4\"}";
    const char *iw = "adblock_info{upstream=\"1.2.3.4\"} 1\n";
    rc = run(ij, strlen(iw) + 1, got, sizeof got, &n);
    CHECK(rc == METRICS_PROM_OK && !strcmp(got, iw), "info exact fit rc=%d", rc);
    rc = run(ij, strlen(iw), got, sizeof got, &n);
    CHECK(rc == METRICS_PROM_ERR_FULL && n == 0, "info one short rc=%d n=%zu", rc, n);
    /* bad arguments */
    char out[8]; size_t l = 9;
    CHECK(metrics_json_to_prom(NULL, 2, out, sizeof out, &l) == METRICS_PROM_ERR_ARG, "null json");
    CHECK(metrics_json_to_prom("{}", 2, NULL, 8, &l) == METRICS_PROM_ERR_ARG, "null out");
    CHECK(metrics_json_to_prom("{}", 2, out, sizeof out, NULL) == METRICS_PROM_ERR_ARG, "null out_len");
}

/* The key set dns_server_metrics_json() really emits (main/dns_server.cpp),
 * with a 2-entry pause_list. */
static const char *REAL =
    "{\"upstream\":\"192.168.1.1\",\"upstream2\":\"\","
    "\"clock\":\"synced\",\"clock_src\":\"rtc\",\"clock_epoch\":1767225600,"
    "\"uptime_s\":86400,"
    "\"queries_total\":1000,\"blocked\":300,\"forwarded\":600,\"tcp_queries\":2,"
    "\"l2_blocked\":10,\"l2_cached\":20,\"l2_tx_fail\":0,"
    "\"l2_fallthrough\":5,\"l2_dns_fallthrough\":4,\"wd_restarts\":0,"
    "\"select_errors\":0,\"dns_task_alive\":true,"
    "\"l2_defer_lock_busy\":0,\"l2_defer_snapshot\":0,\"l2_log_dropped\":0,"
    "\"census_dropped\":0,\"case_mismatch\":0,"
    "\"cache_probes\":500,\"cache_hits\":250,\"cache_hit_rate\":50.0,"
    "\"cache_evictions\":1,\"cache_too_big\":0,\"stale_served\":0,\"coalesced\":3,"
    "\"hedges_sent\":4,\"hedged_completions\":2,"
    "\"up_rotations\":3,\"up_rotate_failures\":1,"
    "\"dropped\":{\"table_full\":0,\"mbox_pressure\":0},"
    "\"upstream_timeouts\":1,\"upstream_inflight\":2,\"upstream_max\":64,"
    "\"blocklist_count\":150000,\"blocklist_loading\":false,\"blocklist_paused\":false,"
    "\"pause_active\":2,\"bypass_count\":0,\"blocklist_dropped\":0,\"blocklist_feed_failures\":0,"
    "\"rejected\":{\"regex\":1,\"wildcard\":2,\"modifier\":3,\"cosmetic\":4,\"cidr\":5,"
    "\"too_wide\":6,\"important_block\":7},"
    "\"exceptions_loaded\":8,\"exceptions_dropped\":0,"
    "\"sd_status\":\"open-failed\",\"sd_bytes\":0,\"flash_status\":\"loaded\","
    "\"heap_free\":40000,\"heap_largest\":20000,\"psram_free\":7000000,\"dns_task_stack_hwm\":3000,"
    "\"latency_us\":{\"blocked\":{\"p50\":10,\"p99\":20,\"max\":30,\"count\":300},"
    "\"cached\":{\"p50\":1,\"p99\":2,\"max\":3,\"count\":4},"
    "\"forwarded_total\":{\"p50\":1,\"p99\":2,\"max\":3,\"count\":4},"
    "\"forwarded_ourovh\":{\"p50\":1,\"p99\":2,\"max\":3,\"count\":4},"
    "\"forwarded_rtt\":{\"p50\":1,\"p99\":2,\"max\":3,\"count\":4},"
    "\"lookup\":{\"p50\":1,\"p99\":2,\"max\":3,\"count\":4},"
    "\"sendto\":{\"p50\":1,\"p99\":2,\"max\":3,\"count\":4}},"
    "\"pause_list\":[{\"ip\":\"all\",\"remaining_s\":60},{\"ip\":\"10.0.0.5\",\"remaining_s\":9}]}";

static void test_real(void)
{
    printf("realistic sample\n");
    static char got[8192]; size_t n;
    int rc = run(REAL, sizeof got, got, sizeof got, &n);
    CHECK(rc == METRICS_PROM_OK, "rc=%d", rc);
    CHECK(strstr(got, "adblock_queries_total 1000\n"), "queries_total");
    CHECK(strstr(got, "adblock_cache_hit_rate 50.0\n"), "cache_hit_rate");
    CHECK(strstr(got, "adblock_dns_task_alive 1\n"), "bool true");
    CHECK(strstr(got, "adblock_blocklist_loading 0\n"), "bool false");
    CHECK(strstr(got, "adblock_dropped_table_full 0\n"), "nested dropped");
    CHECK(strstr(got, "adblock_rejected_important_block 7\n"), "nested rejected");
    CHECK(strstr(got, "adblock_latency_us_blocked_p99 20\n"), "depth-3 latency");
    CHECK(strstr(got, "adblock_latency_us_sendto_count 4\n"), "last latency");
    CHECK(strstr(got, "adblock_psram_free 7000000\n"), "psram");
    CHECK(strstr(got, "adblock_clock_epoch 1767225600\n"), "epoch");
    CHECK(strstr(got, "adblock_info{upstream=\"192.168.1.1\",clock_src=\"rtc\"} 1\n"), "info line");
    CHECK(!strstr(got, "pause_list") && !strstr(got, "sd_status") && !strstr(got, "synced"),
          "skipped fields leaked");
    /* every line is "name[{labels}] value\n" with no blank or partial lines */
    int lines = 0;
    for (const char *p = got; *p; ) {
        const char *e = strchr(p, '\n');
        CHECK(e && e > p, "partial or blank line at offset %ld", (long)(p - got));
        if (!e) break;
        lines++;
        p = e + 1;
    }
    /* 84 numeric/bool leaves counted by hand from REAL (pause_list excluded) + the info line */
    CHECK(lines == 85, "line count %d", lines);
    CHECK(n == strlen(got), "out_len %zu vs strlen %zu", n, strlen(got));
}

static void test_edges(void)
{
    printf("edge cases\n");
    /* number grammar: JSON only */
    expect_err("{\"a\":+1}", METRICS_PROM_ERR_PARSE);
    expect_err("{\"a\":.5}", METRICS_PROM_ERR_PARSE);
    expect_err("{\"a\":NaN}", METRICS_PROM_ERR_PARSE);
    expect_err("{\"a\":Infinity}", METRICS_PROM_ERR_PARSE);
    expect_err("{\"a\":-Infinity}", METRICS_PROM_ERR_PARSE);
    expect_err("{\"a\":1e+}", METRICS_PROM_ERR_PARSE);
    expect_err("{\"a\":-01}", METRICS_PROM_ERR_PARSE);
    /* longest accepted number is 40 chars; 41 is refused */
    {
        char j[160];
        char want[160];
        memset(j, 0, sizeof j);
        strcpy(j, "{\"a\":");
        memset(j + 5, '7', 40);
        strcpy(j + 45, "}");
        snprintf(want, sizeof want, "adblock_a %.40s\n", j + 5);
        expect_ok(j, want);
        memset(j, 0, sizeof j);
        strcpy(j, "{\"a\":");
        memset(j + 5, '7', 41);
        strcpy(j + 46, "}");
        expect_err(j, METRICS_PROM_ERR_PARSE);
        memset(j, 0, sizeof j);
        strcpy(j, "{\"a\":");
        memset(j + 5, '7', 100);   /* no closing brace: ends mid-number */
        expect_err(j, METRICS_PROM_ERR_PARSE);
    }
    /* number running to the very end of the buffer */
    expect_err("{\"a\":12", METRICS_PROM_ERR_PARSE);
    expect_err("{\"a\":1.5e", METRICS_PROM_ERR_PARSE);
    /* strings and escapes */
    expect_ok("{\"a\\\"b\":1}", "adblock_a_b 1\n");
    expect_ok("{\"a\\u0041\":1}", "adblock_aA 1\n");
    expect_ok("{\"a\\u00e9b\":1}", "adblock_a_b 1\n");   /* \u above 0x7F becomes '?', then '_' */
    expect_ok("{\"board\":\"x\\u0000y\"}", "adblock_info{board=\"x?y\"} 1\n");
    expect_ok("{\"board\":\"\\\\\\\"\"}", "adblock_info{board=\"\\\\\\\"\"} 1\n");
    expect_err("{\"a\":\"\\", METRICS_PROM_ERR_PARSE);
    expect_err("{\"a\":\"\\u", METRICS_PROM_ERR_PARSE);
    expect_err("{\"a\":\"\\u00", METRICS_PROM_ERR_PARSE);
    expect_err("{\"a\":\"\\uZZZZ\"}", METRICS_PROM_ERR_PARSE);
    /* an identity string longer than the label buffer is truncated, not refused */
    {
        char j[200];
        char got[512]; size_t n;
        strcpy(j, "{\"board\":\"");
        memset(j + 10, 'b', 120);
        strcpy(j + 130, "\"}");
        int rc = run(j, sizeof got, got, sizeof got, &n);
        CHECK(rc == METRICS_PROM_OK, "long label rc=%d", rc);
        CHECK(n == strlen("adblock_info{board=\"") + 63 + strlen("\"} 1\n"), "long label len %zu", n);
    }
    /* embedded NUL honours json_len: NUL is neither whitespace nor an end marker */
    {
        static const char nul1[] = "{\"a\":1}\0{\"b\":2}";
        char got[128]; size_t n = 7;
        char *j = (char *)malloc(sizeof nul1 - 1);
        memcpy(j, nul1, sizeof nul1 - 1);
        int rc = metrics_json_to_prom(j, sizeof nul1 - 1, got, sizeof got, &n);
        CHECK(rc == METRICS_PROM_ERR_PARSE && n == 0, "NUL then more JSON rc=%d n=%zu", rc, n);
        rc = metrics_json_to_prom(j, 7, got, sizeof got, &n);   /* json_len cut at the NUL */
        CHECK(rc == METRICS_PROM_OK && !strcmp(got, "adblock_a 1\n"), "prefix rc=%d", rc);
        free(j);
        static const char nul2[] = "{\"a\":\"x\0y\"}";
        j = (char *)malloc(sizeof nul2 - 1);
        memcpy(j, nul2, sizeof nul2 - 1);
        rc = metrics_json_to_prom(j, sizeof nul2 - 1, got, sizeof got, &n);
        CHECK(rc == METRICS_PROM_ERR_PARSE && n == 0, "NUL inside string rc=%d", rc);
        free(j);
    }
    /* json_len = 0 with a non-NULL pointer */
    {
        char got[16]; size_t n = 3;
        int rc = metrics_json_to_prom("{}", 0, got, sizeof got, &n);
        CHECK(rc == METRICS_PROM_ERR_PARSE && n == 0, "json_len 0 rc=%d", rc);
    }
    /* duplicate keys and keys that sanitise alike: both emitted, no crash */
    expect_ok("{\"a\":1,\"a\":2}", "adblock_a 1\nadblock_a 2\n");
    expect_ok("{\"a-b\":1,\"a.b\":2}", "adblock_a_b 1\nadblock_a_b 2\n");
    expect_ok("{\"\":1}", "adblock_ 1\n");
    /* whitespace everywhere, nested arrays, empty containers */
    expect_ok(" {\r\n\t\"a\" \t: [ 1 , 2 ] , \"o\" : { } , \"e\" : [ ] } ",
              "adblock_a{idx=\"0\"} 1\nadblock_a{idx=\"1\"} 2\n");
    expect_ok("{\"a\":[[1,2],[3]],\"k\":5}", "adblock_k 5\n");
    expect_ok("{\"a\":[{\"x\":1},{\"x\":2}],\"k\":5}", "adblock_k 5\n");
    /* depth exactly at the limit is fine, one past is refused */
    expect_ok("{\"a\":{\"b\":{\"c\":[1]}}}", "adblock_a_b_c{idx=\"0\"} 1\n");
    expect_err("{\"a\":{\"b\":{\"c\":[[1]]}}}", METRICS_PROM_ERR_DEPTH);
    expect_ok("{\"a\":{\"b\":{\"c\":{}}}}", "");
    expect_err("{\"a\":{\"b\":{\"c\":{}}}}x", METRICS_PROM_ERR_PARSE);
    expect_err("{\"a\":{\"b\":{\"c\":{\"d\":{}}}}}", METRICS_PROM_ERR_DEPTH);
    /* a long array: the index renders in full */
    {
        char j[1600]; size_t p = 0;
        static char got[8192]; size_t n;
        p += (size_t)snprintf(j + p, sizeof j - p, "{\"h\":[");
        for (int i = 0; i < 300; i++) p += (size_t)snprintf(j + p, sizeof j - p, "%s0", i ? "," : "");
        snprintf(j + p, sizeof j - p, "]}");
        int rc = run(j, sizeof got, got, sizeof got, &n);
        CHECK(rc == METRICS_PROM_OK && strstr(got, "adblock_h{idx=\"299\"} 0\n"), "idx 299 rc=%d", rc);
    }
}

/* The worst /metrics document the firmware can produce: every integer at its
 * widest, a full 8-entry pause_list, plus the up_rotations and dns_health keys.
 * web_ui.cpp sizes: JSON buffer 3072 B, text buffer 6144 B. */
static void test_worst_case_size(void)
{
    printf("worst-case size\n");
    char j[3072];
    const char *W = "4294967295";             /* widest uint32 */
    const char *L = "9223372036854775807";    /* widest int64 (clock_epoch, uptime_s) */
    size_t p = 0;
#define A(...) p += (size_t)snprintf(j + p, sizeof j - p, __VA_ARGS__)
    A("{\"upstream\":\"255.255.255.255\",\"upstream2\":\"255.255.255.255\","
      "\"clock\":\"synced\",\"clock_src\":\"floor-no-rtc\",\"clock_epoch\":%s,\"uptime_s\":%s,", L, L);
    const char *u32[] = { "queries_total","blocked","forwarded","tcp_queries","l2_blocked","l2_cached","l2_tx_fail",
        "l2_fallthrough","l2_dns_fallthrough","wd_restarts","select_errors","l2_defer_lock_busy","l2_defer_snapshot",
        "l2_log_dropped","census_dropped","case_mismatch","cache_probes","cache_hits","cache_evictions",
        "cache_too_big","stale_served","coalesced","hedges_sent","hedged_completions","up_rotations",
        "up_rotate_failures","upstream_timeouts","blocklist_count","pause_active","bypass_count","blocklist_dropped",
        "blocklist_feed_failures","exceptions_loaded","exceptions_dropped","sd_bytes","heap_free","heap_largest",
        "psram_free","dns_task_stack_hwm" };
    for (size_t i = 0; i < sizeof u32 / sizeof u32[0]; i++) A("\"%s\":%s,", u32[i], W);
    A("\"dns_task_alive\":false,\"cache_hit_rate\":100.0,\"upstream_inflight\":64,\"upstream_max\":64,"
      "\"blocklist_loading\":false,\"blocklist_paused\":false,");
    A("\"dropped\":{\"table_full\":%s,\"mbox_pressure\":%s},", W, W);
    A("\"rejected\":{\"regex\":%s,\"wildcard\":%s,\"modifier\":%s,\"cosmetic\":%s,\"cidr\":%s,\"too_wide\":%s,"
      "\"important_block\":%s},", W, W, W, W, W, W, W);
    A("\"dns_health\":{\"probe_ok\":%s,\"probe_fail\":%s,\"probe_skipped\":%s,\"last_action\":2},", W, W, W);
    A("\"sd_status\":\"open-failed\",\"flash_status\":\"loaded\",\"latency_us\":{");
    const char *cats[] = { "blocked","cached","forwarded_total","forwarded_ourovh","forwarded_rtt","lookup","sendto" };
    for (size_t i = 0; i < 7; i++)
        A("%s\"%s\":{\"p50\":%s,\"p99\":%s,\"max\":%s,\"count\":%s}", i ? "," : "", cats[i], W, W, W, W);
    A("},\"pause_list\":[");
    for (int i = 0; i < 8; i++) A("%s{\"ip\":\"255.255.255.255\",\"remaining_s\":%s}", i ? "," : "", W);
    A("]}");
#undef A
    CHECK(p < sizeof j, "worst-case JSON %zu overflowed the test buffer", p);
    static char got[16384]; size_t n = 0;
    int rc = run(j, sizeof got, got, sizeof got, &n);
    printf("  worst-case JSON %zu B -> prom text %zu B (rc=%d)\n", p, n, rc);
    CHECK(rc == METRICS_PROM_OK, "worst-case rc=%d", rc);
    /* web_ui.cpp text buffer is 6144 B: require at least 1.5x margin. */
    CHECK(n * 3 <= 6144 * 2, "worst-case text %zu B is too close to the 6144 B buffer", n);
    size_t need = n + 1;
    rc = run(j, need, got, sizeof got, &n);
    CHECK(rc == METRICS_PROM_OK, "exact cap rc=%d", rc);
}

int main(void)
{
    test_basic();
    test_arrays();
    test_info();
    test_errors();
    test_capacity();
    test_real();
    test_edges();
    test_worst_case_size();
    if (g_fail) { printf("%d FAILED\n", g_fail); return 1; }
    printf("all passed\n");
    return 0;
}
