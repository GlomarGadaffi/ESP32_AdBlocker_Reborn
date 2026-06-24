#include "web_ui.h"
#include "blocklist.h"
#include "domain.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <inttypes.h>

static const char *TAG = "web_ui";
static httpd_handle_t  s_server = nullptr;
static DnsSinkServer  *s_dns    = nullptr;

extern "C" void dns_sink_trigger_reload(void);

/* ── helpers ─────────────────────────────────────────────────────── */

/* Escape HTML special chars: <>&"' → entities. Safe for both text and attrs. */
static void html_escape(char *dst, size_t cap, const char *src)
{
    size_t d = 0;
    for (size_t i = 0; src[i] && d + 1 < cap; i++) {
        const char *ent = nullptr;
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

/* URL-decode a form-encoded value (%-hex and + as space). dst is NUL-terminated. */
static void url_decode(char *dst, size_t cap, const char *src, size_t src_len)
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

/* Check Origin/Referer header against Host on POST handlers to block CSRF.
 * Returns true when the request looks same-origin (or has no Origin/Referer). */
static bool csrf_ok(httpd_req_t *r)
{
    char host[64] = {}, origin[128] = {}, referer[128] = {};
    httpd_req_get_hdr_value_str(r, "Host",    host,    sizeof(host));
    httpd_req_get_hdr_value_str(r, "Origin",  origin,  sizeof(origin));
    httpd_req_get_hdr_value_str(r, "Referer", referer, sizeof(referer));

    /* If Origin is present it must contain our host. */
    if (origin[0] != '\0') return (strstr(origin,  host) != nullptr);
    /* If Referer is present it must contain our host. */
    if (referer[0] != '\0') return (strstr(referer, host) != nullptr);
    /* Neither header present — allow (same-origin form with no JS). */
    return true;
}

static void send_html(httpd_req_t *r, const char *body)
{
    httpd_resp_set_type(r, "text/html; charset=utf-8");
    httpd_resp_set_hdr(r, "Cache-Control", "no-store");
    httpd_resp_send(r, body, HTTPD_RESP_USE_STRLEN);
}

/* ── GET / — status page ─────────────────────────────────────────── */
static esp_err_t handle_status(httpd_req_t *r)
{
    uint32_t total   = s_dns ? (uint32_t)s_dns->queries_total()   : 0;
    uint32_t blocked = s_dns ? (uint32_t)s_dns->queries_blocked() : 0;
    uint32_t domains = blocklist_domain_count();
    bool     loading = blocklist_is_loading();
    uint32_t wl_n    = blocklist_whitelist_count();

    static char page[8192];  /* static: avoids stack overflow in httpd task */
    int  n = 0;
    n += snprintf(page + n, sizeof(page) - n,
        "<!DOCTYPE html><html><head><meta charset=utf-8>"
        "<title>DNS Sinkhole</title>"
        "<meta http-equiv='refresh' content='10'>"
        "<style>body{font-family:monospace;max-width:600px;margin:2em auto;}"
        "table{border-collapse:collapse;width:100%%}"
        "td,th{border:1px solid #ccc;padding:.4em .8em;text-align:left}"
        "th{background:#222;color:#eee}.ok{color:green}.warn{color:orange}</style>"
        "</head><body><h2>DNS Sinkhole</h2>");
    n += snprintf(page + n, sizeof(page) - n,
        "<table><tr><th>Metric</th><th>Value</th></tr>"
        "<tr><td>Domains loaded</td><td>%" PRIu32 " %s</td></tr>"
        "<tr><td>Status</td><td class='%s'>%s</td></tr>"
        "<tr><td>Queries total</td><td>%" PRIu32 "</td></tr>"
        "<tr><td>Queries blocked</td><td>%" PRIu32 " (%.1f%%)</td></tr>"
        "<tr><td>Whitelist entries</td><td>%" PRIu32 " / %d</td></tr>"
        "</table>",
        domains, loading ? "(reloading...)" : "",
        loading ? "warn" : "ok",
        loading ? "Reloading" : "Active",
        total, blocked,
        total > 0 ? 100.0f * (float)blocked / (float)total : 0.0f,
        wl_n, WHITELIST_MAX);

    n += snprintf(page + n, sizeof(page) - n,
        "<h3>Actions</h3>"
        "<form method=post action=/reload><button>Reload blocklist</button></form><br>"
        "<form method=post action=/check>"
        "<input name=domain placeholder='Check domain' size=40>"
        "<button>Check</button></form><br>"
        "<form method=post action=/whitelist/add>"
        "<input name=domain placeholder='Add to whitelist' size=40>"
        "<button>Whitelist</button></form>");

    /* whitelist table */
    if (wl_n > 0) {
        n += snprintf(page + n, sizeof(page) - n,
            "<h3>Whitelist</h3><table>"
            "<tr><th>Domain</th><th>Action</th></tr>");
        char wl[WHITELIST_MAX][64]; uint32_t cnt = WHITELIST_MAX;
        blocklist_whitelist_get(wl, &cnt);
        for (uint32_t i = 0; i < cnt && n < (int)sizeof(page) - 256; i++) {
            char safe_text[384], safe_attr[384];
            html_escape(safe_text, sizeof(safe_text), wl[i]);
            html_escape(safe_attr, sizeof(safe_attr), wl[i]);
            n += snprintf(page + n, sizeof(page) - n,
                "<tr><td>%s</td><td>"
                "<form method=post action=/whitelist/remove>"
                "<input type=hidden name=domain value=\"%s\">"
                "<button>Remove</button></form></td></tr>",
                safe_text, safe_attr);
        }
        n += snprintf(page + n, sizeof(page) - n, "</table>");
    }

    /* Blocklist sources section (#4, #9) */
    n += snprintf(page + n, sizeof(page) - n,
        "<h3>Blocklist Sources</h3>"
        "<table><tr><th>#</th><th>URL</th><th>Action</th></tr>"
        "<tr><td>0 (primary)</td><td>%s</td><td>built-in</td></tr>",
        BLOCKLIST_URL);
    for (int i = 0; i < BLOCKLIST_EXTRA_MAX && n < (int)sizeof(page) - 512; i++) {
        char url[BLOCKLIST_URL_CAP]; blocklist_extra_url_get(i, url, sizeof(url));
        if (url[0]) {
            char safe_url[BLOCKLIST_URL_CAP * 2]; html_escape(safe_url, sizeof(safe_url), url);
            n += snprintf(page + n, sizeof(page) - n,
                "<tr><td>%d</td><td>%s</td><td>"
                "<form method=post action=/blocklist/url/clear>"
                "<input type=hidden name=idx value=%d>"
                "<button>Remove</button></form></td></tr>",
                i + 1, safe_url, i);
        } else {
            n += snprintf(page + n, sizeof(page) - n,
                "<tr><td>%d (empty)</td><td>"
                "<form method=post action=/blocklist/url/set style='display:inline'>"
                "<input type=hidden name=idx value=%d>"
                "<input name=url placeholder='https://...' size=50>"
                "<button>Add</button></form></td><td></td></tr>",
                i + 1, i);
        }
    }
    n += snprintf(page + n, sizeof(page) - n, "</table>"
        "<p><small>After adding/removing a source, click <b>Reload blocklist</b> above.</small></p>"
        "<p><small>Suggested security feeds: "
        "<code>https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/tif.txt</code> (malware/phishing) &nbsp; "
        "<code>https://nsfw.oisd.nl/domainswild2</code> (adult content)</small></p>");

    n += snprintf(page + n, sizeof(page) - n, "</body></html>");
    (void)n;
    send_html(r, page);
    return ESP_OK;
}

/* ── GET /metrics — JSON telemetry ───────────────────────────────── */
static esp_err_t handle_metrics(httpd_req_t *r)
{
    static char json[2048];
    int n = dns_server_metrics_json(json, sizeof(json));
    httpd_resp_set_type(r, "application/json");
    httpd_resp_set_hdr(r, "Cache-Control", "no-store");
    httpd_resp_send(r, json, n > 0 ? n : 0);
    return ESP_OK;
}

/* ── POST /metrics/reset — zero counters+histograms ──────────────── */
static esp_err_t handle_metrics_reset(httpd_req_t *r)
{
    if (!csrf_ok(r)) {
        httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "CSRF"); return ESP_FAIL;
    }
    dns_server_metrics_reset();
    httpd_resp_set_type(r, "application/json");
    httpd_resp_sendstr(r, "{\"reset\":true}");
    return ESP_OK;
}

/* ── POST /reload ────────────────────────────────────────────────── */
static esp_err_t handle_reload(httpd_req_t *r)
{
    if (!csrf_ok(r)) {
        httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "CSRF"); return ESP_FAIL;
    }
    dns_sink_trigger_reload();
    httpd_resp_set_status(r, "303 See Other");
    httpd_resp_set_hdr(r, "Location", "/");
    httpd_resp_send(r, nullptr, 0);
    return ESP_OK;
}

/* ── POST /check ─────────────────────────────────────────────────── */
static esp_err_t handle_check(httpd_req_t *r)
{
    if (!csrf_ok(r)) {
        httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "CSRF"); return ESP_FAIL;
    }
    char body[256] = {}; int got = httpd_req_recv(r, body, sizeof(body) - 1);
    if (got <= 0) { httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, ""); return ESP_FAIL; }

    /* parse domain=xxx from form body */
    const char *key = "domain="; const char *p = strstr(body, key);
    if (!p) { httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, ""); return ESP_FAIL; }
    p += strlen(key);
    size_t dlen = strlen(p); while (dlen > 0 && (p[dlen-1] == '\r'||p[dlen-1]=='\n')) dlen--;

    char decoded[256]; url_decode(decoded, sizeof(decoded), p, dlen);
    char norm[256]; size_t nlen = domain_normalize(norm, sizeof(norm), decoded, strlen(decoded));
    bool blocked = (nlen > 0) && blocklist_is_blocked(norm, nlen);

    char safe[384]; html_escape(safe, sizeof(safe), norm);
    char page[768];
    snprintf(page, sizeof(page),
        "<!DOCTYPE html><html><body><h2>Check result</h2>"
        "<p><b>%s</b> is <b style='color:%s'>%s</b></p>"
        "<a href='/'>Back</a></body></html>",
        safe, blocked ? "red" : "green", blocked ? "BLOCKED" : "ALLOWED");
    send_html(r, page);
    return ESP_OK;
}

/* ── POST /whitelist/add ─────────────────────────────────────────── */
static esp_err_t handle_wl_add(httpd_req_t *r)
{
    if (!csrf_ok(r)) {
        httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "CSRF"); return ESP_FAIL;
    }
    char body[256] = {}; httpd_req_recv(r, body, sizeof(body) - 1);
    const char *p = strstr(body, "domain=");
    if (p) {
        p += 7;
        size_t dlen = strlen(p); while (dlen && (p[dlen-1]=='\r'||p[dlen-1]=='\n')) dlen--;
        char decoded[256]; url_decode(decoded, sizeof(decoded), p, dlen);
        char norm[256]; size_t nlen = domain_normalize(norm, sizeof(norm), decoded, strlen(decoded));
        if (nlen > 0) blocklist_whitelist_add(norm);
    }
    httpd_resp_set_status(r, "303 See Other");
    httpd_resp_set_hdr(r, "Location", "/");
    httpd_resp_send(r, nullptr, 0);
    return ESP_OK;
}

/* ── POST /whitelist/remove ─────────────────────────────────────── */
static esp_err_t handle_wl_remove(httpd_req_t *r)
{
    if (!csrf_ok(r)) {
        httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "CSRF"); return ESP_FAIL;
    }
    char body[256] = {}; httpd_req_recv(r, body, sizeof(body) - 1);
    const char *p = strstr(body, "domain=");
    if (p) {
        p += 7;
        size_t dlen = strlen(p); while (dlen && (p[dlen-1]=='\r'||p[dlen-1]=='\n')) dlen--;
        char decoded[256]; url_decode(decoded, sizeof(decoded), p, dlen);
        char norm[256]; size_t nlen = domain_normalize(norm, sizeof(norm), decoded, strlen(decoded));
        if (nlen > 0) blocklist_whitelist_remove(norm);
    }
    httpd_resp_set_status(r, "303 See Other");
    httpd_resp_set_hdr(r, "Location", "/");
    httpd_resp_send(r, nullptr, 0);
    return ESP_OK;
}

/* ── POST /blocklist/url/set — set extra blocklist URL (#4, #9) ── */
static esp_err_t handle_bl_url_set(httpd_req_t *r)
{
    if (!csrf_ok(r)) {
        httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "CSRF"); return ESP_FAIL;
    }
    char body[512] = {}; httpd_req_recv(r, body, sizeof(body) - 1);
    /* parse: idx=0&url=https://... */
    const char *pidx = strstr(body, "idx=");
    const char *purl = strstr(body, "url=");
    if (!pidx || !purl) { httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, ""); return ESP_FAIL; }
    int idx = (int)strtol(pidx + 4, nullptr, 10);
    purl += 4;
    size_t ulen = strlen(purl);
    while (ulen && (purl[ulen-1] == '\r' || purl[ulen-1] == '\n')) ulen--;
    char decoded[BLOCKLIST_URL_CAP]; url_decode(decoded, sizeof(decoded), purl, ulen);
    blocklist_extra_url_set(idx, decoded);
    httpd_resp_set_status(r, "303 See Other");
    httpd_resp_set_hdr(r, "Location", "/");
    httpd_resp_send(r, nullptr, 0);
    return ESP_OK;
}

/* ── POST /blocklist/url/clear — clear extra blocklist URL (#4, #9) */
static esp_err_t handle_bl_url_clear(httpd_req_t *r)
{
    if (!csrf_ok(r)) {
        httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "CSRF"); return ESP_FAIL;
    }
    char body[64] = {}; httpd_req_recv(r, body, sizeof(body) - 1);
    const char *pidx = strstr(body, "idx=");
    if (!pidx) { httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, ""); return ESP_FAIL; }
    int idx = (int)strtol(pidx + 4, nullptr, 10);
    blocklist_extra_url_set(idx, "");
    httpd_resp_set_status(r, "303 See Other");
    httpd_resp_set_hdr(r, "Location", "/");
    httpd_resp_send(r, nullptr, 0);
    return ESP_OK;
}

/* ── Public API ──────────────────────────────────────────────────── */
bool web_ui_start(DnsSinkServer *dns)
{
    s_dns = dns;
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.server_port      = 80;
    cfg.max_uri_handlers = 16;
    cfg.stack_size       = 8192;
    if (httpd_start(&s_server, &cfg) != ESP_OK) {
        ESP_LOGE(TAG, "httpd_start failed"); return false;
    }

    static const httpd_uri_t uris[] = {
        { "/",                    HTTP_GET,  handle_status,        nullptr },
        { "/metrics",             HTTP_GET,  handle_metrics,       nullptr },
        { "/metrics/reset",       HTTP_POST, handle_metrics_reset, nullptr },
        { "/reload",              HTTP_POST, handle_reload,        nullptr },
        { "/check",               HTTP_POST, handle_check,         nullptr },
        { "/whitelist/add",       HTTP_POST, handle_wl_add,        nullptr },
        { "/whitelist/remove",    HTTP_POST, handle_wl_remove,     nullptr },
        { "/blocklist/url/set",   HTTP_POST, handle_bl_url_set,    nullptr },
        { "/blocklist/url/clear", HTTP_POST, handle_bl_url_clear,  nullptr },
    };
    for (auto &u : uris) httpd_register_uri_handler(s_server, &u);

    ESP_LOGI(TAG, "Web UI on port 80");
    return true;
}

void web_ui_stop(void)
{
    if (s_server) { httpd_stop(s_server); s_server = nullptr; }
}
