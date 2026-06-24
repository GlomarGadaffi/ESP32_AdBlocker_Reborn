#include "web_ui.h"
#include "blocklist.h"
#include "domain.h"
#include "rewrite.h"
#include "acl.h"
#include "dot.h"
#include "query_log.h"
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
        "<style>body{font-family:monospace;max-width:700px;margin:2em auto;}"
        "table{border-collapse:collapse;width:100%%}"
        "td,th{border:1px solid #ccc;padding:.4em .8em;text-align:left}"
        "th{background:#222;color:#eee}.ok{color:green}.warn{color:orange}"
        ".stats{display:flex;gap:1em;flex-wrap:wrap;margin:1em 0}"
        ".stat{background:#f4f4f4;border:1px solid #ccc;border-radius:6px;"
        "padding:.6em 1.2em;min-width:110px;text-align:center}"
        ".stat .val{font-size:1.6em;font-weight:bold;color:#1a1a8c}"
        ".stat .lbl{font-size:.75em;color:#555}</style>"
        "</head><body><h2>ESP32 AdBlocker</h2>");
    float pct = total > 0 ? 100.0f * (float)blocked / (float)total : 0.0f;
    n += snprintf(page + n, sizeof(page) - n,
        "<div class=stats>"
        "<div class=stat><div class=val>%" PRIu32 "</div><div class=lbl>Domains</div></div>"
        "<div class=stat><div class=val>%" PRIu32 "</div><div class=lbl>Queries</div></div>"
        "<div class=stat><div class=val>%" PRIu32 "</div><div class=lbl>Blocked</div></div>"
        "<div class=stat><div class=val>%.1f%%</div><div class=lbl>Block rate</div></div>"
        "<div class=stat><div class=val class='%s'>%s</div><div class=lbl>Status</div></div>"
        "</div>",
        domains, total, blocked, pct,
        loading ? "warn" : "ok",
        loading ? "Reloading" : "Active");

    n += snprintf(page + n, sizeof(page) - n,
        "<h3>Actions</h3>"
        "<form method=post action=/reload><button>Reload blocklist</button></form><br>"
        "<form method=post action=/check>"
        "<input name=domain placeholder='Check domain' size=40>"
        "<button>Check</button></form><br>"
        "<form method=post action=/whitelist/add>"
        "<input name=domain placeholder='Add to whitelist' size=40>"
        "<button>Whitelist</button></form><br>"
        "<a href='/log'>Query log</a> &nbsp; <a href='/top'>Top lists</a>"
        " &nbsp; <a href='/metrics'>Metrics JSON</a>");

    /* whitelist table */
    if (wl_n > 0) {
        n += snprintf(page + n, sizeof(page) - n,
            "<h3>Whitelist</h3><table>"
            "<tr><th>Domain</th><th>Action</th></tr>");
        static char wl[WHITELIST_MAX][64]; uint32_t cnt = WHITELIST_MAX;
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

    /* Custom block rules (#14) */
    {
        static char crules[CUSTOM_RULES_CAP + 8];
        static char safe_cr[CUSTOM_RULES_CAP * 2 + 8];
        size_t clen = blocklist_custom_get(crules, sizeof(crules));
        html_escape(safe_cr, sizeof(safe_cr), crules);
        n += snprintf(page + n, sizeof(page) - n,
            "<h3>Custom Block Rules</h3>"
            "<form method=post action=/custom/rules>"
            "<textarea name=rules rows=5 cols=60 placeholder='One domain per line. Lines starting with # are comments."
            " Hosts format (0.0.0.0 domain) also accepted.'>%s</textarea><br>"
            "<button>Save rules</button></form>",
            safe_cr);
        (void)clen;
    }

    /* DNS rewrite table (#12) */
    {
        uint32_t rw_n = rewrite_count();
        n += snprintf(page + n, sizeof(page) - n,
            "<h3>DNS Rewrites</h3>"
            "<form method=post action=/rewrite/set>"
            "<input name=domain placeholder='domain.local' size=24>"
            " → <input name=ip placeholder='192.168.1.x' size=16>"
            "<button>Add rewrite</button></form>");
        if (rw_n > 0) {
            char rw_domains[REWRITE_MAX][64]; uint32_t rw_ips[REWRITE_MAX]; uint32_t rw_cnt = REWRITE_MAX;
            rewrite_list(rw_domains, rw_ips, &rw_cnt);
            n += snprintf(page + n, sizeof(page) - n, "<table><tr><th>Domain</th><th>IP</th><th>Action</th></tr>");
            for (uint32_t i = 0; i < rw_cnt && n < (int)sizeof(page) - 256; i++) {
                char safe_d[128]; html_escape(safe_d, sizeof(safe_d), rw_domains[i]);
                char safe_da[128]; html_escape(safe_da, sizeof(safe_da), rw_domains[i]);
                uint32_t ip = rw_ips[i];
                n += snprintf(page + n, sizeof(page) - n,
                    "<tr><td>%s</td><td>%u.%u.%u.%u</td><td>"
                    "<form method=post action=/rewrite/clear>"
                    "<input type=hidden name=domain value=\"%s\">"
                    "<button>Remove</button></form></td></tr>",
                    safe_d,
                    (unsigned)((ip>>24)&0xFF),(unsigned)((ip>>16)&0xFF),
                    (unsigned)((ip>>8)&0xFF),(unsigned)(ip&0xFF),
                    safe_da);
            }
            n += snprintf(page + n, sizeof(page) - n, "</table>");
        }
    }

    /* Client ACL section (#10) */
    {
        char acl_ips[ACL_MAX][20]; uint32_t acl_n = ACL_MAX;
        acl_list(acl_ips, &acl_n);
        n += snprintf(page + n, sizeof(page) - n,
            "<h3>Client Access Control</h3>"
            "<p><small>Empty = allow all. If any IP is listed, only those clients may use this DNS server.</small></p>"
            "<form method=post action=/acl/add>"
            "<input name=ip placeholder='192.168.x.x' size=18>"
            "<button>Add allowed client</button></form>");
        if (acl_n > 0) {
            n += snprintf(page + n, sizeof(page) - n, "<table><tr><th>Allowed client IP</th><th>Action</th></tr>");
            for (uint32_t i = 0; i < acl_n && n < (int)sizeof(page) - 256; i++) {
                char safe_ip[48]; html_escape(safe_ip, sizeof(safe_ip), acl_ips[i]);
                char safe_ipv[48]; html_escape(safe_ipv, sizeof(safe_ipv), acl_ips[i]);
                n += snprintf(page + n, sizeof(page) - n,
                    "<tr><td>%s</td><td>"
                    "<form method=post action=/acl/remove>"
                    "<input type=hidden name=ip value=\"%s\">"
                    "<button>Remove</button></form></td></tr>",
                    safe_ip, safe_ipv);
            }
            n += snprintf(page + n, sizeof(page) - n, "</table>"
                "<form method=post action=/acl/clear style='margin-top:.5em'>"
                "<button>Clear all (allow everyone)</button></form>");
        }
    }

    /* DoT upstream settings (#5) */
    {
        bool dot_en = dot_is_enabled(); char dot_srv[64]="", dot_sni[64]="";
        dot_get(nullptr, dot_srv, dot_sni);
        n += snprintf(page + n, sizeof(page) - n,
            "<h3>Upstream DNS (DoT)</h3>"
            "<form method=post action=/dot/set>"
            "<label><input type=checkbox name=enabled value=1%s> Enable DNS-over-TLS</label><br>"
            "Server IP: <input name=server value=\"%s\" size=18> "
            "SNI: <input name=sni value=\"%s\" size=28><br>"
            "<small>Default: 1.1.1.1 / one.one.one.one &nbsp; or &nbsp; 9.9.9.9 / dns.quad9.net</small><br>"
            "<button>Save &amp; apply (restart DNS task)</button></form>",
            dot_en ? " checked" : "", dot_srv, dot_sni);
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

/* ── POST /dot/set — configure DoT upstream (#5) ────────────────── */
static esp_err_t handle_dot_set(httpd_req_t *r)
{
    if (!csrf_ok(r)) { httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "CSRF"); return ESP_FAIL; }
    char body[256] = {}; httpd_req_recv(r, body, sizeof(body) - 1);
    bool enabled = (strstr(body, "enabled=1") != nullptr);
    char server[64] = "1.1.1.1", sni[64] = "one.one.one.one";
    const char *ps = strstr(body, "server=");
    if (ps) { ps += 7; size_t l=0; char raw[64]={0}; for(;ps[l]&&ps[l]!='&'&&ps[l]!='\r'&&l<63;l++) raw[l]=ps[l]; url_decode(server,sizeof(server),raw,l); }
    const char *pn = strstr(body, "sni=");
    if (pn) { pn += 4; size_t l=0; char raw[64]={0}; for(;pn[l]&&pn[l]!='&'&&pn[l]!='\r'&&l<63;l++) raw[l]=pn[l]; url_decode(sni,sizeof(sni),raw,l); }
    dot_set(enabled, server, sni);
    httpd_resp_set_status(r, "303 See Other"); httpd_resp_set_hdr(r, "Location", "/"); httpd_resp_send(r,nullptr,0); return ESP_OK;
}

/* ── POST /acl/add — add allowed client IP (#10) ────────────────── */
static esp_err_t handle_acl_add(httpd_req_t *r)
{
    if (!csrf_ok(r)) { httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "CSRF"); return ESP_FAIL; }
    char body[64] = {}; httpd_req_recv(r, body, sizeof(body) - 1);
    const char *p = strstr(body, "ip=");
    if (p) { p += 3; char ip[24]={0}; size_t l=0; for(;p[l]&&p[l]!='&'&&p[l]!='\r'&&l<23;l++) ip[l]=p[l]; ip[l]=0; acl_add(ip); }
    httpd_resp_set_status(r, "303 See Other"); httpd_resp_set_hdr(r, "Location", "/"); httpd_resp_send(r,nullptr,0); return ESP_OK;
}

/* ── POST /acl/remove ────────────────────────────────────────────── */
static esp_err_t handle_acl_remove(httpd_req_t *r)
{
    if (!csrf_ok(r)) { httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "CSRF"); return ESP_FAIL; }
    char body[64] = {}; httpd_req_recv(r, body, sizeof(body) - 1);
    const char *p = strstr(body, "ip=");
    if (p) { p += 3; char ip[24]={0}; size_t l=0; for(;p[l]&&p[l]!='&'&&p[l]!='\r'&&l<23;l++) ip[l]=p[l]; ip[l]=0; acl_remove(ip); }
    httpd_resp_set_status(r, "303 See Other"); httpd_resp_set_hdr(r, "Location", "/"); httpd_resp_send(r,nullptr,0); return ESP_OK;
}

/* ── POST /acl/clear ─────────────────────────────────────────────── */
static esp_err_t handle_acl_clear(httpd_req_t *r)
{
    if (!csrf_ok(r)) { httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "CSRF"); return ESP_FAIL; }
    char body[4] = {}; httpd_req_recv(r, body, sizeof(body) - 1); /* consume body */
    acl_clear();
    httpd_resp_set_status(r, "303 See Other"); httpd_resp_set_hdr(r, "Location", "/"); httpd_resp_send(r,nullptr,0); return ESP_OK;
}

/* ── POST /custom/rules — save inline block rules (#14) ─────────── */
static esp_err_t handle_custom_rules(httpd_req_t *r)
{
    if (!csrf_ok(r)) {
        httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "CSRF"); return ESP_FAIL;
    }
    static char body[CUSTOM_RULES_CAP + 64];
    int got = httpd_req_recv(r, body, sizeof(body) - 1);
    if (got <= 0) { httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, ""); return ESP_FAIL; }
    body[got] = '\0';
    const char *p = strstr(body, "rules=");
    if (!p) { httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, ""); return ESP_FAIL; }
    p += 6;
    /* url-decode into a temp buffer */
    static char decoded[CUSTOM_RULES_CAP + 4];
    url_decode(decoded, sizeof(decoded), p, strlen(p));
    blocklist_custom_set(decoded);
    httpd_resp_set_status(r, "303 See Other");
    httpd_resp_set_hdr(r, "Location", "/");
    httpd_resp_send(r, nullptr, 0);
    return ESP_OK;
}

/* ── GET /log — recent query log (#8) ───────────────────────────── */
static esp_err_t handle_log(httpd_req_t *r)
{
    static QLogEntry entries[64];
    uint32_t n = query_log_snapshot(entries, 64);
    static char page[6144];
    int pg = 0;
    pg += snprintf(page + pg, sizeof(page) - pg,
        "<!DOCTYPE html><html><head><meta charset=utf-8>"
        "<title>Query Log</title>"
        "<style>body{font-family:monospace;max-width:900px;margin:1em auto}"
        "table{border-collapse:collapse;width:100%%}"
        "td,th{border:1px solid #ccc;padding:.3em .6em;font-size:.85em}"
        "th{background:#222;color:#eee}.blk{color:red}.rw{color:blue}"
        ".ok{color:green}</style></head><body>"
        "<h2>Query Log <small>(<a href='/'>home</a>)</small></h2>"
        "<table><tr><th>Time</th><th>Client</th><th>Domain</th>"
        "<th>Type</th><th>Result</th></tr>");
    for (uint32_t i = 0; i < n && pg < (int)sizeof(page) - 256; i++) {
        QLogEntry *e = &entries[i];
        char safe[128]; html_escape(safe, sizeof(safe), e->domain);
        const char *res  = e->blocked ? "BLOCKED" : (e->rewritten ? "REWRITE" : "ALLOWED");
        const char *cls  = e->blocked ? "blk"     : (e->rewritten ? "rw"      : "ok");
        const char *type = e->qtype == 1 ? "A" : (e->qtype == 28 ? "AAAA" :
                           e->qtype == 5 ? "CNAME" : e->qtype == 15 ? "MX" : "?");
        uint32_t ip = e->client_ip;
        pg += snprintf(page + pg, sizeof(page) - pg,
            "<tr><td>+%lus</td><td>%u.%u.%u.%u</td><td>%s</td>"
            "<td>%s</td><td class='%s'>%s</td></tr>",
            (unsigned long)e->ts_s,
            (unsigned)((ip>>24)&0xFF),(unsigned)((ip>>16)&0xFF),
            (unsigned)((ip>>8)&0xFF),(unsigned)(ip&0xFF),
            safe, type, cls, res);
    }
    pg += snprintf(page + pg, sizeof(page) - pg, "</table></body></html>");
    send_html(r, page);
    return ESP_OK;
}

/* ── GET /top — top domains, clients + live history graph (#7,#11) ─ */
static esp_err_t handle_top(httpd_req_t *r)
{
    static QTopEntry top_d[QTOP_DOMAINS], top_c[QTOP_CLIENTS];
    uint32_t nd = query_log_top_domains(top_d, QTOP_DOMAINS);
    uint32_t nc = query_log_top_clients(top_c, QTOP_CLIENTS);
    static uint32_t h_total[QHIST_BUCKETS], h_blocked[QHIST_BUCKETS];
    uint32_t h_count = 0;
    query_log_history(h_total, h_blocked, &h_count);
    /* find max for scaling */
    uint32_t h_max = 1;
    for (uint32_t i = 0; i < h_count; i++) if (h_total[i] > h_max) h_max = h_total[i];

    static char page[6144];
    int pg = 0;
    pg += snprintf(page + pg, sizeof(page) - pg,
        "<!DOCTYPE html><html><head><meta charset=utf-8>"
        "<meta http-equiv='refresh' content='30'>"
        "<title>Stats</title>"
        "<style>body{font-family:monospace;max-width:800px;margin:1em auto}"
        "table{border-collapse:collapse;width:100%%}"
        "td,th{border:1px solid #ccc;padding:.3em .6em}"
        "th{background:#222;color:#eee}"
        ".chart{display:flex;align-items:flex-end;gap:2px;height:80px;border-bottom:1px solid #888;margin:.5em 0}"
        ".bar{width:10px;display:inline-flex;flex-direction:column;justify-content:flex-end}"
        ".bt{background:#4a90d9}.bb{background:#e74c3c}</style></head><body>"
        "<h2>Stats &amp; Graphs <small>(<a href='/'>home</a>)</small></h2>"
        "<h3>Query Volume (last %lu minutes)</h3>"
        "<div class=chart>",
        (unsigned long)h_count);
    /* render bars oldest→newest */
    for (int i = (int)h_count - 1; i >= 0 && pg < (int)sizeof(page) - 256; i--) {
        uint32_t allowed  = h_total[i] > h_blocked[i] ? h_total[i] - h_blocked[i] : 0;
        uint32_t th = (allowed  * 78) / h_max;
        uint32_t bh = (h_blocked[i] * 78) / h_max;
        pg += snprintf(page + pg, sizeof(page) - pg,
            "<div class=bar title='%lut %lub'>"
            "<div class=bb style='height:%lupx'></div>"
            "<div class=bt style='height:%lupx'></div></div>",
            (unsigned long)h_total[i], (unsigned long)h_blocked[i],
            (unsigned long)bh, (unsigned long)th);
    }
    pg += snprintf(page + pg, sizeof(page) - pg,
        "</div><p><small>Blue=allowed Red=blocked. Each bar=1 min.</small></p>"
        "<h3>Top Queried Domains</h3>"
        "<table><tr><th>Domain</th><th>Total</th><th>Blocked</th></tr>");
    for (uint32_t i = 0; i < nd && top_d[i].total > 0 && pg < (int)sizeof(page) - 256; i++) {
        char safe[128]; html_escape(safe, sizeof(safe), top_d[i].key);
        pg += snprintf(page + pg, sizeof(page) - pg,
            "<tr><td>%s</td><td>%lu</td><td>%lu</td></tr>",
            safe, (unsigned long)top_d[i].total, (unsigned long)top_d[i].blocked);
    }
    pg += snprintf(page + pg, sizeof(page) - pg,
        "</table><h3>Top Clients</h3>"
        "<table><tr><th>Client IP</th><th>Total</th><th>Blocked</th></tr>");
    for (uint32_t i = 0; i < nc && top_c[i].total > 0 && pg < (int)sizeof(page) - 256; i++) {
        char safe[64]; html_escape(safe, sizeof(safe), top_c[i].key);
        pg += snprintf(page + pg, sizeof(page) - pg,
            "<tr><td>%s</td><td>%lu</td><td>%lu</td></tr>",
            safe, (unsigned long)top_c[i].total, (unsigned long)top_c[i].blocked);
    }
    pg += snprintf(page + pg, sizeof(page) - pg, "</table></body></html>");
    send_html(r, page);
    return ESP_OK;
}

/* ── POST /rewrite/set — add a DNS rewrite rule (#12) ─────────── */
static esp_err_t handle_rw_set(httpd_req_t *r)
{
    if (!csrf_ok(r)) {
        httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "CSRF"); return ESP_FAIL;
    }
    char body[256] = {}; httpd_req_recv(r, body, sizeof(body) - 1);
    /* parse: domain=foo.local&ip=192.168.1.5 */
    const char *pd = strstr(body, "domain=");
    const char *pi = strstr(body, "ip=");
    if (!pd || !pi) { httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, ""); return ESP_FAIL; }
    pd += 7; pi += 3;
    /* extract domain value (ends at '&' or '\0') */
    char raw_d[64] = {};
    size_t dl = 0;
    for (const char *c = pd; *c && *c != '&' && *c != '\r' && *c != '\n' && dl < 63; c++, dl++)
        raw_d[dl] = *c;
    char decoded_d[64]; url_decode(decoded_d, sizeof(decoded_d), raw_d, dl);
    char norm[64]; size_t nlen = domain_normalize(norm, sizeof(norm), decoded_d, strlen(decoded_d));
    if (nlen == 0) { httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, "bad domain"); return ESP_FAIL; }
    /* extract IP value */
    unsigned b0=0,b1=0,b2=0,b3=0;
    sscanf(pi, "%u.%u.%u.%u", &b0, &b1, &b2, &b3);
    uint32_t ipv4 = ((uint32_t)b0<<24)|((uint32_t)b1<<16)|((uint32_t)b2<<8)|(uint32_t)b3;
    if (ipv4 == 0) { httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, "bad ip"); return ESP_FAIL; }
    rewrite_set(norm, ipv4);
    httpd_resp_set_status(r, "303 See Other");
    httpd_resp_set_hdr(r, "Location", "/");
    httpd_resp_send(r, nullptr, 0);
    return ESP_OK;
}

/* ── POST /rewrite/clear — remove a DNS rewrite rule (#12) ────── */
static esp_err_t handle_rw_clear(httpd_req_t *r)
{
    if (!csrf_ok(r)) {
        httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "CSRF"); return ESP_FAIL;
    }
    char body[128] = {}; httpd_req_recv(r, body, sizeof(body) - 1);
    const char *pd = strstr(body, "domain=");
    if (!pd) { httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, ""); return ESP_FAIL; }
    pd += 7;
    char raw[64] = {}; size_t dl = 0;
    for (const char *c = pd; *c && *c != '&' && *c != '\r' && *c != '\n' && dl < 63; c++, dl++)
        raw[dl] = *c;
    char decoded[64]; url_decode(decoded, sizeof(decoded), raw, dl);
    char norm[64]; size_t nlen = domain_normalize(norm, sizeof(norm), decoded, strlen(decoded));
    if (nlen > 0) rewrite_set(norm, 0);
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
    cfg.max_uri_handlers = 20;
    cfg.stack_size       = 16384;
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
        { "/rewrite/set",         HTTP_POST, handle_rw_set,        nullptr },
        { "/rewrite/clear",       HTTP_POST, handle_rw_clear,      nullptr },
        { "/log",                 HTTP_GET,  handle_log,           nullptr },
        { "/top",                 HTTP_GET,  handle_top,           nullptr },
        { "/custom/rules",        HTTP_POST, handle_custom_rules,  nullptr },
        { "/acl/add",             HTTP_POST, handle_acl_add,       nullptr },
        { "/acl/remove",          HTTP_POST, handle_acl_remove,    nullptr },
        { "/acl/clear",           HTTP_POST, handle_acl_clear,     nullptr },
        { "/dot/set",             HTTP_POST, handle_dot_set,       nullptr },
    };
    for (auto &u : uris) httpd_register_uri_handler(s_server, &u);

    ESP_LOGI(TAG, "Web UI on port 80");
    return true;
}

void web_ui_stop(void)
{
    if (s_server) { httpd_stop(s_server); s_server = nullptr; }
}
