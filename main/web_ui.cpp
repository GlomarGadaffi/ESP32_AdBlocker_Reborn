#include "web_ui.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "blocklist.h"
#include "domain.h"
#include "rewrite.h"
#include "acl.h"
#include "dot.h"
#include "localzone.h"
#include "query_log.h"
#include "esp_http_server.h"
#include "esp_https_server.h"
#include "esp_log.h"
#include "esp_attr.h"
#include "esp_ota_ops.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "web_tls.h"
#include "web_auth.h"
#include <cstring>
#include <strings.h>
#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <ctime>
#include <inttypes.h>
#include "timesync.h"

static const char *TAG = "web_ui";
static httpd_handle_t  s_server   = nullptr;   /* HTTPS :443 — the real UI */
static httpd_handle_t  s_redirect = nullptr;   /* HTTP  :80  — 301 to https only */
static DnsSinkServer  *s_dns      = nullptr;

extern "C" void dns_sink_trigger_reload(void);
extern "C" bool dns_sink_wifi_built(void);
extern "C" void dns_sink_net_status(char *iface, size_t iface_cap,
                                     char *eth_ip, size_t eth_cap,
                                     char *wifi_ip, size_t wifi_cap);
extern "C" bool dns_sink_set_upstream_iface(const char *iface);
extern "C" void dns_sink_wifi_get_ssid(char *out, size_t cap);
extern "C" bool dns_sink_wifi_scan_start(void);
extern "C" int  dns_sink_wifi_scan_get(char *out, size_t cap);
extern "C" bool dns_sink_wifi_set_creds(const char *ssid, const char *pass);
extern "C" bool dns_sink_net_set_static(const char *iface, bool dhcp,
                                         const char *ip, const char *nm,
                                         const char *gw, const char *dns_ip);
extern "C" void dns_sink_net_get_static(const char *iface, bool *dhcp,
                                         char *ip, size_t ip_cap,
                                         char *nm, size_t nm_cap,
                                         char *gw, size_t gw_cap,
                                         char *dns_ip, size_t dns_cap);
extern "C" void dns_sink_net_get_current(const char *iface,
                                          char *ip, size_t ip_cap,
                                          char *nm, size_t nm_cap,
                                          char *gw, size_t gw_cap,
                                          char *dns_ip, size_t dns_cap);
extern "C" void dns_sink_reboot(void);
extern "C" bool dns_sink_setup_ap_active(void);
extern "C" const char *dns_sink_hostname(void);
extern "C" const char *dns_sink_lan_ip(void);

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

/* Compare the host component of an Origin/Referer URL against our Host header.
 * Matches scheme://<host>[:port][/...] — the host must appear immediately after
 * "://" and be terminated by ':', '/', or end-of-string. A plain substring test
 * (the old behavior) accepts http://<host>.evil.com because <host> is a prefix
 * substring; this rejects it (L1). */
static bool origin_host_matches(const char *url, const char *host)
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

/* Pre-session POSTs (/setup, /login) have no CSRF token yet, so they lean on
 * Origin. A browser that sends "Origin: null" (some do on POST under a strict
 * referrer policy, or from a privacy mode) gets judged on Referer instead;
 * with neither present the request is refused (#96). */
static bool presession_origin_ok(httpd_req_t *r)
{
    char host[64] = {}, origin[128] = {}, referer[128] = {};
    httpd_req_get_hdr_value_str(r, "Host",    host,    sizeof(host));
    httpd_req_get_hdr_value_str(r, "Origin",  origin,  sizeof(origin));
    httpd_req_get_hdr_value_str(r, "Referer", referer, sizeof(referer));
    if (origin[0] && strcmp(origin, "null") != 0) return origin_host_matches(origin, host);
    if (referer[0]) return origin_host_matches(referer, host);
    /* (#96) Neither identifies the device -> refuse. /setup creates the admin
     * account, and a cross-site auto-submitting form under referrer-policy
     * no-referrer arrives exactly as "Origin: null" + no Referer. Our own
     * pages send Referer (Referrer-Policy: same-origin), so a legitimate
     * same-origin form always passes one of the two checks above. */
    return false;
}

/* ── Session cookie ────────────────────────────────────────────────
 * The session token rides in `sid`. Pulled once per request in auth_wrap and
 * kept here (single-task httpd, #61 — one request in flight at a time) so
 * handlers and csrf_ok don't re-parse the Cookie header. */
static char s_req_sid[WEB_AUTH_TOKEN_HEX + 1] = "";

static void cookie_get_sid(httpd_req_t *r)
{
    s_req_sid[0] = '\0';
    char ck[256] = {};
    if (httpd_req_get_hdr_value_str(r, "Cookie", ck, sizeof(ck)) != ESP_OK) return;
    const char *p = ck;
    while ((p = strstr(p, "sid=")) != nullptr) {
        /* must be at start or after "; " so `xsid=` can't match */
        if (p == ck || p[-1] == ' ' || p[-1] == ';') {
            p += 4;
            size_t l = 0;
            while (p[l] && p[l] != ';' && l < WEB_AUTH_TOKEN_HEX) l++;
            if (l == WEB_AUTH_TOKEN_HEX) { memcpy(s_req_sid, p, l); s_req_sid[l] = '\0'; }
            return;
        }
        p += 4;
    }
}

/* Cookie attributes: HttpOnly keeps scripts away from it, Secure keeps it off
 * the :80 redirect listener, SameSite=Strict makes the browser itself refuse
 * to attach it to any cross-site request — the first CSRF line of defence,
 * before csrf_ok's own checks. */
static void set_session_cookie(httpd_req_t *r, const char *sid)
{
    static EXT_RAM_BSS_ATTR char hdr[160];
    snprintf(hdr, sizeof(hdr), "sid=%s; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=43200", sid);
    httpd_resp_set_hdr(r, "Set-Cookie", hdr);
}
static void clear_session_cookie(httpd_req_t *r)
{
    httpd_resp_set_hdr(r, "Set-Cookie", "sid=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0");
}

/* Check a state-changing request is same-origin AND carries this session's
 * CSRF token (query string `csrf=` for forms, `X-CSRF` header for fetch()).
 * Three independent checks, any one of which is enough on a modern browser;
 * together they also cover older ones and the "no Origin header sent" case
 * that used to be a silent allow. */
static bool csrf_ok(httpd_req_t *r)
{
    char host[64] = {}, origin[128] = {}, referer[128] = {};
    httpd_req_get_hdr_value_str(r, "Host",    host,    sizeof(host));
    httpd_req_get_hdr_value_str(r, "Origin",  origin,  sizeof(origin));
    httpd_req_get_hdr_value_str(r, "Referer", referer, sizeof(referer));
    if (origin[0]  != '\0' && !origin_host_matches(origin,  host)) return false;
    if (referer[0] != '\0' && !origin_host_matches(referer, host)) return false;

    char want[33];
    if (!web_auth_session_csrf(s_req_sid, want, sizeof(want))) return false;
    char got[48] = {};
    if (httpd_req_get_hdr_value_str(r, "X-CSRF", got, sizeof(got)) != ESP_OK) {
        char q[96] = {};
        if (httpd_req_get_url_query_str(r, q, sizeof(q)) != ESP_OK) return false;
        if (httpd_query_key_value(q, "csrf", got, sizeof(got)) != ESP_OK) return false;
    }
    return strlen(got) == 32 && memcmp(got, want, 32) == 0;
}

/* ── Response hardening ────────────────────────────────────────────
 * Applied to every response by auth_wrap. All values are string literals
 * because httpd keeps the pointers, not copies. CSP allows inline script and
 * style because the page is one self-contained document with no external
 * resources — everything else is closed: no framing, no form posts to other
 * origins, no base-URI tricks. No HSTS on purpose: with a self-signed cert a
 * pinned HSTS entry turns a `cert-reset` (or an NVS wipe) into a browser
 * hard-lockout with no "proceed anyway" link for a year, and it buys nothing
 * here — :80 already redirects and browsers ignore HSTS on untrusted
 * connections anyway. */
static void set_security_headers(httpd_req_t *r)
{
    httpd_resp_set_hdr(r, "Cache-Control", "no-store");
    httpd_resp_set_hdr(r, "X-Content-Type-Options", "nosniff");
    httpd_resp_set_hdr(r, "X-Frame-Options", "DENY");
    /* same-origin, not no-referrer: still nothing leaks cross-site, and the
     * Referer stays available as the pre-session CSRF fallback above. */
    httpd_resp_set_hdr(r, "Referrer-Policy", "same-origin");
    httpd_resp_set_hdr(r, "Content-Security-Policy",
        "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
        "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
}

static void redirect_to(httpd_req_t *r, const char *where)
{
    httpd_resp_set_status(r, "303 See Other");
    httpd_resp_set_hdr(r, "Location", where);
    httpd_resp_send(r, nullptr, 0);
}

/* ── Auth trampoline ──────────────────────────────────────────────
 * Every registered URI is wrapped through this so policy is enforced in one
 * place rather than duplicated at the top of ~30 handlers — the same
 * "policy in shared code, not per-call-site" reasoning as the blocklist
 * verdict path. The real handler is stashed in httpd_uri_t.user_ctx.
 *
 * Order of gates:
 *   1. no admin account yet → everything goes to the setup wizard (#89 —
 *      the device must not serve a single page of config, or accept one,
 *      before it has an owner);
 *   2. no valid session → login page;
 *   3. otherwise run the handler. */
typedef esp_err_t (*raw_handler_t)(httpd_req_t *);
static esp_err_t handle_setup_get(httpd_req_t *r);
static esp_err_t handle_setup_post(httpd_req_t *r);
static esp_err_t handle_login_get(httpd_req_t *r);
static esp_err_t handle_login_post(httpd_req_t *r);

static esp_err_t auth_wrap(httpd_req_t *r)
{
    web_auth_poll_reset();
    set_security_headers(r);
    cookie_get_sid(r);
    raw_handler_t fn = (raw_handler_t)r->user_ctx;

    if (web_auth_setup_needed()) {
        if (fn == handle_setup_get || fn == handle_setup_post) return fn(r);
        if (r->method == HTTP_GET) { redirect_to(r, "/setup"); return ESP_OK; }
        httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "Setup required"); return ESP_FAIL;
    }
    if (fn == handle_setup_get || fn == handle_setup_post) { redirect_to(r, "/"); return ESP_OK; }
    if (fn == handle_login_get  || fn == handle_login_post) return fn(r);

    if (!web_auth_session_valid(s_req_sid)) {
        if (r->method == HTTP_GET) { redirect_to(r, "/login"); return ESP_OK; }
        httpd_resp_send_err(r, HTTPD_401_UNAUTHORIZED, "Login required"); return ESP_FAIL;
    }
    web_auth_session_touch(s_req_sid);
    return fn(r);
}

/* Bounded append into a page buffer. *pos tracks the current write offset.
 * snprintf returns the length it WOULD have written, so a naive
 * `n += snprintf(buf+n, cap-n, ...)` lets n exceed cap; the next call then
 * computes cap-n as a huge size_t and writes past the buffer (H1). This clamps
 * *pos to cap-1 on truncation so every subsequent call is a safe no-op. */
static void page_appendf(char *buf, size_t cap, int *pos, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));
static void page_appendf(char *buf, size_t cap, int *pos, const char *fmt, ...)
{
    if (*pos < 0 || (size_t)*pos >= cap) { if (cap) buf[cap - 1] = '\0'; return; }
    size_t avail = cap - (size_t)*pos;
    va_list ap;
    va_start(ap, fmt);
    int w = vsnprintf(buf + *pos, avail, fmt, ap);
    va_end(ap);
    if (w < 0) return;
    if ((size_t)w >= avail) *pos = (int)cap - 1;   /* truncated — clamp */
    else                    *pos += w;
}

/* F11: last-resort visible marker for a section skipped because the page
 * buffer's running low, instead of letting page_appendf's silent clamp (H1)
 * truncate mid-markup — that presents as dead tabs with no indication why
 * (#60). Reserves TRUNC_CLOSE_RESERVE so printing the marker itself can never
 * be the thing that eats the room the final closing markup needs. */
static constexpr int TRUNC_CLOSE_RESERVE = 128;
static void page_mark_truncated(char *page, size_t cap, int *n)
{
    if (*n < (int)cap - TRUNC_CLOSE_RESERVE)
        page_appendf(page, cap, n, "<p class=warn>[page truncated — too much config to render]</p>");
}

static void send_html(httpd_req_t *r, const char *body)
{
    httpd_resp_set_type(r, "text/html; charset=utf-8");
    httpd_resp_send(r, body, HTTPD_RESP_USE_STRLEN);
}

/* Shared shell for the two pre-login pages (setup wizard, login). Kept
 * deliberately plain: no tabs, no refresh, nothing that needs a session. */
static const char AUTH_PAGE_HEAD[] =
    "<!DOCTYPE html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>DNS Sinkhole</title>"
    "<style>body{font-family:monospace;max-width:520px;margin:3em auto;padding:0 1em}"
    "input{font:inherit;padding:.4em;width:100%%;box-sizing:border-box;margin:.25em 0 .8em}"
    "button{font:inherit;padding:.5em 1.2em}.err{color:#b00020}.fp{word-break:break-all;background:#f4f4f4;"
    "border:1px solid #ccc;padding:.6em;font-size:.85em}small{color:#555}</style></head><body>";

/* Read a form body field into dst (URL-decoded). Body is the raw
 * application/x-www-form-urlencoded request. */
static void form_field(const char *body, const char *key, char *dst, size_t cap)
{
    dst[0] = '\0';
    size_t kl = strlen(key);
    const char *p = body;
    while ((p = strstr(p, key)) != nullptr) {
        if ((p == body || p[-1] == '&') && p[kl] == '=') {
            p += kl + 1;
            size_t l = 0;
            while (p[l] && p[l] != '&' && p[l] != '\r' && p[l] != '\n') l++;
            url_decode(dst, cap, p, l);
            return;
        }
        p += kl;
    }
}

/* ── GET/POST /setup — first-boot onboarding (#89) ───────────────────
 * Reached only while no admin account exists (auth_wrap routes everything
 * here until one does). Creates the account, opens a session, and lands on
 * the dashboard. Shows the certificate fingerprint so the browser warning
 * the user just clicked through can be checked against what the device
 * itself reports — the only trust anchor a self-signed cert has. */
static esp_err_t setup_page(httpd_req_t *r, const char *err)
{
    static EXT_RAM_BSS_ATTR char page[3072];
    char fp[96]; web_tls_fingerprint(fp, sizeof(fp));
    int n = 0;
    page_appendf(page, sizeof(page), &n, AUTH_PAGE_HEAD);
    page_appendf(page, sizeof(page), &n,
        "<h2>Welcome &mdash; secure this device</h2>"
        "<p>This DNS sinkhole will hold your Wi-Fi password and every client's DNS history. "
        "Before it serves anything, create the admin account that guards it.</p>"
        "<p><b>Certificate fingerprint (SHA-256)</b><br><small>Your browser warned about a "
        "self-signed certificate. Compare its fingerprint with this one, then you can trust it "
        "permanently. It also prints on the USB console at boot.</small></p>"
        "<div class=fp>%s</div><br>"
        "%s%s%s"
        "<form method=post action=/setup>"
        "<label>Admin username<input name=user maxlength=%d autocomplete=username required></label>"
        "<label>Password <small>(%d&ndash;%d characters)</small><input name=pass type=password "
        "minlength=%d maxlength=%d autocomplete=new-password required></label>"
        "<label>Confirm password<input name=pass2 type=password minlength=%d maxlength=%d "
        "autocomplete=new-password required></label>"
        "<button>Create account &amp; continue</button></form>"
        "<p><small>Lost the password later? The USB console command <code>admin-reset</code> "
        "brings this page back &mdash; it needs the cable, not the network.</small></p>"
        "</body></html>",
        fp[0] ? fp : "(unavailable)",
        err ? "<p class=err>" : "", err ? err : "", err ? "</p>" : "",
        WEB_AUTH_USER_MAX, WEB_AUTH_PASS_MIN, WEB_AUTH_PASS_MAX,
        WEB_AUTH_PASS_MIN, WEB_AUTH_PASS_MAX, WEB_AUTH_PASS_MIN, WEB_AUTH_PASS_MAX);
    send_html(r, page);
    return ESP_OK;
}

static esp_err_t handle_setup_get(httpd_req_t *r) { return setup_page(r, nullptr); }

static esp_err_t handle_setup_post(httpd_req_t *r)
{
    /* No session exists yet so csrf_ok can't apply; the Origin/Referer check
     * still does, and the window is one request long — the account exists
     * after it. */
    if (!presession_origin_ok(r)) {
        httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "CSRF"); return ESP_FAIL;
    }
    char body[512] = {};
    int got = httpd_req_recv(r, body, sizeof(body) - 1);
    if (got <= 0) { httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, ""); return ESP_FAIL; }
    char user[WEB_AUTH_USER_MAX + 2], pass[WEB_AUTH_PASS_MAX + 2], pass2[WEB_AUTH_PASS_MAX + 2];
    form_field(body, "user",  user,  sizeof(user));
    form_field(body, "pass",  pass,  sizeof(pass));
    form_field(body, "pass2", pass2, sizeof(pass2));
    memset(body, 0, sizeof(body));

    const char *err = nullptr;
    if (strcmp(pass, pass2) != 0)                 err = "Passwords don't match.";
    else if (!web_auth_set_credentials(user, pass)) err = "Username must be 1-31 printable characters (no ':'); password 10-63 characters.";
    memset(pass, 0, sizeof(pass)); memset(pass2, 0, sizeof(pass2));
    if (err) return setup_page(r, err);

    char sid[WEB_AUTH_TOKEN_HEX + 1];
    if (web_auth_session_create(sid, sizeof(sid))) set_session_cookie(r, sid);
    redirect_to(r, "/");
    return ESP_OK;
}

/* ── GET/POST /login, POST /logout ───────────────────────────────── */
static esp_err_t login_page(httpd_req_t *r, const char *err)
{
    static EXT_RAM_BSS_ATTR char page[2048];
    int n = 0;
    page_appendf(page, sizeof(page), &n, AUTH_PAGE_HEAD);
    page_appendf(page, sizeof(page), &n,
        "<h2>DNS Sinkhole &mdash; sign in</h2>"
        "%s%s%s"
        "<form method=post action=/login>"
        "<label>Username<input name=user maxlength=%d autocomplete=username required autofocus></label>"
        "<label>Password<input name=pass type=password maxlength=%d autocomplete=current-password required></label>"
        "<button>Sign in</button></form>"
        "</body></html>",
        err ? "<p class=err>" : "", err ? err : "", err ? "</p>" : "",
        WEB_AUTH_USER_MAX, WEB_AUTH_PASS_MAX);
    send_html(r, page);
    return ESP_OK;
}

static esp_err_t handle_login_get(httpd_req_t *r)
{
    if (web_auth_session_valid(s_req_sid)) { redirect_to(r, "/"); return ESP_OK; }
    return login_page(r, nullptr);
}

static esp_err_t handle_login_post(httpd_req_t *r)
{
    if (!presession_origin_ok(r)) {
        httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "CSRF"); return ESP_FAIL;
    }
    char body[384] = {};
    int got = httpd_req_recv(r, body, sizeof(body) - 1);
    if (got <= 0) { httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, ""); return ESP_FAIL; }
    char user[WEB_AUTH_USER_MAX + 2], pass[WEB_AUTH_PASS_MAX + 2];
    form_field(body, "user", user, sizeof(user));
    form_field(body, "pass", pass, sizeof(pass));
    memset(body, 0, sizeof(body));

    int retry = 0;
    bool ok = web_auth_check_password(user, pass, &retry);
    memset(pass, 0, sizeof(pass));
    if (!ok) {
        static EXT_RAM_BSS_ATTR char msg[96];
        if (retry > 0) snprintf(msg, sizeof(msg), "Too many failed attempts. Try again in %d s.", retry);
        else           snprintf(msg, sizeof(msg), "Wrong username or password.");
        ESP_LOGW(TAG, "failed login for \"%s\"", user);
        return login_page(r, msg);
    }
    char sid[WEB_AUTH_TOKEN_HEX + 1];
    if (!web_auth_session_create(sid, sizeof(sid))) {
        httpd_resp_send_err(r, HTTPD_500_INTERNAL_SERVER_ERROR, "session"); return ESP_FAIL;
    }
    set_session_cookie(r, sid);
    redirect_to(r, "/");
    return ESP_OK;
}

static esp_err_t handle_logout(httpd_req_t *r)
{
    if (!csrf_ok(r)) { httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "CSRF"); return ESP_FAIL; }
    web_auth_session_destroy(s_req_sid);
    clear_session_cookie(r);
    redirect_to(r, "/login");
    return ESP_OK;
}

/* ── GET / — status page ─────────────────────────────────────────── */
static esp_err_t handle_status(httpd_req_t *r)
{
    uint32_t total   = s_dns ? (uint32_t)s_dns->queries_total()   : 0;
    uint32_t blocked = s_dns ? (uint32_t)s_dns->queries_blocked() : 0;
    uint32_t domains = blocklist_domain_count();
    bool     loading = blocklist_is_loading();
    bool     paused  = blocklist_is_paused();
    uint32_t wl_n    = blocklist_whitelist_count();
    /* F9: hoisted so the Dashboard chip below can reflect degradation, not
     * just loading state — these were previously only read down in the
     * Blocklist tab, which the auto-refreshing Dashboard never shows. */
    uint32_t bl_dropped   = blocklist_dropped_count();
    uint32_t bl_feed_fail = blocklist_feed_failures();

    /* static: avoids stack overflow in httpd task. Sized with headroom for a
     * fully-populated device (whitelist + ACL + rewrites + extra sources all
     * at once) — page_appendf clamps silently on overflow (H1), which with the
     * tabbed layout would truncate mid-markup and leave unbalanced <div>s, so
     * the failure would present as dead tabs rather than an error (#60). */
    static EXT_RAM_BSS_ATTR char page[16384];
    int  n = 0;
    char csrf[33] = "";
    web_auth_session_csrf(s_req_sid, csrf, sizeof(csrf));
    page_appendf(page, sizeof(page), &n,
        "<!DOCTYPE html><html><head><meta charset=utf-8>"
        "<title>DNS Sinkhole</title>"
        /* No <meta refresh>: it dropped the URL fragment, so every reload
         * kicked you back to the Dashboard mid-edit, and it wiped half-typed
         * form input on the config tabs (#63). Refresh is JS-driven below and
         * only runs while the Dashboard is actually showing. */
        "<style>body{font-family:monospace;max-width:700px;margin:2em auto;}"
        "table{border-collapse:collapse;width:100%%}"
        "td,th{border:1px solid #ccc;padding:.4em .8em;text-align:left}"
        "th{background:#222;color:#eee}.ok{color:green}.warn{color:orange}"
        ".stats{display:flex;gap:1em;flex-wrap:wrap;margin:1em 0}"
        ".stat{background:#f4f4f4;border:1px solid #ccc;border-radius:6px;"
        "padding:.6em 1.2em;min-width:110px;text-align:center}"
        ".stat .val{font-size:1.6em;font-weight:bold;color:#1a1a8c}"
        ".stat .lbl{font-size:.75em;color:#555}"
        ".tabs{display:flex;gap:.3em;flex-wrap:wrap;border-bottom:2px solid #ccc;margin-bottom:1em}"
        ".tabs button{background:none;border:none;border-bottom:3px solid transparent;"
        "padding:.5em .9em;font:inherit;cursor:pointer;color:#555}"
        ".tabs button.active{border-bottom-color:#1a1a8c;color:#1a1a8c;font-weight:bold}"
        ".tab{display:none}.tab.active{display:block}</style>"
        "<script>"
        /* Per-session CSRF token. Every <form> gets it appended to its action
         * as ?csrf= on submit and every fetch() sends it as X-CSRF, so no
         * handler body-parsing had to change (csrf_ok reads the query string
         * or the header). JS is already required for the tabs, and with JS
         * off every POST simply fails closed with 403. */
        "var CSRF='%s';"
        "document.addEventListener('submit',function(e){var f=e.target;"
        "if(f.method&&f.method.toLowerCase()=='post'){var a=f.getAttribute('action')||location.pathname;"
        "f.action=a+(a.indexOf('?')<0?'?':'&')+'csrf='+CSRF;}});"
        "var _fetch=window.fetch;window.fetch=function(u,o){o=o||{};o.headers=o.headers||{};"
        "o.headers['X-CSRF']=CSRF;return _fetch(u,o);};"
        "var RT=null;"
        "function showTab(id){"
        "document.querySelectorAll('.tab').forEach(function(e){e.classList.remove('active')});"
        "document.querySelectorAll('.tabs button').forEach(function(e){e.classList.remove('active')});"
        "document.getElementById('tab-'+id).classList.add('active');"
        "document.getElementById('btn-'+id).classList.add('active');"
        "location.hash=id;"
        /* sessionStorage as well as the hash: belt and braces, so the tab
         * survives even a navigation that drops the fragment. */
        "try{sessionStorage.setItem('tab',id);}catch(e){}"
        "schedRefresh();"
        "}"
        /* Only the Dashboard shows live counters, so only the Dashboard needs
         * reloading. On the config tabs a reload is pure harm — it would throw
         * away whatever you were typing. location.reload() keeps the fragment,
         * unlike the <meta refresh> this replaced. */
        "function schedRefresh(){"
        "if(RT){clearTimeout(RT);RT=null;}"
        "var a=document.querySelector('.tab.active');"
        "if(a&&a.id=='tab-dashboard'){RT=setTimeout(function(){location.reload();},10000);}"
        "}"
        "window.onload=function(){"
        "var id=location.hash?location.hash.substring(1):'';"
        "if(!id){try{id=sessionStorage.getItem('tab')||'';}catch(e){id='';}}"
        "if(!id||!document.getElementById('tab-'+id))id='dashboard';"
        "showTab(id);"
        "}"
        "</script>"
        "</head><body>"
        "<div style='display:flex;justify-content:space-between;align-items:baseline'>"
        "<h2>ESP32 AdBlocker</h2>"
        "<form method=post action=/logout><button>Sign out</button></form></div>"
        "<div class=tabs>"
        "<button id=btn-dashboard onclick=\"showTab('dashboard')\">Dashboard</button>"
        "<button id=btn-blocklist onclick=\"showTab('blocklist')\">Blocklist</button>"
        "<button id=btn-network onclick=\"showTab('network')\">Network</button>"
        "<button id=btn-access onclick=\"showTab('access')\">Access</button>"
        "<button id=btn-upstream onclick=\"showTab('upstream')\">Upstream DNS</button>"
        "</div>"
        "<div class='tab' id=tab-dashboard>", csrf);
    float pct = total > 0 ? 100.0f * (float)blocked / (float)total : 0.0f;
    /* F9: this chip had a DUPLICATE class attribute (class=val class='%s') —
     * HTML keeps only the first, so the ok/warn class never actually applied.
     * Merged into one. It also only ever said "Active": overflow/feed-failure
     * warnings lived solely on the hidden, never-auto-refreshing Blocklist
     * tab, so this auto-refreshing Dashboard could show "Active" indefinitely
     * on a degraded box. Reloading still wins over Degraded — it's the more
     * urgent, and more likely transient, state. */
    bool degraded = (bl_dropped > 0) || (bl_feed_fail > 0);
    /* Paused ranks above Degraded: it's a deliberate user action, not an
     * incidental condition, so it should never be silently masked by a stale
     * "Degraded" chip left over from before blocking was paused. Loading still
     * wins over both — it's transient and self-clears. */
    const char *status_cls = loading ? "warn" : (paused ? "warn" : (degraded ? "warn" : "ok"));
    const char *status_txt = loading ? "Reloading" : (paused ? "Paused" : (degraded ? "Degraded" : "Active"));
    page_appendf(page, sizeof(page), &n,
        "<div class=stats>"
        "<div class=stat><div class=val>%" PRIu32 "</div><div class=lbl>Domains</div></div>"
        "<div class=stat><div class=val>%" PRIu32 "</div><div class=lbl>Queries</div></div>"
        "<div class=stat><div class=val>%" PRIu32 "</div><div class=lbl>Blocked</div></div>"
        "<div class=stat><div class=val>%.1f%%</div><div class=lbl>Block rate</div></div>"
        "<div class=stat><div class='val %s'>%s</div><div class=lbl>Status</div></div>"
        "</div>",
        domains, total, blocked, pct,
        status_cls, status_txt);

    if (dns_sink_setup_ap_active()) {
        page_appendf(page, sizeof(page), &n,
            "<p style='background:#fff3cd;border:1px solid #ffe08a;border-radius:6px;"
            "padding:.6em 1em'><b>Setup AP active</b> — no Ethernet or Wi-Fi link yet. "
            "Join \"ESP32AdBlock-Setup\" (WPA2 passphrase printed on the USB console) and browse "
            "<b>https://192.168.4.1</b> to enter real Wi-Fi credentials in the Network tab; "
            "this AP shuts off automatically once a link comes up.</p>");
    }
    page_appendf(page, sizeof(page), &n,
        "<h3>Actions</h3>"
        "<form method=post action=/reload><button>Reload blocklist</button></form><br>");
    if (loading) {
        page_appendf(page, sizeof(page), &n,
            "<form method=post action=/blocklist/stop>"
            "<button>Stop load</button></form><br>");
    }
    page_appendf(page, sizeof(page), &n,
        "<form method=post action=/pause>"
        "<input type=hidden name=on value=%d>"
        "<button>%s</button></form><br>"
        "<form method=post action=/check>"
        "<input name=domain placeholder='Check domain' size=40>"
        "<button>Check</button></form><br>"
        "<form method=post action=/whitelist/add>"
        "<input name=domain placeholder='Add to whitelist' size=40>"
        "<button>Whitelist</button></form>"
        "<p><small>Blocked but not on any list? Hash collisions false-positive "
        "roughly 1 domain in 350,000. Whitelisting is the fix &mdash; it is checked "
        "ahead of the blocklist.</small></p>"
        "<a href='/log'>Query log</a> &nbsp; <a href='/top'>Top lists</a>"
        " &nbsp; <a href='/metrics'>Metrics JSON</a>"
        "<p><small>This tab auto-refreshes every 10s; the other tabs don't, so "
        "they won't reload while you're editing.</small></p>",
        paused ? 0 : 1, paused ? "Resume blocking" : "Pause blocking");

    /* Clock status (NTP) */
    {
        uint32_t ep = timesync_epoch();
        if (ep) {
            time_t t = (time_t)ep;
            struct tm tmv; gmtime_r(&t, &tmv);
            char tbuf[32]; strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", &tmv);
            page_appendf(page, sizeof(page), &n,
                "<p><small>Clock: <b>%s UTC</b> (NTP synced)</small></p>", tbuf);
        } else {
            /* #75: not synced no longer means the clock reads 1970 — a floor
             * from NVS or the build stamp is in place, which is what lets TLS
             * certificate dates be checked at all this early. Say which,
             * because "syncing…" alone gave no way to tell a floored box from
             * one whose TLS is about to fail every handshake. */
            time_t fl = time(NULL);
            struct tm tmv; gmtime_r(&fl, &tmv);
            char fbuf[16]; strftime(fbuf, sizeof(fbuf), "%Y-%m-%d", &tmv);
            page_appendf(page, sizeof(page), &n,
                "<p><small>Clock: <span class=warn>syncing via NTP…</span> "
                "running on the <b>%s</b> clock (%s) — good enough for TLS "
                "certificate dates, not for timestamps, so the log shows "
                "uptime until synced.</small></p>",
                timesync_source(), fbuf);
        }
    }
    page_appendf(page, sizeof(page), &n, "</div><div class='tab' id=tab-blocklist>");

    /* whitelist table */
    if (wl_n > 0) {
        page_appendf(page, sizeof(page), &n,
            "<h3>Whitelist</h3><table>"
            "<tr><th>Domain</th><th>Action</th></tr>");
        static EXT_RAM_BSS_ATTR char wl[WHITELIST_MAX][64]; uint32_t cnt = WHITELIST_MAX;
        blocklist_whitelist_get(wl, &cnt);
        for (uint32_t i = 0; i < cnt && n < (int)sizeof(page) - 256; i++) {
            char safe_text[384], safe_attr[384];
            html_escape(safe_text, sizeof(safe_text), wl[i]);
            html_escape(safe_attr, sizeof(safe_attr), wl[i]);
            page_appendf(page, sizeof(page), &n,
                "<tr><td>%s</td><td>"
                "<form method=post action=/whitelist/remove>"
                "<input type=hidden name=domain value=\"%s\">"
                "<button>Remove</button></form></td></tr>",
                safe_text, safe_attr);
        }
        page_appendf(page, sizeof(page), &n, "</table>");
    }

    /* Custom block rules (#14) */
    {
        static EXT_RAM_BSS_ATTR char crules[CUSTOM_RULES_CAP + 8];
        static EXT_RAM_BSS_ATTR char safe_cr[CUSTOM_RULES_CAP * 2 + 8];
        size_t clen = blocklist_custom_get(crules, sizeof(crules));
        html_escape(safe_cr, sizeof(safe_cr), crules);
        page_appendf(page, sizeof(page), &n,
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
        page_appendf(page, sizeof(page), &n,
            "<h3>Local hosts &amp; DNS rewrites</h3>"
            "<p><small>Static name → IP. A bare hostname (<code>printer</code>) or a "
            "domain (<code>nas.lan</code>); a domain also covers its subdomains. "
            "Answered locally for A queries, never forwarded. Up to %d.</small></p>"
            "<form method=post action=/rewrite/set>"
            "<input name=domain placeholder='printer or nas.lan' size=24>"
            " → <input name=ip placeholder='192.168.1.x' size=16>"
            "<button>Add</button></form>", REWRITE_MAX);
        if (rw_n > 0) {
            static EXT_RAM_BSS_ATTR char rw_domains[REWRITE_MAX][64]; static EXT_RAM_BSS_ATTR uint32_t rw_ips[REWRITE_MAX]; uint32_t rw_cnt = REWRITE_MAX;
            rewrite_list(rw_domains, rw_ips, &rw_cnt);
            page_appendf(page, sizeof(page), &n, "<table><tr><th>Domain</th><th>IP</th><th>Action</th></tr>");
            for (uint32_t i = 0; i < rw_cnt && n < (int)sizeof(page) - 256; i++) {
                char safe_d[128]; html_escape(safe_d, sizeof(safe_d), rw_domains[i]);
                char safe_da[128]; html_escape(safe_da, sizeof(safe_da), rw_domains[i]);
                uint32_t ip = rw_ips[i];
                page_appendf(page, sizeof(page), &n,
                    "<tr><td>%s</td><td>%u.%u.%u.%u</td><td>"
                    "<form method=post action=/rewrite/clear>"
                    "<input type=hidden name=domain value=\"%s\">"
                    "<button>Remove</button></form></td></tr>",
                    safe_d,
                    (unsigned)((ip>>24)&0xFF),(unsigned)((ip>>16)&0xFF),
                    (unsigned)((ip>>8)&0xFF),(unsigned)(ip&0xFF),
                    safe_da);
            }
            page_appendf(page, sizeof(page), &n, "</table>");
        }
    }

    /* Blocklist sources section (#4, #9) */
    page_appendf(page, sizeof(page), &n,
        "<h3>Blocklist Sources</h3>"
        "<table><tr><th>#</th><th>URL</th><th>Status</th><th>Action</th></tr>"
        "<tr><td>0 (primary)</td><td>%s</td><td class='ok'>enabled</td><td>built-in</td></tr>",
        BLOCKLIST_URL);
    int free_slot = -1;
    for (int i = 0; i < BLOCKLIST_EXTRA_MAX && n < (int)sizeof(page) - 512; i++) {
        char url[BLOCKLIST_URL_CAP]; blocklist_extra_url_get(i, url, sizeof(url));
        if (url[0]) {
            char safe_url[BLOCKLIST_URL_CAP * 2]; html_escape(safe_url, sizeof(safe_url), url);
            bool en = blocklist_extra_enabled_get(i);
            page_appendf(page, sizeof(page), &n,
                "<tr><td>%d</td><td>%s</td><td class='%s'>%s</td><td>"
                "<form method=post action=/blocklist/url/toggle style='display:inline'>"
                "<input type=hidden name=idx value=%d>"
                "<button>%s</button></form> "
                "<form method=post action=/blocklist/url/clear style='display:inline'>"
                "<input type=hidden name=idx value=%d>"
                "<button>Remove</button></form></td></tr>",
                i + 1, safe_url, en ? "ok" : "warn", en ? "enabled" : "disabled",
                i, en ? "Disable" : "Enable", i);
        } else {
            if (free_slot < 0) free_slot = i;
            page_appendf(page, sizeof(page), &n,
                "<tr><td>%d (empty)</td><td>"
                "<form method=post action=/blocklist/url/set style='display:inline'>"
                "<input type=hidden name=idx value=%d>"
                "<input name=url placeholder='https://...' size=50>"
                "<button>Add</button></form></td><td></td><td></td></tr>",
                i + 1, i);
        }
    }
    page_appendf(page, sizeof(page), &n, "</table>");

    /* F11: this one gate has to cover everything from here to the closing
     * markup — presets below, the overflow banner, the feed-failure line, the
     * capacity note, and the whole Access/Network/Upstream tabs — measured
     * 4.9-6.9 KB post-preset on a fully populated device. The old 2048 B
     * reserve badly under-counted that and was reachable at ~8% of max config:
     * page_appendf clamps silently (H1) on overflow, which with this tabbed
     * layout truncates mid-markup and presents as dead tabs (#60) rather than
     * a visible error. The banner/note gates further down are a second,
     * tighter layer of the same guard: best-effort, not a proof nothing past
     * them can ever clamp, but they turn "silent" into "visible" wherever they
     * do catch it. */
    if (n < (int)sizeof(page) - 7168) {
        /* F12: everything below except tif.medium is the lossless domains/ ->
         * wildcard/ FORMAT change — identical coverage under our suffix-walk
         * matching, just a smaller encoding of the same list. tif.medium is
         * different in kind: hagezi's deliberately REDUCED TIER of TIF, not
         * full TIF in a cheaper encoding (full domains/tif.txt is ~2.1M lines
         * and can never fit BLOCKLIST_CAPACITY) — labeled explicitly so that
         * distinction doesn't get lost again. Counts are 2026-08 snapshots. */
        static const char *HAGEZI_BASE =
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/";
        /* F13: adult-content filtering had no discoverable UI entry after the
         * domains/ cleanup dropped nsfw.oisd.nl with no replacement. No entry
         * count shown — oisd.nl doesn't publish one for this list. */
        static const char *NSFW_URL = "https://nsfw.oisd.nl/domainswild2";
        static const struct { const char *ref, *label; bool full_url; } presets[] = {
            { "tif.medium.txt", "TIF medium — threat intel (~326k)", false },
            { "light.txt",      "Light (~42k)",                       false },
            { "multi.txt",      "Normal (~190k)",                     false },
            { "pro.txt",        "Pro (~226k)",                        false },
            { "pro.plus.txt",   "Pro++ (~250k)",                      false },
            { "ultimate.txt",   "Ultimate (~269k)",                   false },
            { NSFW_URL,         "OISD NSFW (adult)",                  true  },
        };
        if (free_slot >= 0) {
            page_appendf(page, sizeof(page), &n,
                "<form method=post action=/blocklist/url/set>"
                "<input type=hidden name=idx value=%d>"
                "<select name=url><option value=''>hagezi preset&hellip;</option>", free_slot);
            for (size_t i = 0; i < sizeof(presets)/sizeof(presets[0]); i++) {
                if (presets[i].full_url)
                    page_appendf(page, sizeof(page), &n,
                        "<option value='%s'>%s</option>", presets[i].ref, presets[i].label);
                else
                    page_appendf(page, sizeof(page), &n,
                        "<option value='%s%s'>%s</option>",
                        HAGEZI_BASE, presets[i].ref, presets[i].label);
            }
            page_appendf(page, sizeof(page), &n, "</select> <button>Add preset</button></form>");
        } else {
            /* F14: this dropdown is the only place any hagezi (or nsfw) URL
             * appears in the UI, and it used to vanish entirely once all extra
             * slots filled — exactly when the overflow banner just below is
             * telling the user to "remove a source or pick smaller lists"
             * with nowhere left to paste a replacement. Give the copyable
             * base URL + file names so removing a feed (table above) and
             * adding a smaller one doesn't need the README or GitHub open. */
            page_appendf(page, sizeof(page), &n,
                "<p><small>All %d extra source slots are full — remove one above, "
                "then paste a preset URL: base <code>%s</code> + one of ",
                BLOCKLIST_EXTRA_MAX, HAGEZI_BASE);
            bool first = true;
            for (size_t i = 0; i < sizeof(presets)/sizeof(presets[0]); i++) {
                if (presets[i].full_url) continue;
                page_appendf(page, sizeof(page), &n, "%s<code>%s</code>",
                    first ? "" : ", ", presets[i].ref);
                first = false;
            }
            page_appendf(page, sizeof(page), &n,
                ". Adult filtering: <code>%s</code>.</small></p>", NSFW_URL);
        }
    } else {
        page_mark_truncated(page, sizeof(page), &n);
    }

    /* F11: second layer — banner + the new feed-failure line, guarded on
     * their own so a squeeze here degrades to a visible marker rather than a
     * silent clamp even if the outer 7168 reserve above ever proves optimistic. */
    if (n < (int)sizeof(page) - 7168) {
        if (bl_dropped > 0)
            page_appendf(page, sizeof(page), &n,
                "<p class=warn><b>&#9888; Last reload overflowed the %uk-entry buffer: "
                "%" PRIu32 " entries dropped — blocking is incomplete.</b> "
                "Remove a source or pick smaller lists.</p>",
                (unsigned)(BLOCKLIST_CAPACITY / 1000), bl_dropped);
        /* blocklist_feed_failures(): a feed that hard-failed to download is a
         * different failure than capacity overflow above — entries it never
         * got to attempt, not entries it fetched and then discarded. */
        if (bl_feed_fail > 0)
            page_appendf(page, sizeof(page), &n,
                "<p class=warn>&#9888; %" PRIu32 " source feed(s) failed to download on "
                "the last reload — the live list is missing their entries.</p>",
                bl_feed_fail);
    } else {
        page_mark_truncated(page, sizeof(page), &n);
    }

    if (n < (int)sizeof(page) - 6144) {
        page_appendf(page, sizeof(page), &n,
            "<p><small>After adding/removing a source, click <b>Reload blocklist</b> above. "
            "Any http(s) list in plain, hosts, adblock or *.wildcard format works. All sources "
            "combined are capped at %uk entries after dedup vs primary; OISD uses ~270k of that. "
            "For hagezi use the <code>wildcard/</code> files, never <code>domains/</code>.</small></p>",
            (unsigned)(BLOCKLIST_CAPACITY / 1000));
    } else {
        page_mark_truncated(page, sizeof(page), &n);
    }

    page_appendf(page, sizeof(page), &n, "</div><div class='tab' id=tab-access>");

    /* Client ACL section (#10) */
    {
        char acl_ips[ACL_MAX][20]; uint32_t acl_n = ACL_MAX;
        acl_list(acl_ips, &acl_n);
        page_appendf(page, sizeof(page), &n,
            "<h3>Client Access Control</h3>"
            "<p><small>Empty = allow all. If any IP is listed, only those clients may resolve new names. "
            "Note: on Ethernet, blocked and already-cached answers are served by the L2 fast path, "
            "which does not check this list.</small></p>"
            "<form method=post action=/acl/add>"
            "<input name=ip placeholder='192.168.x.x' size=18>"
            "<button>Add allowed client</button></form>");
        if (acl_n > 0) {
            page_appendf(page, sizeof(page), &n, "<table><tr><th>Allowed client IP</th><th>Action</th></tr>");
            for (uint32_t i = 0; i < acl_n && n < (int)sizeof(page) - 256; i++) {
                char safe_ip[48]; html_escape(safe_ip, sizeof(safe_ip), acl_ips[i]);
                char safe_ipv[48]; html_escape(safe_ipv, sizeof(safe_ipv), acl_ips[i]);
                page_appendf(page, sizeof(page), &n,
                    "<tr><td>%s</td><td>"
                    "<form method=post action=/acl/remove>"
                    "<input type=hidden name=ip value=\"%s\">"
                    "<button>Remove</button></form></td></tr>",
                    safe_ip, safe_ipv);
            }
            page_appendf(page, sizeof(page), &n, "</table>"
                "<form method=post action=/acl/clear style='margin-top:.5em'>"
                "<button>Clear all (allow everyone)</button></form>");
        }
    }

    /* Admin account (#89) — always on; changing it signs every session out. */
    {
        char user[WEB_AUTH_USER_MAX + 1]; web_auth_get_user(user, sizeof(user));
        char safe_user[80]; html_escape(safe_user, sizeof(safe_user), user);
        char fp[96]; web_tls_fingerprint(fp, sizeof(fp));
        page_appendf(page, sizeof(page), &n,
            "<h3>Admin account</h3>"
            "<p>Signed in as <b>%s</b>. Sessions expire after 30 min idle / 12 h.</p>"
            "<form method=post action=/auth/set>"
            "<input name=cur type=password placeholder='current password' size=18 autocomplete=current-password> "
            "<input name=user placeholder='username' size=12 value=\"%s\" maxlength=%d> "
            "<input name=pass type=password placeholder='new password (%d+ chars)' size=22 autocomplete=new-password>"
            "<button>Change</button></form>"
            "<p><small>Lost password: USB console <code>admin-reset</code>.</small></p>"
            "<h3>TLS certificate</h3>"
            "<p><small>Self-signed, generated on this device. SHA-256 fingerprint:</small><br>"
            "<code style='word-break:break-all'>%s</code></p>",
            safe_user, safe_user, WEB_AUTH_USER_MAX, WEB_AUTH_PASS_MIN, fp);
    }

    page_appendf(page, sizeof(page), &n, "</div><div class='tab' id=tab-network>");

    /* Dual-WAN interface selection (#53) */
    if (dns_sink_wifi_built()) {
        char iface[8]="", eth_ip[16]="", wifi_ip[16]="";
        dns_sink_net_status(iface, sizeof(iface), eth_ip, sizeof(eth_ip), wifi_ip, sizeof(wifi_ip));
        page_appendf(page, sizeof(page), &n,
            "<h3>Network Interfaces</h3>"
            "<p>Ethernet: %s &nbsp; Wi-Fi: %s</p>"
            "<p><small>Both stay up together. This chooses which one egresses "
            "upstream resolver queries; LAN clients can query either IP either way.</small></p>"
            "<form method=post action=/net/upstream>"
            "<label><input type=radio name=iface value=eth%s> Ethernet</label> "
            "<label><input type=radio name=iface value=wifi%s> Wi-Fi</label> "
            "<button>Set upstream interface</button></form>",
            eth_ip[0] ? eth_ip : "(down)", wifi_ip[0] ? wifi_ip : "(down)",
            strcmp(iface, "eth") == 0 ? " checked" : "",
            strcmp(iface, "wifi") == 0 ? " checked" : "");
    }

    /* DHCP vs static IP, per interface (#55). Saved to NVS; takes effect on
     * next reboot (see apply_static_ip in dns_sink.cpp for why this isn't
     * hot-applied). */
    {
        const char *ifaces[2] = { "eth", "wifi" };
        const char *labels[2] = { "Ethernet", "Wi-Fi" };
        for (int i = 0; i < (dns_sink_wifi_built() ? 2 : 1); i++) {
            bool dhcp = true; char ip[16]="", nm[16]="", gw[16]="", dns_ip[16]="";
            dns_sink_net_get_static(ifaces[i], &dhcp, ip, sizeof(ip), nm, sizeof(nm),
                                     gw, sizeof(gw), dns_ip, sizeof(dns_ip));
            /* Under DHCP prefill the form with the live lease, not whatever
             * strings a past dhcp-mode Save left in NVS (those are saved
             * unvalidated — dns_sink_net_set_static only inet_aton-checks in
             * static mode). "Go static, keep this address" becomes: pick
             * Static, Save. Saved static config still shows as-is — it's the
             * authoritative pending config. */
            if (dhcp)
                dns_sink_net_get_current(ifaces[i], ip, sizeof(ip), nm, sizeof(nm),
                                          gw, sizeof(gw), dns_ip, sizeof(dns_ip));
            page_appendf(page, sizeof(page), &n,
                "<h3>%s: DHCP / Static IP</h3>"
                "<form method=post action=/net/%s/set>"
                "<label><input type=radio name=mode value=dhcp%s> DHCP</label> "
                "<label><input type=radio name=mode value=static%s> Static</label><br>"
                "IP: <input name=ip value=\"%s\" placeholder='192.168.1.50' size=16> "
                "Netmask: <input name=nm value=\"%s\" placeholder='255.255.255.0' size=16><br>"
                "Gateway: <input name=gw value=\"%s\" placeholder='192.168.1.1' size=16> "
                "DNS: <input name=dns value=\"%s\" placeholder='192.168.1.1' size=16><br>"
                "<button>Save</button>"
                "<small> — requires reboot to take effect</small></form>",
                labels[i], ifaces[i],
                dhcp ? " checked" : "", dhcp ? "" : " checked",
                ip, nm, gw, dns_ip);
        }
        page_appendf(page, sizeof(page), &n,
            "<form method=post action=/reboot style='margin-top:.5em'>"
            "<button>Reboot now</button></form>");
    }

    /* Firmware update (#1) — mirrors upstream's OTA Upload tab */
    {
        const esp_partition_t *running = esp_ota_get_running_partition();
        page_appendf(page, sizeof(page), &n,
            "<h3>Firmware Update</h3>"
            "<p><small>Running from: <b>%s</b>. Pick a merged firmware .bin "
            "(built with idf.py build, or a release asset) and upload — no "
            "toolchain or serial cable needed. If the new image never comes "
            "back up cleanly, it auto-reverts to this slot.</small></p>"
            "<input type=file id=ota-file accept='.bin'> "
            "<button type=button onclick=\"otaUpload()\">Upload &amp; apply</button>"
            "<span id=ota-status></span>"
            "<script>"
            "function otaUpload(){"
            "var f=document.getElementById('ota-file').files[0];"
            "if(!f){document.getElementById('ota-status').textContent=' pick a file first';return;}"
            "document.getElementById('ota-status').textContent=' uploading\xe2\x80\xa6';"
            "fetch('/ota/update',{method:'POST',body:f})"
            ".then(function(r){if(!r.ok)return r.text().then(function(t){throw new Error(t)});"
            "document.getElementById('ota-status').textContent=' applied, rebooting\xe2\x80\xa6';})"
            ".catch(function(e){document.getElementById('ota-status').textContent=' failed: '+e.message;});"
            "}"
            "</script>",
            running ? running->label : "?");
    }

    /* Wi-Fi scan + reconfigure (#54) */
    if (dns_sink_wifi_built()) {
        char ssid[33] = ""; dns_sink_wifi_get_ssid(ssid, sizeof(ssid));
        char safe_ssid[80]; html_escape(safe_ssid, sizeof(safe_ssid), ssid);
        page_appendf(page, sizeof(page), &n,
            "<h3>Wi-Fi</h3>"
            "<p>Currently configured SSID: <b>%s</b></p>"
            "<button type=button onclick=\"wifiScan()\">Scan for networks</button>"
            "<span id=wifi-scan-status></span>"
            "<ul id=wifi-results></ul>"
            "<form method=post action=/wifi/connect>"
            "<input id=wifi-ssid name=ssid placeholder='SSID' size=24> "
            "<input id=wifi-pass name=password placeholder='Password' size=24 type=password> "
            "<button>Connect</button></form>"
            "<script>"
            "function wifiStat(t){document.getElementById('wifi-scan-status').textContent=t;}"
            /* Trigger only — the scan runs in a worker task on the device, so
             * this returns straight away and other viewers aren't blocked. */
            "function wifiScan(){wifiStat(' starting\xe2\x80\xa6');"
            "fetch('/wifi/scan',{method:'POST'}).then(function(r){return r.json()})"
            ".then(function(d){if(d.state=='error'){wifiStat(' '+(d.err||'scan failed'));return;}"
            "setTimeout(wifiPoll,600);})"
            ".catch(function(){wifiStat(' scan failed');});}"
            /* Poll the cached result until the worker publishes it. */
            "function wifiPoll(){"
            "fetch('/wifi/scan').then(function(r){return r.json()}).then(function(d){"
            "if(d.state=='scanning'){wifiStat(' scanning\xe2\x80\xa6');setTimeout(wifiPoll,800);return;}"
            "if(d.state=='error'){wifiStat(' '+(d.err||'scan failed'));return;}"
            "wifiRender(d);})"
            ".catch(function(){wifiStat(' scan failed');});}"
            "function wifiRender(d){"
            "var ul=document.getElementById('wifi-results');ul.innerHTML='';"
            "if(d.state!='done'){wifiStat('');return;}"
            "wifiStat(' '+d.aps.length+' found'+(d.age_s>=0?' ('+d.age_s+'s ago)':''));"
            "d.aps.forEach(function(ap){"
            "var li=document.createElement('li');"
            "var btn=document.createElement('button');btn.type='button';"
            "btn.textContent=ap.ssid+' ('+ap.rssi+' dBm)'+(ap.auth==0?' [open]':'');"
            "btn.onclick=function(){document.getElementById('wifi-ssid').value=ap.ssid;"
            "document.getElementById('wifi-pass').focus();};"
            "li.appendChild(btn);ul.appendChild(li);});}"
            /* Repopulate from the device-side cache on load, so the 10s
             * meta-refresh doesn't wipe results out from under you. */
            "wifiPoll();"
            "</script>",
            safe_ssid);
    }
    page_appendf(page, sizeof(page), &n, "</div><div class='tab' id=tab-upstream>");

    /* DoT upstream settings (#5) */
    {
        bool dot_en = dot_is_enabled(); char dot_srv[64]="", dot_sni[64]="";
        dot_get(nullptr, dot_srv, dot_sni);
        page_appendf(page, sizeof(page), &n,
            "<h3>Upstream DNS (DoT)</h3>"
            "<form method=post action=/dot/set>"
            "<label><input type=checkbox name=enabled value=1%s> Enable DNS-over-TLS</label><br>"
            "Server IP: <input name=server value=\"%s\" size=18> "
            "SNI: <input name=sni value=\"%s\" size=28><br>"
            "<small>Default: 1.1.1.1 / one.one.one.one &nbsp; or &nbsp; 9.9.9.9 / dns.quad9.net</small><br>"
            "<button>Save &amp; apply (restart DNS task)</button></form>",
            dot_en ? " checked" : "", dot_srv, dot_sni);

        /* Split-horizon zones: names the router answers, never sent over DoT. */
        char zones[LOCALZONE_LIST_CAP]; localzone_get(zones, sizeof(zones));
        char safe_zones[LOCALZONE_LIST_CAP * 2]; html_escape(safe_zones, sizeof(safe_zones), zones);
        page_appendf(page, sizeof(page), &n,
            "<h3>Local zones</h3>"
            "<p><small>Names in these zones &mdash; and any name with no dot at all &mdash; are "
            "resolved through your router in plain DNS even when DoT is on, because "
            "a public resolver has never heard of <code>nas.lan</code>. Comma-separated "
            "suffixes.</small></p>"
            "<form method=post action=/dot/zones>"
            "<input name=zones value=\"%s\" size=52 maxlength=%d> "
            "<button>Save</button></form>"
            "<p><small>Default: <code>%s</code></small></p>",
            safe_zones, LOCALZONE_LIST_CAP - 1, localzone_default());
    }
    page_appendf(page, sizeof(page), &n, "</div>");

    page_appendf(page, sizeof(page), &n, "</body></html>");
    if (n >= (int)sizeof(page) - 1)
        ESP_LOGW(TAG, "status page hit the %u B cap — markup truncated, tabs "
                      "may not render; raise page[]", (unsigned)sizeof(page));
    send_html(r, page);
    return ESP_OK;
}

/* ── GET /metrics — JSON telemetry ───────────────────────────────── */
static esp_err_t handle_metrics(httpd_req_t *r)
{
    static EXT_RAM_BSS_ATTR char json[2048];
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

/* ── POST /blocklist/stop — abort an in-progress load (#1, upstream xStop) */
static esp_err_t handle_bl_stop(httpd_req_t *r)
{
    if (!csrf_ok(r)) {
        httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "CSRF"); return ESP_FAIL;
    }
    blocklist_stop_load();
    httpd_resp_set_status(r, "303 See Other");
    httpd_resp_set_hdr(r, "Location", "/");
    httpd_resp_send(r, nullptr, 0);
    return ESP_OK;
}

/* ── POST /pause — global block/allow-all toggle, mirrors upstream
 * ESP32_AdBlocker's "Enable AdBlocker" switch ────────────────────── */
static esp_err_t handle_pause(httpd_req_t *r)
{
    if (!csrf_ok(r)) {
        httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "CSRF"); return ESP_FAIL;
    }
    char body[16] = {}; httpd_req_recv(r, body, sizeof(body) - 1);
    blocklist_set_paused(strstr(body, "on=1") != nullptr);
    httpd_resp_set_status(r, "303 See Other");
    httpd_resp_set_hdr(r, "Location", "/");
    httpd_resp_send(r, nullptr, 0);
    return ESP_OK;
}

/* ── POST /auth/set — change the admin account (#1, #89) ──────────
 * Requires the current password: a session cookie left in a browser must
 * not be enough to take the account over. Success drops every session
 * (including this one), so the user lands on the login page. */
static esp_err_t handle_auth_set(httpd_req_t *r)
{
    if (!csrf_ok(r)) {
        httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "CSRF"); return ESP_FAIL;
    }
    char body[512] = {}; httpd_req_recv(r, body, sizeof(body) - 1);   /* 3 x 63 chars, worst-case %XX encoded, fits */
    char cur[WEB_AUTH_PASS_MAX + 2], user[WEB_AUTH_USER_MAX + 2], pass[WEB_AUTH_PASS_MAX + 2];
    form_field(body, "cur",  cur,  sizeof(cur));
    form_field(body, "user", user, sizeof(user));
    form_field(body, "pass", pass, sizeof(pass));
    memset(body, 0, sizeof(body));

    char cur_user[WEB_AUTH_USER_MAX + 1]; web_auth_get_user(cur_user, sizeof(cur_user));
    int retry = 0;
    bool ok = web_auth_check_password(cur_user, cur, &retry);
    memset(cur, 0, sizeof(cur));
    if (!ok) {
        memset(pass, 0, sizeof(pass));
        httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, retry ? "Locked out — wait a minute" : "Current password is wrong");
        return ESP_FAIL;
    }
    ok = web_auth_set_credentials(user, pass);
    memset(pass, 0, sizeof(pass));
    if (!ok) {
        httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, "Username 1-31 printable chars (no ':'), password 10-63 chars");
        return ESP_FAIL;
    }
    clear_session_cookie(r);
    redirect_to(r, "/login");
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
    /* Match the real verdict path (dns_server.cpp): main list OR custom rules.
     * Previously checked only the main list, so a domain blocked solely by a
     * custom rule showed ALLOWED here even though it was genuinely sinkholed
     * on the wire — the tool meant to verify a rule couldn't verify its own
     * kind of rule. */
    bool blocked = (nlen > 0) &&
        (blocklist_is_blocked(norm, nlen) || blocklist_custom_is_blocked(norm, nlen));

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

/* ── POST /dot/zones — local zones forwarded to the router, never DoT ── */
static esp_err_t handle_dot_zones(httpd_req_t *r)
{
    if (!csrf_ok(r)) { httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "CSRF"); return ESP_FAIL; }
    char body[LOCALZONE_LIST_CAP * 3 + 16] = {}; httpd_req_recv(r, body, sizeof(body) - 1);
    char zones[LOCALZONE_LIST_CAP]; form_field(body, "zones", zones, sizeof(zones));
    if (!localzone_set(zones)) {
        httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, "Up to 16 suffixes, letters/digits/dots, comma-separated");
        return ESP_FAIL;
    }
    redirect_to(r, "/#upstream");
    return ESP_OK;
}

/* ── POST /net/upstream — choose eth/wifi as upstream egress (#53) ── */
static esp_err_t handle_net_upstream(httpd_req_t *r)
{
    if (!csrf_ok(r)) { httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "CSRF"); return ESP_FAIL; }
    char body[32] = {}; httpd_req_recv(r, body, sizeof(body) - 1);
    const char *iface = strstr(body, "iface=wifi") ? "wifi" : "eth";
    dns_sink_set_upstream_iface(iface);
    httpd_resp_set_status(r, "303 See Other"); httpd_resp_set_hdr(r, "Location", "/"); httpd_resp_send(r,nullptr,0); return ESP_OK;
}

/* ── POST /net/{eth,wifi}/set — DHCP vs static IP (#55) ──────────────
 * Persists to NVS only; takes effect on the next boot (see apply_static_ip
 * in dns_sink.cpp for why this isn't hot-applied to a running netif). */
static esp_err_t handle_net_static_set(httpd_req_t *r, const char *iface)
{
    if (!csrf_ok(r)) { httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "CSRF"); return ESP_FAIL; }
    char body[256] = {}; httpd_req_recv(r, body, sizeof(body) - 1);
    bool dhcp = (strstr(body, "mode=dhcp") != nullptr);
    char ip[16]="", nm[16]="", gw[16]="", dns_ip[16]="";
    struct { const char *key; char *out; size_t cap; } fields[] = {
        {"ip=", ip, sizeof(ip)}, {"nm=", nm, sizeof(nm)},
        {"gw=", gw, sizeof(gw)}, {"dns=", dns_ip, sizeof(dns_ip)},
    };
    for (auto &f : fields) {
        const char *p = strstr(body, f.key);
        if (!p) continue;
        p += strlen(f.key);
        size_t l = 0; char raw[32] = {0};
        for (; p[l] && p[l] != '&' && p[l] != '\r' && l < 31; l++) raw[l] = p[l];
        url_decode(f.out, f.cap, raw, l);
    }
    if (!dns_sink_net_set_static(iface, dhcp, ip, nm, gw, dns_ip)) {
        httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, "Invalid IP/netmask/gateway/DNS");
        return ESP_FAIL;
    }
    httpd_resp_set_status(r, "303 See Other"); httpd_resp_set_hdr(r, "Location", "/#network"); httpd_resp_send(r,nullptr,0); return ESP_OK;
}
static esp_err_t handle_net_eth_set(httpd_req_t *r)  { return handle_net_static_set(r, "eth"); }
static esp_err_t handle_net_wifi_set(httpd_req_t *r) { return handle_net_static_set(r, "wifi"); }

/* ── POST /reboot — apply a saved static-IP change (#55) ─────────── */
static esp_err_t handle_reboot(httpd_req_t *r)
{
    if (!csrf_ok(r)) { httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "CSRF"); return ESP_FAIL; }
    send_html(r, "<!DOCTYPE html><html><body><h2>Rebooting…</h2>"
                 "<p>Reconnecting in ~10s. <a href='/'>Back</a> (once it's up).</p></body></html>");
    vTaskDelay(pdMS_TO_TICKS(300));   /* let the response flush before the reset */
    dns_sink_reboot();
    return ESP_OK;
}

/* ── POST /ota/update — browser-driven firmware update (#1) ─────────
 * Mirrors upstream ESP32_AdBlocker's "OTA Upload" tab: no toolchain needed
 * to update a device already in the field. Raw firmware bytes as the POST
 * body (the UI form sends the picked File object directly via fetch, not
 * multipart — the simplest thing that streams straight into esp_ota_write
 * with no parsing on this side). Written to whichever OTA slot ISN'T
 * currently running (esp_ota_get_next_update_partition), then that slot is
 * marked bootable and the board reboots into it. If it never comes back up
 * cleanly, CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE auto-reverts to the slot
 * that was running before this request — the load-bearing safety net, since
 * this device has no display for a stuck-boot indicator. */
static esp_err_t handle_ota_update(httpd_req_t *r)
{
    if (!csrf_ok(r)) { httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "CSRF"); return ESP_FAIL; }
    if (r->content_len <= 0) {
        httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, "empty body"); return ESP_FAIL;
    }

    const esp_partition_t *update_part = esp_ota_get_next_update_partition(nullptr);
    if (!update_part) {
        httpd_resp_send_err(r, HTTPD_500_INTERNAL_SERVER_ERROR, "no OTA partition available");
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "OTA: writing %d bytes to %s", (int)r->content_len, update_part->label);

    esp_ota_handle_t ota;
    if (esp_ota_begin(update_part, (size_t)r->content_len, &ota) != ESP_OK) {
        httpd_resp_send_err(r, HTTPD_500_INTERNAL_SERVER_ERROR, "esp_ota_begin failed");
        return ESP_FAIL;
    }

    static char buf[1536];   /* stays INTERNAL: esp_flash_write bounces PSRAM sources 32 B at a time */
    int remaining = r->content_len;
    bool ok = true;
    while (remaining > 0) {
        int want = remaining < (int)sizeof(buf) ? remaining : (int)sizeof(buf);
        int got = httpd_req_recv(r, buf, want);
        if (got <= 0) { ok = false; break; }
        if (esp_ota_write(ota, buf, got) != ESP_OK) { ok = false; break; }
        remaining -= got;
    }
    if (!ok) {
        esp_ota_abort(ota);
        httpd_resp_send_err(r, HTTPD_500_INTERNAL_SERVER_ERROR, "upload interrupted — old firmware still running");
        return ESP_FAIL;
    }

    esp_err_t end_err = esp_ota_end(ota);
    if (end_err != ESP_OK) {
        httpd_resp_send_err(r, HTTPD_500_INTERNAL_SERVER_ERROR,
            end_err == ESP_ERR_OTA_VALIDATE_FAILED
                ? "image validation failed (bad file?) — old firmware still running"
                : "esp_ota_end failed — old firmware still running");
        return ESP_FAIL;
    }
    if (esp_ota_set_boot_partition(update_part) != ESP_OK) {
        httpd_resp_send_err(r, HTTPD_500_INTERNAL_SERVER_ERROR,
            "esp_ota_set_boot_partition failed — old firmware still running");
        return ESP_FAIL;
    }

    send_html(r, "<!DOCTYPE html><html><body><h2>Firmware received</h2>"
                 "<p>Rebooting into the new image in ~10s. If it doesn't come "
                 "back up, the previous firmware reboots itself back in "
                 "automatically.</p><a href='/'>Back</a> (once it's up)."
                 "</body></html>");
    vTaskDelay(pdMS_TO_TICKS(300));
    dns_sink_reboot();
    return ESP_OK;
}

/* ── POST /wifi/scan — start a scan (#54, #62) ────────────────────────
 * Only kicks off the worker and returns immediately; the radio work happens
 * off the httpd task so it can't stall other viewers. POST + csrf_ok because
 * this drives the radio, and IDF warns a scan can knock the STA off its AP,
 * so it must not be triggerable cross-origin (#59). */
static esp_err_t handle_wifi_scan_start(httpd_req_t *r)
{
    if (!csrf_ok(r)) { httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "CSRF"); return ESP_FAIL; }
    bool ok = dns_sink_wifi_scan_start();
    httpd_resp_set_type(r, "application/json");
    httpd_resp_set_hdr(r, "Cache-Control", "no-store");
    httpd_resp_send(r, ok ? "{\"state\":\"scanning\"}"
                          : "{\"state\":\"error\",\"err\":\"cannot start scan right now\"}",
                    HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

/* ── GET /wifi/scan — read the cached result (#62) ────────────────────
 * Pure read of the published cache, so no CSRF and no radio work: safe as a
 * GET, and cheap enough that every page load can repopulate the AP list after
 * the 10s meta-refresh instead of losing it. */
static esp_err_t handle_wifi_scan_get(httpd_req_t *r)
{
    static EXT_RAM_BSS_ATTR char json[3072];   /* wrapper + the cached AP array */
    int n = dns_sink_wifi_scan_get(json, sizeof(json));
    httpd_resp_set_type(r, "application/json");
    httpd_resp_set_hdr(r, "Cache-Control", "no-store");
    httpd_resp_send(r, json, n > 0 ? n : 0);
    return ESP_OK;
}

/* ── POST /wifi/connect — reconfigure Wi-Fi STA (#54) ────────────── */
static esp_err_t handle_wifi_connect(httpd_req_t *r)
{
    if (!csrf_ok(r)) { httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "CSRF"); return ESP_FAIL; }
    char body[512] = {}; httpd_req_recv(r, body, sizeof(body) - 1);
    char ssid[33] = "", pass[65] = "";
    const char *ps = strstr(body, "ssid=");
    if (ps) { ps += 5; size_t l=0; char raw[128]={0}; for(;ps[l]&&ps[l]!='&'&&ps[l]!='\r'&&l<127;l++) raw[l]=ps[l]; url_decode(ssid,sizeof(ssid),raw,l); }
    const char *pp = strstr(body, "password=");
    if (pp) { pp += 9; size_t l=0; char raw[256]={0}; for(;pp[l]&&pp[l]!='&'&&pp[l]!='\r'&&l<255;l++) raw[l]=pp[l]; url_decode(pass,sizeof(pass),raw,l); }
    dns_sink_wifi_set_creds(ssid, pass);
    httpd_resp_set_status(r, "303 See Other"); httpd_resp_set_hdr(r, "Location", "/#network"); httpd_resp_send(r,nullptr,0); return ESP_OK;
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
    static EXT_RAM_BSS_ATTR char body[CUSTOM_RULES_CAP + 64];
    int got = httpd_req_recv(r, body, sizeof(body) - 1);
    if (got <= 0) { httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, ""); return ESP_FAIL; }
    body[got] = '\0';
    const char *p = strstr(body, "rules=");
    if (!p) { httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, ""); return ESP_FAIL; }
    p += 6;
    /* url-decode into a temp buffer */
    static EXT_RAM_BSS_ATTR char decoded[CUSTOM_RULES_CAP + 4];
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
    static EXT_RAM_BSS_ATTR QLogEntry entries[64];
    uint32_t n = query_log_snapshot(entries, 64);
    static EXT_RAM_BSS_ATTR char page[6144];
    int pg = 0;
    page_appendf(page, sizeof(page), &pg,
        "<!DOCTYPE html><html><head><meta charset=utf-8>"
        "<title>Query Log</title>"
        "<style>body{font-family:monospace;max-width:900px;margin:1em auto}"
        "table{border-collapse:collapse;width:100%%}"
        "td,th{border:1px solid #ccc;padding:.3em .6em;font-size:.85em}"
        "th{background:#222;color:#eee}.blk{color:red}.rw{color:blue}"
        ".ok{color:green}</style></head><body>"
        "<h2>Query Log <small>(<a href='/'>home</a>)</small></h2>"
        "<table><tr><th>Time (UTC)</th><th>Client</th><th>Domain</th>"
        "<th>Type</th><th>Result</th></tr>");
    for (uint32_t i = 0; i < n && pg < (int)sizeof(page) - 256; i++) {
        QLogEntry *e = &entries[i];
        char safe[128]; html_escape(safe, sizeof(safe), e->domain);
        const char *res  = e->blocked ? "BLOCKED" : (e->rewritten ? "REWRITE" : "ALLOWED");
        const char *cls  = e->blocked ? "blk"     : (e->rewritten ? "rw"      : "ok");
        const char *type = e->qtype == 1 ? "A" : (e->qtype == 28 ? "AAAA" :
                           e->qtype == 5 ? "CNAME" : e->qtype == 15 ? "MX" : "?");
        uint32_t ip = e->client_ip;
        /* Wall-clock time if NTP has synced, else fall back to uptime offset. */
        char tbuf[24];
        if (e->epoch_s) {
            time_t t = (time_t)e->epoch_s;
            struct tm tmv; gmtime_r(&t, &tmv);
            strftime(tbuf, sizeof(tbuf), "%m-%d %H:%M:%S", &tmv);
        } else {
            snprintf(tbuf, sizeof(tbuf), "+%lus", (unsigned long)e->ts_s);
        }
        page_appendf(page, sizeof(page), &pg,
            "<tr><td>%s</td><td>%u.%u.%u.%u</td><td>%s</td>"
            "<td>%s</td><td class='%s'>%s</td></tr>",
            tbuf,
            (unsigned)((ip>>24)&0xFF),(unsigned)((ip>>16)&0xFF),
            (unsigned)((ip>>8)&0xFF),(unsigned)(ip&0xFF),
            safe, type, cls, res);
    }
    page_appendf(page, sizeof(page), &pg, "</table></body></html>");
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

    static EXT_RAM_BSS_ATTR char page[6144];
    int pg = 0;
    page_appendf(page, sizeof(page), &pg,
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
        page_appendf(page, sizeof(page), &pg,
            "<div class=bar title='%lut %lub'>"
            "<div class=bb style='height:%lupx'></div>"
            "<div class=bt style='height:%lupx'></div></div>",
            (unsigned long)h_total[i], (unsigned long)h_blocked[i],
            (unsigned long)bh, (unsigned long)th);
    }
    page_appendf(page, sizeof(page), &pg,
        "</div><p><small>Blue=allowed Red=blocked. Each bar=1 min.</small></p>"
        "<h3>Top Queried Domains</h3>"
        "<table><tr><th>Domain</th><th>Total</th><th>Blocked</th></tr>");
    for (uint32_t i = 0; i < nd && top_d[i].total > 0 && pg < (int)sizeof(page) - 256; i++) {
        char safe[128]; html_escape(safe, sizeof(safe), top_d[i].key);
        page_appendf(page, sizeof(page), &pg,
            "<tr><td>%s</td><td>%lu</td><td>%lu</td></tr>",
            safe, (unsigned long)top_d[i].total, (unsigned long)top_d[i].blocked);
    }
    page_appendf(page, sizeof(page), &pg,
        "</table><h3>Top Clients</h3>"
        "<table><tr><th>Client IP</th><th>Total</th><th>Blocked</th></tr>");
    for (uint32_t i = 0; i < nc && top_c[i].total > 0 && pg < (int)sizeof(page) - 256; i++) {
        char safe[64]; html_escape(safe, sizeof(safe), top_c[i].key);
        page_appendf(page, sizeof(page), &pg,
            "<tr><td>%s</td><td>%lu</td><td>%lu</td></tr>",
            safe, (unsigned long)top_c[i].total, (unsigned long)top_c[i].blocked);
    }
    page_appendf(page, sizeof(page), &pg, "</table></body></html>");
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
    /* extract IP value — require all four octets to parse and be in range */
    unsigned b0=0,b1=0,b2=0,b3=0;
    if (sscanf(pi, "%u.%u.%u.%u", &b0, &b1, &b2, &b3) != 4 ||
        b0 > 255 || b1 > 255 || b2 > 255 || b3 > 255) {
        httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, "bad ip"); return ESP_FAIL;
    }
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
    /* F10: the preset <select>'s placeholder option has value=''. A stale page
     * (render-time free_slot baked into the form's hidden idx) submitted with
     * the placeholder still selected posts idx=N&url= — which used to call
     * blocklist_extra_url_set(N, "") and silently delete a configured slot
     * behind a success-looking 303. Clearing a slot is a deliberate action
     * that must go through /blocklist/url/clear; reject an empty url here. */
    /* #90: only https. An http:// feed lets anyone on the path rewrite the
     * list this sinkhole trusts. blocklist.c refuses at fetch time too, for
     * entries that predate this check. */
    if (decoded[0] != '\0' && strncasecmp(decoded, "https://", 8) != 0) {
        httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST,
            "Blocklist sources must be https:// URLs");
        return ESP_FAIL;
    }
    if (decoded[0] == '\0') {
        httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST,
            "empty url — use /blocklist/url/clear to remove a source");
        return ESP_FAIL;
    }
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

/* ── POST /blocklist/url/toggle — enable/disable a source without losing its
 * URL (#48). Takes effect on the next reload, same as add/remove. */
static esp_err_t handle_bl_url_toggle(httpd_req_t *r)
{
    if (!csrf_ok(r)) {
        httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "CSRF"); return ESP_FAIL;
    }
    char body[64] = {}; httpd_req_recv(r, body, sizeof(body) - 1);
    const char *pidx = strstr(body, "idx=");
    if (!pidx) { httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, ""); return ESP_FAIL; }
    int idx = (int)strtol(pidx + 4, nullptr, 10);
    blocklist_extra_enabled_set(idx, !blocklist_extra_enabled_get(idx));
    httpd_resp_set_status(r, "303 See Other");
    httpd_resp_set_hdr(r, "Location", "/");
    httpd_resp_send(r, nullptr, 0);
    return ESP_OK;
}

/* ── HTTP :80 → HTTPS redirect ───────────────────────────────────────
 * Its own tiny httpd instance (2 sockets, small stack) because one httpd can
 * only listen on one port. It renders nothing, reads nothing, holds no state
 * — every path gets a 301 to the same path on https — so it doesn't touch
 * the single-task-httpd design rule (#61): that rule exists so the UI's
 * rendering state has exactly one writer, and this server has none. */
static esp_err_t handle_redirect(httpd_req_t *r)
{
    char host[80] = {};
    httpd_req_get_hdr_value_str(r, "Host", host, sizeof(host));
    char *colon = strchr(host, ':');
    if (colon) *colon = '\0';
    /* (#112) Host is client-supplied and unauthenticated on this listener —
     * echoing it into Location let an attacker redirect a LAN client to any
     * origin. Only our own mDNS name or our own current LAN IP are honored;
     * anything else falls back to the mDNS name, same as an empty Host. */
    const char *lan_ip = dns_sink_lan_ip();
    bool host_ok = host[0] &&
        (strcasecmp(host, dns_sink_hostname()) == 0 ||
         (lan_ip[0] && strcmp(host, lan_ip) == 0));
    static EXT_RAM_BSS_ATTR char loc[600];
    snprintf(loc, sizeof(loc), "https://%s%s", host_ok ? host : dns_sink_hostname(), r->uri);
    httpd_resp_set_status(r, "301 Moved Permanently");
    httpd_resp_set_hdr(r, "Location", loc);
    httpd_resp_set_hdr(r, "Cache-Control", "no-store");
    httpd_resp_send(r, nullptr, 0);
    return ESP_OK;
}

static void start_redirect_server(void)
{
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.server_port      = 80;
    cfg.ctrl_port        = 32770;
    cfg.max_open_sockets = 2;
    cfg.max_uri_handlers = 2;
    cfg.stack_size       = 4096;
    cfg.lru_purge_enable = true;
    cfg.uri_match_fn     = httpd_uri_match_wildcard;
    if (httpd_start(&s_redirect, &cfg) != ESP_OK) { ESP_LOGW(TAG, ":80 redirect listener failed"); return; }
    static const httpd_uri_t any_get  = { "/*", HTTP_GET,  handle_redirect, nullptr };
    static const httpd_uri_t any_post = { "/*", HTTP_POST, handle_redirect, nullptr };
    httpd_register_uri_handler(s_redirect, &any_get);
    httpd_register_uri_handler(s_redirect, &any_post);
}

/* ── Public API ──────────────────────────────────────────────────── */
/* Boot-time crypto (legacy password migration's PBKDF2, cert load/generate)
 * runs here, on a task with a real stack — app_main's is 3.5 KB
 * (CONFIG_ESP_MAIN_TASK_STACK_SIZE) and the first attempt to do the cert
 * generation on it overflowed into the heap; the corruption surfaced as an
 * interrupt-WDT spin on a garbage mutex, three frames from the cause. */
struct SecureInitJob {
    SemaphoreHandle_t done;
    const char *crt, *key; size_t crt_len, key_len;
    bool ok;
};

static void secure_init_task(void *arg)
{
    SecureInitJob *job = static_cast<SecureInitJob *>(arg);
    web_auth_init();
    job->ok = web_tls_get_identity(&job->crt, &job->crt_len, &job->key, &job->key_len);
    ESP_LOGI(TAG, "secure_init stack high-water: %u B free", (unsigned)uxTaskGetStackHighWaterMark(nullptr));
    xSemaphoreGive(job->done);
    vTaskDelete(nullptr);
}

bool web_ui_start(DnsSinkServer *dns)
{
    s_dns = dns;

    SecureInitJob job = {};
    job.done = xSemaphoreCreateBinary();
    if (!job.done) return false;
    if (xTaskCreate(secure_init_task, "secure_init", 12288, &job, 5, nullptr) != pdPASS) {
        vSemaphoreDelete(job.done);
        return false;
    }
    xSemaphoreTake(job.done, portMAX_DELAY);
    vSemaphoreDelete(job.done);
    if (!job.ok) {
        /* No identity means no HTTPS, and this UI is not allowed to exist
         * over plain HTTP (#89). DNS keeps running; the USB console is the
         * recovery path (`cert-reset`, then reboot). The caller turns this
         * into an OTA rollback while the image is still unverified. */
        ESP_LOGE(TAG, "no TLS identity — web UI NOT started");
        return false;
    }
    const char *crt = job.crt, *key = job.key;
    size_t crt_len = job.crt_len, key_len = job.key_len;

    /* IDF's HTTPD_SSL_CONFIG_DEFAULT() omits use_secure_element, which
     * -Werror=missing-field-initializers flags under C++; the field is
     * zero-initialised anyway. */
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wmissing-field-initializers"
    httpd_ssl_config_t cfg = HTTPD_SSL_CONFIG_DEFAULT();
    #pragma GCC diagnostic pop
    cfg.servercert       = (const uint8_t *)crt;
    cfg.servercert_len   = crt_len;
    cfg.prvtkey_pem      = (const uint8_t *)key;
    cfg.prvtkey_len      = key_len;
    cfg.port_secure      = 443;
    cfg.httpd.max_uri_handlers = 40;
    cfg.httpd.max_resp_headers = 16;   /* 5 hardening headers + cookie + Location + type */
    cfg.httpd.stack_size       = 16384;
    /* Recycle the least-recently-used connection instead of refusing new ones
     * once max_open_sockets is reached (#61). Without this a client that goes
     * away mid-request holds its slot until recv/send_wait_timeout, and
     * enough of those lock everyone else out. 4 sockets is the TLS default:
     * each idle TLS connection pins ~40 KB (buffers land in PSRAM via
     * CONFIG_MBEDTLS_EXTERNAL_MEM_ALLOC, so internal heap is safe), and
     * CONFIG_LWIP_MAX_SOCKETS=24 still has to leave room for TCP/53, the DoT
     * worker, and the :80 redirect listener. */
    cfg.httpd.lru_purge_enable = true;
    cfg.httpd.recv_wait_timeout = 10;   /* OTA uploads over TLS are slower */
    cfg.httpd.send_wait_timeout = 10;
    /* The handshake runs synchronously on the httpd task; a client that
     * connects and says nothing (port scanner, stalled browser) would
     * otherwise hold every other viewer for the full recv timeout. */
    cfg.tls_handshake_timeout_ms = 3000;
    esp_err_t started = httpd_ssl_start(&s_server, &cfg);
    web_tls_release_identity();   /* httpd_ssl_start took its own copies */
    if (started != ESP_OK) {
        ESP_LOGE(TAG, "httpd_ssl_start failed"); return false;
    }

    /* Every URI routes through auth_wrap with the real handler stashed in
     * user_ctx (#1) — see auth_wrap's comment for why this beats a per-handler
     * check. /setup and /login are in the same table; auth_wrap recognises
     * them by handler pointer and applies the setup/session gates around them. */
    #define H(fn) auth_wrap, (void *)(raw_handler_t)(fn)
    static const httpd_uri_t uris[] = {
        { "/setup",               HTTP_GET,  H(handle_setup_get)     },
        { "/setup",               HTTP_POST, H(handle_setup_post)    },
        { "/login",               HTTP_GET,  H(handle_login_get)     },
        { "/login",               HTTP_POST, H(handle_login_post)    },
        { "/logout",              HTTP_POST, H(handle_logout)        },
        { "/",                    HTTP_GET,  H(handle_status)        },
        { "/metrics",             HTTP_GET,  H(handle_metrics)       },
        { "/metrics/reset",       HTTP_POST, H(handle_metrics_reset) },
        { "/reload",              HTTP_POST, H(handle_reload)        },
        { "/blocklist/stop",      HTTP_POST, H(handle_bl_stop)       },
        { "/pause",               HTTP_POST, H(handle_pause)         },
        { "/check",               HTTP_POST, H(handle_check)         },
        { "/auth/set",            HTTP_POST, H(handle_auth_set)      },
        { "/whitelist/add",       HTTP_POST, H(handle_wl_add)        },
        { "/whitelist/remove",    HTTP_POST, H(handle_wl_remove)     },
        { "/blocklist/url/set",   HTTP_POST, H(handle_bl_url_set)    },
        { "/blocklist/url/clear", HTTP_POST, H(handle_bl_url_clear)  },
        { "/blocklist/url/toggle",HTTP_POST, H(handle_bl_url_toggle) },
        { "/rewrite/set",         HTTP_POST, H(handle_rw_set)        },
        { "/rewrite/clear",       HTTP_POST, H(handle_rw_clear)      },
        { "/log",                 HTTP_GET,  H(handle_log)           },
        { "/top",                 HTTP_GET,  H(handle_top)           },
        { "/custom/rules",        HTTP_POST, H(handle_custom_rules)  },
        { "/acl/add",             HTTP_POST, H(handle_acl_add)       },
        { "/acl/remove",          HTTP_POST, H(handle_acl_remove)    },
        { "/acl/clear",           HTTP_POST, H(handle_acl_clear)     },
        { "/dot/set",             HTTP_POST, H(handle_dot_set)       },
        { "/dot/zones",           HTTP_POST, H(handle_dot_zones)     },
        { "/net/upstream",        HTTP_POST, H(handle_net_upstream)  },
        { "/wifi/scan",           HTTP_POST, H(handle_wifi_scan_start) },
        { "/wifi/scan",           HTTP_GET,  H(handle_wifi_scan_get)   },
        { "/wifi/connect",        HTTP_POST, H(handle_wifi_connect)  },
        { "/net/eth/set",         HTTP_POST, H(handle_net_eth_set)   },
        { "/net/wifi/set",        HTTP_POST, H(handle_net_wifi_set)  },
        { "/reboot",              HTTP_POST, H(handle_reboot)        },
        { "/ota/update",          HTTP_POST, H(handle_ota_update)    },
    };
    #undef H
    for (auto &u : uris) httpd_register_uri_handler(s_server, &u);

    start_redirect_server();
    ESP_LOGI(TAG, "Web UI on https://:443 (:80 redirects)%s",
             web_auth_setup_needed() ? " — SETUP MODE: create the admin account in a browser" : "");
    return true;
}

void web_ui_stop(void)
{
    if (s_server)   { httpd_ssl_stop(s_server); s_server = nullptr; }
    if (s_redirect) { httpd_stop(s_redirect);   s_redirect = nullptr; }
}
