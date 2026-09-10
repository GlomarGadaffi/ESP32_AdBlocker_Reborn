#include "web_ui.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "blocklist.h"
#include "domain.h"
#include "rewrite.h"
#include "acl.h"
#include "bypass.h"
#include "pause.h"
#include "dot.h"
#include "localzone.h"
#include "query_log.h"
#include "census.h"
#include "crashlog.h"
#include "lwip/sockets.h"
#include "esp_http_server.h"
#include "esp_https_server.h"
#include "esp_log.h"
#include "esp_attr.h"
#include "esp_timer.h"
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
#include <cctype>
#include <ctime>
#include <inttypes.h>
#include "timesync.h"

static const char *TAG = "web_ui";
static httpd_handle_t  s_server   = nullptr;   /* HTTPS :443 — the real UI */
static httpd_handle_t  s_redirect = nullptr;   /* HTTP  :80  — 301 to https only */
static DnsSinkServer  *s_dns      = nullptr;

extern "C" void dns_sink_trigger_reload(void);
extern "C" bool dns_sink_wifi_built(void);
extern "C" bool dns_sink_eth_built(void);    /* (#49) false on the Wi-Fi-only board */
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

/* Wraps a non-null error message in <p class=err>...</p>; empty string if err
 * is null. err is always a static or snprintf'd server-generated message
 * (setup_page/login_page never echo request input through it), so this
 * applies no escaping — same as the two call sites it replaces. */
static void err_html(char *dst, size_t cap, const char *err)
{
    if (err) snprintf(dst, cap, "<p class=err>%s</p>", err);
    else     dst[0] = '\0';
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

/* ── Page buffer with truncation tracking (#110 item 4) ─────────────
 * Replaces ad-hoc hand-measured reserve gates with an explicit buffer manager.
 * Reserves TRUNC_RESERVE bytes at the tail so that if markup ever exceeds
 * capacity, a visible truncation banner and closing tags (</div></body></html>)
 * are guaranteed to fit, preventing broken layouts or silently dropped tabs. */
struct PageBuf {
    char *buf;
    size_t cap;
    size_t pos;
    bool truncated;

    static constexpr size_t TRUNC_RESERVE = 256;

    PageBuf(char *b, size_t c) : buf(b), cap(c), pos(0), truncated(false) {
        if (buf && cap > 0) buf[0] = '\0';
    }

    PageBuf(const PageBuf &) = delete;
    PageBuf &operator=(const PageBuf &) = delete;

    bool has_room(size_t needed = 0) const {
        return !truncated && (cap > pos + TRUNC_RESERVE + needed);
    }

    void mark_truncated() {
        truncated = true;
    }

    void appendf(const char *fmt, ...) __attribute__((format(printf, 2, 3))) {
        if (truncated) return;
        if (pos >= cap) {
            truncated = true;
            return;
        }
        size_t avail = (cap > pos + TRUNC_RESERVE) ? (cap - pos - TRUNC_RESERVE) : 0;
        if (avail <= 1) {
            truncated = true;
            return;
        }
        va_list ap;
        va_start(ap, fmt);
        int w = vsnprintf(buf + pos, avail, fmt, ap);
        va_end(ap);
        if (w < 0) return;
        if ((size_t)w >= avail) {
            truncated = true;
            pos += avail - 1;
            buf[pos] = '\0';
        } else {
            pos += (size_t)w;
        }
    }

    void append(const char *str) {
        if (truncated || !str) return;
        size_t len = strlen(str);
        if (pos >= cap) {
            truncated = true;
            return;
        }
        size_t avail = (cap > pos + TRUNC_RESERVE) ? (cap - pos - TRUNC_RESERVE) : 0;
        if (len >= avail) {
            truncated = true;
            if (avail > 1) {
                memcpy(buf + pos, str, avail - 1);
                pos += avail - 1;
                buf[pos] = '\0';
            }
        } else {
            memcpy(buf + pos, str, len);
            pos += len;
            buf[pos] = '\0';
        }
    }

    esp_err_t send(httpd_req_t *r) {
        if (truncated) {
            ESP_LOGW(TAG, "status page hit %u B cap — markup truncated, emitted truncation marker",
                     (unsigned)cap);
            size_t rem = (cap > pos) ? (cap - pos) : 0;
            if (rem > 1) {
                snprintf(buf + pos, rem,
                         "<p class=warn>[page truncated &mdash; too much config to render]</p>"
                         "</div></body></html>");
                pos = strlen(buf);
            }
        }
        httpd_resp_set_type(r, "text/html; charset=utf-8");
        return httpd_resp_send(r, buf, HTTPD_RESP_USE_STRLEN);
    }
};

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
 * application/x-www-form-urlencoded request. Returns false if the key is
 * absent, so a caller can tell "field missing" from "field submitted
 * empty" — dst is set to "" either way. */
static bool form_field(const char *body, const char *key, char *dst, size_t cap)
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
            return true;
        }
        p += kl;
    }
    return false;
}

/* Read a form body field as a bounded integer. Leaves *out unchanged and
 * returns false if the field is missing, unparseable, or outside [lo, hi]. */
static bool form_int(const char *body, const char *key, int *out, int lo, int hi)
{
    char buf[12];
    form_field(body, key, buf, sizeof(buf));
    if (buf[0] == '\0') return false;
    char *end; long v = strtol(buf, &end, 10);
    if (end == buf || v < lo || v > hi) return false;
    *out = (int)v;
    return true;
}

/* (#48) The address the current request came from, host order, 0 if unknown.
 * Read from the TCP connection itself — never from anything the client sent —
 * because it decides whose blocking a default-scope pause switches off. The
 * server listens dual-stack, so an IPv4 client shows up as a v4-mapped IPv6
 * peer (::ffff:a.b.c.d); unwrap that. A native IPv6 peer is reported as 0:
 * the pause table and the DNS paths are IPv4, so there is nothing to match. */
static uint32_t req_peer_ip(httpd_req_t *r)
{
    int fd = httpd_req_to_sockfd(r);
    if (fd < 0) return 0;
    struct sockaddr_storage ss; socklen_t sl = sizeof(ss);
    memset(&ss, 0, sizeof(ss));
    if (getpeername(fd, reinterpret_cast<struct sockaddr *>(&ss), &sl) != 0) return 0;
    if (ss.ss_family == AF_INET)
        return ntohl(reinterpret_cast<struct sockaddr_in *>(&ss)->sin_addr.s_addr);
#if LWIP_IPV6
    if (ss.ss_family == AF_INET6) {
        const uint8_t *a = reinterpret_cast<const uint8_t *>(
            &reinterpret_cast<struct sockaddr_in6 *>(&ss)->sin6_addr);
        static const uint8_t v4mapped[12] = { 0,0,0,0,0,0,0,0,0,0,0xFF,0xFF };
        if (memcmp(a, v4mapped, sizeof(v4mapped)) == 0)
            return ((uint32_t)a[12] << 24) | ((uint32_t)a[13] << 16) |
                   ((uint32_t)a[14] << 8)  |  (uint32_t)a[15];
    }
#endif
    return 0;
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
    char errp[128]; err_html(errp, sizeof(errp), err);
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
        "%s"
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
        errp,
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
    char errp[128]; err_html(errp, sizeof(errp), err);
    int n = 0;
    page_appendf(page, sizeof(page), &n, AUTH_PAGE_HEAD);
    page_appendf(page, sizeof(page), &n,
        "<h2>DNS Sinkhole &mdash; sign in</h2>"
        "%s"
        "<form method=post action=/login>"
        "<label>Username<input name=user maxlength=%d autocomplete=username required autofocus></label>"
        "<label>Password<input name=pass type=password maxlength=%d autocomplete=current-password required></label>"
        "<button>Sign in</button></form>"
        "</body></html>",
        errp,
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

    /* static: avoids stack overflow in httpd task. Sized at 64 KB in PSRAM
     * (#110 item 4) with headroom for a fully-populated device (whitelist +
     * ACL + rewrites + all extra sources) so later tabs like Upstream DNS/DoT
     * are never dropped. PageBuf guarantees balanced closing markup and emits a
     * visible marker if truncation ever occurs. */
    static EXT_RAM_BSS_ATTR char page[65536];
    PageBuf pb(page, sizeof(page));
    char csrf[33] = "";
    web_auth_session_csrf(s_req_sid, csrf, sizeof(csrf));
    /* Hoisted here (was computed down in the pause section) so the head
     * script can embed it — refreshDash's live pause-countdown rebuild
     * needs to know which entry is "this device" the same way the
     * server-rendered table already does. */
    uint32_t me = req_peer_ip(r);
    char my_ip_s[16];
    snprintf(my_ip_s, sizeof(my_ip_s), "%u.%u.%u.%u",
             (unsigned)((me>>24)&0xFF),(unsigned)((me>>16)&0xFF),
             (unsigned)((me>>8)&0xFF),(unsigned)(me&0xFF));
    pb.appendf(
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
        "var MY_IP='%s';"
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
         * refreshing. On the config tabs a refresh is pure harm — it would
         * throw away whatever you were typing.
         * (#105/#108) This used to be location.reload() every 10s, which
         * wiped the Dashboard's own Check-domain/Add-to-whitelist inputs
         * exactly the same way, plus re-walked and re-escaped all ~16KB of
         * every OTHER tab's markup on the single-task httpd just to repaint
         * five stat chips. Polling /metrics and patching the five #st-*
         * elements in place fixes both: nothing on the page is ever
         * replaced, so a half-typed input survives, and the response is a
         * few hundred bytes of JSON already built for /metrics/view instead
         * of the whole page. */
        "function schedRefresh(){"
        "if(RT){clearTimeout(RT);RT=null;}"
        "var a=document.querySelector('.tab.active');"
        "if(a&&a.id=='tab-dashboard'){RT=setTimeout(function(){refreshDash(0);},10000);}"
        "}"
        "var DASH_BUSY=false,DASH_FAILS=0;"
        /* Same Response.redirected check as /metrics/view (#126/#127): an
         * expired session answers this GET with a 303 to /login that fetch()
         * follows and hands back as 200 HTML, so a naive .json() parse would
         * fail confusingly instead of just sending the user back to sign in.
         * BUSY/document.hidden guards and the visibilitychange catch-up
         * mirror /metrics/view's tick() exactly (#126/#127) — same reasons:
         * a slow response must not overlap with the next scheduled one, and
         * a backgrounded tab must not keep hitting the single-task httpd.
         * (A prior version of this function called schedRefresh() right
         * after STARTING the fetch, not after it settled — meaning it
         * re-armed immediately regardless of how long the request took, the
         * exact overlap this guard exists to prevent. Caught by review, not
         * by the mocked-fetch tests, which only ever waited a fixed 50ms.) */
        "function refreshDash(force){"
        "if(DASH_BUSY||(document.hidden&&!force))return;"
        "DASH_BUSY=true;"
        "fetch('/metrics',{cache:'no-store'}).then(function(r){"
        "if(r.redirected){location.reload();return null;}return r.json();"
        "}).then(function(m){"
        "if(m){"
        "document.getElementById('st-domains').textContent=m.blocklist_count;"
        "document.getElementById('st-queries').textContent=m.queries_total;"
        "document.getElementById('st-blocked').textContent=m.blocked;"
        "var pct=m.queries_total>0?(100*m.blocked/m.queries_total):0;"
        "document.getElementById('st-rate').textContent=pct.toFixed(1)+'%%';"
        "var degraded=(m.blocklist_dropped>0)||(m.blocklist_feed_failures>0)||(m.exceptions_dropped>0);"
        "var cls=m.blocklist_loading?'warn':(m.blocklist_paused?'warn':(degraded?'warn':'ok'));"
        "var txt=m.blocklist_loading?'Reloading':(m.blocklist_paused?'Paused':(degraded?'Degraded':'Active'));"
        "var st=document.getElementById('st-status');"
        "st.className='val '+cls;st.textContent=txt;"
        "var sl=document.getElementById('stop-load-form');"
        "if(sl)sl.hidden=!m.blocklist_loading;"
        "renderPause(m.pause_list||[]);"
        "renderClock(m.clock,m.clock_src,m.clock_epoch);"
        "DASH_FAILS=0;"
        "}else{DASH_FAILS++;}"
        "markStale();DASH_BUSY=false;schedRefresh();"
        "}).catch(function(){DASH_FAILS++;markStale();DASH_BUSY=false;schedRefresh();});"
        "}"
        /* (#105/#108 follow-up) A poll failing silently forever is worse than
         * the reload it replaced, which at least errored visibly in the
         * browser's own UI on a dead connection — same reasoning as
         * /metrics/view's FAILS/'stale' handling (#127). */
        "function markStale(){"
        "var e=document.getElementById('dash-stale');if(!e)return;"
        "e.hidden=DASH_FAILS<3;"
        "}"
        /* The ONLY renderer for the pause table — handle_status's C code
         * calls this via an inline <script> at first paint (passing the same
         * pause_list data JSON-encoded) instead of hand-building the HTML
         * itself. A prior version had two copies (server-side C for first
         * paint, this one for refreshes); review caught that as the exact
         * class of drift bug #103/#107 exist because of elsewhere in this
         * file, despite a comment here once claiming otherwise. Now there is
         * one, so first paint and every refresh are provably the same
         * markup. The submit listener above is delegated on `document`, so
         * it CSRF-tags these forms even though they're created via
         * innerHTML, same as any other form. */
        "function renderPause(list){"
        "var c=document.getElementById('pause-active');if(!c)return;"
        "if(!list.length){c.innerHTML='';return;}"
        "var h='<table><tr><th>Paused for</th><th>Time left</th><th></th></tr>';"
        "for(var i=0;i<list.length;i++){"
        "var p=list[i];"
        "var who=p.ip=='all'?'<b>All devices</b>':p.ip;"
        "if(p.ip==MY_IP)who+=' (this device)';"
        "var m=Math.floor(p.remaining_s/60),s=p.remaining_s%%60;"
        "h+='<tr><td>'+who+'</td><td>'+m+'m '+(s<10?'0':'')+s+'s</td>'+"
        "'<td><form method=post action=/pause/resume style=\"margin:0\">'+"
        "'<input type=hidden name=ip value=\"'+p.ip+'\"><button>Resume now</button></form></td></tr>';"
        "}"
        "h+='</table><form method=post action=/pause/resume style=\"margin-top:.4em\">'+"
        "'<input type=hidden name=ip value=every><button>Resume all now</button></form>';"
        "c.innerHTML=h;"
        "}"
        /* Same single-renderer fix as renderPause(), for the same review
         * finding: the Clock line used to freeze at whatever it showed on
         * first paint (a real gap during the exact NTP-sync moment a viewer
         * might be watching for), since /metrics already carried clock and
         * clock_src but nothing patched this line from them. clock_epoch is
         * raw time(NULL) (see dns_server.cpp's comment on that field) — it
         * reflects the floor date while unsynced, matching what this line
         * has always shown, not a new value. */
        "function renderClock(clock,src,epoch){"
        "var c=document.getElementById('clock-status');if(!c)return;"
        "var d=new Date(epoch*1000);"
        "if(clock=='synced'){"
        "c.innerHTML='Clock: <b>'+d.toISOString().slice(0,19).replace('T',' ')+"
        "' UTC</b> (NTP synced)';"
        "}else{"
        "c.innerHTML='Clock: <span class=warn>syncing via NTP\\u2026</span> '+"
        "'running on the <b>'+src+'</b> clock ('+d.toISOString().slice(0,10)+') '+"
        "'\\u2014 good enough for TLS certificate dates, not for timestamps, '+"
        "'so the log shows uptime until synced.';"
        "}"
        "}"
        "document.addEventListener('visibilitychange',function(){"
        "if(!document.hidden){var a=document.querySelector('.tab.active');"
        "if(a&&a.id=='tab-dashboard')refreshDash(1);}"
        "});"
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
        "<div class='tab' id=tab-dashboard>", csrf, my_ip_s);
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
    pb.appendf(
        "<div class=stats>"
        "<div class=stat><div class=val id=st-domains>%" PRIu32 "</div><div class=lbl>Domains</div></div>"
        "<div class=stat><div class=val id=st-queries>%" PRIu32 "</div><div class=lbl>Queries</div></div>"
        "<div class=stat><div class=val id=st-blocked>%" PRIu32 "</div><div class=lbl>Blocked</div></div>"
        "<div class=stat><div class=val id=st-rate>%.1f%%</div><div class=lbl>Block rate</div></div>"
        "<div class=stat><div class='val %s' id=st-status>%s</div><div class=lbl>Status</div></div>"
        "</div>"
        "<p id=dash-stale class=warn hidden><small>The numbers above stopped "
        "updating a few polls ago &mdash; reload the page to check "
        "whether the board is still reachable.</small></p>",
        domains, total, blocked, pct,
        status_cls, status_txt);

    if (dns_sink_setup_ap_active()) {
        pb.appendf(
            "<p style='background:#fff3cd;border:1px solid #ffe08a;border-radius:6px;"
            "padding:.6em 1em'><b>Setup AP active</b> — no Ethernet or Wi-Fi link yet. "
            "Join \"ESP32AdBlock-Setup\" (WPA2 passphrase printed on the USB console) and browse "
            "<b>https://192.168.4.1</b> to enter real Wi-Fi credentials in the Network tab; "
            "this AP shuts off automatically once a link comes up.</p>");
    }
    pb.appendf(
        "<h3>Actions</h3>"
        "<form method=post action=/reload><button>Reload blocklist</button></form><br>"
        /* (#105/#108 follow-up) Always rendered, `hidden` toggled by
         * refreshDash() from m.blocklist_loading — a reload that starts
         * after the page loaded used to only show this button on the next
         * full-page reload; now the 10s poll flips it live like the status
         * chip already does. */
        "<form method=post action=/blocklist/stop id=stop-load-form%s>"
        "<button>Stop load</button></form><br>",
        loading ? "" : " hidden");
    pb.appendf(
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
        " &nbsp; <a href='/census'>LAN census</a>"
        " &nbsp; <a href='/metrics/view'>Metrics</a>"
        " (<a href='/metrics'>JSON</a>)"
        "<p><small>The stat chips, Stop-load button, and the pause countdown "
        "below all refresh every 10s while this tab is open and visible — "
        "nothing on the page reloads, so it's safe to leave the Check-domain "
        "or Add-to-whitelist fields half-filled. The other tabs don't poll "
        "at all.</small></p>",
        paused ? 0 : 1, paused ? "Resume blocking" : "Pause blocking");

    /* (#48) Timed, scoped pause. Default scope is the device viewing the page
     * — its address comes from the connection, never from the form — so one
     * client can unblock itself without switching protection off for the
     * house. "All devices" goes through a confirmation page (handle_pause_timed)
     * before it takes effect. refreshDash() (see the head script) rebuilds
     * the "Time left" table from /metrics's pause_list every 10s — the
     * static render below is just the first paint. */
    {
        pause_view_t pv[PAUSE_MAX];
        uint32_t pn = pause_list(pv, PAUSE_MAX);
        pb.appendf(
            "<h3>Pause blocking for a while</h3>"
            "<form method=post action=/pause/timed>"
            "<input name=min type=number min=1 max=%u value=30 style='width:5em'> minutes "
            "(max %u = 24 h)<br>"
            "<label><input type=radio name=scope value=me checked> This device (%u.%u.%u.%u)</label><br>"
            "<label><input type=radio name=scope value=host> Another host:</label> "
            "<input name=ip placeholder='192.168.1.23' size=15><br>"
            "<label><input type=radio name=scope value=all> All devices (asks you to confirm)</label><br>"
            "<button>Pause</button></form>"
            "<p><small>Only the chosen scope stops being filtered. Blocking resumes on its own "
            "when the time is up, and a reboot always comes back blocking.</small></p>",
            (unsigned)PAUSE_MAX_MINUTES, (unsigned)PAUSE_MAX_MINUTES,
            (unsigned)((me>>24)&0xFF),(unsigned)((me>>16)&0xFF),
            (unsigned)((me>>8)&0xFF),(unsigned)(me&0xFF));
        /* (#105/#108 follow-up, and the review finding that the first cut of
         * this got wrong) A previous version hand-built this table's HTML
         * here in C AND in renderPause() (JS) — two renderers for the same
         * pause_list data, the exact class of drift bug #103/#107 exist
         * because of elsewhere in this file. There is now exactly ONE
         * renderer: renderPause() (head script). The initial paint just
         * calls it with the same data JSON-encoded, so first load and every
         * 10s refresh always go through the same code. The submit listener
         * in the head script is delegated on `document`, so it CSRF-tags
         * these forms' actions even though renderPause() creates them via
         * innerHTML, same as any other form. */
        pb.appendf("<div id=pause-active></div><script>renderPause([");
        for (uint32_t i = 0; i < pn; i++) {
            char ipv[16];
            if (pv[i].ip == PAUSE_IP_ALL) {
                snprintf(ipv, sizeof(ipv), "all");
            } else {
                snprintf(ipv, sizeof(ipv), "%u.%u.%u.%u",
                    (unsigned)((pv[i].ip>>24)&0xFF),(unsigned)((pv[i].ip>>16)&0xFF),
                    (unsigned)((pv[i].ip>>8)&0xFF),(unsigned)(pv[i].ip&0xFF));
            }
            pb.appendf(
                "%s{ip:'%s',remaining_s:%" PRIu32 "}", i ? "," : "", ipv, pv[i].remaining_s);
        }
        pb.appendf("]);</script>");
    }

    /* Clock status (NTP). (#105/#108 follow-up) Single renderer, same fix as
     * the pause table above: renderClock() (head script) builds this from
     * timesync_state()/timesync_source()/time(NULL) at first paint via this
     * inline call, and refreshDash() calls the same function with the same
     * fields from /metrics every 10s — one function, not two copies that
     * used to drift (the #75 "say which floor source" reasoning that
     * motivated the original wording lives in renderClock()'s own comment
     * now, not duplicated here). */
    {
        pb.appendf(
            "<p><small id=clock-status></small></p>"
            "<script>renderClock('%s','%s',%lld);</script>",
            timesync_state(), timesync_source(), (long long)time(NULL));
    }
    pb.appendf("</div><div class='tab' id=tab-blocklist>");

    /* whitelist table */
    if (wl_n > 0) {
        pb.appendf(
            "<h3>Whitelist</h3><table>"
            "<tr><th>Domain</th><th>Action</th></tr>");
        static EXT_RAM_BSS_ATTR char wl[WHITELIST_MAX][64]; uint32_t cnt = WHITELIST_MAX;
        blocklist_whitelist_get(wl, &cnt);
        for (uint32_t i = 0; i < cnt; i++) {
            if (!pb.has_room(256)) {
                pb.mark_truncated();
                break;
            }
            char safe_text[384];
            html_escape(safe_text, sizeof(safe_text), wl[i]);
            pb.appendf(
                "<tr><td>%s</td><td>"
                "<form method=post action=/whitelist/remove>"
                "<input type=hidden name=domain value=\"%s\">"
                "<button>Remove</button></form></td></tr>",
                safe_text, safe_text);
        }
        pb.appendf("</table>");
    }

    /* Custom block rules (#14) */
    {
        static EXT_RAM_BSS_ATTR char crules[CUSTOM_RULES_CAP + 8];
        static EXT_RAM_BSS_ATTR char safe_cr[CUSTOM_RULES_CAP * 2 + 8];
        size_t clen = blocklist_custom_get(crules, sizeof(crules));
        html_escape(safe_cr, sizeof(safe_cr), crules);
        pb.appendf(
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
        pb.appendf(
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
            pb.appendf("<table><tr><th>Domain</th><th>IP</th><th>Action</th></tr>");
            for (uint32_t i = 0; i < rw_cnt; i++) {
                if (!pb.has_room(256)) {
                    pb.mark_truncated();
                    break;
                }
                char safe_d[128]; html_escape(safe_d, sizeof(safe_d), rw_domains[i]);
                uint32_t ip = rw_ips[i];
                pb.appendf(
                    "<tr><td>%s</td><td>%u.%u.%u.%u</td><td>"
                    "<form method=post action=/rewrite/clear>"
                    "<input type=hidden name=domain value=\"%s\">"
                    "<button>Remove</button></form></td></tr>",
                    safe_d,
                    (unsigned)((ip>>24)&0xFF),(unsigned)((ip>>16)&0xFF),
                    (unsigned)((ip>>8)&0xFF),(unsigned)(ip&0xFF),
                    safe_d);
            }
            pb.appendf("</table>");
        }
    }

    /* Blocklist sources section (#4, #9) */
    pb.appendf(
        "<h3>Blocklist Sources</h3>"
        "<table><tr><th>#</th><th>URL</th><th>Status</th><th>Action</th></tr>"
        "<tr><td>0 (primary)</td><td>%s</td><td class='ok'>enabled</td><td>built-in</td></tr>",
        BLOCKLIST_URL);
    int free_slot = -1;
    for (int i = 0; i < BLOCKLIST_EXTRA_MAX; i++) {
        if (!pb.has_room(512)) {
            pb.mark_truncated();
            break;
        }
        char url[BLOCKLIST_URL_CAP]; blocklist_extra_url_get(i, url, sizeof(url));
        if (url[0]) {
            char safe_url[BLOCKLIST_URL_CAP * 2]; html_escape(safe_url, sizeof(safe_url), url);
            bool en = blocklist_extra_enabled_get(i);
            pb.appendf(
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
            pb.appendf(
                "<tr><td>%d (empty)</td><td>"
                "<form method=post action=/blocklist/url/set style='display:inline'>"
                "<input type=hidden name=idx value=%d>"
                "<input name=url placeholder='https://...' size=50>"
                "<button>Add</button></form></td><td></td><td></td></tr>",
                i + 1, i);
        }
    }
    pb.appendf("</table>");

    /* Presets dropdown + overflow text (#110 item 4: PageBuf tracks capacity) */
    {
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
            pb.appendf(
                "<form method=post action=/blocklist/url/set>"
                "<input type=hidden name=idx value=%d>"
                "<select name=url><option value=''>hagezi preset&hellip;</option>", free_slot);
            for (size_t i = 0; i < sizeof(presets)/sizeof(presets[0]); i++) {
                if (presets[i].full_url)
                    pb.appendf(
                        "<option value='%s'>%s</option>", presets[i].ref, presets[i].label);
                else
                    pb.appendf(
                        "<option value='%s%s'>%s</option>",
                        HAGEZI_BASE, presets[i].ref, presets[i].label);
            }
            pb.appendf("</select> <button>Add preset</button></form>");
        } else {
            /* F14: this dropdown is the only place any hagezi (or nsfw) URL
             * appears in the UI, and it used to vanish entirely once all extra
             * slots filled — exactly when the overflow banner just below is
             * telling the user to "remove a source or pick smaller lists"
             * with nowhere left to paste a replacement. Give the copyable
             * base URL + file names so removing a feed (table above) and
             * adding a smaller one doesn't need the README or GitHub open. */
            pb.appendf(
                "<p><small>All %d extra source slots are full — remove one above, "
                "then paste a preset URL: base <code>%s</code> + one of ",
                BLOCKLIST_EXTRA_MAX, HAGEZI_BASE);
            bool first = true;
            for (size_t i = 0; i < sizeof(presets)/sizeof(presets[0]); i++) {
                if (presets[i].full_url) continue;
                pb.appendf("%s<code>%s</code>",
                    first ? "" : ", ", presets[i].ref);
                first = false;
            }
            pb.appendf(
                ". Adult filtering: <code>%s</code>.</small></p>", NSFW_URL);
        }
    }

    if (bl_dropped > 0)
        pb.appendf(
            "<p class=warn><b>&#9888; Last reload overflowed the %uk-entry buffer: "
            "%" PRIu32 " entries dropped — blocking is incomplete.</b> "
            "Remove a source or pick smaller lists.</p>",
            (unsigned)(BLOCKLIST_CAPACITY / 1000), bl_dropped);
    /* blocklist_feed_failures(): a feed that hard-failed to download is a
     * different failure than capacity overflow above — entries it never
     * got to attempt, not entries it fetched and then discarded. */
    if (bl_feed_fail > 0)
        pb.appendf(
            "<p class=warn>&#9888; %" PRIu32 " source feed(s) failed to download on "
            "the last reload — the live list is missing their entries.</p>",
            bl_feed_fail);

    uint32_t bl_exc_drop = blocklist_exceptions_dropped();
    if (bl_exc_drop > 0)
        pb.appendf(
            "<p class=warn>&#9888; %" PRIu32 " feed exception rule(s) dropped (capacity %u) — "
            "allow-rules were dropped and affected names fail closed (remain blocked).</p>",
            bl_exc_drop, (unsigned)BL_EXCEPT_CAPACITY);

    pb.appendf(
        "<p><small>After adding/removing a source, click <b>Reload blocklist</b> above. "
        "Any http(s) list in plain, hosts, adblock or *.wildcard format works. All sources "
        "combined are capped at %uk entries after dedup vs primary; OISD uses ~270k of that. "
        "For hagezi use the <code>wildcard/</code> files, never <code>domains/</code>.</small></p>",
        (unsigned)(BLOCKLIST_CAPACITY / 1000));

    pb.appendf("</div><div class='tab' id=tab-access>");

    /* Client ACL section (#10) */
    {
        char acl_ips[ACL_MAX][20]; uint32_t acl_n = ACL_MAX;
        acl_list(acl_ips, &acl_n);
        pb.appendf(
            "<h3>Client Access Control</h3>"
            "<p><small>Empty = allow all. If any IP is listed, only those clients may resolve "
            "anything — the Ethernet fast path enforces this list too (#87), and hands any query "
            "it cannot clear to the socket path rather than answering it.</small></p>"
            "<form method=post action=/acl/add>"
            "<input name=ip placeholder='192.168.x.x' size=18>"
            "<button>Add allowed client</button></form>");
        if (acl_n > 0) {
            pb.appendf("<table><tr><th>Allowed client IP</th><th>Action</th></tr>");
            for (uint32_t i = 0; i < acl_n; i++) {
            if (!pb.has_room(256)) {
                pb.mark_truncated();
                break;
            }
                char safe_ip[48]; html_escape(safe_ip, sizeof(safe_ip), acl_ips[i]);
                pb.appendf(
                    "<tr><td>%s</td><td>"
                    "<form method=post action=/acl/remove>"
                    "<input type=hidden name=ip value=\"%s\">"
                    "<button>Remove</button></form></td></tr>",
                    safe_ip, safe_ip);
            }
            pb.appendf("</table>"
                "<form method=post action=/acl/clear style='margin-top:.5em'>"
                "<button>Clear all (allow everyone)</button></form>");
        }
    }

    /* Per-client bypass list (#74 Part 2) */
    {
        char byp_ips[BYPASS_MAX][20]; uint32_t byp_n = BYPASS_MAX;
        bypass_list(byp_ips, &byp_n);
        pb.appendf(
            "<h3>Per-Client Bypass</h3>"
            "<p><small>Listed clients always resolve unfiltered — no blocklist, no "
            "custom rules, applied the same way the timed pause is (delivery-time, "
            "never cached), over both Ethernet and Wi-Fi.</small></p>"
            "<form method=post action=/bypass/add>"
            "<input name=ip placeholder='192.168.x.x' size=18>"
            "<button>Add bypassed client</button></form>");
        if (byp_n > 0) {
            pb.appendf("<table><tr><th>Bypassed client IP</th><th>Action</th></tr>");
            for (uint32_t i = 0; i < byp_n; i++) {
            if (!pb.has_room(256)) {
                pb.mark_truncated();
                break;
            }
                char safe_ip[48]; html_escape(safe_ip, sizeof(safe_ip), byp_ips[i]);
                pb.appendf(
                    "<tr><td>%s</td><td>"
                    "<form method=post action=/bypass/remove>"
                    "<input type=hidden name=ip value=\"%s\">"
                    "<button>Remove</button></form></td></tr>",
                    safe_ip, safe_ip);
            }
            pb.appendf("</table>"
                "<form method=post action=/bypass/clear style='margin-top:.5em'>"
                "<button>Clear all</button></form>");
        }
    }

    /* Admin account (#89) — always on; changing it signs every session out. */
    {
        char user[WEB_AUTH_USER_MAX + 1]; web_auth_get_user(user, sizeof(user));
        char safe_user[80]; html_escape(safe_user, sizeof(safe_user), user);
        char fp[96]; web_tls_fingerprint(fp, sizeof(fp));
        pb.appendf(
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

    pb.appendf("</div><div class='tab' id=tab-network>");

    /* Dual-WAN interface selection (#53) — only when both links exist (#49) */
    if (dns_sink_wifi_built() && dns_sink_eth_built()) {
        char iface[8]="", eth_ip[16]="", wifi_ip[16]="";
        dns_sink_net_status(iface, sizeof(iface), eth_ip, sizeof(eth_ip), wifi_ip, sizeof(wifi_ip));
        pb.appendf(
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
        for (int i = 0; i < 2; i++) {
            /* (#49) Only the interfaces this build actually has. */
            if (i == 0 && !dns_sink_eth_built())  continue;
            if (i == 1 && !dns_sink_wifi_built()) continue;
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
            pb.appendf(
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
        pb.appendf(
            "<form method=post action=/reboot style='margin-top:.5em'>"
            "<button>Reboot now</button></form>");
    }

    /* Firmware update (#1) — mirrors upstream's OTA Upload tab */
    {
        const esp_partition_t *running = esp_ota_get_running_partition();
        pb.appendf(
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
        pb.appendf(
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
    pb.appendf("</div><div class='tab' id=tab-upstream>");

    /* DoT upstream settings (#5) */
    {
        bool dot_en = dot_is_enabled(); char dot_srv[64]="", dot_sni[64]="";
        dot_get(nullptr, dot_srv, dot_sni);
        /* (#94) Both fields are attacker-settable through POST /dot/set and were
         * interpolated raw into value="..." — a stored XSS that fired on every
         * later view of this tab. Escaped like every other value rendered here. */
        char safe_srv[sizeof(dot_srv) * 6], safe_sni[sizeof(dot_sni) * 6];
        html_escape(safe_srv, sizeof(safe_srv), dot_srv);
        html_escape(safe_sni, sizeof(safe_sni), dot_sni);
        pb.appendf(
            "<h3>Upstream DNS (DoT)</h3>"
            "<form method=post action=/dot/set>"
            "<label><input type=checkbox name=enabled value=1%s> Enable DNS-over-TLS</label><br>"
            "Server IP: <input name=server value=\"%s\" size=18> "
            "SNI: <input name=sni value=\"%s\" size=28><br>"
            "<small>Default: 1.1.1.1 / one.one.one.one &nbsp; or &nbsp; 9.9.9.9 / dns.quad9.net</small><br>"
            "<button>Save &amp; apply (restart DNS task)</button></form>",
            dot_en ? " checked" : "", safe_srv, safe_sni);

        /* Split-horizon zones: names the router answers, never sent over DoT. */
        char zones[LOCALZONE_LIST_CAP]; localzone_get(zones, sizeof(zones));
        char safe_zones[LOCALZONE_LIST_CAP * 2]; html_escape(safe_zones, sizeof(safe_zones), zones);
        pb.appendf(
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
    pb.appendf("</div>");

    pb.appendf("</body></html>");
    return pb.send(r);
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

/* ── GET /metrics/view ─ rendered dashboard over /metrics (#126) ──── */
/* The page is a plain `static const char[]` in .rodata and goes out through
 * send_html() with no format pass: no PSRAM page buffer (§3a), no vsnprintf
 * over ~7 KB on every request, and CSS percent signs need no doubling.
 *
 * It renders nothing server-side. The field map lives in the page's JS and it
 * polls /metrics, so dns_server_metrics_json() stays the single source of
 * truth for what a metric is called and what it holds — a second server-side
 * renderer would be a second list to keep in step, and it would drift. Any key
 * the map does not claim still appears, under "Other (ungrouped)": adding a
 * field to the JSON can therefore never make it silently invisible here, and a
 * non-empty Other section on a live board is the signal to group it.
 *
 * Two things the poll has to respect. The httpd is single-task (§3), so a
 * forgotten background tab must not keep hitting it — the interval skips while
 * document.hidden and a visibilitychange catches up on return. The very first
 * fetch is forced past that check, or a page opened in a background tab would
 * sit empty until it was looked at. And an expired session answers a GET with
 * a 303 to /login, which fetch follows and hands back as HTML; the response's
 * `redirected` flag is the reliable tell, so the page navigates to the login
 * form rather than silently failing to parse it as JSON.
 *
 * CSP (set_security_headers) is script-src 'unsafe-inline' with no 'self', so
 * this cannot become an external .js file; connect-src 'self' is what lets the
 * fetch through. */
static esp_err_t handle_metrics_view(httpd_req_t *r)
{
    static const char PAGE[] =
    "<!DOCTYPE html><html><head><meta charset=utf-8>\n"
    "<title>Metrics</title>\n"
    "<style>body{font-family:monospace;max-width:900px;margin:1em auto;padding:0 .5em}\n"
    "table{border-collapse:collapse;width:100%;margin:0 0 1.2em}\n"
    "td,th{border:1px solid #ccc;padding:.3em .6em;font-size:.85em}\n"
    "th{background:#222;color:#eee;text-align:left}th.r{text-align:right}\n"
    "td.k{width:55%;color:#333}td.v{text-align:right;font-weight:bold}\n"
    ".stats{display:flex;gap:.8em;flex-wrap:wrap;margin:1em 0}\n"
    ".stat{background:#f4f4f4;border:1px solid #ccc;border-radius:6px;padding:.5em 1em;min-width:100px;text-align:center}\n"
    ".stat .val{font-size:1.4em;font-weight:bold;color:#1a1a8c}\n"
    ".stat .lbl{font-size:.7em;color:#555}\n"
    ".ok{color:green}.warn{color:orange}\n"
    ".stat .val.ok{color:green}.stat .val.warn{color:orange}\n"
    "#age{color:#555;font-size:.8em}#age.stale{color:#c00;font-weight:bold}</style>\n"
    "</head><body>\n"
    "<h2>Metrics <small>(<a href='/'>home</a> &middot; <a href='/metrics'>raw JSON</a>)</small></h2>\n"
    "<div id=chips class=stats></div>\n"
    "<div id=body></div>\n"
    "<p id=age>waiting for the first sample</p>\n"
    "<p><small>Refreshes every 10 s while this tab is visible, and pauses when it is not.\n"
    "p50/p99 come from a log2 histogram and are bucket upper bounds, so they can read\n"
    "above an exact max. \"open-failed\" is the normal SD reading on a board with no card\n"
    "fitted. Counters that should stay at zero turn orange when they don't.</small></p>\n"
    "<script>\n"
    "var F=[\n"
    "['Traffic',[\n"
    " ['queries_total','Queries (socket path)','n',0],\n"
    " ['blocked','Blocked','n',0],\n"
    " ['forwarded','Forwarded upstream','n',0],\n"
    " ['tcp_queries','TCP queries','n',0],\n"
    " ['coalesced','Coalesced duplicates','n',0],\n"
    " ['stale_served','Stale answers served','n',0],\n"
    " ['case_mismatch','0x20 case mismatches','n',1]]],\n"
    "['Ethernet fast path',[\n"
    " ['l2_blocked','Blocked in the L2 hook','n',0],\n"
    " ['l2_cached','Cache hits in the L2 hook','n',0],\n"
    " ['l2_fallthrough','Handed to lwIP','n',0],\n"
    " ['l2_dns_fallthrough','...of which, confirmed DNS','n',0],\n"
    " ['l2_tx_fail','Transmit failures','n',1],\n"
    " ['l2_log_dropped','Query-log entries dropped','n',1],\n"
    " ['census_dropped','Census sightings dropped','n',1],\n"
    " ['wd_restarts','Watchdog restarts','n',1]]],\n"
    "['Forward cache',[\n"
    " ['cache_probes','Probes','n',0],\n"
    " ['cache_hits','Hits','n',0],\n"
    " ['cache_hit_rate','Hit rate','p',0],\n"
    " ['cache_evictions','Evictions','n',0],\n"
    " ['cache_too_big','Replies too big to cache','n',1]]],\n"
    "['Upstream',[\n"
    " ['upstream','Resolver','s',0],\n"
    " ['upstream_inflight','In flight','n',0],\n"
    " ['upstream_max','Table size','n',0],\n"
    " ['upstream_timeouts','Timeouts','n',1],\n"
    " ['hedges_sent','Hedged retransmits sent','n',0],\n"
    " ['hedged_completions','Answered by the hedge','n',0],\n"
    " ['dropped.table_full','Dropped: table full','n',1],\n"
    " ['dropped.mbox_pressure','Dropped: mailbox pressure','n',1]]],\n"
    "['Blocklist',[\n"
    " ['blocklist_count','Domains loaded','n',0],\n"
    " ['blocklist_loading','Reloading','B',0],\n"
    " ['blocklist_paused','Blocking paused','B',0],\n"
    " ['pause_active','Timed pauses active','n',0],\n"
    " ['bypass_count','Bypass entries','n',0],\n"
    " ['blocklist_dropped','Domains dropped (overflow)','n',1],\n"
    " ['blocklist_feed_failures','Feed failures','n',1],\n"
    " ['flash_status','Flash snapshot','T',0],\n"
    " ['sd_status','SD snapshot','T',0],\n"
    " ['sd_bytes','SD snapshot size','b',0]]],\n"
    "['System',[\n"
    " ['uptime_s','Uptime','d',0],\n"
    " ['clock','Clock','s',0],\n"
    " ['clock_src','Clock source','s',0],\n"
    " ['heap_free','Internal heap free','b',0],\n"
    " ['heap_largest','Largest internal block','b',0],\n"
    " ['psram_free','PSRAM free','b',0],\n"
    " ['dns_task_stack_hwm','DNS task stack headroom','b',0]]]];\n"
    "var SOK={loaded:1,saved:1};\n"
    "var SNEU={unknown:1,absent:1,empty:1,'open-failed':1};\n"
    "function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}\n"
    "function nf(v){return String(v).replace(/\\B(?=(\\d{3})+(?!\\d))/g,',');}\n"
    "function bf(v){v=+v;if(v<1024)return v+' B';if(v<1048576)return (v/1024).toFixed(1)+' KB';\n"
    " return (v/1048576).toFixed(2)+' MB';}\n"
    "function df(v){v=+v;var d=Math.floor(v/86400),h=Math.floor(v%86400/3600);\n"
    " var m=Math.floor(v%3600/60),s=Math.floor(v%60);\n"
    " return (d?d+'d ':'')+(d||h?h+'h ':'')+m+'m '+s+'s';}\n"
    "function uf(v){v=+v;if(v<1000)return v+' &micro;s';if(v<1000000)return (v/1000).toFixed(1)+' ms';\n"
    " return (v/1000000).toFixed(2)+' s';}\n"
    "function fmt(f,v){\n"
    " if(v===undefined||v===null)return '&mdash;';\n"
    " if(f[2]=='n')return nf(v);\n"
    " if(f[2]=='b')return bf(v);\n"
    " if(f[2]=='p')return (+v).toFixed(1)+'%';\n"
    " if(f[2]=='d')return df(v);\n"
    " if(f[2]=='B')return v?'yes':'no';\n"
    " return esc(v);}\n"
    "function cls(f,v){\n"
    " if(v===undefined||v===null)return '';\n"
    " if(f[2]=='T')return SOK[v]?'ok':(SNEU[v]?'':'warn');\n"
    " if(f[2]=='B')return v?'warn':'';\n"
    " if(f[3])return (+v>0)?'warn':'';\n"
    " return '';}\n"
    "function flat(j){var o={};\n"
    " for(var k in j){var v=j[k];\n"
    "  if(k=='latency_us')continue;\n"
    "  if(v&&typeof v=='object'){for(var k2 in v)o[k+'.'+k2]=v[k2];}\n"
    "  else o[k]=v;}\n"
    " return o;}\n"
    "function render(j){\n"
    " var m=flat(j),seen={},h='',i,s,k;\n"
    " var tot=+m.queries_total||0,blk=+m.blocked||0;\n"
    " var st=m.blocklist_loading?['Reloading','warn']:(m.blocklist_paused?['Paused','warn']:\n"
    "  ((+m.blocklist_dropped>0||+m.blocklist_feed_failures>0||+m.exceptions_dropped>0)?['Degraded','warn']:['Active','ok']));\n"
    " var chips=[[nf(m.blocklist_count),'Domains',''],[nf(tot),'Queries',''],[nf(blk),'Blocked',''],\n"
    "  [(tot?(100*blk/tot).toFixed(1):'0.0')+'%','Block rate',''],[st[0],'Status',st[1]],\n"
    "  [df(m.uptime_s),'Uptime','']];\n"
    " var c='';\n"
    " for(i=0;i<chips.length;i++)\n"
    "  c+='<div class=stat><div class=\"val '+chips[i][2]+'\">'+chips[i][0]+\n"
    "     '</div><div class=lbl>'+chips[i][1]+'</div></div>';\n"
    " document.getElementById('chips').innerHTML=c;\n"
    " for(s=0;s<F.length;s++){\n"
    "  h+='<table><tr><th>'+F[s][0]+'</th><th class=r>value</th></tr>';\n"
    "  for(i=0;i<F[s][1].length;i++){\n"
    "   var f=F[s][1][i];seen[f[0]]=1;\n"
    "   h+='<tr><td class=k>'+f[1]+'</td><td class=\"v '+cls(f,m[f[0]])+'\">'+fmt(f,m[f[0]])+'</td></tr>';}\n"
    "  h+='</table>';}\n"
    " var L=j.latency_us||{};\n"
    " h+='<table><tr><th>Latency</th><th class=r>p50</th><th class=r>p99</th>'+\n"
    "    '<th class=r>max</th><th class=r>count</th></tr>';\n"
    " for(k in L)h+='<tr><td class=k>'+esc(k)+'</td><td class=v>'+uf(L[k].p50)+'</td><td class=v>'+\n"
    "    uf(L[k].p99)+'</td><td class=v>'+uf(L[k].max)+'</td><td class=v>'+nf(L[k].count)+'</td></tr>';\n"
    " h+='</table>';\n"
    " var o='';\n"
    " for(k in m)if(!seen[k])o+='<tr><td class=k>'+esc(k)+'</td><td class=v>'+esc(m[k])+'</td></tr>';\n"
    " if(o)h+='<table><tr><th>Other (ungrouped)</th><th class=r>value</th></tr>'+o+'</table>';\n"
    " document.getElementById('body').innerHTML=h;}\n"
    "var LAST=0,FAILS=0,BUSY=false;\n"
    "function mark(){var a=document.getElementById('age');\n"
    " if(!LAST){\n"
    "  a.textContent=FAILS?('could not load /metrics - '+FAILS+' failed attempt'+(FAILS>1?'s':'')):'waiting for the first sample';\n"
    "  a.className=FAILS?'stale':'';return;}\n"
    " var s=Math.round((Date.now()-LAST)/1000);\n"
    " a.textContent='updated '+(s<2?'just now':s+'s ago')+(FAILS?' ('+FAILS+' failed since)':'');\n"
    " a.className=s>25?'stale':'';}\n"
    "function tick(force){\n"
    " if(BUSY||(document.hidden&&!force))return;\n"
    " BUSY=true;\n"
    " fetch('/metrics',{cache:'no-store'}).then(function(r){\n"
    "  if(r.redirected){location.href='/login';return null;}\n"
    "  return r.json();\n"
    " }).then(function(j){if(j){render(j);LAST=Date.now();FAILS=0;}BUSY=false;mark();})\n"
    " .catch(function(e){BUSY=false;FAILS++;console.error('metrics view:',e);mark();});}\n"
    "setInterval(tick,10000);\n"
    "setInterval(mark,1000);\n"
    "document.addEventListener('visibilitychange',function(){if(!document.hidden)tick();});\n"
    "tick(1);\n"
    "</script>\n"
    "</body></html>\n";
    send_html(r, PAGE);
    return ESP_OK;
}

/* ── GET /lastwords — crash flight recorder (#71) ────────────────── */
static esp_err_t handle_lastwords(httpd_req_t *r)
{
    static EXT_RAM_BSS_ATTR char json[1024];
    int n = crashlog_json(json, sizeof(json));
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
    /* #97: was a fixed 16-byte body window read with a raw strstr("on=1") —
     * any other field sent ahead of "on=" (or padding past 15 bytes) pushed
     * it out of the window and silently un-paused. form_field() is anchored
     * and url-decodes, so field order and extra fields no longer matter. */
    char body[64] = {}; httpd_req_recv(r, body, sizeof(body) - 1);
    char onv[4]; form_field(body, "on", onv, sizeof(onv));
    blocklist_set_paused(strcmp(onv, "1") == 0);
    httpd_resp_set_status(r, "303 See Other");
    httpd_resp_set_hdr(r, "Location", "/");
    httpd_resp_send(r, nullptr, 0);
    return ESP_OK;
}

/* ── POST /pause/timed — timed, scoped pause (#48) ─────────────────
 * Fields: min (1..PAUSE_MAX_MINUTES), scope (me | host | all), ip (with
 * scope=host), confirm=1 (with scope=all, second step). The cap and the
 * scope rules are enforced here, not just in the form; "me" is the
 * connection's own address, never a submitted one. A global pause without
 * confirm=1 renders a confirmation page instead of taking effect. */
static esp_err_t handle_pause_timed(httpd_req_t *r)
{
    if (!csrf_ok(r)) {
        httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "CSRF"); return ESP_FAIL;
    }
    char body[128] = {}; httpd_req_recv(r, body, sizeof(body) - 1);
    char minv[12], scope[8], ipv[24], conf[4];
    form_field(body, "min",     minv,  sizeof(minv));
    form_field(body, "scope",   scope, sizeof(scope));
    form_field(body, "ip",      ipv,   sizeof(ipv));
    form_field(body, "confirm", conf,  sizeof(conf));

    char *end = nullptr;
    long minutes = strtol(minv, &end, 10);
    if (minv[0] == '\0' || (end && *end != '\0') || minutes < 1 ||
        minutes > (long)PAUSE_MAX_MINUTES) {
        httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST,
                            "Duration must be 1 to 1440 minutes (24 h)");
        return ESP_FAIL;
    }

    uint32_t target;
    if (strcmp(scope, "all") == 0) {
        if (strcmp(conf, "1") != 0) {
            /* Second confirmation for the whole-network case. Self-contained
             * page (no tab script), so the CSRF token rides on the action. */
            char csrf[33] = ""; web_auth_session_csrf(s_req_sid, csrf, sizeof(csrf));
            static EXT_RAM_BSS_ATTR char page[1536];
            int n = snprintf(page, sizeof(page),
                "<!DOCTYPE html><html><head><meta charset=utf-8><title>Confirm pause</title>"
                "<style>body{font-family:monospace;max-width:700px;margin:2em auto}</style>"
                "</head><body><h2>Pause blocking for every device?</h2>"
                "<p>Are you sure? This disables blocking for <b>every device</b> on the "
                "network for <b>%ld minute%s</b>. It resumes by itself afterwards.</p>"
                "<form method=post action='/pause/timed?csrf=%s'>"
                "<input type=hidden name=min value=%ld>"
                "<input type=hidden name=scope value=all>"
                "<input type=hidden name=confirm value=1>"
                "<button>Yes, pause for everyone</button></form>"
                "<p><a href='/'>Cancel</a></p></body></html>",
                minutes, minutes == 1 ? "" : "s", csrf, minutes);
            httpd_resp_set_type(r, "text/html");
            httpd_resp_send(r, page, n);
            return ESP_OK;
        }
        target = PAUSE_IP_ALL;
    } else if (strcmp(scope, "host") == 0) {
        target = acl_parse_ip4(ipv);
        if (target == 0) {
            httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, "Enter the host's IPv4 address");
            return ESP_FAIL;
        }
    } else {
        target = req_peer_ip(r);
        if (target == 0) {
            httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST,
                                "Could not determine this device's IPv4 address");
            return ESP_FAIL;
        }
    }
    if (!pause_set(target, (uint32_t)minutes)) {
        httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST,
                            "Pause table is full — resume an existing pause first");
        return ESP_FAIL;
    }
    httpd_resp_set_status(r, "303 See Other");
    httpd_resp_set_hdr(r, "Location", "/");
    httpd_resp_send(r, nullptr, 0);
    return ESP_OK;
}

/* ── POST /pause/resume — end a timed pause early (#48) ───────────
 * ip=<dotted quad> resumes that host, ip=all resumes the all-devices entry,
 * ip=every clears the whole table. */
static esp_err_t handle_pause_resume(httpd_req_t *r)
{
    if (!csrf_ok(r)) {
        httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "CSRF"); return ESP_FAIL;
    }
    char body[64] = {}; httpd_req_recv(r, body, sizeof(body) - 1);
    char ipv[24]; form_field(body, "ip", ipv, sizeof(ipv));
    if (strcmp(ipv, "every") == 0)      pause_clear_all();
    else if (strcmp(ipv, "all") == 0)   pause_clear(PAUSE_IP_ALL);
    else {
        uint32_t ip = acl_parse_ip4(ipv);
        if (ip) pause_clear(ip);
    }
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
    char decoded[256]; form_field(body, "domain", decoded, sizeof(decoded));
    char norm[256]; size_t nlen = domain_normalize(norm, sizeof(norm), decoded, strlen(decoded));

    /* (#103, #117) Match the real verdict path exactly, in the same order:
     * rewrite first — a name with a matching rewrite never reaches the
     * resolver at all on the wire — then the shared rank-ordered verdict
     * (feed + whitelist + custom, including @@ exceptions and $important),
     * reporting which source decided it. Previously this only checked the
     * main list and never rewrites, so a rewritten or custom-rule-only
     * name showed the wrong answer here even though the wire behaved
     * correctly — the tool meant to verify a rule couldn't verify its own
     * kind of rule. */
    char verdict_text[64] = "ALLOWED";
    const char *color = "green";
    if (nlen > 0) {
        uint32_t rw_ip = rewrite_lookup(norm);
        if (rw_ip) {
            snprintf(verdict_text, sizeof(verdict_text), "REWRITE -&gt; %u.%u.%u.%u",
                     (unsigned)((rw_ip >> 24) & 0xFF), (unsigned)((rw_ip >> 16) & 0xFF),
                     (unsigned)((rw_ip >> 8) & 0xFF), (unsigned)(rw_ip & 0xFF));
            color = "blue";
        } else {
            bl_verdict_t v = blocklist_verdict(norm, nlen);
            bool blocked = v.state == BL_BLOCK;
            color = blocked ? "red" : "green";
            if (v.state == BL_NO_MATCH) {
                snprintf(verdict_text, sizeof(verdict_text), "ALLOWED");
            } else {
                snprintf(verdict_text, sizeof(verdict_text), "%s (%s)",
                         blocked ? "BLOCKED" : "ALLOWED", blocklist_verdict_src_name(v.src));
            }
        }
    }

    char safe[384]; html_escape(safe, sizeof(safe), norm);
    char page[768];
    snprintf(page, sizeof(page),
        "<!DOCTYPE html><html><body><h2>Check result</h2>"
        "<p><b>%s</b> is <b style='color:%s'>%s</b></p>"
        "<a href='/'>Back</a></body></html>",
        safe, color, verdict_text);
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
    char decoded[256]; form_field(body, "domain", decoded, sizeof(decoded));
    char norm[256]; size_t nlen = domain_normalize(norm, sizeof(norm), decoded, strlen(decoded));
    if (nlen == 0) { httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, "bad domain"); return ESP_FAIL; }
    if (!blocklist_whitelist_add(norm)) {
        httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST,
            "Whitelist is full (max 64), or the domain is too long");
        return ESP_FAIL;
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
    char decoded[256]; form_field(body, "domain", decoded, sizeof(decoded));
    char norm[256]; size_t nlen = domain_normalize(norm, sizeof(norm), decoded, strlen(decoded));
    if (nlen > 0) blocklist_whitelist_remove(norm);
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
    char sv[64]; form_field(body, "server", sv, sizeof(sv));
    if (sv[0]) snprintf(server, sizeof(server), "%s", sv);
    char sn[64]; form_field(body, "sni", sn, sizeof(sn));
    if (sn[0]) snprintf(sni, sizeof(sni), "%s", sn);
    /* (#94) Defence in depth behind the escaping: neither field can legitimately
     * hold anything but a dotted quad and a hostname, so reject the rest at the
     * door instead of storing it in NVS and re-rendering it forever. */
    unsigned o0, o1, o2, o3;
    if (sscanf(server, "%u.%u.%u.%u", &o0, &o1, &o2, &o3) != 4 ||
        o0 > 255 || o1 > 255 || o2 > 255 || o3 > 255) {
        httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, "bad server IP"); return ESP_FAIL;
    }
    for (const char *c = sni; *c; c++) {
        if (!isalnum((unsigned char)*c) && *c != '.' && *c != '-') {
            httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, "bad SNI"); return ESP_FAIL;
        }
    }
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
        {"ip", ip, sizeof(ip)}, {"nm", nm, sizeof(nm)},
        {"gw", gw, sizeof(gw)}, {"dns", dns_ip, sizeof(dns_ip)},
    };
    for (auto &f : fields) form_field(body, f.key, f.out, f.cap);
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
    form_field(body, "ssid", ssid, sizeof(ssid));
    form_field(body, "password", pass, sizeof(pass));
    if (!dns_sink_wifi_set_creds(ssid, pass)) {
        httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, "SSID must be 1-32 characters");
        return ESP_FAIL;
    }
    httpd_resp_set_status(r, "303 See Other"); httpd_resp_set_hdr(r, "Location", "/#network"); httpd_resp_send(r,nullptr,0); return ESP_OK;
}

/* ── POST /acl/add — add allowed client IP (#10) ────────────────── */
static esp_err_t handle_acl_add(httpd_req_t *r)
{
    if (!csrf_ok(r)) { httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "CSRF"); return ESP_FAIL; }
    char body[64] = {}; httpd_req_recv(r, body, sizeof(body) - 1);
    char ip[24]; form_field(body, "ip", ip, sizeof(ip));
    if (!acl_add(ip)) {
        httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, "ACL is full (max 8), or the IP is unparsable");
        return ESP_FAIL;
    }
    httpd_resp_set_status(r, "303 See Other"); httpd_resp_set_hdr(r, "Location", "/"); httpd_resp_send(r,nullptr,0); return ESP_OK;
}

/* ── POST /acl/remove ────────────────────────────────────────────── */
static esp_err_t handle_acl_remove(httpd_req_t *r)
{
    if (!csrf_ok(r)) { httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "CSRF"); return ESP_FAIL; }
    char body[64] = {}; httpd_req_recv(r, body, sizeof(body) - 1);
    char ip[24]; form_field(body, "ip", ip, sizeof(ip)); acl_remove(ip);
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

/* ── POST /bypass/add — add a per-client bypass IP (#74 Part 2) ──── */
static esp_err_t handle_bypass_add(httpd_req_t *r)
{
    if (!csrf_ok(r)) { httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "CSRF"); return ESP_FAIL; }
    char body[64] = {}; httpd_req_recv(r, body, sizeof(body) - 1);
    char ip[24]; form_field(body, "ip", ip, sizeof(ip)); bypass_add(ip);
    httpd_resp_set_status(r, "303 See Other"); httpd_resp_set_hdr(r, "Location", "/"); httpd_resp_send(r,nullptr,0); return ESP_OK;
}

/* ── POST /bypass/remove ──────────────────────────────────────────── */
static esp_err_t handle_bypass_remove(httpd_req_t *r)
{
    if (!csrf_ok(r)) { httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "CSRF"); return ESP_FAIL; }
    char body[64] = {}; httpd_req_recv(r, body, sizeof(body) - 1);
    char ip[24]; form_field(body, "ip", ip, sizeof(ip)); bypass_remove(ip);
    httpd_resp_set_status(r, "303 See Other"); httpd_resp_set_hdr(r, "Location", "/"); httpd_resp_send(r,nullptr,0); return ESP_OK;
}

/* ── POST /bypass/clear ───────────────────────────────────────────── */
static esp_err_t handle_bypass_clear(httpd_req_t *r)
{
    if (!csrf_ok(r)) { httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "CSRF"); return ESP_FAIL; }
    char body[4] = {}; httpd_req_recv(r, body, sizeof(body) - 1); /* consume body */
    bypass_clear();
    httpd_resp_set_status(r, "303 See Other"); httpd_resp_set_hdr(r, "Location", "/"); httpd_resp_send(r,nullptr,0); return ESP_OK;
}

/* ── POST /custom/rules — save inline block rules (#14) ─────────── */
static esp_err_t handle_custom_rules(httpd_req_t *r)
{
    if (!csrf_ok(r)) {
        httpd_resp_send_err(r, HTTPD_403_FORBIDDEN, "CSRF"); return ESP_FAIL;
    }
    /* Sized for the wire form, not the decoded cap: the textarea arrives
     * percent-encoded (every newline is 6 B for 2 decoded, '#'/space 3 B
     * each), so CUSTOM_RULES_CAP decoded chars can cost up to 3x that on
     * the wire. A single recv() isn't enough at this size either — loop to
     * content_len like handle_ota_update does. (#91) */
    static EXT_RAM_BSS_ATTR char body[CUSTOM_RULES_CAP * 3 + 64];
    if (r->content_len <= 0) { httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, ""); return ESP_FAIL; }
    if (r->content_len > (int)sizeof(body) - 1) {
        httpd_resp_send_err(r, HTTPD_413_CONTENT_TOO_LARGE, "");
        return ESP_FAIL;
    }
    int total = 0;
    while (total < r->content_len) {
        int got = httpd_req_recv(r, body + total, r->content_len - total);
        if (got <= 0) { httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, ""); return ESP_FAIL; }
        total += got;
    }
    body[total] = '\0';
    /* url-decode into a temp buffer. Sized the same as body (not the smaller
     * CUSTOM_RULES_CAP+4 decoded cap): decoding never grows a string, so
     * matching body's wire-worst-case bound here is the only way to guarantee
     * this can't itself truncate a submission that already fit in body. */
    static EXT_RAM_BSS_ATTR char decoded[CUSTOM_RULES_CAP * 3 + 64];
    if (!form_field(body, "rules", decoded, sizeof(decoded))) {
        httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, ""); return ESP_FAIL;
    }
    if (strlen(decoded) >= CUSTOM_RULES_CAP) {
        httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, "rules text exceeds the 4000-character cap");
        return ESP_FAIL;
    }
    if (!blocklist_custom_set(decoded)) {
        /* (#117) blocklist_custom_set() validates before writing anything —
         * the only realistic way to reach here from user input is too many
         * rules or one too long, not an NVS failure. */
        httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST,
            "too many rules (max 256) or a rule over 63 chars");
        return ESP_FAIL;
    }
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

/* ── GET /census — passive L2 census (#73 foundation) ────────────── */
static esp_err_t handle_census(httpd_req_t *r)
{
    static EXT_RAM_BSS_ATTR CensusClient entries[CENSUS_MAX];
    uint32_t n = census_snapshot(entries, CENSUS_MAX);
    uint32_t now_s = (uint32_t)(esp_timer_get_time() / 1000000ULL);

    /* Most-recently-seen first, so the newest device is easy to find and the
     * next one due for LRU eviction (census_observe's policy) is at the
     * bottom. Insertion sort, same shape as query_log_top_domains — n is
     * at most CENSUS_MAX (64). */
    for (uint32_t i = 1; i < n; i++) {
        CensusClient key = entries[i]; int j = (int)i - 1;
        while (j >= 0 && entries[j].last_seen_s < key.last_seen_s) { entries[j+1] = entries[j]; j--; }
        entries[j+1] = key;
    }

    static EXT_RAM_BSS_ATTR char page[12288];
    int pg = 0;
    page_appendf(page, sizeof(page), &pg,
        "<!DOCTYPE html><html><head><meta charset=utf-8>"
        "<title>LAN Census</title>"
        "<style>body{font-family:monospace;max-width:900px;margin:1em auto}"
        "table{border-collapse:collapse;width:100%%}"
        "td,th{border:1px solid #ccc;padding:.3em .6em;font-size:.85em}"
        "th{background:#222;color:#eee}.warn{color:#b58900}</style></head><body>"
        "<h2>LAN Census <small>(<a href='/'>home</a>)</small></h2>"
        "<p>Sightings on the wire (ARP/DHCP/DNS), not a verdict — a client "
        "flagged <b class='warn'>suspected bypass</b> has been seen on the "
        "LAN for over %d minutes but has never sent this board a DNS query; "
        "that means it may be using another resolver, not that it is doing "
        "anything wrong. IP and hostname are last-writer-wins across sighting "
        "kinds, so either can briefly show a stale value after a lease "
        "change.</p>"
        "<table><tr><th>MAC</th><th>IP</th><th>Hostname</th>"
        "<th>First seen</th><th>Last seen</th>"
        "<th>ARP</th><th>DHCP</th><th>Queries</th><th></th></tr>",
        CENSUS_GRACE_S / 60);
    uint32_t shown = 0;
    for (uint32_t i = 0; i < n && pg < (int)sizeof(page) - 256; i++, shown++) {
        CensusClient *c = &entries[i];
        char host[64]; html_escape(host, sizeof(host), c->hostname[0] ? c->hostname : "-");
        uint32_t age_s = now_s - c->first_seen_s;
        bool bypass = (c->arp_count || c->dhcp_count) && !c->query_count &&
                      age_s >= CENSUS_GRACE_S;
        page_appendf(page, sizeof(page), &pg,
            "<tr><td>%02x:%02x:%02x:%02x:%02x:%02x</td><td>%u.%u.%u.%u</td>"
            "<td>%s</td><td>%lus ago</td><td>%lus ago</td>"
            "<td>%" PRIu32 "</td><td>%" PRIu32 "</td><td>%" PRIu32 "</td>"
            "<td class='warn'>%s</td></tr>",
            c->mac[0], c->mac[1], c->mac[2], c->mac[3], c->mac[4], c->mac[5],
            (unsigned)((c->ip>>24)&0xFF),(unsigned)((c->ip>>16)&0xFF),
            (unsigned)((c->ip>>8)&0xFF),(unsigned)(c->ip&0xFF),
            host,
            (unsigned long)age_s, (unsigned long)(now_s - c->last_seen_s),
            c->arp_count, c->dhcp_count, c->query_count,
            bypass ? "suspected bypass" : "");
    }
    page_appendf(page, sizeof(page), &pg, "</table>");
    if (shown < n) {
        page_appendf(page, sizeof(page), &pg,
            "<p><b>%" PRIu32 " of %" PRIu32 " clients shown</b> — the page "
            "buffer filled before the rest would fit.</p>", shown, n);
    }
    page_appendf(page, sizeof(page), &pg, "</body></html>");
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
    char decoded_d[64]; form_field(body, "domain", decoded_d, sizeof(decoded_d));
    char norm[64]; size_t nlen = domain_normalize(norm, sizeof(norm), decoded_d, strlen(decoded_d));
    if (nlen == 0) { httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, "bad domain"); return ESP_FAIL; }
    /* extract IP value — require all four octets to parse and be in range */
    char ipv[24]; form_field(body, "ip", ipv, sizeof(ipv));
    unsigned b0=0,b1=0,b2=0,b3=0;
    if (sscanf(ipv, "%u.%u.%u.%u", &b0, &b1, &b2, &b3) != 4 ||
        b0 > 255 || b1 > 255 || b2 > 255 || b3 > 255) {
        httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, "bad ip"); return ESP_FAIL;
    }
    uint32_t ipv4 = ((uint32_t)b0<<24)|((uint32_t)b1<<16)|((uint32_t)b2<<8)|(uint32_t)b3;
    if (ipv4 == 0) { httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, "bad ip"); return ESP_FAIL; }
    if (!rewrite_set(norm, ipv4)) {
        httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, "Rewrite table is full (max 48)");
        return ESP_FAIL;
    }
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
    char decoded[64]; form_field(body, "domain", decoded, sizeof(decoded));
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
    int idx;
    if (!form_int(body, "idx", &idx, 0, BLOCKLIST_EXTRA_MAX - 1)) {
        httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, "bad idx"); return ESP_FAIL;
    }
    char decoded[BLOCKLIST_URL_CAP]; form_field(body, "url", decoded, sizeof(decoded));
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
    if (!blocklist_extra_url_set(idx, decoded)) {
        httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, "bad slot index or URL too long");
        return ESP_FAIL;
    }
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
    int idx;
    if (!form_int(body, "idx", &idx, 0, BLOCKLIST_EXTRA_MAX - 1)) {
        httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, "bad idx"); return ESP_FAIL;
    }
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
    int idx;
    if (!form_int(body, "idx", &idx, 0, BLOCKLIST_EXTRA_MAX - 1)) {
        httpd_resp_send_err(r, HTTPD_400_BAD_REQUEST, "bad idx"); return ESP_FAIL;
    }
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
    cfg.httpd.max_uri_handlers = 48;   /* 44 registered as of #73 — keep headroom */
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
        { "/metrics/view",        HTTP_GET,  H(handle_metrics_view)  },
        { "/lastwords",           HTTP_GET,  H(handle_lastwords)     },
        { "/metrics/reset",       HTTP_POST, H(handle_metrics_reset) },
        { "/reload",              HTTP_POST, H(handle_reload)        },
        { "/blocklist/stop",      HTTP_POST, H(handle_bl_stop)       },
        { "/pause",               HTTP_POST, H(handle_pause)         },
        { "/pause/timed",         HTTP_POST, H(handle_pause_timed)   },
        { "/pause/resume",        HTTP_POST, H(handle_pause_resume)  },
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
        { "/census",              HTTP_GET,  H(handle_census)        },
        { "/top",                 HTTP_GET,  H(handle_top)           },
        { "/custom/rules",        HTTP_POST, H(handle_custom_rules)  },
        { "/acl/add",             HTTP_POST, H(handle_acl_add)       },
        { "/acl/remove",          HTTP_POST, H(handle_acl_remove)    },
        { "/acl/clear",           HTTP_POST, H(handle_acl_clear)     },
        { "/bypass/add",          HTTP_POST, H(handle_bypass_add)    },
        { "/bypass/remove",       HTTP_POST, H(handle_bypass_remove) },
        { "/bypass/clear",        HTTP_POST, H(handle_bypass_clear)  },
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
