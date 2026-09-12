#include "console.h"
#include "web_auth.h"
#include "web_tls.h"
#include "pause.h"
#include "acl.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/usb_serial_jtag.h"
#include "esp_log.h"
#include "esp_heap_caps.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static const char *TAG = "console";

/* dns_sink.cpp (extern "C") */
bool dns_sink_wifi_set_creds(const char *ssid, const char *pass);
void dns_sink_wifi_get_ssid(char *out, size_t cap);
bool dns_sink_wifi_built(void);
bool dns_sink_wifi_enabled(void);          /* live — this boot */
bool dns_sink_wifi_enabled_pending(void);  /* saved — next boot */
bool dns_sink_wifi_set_enabled(bool on);
bool dns_sink_setup_ap_active(void);
void dns_sink_setup_ap_passphrase(char *out, size_t cap);
const char *dns_sink_hostname(void);

/* Minimal USB recovery console (first slice of the USB-gadget roadmap item).
 * Reads newline-terminated commands from the native USB-Serial-JTAG port so a
 * headless board can be rescued over the same cable that flashes it — the
 * exact failure mode where the network is the thing that's broken.
 *
 * Commands:
 *   wifi <ssid> <password>     switch Wi-Fi STA credentials and reconnect;
 *                              quote an SSID containing spaces: wifi "a b" pw
 *   wifi-on / wifi-off         enable/disable Wi-Fi STA at boot (was the
 *                              build-time-only ADBLOCK_NET_WIFI option, now
 *                              an NVS flag — same "saved, reboot to apply"
 *                              as the web UI's checkbox). The recovery path
 *                              this exists for: an Ethernet board with
 *                              Wi-Fi disabled and no cable plugged in has no
 *                              other way to reach the web UI's toggle.
 *   status                     one-line liveness print
 *   heap                       internal / PSRAM free, largest block, low-water
 *   admin-reset                erase the web UI admin account; the browser
 *                              shows the first-boot setup wizard again (#89)
 *   cert-reset                 erase the self-signed TLS identity; a new one
 *                              is minted on the next boot (#89)
 *   cert                       print the TLS certificate fingerprint
 *   setup-psk                  print the setup AP's WPA2 passphrase
 *   pause <min> [ip|all]       suspend blocking for <min> minutes (#48), for
 *                              one client IP or, with "all", every client;
 *                              no scope argument lists what is active
 *   resume [ip|all]            end a pause early; no argument clears them all
 *
 * Replies go out as normal log lines (visible on both consoles). Physical
 * USB access already implies full control (reflash), so no auth here — which
 * is exactly why the lost-password and lost-trust recoveries live here and
 * not in the web UI. */

static void console_pause_list(void)
{
    pause_view_t pv[PAUSE_MAX];
    uint32_t n = pause_list(pv, PAUSE_MAX);
    if (n == 0) { ESP_LOGI(TAG, "no pause active — blocking is on for every client"); return; }
    for (uint32_t i = 0; i < n; i++) {
        if (pv[i].ip == PAUSE_IP_ALL)
            ESP_LOGI(TAG, "paused: ALL clients, %um%02us left",
                     (unsigned)(pv[i].remaining_s / 60), (unsigned)(pv[i].remaining_s % 60));
        else
            ESP_LOGI(TAG, "paused: %u.%u.%u.%u, %um%02us left",
                     (unsigned)((pv[i].ip >> 24) & 0xFF), (unsigned)((pv[i].ip >> 16) & 0xFF),
                     (unsigned)((pv[i].ip >> 8) & 0xFF), (unsigned)(pv[i].ip & 0xFF),
                     (unsigned)(pv[i].remaining_s / 60), (unsigned)(pv[i].remaining_s % 60));
    }
}

static void handle_line(char *line)
{
    while (*line == ' ') line++;
    if (line[0] == '\0') return;

    if (strncmp(line, "wifi ", 5) == 0) {
        char *p = line + 5;
        while (*p == ' ') p++;
        char *ssid = p, *pass = NULL;
        if (*p == '"') {
            ssid = ++p;
            while (*p && *p != '"') p++;
            if (*p != '"') { ESP_LOGW(TAG, "unterminated quote"); return; }
            *p++ = '\0';
        } else {
            while (*p && *p != ' ') p++;
        }
        if (*p) { *p++ = '\0'; while (*p == ' ') p++; pass = p; }
        if (dns_sink_wifi_set_creds(ssid, pass))
            ESP_LOGI(TAG, "Wi-Fi credentials set — reconnecting to \"%s\"", ssid);
        else
            ESP_LOGW(TAG, "wifi: rejected (bad ssid/password length, or Wi-Fi not built in)");
    } else if (strcmp(line, "wifi-on") == 0 || strcmp(line, "wifi-off") == 0) {
        bool on = (strcmp(line, "wifi-on") == 0);
        if (!dns_sink_wifi_built())
            ESP_LOGW(TAG, "wifi-%s: Wi-Fi not built into this image", on ? "on" : "off");
        else if (!dns_sink_wifi_set_enabled(on))
            ESP_LOGW(TAG, "wifi-off: rejected — this board has no Ethernet to fall back to");
        else
            ESP_LOGI(TAG, "Wi-Fi will be %s on next reboot (currently %s) — reboot to apply",
                     on ? "enabled" : "disabled", dns_sink_wifi_enabled() ? "on" : "off");
    } else if (strcmp(line, "status") == 0) {
        char ssid[33];
        dns_sink_wifi_get_ssid(ssid, sizeof(ssid));
        char user[WEB_AUTH_USER_MAX + 1];
        web_auth_get_user(user, sizeof(user));
        char wifi_state[40] = "not built";
        if (dns_sink_wifi_built()) {
            bool en = dns_sink_wifi_enabled(), pend = dns_sink_wifi_enabled_pending();
            if (en == pend) snprintf(wifi_state, sizeof(wifi_state), "%s", en ? "on" : "off");
            else snprintf(wifi_state, sizeof(wifi_state), "%s (pending %s)",
                          en ? "on" : "off", pend ? "on" : "off");
        }
        ESP_LOGI(TAG, "alive, uptime %llus, wifi %s ssid \"%s\", web admin %s, setup AP %s",
                 (unsigned long long)(esp_log_timestamp() / 1000u), wifi_state, ssid,
                 web_auth_setup_needed() ? "NOT SET (setup mode)" : user,
                 dns_sink_setup_ap_active() ? "active" : "off");
    } else if (strcmp(line, "admin-reset") == 0) {
        web_auth_reset();
        ESP_LOGW(TAG, "browse to https://%s/ to create a new admin account", dns_sink_hostname());
    } else if (strcmp(line, "cert-reset") == 0) {
        web_tls_reset();
        ESP_LOGW(TAG, "reboot to generate the new certificate");
    } else if (strcmp(line, "cert") == 0) {
        char fp[96]; web_tls_fingerprint(fp, sizeof(fp));
        ESP_LOGI(TAG, "TLS certificate SHA-256: %s", fp[0] ? fp : "(none yet)");
    } else if (strcmp(line, "heap") == 0) {
        ESP_LOGI(TAG, "internal free %u largest %u min-ever %u | psram free %u largest %u",
                 (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
                 (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL),
                 (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL),
                 (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM),
                 (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM));
    } else if (strcmp(line, "setup-psk") == 0) {
        char psk[24]; dns_sink_setup_ap_passphrase(psk, sizeof(psk));
        if (psk[0]) ESP_LOGI(TAG, "setup AP \"ESP32AdBlock-Setup\" WPA2 passphrase: %s", psk);
        else        ESP_LOGI(TAG, "Wi-Fi not built in — no setup AP");
    } else if (strncmp(line, "pause", 5) == 0 && (line[5] == '\0' || line[5] == ' ')) {
        /* (#48) The web UI is the intended control, but it needs a login —
         * and the whole point of this console is the case where that is not
         * available. Same server-side cap and scope rules as the UI; the
         * only difference is that a global pause here needs no second
         * confirmation, because physical USB access already implies it. */
        char *p = line + 5;
        while (*p == ' ') p++;
        if (*p == '\0') { console_pause_list(); return; }
        char *scope = p;
        while (*scope && *scope != ' ') scope++;
        if (*scope) *scope++ = '\0';
        while (*scope == ' ') scope++;
        long minutes = strtol(p, NULL, 10);
        uint32_t ip = (*scope == '\0' || strcmp(scope, "all") == 0)
                    ? PAUSE_IP_ALL : acl_parse_ip4(scope);
        if (*scope != '\0' && strcmp(scope, "all") != 0 && ip == 0)
            ESP_LOGW(TAG, "pause: '%s' is not an IPv4 address", scope);
        else if (!pause_set(ip, (uint32_t)minutes))
            ESP_LOGW(TAG, "pause: rejected (1-%u minutes, and the table holds %d entries)",
                     (unsigned)PAUSE_MAX_MINUTES, PAUSE_MAX);
        else
            console_pause_list();
    } else if (strncmp(line, "resume", 6) == 0 && (line[6] == '\0' || line[6] == ' ')) {
        char *p = line + 6;
        while (*p == ' ') p++;
        if (*p == '\0')                    ESP_LOGI(TAG, "resume: %u pause(s) cleared",
                                                    (unsigned)pause_clear_all());
        else if (strcmp(p, "all") == 0)    ESP_LOGI(TAG, "resume all-clients pause: %s",
                                                    pause_clear(PAUSE_IP_ALL) ? "cleared" : "none active");
        else {
            uint32_t ip = acl_parse_ip4(p);
            if (!ip) ESP_LOGW(TAG, "resume: '%s' is not an IPv4 address", p);
            else     ESP_LOGI(TAG, "resume %s: %s", p, pause_clear(ip) ? "cleared" : "none active");
        }
        console_pause_list();
    } else {
        ESP_LOGW(TAG, "unknown command (have: wifi, wifi-on, wifi-off, status, heap, "
                      "admin-reset, cert-reset, cert, setup-psk, pause, resume)");
    }
}

static void console_task(void *arg)
{
    (void)arg;
    usb_serial_jtag_driver_config_t cfg = {
        .tx_buffer_size = 256,
        .rx_buffer_size = 256,
    };
    if (usb_serial_jtag_driver_install(&cfg) != ESP_OK) {
        ESP_LOGW(TAG, "usb_serial_jtag driver install failed — console disabled");
        vTaskDelete(NULL);
        return;
    }
    ESP_LOGI(TAG, "USB recovery console ready "
                  "(wifi/wifi-on/wifi-off/status/heap/admin-reset/cert-reset/cert/setup-psk/pause/resume)");
    static char line[160];
    size_t have = 0;
    for (;;) {
        uint8_t ch;
        if (usb_serial_jtag_read_bytes(&ch, 1, pdMS_TO_TICKS(250)) <= 0) continue;
        if (ch == '\r') continue;
        if (ch != '\n') {
            if (have < sizeof(line) - 1) line[have++] = (char)ch;
            continue;
        }
        line[have] = '\0';
        have = 0;
        handle_line(line);
    }
}

void console_start(void)
{
    xTaskCreate(console_task, "usb_console", 3072, NULL, 2, NULL);
}
