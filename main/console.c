#include "console.h"
#include "web_auth.h"
#include "web_tls.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/usb_serial_jtag.h"
#include "esp_log.h"
#include "esp_heap_caps.h"
#include <string.h>

static const char *TAG = "console";

/* dns_sink.cpp (extern "C") */
bool dns_sink_wifi_set_creds(const char *ssid, const char *pass);
void dns_sink_wifi_get_ssid(char *out, size_t cap);
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
 *   status                     one-line liveness print
 *   heap                       internal / PSRAM free, largest block, low-water
 *   admin-reset                erase the web UI admin account; the browser
 *                              shows the first-boot setup wizard again (#89)
 *   cert-reset                 erase the self-signed TLS identity; a new one
 *                              is minted on the next boot (#89)
 *   cert                       print the TLS certificate fingerprint
 *   setup-psk                  print the setup AP's WPA2 passphrase
 *
 * Replies go out as normal log lines (visible on both consoles). Physical
 * USB access already implies full control (reflash), so no auth here — which
 * is exactly why the lost-password and lost-trust recoveries live here and
 * not in the web UI. */

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
            ESP_LOGW(TAG, "wifi: rejected (bad ssid/password length, or Wi-Fi disabled)");
    } else if (strcmp(line, "status") == 0) {
        char ssid[33];
        dns_sink_wifi_get_ssid(ssid, sizeof(ssid));
        char user[WEB_AUTH_USER_MAX + 1];
        web_auth_get_user(user, sizeof(user));
        ESP_LOGI(TAG, "alive, uptime %llus, wifi ssid \"%s\", web admin %s, setup AP %s",
                 (unsigned long long)(esp_log_timestamp() / 1000u), ssid,
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
    } else {
        ESP_LOGW(TAG, "unknown command (have: wifi, status, heap, admin-reset, cert-reset, cert, setup-psk)");
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
    ESP_LOGI(TAG, "USB recovery console ready (wifi/status/heap/admin-reset/cert-reset/cert/setup-psk)");
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
