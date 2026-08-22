#include "console.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/usb_serial_jtag.h"
#include "esp_log.h"
#include <string.h>

static const char *TAG = "console";

/* dns_sink.cpp (extern "C") */
bool dns_sink_wifi_set_creds(const char *ssid, const char *pass);
void dns_sink_wifi_get_ssid(char *out, size_t cap);

/* Minimal USB recovery console (first slice of the USB-gadget roadmap item).
 * Reads newline-terminated commands from the native USB-Serial-JTAG port so a
 * headless board can be rescued over the same cable that flashes it — the
 * exact failure mode where the network is the thing that's broken.
 *
 * Commands:
 *   wifi <ssid> <password>     switch Wi-Fi STA credentials and reconnect;
 *                              quote an SSID containing spaces: wifi "a b" pw
 *   status                     one-line liveness print
 *
 * Replies go out as normal log lines (visible on both consoles). Physical
 * USB access already implies full control (reflash), so no auth here. */

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
        ESP_LOGI(TAG, "alive, uptime %llus, wifi ssid \"%s\"",
                 (unsigned long long)(esp_log_timestamp() / 1000u), ssid);
    } else {
        ESP_LOGW(TAG, "unknown command (have: wifi, status)");
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
    ESP_LOGI(TAG, "USB recovery console ready (wifi/status)");
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
