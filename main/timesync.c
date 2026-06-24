#include "timesync.h"
#include "esp_netif_sntp.h"
#include "esp_sntp.h"
#include "esp_log.h"
#include <time.h>
#include <sys/time.h>
#include <stdlib.h>

/* Uses the built-in lwIP SNTP client (esp_netif_sntp) — the lightweight
 * Espressif-native path: one UDP socket, ~1 KB, no extra component. */

static const char *TAG = "timesync";
static volatile bool s_synced = false;

static void on_sync(struct timeval *tv)
{
    (void)tv;
    s_synced = true;
    time_t now = time(NULL);
    struct tm tm_utc;
    gmtime_r(&now, &tm_utc);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_utc);
    ESP_LOGI(TAG, "Clock synced: %s UTC", buf);
}

void timesync_start(void)
{
    setenv("TZ", "UTC0", 1);
    tzset();

    esp_sntp_config_t cfg = ESP_NETIF_SNTP_DEFAULT_CONFIG_MULTIPLE(
        2, ESP_SNTP_SERVER_LIST("time.nist.gov", "pool.ntp.org"));
    cfg.sync_cb = on_sync;
    cfg.start   = true;

    esp_err_t e = esp_netif_sntp_init(&cfg);
    if (e != ESP_OK) {
        ESP_LOGW(TAG, "SNTP init failed: %s", esp_err_to_name(e));
        return;
    }
    ESP_LOGI(TAG, "SNTP started (time.nist.gov, pool.ntp.org) — UTC");
}

bool timesync_is_synced(void) { return s_synced; }

uint32_t timesync_epoch(void)
{
    if (!s_synced) return 0;
    return (uint32_t)time(NULL);
}
