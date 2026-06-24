#include "dot.h"
#include "esp_tls.h"
#include "esp_crt_bundle.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

static const char *TAG = "dot";
#define NVS_NS  "dns_sink"
#define DOT_PORT 853
#define DOT_TIMEOUT_MS 3000

static bool s_enabled    = false;
static char s_server[64] = "1.1.1.1";
static char s_sni[64]    = "one.one.one.one";

bool dot_is_enabled(void) { return s_enabled; }

void dot_set(bool enabled, const char *server_ip, const char *sni)
{
    s_enabled = enabled;
    if (server_ip) snprintf(s_server, sizeof(s_server), "%s", server_ip);
    if (sni)       snprintf(s_sni,    sizeof(s_sni),    "%s", sni);

    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) return;
    nvs_set_u8(h,  "dot_en",  enabled ? 1 : 0);
    nvs_set_str(h, "dot_srv", s_server);
    nvs_set_str(h, "dot_sni", s_sni);
    nvs_commit(h);
    nvs_close(h);
}

void dot_get(bool *en, char *srv, char *sni)
{
    if (en)  *en  = s_enabled;
    if (srv) snprintf(srv, 64, "%s", s_server);
    if (sni) snprintf(sni, 64, "%s", s_sni);
}

/* Load persisted config at boot */
__attribute__((constructor))
static void dot_load_nvs(void)
{
    /* called too early — NVS may not be initialized yet; use dot_init instead */
}

bool dot_init_nvs(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) return true;
    uint8_t en = 0;
    nvs_get_u8(h, "dot_en", &en);
    s_enabled = (en != 0);
    size_t len = sizeof(s_server);
    nvs_get_str(h, "dot_srv", s_server, &len);
    len = sizeof(s_sni);
    nvs_get_str(h, "dot_sni", s_sni, &len);
    nvs_close(h);
    if (s_enabled)
        ESP_LOGI(TAG, "DoT upstream enabled: %s (SNI: %s)", s_server, s_sni);
    return true;
}

int dot_resolve(const uint8_t *query, int qlen, uint8_t *resp, int cap)
{
    if (qlen <= 0 || qlen > 512 || !query || !resp || cap < 16) return -1;

    esp_tls_cfg_t cfg = {
        .timeout_ms            = DOT_TIMEOUT_MS,
        .crt_bundle_attach     = esp_crt_bundle_attach,
        .skip_common_name      = false,
        .common_name           = s_sni[0] ? s_sni : NULL,
        .use_secure_element    = false,
        .use_global_ca_store   = false,
    };

    esp_tls_t *tls = esp_tls_init();
    if (!tls) { ESP_LOGW(TAG, "esp_tls_init failed"); return -1; }

    /* Connect to DoT server on port 853 */
    char host[80]; snprintf(host, sizeof(host), "%s", s_server);
    int ret = esp_tls_conn_new_sync(host, strlen(host), DOT_PORT, &cfg, tls);
    if (ret != 1) {
        ESP_LOGW(TAG, "TLS connect failed (%s:%d): %d", s_server, DOT_PORT, ret);
        esp_tls_conn_destroy(tls);
        return -1;
    }

    /* RFC 7858: 2-byte length prefix then DNS message */
    uint8_t framed[2 + 512];
    framed[0] = (uint8_t)((qlen >> 8) & 0xFF);
    framed[1] = (uint8_t)(qlen & 0xFF);
    memcpy(framed + 2, query, (size_t)qlen);

    size_t written = 0;
    while (written < (size_t)(qlen + 2)) {
        int w = esp_tls_conn_write(tls, framed + written, (size_t)(qlen + 2) - written);
        if (w <= 0) { ESP_LOGW(TAG, "write failed: %d", w); esp_tls_conn_destroy(tls); return -1; }
        written += (size_t)w;
    }

    /* Read 2-byte response length */
    uint8_t lenbuf[2]; size_t rread = 0;
    while (rread < 2) {
        int r = esp_tls_conn_read(tls, lenbuf + rread, 2 - rread);
        if (r <= 0) { ESP_LOGW(TAG, "read len failed: %d", r); esp_tls_conn_destroy(tls); return -1; }
        rread += (size_t)r;
    }
    int rlen = ((int)lenbuf[0] << 8) | lenbuf[1];
    if (rlen <= 0 || rlen > cap) {
        ESP_LOGW(TAG, "bad response length %d", rlen);
        esp_tls_conn_destroy(tls);
        return -1;
    }

    /* Read response body */
    rread = 0;
    while (rread < (size_t)rlen) {
        int r = esp_tls_conn_read(tls, resp + rread, (size_t)rlen - rread);
        if (r <= 0) { ESP_LOGW(TAG, "read body failed: %d", r); esp_tls_conn_destroy(tls); return -1; }
        rread += (size_t)r;
    }

    esp_tls_conn_destroy(tls);
    ESP_LOGD(TAG, "DoT resolved %d bytes response", rlen);
    return rlen;
}
