#include "dot.h"
#include "esp_tls.h"
#include "esp_crt_bundle.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

static const char *TAG = "dot";
#define NVS_NS  "dns_sink"
#define DOT_PORT 853

/* Per-operation TLS bound. This now runs in the worker task, so a slow DoT
 * query stalls only other DoT queries — never UDP service (C2 closed). */
#define DOT_TIMEOUT_MS 1500

#define DOT_REQ_MAX   512    /* queries are question-sized */
#define DOT_REP_MAX   1500   /* matches the dns_task rx buffer */
#define DOT_REQ_DEPTH 12
#define DOT_REP_DEPTH 6

typedef struct { uint16_t len; uint8_t data[DOT_REQ_MAX]; } dot_req_t;
typedef struct { uint16_t len; uint8_t failed; uint8_t data[DOT_REP_MAX]; } dot_rep_t;

static bool s_enabled    = false;
static char s_server[64] = "1.1.1.1";
static char s_sni[64]    = "one.one.one.one";

static QueueHandle_t s_req_q = NULL;
static QueueHandle_t s_rep_q = NULL;
static bool          s_worker_up = false;
static esp_tls_t    *s_conn = NULL;      /* worker-task-only */

bool dot_is_enabled(void) { return s_enabled && s_worker_up; }

/* ── Persistent-session plumbing (worker task only) ──────────────── */

static void conn_drop(void)
{
    if (s_conn) { esp_tls_conn_destroy(s_conn); s_conn = NULL; }
}

static bool conn_ensure(void)
{
    if (s_conn) return true;

    esp_tls_cfg_t cfg = {
        .timeout_ms          = DOT_TIMEOUT_MS,
        .crt_bundle_attach   = esp_crt_bundle_attach,
        .skip_common_name    = false,
        .common_name         = s_sni[0] ? s_sni : NULL,
        .use_secure_element  = false,
        .use_global_ca_store = false,
    };
    esp_tls_t *tls = esp_tls_init();
    if (!tls) return false;
    char host[80]; snprintf(host, sizeof(host), "%s", s_server);
    if (esp_tls_conn_new_sync(host, strlen(host), DOT_PORT, &cfg, tls) != 1) {
        ESP_LOGW(TAG, "TLS connect failed (%s:%d)", s_server, DOT_PORT);
        esp_tls_conn_destroy(tls);
        return false;
    }
    s_conn = tls;
    ESP_LOGI(TAG, "persistent DoT session up (%s, SNI %s)", s_server, s_sni);
    return true;
}

/* One RFC 7858 exchange on the persistent session. Returns reply length,
 * or -1 on any transport error (caller drops the session and may retry). */
static int conn_roundtrip(const uint8_t *q, int qlen, uint8_t *out, int cap)
{
    uint8_t framed[2 + DOT_REQ_MAX];
    framed[0] = (uint8_t)(qlen >> 8);
    framed[1] = (uint8_t)(qlen & 0xFF);
    memcpy(framed + 2, q, (size_t)qlen);

    size_t written = 0;
    while (written < (size_t)(qlen + 2)) {
        int w = esp_tls_conn_write(s_conn, framed + written, (size_t)(qlen + 2) - written);
        if (w <= 0) return -1;
        written += (size_t)w;
    }
    uint8_t lenbuf[2]; size_t rread = 0;
    while (rread < 2) {
        int r = esp_tls_conn_read(s_conn, lenbuf + rread, 2 - rread);
        if (r <= 0) return -1;
        rread += (size_t)r;
    }
    int rlen = ((int)lenbuf[0] << 8) | lenbuf[1];
    if (rlen <= 0 || rlen > cap) {
        ESP_LOGW(TAG, "oversize/bad DoT reply length %d", rlen);
        return -1;                       /* drop session; UDP fallback serves it */
    }
    rread = 0;
    while (rread < (size_t)rlen) {
        int r = esp_tls_conn_read(s_conn, out + rread, (size_t)rlen - rread);
        if (r <= 0) return -1;
        rread += (size_t)r;
    }
    return rlen;
}

static void dot_task(void *arg)
{
    (void)arg;
    for (;;) {
        dot_req_t req;
        if (xQueueReceive(s_req_q, &req, pdMS_TO_TICKS(1000)) != pdTRUE) {
            /* idle: nothing to do. The session stays parked; a server-side
             * idle close surfaces as a failed first attempt + reconnect. */
            continue;
        }
        static dot_rep_t rep;            /* worker-task-only; keep off the stack */
        int rlen = -1;
        /* Two attempts: the first failure is usually a server-closed idle
         * session — reconnect and retry once before declaring failure. */
        for (int attempt = 0; attempt < 2 && rlen < 0; attempt++) {
            if (!conn_ensure()) continue;
            rlen = conn_roundtrip(req.data, req.len, rep.data, sizeof(rep.data));
            if (rlen < 0) conn_drop();
        }
        if (rlen > 0) {
            rep.len = (uint16_t)rlen; rep.failed = 0;
        } else {
            /* echo the query back so the dns_task can re-send it over UDP */
            memcpy(rep.data, req.data, req.len);
            rep.len = req.len; rep.failed = 1;
        }
        if (xQueueSend(s_rep_q, &rep, 0) != pdTRUE) {
            /* reply queue full — the entry times out via upstream eviction */
            ESP_LOGW(TAG, "reply queue full, result dropped");
        }
    }
}

static void worker_start_once(void)
{
    if (s_worker_up) return;
    s_req_q = xQueueCreate(DOT_REQ_DEPTH, sizeof(dot_req_t));
    s_rep_q = xQueueCreate(DOT_REP_DEPTH, sizeof(dot_rep_t));
    if (!s_req_q || !s_rep_q) {
        ESP_LOGE(TAG, "queue alloc failed — DoT disabled");
        return;
    }
    if (xTaskCreatePinnedToCore(dot_task, "dot_worker", 8192, NULL, 5, NULL, 0) != pdPASS) {
        ESP_LOGE(TAG, "worker task create failed — DoT disabled");
        return;
    }
    s_worker_up = true;
}

/* ── dns_task-facing API ─────────────────────────────────────────── */

bool dot_enqueue(const uint8_t *query, int qlen)
{
    if (!dot_is_enabled() || qlen <= 0 || qlen > DOT_REQ_MAX) return false;
    dot_req_t req;
    req.len = (uint16_t)qlen;
    memcpy(req.data, query, (size_t)qlen);
    return xQueueSend(s_req_q, &req, 0) == pdTRUE;
}

int dot_reply_get(uint8_t *out, int cap, bool *failed)
{
    if (!s_worker_up || !out || !failed) return 0;
    dot_rep_t rep;                        /* 1.5KB on dns_task stack (12KB, HWM ok) */
    if (xQueueReceive(s_rep_q, &rep, 0) != pdTRUE) return 0;
    if (rep.len > cap) return 0;          /* can't happen: cap is the rx buffer */
    memcpy(out, rep.data, rep.len);
    *failed = (rep.failed != 0);
    return rep.len;
}

/* ── Config (unchanged surface) ──────────────────────────────────── */

void dot_set(bool enabled, const char *server_ip, const char *sni)
{
    s_enabled = enabled;
    if (server_ip) snprintf(s_server, sizeof(s_server), "%s", server_ip);
    if (sni)       snprintf(s_sni,    sizeof(s_sni),    "%s", sni);

    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_u8(h,  "dot_en",  enabled ? 1 : 0);
        nvs_set_str(h, "dot_srv", s_server);
        nvs_set_str(h, "dot_sni", s_sni);
        nvs_commit(h);
        nvs_close(h);
    }
    if (enabled) worker_start_once();
}

void dot_get(bool *en, char *srv, char *sni)
{
    if (en)  *en  = s_enabled;
    if (srv) snprintf(srv, 64, "%s", s_server);
    if (sni) snprintf(sni, 64, "%s", s_sni);
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
    if (s_enabled) {
        ESP_LOGI(TAG, "DoT upstream enabled: %s (SNI: %s)", s_server, s_sni);
        worker_start_once();
    }
    return true;
}
