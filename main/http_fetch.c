#include "http_fetch.h"
#include "esp_http_client.h"
#include "esp_crt_bundle.h"
#include "esp_log.h"
#include "esp_timer.h"
#include <string.h>
#include <inttypes.h>

static const char *TAG = "http_fetch";

#define CHUNK_SIZE  4096
#define CARRY_SIZE  256

typedef struct {
    http_fetch_line_cb  cb;
    void               *user_ctx;
    char                carry[CARRY_SIZE];
    size_t              carry_len;
    bool                aborted;
    uint64_t            total_bytes;
    uint32_t            total_lines;
    int64_t             start_us;
    int64_t             last_log_us;
} fetch_ctx_t;

static void dispatch_line(fetch_ctx_t *fc, const char *p, size_t len)
{
    /* skip blank lines and comment lines (! or #) */
    if (len == 0 || p[0] == '!' || p[0] == '#') return;
    /* strip trailing CR */
    while (len > 0 && (p[len-1] == '\r' || p[len-1] == ' ')) len--;
    if (len == 0) return;
    fc->total_lines++;
    if (!fc->cb(p, len, fc->user_ctx)) fc->aborted = true;
}

static void maybe_log_progress(fetch_ctx_t *fc)
{
    int64_t now = esp_timer_get_time();
    if (now - fc->last_log_us < 2000000) return;   /* every 2s */
    float secs = (float)(now - fc->start_us) / 1e6f;
    float kbps = secs > 0 ? ((float)fc->total_bytes / 1024.0f) / secs : 0;
    ESP_LOGI(TAG, "downloading: %" PRIu32 " KB, %" PRIu32 " lines, %.0f KB/s",
             (uint32_t)(fc->total_bytes / 1024), fc->total_lines, kbps);
    fc->last_log_us = now;
}

static esp_err_t http_event_handler(esp_http_client_event_t *evt)
{
    fetch_ctx_t *fc = (fetch_ctx_t *)evt->user_data;
    if (fc->aborted) return ESP_FAIL;

    if (evt->event_id != HTTP_EVENT_ON_DATA) return ESP_OK;

    const char *in = (const char *)evt->data;
    int remaining = evt->data_len;
    fc->total_bytes += (uint64_t)remaining;
    maybe_log_progress(fc);

    while (remaining > 0 && !fc->aborted) {
        /* find next newline in current chunk */
        const char *nl = (const char *)memchr(in, '\n', remaining);
        if (!nl) {
            /* no newline — append to carry (capped) */
            size_t take = remaining;
            if (fc->carry_len + take >= CARRY_SIZE)
                take = CARRY_SIZE - fc->carry_len - 1;
            if (take > 0) {
                memcpy(fc->carry + fc->carry_len, in, take);
                fc->carry_len += take;
            }
            break;
        }

        size_t seg_len = nl - in;
        if (fc->carry_len > 0) {
            /* combine carry + segment before the newline */
            size_t take = seg_len;
            if (fc->carry_len + take >= CARRY_SIZE)
                take = CARRY_SIZE - fc->carry_len - 1;
            memcpy(fc->carry + fc->carry_len, in, take);
            fc->carry_len += take;
            fc->carry[fc->carry_len] = '\0';
            dispatch_line(fc, fc->carry, fc->carry_len);
            fc->carry_len = 0;
        } else {
            /* fast path: line entirely in current chunk */
            dispatch_line(fc, in, seg_len);
        }
        in += seg_len + 1;  /* skip past '\n' */
        remaining -= (int)(seg_len + 1);
    }
    return fc->aborted ? ESP_FAIL : ESP_OK;
}

bool http_fetch_lines(const char *url, http_fetch_line_cb cb, void *ctx)
{
    fetch_ctx_t fc = { .cb = cb, .user_ctx = ctx, .carry_len = 0, .aborted = false };
    fc.start_us = esp_timer_get_time();
    fc.last_log_us = fc.start_us;

    esp_http_client_config_t cfg = {
        .url                = url,
        .event_handler      = http_event_handler,
        .user_data          = &fc,
        .buffer_size        = CHUNK_SIZE,
        .timeout_ms         = 60000,
        .keep_alive_enable  = false,
        .crt_bundle_attach  = esp_crt_bundle_attach,
    };

    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    if (!client) { ESP_LOGE(TAG, "init failed"); return false; }

    esp_err_t err = esp_http_client_perform(client);
    int status    = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);

    if (err != ESP_OK || status != 200) {
        ESP_LOGE(TAG, "fetch failed err=%d status=%d", err, status);
        return false;
    }
    /* flush any unterminated last line */
    if (fc.carry_len > 0 && !fc.aborted) {
        fc.carry[fc.carry_len] = '\0';
        dispatch_line(&fc, fc.carry, fc.carry_len);
    }
    return !fc.aborted;
}
