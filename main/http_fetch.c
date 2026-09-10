#include "http_fetch.h"
#include "esp_http_client.h"
#include "esp_crt_bundle.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "lwip/sockets.h"
#include <string.h>
#include <inttypes.h>

static const char *TAG = "http_fetch";

#define CHUNK_SIZE  4096
#define CARRY_SIZE  256

typedef struct {
    http_fetch_line_cb   line_cb;
    http_fetch_abort_cb  abort_cb;
    void                *user_ctx;
    char                 carry[CARRY_SIZE];
    size_t               carry_len;
    volatile bool        aborted;
    volatile bool        timed_out;
    uint64_t             total_bytes;
    uint32_t             total_lines;
    int64_t              start_us;
    int64_t              last_data_us;
    int64_t              last_log_us;
    int64_t              inactivity_timeout_us;
    int64_t              total_timeout_us;
    esp_http_client_handle_t client;
} fetch_ctx_t;

static void dispatch_line(fetch_ctx_t *fc, const char *p, size_t len)
{
    /* skip blank lines and comment lines (! or #) */
    if (len == 0 || p[0] == '!' || p[0] == '#') return;
    /* strip trailing CR */
    while (len > 0 && (p[len-1] == '\r' || p[len-1] == ' ')) len--;
    if (len == 0) return;
    fc->total_lines++;
    if (!fc->line_cb(p, len, fc->user_ctx)) fc->aborted = true;
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

static void fetch_watchdog_timer_cb(void *arg)
{
    fetch_ctx_t *fc = (fetch_ctx_t *)arg;
    if (!fc || fc->aborted) return;

    int64_t now = esp_timer_get_time();

    /* 1. Inactivity check */
    if (fc->inactivity_timeout_us > 0 && (now - fc->last_data_us > fc->inactivity_timeout_us)) {
        ESP_LOGE(TAG, "Fetch watchdog: stream stalled (no data for %" PRId64 "s) — aborting",
                 (now - fc->last_data_us) / 1000000);
        fc->aborted = true;
        fc->timed_out = true;
        if (fc->client) {
            int sock = esp_http_client_get_socket(fc->client);
            if (sock >= 0) {
                shutdown(sock, SHUT_RDWR);
            }
        }
        return;
    }

    /* 2. Total duration check */
    if (fc->total_timeout_us > 0 && (now - fc->start_us > fc->total_timeout_us)) {
        ESP_LOGE(TAG, "Fetch watchdog: feed exceeded total timeout (%" PRId64 "s) — aborting",
                 (now - fc->start_us) / 1000000);
        fc->aborted = true;
        fc->timed_out = true;
        if (fc->client) {
            int sock = esp_http_client_get_socket(fc->client);
            if (sock >= 0) {
                shutdown(sock, SHUT_RDWR);
            }
        }
        return;
    }

    /* 3. External abort request check (e.g. user clicked Stop load) */
    if (fc->abort_cb && fc->abort_cb(fc->user_ctx)) {
        ESP_LOGW(TAG, "Fetch watchdog: stop requested by caller — aborting");
        fc->aborted = true;
        if (fc->client) {
            int sock = esp_http_client_get_socket(fc->client);
            if (sock >= 0) {
                shutdown(sock, SHUT_RDWR);
            }
        }
        return;
    }
}

static esp_err_t http_event_handler(esp_http_client_event_t *evt)
{
    fetch_ctx_t *fc = (fetch_ctx_t *)evt->user_data;
    if (!fc) return ESP_FAIL;
    if (fc->aborted) return ESP_FAIL;

    if (evt->event_id == HTTP_EVENT_ON_CONNECTED || evt->event_id == HTTP_EVENT_ON_HEADER) {
        fc->last_data_us = esp_timer_get_time();
        return ESP_OK;
    }

    if (evt->event_id != HTTP_EVENT_ON_DATA) return ESP_OK;

    int64_t now = esp_timer_get_time();
    fc->last_data_us = now;

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

bool http_fetch_lines_ex(const char *url,
                         http_fetch_line_cb line_cb,
                         void *user_ctx,
                         http_fetch_abort_cb abort_cb,
                         uint32_t inactivity_timeout_s,
                         uint32_t total_timeout_s)
{
    fetch_ctx_t fc = {
        .line_cb               = line_cb,
        .abort_cb              = abort_cb,
        .user_ctx              = user_ctx,
        .carry_len             = 0,
        .aborted               = false,
        .timed_out             = false,
        .total_bytes           = 0,
        .total_lines           = 0,
        .inactivity_timeout_us = (int64_t)inactivity_timeout_s * 1000000LL,
        .total_timeout_us      = (int64_t)total_timeout_s * 1000000LL,
        .client                = NULL,
    };
    fc.start_us = esp_timer_get_time();
    fc.last_data_us = fc.start_us;
    fc.last_log_us = fc.start_us;

    esp_http_client_config_t cfg = {
        .url                = url,
        .event_handler      = http_event_handler,
        .user_data          = &fc,
        .buffer_size        = CHUNK_SIZE,
        .timeout_ms         = (inactivity_timeout_s > 0 && inactivity_timeout_s < 30)
                               ? (int)(inactivity_timeout_s * 1000) : 30000,
        .keep_alive_enable  = false,
        .crt_bundle_attach  = esp_crt_bundle_attach,
    };

    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    if (!client) { ESP_LOGE(TAG, "init failed"); return false; }
    fc.client = client;

    /* Start active watchdog timer (ticks every 1s) */
    esp_timer_handle_t wd_timer = NULL;
    esp_timer_create_args_t timer_args = {
        .callback = fetch_watchdog_timer_cb,
        .arg      = &fc,
        .name     = "fetch_wd",
    };
    esp_err_t timer_err = esp_timer_create(&timer_args, &wd_timer);
    if (timer_err == ESP_OK) {
        esp_timer_start_periodic(wd_timer, 1000000);  /* 1 second */
    } else {
        ESP_LOGW(TAG, "Could not create watchdog timer (%d) — falling back to socket timeout", timer_err);
    }

    esp_err_t err = esp_http_client_perform(client);
    int status    = esp_http_client_get_status_code(client);

    if (wd_timer) {
        esp_timer_stop(wd_timer);
        esp_timer_delete(wd_timer);
    }

    esp_http_client_cleanup(client);

    if (fc.timed_out) {
        ESP_LOGE(TAG, "fetch timed out: %s", url);
        return false;
    }
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

bool http_fetch_lines(const char *url, http_fetch_line_cb cb, void *ctx)
{
    return http_fetch_lines_ex(url, cb, ctx, NULL, 30, 360);
}
