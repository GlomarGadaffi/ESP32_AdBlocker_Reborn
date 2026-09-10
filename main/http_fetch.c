#include "http_fetch.h"
#include "esp_http_client.h"
#include "esp_crt_bundle.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "lwip/sockets.h"
#include <stdatomic.h>
#include <string.h>
#include <inttypes.h>

static const char *TAG = "http_fetch";

#define CHUNK_SIZE  4096
#define CARRY_SIZE  256

/* start_us/last_data_us are written by the task running the HTTP event handler
 * and read by the esp_timer task in the watchdog callback, so they are atomic:
 * a plain int64_t is two stores on a 32-bit core, and a read torn across the
 * low word's carry (once per ~71 min of uptime) yields a huge bogus idle time
 * and force-aborts a healthy download. The bool flags are single-byte and
 * cannot tear. */
typedef struct {
    http_fetch_line_cb   line_cb;
    http_fetch_abort_cb  abort_cb;
    void                *user_ctx;
    char                 carry[CARRY_SIZE];
    size_t               carry_len;
    volatile bool        aborted;
    volatile bool        timed_out;
    volatile bool        stopped;
    uint64_t             total_bytes;
    uint32_t             total_lines;
    _Atomic int64_t      start_us;
    _Atomic int64_t      last_data_us;
    int64_t              last_log_us;
    int64_t              inactivity_timeout_us;
    int64_t              total_timeout_us;
    esp_http_client_handle_t client;
} fetch_ctx_t;

/*
 * Watchdog teardown handshake.
 *
 * esp_timer's dispatcher releases the timer-list lock BEFORE invoking a
 * callback (esp-idf components/esp_timer/src/esp_timer.c, timer_process_alarm),
 * and esp_timer_stop()/esp_timer_delete() do nothing but take that same lock —
 * so neither waits for a callback that is already running. Without a handshake
 * the watchdog can still be inside fetch_watchdog_timer_cb(), dereferencing the
 * fetch context and calling esp_http_client_get_socket() on the client, after
 * http_fetch_lines_ex() has returned and both are gone.
 *
 * These two therefore have static lifetime and are the ONLY things a callback
 * may touch before it has proven a fetch is still live. The mutex is statically
 * allocated on purpose: #84 is a heap-starvation bug, and a fix that needs a
 * heap allocation to work is no fix at all.
 *
 * One fetch at a time — both callers are the single download task.
 */
static StaticSemaphore_t     s_wd_lock_storage;
static SemaphoreHandle_t     s_wd_lock;    /* created once, never deleted */
static fetch_ctx_t *_Atomic  s_wd_fc;      /* the live fetch, or NULL */

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
    int64_t start = atomic_load_explicit(&fc->start_us, memory_order_relaxed);
    float secs = (float)(now - start) / 1e6f;
    float kbps = secs > 0 ? ((float)fc->total_bytes / 1024.0f) / secs : 0;
    ESP_LOGI(TAG, "downloading: %" PRIu32 " KB, %" PRIu32 " lines, %.0f KB/s",
             (uint32_t)(fc->total_bytes / 1024), fc->total_lines, kbps);
    fc->last_log_us = now;
}

/* Shutting the socket down is what unblocks esp_http_client_perform(): a recv
 * stalled with nothing arriving will not return on its own. */
static void fetch_kill_socket(fetch_ctx_t *fc)
{
    if (!fc->client) return;
    int sock = esp_http_client_get_socket(fc->client);
    if (sock >= 0) shutdown(sock, SHUT_RDWR);
}

static void fetch_watchdog_timer_cb(void *arg)
{
    (void)arg;   /* the live fetch is found via s_wd_fc, never a captured pointer */

    /* Non-blocking: the lock is only ever held by a teardown, and a fetch that
     * is going away does not need this tick. */
    if (xSemaphoreTake(s_wd_lock, 0) != pdTRUE) return;

    fetch_ctx_t *fc = atomic_load(&s_wd_fc);
    if (fc && !fc->aborted) {
        int64_t now  = esp_timer_get_time();
        int64_t last = atomic_load_explicit(&fc->last_data_us, memory_order_relaxed);
        int64_t start = atomic_load_explicit(&fc->start_us, memory_order_relaxed);

        if (fc->inactivity_timeout_us > 0 && (now - last > fc->inactivity_timeout_us)) {
            ESP_LOGE(TAG, "Fetch watchdog: stream stalled (no data for %" PRId64 "s) — aborting",
                     (now - last) / 1000000);
            fc->aborted   = true;
            fc->timed_out = true;
            fetch_kill_socket(fc);
        } else if (fc->total_timeout_us > 0 && (now - start > fc->total_timeout_us)) {
            ESP_LOGE(TAG, "Fetch watchdog: feed exceeded total timeout (%" PRId64 "s) — aborting",
                     (now - start) / 1000000);
            fc->aborted   = true;
            fc->timed_out = true;
            fetch_kill_socket(fc);
        } else if (fc->abort_cb && fc->abort_cb(fc->user_ctx)) {
            /* A caller-requested stop is not a failure — stopped, not timed_out,
             * so the caller logs it as intentional rather than as a dead feed. */
            ESP_LOGW(TAG, "Fetch watchdog: stop requested by caller — aborting");
            fc->aborted = true;
            fc->stopped = true;
            fetch_kill_socket(fc);
        }
    }

    xSemaphoreGive(s_wd_lock);
}

static esp_err_t http_event_handler(esp_http_client_event_t *evt)
{
    fetch_ctx_t *fc = (fetch_ctx_t *)evt->user_data;
    if (!fc) return ESP_FAIL;
    if (fc->aborted) return ESP_FAIL;

    if (evt->event_id == HTTP_EVENT_ON_CONNECTED || evt->event_id == HTTP_EVENT_ON_HEADER) {
        atomic_store_explicit(&fc->last_data_us, esp_timer_get_time(), memory_order_relaxed);
        return ESP_OK;
    }

    if (evt->event_id != HTTP_EVENT_ON_DATA) return ESP_OK;

    atomic_store_explicit(&fc->last_data_us, esp_timer_get_time(), memory_order_relaxed);

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
    if (!s_wd_lock)
        s_wd_lock = xSemaphoreCreateMutexStatic(&s_wd_lock_storage);

    fetch_ctx_t fc = {
        .line_cb               = line_cb,
        .abort_cb              = abort_cb,
        .user_ctx              = user_ctx,
        .carry_len             = 0,
        .aborted               = false,
        .timed_out             = false,
        .stopped               = false,
        .total_bytes           = 0,
        .total_lines           = 0,
        .inactivity_timeout_us = (int64_t)inactivity_timeout_s * 1000000LL,
        .total_timeout_us      = (int64_t)total_timeout_s * 1000000LL,
        .client                = NULL,
    };
    int64_t now = esp_timer_get_time();
    atomic_store(&fc.start_us, now);
    atomic_store(&fc.last_data_us, now);
    fc.last_log_us = now;

    esp_http_client_config_t cfg = {
        .url                = url,
        .event_handler      = http_event_handler,
        .user_data          = &fc,
        .buffer_size        = CHUNK_SIZE,
        /* The watchdog owns stall detection — it is what tells a stall from a
         * caller-requested stop and sets timed_out. esp_http_client's own recv
         * timeout is only the backstop for a watchdog timer that could not be
         * created, so it sits deliberately ABOVE the inactivity deadline: the
         * watchdog ticks once a second, and an equal value would let the socket
         * win the race and report a generic "fetch failed" instead. */
        .timeout_ms         = inactivity_timeout_s > 0
                               ? (int)((inactivity_timeout_s + 5) * 1000) : 30000,
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
        .arg      = NULL,   /* see s_wd_fc: a captured pointer would outlive fc */
        .name     = "fetch_wd",
    };
    esp_err_t timer_err = esp_timer_create(&timer_args, &wd_timer);
    if (timer_err == ESP_OK) {
        /* Publish last. A tick can fire the instant the timer starts, and a
         * stale tick left over from a previous fetch picks up whatever s_wd_fc
         * points at — so everything the callback reads, fc.client included,
         * must already be set before fc becomes visible to it. */
        atomic_store(&s_wd_fc, &fc);
        esp_timer_start_periodic(wd_timer, 1000000);  /* 1 second */
    } else {
        ESP_LOGW(TAG, "Could not create watchdog timer (%d) — falling back to socket timeout", timer_err);
    }

    esp_err_t err = esp_http_client_perform(client);
    int status    = esp_http_client_get_status_code(client);

    /* Retire the watchdog before the client and this stack frame go away.
     * esp_timer_stop() guarantees nothing further is dispatched; taking the
     * lock then waits out the at-most-one callback that was already in flight
     * when it did, so by the time we return no callback can be holding either. */
    if (wd_timer) esp_timer_stop(wd_timer);
    xSemaphoreTake(s_wd_lock, portMAX_DELAY);
    atomic_store(&s_wd_fc, NULL);
    xSemaphoreGive(s_wd_lock);
    if (wd_timer) esp_timer_delete(wd_timer);

    esp_http_client_cleanup(client);

    if (fc.stopped) {
        ESP_LOGW(TAG, "fetch stopped by caller: %s", url);
        return false;
    }
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
