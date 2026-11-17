#include "pause.h"
#include "esp_attr.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "nvs.h"
#include "nvs_keys.h"
#include "timesync.h"
#include "blocklist.h"
#include <stdatomic.h>
#include <string.h>
#include <inttypes.h>

static const char *TAG = "pause";

/* One slot = (ip, expiry-in-seconds-since-boot). expires_s == 0 means empty;
 * a real expiry is always > 0 because minutes >= 1. Seconds, not the raw
 * esp_timer microseconds, so the pair fits two 32-bit atomics — the L2 hook
 * runs in IRAM and must not call into the emulated 64-bit atomic helpers. */
typedef struct {
    _Atomic uint32_t ip;
    _Atomic uint32_t expires_s;
} pause_slot_t;

static pause_slot_t      s_slots[PAUSE_MAX];
/* Hot-path gate: live slots, plus one while a schedule window is active. Zero
 * means "nothing can possibly be paused" and the reader stops after one load. */
static _Atomic uint32_t  s_armed = 0;
static uint32_t          s_slot_count = 0;       /* live slots only; mutex held */
static _Atomic uint32_t  s_sched_on = 0;         /* a schedule window is active now */
static pause_sched_t     s_sched;                /* mutex held */
static esp_timer_handle_t s_sched_timer = NULL;
static SemaphoreHandle_t s_mutex = NULL;   /* writers only */

static inline uint32_t now_s(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000000);
}

/* Writers hold s_mutex. Ordering is what lets readers stay lock-free:
 *   1. expires_s = 0      (slot reads as empty from here on)
 *   2. ip        = new
 *   3. expires_s = new    (release: publishes the ip written in step 2)
 * A reader that loads expires_s, then ip, then expires_s again and sees the
 * two expiries differ has straddled an update and drops the slot. */
static void slot_write(pause_slot_t *s, uint32_t ip, uint32_t expires)
{
    atomic_store_explicit(&s->expires_s, 0, memory_order_release);
    atomic_store_explicit(&s->ip, ip, memory_order_relaxed);
    atomic_store_explicit(&s->expires_s, expires, memory_order_release);
}

/* Recount armed slots and drop expired ones. Mutex held. */
static void sweep_locked(void)
{
    uint32_t now = now_s(), armed = 0;
    for (int i = 0; i < PAUSE_MAX; i++) {
        uint32_t e = atomic_load_explicit(&s_slots[i].expires_s, memory_order_relaxed);
        if (e == 0) continue;
        if (e <= now) { atomic_store_explicit(&s_slots[i].expires_s, 0, memory_order_release); continue; }
        armed++;
    }
    s_slot_count = armed;
    armed += atomic_load_explicit(&s_sched_on, memory_order_relaxed) ? 1u : 0u;
    atomic_store_explicit(&s_armed, armed, memory_order_release);
}

/* Recompute whether a schedule window is active and publish it. Mutex held.
 * An unsynced clock reads as "no window active": keep filtering. */
static void sched_eval_locked(void)
{
    uint32_t on = 0;
    uint32_t epoch = timesync_is_synced() ? timesync_epoch() : 0;
    int wd = 0, mn = 0;
    if (epoch != 0 && pause_sched_localtime(epoch, s_sched.utc_offset_min, &wd, &mn) == 0)
        on = pause_sched_active(&s_sched, wd, mn) ? 1u : 0u;
    uint32_t was = atomic_load_explicit(&s_sched_on, memory_order_relaxed);
    atomic_store_explicit(&s_sched_on, on, memory_order_release);
    sweep_locked();                              /* refolds s_sched_on into s_armed */
    if (on != was) ESP_LOGW(TAG, "scheduled pause %s", on ? "STARTED: blocking off" : "ended: blocking on");
}

static void sched_timer_cb(void *arg)
{
    (void)arg;
    if (!s_mutex) return;
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    sched_eval_locked();
    xSemaphoreGive(s_mutex);
}

/* Write the schedule blob. Mutex held. */
static bool sched_save_locked(const pause_sched_t *s)
{
    uint8_t blob[PAUSE_SCHED_BLOB_LEN];
    if (pause_sched_serialise(s, blob, sizeof(blob)) != 0) return false;
    nvs_handle_t h;
    if (nvs_open(NVS_NS_MAIN, NVS_READWRITE, &h) != ESP_OK) return false;
    esp_err_t e = nvs_set_blob(h, NVSK_PAUSE_SCHED, blob, sizeof(blob));
    if (e == ESP_OK) e = nvs_commit(h);
    nvs_close(h);
    if (e != ESP_OK) ESP_LOGW(TAG, "schedule NVS write failed: %s", esp_err_to_name(e));
    return e == ESP_OK;
}

static void sched_load(void)
{
    memset(&s_sched, 0, sizeof(s_sched));
    nvs_handle_t h;
    if (nvs_open(NVS_NS_MAIN, NVS_READONLY, &h) != ESP_OK) return;
    uint8_t blob[PAUSE_SCHED_BLOB_LEN];
    size_t len = sizeof(blob);
    esp_err_t e = nvs_get_blob(h, NVSK_PAUSE_SCHED, blob, &len);
    nvs_close(h);
    if (e == ESP_ERR_NVS_NOT_FOUND) return;
    pause_sched_t t;
    if (e != ESP_OK || pause_sched_deserialise(blob, len, &t) != 0) {
        ESP_LOGW(TAG, "stored pause schedule unreadable — ignored (blocking stays on)");
        return;
    }
    s_sched = t;
}

bool pause_init(void)
{
    if (!s_mutex) s_mutex = xSemaphoreCreateMutex();
    if (!s_mutex) return false;
    for (int i = 0; i < PAUSE_MAX; i++) slot_write(&s_slots[i], 0, 0);
    atomic_store(&s_sched_on, 0);
    atomic_store(&s_armed, 0);
    s_slot_count = 0;
    sched_load();
    if (!s_sched_timer) {
        const esp_timer_create_args_t args = { .callback = sched_timer_cb, .name = "pause_sched" };
        if (esp_timer_create(&args, &s_sched_timer) != ESP_OK) { s_sched_timer = NULL; return false; }
        if (esp_timer_start_periodic(s_sched_timer, 1000000) != ESP_OK) return false;
    }
    return true;
}

pause_reason_t pause_effective(void)
{
    if (!s_mutex) return PAUSE_REASON_NONE;
    if (blocklist_is_paused() || pause_count() > 0) return PAUSE_REASON_MANUAL;
    return atomic_load_explicit(&s_sched_on, memory_order_acquire) ? PAUSE_REASON_SCHEDULE : PAUSE_REASON_NONE;
}

bool pause_schedule_get(pause_sched_t *out)
{
    if (!s_mutex || !out) return false;
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    *out = s_sched;
    xSemaphoreGive(s_mutex);
    return true;
}

/* Apply a modified copy: persist first, publish only if the write held. */
static bool sched_commit(const pause_sched_t *next)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    bool ok = sched_save_locked(next);
    if (ok) { s_sched = *next; sched_eval_locked(); }
    xSemaphoreGive(s_mutex);
    return ok;
}

bool pause_schedule_set_window(int slot, const pause_sched_window_t *w)
{
    if (!s_mutex || !w || slot < 0 || slot >= PAUSE_SCHED_MAX_WINDOWS) return false;
    pause_sched_t next;
    if (!pause_schedule_get(&next)) return false;
    next.win[slot] = *w;
    return sched_commit(&next);
}

bool pause_schedule_clear_window(int slot)
{
    pause_sched_window_t empty = { false, 0, 0, 0 };
    return pause_schedule_set_window(slot, &empty);
}

bool pause_schedule_set_utc_offset(int minutes)
{
    if (!s_mutex || minutes < PAUSE_SCHED_UTC_MIN_MIN || minutes > PAUSE_SCHED_UTC_MAX_MIN) return false;
    pause_sched_t next;
    if (!pause_schedule_get(&next)) return false;
    next.utc_offset_min = (int16_t)minutes;
    return sched_commit(&next);
}

bool pause_set(uint32_t ip_hbo, uint32_t minutes)
{
    if (!s_mutex || minutes == 0 || minutes > PAUSE_MAX_MINUTES) return false;
    uint32_t expires = now_s() + minutes * 60u;
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    sweep_locked();
    int target = -1;
    for (int i = 0; i < PAUSE_MAX; i++) {           /* same IP -> replace */
        if (atomic_load_explicit(&s_slots[i].expires_s, memory_order_relaxed) != 0 &&
            atomic_load_explicit(&s_slots[i].ip, memory_order_relaxed) == ip_hbo) { target = i; break; }
    }
    if (target < 0) {
        for (int i = 0; i < PAUSE_MAX; i++)          /* else first empty slot */
            if (atomic_load_explicit(&s_slots[i].expires_s, memory_order_relaxed) == 0) { target = i; break; }
    }
    if (target >= 0) slot_write(&s_slots[target], ip_hbo, expires);
    sweep_locked();
    xSemaphoreGive(s_mutex);
    if (target < 0) { ESP_LOGW(TAG, "pause table full (%d entries)", PAUSE_MAX); return false; }
    if (ip_hbo == PAUSE_IP_ALL)
        ESP_LOGW(TAG, "blocking PAUSED for ALL clients, %" PRIu32 " min", minutes);
    else
        ESP_LOGW(TAG, "blocking paused for %u.%u.%u.%u, %" PRIu32 " min",
                 (unsigned)(ip_hbo >> 24), (unsigned)((ip_hbo >> 16) & 0xFF),
                 (unsigned)((ip_hbo >> 8) & 0xFF), (unsigned)(ip_hbo & 0xFF), minutes);
    return true;
}

bool pause_clear(uint32_t ip_hbo)
{
    if (!s_mutex) return false;
    bool found = false;
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    uint32_t now = now_s();
    for (int i = 0; i < PAUSE_MAX; i++) {
        uint32_t e = atomic_load_explicit(&s_slots[i].expires_s, memory_order_relaxed);
        if (e > now && atomic_load_explicit(&s_slots[i].ip, memory_order_relaxed) == ip_hbo) {
            atomic_store_explicit(&s_slots[i].expires_s, 0, memory_order_release);
            found = true;
        }
    }
    sweep_locked();
    xSemaphoreGive(s_mutex);
    if (found) ESP_LOGW(TAG, "blocking resumed for %s", ip_hbo == PAUSE_IP_ALL ? "ALL clients" : "one client");
    return found;
}

uint32_t pause_clear_all(void)
{
    if (!s_mutex) return 0;
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    sweep_locked();
    uint32_t n = s_slot_count;
    for (int i = 0; i < PAUSE_MAX; i++)
        atomic_store_explicit(&s_slots[i].expires_s, 0, memory_order_release);
    sweep_locked();                              /* leaves the schedule's share of s_armed */
    xSemaphoreGive(s_mutex);
    if (n) ESP_LOGW(TAG, "blocking resumed: %" PRIu32 " pause(s) cleared", n);
    return n;
}

uint32_t pause_list(pause_view_t *out, uint32_t max)
{
    if (!s_mutex) return 0;
    uint32_t n = 0;
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    sweep_locked();
    uint32_t now = now_s();
    for (int i = 0; i < PAUSE_MAX && n < max; i++) {
        uint32_t e = atomic_load_explicit(&s_slots[i].expires_s, memory_order_relaxed);
        if (e == 0 || e <= now) continue;
        out[n].ip          = atomic_load_explicit(&s_slots[i].ip, memory_order_relaxed);
        out[n].remaining_s = e - now;
        n++;
    }
    xSemaphoreGive(s_mutex);
    return n;
}

uint32_t pause_count(void)
{
    if (!s_mutex) return 0;
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    sweep_locked();
    uint32_t n = s_slot_count;
    xSemaphoreGive(s_mutex);
    return n;
}

/* IRAM_ATTR (#78): called from l2_input_cb, which must never fault to flash.
 * esp_timer_get_time() is itself IRAM-resident. */
bool IRAM_ATTR pause_active_for(uint32_t client_ip_hbo)
{
    if (atomic_load_explicit(&s_armed, memory_order_acquire) == 0) return false;
    uint32_t now = now_s();
    for (int i = 0; i < PAUSE_MAX; i++) {
        uint32_t e1 = atomic_load_explicit(&s_slots[i].expires_s, memory_order_acquire);
        if (e1 == 0 || e1 <= now) continue;
        uint32_t ip = atomic_load_explicit(&s_slots[i].ip, memory_order_relaxed);
        uint32_t e2 = atomic_load_explicit(&s_slots[i].expires_s, memory_order_acquire);
        if (e2 != e1) continue;                    /* torn update: fail closed for this query */
        if (ip == PAUSE_IP_ALL || ip == client_ip_hbo) return true;
    }
    /* No slot matched. A schedule window pauses everyone; this load is only
     * reached when s_armed was non-zero, so the idle path stays one load. */
    return atomic_load_explicit(&s_sched_on, memory_order_acquire) != 0;
}
