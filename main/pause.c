#include "pause.h"
#include "esp_attr.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
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
static _Atomic uint32_t  s_armed = 0;      /* slots with a non-zero expiry: hot-path gate */
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
    atomic_store_explicit(&s_armed, armed, memory_order_release);
}

bool pause_init(void)
{
    if (!s_mutex) s_mutex = xSemaphoreCreateMutex();
    if (!s_mutex) return false;
    for (int i = 0; i < PAUSE_MAX; i++) slot_write(&s_slots[i], 0, 0);
    atomic_store(&s_armed, 0);
    return true;
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
    uint32_t n = atomic_load(&s_armed);
    for (int i = 0; i < PAUSE_MAX; i++)
        atomic_store_explicit(&s_slots[i].expires_s, 0, memory_order_release);
    atomic_store_explicit(&s_armed, 0, memory_order_release);
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
    uint32_t n = atomic_load(&s_armed);
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
    return false;
}
