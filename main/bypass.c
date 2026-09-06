#include "bypass.h"
#include "acl.h"          /* acl_parse_ip4 — one parser shared across ACL/bypass/USB console */
#include "esp_attr.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include <string.h>
#include <stdio.h>

static const char *TAG = "bypass";
#define NVS_NS "dns_sink"

/* s_ips/s_count are mutated from the httpd task and read from the dns_task
 * hot path (and, via the _nb variant, the L2 RX task). The mutex serializes
 * the in-memory mutation against both readers, same shape as acl.c. NVS
 * writes happen OUTSIDE the lock so neither reader ever blocks on flash. */
static uint32_t s_ips[BYPASS_MAX];
static uint32_t s_count = 0;
static SemaphoreHandle_t s_mutex = NULL;

static void save_nvs(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) return;
    for (int i = 0; i < BYPASS_MAX; i++) {
        char key[12]; snprintf(key, sizeof(key), "byp_%d", i);
        if (i < (int)s_count) {
            char val[20]; snprintf(val, sizeof(val), "%u.%u.%u.%u",
                (unsigned)((s_ips[i]>>24)&0xFF),(unsigned)((s_ips[i]>>16)&0xFF),
                (unsigned)((s_ips[i]>>8)&0xFF),(unsigned)(s_ips[i]&0xFF));
            nvs_set_str(h, key, val);
        } else {
            nvs_erase_key(h, key);
        }
    }
    nvs_commit(h);
    nvs_close(h);
}

bool bypass_init(void)
{
    if (!s_mutex) s_mutex = xSemaphoreCreateMutex();
    if (!s_mutex) return false;
    s_count = 0;
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) return true;
    for (int i = 0; i < BYPASS_MAX; i++) {
        char key[12]; snprintf(key, sizeof(key), "byp_%d", i);
        char val[24]; size_t vlen = sizeof(val);
        if (nvs_get_str(h, key, val, &vlen) != ESP_OK) continue;
        uint32_t ip = acl_parse_ip4(val);
        if (ip) s_ips[s_count++] = ip;
    }
    nvs_close(h);
    if (s_count > 0)
        ESP_LOGI(TAG, "Bypass list active: %lu client(s)", (unsigned long)s_count);
    return true;
}

bool bypass_add(const char *ip_str)
{
    if (!ip_str || s_count >= BYPASS_MAX) return false;
    uint32_t ip = acl_parse_ip4(ip_str);
    if (ip == 0) return false;
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    bool changed = false;
    bool exists = false;
    for (uint32_t i = 0; i < s_count; i++)
        if (s_ips[i] == ip) { exists = true; break; }
    if (!exists && s_count < BYPASS_MAX) { s_ips[s_count++] = ip; changed = true; }
    xSemaphoreGive(s_mutex);
    if (changed) save_nvs();          /* NVS write outside the lock */
    return exists || changed;
}

bool bypass_remove(const char *ip_str)
{
    if (!ip_str) return false;
    uint32_t ip = acl_parse_ip4(ip_str);
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    bool found = false;
    for (uint32_t i = 0; i < s_count; i++) {
        if (s_ips[i] == ip) {
            /* shift down so a concurrent reader never sees a duplicate or a
             * stale slot above the new count (swap-remove could). */
            for (uint32_t j = i; j + 1 < s_count; j++) s_ips[j] = s_ips[j + 1];
            s_count--;
            found = true;
            break;
        }
    }
    xSemaphoreGive(s_mutex);
    if (found) save_nvs();
    return found;
}

bool bypass_clear(void)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    s_count = 0;
    xSemaphoreGive(s_mutex);
    save_nvs();
    return true;
}

uint32_t bypass_count(void) { return s_count; }

void bypass_list(char out[][20], uint32_t *count_inout)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    uint32_t n = s_count < *count_inout ? s_count : *count_inout;
    for (uint32_t i = 0; i < n; i++)
        snprintf(out[i], 20, "%u.%u.%u.%u",
            (unsigned)((s_ips[i]>>24)&0xFF),(unsigned)((s_ips[i]>>16)&0xFF),
            (unsigned)((s_ips[i]>>8)&0xFF),(unsigned)(s_ips[i]&0xFF));
    *count_inout = n;
    xSemaphoreGive(s_mutex);
}

/* IRAM_ATTR (#78): called from l2_input_cb, which must never fault to flash. */
bool IRAM_ATTR bypass_active_for_nb(uint32_t client_ip_hbo)
{
    if (s_count == 0) return false;            /* no bypass list configured */
    if (!s_mutex) return false;
    if (xSemaphoreTake(s_mutex, 0) != pdTRUE) return false;   /* busy → not proven */
    bool bypassed = false;
    for (uint32_t i = 0; i < s_count; i++)
        if (s_ips[i] == client_ip_hbo) { bypassed = true; break; }
    xSemaphoreGive(s_mutex);
    return bypassed;
}

bool bypass_active_for(uint32_t client_ip_hbo)
{
    /* Fast lock-free path: an empty list is the common case. */
    if (s_count == 0) return false;
    /* Bounded lock. On contention (a config edit is mid-flight) treat as not
     * bypassed for this one query rather than stall the DNS hot path — the
     * next query, a moment later, sees the settled list. */
    if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(2)) != pdTRUE) return false;
    bool bypassed = false;
    for (uint32_t i = 0; i < s_count; i++)
        if (s_ips[i] == client_ip_hbo) { bypassed = true; break; }
    xSemaphoreGive(s_mutex);
    return bypassed;
}
