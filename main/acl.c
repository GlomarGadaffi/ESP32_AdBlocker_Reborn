#include "acl.h"
#include "nvs_keys.h"     /* every NVS key this project owns, in one place (#111) */
#include "esp_attr.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include <string.h>
#include <stdio.h>

static const char *TAG = "acl";
#define NVS_NS NVS_NS_MAIN

/* s_ips/s_count are mutated from the httpd task and read from the dns_task hot
 * path. The mutex serializes the in-memory mutation against the reader (H3).
 * NVS writes are done OUTSIDE the lock so the reader never blocks on flash. */
static uint32_t s_ips[ACL_MAX];
static uint32_t s_count = 0;
static SemaphoreHandle_t s_mutex = NULL;

uint32_t acl_parse_ip4(const char *s)
{
    unsigned b0=256,b1=256,b2=256,b3=256; char tail=0;
    if (!s || sscanf(s, "%u.%u.%u.%u%c", &b0, &b1, &b2, &b3, &tail) != 4) return 0;
    if (b0>255 || b1>255 || b2>255 || b3>255) return 0;
    return ((uint32_t)b0<<24)|((uint32_t)b1<<16)|((uint32_t)b2<<8)|(uint32_t)b3;
}

static void save_nvs(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) return;
    for (int i = 0; i < ACL_MAX; i++) {
        char key[12]; snprintf(key, sizeof(key), NVSK_ACL_FMT, i);
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

bool acl_init(void)
{
    if (!s_mutex) s_mutex = xSemaphoreCreateMutex();
    if (!s_mutex) return false;
    s_count = 0;
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) return true;
    for (int i = 0; i < ACL_MAX; i++) {
        char key[12]; snprintf(key, sizeof(key), NVSK_ACL_FMT, i);
        char val[24]; size_t vlen = sizeof(val);
        if (nvs_get_str(h, key, val, &vlen) != ESP_OK) continue;
        uint32_t ip = acl_parse_ip4(val);
        if (ip) s_ips[s_count++] = ip;
    }
    nvs_close(h);
    if (s_count > 0)
        ESP_LOGI(TAG, "ACL active: %lu allowed client(s)", (unsigned long)s_count);
    return true;
}

bool acl_add(const char *ip_str)
{
    if (!ip_str || s_count >= ACL_MAX) return false;
    uint32_t ip = acl_parse_ip4(ip_str);
    if (ip == 0) return false;
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    bool changed = false;
    bool exists = false;
    for (uint32_t i = 0; i < s_count; i++)
        if (s_ips[i] == ip) { exists = true; break; }
    if (!exists && s_count < ACL_MAX) { s_ips[s_count++] = ip; changed = true; }
    xSemaphoreGive(s_mutex);
    if (changed) save_nvs();          /* NVS write outside the lock */
    return exists || changed;
}

bool acl_remove(const char *ip_str)
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

bool acl_clear(void)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    s_count = 0;
    xSemaphoreGive(s_mutex);
    save_nvs();
    return true;
}

uint32_t acl_count(void) { return s_count; }

void acl_list(char out[][20], uint32_t *count_inout)
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
bool IRAM_ATTR acl_permits_nb(uint32_t client_ip_hbo)
{
    if (s_count == 0) return true;             /* no ACL configured — allow all */
    if (!s_mutex) return false;
    if (xSemaphoreTake(s_mutex, 0) != pdTRUE) return false;   /* busy → defer */
    bool permit = false;
    for (uint32_t i = 0; i < s_count; i++)
        if (s_ips[i] == client_ip_hbo) { permit = true; break; }
    xSemaphoreGive(s_mutex);
    return permit;
}

bool acl_permits(uint32_t client_ip_hbo)
{
    /* Fast lock-free path: an empty allowlist means allow-all, which is the
     * common case (no ACL configured), so the hot path stays lock-free. */
    if (s_count == 0) return true;
    /* ACL configured: take a bounded lock. On contention (a config edit is
     * mid-flight) allow the query through rather than stall DNS or wrongly deny
     * every client for the brief mutation window. */
    if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(2)) != pdTRUE) return true;
    bool permit = (s_count == 0);
    for (uint32_t i = 0; i < s_count; i++)
        if (s_ips[i] == client_ip_hbo) { permit = true; break; }
    xSemaphoreGive(s_mutex);
    return permit;
}
