#include "acl.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"
#include <string.h>
#include <stdio.h>

static const char *TAG = "acl";
#define NVS_NS "dns_sink"

static uint32_t s_ips[ACL_MAX];
static uint32_t s_count = 0;

static uint32_t parse_ip(const char *s)
{
    unsigned b0=0,b1=0,b2=0,b3=0;
    if (sscanf(s, "%u.%u.%u.%u", &b0, &b1, &b2, &b3) != 4) return 0;
    return ((uint32_t)b0<<24)|((uint32_t)b1<<16)|((uint32_t)b2<<8)|(uint32_t)b3;
}

static void save_nvs(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) return;
    for (int i = 0; i < ACL_MAX; i++) {
        char key[12]; snprintf(key, sizeof(key), "acl_%d", i);
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
    s_count = 0;
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) return true;
    for (int i = 0; i < ACL_MAX; i++) {
        char key[12]; snprintf(key, sizeof(key), "acl_%d", i);
        char val[24]; size_t vlen = sizeof(val);
        if (nvs_get_str(h, key, val, &vlen) != ESP_OK) continue;
        uint32_t ip = parse_ip(val);
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
    uint32_t ip = parse_ip(ip_str);
    if (ip == 0) return false;
    for (uint32_t i = 0; i < s_count; i++)
        if (s_ips[i] == ip) return true;
    s_ips[s_count++] = ip;
    save_nvs();
    return true;
}

bool acl_remove(const char *ip_str)
{
    if (!ip_str) return false;
    uint32_t ip = parse_ip(ip_str);
    for (uint32_t i = 0; i < s_count; i++) {
        if (s_ips[i] == ip) {
            s_ips[i] = s_ips[--s_count];
            save_nvs();
            return true;
        }
    }
    return false;
}

bool acl_clear(void)
{
    s_count = 0;
    save_nvs();
    return true;
}

uint32_t acl_count(void) { return s_count; }

void acl_list(char out[][20], uint32_t *count_inout)
{
    uint32_t n = s_count < *count_inout ? s_count : *count_inout;
    for (uint32_t i = 0; i < n; i++)
        snprintf(out[i], 20, "%u.%u.%u.%u",
            (unsigned)((s_ips[i]>>24)&0xFF),(unsigned)((s_ips[i]>>16)&0xFF),
            (unsigned)((s_ips[i]>>8)&0xFF),(unsigned)(s_ips[i]&0xFF));
    *count_inout = n;
}

bool acl_permits(uint32_t client_ip_hbo)
{
    if (s_count == 0) return true;
    for (uint32_t i = 0; i < s_count; i++)
        if (s_ips[i] == client_ip_hbo) return true;
    return false;
}
