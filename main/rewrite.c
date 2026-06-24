#include "rewrite.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include <string.h>
#include <stdio.h>

static const char *TAG = "rewrite";
#define NVS_NS "dns_sink"

typedef struct {
    char     domain[64];
    uint32_t ipv4_hbo;
} RewriteEntry;

/* s_rules/s_count are mutated from the httpd task and read from the dns_task
 * (rewrite_lookup, on A queries). The mutex serializes the in-memory mutation
 * against the reader (H3); NVS writes happen outside the lock. */
static RewriteEntry s_rules[REWRITE_MAX];
static uint32_t     s_count = 0;
static SemaphoreHandle_t s_mutex = NULL;

/* Serialize an entry as "domain=A.B.C.D\0" for NVS string storage. */
static void entry_to_str(const RewriteEntry *e, char *buf, size_t cap)
{
    uint8_t b0 = (e->ipv4_hbo >> 24) & 0xFF;
    uint8_t b1 = (e->ipv4_hbo >> 16) & 0xFF;
    uint8_t b2 = (e->ipv4_hbo >> 8)  & 0xFF;
    uint8_t b3 =  e->ipv4_hbo        & 0xFF;
    /* %.63s bounds the domain so "domain=255.255.255.255\0" provably fits in the
     * 80-byte NVS value buffer (63 + 1 + 15 + 1 = 80). */
    snprintf(buf, cap, "%.63s=%u.%u.%u.%u", e->domain, b0, b1, b2, b3);
}

static bool str_to_entry(const char *s, RewriteEntry *e)
{
    const char *eq = strchr(s, '=');
    if (!eq || eq - s >= 64) return false;
    size_t dlen = (size_t)(eq - s);
    memcpy(e->domain, s, dlen);
    e->domain[dlen] = '\0';
    unsigned b0, b1, b2, b3;
    if (sscanf(eq + 1, "%u.%u.%u.%u", &b0, &b1, &b2, &b3) != 4) return false;
    e->ipv4_hbo = ((uint32_t)b0 << 24) | ((uint32_t)b1 << 16) |
                  ((uint32_t)b2 << 8)  |  (uint32_t)b3;
    return true;
}

static void save_nvs(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) return;
    for (int i = 0; i < REWRITE_MAX; i++) {
        char key[12]; snprintf(key, sizeof(key), "rw_%d", i);
        if (i < (int)s_count) {
            char val[80]; entry_to_str(&s_rules[i], val, sizeof(val));
            nvs_set_str(h, key, val);
        } else {
            nvs_erase_key(h, key);
        }
    }
    nvs_commit(h);
    nvs_close(h);
}

bool rewrite_init(void)
{
    if (!s_mutex) s_mutex = xSemaphoreCreateMutex();
    if (!s_mutex) return false;
    s_count = 0;
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) return true;
    for (int i = 0; i < REWRITE_MAX; i++) {
        char key[12]; snprintf(key, sizeof(key), "rw_%d", i);
        char val[80]; size_t vlen = sizeof(val);
        if (nvs_get_str(h, key, val, &vlen) != ESP_OK) continue;
        RewriteEntry e;
        if (str_to_entry(val, &e)) {
            s_rules[s_count++] = e;
        }
    }
    nvs_close(h);
    ESP_LOGI(TAG, "Loaded %lu DNS rewrite rules", (unsigned long)s_count);
    return true;
}

bool rewrite_set(const char *domain, uint32_t ipv4_hbo)
{
    if (!domain || strlen(domain) >= 64) return false;

    xSemaphoreTake(s_mutex, portMAX_DELAY);
    bool dirty = false;
    bool result = true;

    if (ipv4_hbo == 0) {
        /* Delete: remove matching entry, shift down (not swap) so a concurrent
         * reader never sees a duplicate or a stale slot above the new count. */
        for (uint32_t i = 0; i < s_count; i++) {
            if (strcmp(s_rules[i].domain, domain) == 0) {
                for (uint32_t j = i; j + 1 < s_count; j++) s_rules[j] = s_rules[j + 1];
                s_count--;
                dirty = true;
                break;
            }
        }
    } else {
        bool updated = false;
        for (uint32_t i = 0; i < s_count; i++) {
            if (strcmp(s_rules[i].domain, domain) == 0) {
                s_rules[i].ipv4_hbo = ipv4_hbo;
                updated = true; dirty = true;
                break;
            }
        }
        if (!updated) {
            if (s_count >= REWRITE_MAX) {
                result = false;
            } else {
                snprintf(s_rules[s_count].domain, 64, "%s", domain);
                s_rules[s_count].ipv4_hbo = ipv4_hbo;
                s_count++;
                dirty = true;
            }
        }
    }
    xSemaphoreGive(s_mutex);
    if (dirty) save_nvs();             /* NVS write outside the lock */
    return result;
}

uint32_t rewrite_lookup(const char *domain)
{
    if (!domain) return 0;
    /* Fast lock-free path: no rules configured (the common case). */
    if (s_count == 0) return 0;
    if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(2)) != pdTRUE) return 0;
    uint32_t result = 0;
    size_t dlen = strlen(domain);
    for (uint32_t i = 0; i < s_count; i++) {
        const char *rule = s_rules[i].domain;
        size_t rlen = strlen(rule);
        /* Exact match */
        if (dlen == rlen && memcmp(domain, rule, dlen) == 0) {
            result = s_rules[i].ipv4_hbo; break;
        }
        /* Subdomain match: domain ends with ".rule" */
        if (dlen > rlen + 1 &&
            domain[dlen - rlen - 1] == '.' &&
            memcmp(domain + dlen - rlen, rule, rlen) == 0) {
            result = s_rules[i].ipv4_hbo; break;
        }
    }
    xSemaphoreGive(s_mutex);
    return result;
}

void rewrite_list(char out_domains[][64], uint32_t out_ips[], uint32_t *count_inout)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    uint32_t cap = *count_inout;
    uint32_t n = s_count < cap ? s_count : cap;
    for (uint32_t i = 0; i < n; i++) {
        snprintf(out_domains[i], 64, "%.63s", s_rules[i].domain);
        out_ips[i] = s_rules[i].ipv4_hbo;
    }
    *count_inout = n;
    xSemaphoreGive(s_mutex);
}

uint32_t rewrite_count(void) { return s_count; }
