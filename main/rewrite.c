#include "rewrite.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"
#include <string.h>
#include <stdio.h>

static const char *TAG = "rewrite";
#define NVS_NS "dns_sink"

typedef struct {
    char     domain[64];
    uint32_t ipv4_hbo;
} RewriteEntry;

static RewriteEntry s_rules[REWRITE_MAX];
static uint32_t     s_count = 0;

/* Serialize an entry as "domain=A.B.C.D\0" for NVS string storage. */
static void entry_to_str(const RewriteEntry *e, char *buf, size_t cap)
{
    uint8_t b0 = (e->ipv4_hbo >> 24) & 0xFF;
    uint8_t b1 = (e->ipv4_hbo >> 16) & 0xFF;
    uint8_t b2 = (e->ipv4_hbo >> 8)  & 0xFF;
    uint8_t b3 =  e->ipv4_hbo        & 0xFF;
    snprintf(buf, cap, "%s=%u.%u.%u.%u", e->domain, b0, b1, b2, b3);
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

    /* Delete: remove matching entry */
    if (ipv4_hbo == 0) {
        for (uint32_t i = 0; i < s_count; i++) {
            if (strcmp(s_rules[i].domain, domain) == 0) {
                s_rules[i] = s_rules[--s_count];
                save_nvs();
                return true;
            }
        }
        return true;
    }

    /* Update existing */
    for (uint32_t i = 0; i < s_count; i++) {
        if (strcmp(s_rules[i].domain, domain) == 0) {
            s_rules[i].ipv4_hbo = ipv4_hbo;
            save_nvs();
            return true;
        }
    }

    /* Insert new */
    if (s_count >= REWRITE_MAX) return false;
    snprintf(s_rules[s_count].domain, 64, "%s", domain);
    s_rules[s_count].ipv4_hbo = ipv4_hbo;
    s_count++;
    save_nvs();
    return true;
}

uint32_t rewrite_lookup(const char *domain)
{
    if (!domain) return 0;
    size_t dlen = strlen(domain);
    for (uint32_t i = 0; i < s_count; i++) {
        const char *rule = s_rules[i].domain;
        size_t rlen = strlen(rule);
        /* Exact match */
        if (dlen == rlen && memcmp(domain, rule, dlen) == 0)
            return s_rules[i].ipv4_hbo;
        /* Subdomain match: domain ends with ".rule" */
        if (dlen > rlen + 1 &&
            domain[dlen - rlen - 1] == '.' &&
            memcmp(domain + dlen - rlen, rule, rlen) == 0)
            return s_rules[i].ipv4_hbo;
    }
    return 0;
}

void rewrite_list(char out_domains[][64], uint32_t out_ips[], uint32_t *count_inout)
{
    uint32_t cap = *count_inout;
    uint32_t n = s_count < cap ? s_count : cap;
    for (uint32_t i = 0; i < n; i++) {
        snprintf(out_domains[i], 64, "%s", s_rules[i].domain);
        out_ips[i] = s_rules[i].ipv4_hbo;
    }
    *count_inout = n;
}

uint32_t rewrite_count(void) { return s_count; }
