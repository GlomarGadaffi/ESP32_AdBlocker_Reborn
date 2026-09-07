#include "census.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include <string.h>
#include <stdio.h>

static const char *TAG = "census";

static CensusClient      *s_table = NULL;
static uint32_t           s_count = 0;
static SemaphoreHandle_t  s_mutex = NULL;

bool census_init(void)
{
    s_table = heap_caps_calloc(CENSUS_MAX, sizeof(CensusClient), MALLOC_CAP_SPIRAM);
    if (!s_table) {
        ESP_LOGE(TAG, "PSRAM alloc failed");
        return false;
    }
    s_mutex = xSemaphoreCreateMutex();
    return s_mutex != NULL;
}

void census_observe(const uint8_t mac[6], uint32_t ip, int kind,
                    const char *hostname, size_t hostname_len)
{
    if (!s_table || !s_mutex) return;
    uint32_t now_s = (uint32_t)(esp_timer_get_time() / 1000000ULL);

    /* Called from dns_task, which must never block — the only other holder
     * (census_snapshot, from the single-task httpd) is a sub-millisecond
     * memcpy, so contention is expected to be essentially never, but this is
     * a census, not a verdict: losing a sighting on a missed lock is fine,
     * blocking dns_task is not. */
    if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(1)) != pdTRUE) return;
    int idx = -1;
    for (uint32_t i = 0; i < s_count; i++) {
        if (memcmp(s_table[i].mac, mac, 6) == 0) { idx = (int)i; break; }
    }
    if (idx < 0) {
        if (s_count < CENSUS_MAX) {
            idx = (int)s_count++;
            memset(&s_table[idx], 0, sizeof(s_table[idx]));
        } else {
            /* Table full: evict the least-recently-seen entry rather than
             * refusing a new client — a stale entry for a device that left
             * the LAN hours ago is less useful than one for a device on it
             * right now. */
            uint32_t min_ls = s_table[0].last_seen_s;
            int min_i = 0;
            for (uint32_t i = 1; i < CENSUS_MAX; i++) {
                if (s_table[i].last_seen_s < min_ls) { min_ls = s_table[i].last_seen_s; min_i = (int)i; }
            }
            idx = min_i;
            memset(&s_table[idx], 0, sizeof(s_table[idx]));
        }
        memcpy(s_table[idx].mac, mac, 6);
        s_table[idx].first_seen_s = now_s;
    }

    CensusClient *c = &s_table[idx];
    c->last_seen_s = now_s;
    if (ip) c->ip = ip;
    /* Unlike census_stage's raw per-event copy, an absent hostname here must
     * NOT clear a previously learned one — only DHCP sightings ever carry a
     * hostname, and an ARP/QUERY sighting in between shouldn't erase it. */
    if (hostname && hostname_len > 0) {
        census_copy_hostname(c->hostname, hostname, hostname_len);
    }
    switch (kind) {
        case CENSUS_SEEN_ARP:   c->arp_count++;   break;
        case CENSUS_SEEN_DHCP:  c->dhcp_count++;  break;
        case CENSUS_SEEN_QUERY: c->query_count++; break;
    }
    xSemaphoreGive(s_mutex);
}

uint32_t census_snapshot(CensusClient *out, uint32_t cap)
{
    if (!s_table || !s_mutex) return 0;
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    uint32_t n = s_count < cap ? s_count : cap;
    memcpy(out, s_table, n * sizeof(CensusClient));
    xSemaphoreGive(s_mutex);
    return n;
}
