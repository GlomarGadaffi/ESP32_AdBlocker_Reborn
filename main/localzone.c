#include "localzone.h"
#include "nvs.h"
#include "esp_log.h"
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdatomic.h>

static const char *TAG = "localzone";
#define NVS_NS  "dns_sink"
#define NVS_KEY "local_zones"
#define MAX_ZONES 16

static const char DEFAULT_LIST[] = "lan,local,home,home.arpa,internal,localdomain,intranet";

/* Two parsed tables, ping-pong like the blocklist: the httpd task builds the
 * inactive one and flips s_live; dns_task only ever reads through s_live. */
typedef struct {
    char  suffix[MAX_ZONES][40];
    int   n;
    char  text[LOCALZONE_LIST_CAP];
} zone_table_t;

static zone_table_t s_tab[2];
static _Atomic(zone_table_t *) s_live = NULL;

static bool parse_into(zone_table_t *t, const char *list)
{
    t->n = 0;
    int tp = 0;
    const char *p = list;
    while (*p) {
        while (*p == ',' || *p == ' ' || *p == '.') p++;
        if (!*p) break;
        char z[40]; int zl = 0;
        while (*p && *p != ',' && *p != ' ') {
            if (zl < (int)sizeof(z) - 1) z[zl++] = (char)tolower((unsigned char)*p);
            p++;
        }
        z[zl] = '\0';
        while (zl > 0 && z[zl - 1] == '.') z[--zl] = '\0';
        if (zl == 0) continue;
        if (t->n >= MAX_ZONES) return false;
        memcpy(t->suffix[t->n++], z, (size_t)zl + 1);
        int w = snprintf(t->text + tp, sizeof(t->text) - (size_t)tp, "%s%s", tp ? "," : "", z);
        if (w < 0 || tp + w >= (int)sizeof(t->text)) return false;
        tp += w;
    }
    if (tp == 0) t->text[0] = '\0';
    return true;
}

static void publish(const char *list)
{
    zone_table_t *cur = atomic_load(&s_live);
    zone_table_t *next = (cur == &s_tab[0]) ? &s_tab[1] : &s_tab[0];
    if (!parse_into(next, list)) parse_into(next, DEFAULT_LIST);
    atomic_store_explicit(&s_live, next, memory_order_release);
}

bool localzone_init_nvs(void)
{
    char buf[LOCALZONE_LIST_CAP];
    size_t len = sizeof(buf);
    nvs_handle_t h;
    bool have = false;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) == ESP_OK) {
        have = nvs_get_str(h, NVS_KEY, buf, &len) == ESP_OK;
        nvs_close(h);
    }
    publish(have ? buf : DEFAULT_LIST);
    ESP_LOGI(TAG, "local zones: %s (+ single-label names)", atomic_load(&s_live)->text);
    return true;
}

bool localzone_match(const char *name, size_t len)
{
    if (!name || len == 0) return false;
    if (memchr(name, '.', len) == NULL) return true;     /* "printer", "glolab" */
    zone_table_t *t = atomic_load_explicit(&s_live, memory_order_acquire);
    if (!t) return false;
    for (int i = 0; i < t->n; i++) {
        size_t sl = strlen(t->suffix[i]);
        if (len > sl && name[len - sl - 1] == '.' &&
            memcmp(name + len - sl, t->suffix[i], sl) == 0) return true;
        if (len == sl && memcmp(name, t->suffix[i], sl) == 0) return true;
    }
    return false;
}

bool localzone_set(const char *list)
{
    if (!list || strlen(list) >= LOCALZONE_LIST_CAP) return false;
    zone_table_t probe;
    if (!parse_into(&probe, list)) return false;
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) return false;
    esp_err_t e = nvs_set_str(h, NVS_KEY, probe.text);
    if (e == ESP_OK) e = nvs_commit(h);
    nvs_close(h);
    if (e != ESP_OK) return false;
    publish(probe.text);
    ESP_LOGI(TAG, "local zones set: %s", probe.text);
    return true;
}

void localzone_get(char *out, size_t cap)
{
    zone_table_t *t = atomic_load(&s_live);
    snprintf(out, cap, "%s", t ? t->text : DEFAULT_LIST);
}

const char *localzone_default(void) { return DEFAULT_LIST; }
