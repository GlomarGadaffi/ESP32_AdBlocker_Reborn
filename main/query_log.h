#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/* Query log — ring buffer of recent DNS queries + approximate top lists (#7, #8). */

#define QLOG_SIZE     512   /* ring buffer entries (PSRAM) */
#define QTOP_DOMAINS  32    /* slots in top-domain table */
#define QTOP_CLIENTS  16    /* slots in top-client table */

typedef struct {
    char     domain[64];
    uint32_t client_ip;   /* host byte order */
    uint32_t ts_s;        /* seconds since boot (esp_timer / 1e6) */
    uint16_t qtype;
    bool     blocked;
    bool     rewritten;
} QLogEntry;

typedef struct {
    char     key[64];     /* domain name or "A.B.C.D" for clients */
    uint32_t total;
    uint32_t blocked;
} QTopEntry;

bool query_log_init(void);

/* Record one query (called from dns_task on Core 1). */
void query_log_record(const char *domain, uint16_t qtype, uint32_t client_ip_hbo,
                      bool blocked, bool rewritten);

/* Copy ring buffer snapshot (newest first, up to cap entries).
 * Returns number of entries written. Thread-safe (no mutex; may see torn writes). */
uint32_t query_log_snapshot(QLogEntry *out, uint32_t cap);

/* Copy top-domain / top-client tables (sorted desc by total). */
uint32_t query_log_top_domains(QTopEntry *out, uint32_t cap);
uint32_t query_log_top_clients(QTopEntry *out, uint32_t cap);

/* Total unique domains seen (approx), total queries, total blocked */
void query_log_stats(uint32_t *total_out, uint32_t *blocked_out);

/* Per-minute history ring: up to 60 buckets of (total, blocked) counts (#11).
 * Bucket granularity: 60 seconds. */
#define QHIST_BUCKETS 60
void query_log_history(uint32_t total_out[QHIST_BUCKETS],
                       uint32_t blocked_out[QHIST_BUCKETS],
                       uint32_t *count_out);  /* actual buckets filled */

#ifdef __cplusplus
}
#endif
