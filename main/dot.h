#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/* DNS-over-TLS upstream (#5, RFC 7858) — worker-task edition (closes C2).
 *
 * A dedicated worker owns ONE persistent TLS session to the upstream. The
 * dns_task never blocks on TLS: it enqueues the raw query (dot_enqueue) and
 * later drains raw replies (dot_reply_get) through the same validation and
 * delivery code as plain-UDP upstream replies. On TLS failure the worker
 * echoes the original query back flagged as failed, and the dns_task re-sends
 * it over plain UDP — same fallback contract as the old synchronous path,
 * with the 3s upstream-table eviction as the outer safety net. */

bool dot_is_enabled(void);
bool dot_init_nvs(void);   /* call after nvs_flash_init, before dns start */
void dot_set(bool enabled, const char *server_ip, const char *sni);
void dot_get(bool *enabled_out, char *server_ip_out, char *sni_out);

/* Hand one raw DNS query (wire format, no length prefix, txid already the
 * upstream-table txid) to the worker. Returns false if the worker isn't
 * running or its queue is full — caller must fall back to plain UDP. */
bool dot_enqueue(const uint8_t *query, int qlen);

/* Drain one worker result without blocking. Returns the byte count copied
 * into out, or 0 if nothing is pending. *failed=false: a raw DoT reply,
 * process like a UDP upstream reply. *failed=true: out holds the ORIGINAL
 * query (txid intact) — re-send it upstream over plain UDP. */
int dot_reply_get(uint8_t *out, int cap, bool *failed);

#ifdef __cplusplus
}
#endif
