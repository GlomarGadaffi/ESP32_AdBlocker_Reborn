#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/* DNS-over-TLS upstream (#5, RFC 7858).
 * Optional replacement for the default plain-UDP upstream.
 * When enabled, each query uses a new esp-tls connection (session-resumption
 * caches the handshake so latency converges toward ~30ms after the first query). */

bool dot_is_enabled(void);
bool dot_init_nvs(void);   /* call after nvs_flash_init, before dns start */
void dot_set(bool enabled, const char *server_ip, const char *sni);
void dot_get(bool *enabled_out, char *server_ip_out, char *sni_out);

/* Resolve one DNS query via DoT.
 * query: raw DNS wire bytes (standard UDP DNS, no length prefix)
 * qlen:  length of query (bytes)
 * resp:  output buffer for raw DNS response
 * cap:   size of resp buffer
 * Returns response length, or -1 on failure. */
int dot_resolve(const uint8_t *query, int qlen, uint8_t *resp, int cap);

#ifdef __cplusplus
}
#endif
