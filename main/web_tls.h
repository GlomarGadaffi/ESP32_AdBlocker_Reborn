#pragma once
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Self-signed TLS identity for the web UI (#89).
 *
 * On first call generates an ECDSA P-256 key + self-signed X.509 cert
 * (CN/SAN = the device's mDNS hostname, 10-year validity), stores both as PEM
 * blobs in NVS, and keeps them resident for httpd_ssl_start(). Subsequent
 * boots load the stored pair so the fingerprint stays stable — that stability
 * is what makes the fingerprint shown on the setup page / console meaningful
 * to pin against. */

/* Returns false if no identity could be loaded or generated. PEM lengths
 * INCLUDE the terminating NUL, as esp_https_server requires. Needs a task
 * with a real stack (≥ 8 KB): ECDSA + the X.509 writer + the parse for the
 * fingerprint do not fit on app_main's. The pointers stay valid until
 * web_tls_release_identity(). */
bool web_tls_get_identity(const char **crt_pem, size_t *crt_len,
                          const char **key_pem, size_t *key_len);

/* Free the PEM buffers once httpd_ssl_start() has taken its own copies. The
 * fingerprint stays available. */
void web_tls_release_identity(void);

/* SHA-256 fingerprint of the certificate DER as "AA:BB:...:FF" (95 chars +
 * NUL). Empty string if no identity yet. */
void web_tls_fingerprint(char *out, size_t cap);

/* Erase the stored identity so a fresh one is generated on next boot
 * (USB console `cert-reset`). */
void web_tls_reset(void);

#ifdef __cplusplus
}
#endif
