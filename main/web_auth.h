#pragma once
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Web UI authentication (#89).
 *
 * Replaces the HTTP Basic scheme (credentials on every request, stored in
 * NVS as plaintext) with:
 *   - a salted PBKDF2-HMAC-SHA256 password hash in NVS (never the password),
 *   - short-lived random session tokens carried in an HttpOnly/Secure/
 *     SameSite=Strict cookie,
 *   - a global failed-login lockout so the password can't be brute-forced
 *     over the LAN.
 *
 * All functions are called from the httpd task only (the single-task httpd
 * design, #61) — the session table needs no locking — with two exceptions
 * for the USB console task: web_auth_reset() (erases NVS and sets a flag
 * the httpd task consumes via web_auth_poll_reset()) and
 * web_auth_get_user() (a read of a short string; a torn read is harmless).
 * web_auth_init() does a PBKDF2 when migrating a legacy password, so it
 * needs a task with a real stack — not app_main's.
 *
 * Threat model: the device holds Wi-Fi credentials, the admin password, and
 * per-client DNS query history. Anyone who can reach the UI must prove they
 * know the admin password, and nothing that proves it may cross the wire in
 * the clear (hence web_tls.h). */

#define WEB_AUTH_USER_MAX   31
#define WEB_AUTH_PASS_MIN   10
#define WEB_AUTH_PASS_MAX   63
#define WEB_AUTH_TOKEN_HEX  64      /* 32 random bytes as hex */

void web_auth_init(void);

/* True until an admin account has been created — the setup wizard gates
 * every other route while this holds. */
bool web_auth_setup_needed(void);

/* Create or replace the admin account. Returns false on policy violation
 * (empty user, password shorter than WEB_AUTH_PASS_MIN, either too long). */
bool web_auth_set_credentials(const char *user, const char *pass);

/* Erase the account (USB console `admin-reset`). Every session is dropped and
 * the setup wizard reappears. Physical access only. */
void web_auth_reset(void);
/* httpd task, once per request: apply a console-requested reset. */
void web_auth_poll_reset(void);

void web_auth_get_user(char *out, size_t cap);

/* Verify a login attempt. Constant-time on the hash; enforces the lockout.
 * *retry_after_s is set when locked out. */
bool web_auth_check_password(const char *user, const char *pass, int *retry_after_s);

/* Sessions. token_out receives WEB_AUTH_TOKEN_HEX hex chars + NUL. */
bool web_auth_session_create(char *token_out, size_t cap);
bool web_auth_session_valid(const char *token);
void web_auth_session_touch(const char *token);
void web_auth_session_destroy(const char *token);
void web_auth_session_destroy_all(void);

/* Per-session CSRF token (hex, 32 chars + NUL) — bound to the session so a
 * token leaked from one session is useless in another. */
bool web_auth_session_csrf(const char *token, char *out, size_t cap);

#ifdef __cplusplus
}
#endif
