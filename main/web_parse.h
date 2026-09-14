#pragma once
/*
 * Request-parsing helpers for the web UI with zero ESP-IDF dependencies.
 *
 * These run on attacker-controlled bytes BEFORE any login check (the form
 * body of /setup and /login, the Cookie/Origin/Referer/Host headers of every
 * request), so they are compiled on the host and fuzzed (tests/fuzz/
 * fuzz_web_parse.c) — same treatment as dns_wire.c. Pure string functions:
 * no logging, no allocation, no globals. Keep it that way.
 *
 * Behaviour is byte-for-byte what web_ui.cpp had before the move.
 */
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Escape HTML special chars: <>&"' -> entities. Safe for both text and attrs.
 * dst is always NUL-terminated (cap >= 1). */
void web_html_escape(char *dst, size_t cap, const char *src);

/* URL-decode a form-encoded value (%-hex and + as space). dst is
 * NUL-terminated (cap >= 1); output is truncated to fit. */
void web_url_decode(char *dst, size_t cap, const char *src, size_t src_len);

/* Read a form body field into dst (URL-decoded). Body is the raw
 * application/x-www-form-urlencoded request, NUL-terminated. Returns false
 * if the key is absent, so a caller can tell "field missing" from "field
 * submitted empty" — dst is set to "" either way. */
bool web_form_field(const char *body, const char *key, char *dst, size_t cap);

/* Compare the host component of an Origin/Referer URL against our Host
 * header. Matches scheme://<host>[:port][/...] — the host must appear
 * immediately after "://" and be terminated by ':', '/', or end-of-string.
 * A plain substring test accepts http://<host>.evil.com; this rejects it.
 * Host may carry an explicit port (":443"); host names are compared
 * case-insensitively. */
bool web_origin_host_matches(const char *url, const char *host);

/* Find the `sid` cookie in a Cookie header value and copy its value into out
 * if it is exactly sid_len characters long. `sid=` must be at the start of
 * the header or follow "; " (or ";"), so `xsid=` never matches. out[0] is
 * set to '\0' first; returns true only when a value of exactly sid_len chars
 * was copied. out must hold sid_len + 1 bytes. */
bool web_cookie_sid(const char *cookie, char *out, size_t sid_len);

#ifdef __cplusplus
}
#endif
