#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

/*
 * Called once per domain line extracted from the HTTP stream.
 * Return false to abort the download early.
 */
typedef bool (*http_fetch_line_cb)(const char *line, size_t len, void *ctx);

/*
 * Optional callback checked by the fetch watchdog every 1s.
 * Return true to abort the download early (e.g. user-requested stop).
 */
typedef bool (*http_fetch_abort_cb)(void *ctx);

/*
 * Stream-download url line by line, calling cb for each non-empty, non-comment line.
 * Uses a 4KB SRAM chunk buffer with a 256-byte carry buffer for chunk-spanning names.
 * Features an active watchdog enforcing inactivity_timeout_s and total_timeout_s.
 * Returns true on success (all bytes consumed), false on HTTP or network error.
 */
bool http_fetch_lines_ex(const char *url,
                         http_fetch_line_cb line_cb,
                         void *user_ctx,
                         http_fetch_abort_cb abort_cb,
                         uint32_t inactivity_timeout_s,
                         uint32_t total_timeout_s);

/*
 * Default wrapper with 30s inactivity timeout and 360s total timeout.
 */
bool http_fetch_lines(const char *url, http_fetch_line_cb cb, void *ctx);

#ifdef __cplusplus
}
#endif
