#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdbool.h>

/*
 * Called once per domain line extracted from the HTTP stream.
 * Return false to abort the download early.
 */
typedef bool (*http_fetch_line_cb)(const char *line, size_t len, void *ctx);

/*
 * Stream-download url line by line, calling cb for each non-empty, non-comment line.
 * Uses a 4KB SRAM chunk buffer with a 256-byte carry buffer for chunk-spanning names.
 * Returns true on success (all bytes consumed), false on HTTP or network error.
 */
bool http_fetch_lines(const char *url, http_fetch_line_cb cb, void *ctx);

#ifdef __cplusplus
}
#endif
