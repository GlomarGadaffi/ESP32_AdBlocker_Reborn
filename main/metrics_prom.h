#pragma once
/*
 * Prometheus text exposition (format 0.0.4) built from the /metrics JSON.
 *
 * dns_server_metrics_json() stays the single list of metrics. This converter
 * walks its output once and renders it as Prometheus text, so a field added
 * to the JSON shows up in /metrics/prom with no second table to update.
 *
 * Pure C, no ESP-IDF, no heap, no recursion (explicit frame stack, depth <= 4),
 * so it builds on the host and is fuzzed (tests/fuzz/fuzz_metrics_prom.c).
 *
 * Mapping:
 *   number leaf          adblock_<path joined by _> <number text, verbatim>
 *   true / false         1 / 0
 *   array of numbers     adblock_<path>{idx="N"} <value>
 *   null, other strings  skipped
 *   top-level strings    version, board, upstream, clock_src become labels on
 *                        one trailing adblock_info{...} 1 line (when present)
 *   arrays of objects    skipped (still validated), e.g. pause_list
 * Metric names are sanitised to [a-zA-Z0-9_].
 */
#include <stddef.h>

#define METRICS_PROM_OK          0
#define METRICS_PROM_ERR_PARSE  (-1)   /* malformed JSON, or a key too long for the name buffer */
#define METRICS_PROM_ERR_DEPTH  (-2)   /* more than 4 nested containers */
#define METRICS_PROM_ERR_FULL   (-3)   /* output does not fit in out_cap (text + NUL) */
#define METRICS_PROM_ERR_ARG    (-4)   /* NULL pointer */

#define METRICS_PROM_MAX_DEPTH 4

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Convert `json` (json_len bytes, not necessarily NUL-terminated) into
 * Prometheus text in out[0..out_cap). On success the text is NUL-terminated,
 * *out_len is its length without the NUL, and the return is METRICS_PROM_OK.
 * On any error *out_len is 0, out[0] is '\0' (when out_cap > 0), and the
 * return is one of the METRICS_PROM_ERR_* codes. Output is all-or-nothing:
 * a truncated result is an error, never a partial line.
 */
int metrics_json_to_prom(const char *json, size_t json_len,
                         char *out, size_t out_cap, size_t *out_len);

#ifdef __cplusplus
}
#endif
