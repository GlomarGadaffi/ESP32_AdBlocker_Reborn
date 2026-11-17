/*
 * libFuzzer target: main/metrics_prom.c, the /metrics JSON to Prometheus text
 * converter.
 *
 * On the device the input is the firmware's own JSON, but the converter is a
 * parser, so it is fuzzed like the others: arbitrary bytes in, exact-size
 * heap buffers on both sides so a one-byte over-read or over-write is an
 * AddressSanitizer report.
 *
 * Input: [cap byte][json bytes]. The first byte picks the output capacity
 * (16 bytes per step, 0..4080), the rest is the JSON, copied to an exact-size heap buffer with no
 * NUL.
 *
 * Invariants (a false assert is a finding):
 *  - the status is one of the documented codes
 *  - on error: *out_len is 0 and out[0] is '\0' (cap > 0)
 *  - on success: out is NUL-terminated at out_len < cap, ends in '\n' (or is
 *    empty), has no empty lines, and every line starts with "adblock_"
 *  - a larger capacity never turns a success into an error, and never changes
 *    the text (all-or-nothing output)
 *  - a success at capacity C fails with ERR_FULL at capacity out_len (no room
 *    for the NUL), so the length is exact
 */
#include "metrics_prom.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) return 0;
    size_t cap = (size_t)data[0] * 16;   /* 0..4080: room for a full /metrics render */
    data++; size--;

    char *json = (char *)malloc(size ? size : 1);
    memcpy(json, data, size);
    char *out = (char *)malloc(cap ? cap : 1);
    size_t olen = 777;

    int rc = metrics_json_to_prom(json, size, out, cap, &olen);
    assert(rc == METRICS_PROM_OK || rc == METRICS_PROM_ERR_PARSE ||
           rc == METRICS_PROM_ERR_DEPTH || rc == METRICS_PROM_ERR_FULL);

    if (rc != METRICS_PROM_OK) {
        assert(olen == 0);
        if (cap > 0) assert(out[0] == '\0');
    } else {
        assert(olen < cap);
        assert(out[olen] == '\0');
        assert(strlen(out) == olen);
        if (olen > 0) {
            assert(out[olen - 1] == '\n');
            for (size_t i = 0; i < olen; i++) {
                if (out[i] == '\n' && i + 1 < olen)
                    assert(out[i + 1] != '\n');
            }
            assert(strncmp(out, "adblock_", 8) == 0);
            for (size_t i = 0; i + 1 < olen; i++) {
                if (out[i] == '\n')
                    assert(strncmp(out + i + 1, "adblock_", 8) == 0);
            }
        }

        /* Same input, bigger buffer: same text. */
        char *big = (char *)malloc(cap + 64);
        size_t blen = 0;
        int rc2 = metrics_json_to_prom(json, size, big, cap + 64, &blen);
        assert(rc2 == METRICS_PROM_OK && blen == olen && memcmp(big, out, olen) == 0);
        free(big);

        /* Exactly the text, no NUL room: must refuse, not truncate. */
        char *tight = (char *)malloc(olen ? olen : 1);
        size_t tlen = 5;
        int rc3 = metrics_json_to_prom(json, size, tight, olen, &tlen);
        assert(rc3 == METRICS_PROM_ERR_FULL && tlen == 0);
        free(tight);
    }

    free(out);
    free(json);
    return 0;
}
