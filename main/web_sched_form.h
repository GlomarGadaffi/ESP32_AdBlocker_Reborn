#pragma once
/*
 * POST /pause/schedule form-body conversion, with zero ESP-IDF dependencies so
 * it is compiled and tested on the host (tests/web_sched_form_test.c). The body
 * is attacker-controlled (any logged-in session), so every length is bounded
 * and nothing is allocated.
 *
 * Accepted bodies (field order does not matter):
 *   slot=<0-3>&spec=<text>          spec non-empty -> WSF_SET_WINDOW
 *                                   spec empty     -> WSF_CLEAR_WINDOW
 *   utc_offset_min=<-720..840>      -> WSF_SET_OFFSET
 * Anything else, including both forms at once, is rejected.
 */
#include <stdbool.h>
#include "pause_sched.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    WSF_REJECT = 0,
    WSF_SET_WINDOW,
    WSF_CLEAR_WINDOW,
    WSF_SET_OFFSET
} wsf_kind_t;

typedef struct {
    wsf_kind_t           kind;
    int                  slot;             /* WSF_SET_WINDOW, WSF_CLEAR_WINDOW */
    pause_sched_window_t win;              /* WSF_SET_WINDOW only */
    int                  utc_offset_min;   /* WSF_SET_OFFSET only */
    const char          *err;              /* static plain-text reason when rejected */
} web_sched_form_t;

/* Returns true and fills *out on an accepted body; false with out->kind ==
 * WSF_REJECT and out->err set otherwise. NULL arguments return false. */
bool web_sched_form_parse(const char *body, web_sched_form_t *out);

#ifdef __cplusplus
}
#endif
