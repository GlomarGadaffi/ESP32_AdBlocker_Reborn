#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#ifdef ESP_PLATFORM
#include "esp_attr.h"
#else
#define IRAM_ATTR
#endif

/* MurmurHash3_x86_32 — public domain (Austin Appleby). IRAM_ATTR (#78): the
 * only caller of domain_hash() that matters for placement is the L2 fast
 * path — tagging domain_hash() there but leaving the actual hash work here
 * in flash (no LTO in this build, so it can't get inlined across the TU
 * boundary) would make that tag a no-op. Tag lives on the definition in
 * murmur3.c only — repeating it here would give GCC two different
 * generated section names for the same symbol and fail under
 * -Werror=attributes. */
uint32_t murmur3_32(const void *key, size_t len, uint32_t seed);

#ifdef __cplusplus
}
#endif
