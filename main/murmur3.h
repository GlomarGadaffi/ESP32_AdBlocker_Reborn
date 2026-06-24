#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

/* MurmurHash3_x86_32 — public domain (Austin Appleby) */
uint32_t murmur3_32(const void *key, size_t len, uint32_t seed);

#ifdef __cplusplus
}
#endif
