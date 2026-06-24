#include "murmur3.h"
#include <string.h>

static inline uint32_t rotl32(uint32_t x, int8_t r) { return (x << r) | (x >> (32 - r)); }
#define FMIX32(h) h ^= h >> 16; h *= 0x85ebca6bu; h ^= h >> 13; h *= 0xc2b2ae35u; h ^= h >> 16;

uint32_t murmur3_32(const void *key, size_t len, uint32_t seed)
{
    const uint8_t *data = (const uint8_t *)key;
    const int nblocks = (int)len / 4;
    uint32_t h1 = seed;
    const uint32_t c1 = 0xcc9e2d51u, c2 = 0x1b873593u;

    for (int i = 0; i < nblocks; i++) {
        uint32_t k1;
        memcpy(&k1, data + i * 4, 4);
        k1 *= c1; k1 = rotl32(k1, 15); k1 *= c2;
        h1 ^= k1; h1 = rotl32(h1, 13); h1 = h1 * 5u + 0xe6546b64u;
    }

    const uint8_t *tail = data + nblocks * 4;
    uint32_t k1 = 0;
    switch (len & 3) {
        case 3: k1 ^= (uint32_t)tail[2] << 16; /* fall through */
        case 2: k1 ^= (uint32_t)tail[1] << 8;  /* fall through */
        case 1: k1 ^= tail[0]; k1 *= c1; k1 = rotl32(k1, 15); k1 *= c2; h1 ^= k1;
    }

    h1 ^= (uint32_t)len;
    FMIX32(h1);
    return h1;
}
