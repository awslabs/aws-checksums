/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/checksums/private/crc_util.h>
#include <stddef.h>

static inline int s_msb_128(const uint128_t x) {
    // __builtin_clzll returns the number of leading zeros (from MSB end) - undefined for x==0 !!!
    if (x >> 64) {
        return 127 - __builtin_clzll((uint64_t)(x >> 64));
    }
    return x ? 63 - __builtin_clzll((uint64_t)x) : -1;
}

static inline int s_lsb_128(const uint128_t x) {
    // __builtin_ctzll returns the number of trailing zeros (from LSB end) - undefined for x==0 !!!
    if ((uint64_t)x) {
        return __builtin_ctzll((uint64_t)x);
    }
    return (x >> 64) ? 64 + __builtin_ctzll((uint64_t)(x >> 64)) : -1;
}

static inline uint128_t s_pow_2(const int n) {
    return ((uint128_t)1) << n;
}

static inline uint128_t s_msb_mask(const uint128_t x) {
    return s_pow_2(s_msb_128(x));
}

uint128_t aws_checksums_multiply_mod_p_reflected(const uint128_t poly, uint128_t a, uint128_t b) {

    if (!a || !b)
        return 0;
    uint128_t hi_bit = s_msb_mask(poly) >> 1;
    // Choose the factor with the most trailing zero bits so the loop can exit soonest
    int swap = s_lsb_128(b) > s_lsb_128(a);
    uint128_t x = swap ? b : a;
    uint128_t y = swap ? a : b;
    uint128_t product = 0;
    // Loop through the bits in the x factor
    while (x) {
        // Every iteration will keep doubling the y factor using right shifts (it's bit-reflected)
        if (y & 1) {
            // But when the field degree bit is set, first reduce using the field polynomial
            y ^= poly;
        }
        y >>= 1;

        if (x & hi_bit) {
            product ^= y;
            // Clear the bit in x so the loop will quit when there are no more bits set
            x ^= hi_bit;
        }

        // Advance to test the next lowest bit in x
        hi_bit >>= 1;
    }
    return product;
}
