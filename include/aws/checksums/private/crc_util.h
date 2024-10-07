#ifndef AWS_CHECKSUMS_PRIVATE_CRC_UTIL_H
#define AWS_CHECKSUMS_PRIVATE_CRC_UTIL_H
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/byte_order.h>
#include <aws/common/stdint.h>
#include <limits.h>

#define large_buffer_apply_impl(Name, T)                                                                               \
    static T aws_large_buffer_apply_##Name(                                                                            \
        T (*checksum_fn)(const uint8_t *, int, T), const uint8_t *buffer, size_t length, T previous) {                 \
        T val = previous;                                                                                              \
        while (length > INT_MAX) {                                                                                     \
            val = checksum_fn(buffer, INT_MAX, val);                                                                   \
            buffer += (size_t)INT_MAX;                                                                                 \
            length -= (size_t)INT_MAX;                                                                                 \
        }                                                                                                              \
        val = checksum_fn(buffer, (int)length, val);                                                                   \
        return val;                                                                                                    \
    }

/* helper function to reverse byte order on big-endian platforms*/
static inline uint32_t aws_swap_bytes_if_needed_32(uint32_t x) {
    if (!aws_is_big_endian()) {
        return x;
    }

    uint8_t c1 = x & 0xFF;
    uint8_t c2 = (x >> 8) & 0xFF;
    uint8_t c3 = (x >> 16) & 0xFF;
    uint8_t c4 = (x >> 24) & 0xFF;

    return ((uint32_t)c1 << 24) + ((uint32_t)c2 << 16) + ((uint32_t)c3 << 8) + c4;
}

/* Reverse the bytes in a 64-bit word. */
static inline uint64_t aws_swap_bytes_if_needed_64(uint64_t x) {
    if (!aws_is_big_endian()) {
        return x;
    }

    uint64_t m;
    m = 0xff00ff00ff00ff;
    x = ((x >> 8) & m) | (x & m) << 8;
    m = 0xffff0000ffff;
    x = ((x >> 16) & m) | (x & m) << 16;
    return x >> 32 | x << 32;
}


#endif /* AWS_CHECKSUMS_PRIVATE_CRC_UTIL_H */
