#ifndef AWS_CHECKSUMS_PRIVATE_CRC_UTIL_H
#define AWS_CHECKSUMS_PRIVATE_CRC_UTIL_H
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

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

#endif /* AWS_CHECKSUMS_PRIVATE_CRC_UTIL_H */
