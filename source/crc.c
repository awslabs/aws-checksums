/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/checksums/crc.h>

#include <aws/checksums/private/cpuid.h>
#include <aws/checksums/private/crc_priv.h>

static uint32_t (*s_crc32c_fn_ptr)(const uint8_t *input, int length, uint32_t previousCrc32) = 0;

uint32_t aws_checksums_crc32(const uint8_t *input, int length, uint32_t previousCrc32) {
    return aws_checksums_crc32_sw(input, length, previousCrc32);
}

uint32_t aws_checksums_crc32c(const uint8_t *input, int length, uint32_t previousCrc32) {
    if (!s_crc32c_fn_ptr) {
        if (aws_checksums_is_sse42_present()) {
            s_crc32c_fn_ptr = aws_checksums_crc32c_hw;
        } else {
            s_crc32c_fn_ptr = aws_checksums_crc32c_sw;
        }
    }
    return s_crc32c_fn_ptr(input, length, previousCrc32);
}
