/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/checksums/private/crc_priv.h>

#include <aws/common/macros.h>

uint32_t aws_checksums_crc32c_hw(const uint8_t *input, int length, uint32_t previousCrc32) {
    AWS_FATAL_ASSERT(! "crc32c hardware instructions are not available for this platform!");
    return 0;
}