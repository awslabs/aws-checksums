/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

/* for the moment, fallback to SW on ARM until MSFT adds intrensics for ARM v8.1+ */
#if (defined(_M_ARM) || defined(__arm__) || defined(__aarch64__) || defined(__ARM_ARCH_ISA_A64))

#    include <aws/checksums/private/crc_priv.h>

uint32_t aws_checksums_crc32c_hw(const uint8_t *data, int length, uint32_t previousCrc32) {
    return aws_checksums_crc32c_sw(data, length, previousCrc32);
}

#endif
