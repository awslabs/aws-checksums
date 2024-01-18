#ifndef AWS_CHECKSUMS_CRC_H
#define AWS_CHECKSUMS_CRC_H
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/checksums/exports.h>
#include <aws/common/macros.h>
#include <stdint.h>

AWS_PUSH_SANE_WARNING_LEVEL
AWS_EXTERN_C_BEGIN

/**
 * The entry point function to perform a CRC32 (Ethernet, gzip) computation.
 * Selects a suitable implementation based on hardware capabilities.
 * Pass 0 in the previousCrc32 parameter as an initial value unless continuing
 * to update a running crc in a subsequent call.
 */
AWS_CHECKSUMS_API uint32_t aws_checksums_crc32(const uint8_t *input, int length, uint32_t previous_crc32);

/**
 * The entry point function to perform a Castagnoli CRC32c (iSCSI) computation.
 * Selects a suitable implementation based on hardware capabilities.
 * Pass 0 in the previousCrc32 parameter as an initial value unless continuing
 * to update a running crc in a subsequent call.
 */
AWS_CHECKSUMS_API uint32_t aws_checksums_crc32c(const uint8_t *input, int length, uint32_t previous_crc32c);

/**
 * The entry point function to perform a CRC64-XZ (a.k.a. CRC64-GOECMA) computation.
 * Selects a suitable implementation based on hardware capabilities.
 * Pass 0 in the previousCrc64 parameter as an initial value unless continuing
 * to update a running crc in a subsequent call.
 * There are many variants of CRC64 algorithms. This CRC64 variant is bit-reflected (based on
 * the non bit-reflected polynomial 0x142F0E1EBA9EA3693) and inverts the CRC input and output bits.
 */
AWS_CHECKSUMS_API uint64_t aws_checksums_crc64xz(const uint8_t *input, int length, uint64_t previous_crc64);

AWS_EXTERN_C_END
AWS_POP_SANE_WARNING_LEVEL

#endif /* AWS_CHECKSUMS_CRC_H */
