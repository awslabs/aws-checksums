#ifndef AWS_CHECKSUMS_PRIVATE_CRC64_PRIV_H
#define AWS_CHECKSUMS_PRIVATE_CRC64_PRIV_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <stdint.h>
#include <aws/common/macros.h>
#include <aws/checksums/exports.h>

AWS_EXTERN_C_BEGIN

uint64_t aws_checksums_crc64xz_sw(const uint8_t *input, int length, uint64_t previousCrc64);

#if defined(__x86_64__)
uint64_t aws_checksums_crc64xz_intel_clmul(const uint8_t *input, int length, uint64_t previousCrc64);
#endif /* defined(__x86_64__) */

#if defined(__aarch64__)
uint64_t aws_checksums_crc64xz_arm_pmull(const uint8_t *input, int length, uint64_t previousCrc64);
#endif /* defined(__aarch64__) */

/* Pre-computed constants for CRC64 */
typedef struct {
    uint64_t x2048[8]; // x^2112 mod P(x) / x^2048 mod P(x)
    uint64_t x1536[8]; // x^1600 mod P(x) / x^1536 mod P(x)
    uint64_t x1024[8]; // x^1088 mod P(x) / x^1024 mod P(x)
    uint64_t x512[8];  // x^576  mod P(x) / x^512  mod P(x)
    uint64_t x384[2];  // x^448  mod P(x) / x^384  mod P(x)
    uint64_t x256[2];  // x^320  mod P(x) / x^256  mod P(x)
    uint64_t x128[2];  // x^192  mod P(x) / x^128  mod P(x)
    uint64_t mu_poly[2]; // Barrett mu / polynomial P(x)
    uint64_t trailing[15][2]; // Folding constants for 15 possible trailing input data lengths
} aws_checksums_crc64_constants_t;

extern uint8_t aws_checksums_masks_shifts[6][16];
extern aws_checksums_crc64_constants_t aws_checksums_crc64xz_constants;

AWS_EXTERN_C_END

#endif /* AWS_CHECKSUMS_PRIVATE_CRC64_PRIV_H */
