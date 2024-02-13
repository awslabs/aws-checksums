#ifndef AWS_CHECKSUMS_PRIVATE_CRC_PRIV_H
#define AWS_CHECKSUMS_PRIVATE_CRC_PRIV_H
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#define AWS_CRC32_SIZE_BYTES 4
#include <aws/checksums/exports.h>
#include <aws/common/common.h>

#include <aws/common/config.h>
#include <stdint.h>

/* Pre-computed constants for CRC32 */
typedef struct {
    uint64_t x2048[8];        // x^2112 mod P(x) / x^2048 mod P(x)
    uint64_t x1536[8];        // x^1600 mod P(x) / x^1536 mod P(x)
    uint64_t x1024[8];        // x^1088 mod P(x) / x^1024 mod P(x)
    uint64_t x512[8];         // x^576  mod P(x) / x^512  mod P(x)
    uint64_t x384[2];         // x^448  mod P(x) / x^384  mod P(x)
    uint64_t x256[2];         // x^320  mod P(x) / x^256  mod P(x)
    uint64_t x128[2];         // x^192  mod P(x) / x^128  mod P(x)
    uint64_t x64[2];          // x^96   mod P(x) / x^64   mod P(x)
    uint64_t mu_poly[2];      // Barrett mu / 33-bit polynomial P(x)
    uint64_t trailing[15][2]; // Folding constants for 15 possible trailing input data lengths
} aws_checksums_crc32_constants_t;
extern uint8_t aws_checksums_masks_shifts[6][16];

AWS_EXTERN_C_BEGIN

AWS_CHECKSUMS_API aws_checksums_crc32_constants_t aws_checksums_crc32_constants;

/* Computes CRC32 (Ethernet, gzip, et. al.) using a (slow) reference implementation. */
AWS_CHECKSUMS_API uint32_t aws_checksums_crc32_sw(const uint8_t *input, int length, uint32_t previousCrc32);

/* Computes the Castagnoli CRC32c (iSCSI) using a (slow) reference implementation. */
AWS_CHECKSUMS_API uint32_t aws_checksums_crc32c_sw(const uint8_t *input, int length, uint32_t previousCrc32c);

#if defined(AWS_USE_CPU_EXTENSIONS) && defined(AWS_ARCH_ARM64)
uint32_t aws_checksums_crc32_armv8(const uint8_t *input, int length, uint32_t previous_crc32);
uint32_t aws_checksums_crc32c_armv8(const uint8_t *input, int length, uint32_t previous_crc32c);
#elif defined(AWS_USE_CPU_EXTENSIONS) && defined(AWS_ARCH_INTEL)
#    if defined(AWS_ARCH_INTEL_X64)
typedef uint64_t *slice_ptr_type;
typedef uint64_t slice_ptr_int_type;
#        define crc_intrin_fn _mm_crc32_u64

#        if !defined(_MSC_VER)
uint32_t aws_checksums_crc32c_clmul_sse42(const uint8_t *data, int length, uint32_t previous_crc32c);
#        endif

#    else
typedef uint32_t *slice_ptr_type;
typedef uint32_t slice_ptr_int_type;
#        define crc_intrin_fn _mm_crc32_u32
#    endif
uint32_t aws_checksums_crc32c_intel_avx512_with_sse_fallback(
    const uint8_t *input,
    int length,
    uint32_t previous_crc32c);

uint32_t aws_checksums_crc32_intel_clmul(const uint8_t *input, int length, uint32_t previous_crc);
#endif

AWS_EXTERN_C_END

#endif /* AWS_CHECKSUMS_PRIVATE_CRC_PRIV_H */
