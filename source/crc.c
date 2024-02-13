/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/checksums/crc.h>
#include <aws/checksums/private/crc_priv.h>

#include <aws/common/cpuid.h>

static uint32_t (*s_crc32c_fn_ptr)(const uint8_t *input, int length, uint32_t previous_crc32c) = 0;
static uint32_t (*s_crc32_fn_ptr)(const uint8_t *input, int length, uint32_t previous_crc32) = 0;

/* clang-format off */
AWS_ALIGNED_TYPEDEF(aws_checksums_crc32_constants_t, cheksums_constants, 16);

// Pre-computed bit-reflected constants for CRC32
// The actual exponents are reduced by 1 to compensate for bit-reflection (e.g. x^1024 is actually x^1023)
// Inconsistent alignment of the 32-bit constants is by design so that carryless multiplication results align
aws_checksums_crc32_constants_t aws_checksums_crc32_constants = {
    .x2048 =
        {0x7cc8e1e700000000, // x^2112 mod P(x) / x^2048 mod P(x)
         0x03f9f86300000000,
         0x7cc8e1e700000000, // duplicated 3 times to support 64 byte avx512 loads
         0x03f9f86300000000,
         0x7cc8e1e700000000,
         0x03f9f86300000000,
         0x7cc8e1e700000000,
         0x03f9f86300000000},
    .x1536 =
        {0x67f7947600000000, // x^1600 mod P(x) / x^1536 mod P(x)
         0xc56d949600000000,
         0x67f7947600000000, // duplicated 3 times to support 64 byte avx512 loads
         0xc56d949600000000,
         0x67f7947600000000,
         0xc56d949600000000,
         0x67f7947600000000,
         0xc56d949600000000},
    .x1024 =
        {0x7d657a1000000000, // x^1088 mod P(x) / x^1024 mod P(x)
         0x7406fa9500000000,
         0x7d657a1000000000, // duplicated 3 times to support 64 byte avx512 loads
         0x7406fa9500000000,
         0x7d657a1000000000,
         0x7406fa9500000000,
         0x7d657a1000000000,
         0x7406fa9500000000},
    .x512 =
        {0x653d982200000000, // x^576 mod P(x) / x^512 mod P(x)
         0xcad38e8f00000000,
         0x653d982200000000, // duplicated 3 times to support 64 byte avx512 loads
         0xcad38e8f00000000,
         0x653d982200000000,
         0xcad38e8f00000000,
         0x653d982200000000,
         0xcad38e8f00000000},
    .x384 = {0x69ccfc0d00000000, 0x2a28386200000000},    //  x^448 mod P(x) / x^384 mod P(x)
    .x256 = {0x9570d49500000000, 0x01b5fd1d00000000},    //  x^320 mod P(x) / x^256 mod P(x)
    .x128 = {0x65673b4600000000, 0x9ba54c6f00000000},    //  x^192 mod P(x) / x^128 mod P(x)
    .x64 = {0xccaa009e00000000, 0x00000000b8bc6765},     //  x^96  mod P(x) / x^64  mod P(x) (alignment deliberate)
    .mu_poly = {0x00000000f7011641, 0x00000001db710641}, // Barrett mu / polynomial P(x) (bit-reflected)
    .trailing =
        {
            // bit-reflected trailing input constants for data lengths of 1-15 bytes
            {0x3d6029b000000000, 0x0100000000000000}, //  1 trailing bytes:  x^72 mod P(x) /  shift  8 bits
            {0xcb5cd3a500000000, 0x0001000000000000}, //  2 trailing bytes:  x^80 mod P(x) /  shift 16 bits
            {0xa6770bb400000000, 0x0000010000000000}, //  3 trailing bytes:  x^88 mod P(x) /  shift 24 bits
            {0xccaa009e00000000, 0x0000000100000000}, //  4 trailing bytes:  x^96 mod P(x) /  shift 32 bits
            {0x177b144300000000, 0x0000000001000000}, //  5 trailing bytes: x^104 mod P(x) /  shift 40 bits
            {0xefc26b3e00000000, 0x0000000000010000}, //  6 trailing bytes: x^112 mod P(x) /  shift 48 bits
            {0xc18edfc000000000, 0x0000000000000100}, //  7 trailing bytes: x^120 mod P(x) /  shift 56 bits
            {0x9ba54c6f00000000, 0x0000000000000001}, //  8 trailing bytes: x^128 mod P(x) /  shift 64 bits
            {0xdd96d98500000000, 0x3d6029b000000000}, //  9 trailing bytes: x^136 mod P(x) /  x^72 mod P(x)
            {0x9d0fe17600000000, 0xcb5cd3a500000000}, // 10 trailing bytes: x^144 mod P(x) /  x^80 mod P(x)
            {0xb9fbdbe800000000, 0xa6770bb400000000}, // 11 trailing bytes: x^152 mod P(x) /  x^88 mod P(x)
            {0xae68919100000000, 0xccaa009e00000000}, // 12 trailing bytes: x^160 mod P(x) /  x^96 mod P(x)
            {0x87a6cb4300000000, 0x177b144300000000}, // 13 trailing bytes: x^168 mod P(x) / x^104 mod P(x)
            {0xef52b6e100000000, 0xefc26b3e00000000}, // 14 trailing bytes: x^176 mod P(x) / x^112 mod P(x)
            {0xd7e2805800000000, 0xc18edfc000000000}  // 15 trailing bytes: x^184 mod P(x) / x^120 mod P(x)
        },
};
/* clang-format on */

uint32_t aws_checksums_crc32(const uint8_t *input, int length, uint32_t previous_crc32) {
    if (AWS_UNLIKELY(!s_crc32_fn_ptr)) {
#if defined(AWS_USE_CPU_EXTENSIONS) && defined(AWS_ARCH_INTEL_X64) && !(defined(_MSC_VER) && _MSC_VER < 1920)
        if (aws_cpu_has_feature(AWS_CPU_FEATURE_CLMUL) && aws_cpu_has_feature(AWS_CPU_FEATURE_AVX2)) {
            s_crc32_fn_ptr = aws_checksums_crc32_intel_clmul;
        } else {
            s_crc32c_fn_ptr = aws_checksums_crc32_sw;
        }
#elif defined(AWS_USE_CPU_EXTENSIONS) && defined(AWS_ARCH_ARM64)
        if (aws_cpu_has_feature(AWS_CPU_FEATURE_ARM_CRC)) {
            s_crc32c_fn_ptr = aws_checksums_crc32_armv8;
        } else {
            s_crc32c_fn_ptr = aws_checksums_crc32_sw;
        }
#else
        s_crc32c_fn_ptr = aws_checksums_crc32_sw;
#endif
    }
    return s_crc32_fn_ptr(input, length, previous_crc32);
}

uint32_t aws_checksums_crc32c(const uint8_t *input, int length, uint32_t previous_crc32c) {
    if (AWS_UNLIKELY(!s_crc32c_fn_ptr)) {
#if defined(AWS_USE_CPU_EXTENSIONS) && defined(AWS_ARCH_INTEL_X64)
        if (aws_cpu_has_feature(AWS_CPU_FEATURE_SSE_4_2)) {
            s_crc32c_fn_ptr = aws_checksums_crc32c_intel_avx512_with_sse_fallback;
        } else {
            s_crc32c_fn_ptr = aws_checksums_crc32c_sw;
        }
#elif defined(AWS_USE_CPU_EXTENSIONS) && defined(AWS_ARCH_ARM64)
        if (aws_cpu_has_feature(AWS_CPU_FEATURE_ARM_CRC)) {
            s_crc32c_fn_ptr = aws_checksums_crc32c_armv8;
        } else {
            s_crc32c_fn_ptr = aws_checksums_crc32c_sw;
        }
#else
        s_crc32c_fn_ptr = aws_checksums_crc32c_sw;
#endif
    }

    return s_crc32c_fn_ptr(input, length, previous_crc32c);
}
