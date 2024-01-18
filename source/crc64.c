/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/checksums/crc.h>
#include <aws/checksums/private/crc64_priv.h>
#include <aws/common/cpuid.h>

AWS_ALIGNED_TYPEDEF(uint8_t, checksums_maxks_shifts_type[6][16], 16);
// Intel PSHUFB / ARM VTBL patterns for left/right shifts and masks
checksums_maxks_shifts_type aws_checksums_masks_shifts = {
    {0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80}, //
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, // left/right
                                                                                                      // shifts
    {0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80}, //
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, //
    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // byte masks
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, //
};

AWS_ALIGNED_TYPEDEF(aws_checksums_crc64_constants_t, cheksums_constants, 16);

// Pre-computed bit-reflected constants for CRC64XZ
// The actual exponents are reduced by 1 to compensate for bit-reflection (e.g. x^1024 is actually x^1023)
cheksums_constants aws_checksums_crc64xz_constants = {
    //

    .x2048 =
        {0x8260adf2381ad81c,
         0xf31fd9271e228b79, // x^2112 mod P(x) / x^2048 mod P(x)
         0x8260adf2381ad81c,
         0xf31fd9271e228b79, // duplicated 3 times to support 64 byte avx512 loads
         0x8260adf2381ad81c,
         0xf31fd9271e228b79, //
         0x8260adf2381ad81c,
         0xf31fd9271e228b79}, //
    .x1536 =
        {0x47b00921f036ff71,
         0xb0382771eb06c453, // x^1600 mod P(x) / x^1536 mod P(x)
         0x47b00921f036ff71,
         0xb0382771eb06c453, // duplicated 3 times to support 64 byte avx512 loads
         0x47b00921f036ff71,
         0xb0382771eb06c453, //
         0x47b00921f036ff71,
         0xb0382771eb06c453}, //
    .x1024 =
        {0x8757d71d4fcc1000,
         0xd7d86b2af73de740, // x^1088 mod P(x) / x^1024 mod P(x)
         0x8757d71d4fcc1000,
         0xd7d86b2af73de740, // duplicated 3 times to support 64 byte avx512 loads
         0x8757d71d4fcc1000,
         0xd7d86b2af73de740, //
         0x8757d71d4fcc1000,
         0xd7d86b2af73de740}, //
    .x512 =
        {0x6ae3efbb9dd441f3,
         0x081f6054a7842df4, // x^576 mod P(x) / x^512 mod P(x)
         0x6ae3efbb9dd441f3,
         0x081f6054a7842df4, // duplicated 3 times to support 64 byte avx512 loads
         0x6ae3efbb9dd441f3,
         0x081f6054a7842df4, //
         0x6ae3efbb9dd441f3,
         0x081f6054a7842df4},                            //
    .x384 = {0xb5ea1af9c013aca4, 0x69a35d91c3730254},    //  x^448 mod P(x) / x^384 mod P(x)
    .x256 = {0x60095b008a9efa44, 0x3be653a30fe1af51},    //  x^320 mod P(x) / x^256 mod P(x)
    .x128 = {0xe05dd497ca393ae4, 0xdabe95afc7875f40},    //  x^192 mod P(x) / x^128 mod P(x)
    .mu_poly = {0x9c3e466c172963d5, 0x92d8af2baf0e1e85}, // Barrett mu / polynomial P(x) (bit-reflected)
    .trailing =
        {
            // trailing input constants for data lengths of 1-15 bytes
            {0x646c955f440400fe, 0xb32e4cbe03a75f6f}, //  1 trailing bytes:  x^72 mod P(x) /   x^8 mod P(x)
            {0x53e7815838846436, 0x54e979925cd0f10d}, //  2 trailing bytes:  x^80 mod P(x) /  x^15 mod P(x)
            {0x09abf11afca2d0d7, 0x3f0be14a916a6dcb}, //  3 trailing bytes:  x^88 mod P(x) /  x^24 mod P(x)
            {0xec32cffb23e3ed7d, 0x1dee8a5e222ca1dc}, //  4 trailing bytes:  x^96 mod P(x) /  x^32 mod P(x)
            {0xdda9f27ee08373ad, 0x5c2d776033c4205e}, //  5 trailing bytes: x^104 mod P(x) /  x^40 mod P(x)
            {0x0dd9b4240837fd99, 0x6184d55f721267c6}, //  6 trailing bytes: x^110 mod P(x) /  x^48 mod P(x)
            {0xf075e4ae5e05bdff, 0x22ef0d5934f964ec}, //  7 trailing bytes: x^110 mod P(x) /  x^56 mod P(x)
            {0xe05dd497ca393ae4, 0xdabe95afc7875f40}, //  8 trailing bytes: x^120 mod P(x) /  x^64 mod P(x)
            {0x2ddda07ff6672378, 0x646c955f440400fe}, //  9 trailing bytes: x^128 mod P(x) /  x^72 mod P(x)
            {0x1596922b987ef63f, 0x53e7815838846436}, // 10 trailing bytes: x^144 mod P(x) /  x^80 mod P(x)
            {0x4d624bbe73bbc94c, 0x09abf11afca2d0d7}, // 11 trailing bytes: x^152 mod P(x) /  x^88 mod P(x)
            {0xe88a0d0c5521de3d, 0xec32cffb23e3ed7d}, // 12 trailing bytes: x^160 mod P(x) /  x^96 mod P(x)
            {0xb91b6176fc36363f, 0xdda9f27ee08373ad}, // 13 trailing bytes: x^168 mod P(x) / x^104 mod P(x)
            {0x4dcec64d2edf818c, 0x0dd9b4240837fd99}, // 14 trailing bytes: x^176 mod P(x) / x^112 mod P(x)
            {0x4550ddde9a383296, 0xf075e4ae5e05bdff}  // 15 trailing bytes: x^184 mod P(x) / x^120 mod P(x)
        },                                            //
};

static uint64_t (*s_crc64xz_fn_ptr)(const uint8_t *input, int length, uint64_t previousCrc64) = 0;

uint64_t aws_checksums_crc64xz(const uint8_t *input, int length, uint64_t previousCrc64) {

    if (AWS_UNLIKELY(!s_crc64xz_fn_ptr)) {
#if defined(__x86_64__)
        if (aws_cpu_has_feature(AWS_CPU_FEATURE_AVX512) && aws_cpu_has_feature(AWS_CPU_FEATURE_CLMUL) &&
            aws_cpu_has_feature(AWS_CPU_FEATURE_VPCLMULQDQ)) {
            s_crc64xz_fn_ptr = aws_checksums_crc64xz_intel_clmul;
        } else {
            s_crc64xz_fn_ptr = aws_checksums_crc64xz_sw;
        }
#elif defined(__aarch64__) // defined(__x86_64__)
        // TODO need to add these feature flags to aws-c-common
        // if (aws_cpu_has_feature(AWS_CPU_FEATURE_ARM_CRYPTO) && aws_cpu_has_feature(AWS_CPU_FEATURE_ARM_PMULL64)) {
        s_crc64xz_fn_ptr = aws_checksums_crc64xz_arm_pmull;
        //} else {
        //    s_crc64xz_fn_ptr = aws_checksums_crc64xz_sw;
        //}
#else                      // defined(__aarch64__)

        s_crc64xz_fn_ptr = aws_checksums_crc64xz_sw;
#endif
    }

    return s_crc64xz_fn_ptr(input, length, previousCrc64);
}
