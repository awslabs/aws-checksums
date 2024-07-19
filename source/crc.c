/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/checksums/crc.h>
#include <aws/checksums/private/crc_priv.h>

#include <aws/common/cpuid.h>

static uint32_t (*s_crc32c_fn_ptr)(const uint8_t *input, int length, uint32_t previousCrc32) = 0;
static uint32_t (*s_crc32_fn_ptr)(const uint8_t *input, int length, uint32_t previousCrc32) = 0;

uint32_t aws_checksums_crc32(const uint8_t *input, int length, uint32_t previousCrc32) {
    if (AWS_UNLIKELY(!s_crc32_fn_ptr)) {
#ifdef AWS_HAVE_ARM32_CRC
        if (aws_cpu_has_feature(AWS_CPU_FEATURE_ARM_CRC))
            s_crc32_fn_ptr = aws_checksums_crc32_hw;
#elif defined AWS_HAVE_AVX512_INTRINSICS
        if (aws_cpu_has_feature(AWS_CPU_FEATURE_AVX512) &&
            aws_cpu_has_feature(AWS_CPU_FEATURE_VPCLMULQDQ))
            s_crc32_fn_ptr = aws_checksums_crc32_avx512;
#else
        if (0) {}
#endif
        else
            s_crc32_fn_ptr = aws_checksums_crc32_sw;
    }
    return s_crc32_fn_ptr(input, length, previousCrc32);
}

uint32_t aws_checksums_crc32c(const uint8_t *input, int length, uint32_t previousCrc32) {
    if (AWS_UNLIKELY(!s_crc32c_fn_ptr)) {
#ifdef AWS_HAVE_ARM32_CRC
        if (aws_cpu_has_feature(AWS_CPU_FEATURE_ARM_CRC))
            s_crc32c_fn_ptr = aws_checksums_crc32c_hw;
#else
# ifdef AWS_HAVE_AVX512_INTRINSICS
        if (aws_cpu_has_feature(AWS_CPU_FEATURE_AVX512) &&
            aws_cpu_has_feature(AWS_CPU_FEATURE_VPCLMULQDQ))
            s_crc32c_fn_ptr = aws_checksums_crc32c_avx512;
        else
# endif
        if (aws_cpu_has_feature(AWS_CPU_FEATURE_SSE_4_2)) {
# ifdef AWS_HAVE_CLMUL
            if (aws_cpu_has_feature(AWS_CPU_FEATURE_CLMUL))
                s_crc32c_fn_ptr = aws_checksums_crc32c_clmul;
            else
# endif
                s_crc32c_fn_ptr = aws_checksums_crc32c_hw;
        }
#endif
        else
            s_crc32c_fn_ptr = aws_checksums_crc32c_sw;
    }
    return s_crc32c_fn_ptr(input, length, previousCrc32);
}
