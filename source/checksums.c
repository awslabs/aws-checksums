/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/checksums/checksums.h>
#include <aws/checksums/private/crc_util.h>
#include <aws/common/cpuid.h>

static bool s_checksums_library_initialized = false;

void aws_checksums_library_init(struct aws_allocator *allocator) {
    if (!s_checksums_library_initialized) {
        s_checksums_library_initialized = true;

        aws_common_library_init(allocator);

        (void)aws_cpu_has_clmul_cached(); /* warm up the cache */
        aws_checksums_crc32_init();
        aws_checksums_crc64_init();
    }
}

void aws_checksums_library_clean_up(void) {
    if (s_checksums_library_initialized) {
        s_checksums_library_initialized = false;
        aws_common_library_clean_up();
    }
}

static bool s_detection_performed = false;
static bool s_detected_sse42 = false;
static bool s_detected_avx512 = false;
static bool s_detected_clmul = false;
static bool s_detected_vpclmulqdq = false;

static void s_init_detection_cache() {
    s_detected_clmul = aws_cpu_has_feature(AWS_CPU_FEATURE_CLMUL);
    s_detected_sse42 = aws_cpu_has_feature(AWS_CPU_FEATURE_SSE_4_2);
    s_detected_avx512 = aws_cpu_has_feature(AWS_CPU_FEATURE_AVX512);
    s_detected_clmul = aws_cpu_has_feature(AWS_CPU_FEATURE_CLMUL);
    s_detected_vpclmulqdq = aws_cpu_has_feature(AWS_CPU_FEATURE_VPCLMULQDQ);
}

extern inline bool aws_cpu_has_clmul_cached() {
    if (AWS_UNLIKELY(!s_detection_performed)) {
        s_init_detection_cache();
    }
    return s_detected_clmul;
}

extern inline bool aws_cpu_has_sse42_cached() {
    if (AWS_UNLIKELY(!s_detection_performed)) {
        s_init_detection_cache();
    }
    return s_detected_sse42;
}

extern inline bool aws_cpu_has_avx512_cached() {
    if (AWS_UNLIKELY(!s_detection_performed)) {
        s_init_detection_cache();
    }
    return s_detected_avx512;
}

extern inline bool aws_cpu_has_vpclmulqdq_cached() {
    if (AWS_UNLIKELY(!s_detection_performed)) {
        s_init_detection_cache();
    }
    return s_detected_vpclmulqdq;
}
