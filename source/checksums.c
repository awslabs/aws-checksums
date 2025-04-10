/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/checksums/checksums.h>
#include <aws/checksums/private/crc_util.h>
#include <aws/common/cpuid.h>

bool s_detection_performed = false;
bool s_detected_sse42 = false;
bool s_detected_avx512 = false;
bool s_detected_clmul = false;
bool s_detected_vpclmulqdq = false;

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
