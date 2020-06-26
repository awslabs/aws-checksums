/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/checksums/private/cpuid.h>
#include <intrin.h>
#include <inttypes.h>

#if defined(_M_X64) || defined(_M_IX86)

static int s_cpuid_check_ran = 0;
static int32_t s_cpuid_output = 0;

int aws_checksums_is_cpuid_supported(void) {
    return 1;
}

int aws_checksums_do_cpu_id(int32_t *cpuid) {

    if (!s_cpuid_check_ran) {
        int cpu_info[4] = {-1};
        __cpuid(cpu_info, 0);
        unsigned nIds_ = cpu_info[0];

        __cpuid(cpu_info, 0);

        if (nIds_ >= 2) {
            __cpuid(cpu_info, 1);
            s_cpuid_output = cpu_info[2];
        } else {
            return 0;
        }

        s_cpuid_check_ran = 1;
    }

    *cpuid = s_cpuid_output;
    return 1;
}

#endif
