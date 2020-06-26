/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

/* for the moment, fallback to SW on ARM until MSFT adds intrensics for ARM v8.1+ */
#if (defined(_M_ARM) || defined(__arm__) || defined(__ARM_ARCH_ISA_A64))

#    include <aws/checksums/private/cpuid.h>

int aws_checksums_do_cpu_id(int32_t *cpuid) {
    (void)cpuid;
    return 0;
}

#endif
