/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/checksums/private/cpuid.h>
#include <stdint.h>

#if defined(__x86_64__) &&                                                                                             \
    (defined(__clang__) || !((defined(__GNUC__)) && ((__GNUC__ == 4 && __GNUC_MINOR__ < 4) || defined(DEBUG_BUILD))))

static int32_t s_cpuid_output = 0;
static int s_cpuid_ran = 0;

int aws_checksums_do_cpu_id(int32_t *cpuid) {

    if (!s_cpuid_ran) {

        asm volatile("XOR    %%rax, %%rax    # zero the eax register\n"
                     "INC    %%eax           # eax=1 for processor feature bits\n"
                     "CPUID                  #get feature bits\n"
                     : "=c"(s_cpuid_output)
                     : // none
                     : "%rax", "%rbx", "%rdx", "cc");
        s_cpuid_ran = 1;
    }

    *cpuid = s_cpuid_output;
    return 1;
}

#endif /* defined(__x86_64__) && (defined(__clang__) || !((defined(__GNUC__)) && ((__GNUC__ == 4 && __GNUC_MINOR__ <   \
          4) || defined(DEBUG_BUILD)))) */
