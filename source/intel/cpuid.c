/*
 * Copyright 2010-2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
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

static int32_t s_cpuid = 0;

static void do_check(void) {
    if (!s_cpuid) {
        aws_checksums_do_cpu_id(&s_cpuid);
    }
}

/** Returns non-zero if the CPU supports the PCLMULQDQ instruction. */
int aws_checksums_is_clmul_present(void) {
    do_check();
    return s_cpuid & 0x00000002;
}

/** Returns non-zero if the CPU supports SSE4.1 instructions. */
int aws_checksums_is_sse41_present(void) {
    do_check();
    return s_cpuid & 0x00080000;
}

/** Returns non-zero if the CPU supports SSE4.2 instructions (i.e. CRC32). */
int aws_checksums_is_sse42_present(void) {
    do_check();
    return s_cpuid & 0x00100000;
}

/** Returns non-zero if the CPU support Arm CRC32/CRC32C instructions */
int aws_checksums_is_arm_crc_present(void) {
    return 0;
}

#endif /* defined(__x86_64__) && (defined(__clang__) || !((defined(__GNUC__)) && ((__GNUC__ == 4 && __GNUC_MINOR__ <   \
          4) || defined(DEBUG_BUILD)))) */
