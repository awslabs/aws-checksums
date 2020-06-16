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

/* for the moment, fallback to SW on ARM until MSFT adds intrensics for ARM v8.1+ */
#if (defined(_M_ARM) || defined(__arm__) || defined(__ARM_ARCH_ISA_A64))

#    include <aws/checksums/private/cpuid.h>
#    if (defined(__linux__) || (defined(__FreeBSD__) && __has_include(<sys/auxv.h>)))
#        include <sys/auxv.h>
#    endif

static int32_t s_cpuid = 0;

int aws_checksums_do_cpu_id(int32_t *cpuid) {
#    ifdef __linux__
    *cpuid = getauxval(AT_HWCAP);
#    elif defined(__FreeBSD__) && __has_include(<sys/auxv.h>)
    unsigned long id;
    int ret = elf_aux_info(AT_HWCAP, &id, sizeof(unsigned long));
    if (!ret)
        *cpuid = id;
#    else
    (void)cpuid;
#    endif
    return 0;
}
static void do_check(void) {
    if (!s_cpuid) {
        aws_checksums_do_cpu_id(&s_cpuid);
    }
}

/** Returns non-zero if the CPU supports the PCLMULQDQ instruction. */
int aws_checksums_is_clmul_present(void) {
    return 0;
}

/** Returns non-zero if the CPU supports SSE4.1 instructions. */
int aws_checksums_is_sse41_present(void) {
    return 0;
}

/** Returns non-zero if the CPU supports SSE4.2 instructions (i.e. CRC32). */
int aws_checksums_is_sse42_present(void) {
    return 0;
}

/** Returns non-zero if the CPU support Arm CRC32/CRC32C instructions */
int aws_checksums_is_arm_crc_present(void) {
    const uint32_t hwcap_crc32 = (1 << 7);

    do_check();
    return s_cpuid & hwcap_crc32;
}

#endif
