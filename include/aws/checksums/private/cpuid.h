#ifndef AWS_CHECKSUMS_PRIVATE_CPUID_H
#define AWS_CHECKSUMS_PRIVATE_CPUID_H
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <stdint.h>

/***
 * runs cpu id and fills in capabilities for the current cpu architecture.
 * returns non zero on success, zero on failure. If the operation was successful
 * cpuid will be set with the bits from the cpuid call, otherwise they will be untouched.
 **/
int aws_checksums_do_cpu_id(int32_t *cpuid);

/** Returns non-zero if the CPU supports the PCLMULQDQ instruction. */
int aws_checksums_is_clmul_present(void);

/** Returns non-zero if the CPU supports SSE4.1 instructions. */
int aws_checksums_is_sse41_present(void);

/** Returns non-zero if the CPU supports SSE4.2 instructions (i.e. CRC32). */
int aws_checksums_is_sse42_present(void);

#endif /* AWS_CHECKSUMS_PRIVATE_CPUID_H */
