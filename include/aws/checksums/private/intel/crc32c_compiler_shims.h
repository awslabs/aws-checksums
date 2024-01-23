/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/checksums/private/crc_priv.h>

#include <aws/common/config.h>
#include <nmmintrin.h>

#if INTPTR_MAX == INT64_MAX
typedef uint64_t *slice_ptr_type;
typedef uint64_t slice_ptr_int_type;
#    define crc_intrin_fn _mm_crc32_u64
#else
typedef uint32_t *slice_ptr_type;
typedef uint32_t slice_ptr_int_type;
#    define crc_intrin_fn _mm_crc32_u32
#endif

#if defined(AWS_HAVE_AVX512_INTRINSICS) && (INTPTR_MAX == INT64_MAX)
uint32_t aws_checksums_crc32c_avx512(const uint8_t *input, int length, uint32_t crc);
#endif

uint32_t aws_checksums_crc32c_sse42(const uint8_t *input, int length, uint32_t crc);
