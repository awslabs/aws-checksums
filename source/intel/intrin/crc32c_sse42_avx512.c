/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/checksums/private/intel/crc32c_compiler_shims.h>

#include <aws/common/assert.h>
#include <aws/common/macros.h>

#include <emmintrin.h>
#include <immintrin.h>
#include <smmintrin.h>
#include <wmmintrin.h>

#if defined(AWS_HAVE_AVX512_INTRINSICS) && (INTPTR_MAX == INT64_MAX)

AWS_ALIGNED_TYPEDEF(const uint64_t, zalign_8, 64);
AWS_ALIGNED_TYPEDEF(const uint64_t, zalign_2, 16);

/*
 * crc32c_avx512(): compute the crc32c of the buffer, where the buffer
 * length must be at least 256, and a multiple of 64. Based on:
 *
 * "Fast CRC Computation for Generic Polynomials Using PCLMULQDQ Instruction"
 *  V. Gopal, E. Ozturk, et al., 2009, http://download.intel.com/design/intarch/papers/323102.pdf
 */
uint32_t aws_checksums_crc32c_avx512(const uint8_t *input, int length, uint32_t previous_crc) {
    AWS_ASSERT(
        length >= 256 && "invariant violated. length must be greater than 255 bytes to use avx512 to compute crc.");

    uint32_t crc = ~previous_crc;
    /*
     * Definitions of the bit-reflected domain constants k1,k2,k3,k4,k5,k6
     * are similar to those given at the end of the paper
     *
     * k1 = ( x ^ ( 512 * 4 + 32 ) mod P(x) << 32 )' << 1
     * k2 = ( x ^ ( 512 * 4 - 32 ) mod P(x) << 32 )' << 1
     * k3 = ( x ^ ( 512 + 32 ) mod P(x) << 32 )' << 1
     * k4 = ( x ^ ( 512 - 32 ) mod P(x) << 32 )' << 1
     * k5 = ( x ^ ( 128 + 32 ) mod P(x) << 32 )' << 1
     * k6 = ( x ^ ( 128 - 32 ) mod P(x) << 32 )' << 1
     */

    static zalign_8 k1k2[8] = {
        0xdcb17aa4, 0xb9e02b86, 0xdcb17aa4, 0xb9e02b86, 0xdcb17aa4, 0xb9e02b86, 0xdcb17aa4, 0xb9e02b86};

    static zalign_8 k3k4[8] = {
        0x740eef02, 0x9e4addf8, 0x740eef02, 0x9e4addf8, 0x740eef02, 0x9e4addf8, 0x740eef02, 0x9e4addf8};
    static zalign_8 k9k10[8] = {
        0x6992cea2, 0x0d3b6092, 0x6992cea2, 0x0d3b6092, 0x6992cea2, 0x0d3b6092, 0x6992cea2, 0x0d3b6092};
    static zalign_8 k1k4[8] = {
        0x1c291d04, 0xddc0152b, 0x3da6d0cb, 0xba4fc28e, 0xf20c0dfe, 0x493c7d27, 0x00000000, 0x00000000};

    __m512i x0, x1, x2, x3, x4, x5, x6, x7, x8, y5, y6, y7, y8;
    __m128i a1, a2;

    /*
     * There's at least one block of 256.
     */
    x1 = _mm512_loadu_si512((__m512i *)(input + 0x00));
    x2 = _mm512_loadu_si512((__m512i *)(input + 0x40));
    x3 = _mm512_loadu_si512((__m512i *)(input + 0x80));
    x4 = _mm512_loadu_si512((__m512i *)(input + 0xC0));

    x1 = _mm512_xor_si512(x1, _mm512_castsi128_si512(_mm_cvtsi32_si128(crc)));

    x0 = _mm512_load_si512((__m512i *)k1k2);

    input += 256;
    length -= 256;

    /*
     * Parallel fold blocks of 256, if any.
     */
    while (length >= 256) {
        x5 = _mm512_clmulepi64_epi128(x1, x0, 0x00);
        x6 = _mm512_clmulepi64_epi128(x2, x0, 0x00);
        x7 = _mm512_clmulepi64_epi128(x3, x0, 0x00);
        x8 = _mm512_clmulepi64_epi128(x4, x0, 0x00);

        x1 = _mm512_clmulepi64_epi128(x1, x0, 0x11);
        x2 = _mm512_clmulepi64_epi128(x2, x0, 0x11);
        x3 = _mm512_clmulepi64_epi128(x3, x0, 0x11);
        x4 = _mm512_clmulepi64_epi128(x4, x0, 0x11);

        y5 = _mm512_loadu_si512((__m512i *)(input + 0x00));
        y6 = _mm512_loadu_si512((__m512i *)(input + 0x40));
        y7 = _mm512_loadu_si512((__m512i *)(input + 0x80));
        y8 = _mm512_loadu_si512((__m512i *)(input + 0xC0));

        x1 = _mm512_ternarylogic_epi64(x1, x5, y5, 0x96);
        x2 = _mm512_ternarylogic_epi64(x2, x6, y6, 0x96);
        x3 = _mm512_ternarylogic_epi64(x3, x7, y7, 0x96);
        x4 = _mm512_ternarylogic_epi64(x4, x8, y8, 0x96);

        input += 256;
        length -= 256;
    }

    /*
     * Fold 256 bytes into 64 bytes.
     */
    x0 = _mm512_load_si512((__m512i *)k9k10);
    x5 = _mm512_clmulepi64_epi128(x1, x0, 0x00);
    x6 = _mm512_clmulepi64_epi128(x1, x0, 0x11);
    x3 = _mm512_ternarylogic_epi64(x3, x5, x6, 0x96);

    x7 = _mm512_clmulepi64_epi128(x2, x0, 0x00);
    x8 = _mm512_clmulepi64_epi128(x2, x0, 0x11);
    x4 = _mm512_ternarylogic_epi64(x4, x7, x8, 0x96);

    x0 = _mm512_load_si512((__m512i *)k3k4);
    y5 = _mm512_clmulepi64_epi128(x3, x0, 0x00);
    y6 = _mm512_clmulepi64_epi128(x3, x0, 0x11);
    x1 = _mm512_ternarylogic_epi64(x4, y5, y6, 0x96);

    /*
     * Single fold blocks of 64, if any.
     */
    while (length >= 64) {
        x2 = _mm512_loadu_si512((__m512i *)input);

        x5 = _mm512_clmulepi64_epi128(x1, x0, 0x00);
        x1 = _mm512_clmulepi64_epi128(x1, x0, 0x11);
        x1 = _mm512_ternarylogic_epi64(x1, x2, x5, 0x96);

        input += 64;
        length -= 64;
    }

    /*
     * Fold 512-bits to 128-bits.
     */
    x0 = _mm512_loadu_si512((__m512i *)k1k4);

    a2 = _mm512_extracti32x4_epi32(x1, 3);
    x5 = _mm512_clmulepi64_epi128(x1, x0, 0x00);
    x1 = _mm512_clmulepi64_epi128(x1, x0, 0x11);
    x1 = _mm512_ternarylogic_epi64(x1, x5, _mm512_castsi128_si512(a2), 0x96);

    x0 = _mm512_shuffle_i64x2(x1, x1, 0x4E);
    x0 = _mm512_xor_epi64(x1, x0);
    a1 = _mm512_extracti32x4_epi32(x0, 1);
    a1 = _mm_xor_epi64(a1, _mm512_castsi512_si128(x0));

    /*
     * Fold 128-bits to 32-bits.
     */
    uint64_t val;
    val = _mm_crc32_u64(0, _mm_extract_epi64(a1, 0));
    return (uint32_t)_mm_crc32_u64(val, _mm_extract_epi64(a1, 1));
}

#endif /* #if defined(AWS_HAVE_AVX512_INTRINSICS) && (INTPTR_MAX == INT64_MAX) */