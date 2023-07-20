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

AWS_ALIGNED_TYPEDEF(const uint64_t, zalign_8, 64);
AWS_ALIGNED_TYPEDEF(const uint64_t, zalign_2, 16);

/*
 * crc32c_avx512(): compute the crc32c of the buffer, where the buffer
 * length must be at least 256, and a multiple of 64. Based on:
 *
 * "Fast CRC Computation for Generic Polynomials Using PCLMULQDQ Instruction"
 *  V. Gopal, E. Ozturk, et al., 2009, http://intel.ly/2ySEwL0
 */
uint32_t aws_checksums_crc32c_avx512(const uint8_t *input, int length, uint32_t previous_crc) {
    AWS_ASSERT(
        length >= 256 && "invariant violated. length must be greater than 256 bytes to use avx512 to compute crc.");

    fprintf(stderr, "Entered AVX512 branch.");
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

    static zalign_8 k1k2[8] = 
        {0xdcb17aa4, 0xb9e02b86, 0xdcb17aa4, 0xb9e02b86, 0xdcb17aa4, 0xb9e02b86, 0xdcb17aa4, 0xb9e02b86};

    static zalign_8 k3k4[8] =
        {0x740eef02, 0x9e4addf8, 0x740eef02, 0x9e4addf8, 0x740eef02, 0x9e4addf8, 0x740eef02, 0x9e4addf8};
    static zalign_2 k5k6[2] = {0xf20c0dfe, 0x14cd00bd6};
    static zalign_2 k7k8[2] = {0xdd45aab8, 0x000000000};
    static zalign_2 poly[2] = {0x105ec76f1, 0xdea713f1};

    __m512i x0, x1, x2, x3, x4, x5, x6, x7, x8, y5, y6, y7, y8;
    __m128i a0, a1, a2, a3;

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

        x1 = _mm512_xor_si512(x1, x5);
        x2 = _mm512_xor_si512(x2, x6);
        x3 = _mm512_xor_si512(x3, x7);
        x4 = _mm512_xor_si512(x4, x8);

        x1 = _mm512_xor_si512(x1, y5);
        x2 = _mm512_xor_si512(x2, y6);
        x3 = _mm512_xor_si512(x3, y7);
        x4 = _mm512_xor_si512(x4, y8);

        input += 256;
        length -= 256;
    }

    /*
     * Fold into 512-bits.
     */
    x0 = _mm512_load_si512((__m512i *)k3k4);

    x5 = _mm512_clmulepi64_epi128(x1, x0, 0x00);
    x1 = _mm512_clmulepi64_epi128(x1, x0, 0x11);
    x1 = _mm512_xor_si512(x1, x2);
    x1 = _mm512_xor_si512(x1, x5);

    x5 = _mm512_clmulepi64_epi128(x1, x0, 0x00);
    x1 = _mm512_clmulepi64_epi128(x1, x0, 0x11);
    x1 = _mm512_xor_si512(x1, x3);
    x1 = _mm512_xor_si512(x1, x5);

    x5 = _mm512_clmulepi64_epi128(x1, x0, 0x00);
    x1 = _mm512_clmulepi64_epi128(x1, x0, 0x11);
    x1 = _mm512_xor_si512(x1, x4);
    x1 = _mm512_xor_si512(x1, x5);

    /*
     * Single fold blocks of 64, if any.
     */
    while (length >= 64) {
        x2 = _mm512_loadu_si512((__m512i *)input);

        x5 = _mm512_clmulepi64_epi128(x1, x0, 0x00);
        x1 = _mm512_clmulepi64_epi128(x1, x0, 0x11);
        x1 = _mm512_xor_si512(x1, x2);
        x1 = _mm512_xor_si512(x1, x5);

        input += 64;
        length -= 64;
    }

    /*
     * Fold 512-bits to 384-bits.
     */
    a0 = _mm_load_si128((__m128i *)k5k6);

    a1 = _mm512_extracti32x4_epi32(x1, 0);
    a2 = _mm512_extracti32x4_epi32(x1, 1);

    a3 = _mm_clmulepi64_si128(a1, a0, 0x00);
    a1 = _mm_clmulepi64_si128(a1, a0, 0x11);

    a1 = _mm_xor_si128(a1, a3);
    a1 = _mm_xor_si128(a1, a2);

    /*
     * Fold 384-bits to 256-bits.
     */
    a2 = _mm512_extracti32x4_epi32(x1, 2);
    a3 = _mm_clmulepi64_si128(a1, a0, 0x00);
    a1 = _mm_clmulepi64_si128(a1, a0, 0x11);
    a1 = _mm_xor_si128(a1, a3);
    a1 = _mm_xor_si128(a1, a2);

    /*
     * Fold 256-bits to 128-bits.
     */
    a2 = _mm512_extracti32x4_epi32(x1, 3);
    a3 = _mm_clmulepi64_si128(a1, a0, 0x00);
    a1 = _mm_clmulepi64_si128(a1, a0, 0x11);
    a1 = _mm_xor_si128(a1, a3);
    a1 = _mm_xor_si128(a1, a2);

    /*
     * Fold 128-bits to 64-bits.
     */
    a2 = _mm_clmulepi64_si128(a1, a0, 0x10);
    a3 = _mm_setr_epi32(~0, 0, ~0, 0);
    a1 = _mm_srli_si128(a1, 8);
    a1 = _mm_xor_si128(a1, a2);

    a0 = _mm_loadl_epi64((__m128i *)k7k8);
    a2 = _mm_srli_si128(a1, 4);
    a1 = _mm_and_si128(a1, a3);
    a1 = _mm_clmulepi64_si128(a1, a0, 0x00);
    a1 = _mm_xor_si128(a1, a2);

    /*
     * Barret reduce to 32-bits.
     */
    a0 = _mm_load_si128((__m128i *)poly);

    a2 = _mm_and_si128(a1, a3);
    a2 = _mm_clmulepi64_si128(a2, a0, 0x10);
    a2 = _mm_and_si128(a2, a3);
    a2 = _mm_clmulepi64_si128(a2, a0, 0x00);
    a1 = _mm_xor_si128(a1, a2);

    /*
     * Return the crc32.
     */
    return ~_mm_extract_epi32(a1, 1);
}
