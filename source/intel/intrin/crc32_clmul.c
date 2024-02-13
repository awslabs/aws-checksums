/**
* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
* SPDX-License-Identifier: Apache-2.0.
*/

#include <aws/checksums/private/crc_priv.h>
#include <aws/common/assert.h>

// msvc compilers older than 2019 are missing some intrinsics. Gate those off.
#if defined(AWS_ARCH_INTEL_X64) && defined(AWS_HAVE_CLMUL) && !(defined(_MSC_VER) && _MSC_VER < 1920)

#    include <emmintrin.h>
#    include <immintrin.h>
#    include <smmintrin.h>
#    include <wmmintrin.h>

#    define load_xmm(ptr) _mm_loadu_si128((const __m128i *)(const void *)(ptr))
#    define mask_high_bytes(xmm, count)                                                                                \
       _mm_and_si128((xmm), load_xmm(aws_checksums_masks_shifts[3] + (intptr_t)(count)))
#    define cmull_xmm_hi(xmm1, xmm2) _mm_clmulepi64_si128((xmm1), (xmm2), 0x11)
#    define cmull_xmm_lo(xmm1, xmm2) _mm_clmulepi64_si128((xmm1), (xmm2), 0x00)
#    define cmull_xmm_pair(xmm1, xmm2) _mm_xor_si128(cmull_xmm_hi((xmm1), (xmm2)), cmull_xmm_lo((xmm1), (xmm2)))

uint32_t aws_checksums_crc32_intel_clmul(const uint8_t *input, int length, uint32_t previous_crc) {

    // the amount of complexity required to handle vector instructions on
    // memory regions smaller than an xmm register does not justify the very negligible performance gains
    // we would get for using it on an input this small.
    if (length < 16) {
        return aws_checksums_crc32_sw(input, length, previous_crc);
    }

    // Invert the previous crc bits and load into the lower half of an xmm register
    __m128i a1 = _mm_cvtsi32_si128((int32_t)(~previous_crc));

    // There are 16 or more bytes of input - load the first 16 bytes and XOR with the previous crc
    a1 = _mm_xor_si128(a1, load_xmm(input));
    input += 16;
    length -= 16;

    // Load the folding constants x^128 and x^192
    const __m128i x128 = load_xmm(aws_checksums_crc32_constants.x128);

    if (length >= 48) {
        // Load the next 48 bytes
        __m128i b1 = load_xmm(input + 0x00);
        __m128i c1 = load_xmm(input + 0x10);
        __m128i d1 = load_xmm(input + 0x20);

        input += 48;
        length -= 48;

        // Load the folding constants x^512 and x^576
        const __m128i x512 = load_xmm(aws_checksums_crc32_constants.x512);

        if (length >= 64) {
            // Load the next 64 bytes
            __m128i e1 = load_xmm(input + 0x00);
            __m128i f1 = load_xmm(input + 0x10);
            __m128i g1 = load_xmm(input + 0x20);
            __m128i h1 = load_xmm(input + 0x30);
            input += 64;
            length -= 64;

            // Load the folding constants x^1024 and x^1088
            const __m128i x1024 = load_xmm(aws_checksums_crc32_constants.x1024);

            // Spin through 128 bytes and fold in parallel
            int loops = length / 128;
            length &= 127;
            while (loops--) {
                a1 = _mm_xor_si128(cmull_xmm_pair(x1024, a1), load_xmm(input + 0x00));
                b1 = _mm_xor_si128(cmull_xmm_pair(x1024, b1), load_xmm(input + 0x10));
                c1 = _mm_xor_si128(cmull_xmm_pair(x1024, c1), load_xmm(input + 0x20));
                d1 = _mm_xor_si128(cmull_xmm_pair(x1024, d1), load_xmm(input + 0x30));
                e1 = _mm_xor_si128(cmull_xmm_pair(x1024, e1), load_xmm(input + 0x40));
                f1 = _mm_xor_si128(cmull_xmm_pair(x1024, f1), load_xmm(input + 0x50));
                g1 = _mm_xor_si128(cmull_xmm_pair(x1024, g1), load_xmm(input + 0x60));
                h1 = _mm_xor_si128(cmull_xmm_pair(x1024, h1), load_xmm(input + 0x70));
                input += 128;
            }

            // Fold 128 to 64 bytes - e1 through h1 fold into a1 through d1
            a1 = _mm_xor_si128(cmull_xmm_pair(x512, a1), e1);
            b1 = _mm_xor_si128(cmull_xmm_pair(x512, b1), f1);
            c1 = _mm_xor_si128(cmull_xmm_pair(x512, c1), g1);
            d1 = _mm_xor_si128(cmull_xmm_pair(x512, d1), h1);
        }

        if (length & 64) {
            a1 = _mm_xor_si128(cmull_xmm_pair(x512, a1), load_xmm(input + 0x00));
            b1 = _mm_xor_si128(cmull_xmm_pair(x512, b1), load_xmm(input + 0x10));
            c1 = _mm_xor_si128(cmull_xmm_pair(x512, c1), load_xmm(input + 0x20));
            d1 = _mm_xor_si128(cmull_xmm_pair(x512, d1), load_xmm(input + 0x30));
            input += 64;
        }
        length &= 63;

        // Load the x^256, x^320, x^384, and x^448 constants
        const __m128i x384 = load_xmm(aws_checksums_crc32_constants.x384);
        const __m128i x256 = load_xmm(aws_checksums_crc32_constants.x256);

        // Fold 64 bytes to 16 bytes
        a1 = _mm_xor_si128(d1, cmull_xmm_pair(x384, a1));
        a1 = _mm_xor_si128(a1, cmull_xmm_pair(x256, b1));
        a1 = _mm_xor_si128(a1, cmull_xmm_pair(x128, c1));
    }

    // Process any remaining chunks of 16 bytes
    int loops = length / 16;
    while (loops--) {
        a1 = _mm_xor_si128(cmull_xmm_pair(a1, x128), load_xmm(input));
        input += 16;
    }

    // The remaining length can be only 0-15 bytes
    length &= 15;
    if (length) {
        // Multiply the crc register by a pair of trailing length constants in order to fold it into the trailing input
        a1 = cmull_xmm_pair(a1, load_xmm(aws_checksums_crc32_constants.trailing[length - 1]));
        // Safely load trailing input by ending at the last byte and mask out any leading garbage
        a1 = _mm_xor_si128(a1, mask_high_bytes(load_xmm(input + length - 16), length));
    }

    // Fold 16 bytes to 8 bytes while also multiplying all input by x^32 (i.e. the definition of crc32)
    const __m128i x64 = load_xmm(aws_checksums_crc32_constants.x64);
    // Split a1 into two registers containing the even and odd 32-bit dqwords[0-3]
    __m128i dqwords_0_2 = _mm_slli_epi64(a1, 32);
    __m128i dqwords_1_3 = _mm_srli_epi64(a1, 32);
    // Multiply each dqword by x^32 plus its offset from the end of input
    __m128i dqword_0 = cmull_xmm_lo(dqwords_0_2, _mm_bsrli_si128(x128, 12)); // dqword[0] * x^128
    __m128i dqword_1 = cmull_xmm_lo(dqwords_1_3, x64);                       // dqword[1] * x^96
    __m128i dqword_2 = cmull_xmm_hi(dqwords_0_2, x64);                       // dqword[2] * x^64
    a1 = _mm_bsrli_si128(dqwords_1_3, 4);                                    // dqword[3] * x^32 (via bit shift)

    // Combine products. They align such that we will have 64 bits in the "middle" of the xmm register
    a1 = _mm_xor_si128(_mm_xor_si128(a1, dqword_0), _mm_xor_si128(dqword_1, dqword_2));

    // Barrett modular reduction
    const __m128i mu_poly = load_xmm(aws_checksums_crc32_constants.mu_poly);
    // Multiply the lower 32 bits by mu
    __m128i mul_by_mu = cmull_xmm_lo(mu_poly, a1);
    // Multiply the lower half of the mul_by_mu result by poly (poly is in the upper half)
    __m128i mul_by_poly = _mm_clmulepi64_si128(mu_poly, mul_by_mu, 0x01);
    // Combine with the upper bits of the original value
    __m128i reduced = _mm_xor_si128(a1, mul_by_poly);
    // After the XORs, the CRC falls in the upper half the register - invert the bits before returning the crc
    return ~(uint32_t)_mm_extract_epi32(reduced, 2);
}

#endif
