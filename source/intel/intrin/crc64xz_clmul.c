/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/checksums/private/crc64_priv.h>

// msvc compilers older than 2019 are missing some intrinsics. Gate those off.
#if defined(AWS_HAVE_CLMUL) && INTPTR_MAX == INT64_MAX && \
    !(defined(_MSC_VER) && _MSC_VER < 1920)

#    include <emmintrin.h>
#    include <immintrin.h>
#    include <smmintrin.h>
#    include <wmmintrin.h>

#    define load_xmm(ptr) _mm_loadu_si128((const __m128i *)(const void *)(ptr))
#    define left_shift_bytes(xmm, count)                                                                               \
        _mm_shuffle_epi8((xmm), load_xmm(aws_checksums_masks_shifts[1] - (intptr_t)(count)))
#    define right_shift_bytes(xmm, count)                                                                              \
        _mm_shuffle_epi8((xmm), load_xmm(aws_checksums_masks_shifts[1] + (intptr_t)(count)))
#    define mask_high_bytes(xmm, count)                                                                                \
        _mm_and_si128((xmm), load_xmm(aws_checksums_masks_shifts[3] + (intptr_t)(count)))
#    define mask_low_bytes(xmm, count) _mm_and_si128((xmm), load_xmm(aws_checksums_masks_shifts[5] - (intptr_t)(count)))
#    define cmull_xmm_hi(xmm1, xmm2) _mm_clmulepi64_si128((xmm1), (xmm2), 0x11)
#    define cmull_xmm_lo(xmm1, xmm2) _mm_clmulepi64_si128((xmm1), (xmm2), 0x00)
#    define cmull_xmm_pair(xmm1, xmm2) _mm_xor_si128(cmull_xmm_hi((xmm1), (xmm2)), cmull_xmm_lo((xmm1), (xmm2)))

uint64_t aws_checksums_crc64xz_intel_clmul(const uint8_t *input, int length, const uint64_t previousCrc64) {
    if (!input || length <= 0) {
        return previousCrc64;
    }

    // Invert the previous crc bits and load into the lower half of an xmm register
    __m128i a1 = _mm_cvtsi64_si128((int64_t)(~previousCrc64));

    // For lengths less than 16 we need to carefully load from memory to prevent reading beyond the end of the input
    // buffer
    if (length < 16) {
        int alignment = (intptr_t)input & 15;
        if (alignment + length <= 16) {
            // The input falls in a single 16 byte segment so we load from a 16 byte aligned address
            // The input data will be loaded "into the middle" of the xmm register
            // Right shift the input data register to eliminate any leading bytes and move the data to the least
            // significant bytes Mask out the most significant bytes that may contain garbage XOR the masked input data
            // with the previous crc
            a1 = _mm_xor_si128(a1, mask_low_bytes(right_shift_bytes(load_xmm(input - alignment), alignment), length));
        } else {
            // The input spans two 16 byte segments so it's safe to load the input from its actual starting address
            // The input data will be in the least significant bytes of the xmm register
            // Mask out the most significant bytes that may contain garbage
            // XOR the masked input data with the previous crc
            a1 = _mm_xor_si128(a1, mask_low_bytes(load_xmm(input), length));
        }

        if (length <= 8) {
            // For 8 or less bytes of input we just left shift to effectively multiply by x^64
            a1 = left_shift_bytes(a1, 8 - length);
        } else {
            // For 8-15 bytes of input we need to fold the two halves of the crc register together
            a1 = left_shift_bytes(a1, 16 - length);
            const __m128i x128 = _mm_set_epi64x(0, aws_checksums_crc64xz_constants.x128[1]);
            // Multiply the lower half of the crc register by x^128
            __m128i mul_by_x128 = _mm_clmulepi64_si128(a1, x128, 0x00);
            // XOR the result with the upper half of the crc
            a1 = _mm_xor_si128(_mm_bsrli_si128(a1, 8), mul_by_x128);
        }
    } else {
        // There are 16 or more bytes of input - load the first 16 bytes and XOR with the previous crc
        a1 = _mm_xor_si128(a1, load_xmm(input));
        input += 16;
        length -= 16;

        // Load the folding constants x^128 and x^192
        const __m128i x128 = load_xmm(aws_checksums_crc64xz_constants.x128);

        if (length >= 48) {
            // Load the next 48 bytes
            __m128i b1 = load_xmm(input + 0x00);
            __m128i c1 = load_xmm(input + 0x10);
            __m128i d1 = load_xmm(input + 0x20);

            input += 48;
            length -= 48;

            // Load the folding constants x^512 and x^576
            const __m128i x512 = load_xmm(aws_checksums_crc64xz_constants.x512);

            if (length >= 64) {
                // Load the next 64 bytes
                __m128i e1 = load_xmm(input + 0x00);
                __m128i f1 = load_xmm(input + 0x10);
                __m128i g1 = load_xmm(input + 0x20);
                __m128i h1 = load_xmm(input + 0x30);
                input += 64;
                length -= 64;

                // Load the folding constants x^1024 and x^1088
                const __m128i x1024 = load_xmm(aws_checksums_crc64xz_constants.x1024);

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
            const __m128i x384 = load_xmm(aws_checksums_crc64xz_constants.x384);
            const __m128i x256 = load_xmm(aws_checksums_crc64xz_constants.x256);

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
        if (length == 0) {
            // Multiply the lower half of the crc register by x^128 (it's in the upper half)
            __m128i mul_by_x128 = _mm_clmulepi64_si128(a1, x128, 0x10);
            // XOR the result with the upper half of the crc
            a1 = _mm_xor_si128(_mm_bsrli_si128(a1, 8), mul_by_x128);
        } else { // Handle any trailing input from 1-15 bytes
            // Multiply the crc by a pair of trailing length constants in order to fold it into the trailing input
            a1 = cmull_xmm_pair(a1, load_xmm(aws_checksums_crc64xz_constants.trailing[length - 1]));
            // Safely load (ending at the trailing input) and mask out any leading garbage
            __m128i trailing_input = mask_high_bytes(load_xmm(input + length - 16), length);
            // Multiply the lower half of the trailing input register by x^128 (it's in the upper half)
            __m128i mul_by_x128 = _mm_clmulepi64_si128(trailing_input, x128, 0x10);
            // XOR the results with the upper half of the trailing input
            a1 = _mm_xor_si128(a1, _mm_bsrli_si128(trailing_input, 8));
            a1 = _mm_xor_si128(a1, mul_by_x128);
        }
    }

    // Barrett modular reduction
    const __m128i mu_poly = load_xmm(aws_checksums_crc64xz_constants.mu_poly);
    // Multiply the lower half of input by mu
    __m128i mul_by_mu = _mm_clmulepi64_si128(mu_poly, a1, 0x00);
    // Multiply the lower half of the mul_by_mu result by poly (it's in the upper half)
    __m128i mul_by_poly = _mm_clmulepi64_si128(mu_poly, mul_by_mu, 0x01);
    // Left shift mul_by_mu to get the low half into the upper half and XOR all the upper halves
    __m128i reduced = _mm_xor_si128(_mm_xor_si128(a1, _mm_bslli_si128(mul_by_mu, 8)), mul_by_poly);
    // After the XORs, the CRC falls in the upper half of the register - invert the bits before returning the crc
    return ~(uint64_t)_mm_extract_epi64(reduced, 1);
}

#endif /* defined(AWS_HAVE_CLMUL) && INTPTR_MAX == INT64_MAX */
