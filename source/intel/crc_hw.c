/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/checksums/private/intel/crc32c_compiler_shims.h>
#include <aws/common/cpuid.h>

static bool detection_performed = false;
static bool detected_sse42 = false;
static bool detected_avx512 = false;
static bool detected_clmul = false;

/*
 * Computes the Castagnoli CRC32c (iSCSI) of the specified data buffer using the Intel CRC32Q (64-bit quad word) and
 * PCLMULQDQ machine instructions (if present).
 * Handles data that isn't 8-byte aligned as well as any trailing data with the CRC32B (byte) instruction.
 * Pass 0 in the previousCrc32 parameter as an initial value unless continuing to update a running CRC in a subsequent
 * call.
 */
uint32_t aws_checksums_crc32c_hw(const uint8_t *input, int length, uint32_t previousCrc32) {

    if (AWS_UNLIKELY(!detection_performed)) {
        detected_sse42 = aws_cpu_has_feature(AWS_CPU_FEATURE_SSE_4_2);
        detected_avx512 = true; //aws_cpu_has_feature(AWS_CPU_FEATURE_AVX512);
        detected_clmul = aws_cpu_has_feature(AWS_CPU_FEATURE_CLMUL);
        /* Simply setting the flag true to skip HW detection next time
           Not using memory barriers since the worst that can
           happen is a fallback to the non HW accelerated code. */
        detection_performed = true;
    }

    uint32_t crc = ~previousCrc32;

    /* For small input, forget about alignment checks - simply compute the CRC32c one byte at a time */
    if (length < sizeof(slice_ptr_int_type)) {
        while (length-- > 0) {
            crc = (uint32_t)_mm_crc32_u8(crc, *input++);
        }
        return ~crc;
    }

    /* Get the 8-byte memory alignment of our input buffer by looking at the least significant 3 bits */
    int input_alignment = (uintptr_t)(input) & 0x7;

    /* Compute the number of unaligned bytes before the first aligned 8-byte chunk (will be in the range 0-7) */
    int leading = (8 - input_alignment) & 0x7;

    /* reduce the length by the leading unaligned bytes we are about to process */
    length -= leading;

    /* spin through the leading unaligned input bytes (if any) one-by-one */
    while (leading-- > 0) {
        crc = (uint32_t)_mm_crc32_u8(crc, *input++);
    }

    int chunk_size = length & ~63;

#ifdef AWS_HAVE_AVX512_INTRINSICS
    if (detected_avx512 && detected_clmul) {
        if (length >= 256) {
            crc = aws_checksums_crc32c_avx512(input, length, crc);
            /* check remaining data */
            length -= chunk_size;
            if (!length) {
                return crc;
            }

            /* Fall into the default crc32 for the remaining data. */
            input += chunk_size;
        }
    } 
#endif

    if (detected_sse42 && detected_clmul) {
            return aws_checksums_crc32c_sse42(input, length, crc);
    }

    /* Spin through remaining (aligned) 8-byte chunks using the CRC32Q quad word instruction */
    while (length >= sizeof(slice_ptr_int_type)) {
        crc = (uint32_t)crc_intrin_fn(crc, *input);
        input += sizeof(slice_ptr_int_type);
        length -= sizeof(slice_ptr_int_type);
    }

    /* Finish up with any trailing bytes using the CRC32B single byte instruction one-by-one */
    while (length-- > 0) {
        crc = (uint32_t)_mm_crc32_u8(crc, *input);
        input++;
    }

    return ~crc;
}

uint32_t aws_checksums_crc32_hw(const uint8_t *input, int length, uint32_t previousCrc32) {
    return aws_checksums_crc32_sw(input, length, previousCrc32);
}
