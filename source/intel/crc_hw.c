/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/checksums/private/intel/crc32c_compiler_shims.h>
#include <aws/common/macros.h>

static uint32_t aws_checksums_crc32c_hw_small(const uint8_t *input, int length, uint32_t crc) {
        while (length-- > 0) {
            crc = (uint32_t)_mm_crc32_u8(crc, *input++);
        }
        return ~crc;
}

static uint32_t aws_checksums_crc32c_hw_unaligned(const uint8_t **input, int *length, uint32_t crc) {
    /* Get the 8-byte memory alignment of our input buffer by looking at the least significant 3 bits */
    int input_alignment = (uintptr_t)(*input)&0x7;

    /* Compute the number of unaligned bytes before the first aligned 8-byte chunk (will be in the range 0-7) */
    int leading = (8 - input_alignment) & 0x7;

    /* reduce the length by the leading unaligned bytes we are about to process */
    *length -= leading;

    /* spin through the leading unaligned input bytes (if any) one-by-one */
    while (leading-- > 0) {
        crc = (uint32_t)_mm_crc32_u8(crc, *(*input)++);
    }

    return crc;
}

/*
 * Computes the Castagnoli CRC32c (iSCSI) of the specified data buffer using the Intel CRC32Q (64-bit quad word) instructions.
 * Handles data that isn't 8-byte aligned as well as any trailing data with the CRC32B (byte) instruction.
 * Pass 0 in the previousCrc32 parameter as an initial value unless continuing to update a running CRC in a subsequent
 * call.
 */
uint32_t aws_checksums_crc32c_hw(const uint8_t *input, int length, uint32_t previousCrc32) {

    /* this is the entry point. We should only do the bit flip once. It should not be done for the subfunctions and
     * branches.*/
    uint32_t crc = ~previousCrc32;

    /* For small input, forget about alignment checks - simply compute the CRC32c one byte at a time */
    if (length < (int)sizeof(slice_ptr_int_type)) {
        return aws_checksums_crc32c_hw_small(input, length, crc);
    }

    crc = aws_checksums_crc32c_hw_unaligned(&input, &length, crc);
    /* Spin through remaining (aligned) 8-byte chunks using the CRC32Q quad word instruction */
    while (length >= (int)sizeof(slice_ptr_int_type)) {
        crc = (uint32_t)crc_intrin_fn(crc, *(const slice_ptr_int_type*) input);
        input += sizeof(slice_ptr_int_type);
        length -= (int)sizeof(slice_ptr_int_type);
    }

    /* Finish up with any trailing bytes using the CRC32B single byte instruction one-by-one */
    while (length-- > 0) {
        crc = (uint32_t)_mm_crc32_u8(crc, *input);
        input++;
    }

    return ~crc;
}

/*
 * Computes the Castagnoli CRC32c (iSCSI) of the specified data buffer using the Intel CRC32Q (64-bit quad word) and
 * PCLMULQDQ machine instructions (if present).
 * Handles data that isn't 8-byte aligned as well as any trailing data with the CRC32B (byte) instruction.
 * Pass 0 in the previousCrc32 parameter as an initial value unless continuing to update a running CRC in a subsequent
 * call.
 */
uint32_t aws_checksums_crc32c_clmul(const uint8_t *input, int length, uint32_t previousCrc32) {

    /* this is the entry point. We should only do the bit flip once. It should not be done for the subfunctions and
     * branches.*/
    uint32_t crc = ~previousCrc32;

    /* For small input, forget about alignment checks - simply compute the CRC32c one byte at a time */
    if (length < (int)sizeof(slice_ptr_int_type)) {
        return aws_checksums_crc32c_hw_small(input, length, crc);
    }

    crc = aws_checksums_crc32c_hw_unaligned(&input, &length, crc);

    return aws_checksums_crc32c_sse42(input, length, crc);
}

uint32_t aws_checksums_crc32_hw(const uint8_t *input, int length, uint32_t previousCrc32) {
    return aws_checksums_crc32_sw(input, length, previousCrc32);
}
