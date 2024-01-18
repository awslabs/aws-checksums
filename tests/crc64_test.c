/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/checksums/crc.h>
#include <aws/checksums/private/crc64_priv.h>
#include <aws/testing/aws_test_harness.h>

// The polynomial used for CRC64XZ (in bit-reflected form)
static const uint64_t POLY_CRC64XZ = 0xc96c5795d7870f42;

// Any input with the CRC of that input appended should produce this CRC value. (Note: inverting the bits)
static const uint64_t RESIDUE_CRC64XZ = (uint64_t)~0x49958c9abd7d353f;

static const uint8_t DATA_32_ZEROS[32] = {0};
static const uint64_t KNOWN_CRC64XZ_32_ZEROES = 0xC95AF8617CD5330C;

static const uint8_t DATA_32_VALUES[32] = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
                                           16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
static const uint64_t KNOWN_CRC64XZ_32_VALUES = 0x7FE571A587084D10;

static const uint8_t TEST_VECTOR[] = {'1', '2', '3', '4', '5', '6', '7', '8', '9'};
static const uint64_t KNOWN_CRC64XZ_TEST_VECTOR = 0x995DC9BBDF1939FA;

static uint8_t *s_non_mem_aligned_vector;

typedef uint64_t(crc_fn)(const uint8_t *input, int length, uint64_t previousCrc64);
#define CRC_FUNC_NAME(crc_func) #crc_func, crc_func
#define DATA_NAME(dataset) #dataset, dataset, sizeof(dataset)

// Very, very slow reference implementation that computes CRC64XZ.
static uint64_t crc64xz_reference(const uint8_t *input, int length, const uint64_t previousCrc64) {
    uint64_t crc = ~previousCrc64;
    while (length-- > 0) {
        crc ^= *input++;
        for (int j = 8; j > 0; --j) {
            crc = (crc >> 1) ^ ((((crc & 1) ^ 1) - 1) & POLY_CRC64XZ);
        }
    }
    return ~crc;
}

/* Makes sure that the specified crc function produces the expected results for known input and output */
static int s_test_known_crc(
    const char *func_name,
    crc_fn *func,
    const char *data_name,
    const uint8_t *input,
    size_t length,
    uint64_t expected) {

    uint64_t result = func(input, (int)length, 0);
    ASSERT_HEX_EQUALS(expected, result, "%s(%s)", func_name, data_name);

    /* chain the crc computation so 2 calls each operate on about 1/2 of the buffer*/
    uint64_t crc1 = func(input, (int)(length / 2), 0);
    result = func(input + (length / 2), (int)(length - length / 2), crc1);
    ASSERT_HEX_EQUALS(expected, result, "chaining %s(%s)", func_name, data_name);

    crc1 = 0;
    for (size_t i = 0; i < length; ++i) {
        crc1 = func(input + i, 1, crc1);
    }

    ASSERT_HEX_EQUALS(expected, crc1, "one byte at a time %s(%s)", func_name, data_name);

    return AWS_OP_SUCCESS;
}

/* Makes sure that the specified crc function produces the expected residue value */
static int s_test_crc_residue(
    const char *func_name,
    crc_fn *func,
    const char *data_name,
    const uint8_t *input,
    size_t length,
    uint64_t expected) {

    for (int len = 0; len < length; ++len) {
        uint64_t crc = func(input, len, 0);
        uint64_t residue = func((const uint8_t *)&crc, 8, crc); // assuming little endian
        ASSERT_HEX_EQUALS(expected, residue, "len %d residue %s(%s)", len, func_name, data_name);
    }

    return AWS_OP_SUCCESS;
}

/* helper function that groups crc64xz tests */
static int s_test_known_crc64xz(const char *func_name, crc_fn *func) {
    int res = 0;

    res |= s_test_known_crc(func_name, func, DATA_NAME(DATA_32_ZEROS), KNOWN_CRC64XZ_32_ZEROES);
    res |= s_test_known_crc(func_name, func, DATA_NAME(DATA_32_VALUES), KNOWN_CRC64XZ_32_VALUES);
    res |= s_test_known_crc(func_name, func, DATA_NAME(TEST_VECTOR), KNOWN_CRC64XZ_TEST_VECTOR);
    res |= s_test_crc_residue(func_name, func, "32_values", DATA_32_VALUES, sizeof(DATA_32_VALUES), RESIDUE_CRC64XZ);

    /* this tests three things, first it tests the case where we aren't 8-byte aligned */
    /* second, it tests that reads aren't performed before start of buffer */
    /* third, it tests that writes aren't performed after the end of the buffer. */
    /* if any of those things happen, then the checksum will be wrong and the assertion will fail */
    s_non_mem_aligned_vector = malloc(sizeof(DATA_32_VALUES) + 6);
    memset(s_non_mem_aligned_vector, 1, sizeof(DATA_32_VALUES) + 6);
    memcpy(s_non_mem_aligned_vector + 3, DATA_32_VALUES, sizeof(DATA_32_VALUES));
    res |= s_test_known_crc(
        func_name,
        func,
        "non_mem_aligned_vector",
        s_non_mem_aligned_vector + 3,
        sizeof(DATA_32_VALUES),
        KNOWN_CRC64XZ_32_VALUES);

    free(s_non_mem_aligned_vector);
    return res;
}

/**
 * Quick sanity check of some known CRC values for known input.
 * The reference functions are included in these tests to verify that they aren't obviously broken.
 */
static int s_test_crc64xz(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    int res = 0;

    res |= s_test_known_crc64xz(CRC_FUNC_NAME(crc64xz_reference));
    res |= s_test_known_crc64xz(CRC_FUNC_NAME(aws_checksums_crc64xz_sw));
    res |= s_test_known_crc64xz(CRC_FUNC_NAME(aws_checksums_crc64xz));

    return res;
}

AWS_TEST_CASE(test_crc64xz, s_test_crc64xz)
