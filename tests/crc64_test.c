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

typedef uint64_t(crc_fn)(const uint8_t *input, int length, uint64_t previousCrc64);
#define CRC_FUNC_NAME(crc_func) #crc_func, crc_func
#define DATA_NAME(dataset) #dataset, dataset, sizeof(dataset)
#define TEST_BUFFER_SIZE 2048 + 64

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
    const size_t length,
    const uint64_t expected_crc,
    const uint64_t expected_residue) {

    uint64_t result = func(input, (int)length, 0);
    ASSERT_HEX_EQUALS(expected_crc, result, "%s(%s)", func_name, data_name);

    // Compute the residue of the buffer (the CRC of the buffer plus its CRC) - will always be a constant value
    uint64_t residue = func((const uint8_t *)&result, 8, result); // assuming little endian
    ASSERT_HEX_EQUALS(expected_residue, residue, "len %d residue %s(%s)", length, func_name, data_name);

    // chain the crc computation so 2 calls each operate on about 1/2 of the buffer
    uint64_t crc1 = func(input, (int)(length / 2), 0);
    result = func(input + (length / 2), (int)(length - length / 2), crc1);
    ASSERT_HEX_EQUALS(expected_crc, result, "chaining %s(%s)", func_name, data_name);

    crc1 = 0;
    for (size_t i = 0; i < length; ++i) {
        crc1 = func(input + i, 1, crc1);
    }
    ASSERT_HEX_EQUALS(expected_crc, crc1, "one byte at a time %s(%s)", func_name, data_name);

    return AWS_OP_SUCCESS;
}

/* helper function that groups crc64xz tests */
static int s_test_known_crc64xz(const char *func_name, crc_fn *func) {
    int res = 0;

    // Quick sanity check of some known CRC values for known input.
    res |= s_test_known_crc(func_name, func, DATA_NAME(DATA_32_ZEROS), KNOWN_CRC64XZ_32_ZEROES, RESIDUE_CRC64XZ);
    res |= s_test_known_crc(func_name, func, DATA_NAME(DATA_32_VALUES), KNOWN_CRC64XZ_32_VALUES, RESIDUE_CRC64XZ);
    res |= s_test_known_crc(func_name, func, DATA_NAME(TEST_VECTOR), KNOWN_CRC64XZ_TEST_VECTOR, RESIDUE_CRC64XZ);

    if (func == crc64xz_reference) {
        // Don't proceed further since we'd just be testing the reference function against itself
        return res;
    }

    uint8_t *test_buffer = malloc(TEST_BUFFER_SIZE);
    // Spin through buffer offsets
    for (int off = 0; off < 16; off++) {
        // Fill the test buffer with different values for each iteration
        memset(test_buffer, off + 129, TEST_BUFFER_SIZE);
        uint64_t expected = 0;
        int len = 1;
        // Spin through input data lengths
        for (int i = 0; i < (TEST_BUFFER_SIZE - off) && !res; i++, len++) {
            // Compute the expected CRC one byte at a time using the reference function
            expected = crc64xz_reference(&test_buffer[off + i], 1, expected);
            // Recompute the full CRC of the buffer at each offset and length and compare against expected value
            res |= s_test_known_crc(func_name, func, "test_buffer", &test_buffer[off], len, expected, RESIDUE_CRC64XZ);
        }
    }
    free(test_buffer);

    return res;
}

/**
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
