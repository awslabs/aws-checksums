/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/checksums/checksums.h>
#include <aws/checksums/xxhash.h>
#include <aws/testing/aws_test_harness.h>

static const char *TEST_VECTOR = "abcdefghijklmnopqrstuvwxyz";

static int s_test_xxhash64(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_checksums_library_init(allocator);

    struct aws_byte_buf result;
    aws_byte_buf_init(&result, allocator, 8);

    struct aws_byte_cursor input = aws_byte_cursor_from_c_str("Hello world");

    ASSERT_SUCCESS(aws_xxhash64_compute(0, input, &result));

    uint8_t expected[] = {0xc5, 0x00, 0xb0, 0xc9, 0x12, 0xb3, 0x76, 0xd8};

    ASSERT_BIN_ARRAYS_EQUALS(result.buffer, result.len, expected, sizeof(expected));

    struct aws_xxhash *hash = aws_xxhash64_new(allocator, 0);
    aws_xxhash_update(hash, input);
    aws_byte_buf_reset(&result, false);
    ASSERT_SUCCESS(aws_xxhash_finalize(hash, &result));

    ASSERT_BIN_ARRAYS_EQUALS(result.buffer, result.len, expected, sizeof(expected));

    aws_byte_buf_clean_up(&result);
    aws_xxhash_destroy(hash);

    aws_checksums_library_clean_up();

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_xxhash64, s_test_xxhash64)

static int s_test_xxhash64_generic(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_checksums_library_init(allocator);

    struct aws_byte_buf result;
    aws_byte_buf_init(&result, allocator, 8);

    struct aws_byte_cursor input = aws_byte_cursor_from_c_str(TEST_VECTOR);

    ASSERT_SUCCESS(aws_xxhash64_compute(0, input, &result));

    uint8_t expected[] = {0xcf, 0xe1, 0xf2, 0x78, 0xfa, 0x89, 0x83, 0x5c};

    ASSERT_BIN_ARRAYS_EQUALS(result.buffer, result.len, expected, sizeof(expected));

    struct aws_xxhash *hash = aws_xxhash64_new(allocator, 0);
    aws_xxhash_update(hash, input);
    aws_byte_buf_reset(&result, false);
    ASSERT_SUCCESS(aws_xxhash_finalize(hash, &result));

    ASSERT_BIN_ARRAYS_EQUALS(result.buffer, result.len, expected, sizeof(expected));

    aws_byte_buf_clean_up(&result);
    aws_xxhash_destroy(hash);

    aws_checksums_library_clean_up();

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_xxhash64_generic, s_test_xxhash64_generic)

static int s_test_xxhash3_64(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_checksums_library_init(allocator);

    struct aws_byte_buf result;
    aws_byte_buf_init(&result, allocator, 8);

    struct aws_byte_cursor input = aws_byte_cursor_from_c_str("Hello world");

    ASSERT_SUCCESS(aws_xxhash3_64_compute(0, input, &result));

    uint8_t expected[] = {0xb6, 0xac, 0xb9, 0xd8, 0x4a, 0x38, 0xff, 0x74};

    ASSERT_BIN_ARRAYS_EQUALS(result.buffer, result.len, expected, sizeof(expected));

    struct aws_xxhash *hash = aws_xxhash3_64_new(allocator, 0);
    aws_xxhash_update(hash, input);
    aws_byte_buf_reset(&result, false);
    ASSERT_SUCCESS(aws_xxhash_finalize(hash, &result));

    ASSERT_BIN_ARRAYS_EQUALS(result.buffer, result.len, expected, sizeof(expected));

    aws_byte_buf_clean_up(&result);
    aws_xxhash_destroy(hash);

    aws_checksums_library_clean_up();

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_xxhash3_64, s_test_xxhash3_64)

static int s_test_xxhash3_64_generic(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_checksums_library_init(allocator);

    struct aws_byte_buf result;
    aws_byte_buf_init(&result, allocator, 8);

    struct aws_byte_cursor input = aws_byte_cursor_from_c_str(TEST_VECTOR);

    ASSERT_SUCCESS(aws_xxhash3_64_compute(0, input, &result));

    uint8_t expected[] = {0x81, 0x0f, 0x9c, 0xa0, 0x67, 0xfb, 0xb9, 0x0c};

    ASSERT_BIN_ARRAYS_EQUALS(result.buffer, result.len, expected, sizeof(expected));

    struct aws_xxhash *hash = aws_xxhash3_64_new(allocator, 0);
    aws_xxhash_update(hash, input);
    aws_byte_buf_reset(&result, false);
    ASSERT_SUCCESS(aws_xxhash_finalize(hash, &result));

    ASSERT_BIN_ARRAYS_EQUALS(result.buffer, result.len, expected, sizeof(expected));

    aws_byte_buf_clean_up(&result);
    aws_xxhash_destroy(hash);

    aws_checksums_library_clean_up();

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_xxhash3_64_generic, s_test_xxhash3_64_generic)

static int s_test_xxhash3_128(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_checksums_library_init(allocator);

    struct aws_byte_buf result;
    aws_byte_buf_init(&result, allocator, 16);

    struct aws_byte_cursor input = aws_byte_cursor_from_c_str("Hello world");

    ASSERT_SUCCESS(aws_xxhash3_128_compute(0, input, &result));

    uint8_t expected[] = {
        0x73, 0x51, 0xf8, 0x98, 0x12, 0xf9, 0x73, 0x82, 0xb9, 0x1d, 0x05, 0xb3, 0x1e, 0x04, 0xdd, 0x7f};

    ASSERT_BIN_ARRAYS_EQUALS(result.buffer, result.len, expected, sizeof(expected));

    struct aws_xxhash *hash = aws_xxhash3_128_new(allocator, 0);
    aws_xxhash_update(hash, input);
    aws_byte_buf_reset(&result, false);
    ASSERT_SUCCESS(aws_xxhash_finalize(hash, &result));

    ASSERT_BIN_ARRAYS_EQUALS(result.buffer, result.len, expected, sizeof(expected));

    aws_byte_buf_clean_up(&result);
    aws_xxhash_destroy(hash);

    aws_checksums_library_clean_up();

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_xxhash3_128, s_test_xxhash3_128)

static int s_test_xxhash3_128_generic(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_checksums_library_init(allocator);

    struct aws_byte_buf result;
    aws_byte_buf_init(&result, allocator, 16);

    struct aws_byte_cursor input = aws_byte_cursor_from_c_str(TEST_VECTOR);

    ASSERT_SUCCESS(aws_xxhash3_128_compute(0, input, &result));

    uint8_t expected[] = {
        0xdb, 0x7c, 0xa4, 0x4e, 0x84, 0x84, 0x3d, 0x67, 0xeb, 0xe1, 0x62, 0x22, 0x01, 0x54, 0xe1, 0xe6};

    ASSERT_BIN_ARRAYS_EQUALS(result.buffer, result.len, expected, sizeof(expected));

    struct aws_xxhash *hash = aws_xxhash3_128_new(allocator, 0);
    aws_xxhash_update(hash, input);
    aws_byte_buf_reset(&result, false);
    ASSERT_SUCCESS(aws_xxhash_finalize(hash, &result));

    ASSERT_BIN_ARRAYS_EQUALS(result.buffer, result.len, expected, sizeof(expected));

    aws_byte_buf_clean_up(&result);
    aws_xxhash_destroy(hash);

    aws_checksums_library_clean_up();

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(test_xxhash3_128_generic, s_test_xxhash3_128_generic)
