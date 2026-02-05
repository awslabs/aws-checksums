#ifndef AWS_CHECKSUMS_XXHASH_H
#define AWS_CHECKSUMS_XXHASH_H
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/checksums/exports.h>
#include <aws/common/byte_buf.h>

AWS_PUSH_SANE_WARNING_LEVEL

struct aws_xxhash_impl;

enum aws_xxhash_type { XXHASH64 = 0, XXHASH3_64 = 1, XXHASH3_128 = 2 };

struct aws_xxhash {
    struct aws_allocator *allocator;
    enum aws_xxhash_type type;
    struct aws_xxhash_impl *impl;
};

AWS_EXTERN_C_BEGIN

AWS_CHECKSUMS_API struct aws_xxhash *aws_xxhash64_new(struct aws_allocator *allocator, uint64_t seed);
AWS_CHECKSUMS_API struct aws_xxhash *aws_xxhash3_64_new(struct aws_allocator *allocator, uint64_t seed);
AWS_CHECKSUMS_API struct aws_xxhash *aws_xxhash3_128_new(struct aws_allocator *allocator, uint64_t seed);

AWS_CHECKSUMS_API int aws_xxhash_update(struct aws_xxhash *hash, struct aws_byte_cursor data);
AWS_CHECKSUMS_API int aws_xxhash_finalize(struct aws_xxhash *hash, struct aws_byte_buf *out);
AWS_CHECKSUMS_API void aws_xxhash_destroy(struct aws_xxhash *hash);

AWS_CHECKSUMS_API int aws_xxhash64_compute(uint64_t seed, struct aws_byte_cursor data, struct aws_byte_buf *out);
AWS_CHECKSUMS_API int aws_xxhash3_64_compute(uint64_t seed, struct aws_byte_cursor data, struct aws_byte_buf *out);
AWS_CHECKSUMS_API int aws_xxhash3_128_compute(uint64_t seed, struct aws_byte_cursor data, struct aws_byte_buf *out);

AWS_EXTERN_C_END
AWS_POP_SANE_WARNING_LEVEL

#endif /* AWS_CHECKSUMS_XXHASH_H */
