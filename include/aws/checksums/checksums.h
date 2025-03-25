#ifndef AWS_CHECKSUMS_CHECKSUMS_H
#define AWS_CHECKSUMS_CHECKSUMS_H

#include <aws/common/common.h>

#include <aws/checksums/exports.h>

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

/**
 * Initializes internal data structures used by aws-checksums.
 * Should be called before using any functionality in aws-checksums.
 * Note: historically aws-checksums lazily initialized some internal pointers,
 * which some tools picked up as thread unsafe. As best practice prefer explicit init
 * before using this library.
 */
AWS_CHECKSUMS_API void aws_checksums_library_init(struct aws_allocator *allocator);

/**
 * Shuts down the internal data structures used by aws-checksums.
 */
AWS_CHECKSUMS_API void aws_checksums_library_clean_up(void);

#endif /* AWS_CHECKSUMS_CHECKSUMS_H */
