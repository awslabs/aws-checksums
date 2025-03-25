/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/checksums/checksums.h>
#include <aws/checksums/private/crc_util.h>

void aws_checksums_library_init(struct aws_allocator *allocator) {
    (void)allocator;

    aws_checksums_crc32_init();
    aws_checksums_crc64_init();
}

void aws_checksums_library_clean_up(void) {}
