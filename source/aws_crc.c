/*
* Copyright 2010-2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License").
* You may not use this file except in compliance with the License.
* A copy of the License is located at
*
*  http://aws.amazon.com/apache2.0
*
* or in the "license" file accompanying this file. This file is distributed
* on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
* express or implied. See the License for the specific language governing
* permissions and limitations under the License.
*/
#include <aws/checksums/private/aws_cpuid.h>
#include <aws/checksums/private/aws_crc_priv.h>
#include <aws/checksums/aws_crc.h>

// A normalized function signature for all CRC functions.
static uint32_t(*crc32c_func)(const uint8_t *input, int length, uint32_t previousCrc32) = 0;

uint32_t aws_checksums_crc32(const uint8_t *input, int length, uint32_t previousCrc32) {
    return aws_checksums_crc32_sw(input, length, previousCrc32);
}

uint32_t aws_checksums_crc32c(const uint8_t *input, int length, uint32_t previousCrc32) {
    if (!crc32c_func) {
        if (aws_checksums_is_sse42_present()) {
            crc32c_func = aws_checksums_crc32c_hw;
        }
        else {
            crc32c_func = aws_checksums_crc32c_sw;
        }
    }
    return crc32c_func(input, length, previousCrc32);
}
