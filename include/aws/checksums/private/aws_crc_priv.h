#ifndef AWS_CRC_PRIV_H_
#define AWS_CRC_PRIV_H_
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


#define AWS_CRC32_SIZE_BYTES 4

#include <stdint.h>
#include <aws/checksums/aws_checksums_exports.h>

#ifdef __cplusplus
extern "C" {  // only need to export C interface if
              // used by C++ source code
#endif

/* Computes CRC32 (Ethernet, gzip, et. al.) using a (slow) reference implementation. */
AWS_CHECKSUMS_API uint32_t aws_checksums_crc32_sw(const uint8_t *input, int length, uint32_t previousCrc32);

/* Computes the Castagnoli CRC32c (iSCSI) using a (slow) reference implementation. */
AWS_CHECKSUMS_API uint32_t aws_checksums_crc32c_sw(const uint8_t *input, int length, uint32_t previousCrc32c);

/* Computes the Castagnoli CRC32c (iSCSI). */
AWS_CHECKSUMS_API uint32_t aws_checksums_crc32c_hw(const uint8_t* data, int length, uint32_t previousCrc32);

#ifdef __cplusplus
}
#endif

#endif /* AWS_CRC_PRIV_H_ */
