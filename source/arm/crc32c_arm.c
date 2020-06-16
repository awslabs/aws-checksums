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

/* for the moment, fallback to SW on ARM until MSFT adds intrensics for ARM v8.1+ */
#if (defined(_M_ARM) || defined(__arm__) || defined(__aarch64__) || defined(__ARM_ARCH_ISA_A64))

#    include <aws/checksums/private/crc_priv.h>

static inline uint32_t crc32cb(uint32_t crc, uint8_t data) {
    asm(".arch_extension crc\n"
        "crc32cb %w0, %w0, %w1"
        : "+r"(crc)
        : "r"(data));
    return crc;
}

static inline uint32_t crc32cd(uint32_t crc, uint64_t data) {
    asm(".arch_extension crc\n"
        "crc32cx %w0, %w0, %x1"
        : "+r"(crc)
        : "r"(data));
    return crc;
}

static inline uint32_t crc32b(uint32_t crc, uint8_t data) {
    asm(".arch_extension crc\n"
        "crc32b %w0, %w0, %w1"
        : "+r"(crc)
        : "r"(data));
    return crc;
}

static inline uint32_t crc32d(uint32_t crc, uint64_t data) {
    asm(".arch_extension crc\n"
        "crc32x %w0, %w0, %x1"
        : "+r"(crc)
        : "r"(data));
    return crc;
}

uint32_t aws_checksums_crc32c_hw(const uint8_t *data, int length, uint32_t previousCrc32) {
    uint32_t crc = ~previousCrc32;

    // Align data if it's not aligned
    while (((uintptr_t)data & 7) && length > 0) {
        crc = crc32cb(crc, *(uint8_t *)data);
        data++;
        length--;
    }

    while (length >= 8) {
        crc = crc32cd(crc, *(uint64_t *)data);
        data += 8;
        length -= 8;
    }

    while (length > 0) {
        crc = crc32cb(crc, *(uint8_t *)data);
        data++;
        length--;
    }

    return ~crc;
}

uint32_t aws_checksums_crc32_hw(const uint8_t *data, int length, uint32_t previousCrc32) {
    uint32_t crc = ~previousCrc32;

    // Align data if it's not aligned
    while (((uintptr_t)data & 7) && length > 0) {
        crc = crc32b(crc, *(uint8_t *)data);
        data++;
        length--;
    }

    while (length >= 8) {
        crc = crc32d(crc, *(uint64_t *)data);
        data += 8;
        length -= 8;
    }

    while (length > 0) {
        crc = crc32b(crc, *(uint8_t *)data);
        data++;
        length--;
    }

    return ~crc;
}

#endif
