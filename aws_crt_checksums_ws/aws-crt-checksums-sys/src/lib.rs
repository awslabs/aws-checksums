/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

/// This module is a rust translation of the relevant declarations from the aws-c-common
/// header files. They are used from higher-level wrapper modules.

#[allow(dead_code)]
extern "C" {
    pub fn aws_checksums_crc32(input: *const u8, length: i32, previous_crc: u32) -> u32;
    pub fn aws_checksums_crc32c(input: *const u8, length: i32, previous_crc: u32) -> u32;
}
