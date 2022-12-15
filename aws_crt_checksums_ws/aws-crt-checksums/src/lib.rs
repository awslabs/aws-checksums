/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
use aws_crt_checksums_sys::{aws_checksums_crc32, aws_checksums_crc32c};

#[derive(Clone)]
pub struct Crc32C {
    running_checksum: u32,
}

#[derive(Clone)]
pub struct Crc32 {
    running_checksum: u32,
}

/// Trait for computing running checksums.
pub trait Checksum {
    type Output;
    /// update the checksum with the checksum value of input
    /// # Arguments
    /// * `input` the input data to be appended to the running checksum.
    fn update(&mut self, input: &Vec<u8>);
    /// Return the current value of the running checksum.
    fn checksum(&self) -> Self::Output;
}

impl Checksum for Crc32C {
    type Output = u32;

    fn update(&mut self, input: &Vec<u8>) {
        unsafe {
            self.running_checksum =
                aws_checksums_crc32c(input.as_ptr(), input.len() as i32, self.running_checksum);
        }
    }

    fn checksum(&self) -> u32 {
        self.running_checksum
    }
}

impl Checksum for Crc32 {
    type Output = u32;

    fn update(&mut self, input: &Vec<u8>) {
        unsafe {
            self.running_checksum =
                aws_checksums_crc32(input.as_ptr(), input.len() as i32, self.running_checksum);
        }
    }

    fn checksum(&self) -> u32 {
        self.running_checksum
    }
}

impl Crc32C {
    /// Creates a new instance of the castagnoli CRC32c (iSCSI) checksum algorithm. Where supported
    /// by the hardware, this implementation is hw accelerated.
    pub fn new() -> Crc32C {
        Crc32C {
            running_checksum: 0,
        }
    }
}

impl Crc32 {
    /// Creates a new instance of the CRC32 (Ethernet, gzip) algorithm. Where supported
    /// by the hardware, this implementation is hw accelerated.
    pub fn new() -> Crc32 {
        Crc32 {
            running_checksum: 0,
        }
    }
}
