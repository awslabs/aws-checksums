/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#[cfg(test)]
mod tests {
    use aws_crt_checksums::{Checksum, Crc32, Crc32C};

    #[test]
    fn test_crc32_zeroes() {
        let test_input: Vec<u8> = vec![0; 32];
        let expected_crc = 0x190A55AD;

        let mut crc_checksum = Crc32::new();
        crc_checksum.update(&test_input);
        assert_eq!(expected_crc, crc_checksum.checksum());
    }

    #[test]
    fn test_known_crc32() {
        let test_input: Vec<u8> = vec![
            '1' as u8, '2' as u8, '3' as u8, '4' as u8, '5' as u8, '6' as u8, '7' as u8, '8' as u8,
            '9' as u8,
        ];
        let expected_crc = 0xCBF43926;

        let mut crc_checksum = Crc32::new();
        crc_checksum.update(&test_input);
        assert_eq!(expected_crc, crc_checksum.checksum());
    }

    #[test]
    fn test_crc32c_zeroes() {
        let test_input: Vec<u8> = vec![0; 32];
        let expected_crc = 0x8A9136AA;

        let mut crc_checksum = Crc32C::new();
        crc_checksum.update(&test_input);
        assert_eq!(expected_crc, crc_checksum.checksum());
    }

    #[test]
    fn test_known_crc32c() {
        let test_input: Vec<u8> = vec![
            '1' as u8, '2' as u8, '3' as u8, '4' as u8, '5' as u8, '6' as u8, '7' as u8, '8' as u8,
            '9' as u8,
        ];
        let expected_crc = 0xE3069283;

        let mut crc_checksum = Crc32C::new();
        crc_checksum.update(&test_input);
        assert_eq!(expected_crc, crc_checksum.checksum());
    }
}
