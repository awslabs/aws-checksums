/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

using System;
using System.Runtime.InteropServices;
using System.Security;

namespace AWS.Checksums.NativeInterop
{
    internal class AWSCRCNative
    {
        [DllImport(LibraryDefinitions.AwsChecksumsLibName, EntryPoint = "aws_checksums_crc32")]
        internal static extern UInt32 CRC32(byte[] input, int length, UInt32 previousCrc32);

        [DllImport(LibraryDefinitions.AwsChecksumsLibName, EntryPoint = "aws_checksums_crc32c")]
        internal static extern UInt32 CRC32C(byte[] input, int length, UInt32 previousCrc32);
    }
}
