
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0.

from cffi import FFI

aws_checksums_lib_handle = FFI()

#crc functions
aws_checksums_lib_handle.cdef("uint32_t aws_checksums_crc32(uint8_t *input, int length, uint32_t previousCrc32);")
aws_checksums_lib_handle.cdef("uint32_t aws_checksums_crc32c(uint8_t *input, int length, uint32_t previousCrc32);")

class AWSChecksumsLib():

    def __init__(self):
        try:
            self.handle = aws_checksums_lib_handle.dlopen("aws-checksums")
#            aws_checksums_lib_handle.verify()
            self.loaded = True

        except Exception as ex:
            print(ex)
            self.load_error = ex
            self.loaded = False

    def is_available(self):
        return self.loaded
        
    def get_crc32c_instance(self):
        return AWSCRC32c(self.handle)

    def get_crc32_instance(self):
        return AWSCRC32(self.handle)

class AWSCRC32c():

    def __init__(self, checksums_lib_handle):
        self.checksums_lib_handle = checksums_lib_handle
        self.crc = 0

    def update(self, data):
        self.crc = self.checksums_lib_handle.aws_checksums_crc32c(data, len(data), self.crc)

    def reset(self):
        self.crc = 0

    def value(self):
        return self.crc

class AWSCRC32():

    def __init__(self, checksums_lib_handle):
        self.checksums_lib_handle = checksums_lib_handle
        self.crc = 0

    def update(self, data):
        self.crc = self.checksums_lib_handle.aws_checksums_crc32(data, len(data), self.crc)

    def reset(self):
        self.crc = 0

    def value(self):
        return self.crc

