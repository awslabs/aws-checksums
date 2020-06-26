/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <crc_test.c>

int main(int argc, char *argv[]) {

    if (argc < 2) {
        int retVal = 0;
        retVal |= s_test_crc32c();
        retVal |= s_test_crc32();

        printf("Test run finished press any key to exit\n");
        // if this path is being run, it's manually from a console or IDE and the user likely want's to see the results.
        getchar();
        return retVal;
    }

    // I know this looks painful, but it's far less painful than a GTEST dependency and it integrates nicely with CTest.
    if (!strcmp(argv[1], "crc32c")) {
        return s_test_crc32c();
    }
    if (!strcmp(argv[1], "crc32")) {
        return s_test_crc32();
    }

    return 0;
}
