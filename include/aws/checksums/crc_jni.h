#ifndef AWS_CHECKSUMS_CRC_JNI_H
#define AWS_CHECKSUMS_CRC_JNI_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#ifdef BUILD_JNI_BINDINGS
#    include <jni.h>

#    ifdef __cplusplus
extern "C" {
#    endif
JNIEXPORT jint JNICALL
    Java_software_amazon_awschecksums_AWSCRC32C_crc32c(JNIEnv *, jobject, jbyteArray, jint, jint, jint);
JNIEXPORT jint JNICALL
    Java_software_amazon_awschecksums_AWSCRC32C_crc32cDirect(JNIEnv *, jobject, jobject, jint, jint, jint);

JNIEXPORT jint JNICALL
    Java_software_amazon_awschecksums_AWSCRC32_crc32(JNIEnv *, jobject, jbyteArray, jint, jint, jint);
JNIEXPORT jint JNICALL
    Java_software_amazon_awschecksums_AWSCRC32_crc32Direct(JNIEnv *, jobject, jobject, jint, jint, jint);

#    ifdef __cplusplus
}
#    endif

#endif
#endif /* AWS_CHECKSUMS_CRC_JNI_H */
