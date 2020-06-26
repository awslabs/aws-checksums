/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#ifdef BUILD_JNI_BINDINGS
#    include <aws/checksums/crc.h>
#    include <aws/checksums/crc_jni.h>

jint JNICALL Java_software_amazon_awschecksums_AWSCRC32C_crc32c(
    JNIEnv *env,
    jobject obj,
    jbyteArray data,
    jint offset,
    jint length,
    jint previous_crc) {
    jbyte *buffer_ptr = (*env)->GetPrimitiveArrayCritical(env, data, 0);
    int ret_val = (int)aws_checksums_crc32c((const uint8_t *)(buffer_ptr + offset), length, previous_crc);
    (*env)->ReleasePrimitiveArrayCritical(env, data, buffer_ptr, 0);

    return ret_val;
}

jint JNICALL Java_software_amazon_awschecksums_AWSCRC32C_crc32cDirect(
    JNIEnv *env,
    jobject obj,
    jobject data,
    jint offset,
    jint length,
    jint previous_crc) {
    jbyte *buf_ptr = (*env)->GetDirectBufferAddress(env, data);
    return aws_checksums_crc32c((const uint8_t *)(buf_ptr + offset), length, previous_crc);
}

jint JNICALL Java_software_amazon_awschecksums_AWSCRC32_crc32(
    JNIEnv *env,
    jobject obj,
    jbyteArray data,
    jint offset,
    jint length,
    jint previous_crc) {
    jbyte *buffer_ptr = (*env)->GetPrimitiveArrayCritical(env, data, 0);
    int ret_val = (int)aws_checksums_crc32((const uint8_t *)(buffer_ptr + offset), length, previous_crc);
    (*env)->ReleasePrimitiveArrayCritical(env, data, buffer_ptr, 0);

    return ret_val;
}

jint JNICALL Java_software_amazon_awschecksums_AWSCRC32_crc32Direct(
    JNIEnv *env,
    jobject obj,
    jobject data,
    jint offset,
    jint length,
    jint previous_crc) {
    jbyte *buf_ptr = (*env)->GetDirectBufferAddress(env, data);
    return aws_checksums_crc32((const uint8_t *)(buf_ptr + offset), length, previous_crc);
}

#endif
