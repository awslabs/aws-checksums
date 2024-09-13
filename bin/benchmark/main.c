/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/checksums/crc.h>
#include <aws/checksums/private/crc64_priv.h>
#include <aws/checksums/private/crc_priv.h>

#include <aws/common/allocator.h>
#include <aws/common/byte_buf.h>
#include <aws/common/clock.h>
#include <aws/common/cpuid.h>
#include <aws/common/device_random.h>

#include <inttypes.h>

struct aws_allocator_types {
    struct aws_allocator *allocator;
    const char *name;
};

struct checksum_profile_run {
    void (*profile_run)(struct aws_byte_cursor checksum_this);
    const char *name;
};

static void s_runcrc32_sw(struct aws_byte_cursor checksum_this) {
    uint32_t crc = aws_checksums_crc32_sw(checksum_this.ptr, (int)checksum_this.len, 0);
    (void)crc;
}

static void s_runcrc32(struct aws_byte_cursor checksum_this) {
    uint32_t crc = aws_checksums_crc32(checksum_this.ptr, (int)checksum_this.len, 0);
    (void)crc;
}

static void s_runcrc32c_sw(struct aws_byte_cursor checksum_this) {
    uint32_t crc = aws_checksums_crc32c_sw(checksum_this.ptr, (int)checksum_this.len, 0);
    (void)crc;
}

static void s_runcrc32c(struct aws_byte_cursor checksum_this) {
    uint32_t crc = aws_checksums_crc32c(checksum_this.ptr, (int)checksum_this.len, 0);
    (void)crc;
}

static void s_runcrc64_sw(struct aws_byte_cursor checksum_this) {
    uint64_t crc = aws_checksums_crc64nvme_sw(checksum_this.ptr, (int)checksum_this.len, 0);
    (void)crc;
}

static void s_runcrc64(struct aws_byte_cursor checksum_this) {
    uint64_t crc = aws_checksums_crc64nvme(checksum_this.ptr, (int)checksum_this.len, 0);
    (void)crc;
}

#define KB_TO_BYTES(kb) ((kb) * 1024)
#define MB_TO_BYTES(mb) ((mb) * 1024 * 1024)
#define GB_TO_BYTES(gb) ((gb) * 1024 * 1024 * 1024ULL)

int main(void) {

    fprintf(stdout, "hw features for this run:\n");
    fprintf(stdout, "clmul: %s\n", aws_cpu_has_feature(AWS_CPU_FEATURE_CLMUL) ? "true" : "false");
    fprintf(stdout, "sse4.1: %s\n", aws_cpu_has_feature(AWS_CPU_FEATURE_SSE_4_1) ? "true" : "false");
    fprintf(stdout, "sse4.2: %s\n", aws_cpu_has_feature(AWS_CPU_FEATURE_SSE_4_2) ? "true" : "false");
    fprintf(stdout, "avx2: %s\n", aws_cpu_has_feature(AWS_CPU_FEATURE_AVX2) ? "true" : "false");
    fprintf(stdout, "avx512: %s\n", aws_cpu_has_feature(AWS_CPU_FEATURE_AVX512) ? "true" : "false");
    fprintf(stdout, "arm crc: %s\n", aws_cpu_has_feature(AWS_CPU_FEATURE_ARM_CRC) ? "true" : "false");
    fprintf(stdout, "bmi2: %s\n", aws_cpu_has_feature(AWS_CPU_FEATURE_BMI2) ? "true" : "false");
    fprintf(stdout, "vpclmul: %s\n", aws_cpu_has_feature(AWS_CPU_FEATURE_VPCLMULQDQ) ? "true" : "false");
    fprintf(stdout, "arm pmull: %s\n", aws_cpu_has_feature(AWS_CPU_FEATURE_ARM_PMULL) ? "true" : "false");
    fprintf(stdout, "arm crypto: %s\n\n", aws_cpu_has_feature(AWS_CPU_FEATURE_ARM_CRYPTO) ? "true" : "false");

    struct aws_allocator_types allocators[2];
    allocators[0].allocator = aws_default_allocator();
    allocators[0].name = "Default runtime allocator";
    allocators[1].allocator = aws_aligned_allocator();
    allocators[1].name = "Aligned allocator";

    struct checksum_profile_run profile_runs[] = {
        {.profile_run = s_runcrc32_sw, .name = "crc32 C only"},
        {.profile_run = s_runcrc32, .name = "crc32 with hw optimizations"},
        {.profile_run = s_runcrc32c_sw, .name = "crc32c C only"},
        {.profile_run = s_runcrc32c, .name = "crc32c with hw optimizations"},
        {.profile_run = s_runcrc64_sw, .name = "crc64nvme C only"},
        {.profile_run = s_runcrc64, .name = "crc64nvme with hw optimizations"},
    };

    const size_t allocators_array_size = AWS_ARRAY_SIZE(allocators);
    const size_t profile_runs_size = AWS_ARRAY_SIZE(profile_runs);

    for (size_t i = 0; i < profile_runs_size; ++i) {
        fprintf(stdout, "--------Profile %s---------\n", profile_runs[i].name);

        for (size_t j = 0; j < allocators_array_size; ++j) {
            fprintf(stdout, "%s\n\n", allocators[j].name);

            struct aws_allocator *allocator = allocators[j].allocator;

            // get buffer sizes large enough that all the simd code paths get hit hard, but
            // also measure the smaller buffer paths since they often can't be optimized as thoroughly.
            size_t buffer_sizes[] = {8, 16, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384,
                KB_TO_BYTES(32), KB_TO_BYTES(64), KB_TO_BYTES(256), MB_TO_BYTES(1), MB_TO_BYTES(10), MB_TO_BYTES(100), GB_TO_BYTES(1)};
            size_t buffer_sizes_len = AWS_ARRAY_SIZE(buffer_sizes);

            // warm it up to factor out the cpuid checks:
            struct aws_byte_cursor warmup_cur = aws_byte_cursor_from_array(buffer_sizes, buffer_sizes_len);
            profile_runs[i].profile_run(warmup_cur);

            for (size_t k = 0; k < buffer_sizes_len; ++k) {
                struct aws_byte_buf x_bytes;
                aws_byte_buf_init(&x_bytes, allocator, buffer_sizes[k]);
                aws_device_random_buffer(&x_bytes);
                uint64_t start_time = 0;
                aws_high_res_clock_get_ticks(&start_time);
                profile_runs[i].profile_run(aws_byte_cursor_from_buf(&x_bytes));
                uint64_t end_time = 0;
                aws_high_res_clock_get_ticks(&end_time);
                fprintf(
                    stdout,
                    "buffer size %zu (bytes), latency: %" PRIu64 " ns throughput: %f GiB/s\n",
                    buffer_sizes[k],
                    end_time - start_time,
                    (buffer_sizes[k] * 1000000000.0 /* ns -> sec factor */ / GB_TO_BYTES(1)) / (end_time - start_time));
                aws_byte_buf_clean_up(&x_bytes);
            }
            fprintf(stdout, "\n");
        }
    }
    return 0;
}
