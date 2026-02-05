/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/checksums/xxhash.h>
#include <aws/common/logging.h>

#if defined(AWS_USE_CPU_EXTENSIONS) && defined(AWS_ARCH_INTEL_X64)
#    define XXH_X86DISPATCH

#    define AWS_XXHASH_USE_X86_INTRINSICS

#    if defined(__GNUC__)
#        include <emmintrin.h> /* SSE2 */
#        if defined(AWS_HAVE_AVX2_INTRINSICS) || defined(AWS_HAVE_AVX512_INTRINSICS)
#            include <immintrin.h> /* AVX2, AVX512F */
#        endif
#        define AWS_XXHASH_TARGET_SSE2 __attribute__((__target__("sse2")))
#        define AWS_XXHASH_TARGET_AVX2 __attribute__((__target__("avx2")))
#        define AWS_XXHASH_TARGET_AVX512 __attribute__((__target__("avx512f")))
#    elif defined(__clang__) && defined(_MSC_VER) /* clang-cl.exe */
#        include <emmintrin.h>                    /* SSE2 */
#        if defined(AWS_HAVE_AVX2_INTRINSICS) || defined(AWS_HAVE_AVX512_INTRINSICS)
#            include <avx2intrin.h>
#            include <avx512fintrin.h>
#            include <avxintrin.h>
#            include <immintrin.h> /* AVX2, AVX512F */
#            include <smmintrin.h>
#        endif
#        define AWS_XXHASH_TARGET_SSE2 __attribute__((__target__("sse2")))
#        define AWS_XXHASH_TARGET_AVX2 __attribute__((__target__("avx2")))
#        define AWS_XXHASH_TARGET_AVX512 __attribute__((__target__("avx512f")))
#    elif defined(_MSC_VER)
#        include <intrin.h>
#        define AWS_XXHASH_TARGET_SSE2
#        define AWS_XXHASH_TARGET_AVX2
#        define AWS_XXHASH_TARGET_AVX512
#    endif
#endif

#define XXH_INLINE_ALL
#include "external/xxhash.h"

#if defined(AWS_ARCH_INTEL_X64)
XXH_NO_INLINE XXH64_hash_t
    XXH3_64_seed_scalar(XXH_NOESCAPE const void *XXH_RESTRICT input, size_t len, XXH64_hash_t seed) {
    return XXH3_hashLong_64b_withSeed_internal(
        input, len, seed, XXH3_accumulate_scalar, XXH3_scrambleAcc_scalar, XXH3_initCustomSecret_scalar);
}

XXH_NO_INLINE XXH128_hash_t
    XXH3_128_seed_scalar(XXH_NOESCAPE const void *XXH_RESTRICT input, size_t len, XXH64_hash_t seed) {
    return XXH3_hashLong_128b_withSeed_internal(
        input, len, seed, XXH3_accumulate_scalar, XXH3_scrambleAcc_scalar, XXH3_initCustomSecret_scalar);
}

XXH_NO_INLINE XXH_errorcode
    XXH3_update_scalar(XXH_NOESCAPE XXH3_state_t *state, XXH_NOESCAPE const void *input, size_t len) {
    return XXH3_update(state, (const xxh_u8 *)input, len, XXH3_accumulate_scalar, XXH3_scrambleAcc_scalar);
}

#    if defined(AWS_USE_CPU_EXTENSIONS)

XXH_NO_INLINE AWS_XXHASH_TARGET_SSE2 XXH64_hash_t
    XXH3_64_seed_sse2(XXH_NOESCAPE const void *XXH_RESTRICT input, size_t len, XXH64_hash_t seed) {
    return XXH3_hashLong_64b_withSeed_internal(
        input, len, seed, XXH3_accumulate_sse2, XXH3_scrambleAcc_sse2, XXH3_initCustomSecret_sse2);
}

XXH_NO_INLINE AWS_XXHASH_TARGET_SSE2 XXH128_hash_t
    XXH3_128_seed_sse2(XXH_NOESCAPE const void *XXH_RESTRICT input, size_t len, XXH64_hash_t seed) {
    return XXH3_hashLong_128b_withSeed_internal(
        input, len, seed, XXH3_accumulate_sse2, XXH3_scrambleAcc_sse2, XXH3_initCustomSecret_sse2);
}

XXH_NO_INLINE AWS_XXHASH_TARGET_SSE2 XXH_errorcode
    XXH3_update_avx2(XXH_NOESCAPE XXH3_state_t *state, XXH_NOESCAPE const void *input, size_t len) {
    return XXH3_update(state, (const xxh_u8 *)input, len, XXH3_accumulate_sse2, XXH3_scrambleAcc_sse2);
}

#        ifdef AWS_HAVE_AVX2_INTRINSICS
XXH_NO_INLINE AWS_XXHASH_TARGET_AVX2 XXH64_hash_t
    XXH3_64_seed_avx2(XXH_NOESCAPE const void *XXH_RESTRICT input, size_t len, XXH64_hash_t seed) {
    return XXH3_hashLong_64b_withSeed_internal(
        input, len, seed, XXH3_accumulate_avx2, XXH3_scrambleAcc_avx2, XXH3_initCustomSecret_avx2);
}

XXH_NO_INLINE AWS_XXHASH_TARGET_AVX2 XXH128_hash_t
    XXH3_128_seed_avx2(XXH_NOESCAPE const void *XXH_RESTRICT input, size_t len, XXH64_hash_t seed) {
    return XXH3_hashLong_128b_withSeed_internal(
        input, len, seed, XXH3_accumulate_avx2, XXH3_scrambleAcc_avx2, XXH3_initCustomSecret_sse2);
}

XXH_NO_INLINE AWS_XXHASH_TARGET_AVX2 XXH_errorcode
    XXH3_update_avx2(XXH_NOESCAPE XXH3_state_t *state, XXH_NOESCAPE const void *input, size_t len) {
    return XXH3_update(state, (const xxh_u8 *)input, len, XXH3_accumulate_avx2, XXH3_scrambleAcc_avx2);
}
#        endif

#        ifdef AWS_HAVE_AVX512_INTRINSICS
XXH_NO_INLINE AWS_XXHASH_TARGET_AVX512 XXH64_hash_t
    XXH3_64_seed_avx512(XXH_NOESCAPE const void *XXH_RESTRICT input, size_t len, XXH64_hash_t seed) {
    return XXH3_hashLong_64b_withSeed_internal(
        input, len, seed, XXH3_accumulate_avx512, XXH3_scrambleAcc_avx512, XXH3_initCustomSecret_avx512);
}

XXH_NO_INLINE AWS_XXHASH_TARGET_AVX512 XXH128_hash_t
    XXH3_128_seed_512(XXH_NOESCAPE const void *XXH_RESTRICT input, size_t len, XXH64_hash_t seed) {
    return XXH3_hashLong_128b_withSeed_internal(
        input, len, seed, XXH3_accumulate_avx512, XXH3_scrambleAcc_avx512, XXH3_initCustomSecret_sse512);
}

XXH_NO_INLINE AWS_XXHASH_TARGET_AVX512 XXH_errorcode
    XXH3_update_avx512(XXH_NOESCAPE XXH3_state_t *state, XXH_NOESCAPE const void *input, size_t len) {
    return XXH3_update(state, (const xxh_u8 *)input, len, XXH3_accumulate_avx512, XXH3_scrambleAcc_avx512);
}
#        endif
#    endif

typedef XXH64_hash_t (*dispatch_x86_XXH3_64_seed_fn)(XXH_NOESCAPE const void *XXH_RESTRICT, size_t, XXH64_hash_t);
typedef XXH_errorcode (*dispatch_x86_XXH3_update_fn)(XXH_NOESCAPE XXH3_state_t *, XXH_NOESCAPE const void *, size_t);
typedef XXH128_hash_t (*dispatch_x86_XXH3_128_seed_fn)(XXH_NOESCAPE const void *XXH_RESTRICT, size_t, XXH64_hash_t);

static dispatch_x86_XXH3_64_seed_fn s_x86_XXH3_64_seed_compute = NULL;
static dispatch_x86_XXH3_128_seed_fn s_x86_XXH3_128_seed_compute = NULL;
static dispatch_x86_XXH3_update_fn s_x86_XXH3_update = NULL;

#endif

void aws_checksums_xxhash_init(void) {
#if defined(AWS_ARCH_INTEL_X64)
#    if defined(AWS_USE_CPU_EXTENSIONS)

    s_x86_XXH3_64_seed_compute = XXH3_64_seed_sse2;
    s_x86_XXH3_128_seed_compute = XXH3_128_seed_sse2;
    s_x86_XXH3_update = XXH3_update_sse2;

#        if defined(AWS_HAVE_AVX2_INTRINSICS)
    if (aws_cpu_has_feature(AWS_CPU_FEATURE_AVX2)) {
        s_x86_XXH3_64_seed_compute = XXH3_64_seed_avx2;
        s_x86_XXH3_128_seed_compute = XXH3_128_seed_avx2;
        s_x86_XXH3_update = XXH3_update_avx2;
    }
#        endif

#        if defined(AWS_HAVE_AVX512_INTRINSICS)
    if (aws_cpu_has_feature(AWS_CPU_FEATURE_AVX512)) {
        s_x86_XXH3_64_seed_compute = XXH3_64_seed_avx512;
        s_x86_XXH3_128_seed_compute = XXH3_128_seed_avx512;
        s_x86_XXH3_update = XXH3_update_avx512;
    }
#        endif
#    else
    s_x86_XXH3_64_seed_compute = XXH3_64_seed_scalar;
    s_x86_XXH3_128_seed_compute = XXH3_128_seed_scalar;
    s_x86_XXH3_update = XXH3_update_scalar;
#    endif

#endif
}

typedef int (*xxhash_update_fn)(void *state, struct aws_byte_cursor data);
int s_update_XXH64(void *state, struct aws_byte_cursor data) {
    if (XXH64_update((XXH64_state_t *)state, data.ptr, data.len) == XXH_ERROR) {
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }
    return AWS_OP_SUCCESS;
}

int s_update_XXH3_64(void *state, struct aws_byte_cursor data) {
#if defined(AWS_ARCH_INTEL_X64)
    AWS_FATAL_ASSERT(s_x86_XXH3_update);
    if (s_x86_XXH3_update((XXH3_state_t *)state, data.ptr, data.len) == XXH_ERROR) {
#else
    if (XXH3_64bits_update((XXH3_state_t *)state, data.ptr, data.len) == XXH_ERROR) {
#endif
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }
    return AWS_OP_SUCCESS;
}

int s_update_XXH3_128(void *state, struct aws_byte_cursor data) {
#if defined(AWS_ARCH_INTEL_X64)
    AWS_FATAL_ASSERT(s_x86_XXH3_update);
    if (s_x86_XXH3_update((XXH3_state_t *)state, data.ptr, data.len) == XXH_ERROR) {
#else
    if (XXH3_128bits_update((XXH3_state_t *)state, data.ptr, data.len) == XXH_ERROR) {
#endif
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    return AWS_OP_SUCCESS;
}

typedef int (*xxhash_finalize_fn)(void *state, struct aws_byte_buf *out);
int s_finalize_XXH64(void *state, struct aws_byte_buf *out) {
    XXH64_hash_t hash = XXH64_digest((XXH64_state_t *)state);

    if (!aws_byte_buf_write_be64(out, hash)) {
        return aws_raise_error(AWS_ERROR_INVALID_BUFFER_SIZE);
    }
    return AWS_OP_SUCCESS;
}

int s_finalize_XXH3_64(void *state, struct aws_byte_buf *out) {
    XXH64_hash_t hash = XXH3_64bits_digest((XXH3_state_t *)state);

    if (!aws_byte_buf_write_be64(out, hash)) {
        return aws_raise_error(AWS_ERROR_INVALID_BUFFER_SIZE);
    }
    return AWS_OP_SUCCESS;
}

int s_finalize_XXH3_128(void *state, struct aws_byte_buf *out) {
    XXH128_hash_t hash = XXH3_128bits_digest((XXH3_state_t *)state);
    if (out->capacity - out->len < 16) {
        return aws_raise_error(AWS_ERROR_INVALID_BUFFER_SIZE);
    }
    aws_byte_buf_write_be64(out, hash.high64);
    aws_byte_buf_write_be64(out, hash.low64);
    return AWS_OP_SUCCESS;
}

typedef void (*xxhash_state_free_fn)(void *state);
void s_state_free_XXH64(void *state) {
    XXH64_freeState((XXH64_state_t *)state);
}

void s_state_free_XXH3(void *state) {
    XXH3_freeState((XXH3_state_t *)state);
}

struct aws_xxhash_impl {
    void *state;
    xxhash_update_fn update_fn;
    xxhash_finalize_fn finalize_fn;
    xxhash_state_free_fn state_free_fn;
};

struct aws_xxhash *aws_xxhash64_new(struct aws_allocator *allocator, uint64_t seed) {
    XXH64_state_t *const state = XXH64_createState();

    if (state == NULL) {
        aws_raise_error(AWS_ERROR_UNKNOWN);
        return NULL;
    }

    if (XXH64_reset(state, seed) == XXH_ERROR) {
        aws_raise_error(AWS_ERROR_UNKNOWN);
        goto on_error;
    }

    struct aws_xxhash *hash = NULL;
    struct aws_xxhash_impl *impl = NULL;

    aws_mem_acquire_many(allocator, 2, &hash, sizeof(struct aws_xxhash), &impl, sizeof(struct aws_xxhash_impl));
    hash->allocator = allocator;
    hash->type = XXHASH64;
    hash->impl = impl;
    hash->impl->state = state;
    hash->impl->update_fn = s_update_XXH64;
    hash->impl->finalize_fn = s_finalize_XXH64;
    hash->impl->state_free_fn = s_state_free_XXH64;

    return hash;

on_error:
    XXH64_freeState(state);
    return NULL;
}

struct aws_xxhash *aws_xxhash3_64_new(struct aws_allocator *allocator, uint64_t seed) {
    XXH3_state_t *state = XXH3_createState();

    if (state == NULL) {
        aws_raise_error(AWS_ERROR_UNKNOWN);
        return NULL;
    }

    if (XXH3_64bits_reset_withSeed(state, seed) == XXH_ERROR) {
        aws_raise_error(AWS_ERROR_UNKNOWN);
        goto on_error;
    }

    struct aws_xxhash *hash = NULL;
    struct aws_xxhash_impl *impl = NULL;

    aws_mem_acquire_many(allocator, 2, &hash, sizeof(struct aws_xxhash), &impl, sizeof(struct aws_xxhash_impl));
    hash->allocator = allocator;
    hash->type = XXHASH3_64;
    hash->impl = impl;
    hash->impl->state = state;
    hash->impl->update_fn = s_update_XXH3_64;
    hash->impl->finalize_fn = s_finalize_XXH3_64;
    hash->impl->state_free_fn = s_state_free_XXH3;

    return hash;

on_error:
    XXH3_freeState(state);
    return NULL;
}

struct aws_xxhash *aws_xxhash3_128_new(struct aws_allocator *allocator, uint64_t seed) {
    XXH3_state_t *state = XXH3_createState();

    if (state == NULL) {
        aws_raise_error(AWS_ERROR_UNKNOWN);
        return NULL;
    }

    if (XXH3_128bits_reset_withSeed(state, seed) == XXH_ERROR) {
        aws_raise_error(AWS_ERROR_UNKNOWN);
        goto on_error;
    }

    struct aws_xxhash *hash = NULL;
    struct aws_xxhash_impl *impl = NULL;

    aws_mem_acquire_many(allocator, 2, &hash, sizeof(struct aws_xxhash), &impl, sizeof(struct aws_xxhash_impl));
    hash->allocator = allocator;
    hash->type = XXHASH3_128;
    hash->impl = impl;
    hash->impl->state = state;
    hash->impl->update_fn = s_update_XXH3_128;
    hash->impl->finalize_fn = s_finalize_XXH3_128;
    hash->impl->state_free_fn = s_state_free_XXH3; /* Same free as 64bit variant */

    return hash;

on_error:
    XXH3_freeState(state);
    return NULL;
}

int aws_xxhash_update(struct aws_xxhash *hash, struct aws_byte_cursor data) {
    AWS_ERROR_PRECONDITION(hash);

    return hash->impl->update_fn(hash->impl->state, data);
}

int aws_xxhash_finalize(struct aws_xxhash *hash, struct aws_byte_buf *out) {
    AWS_ERROR_PRECONDITION(hash);
    AWS_ERROR_PRECONDITION(out);

    return hash->impl->finalize_fn(hash->impl->state, out);
}

void aws_xxhash_destroy(struct aws_xxhash *hash) {
    if (hash == NULL) {
        return;
    }

    hash->impl->state_free_fn(hash->impl->state);
    aws_mem_release(hash->allocator, hash);
}

int aws_xxhash64_compute(uint64_t seed, struct aws_byte_cursor data, struct aws_byte_buf *out) {
    XXH64_hash_t hash = XXH64(data.ptr, data.len, seed);
    if (!aws_byte_buf_write_be64(out, hash)) {
        return aws_raise_error(AWS_ERROR_INVALID_BUFFER_SIZE);
    }
    return AWS_OP_SUCCESS;
}

int aws_xxhash3_64_compute(uint64_t seed, struct aws_byte_cursor data, struct aws_byte_buf *out) {
#if defined(AWS_ARCH_INTEL_X64)
    AWS_FATAL_ASSERT(s_x86_XXH3_64_seed_compute);
    XXH64_hash_t hash = s_x86_XXH3_64_seed_compute(data.ptr, data.len, seed);
#else
    XXH64_hash_t hash = XXH3_64bits_withSeed(data.ptr, data.len, seed);
#endif

    if (!aws_byte_buf_write_be64(out, hash)) {
        return aws_raise_error(AWS_ERROR_INVALID_BUFFER_SIZE);
    }
    return AWS_OP_SUCCESS;
}

int aws_xxhash3_128_compute(uint64_t seed, struct aws_byte_cursor data, struct aws_byte_buf *out) {
#if defined(AWS_ARCH_INTEL_X64)
    AWS_FATAL_ASSERT(s_x86_XXH3_128_seed_compute);
    XXH128_hash_t hash = s_x86_XXH3_128_seed_compute(data.ptr, data.len, seed);
#else
    XXH128_hash_t hash = XXH3_128bits_withSeed(data.ptr, data.len, seed);
#endif
    if (out->capacity - out->len < 16) {
        return aws_raise_error(AWS_ERROR_INVALID_BUFFER_SIZE);
    }
    aws_byte_buf_write_be64(out, hash.high64);
    aws_byte_buf_write_be64(out, hash.low64);
    return AWS_OP_SUCCESS;
}
