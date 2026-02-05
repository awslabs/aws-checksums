/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include "external/xxhash.h"
#include <aws/checksums/xxhash.h>
#include <aws/common/logging.h>

typedef int (*xxhash_update_fn)(void *state, struct aws_byte_cursor data);
int s_update_XXH64(void *state, struct aws_byte_cursor data) {
    if (XXH64_update((XXH64_state_t *)state, data.ptr, data.len) == XXH_ERROR) {
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }
    return AWS_OP_SUCCESS;
}

int s_update_XXH3_64(void *state, struct aws_byte_cursor data) {
    if (XXH3_64bits_update((XXH3_state_t *)state, data.ptr, data.len) == XXH_ERROR) {
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }
    return AWS_OP_SUCCESS;
}

int s_update_XXH3_128(void *state, struct aws_byte_cursor data) {
    if (XXH3_128bits_update((XXH3_state_t *)state, data.ptr, data.len) == XXH_ERROR) {
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
    XXH64_hash_t hash = XXH3_64bits_withSeed(data.ptr, data.len, seed);
    if (!aws_byte_buf_write_be64(out, hash)) {
        return aws_raise_error(AWS_ERROR_INVALID_BUFFER_SIZE);
    }
    return AWS_OP_SUCCESS;
}

int aws_xxhash3_128_compute(uint64_t seed, struct aws_byte_cursor data, struct aws_byte_buf *out) {
    XXH128_hash_t hash = XXH3_128bits_withSeed(data.ptr, data.len, seed);
    if (out->capacity - out->len < 16) {
        return aws_raise_error(AWS_ERROR_INVALID_BUFFER_SIZE);
    }
    aws_byte_buf_write_be64(out, hash.high64);
    aws_byte_buf_write_be64(out, hash.low64);
    return AWS_OP_SUCCESS;
}
