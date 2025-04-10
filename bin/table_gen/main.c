/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/stdint.h>
#include <stdio.h>
#include <string.h>
#include "crc_math.h"

static void crc64_init_slice_table_reflected(uint64_t poly, uint64_t table[8][256]) {

    for (uint64_t i = 0; i < 256; i++) {
        uint64_t r = i;
        for (int j = 0; j < 8; j++) {
            if (r & 0x1UL) {
                r >>= 1;
                r ^= poly;
            } else {
                r >>= 1;
            }
        }
        table[0][i] = r;
    }

    for (uint64_t i = 0; i < 256; i++) {
        uint64_t c = table[0][i];
        for (int t = 1; t < 8; t++) {
            c = table[0][c & 0xff] ^ (c >> 8);
            table[t][i] = c;
        }
    }
}

/* Reverse the bytes in a 64-bit word. */
static inline uint64_t rev8(uint64_t a)
{
    uint64_t m;

    m = UINT64_C(0xff00ff00ff00ff);
    a = ((a >> 8) & m) | (a & m) << 8;
    m = UINT64_C(0xffff0000ffff);
    a = ((a >> 16) & m) | (a & m) << 16;
    return a >> 32 | a << 32;
}

/* This function is called once to initialize the CRC-64 table for use on a
   big-endian architecture. */
static void crc64_big_init(uint64_t table[8][256])
{
    unsigned k, n;

    for (k = 0; k < 8; k++)
        for (n = 0; n < 256; n++)
            table[k][n] = rev8(table[k][n]);
}

#define mem_align(alignment) __attribute__ ((aligned (alignment)))

/** Contains the folding constants for CRC32* and CRC64*. */
typedef struct crc_constants_struct {

    // The constants vary depending on whether the CRC is normal or bit-reflected (incompatible, but often faster).
    // We take advantage of the fact that:
    //     (bit-reflected(A) * bit-reflected(B)) << 1 == bit-reflected(A * B)
    // and use alternate constants for bit-reflected CRCs, e.g.

    // poly   degree 32/64 normal or bit-reflected polynomial (implied x^32/x^64)
    // mu32   normal:x^64 / P(x)          reflected:x^(64-1) / P(x)
    // mu64   normal:x^128 / P(x)         reflected:x^(128-1) / P(x)
    // k128   normal:x^128 mod P(x)       reflected:x^(128-1) mod P(x)
    // k192   normal:x^(128+64) mod P(x)  reflected:x^(128+64-1) mod P(x)
    // ...
    // k1024  normal:x^1024 mod P(x)      reflected:x^(1024-1) mod P(x)
    // k1088  normal:x^(1024+64) mod P(x) reflected:x^(1024+64-1) mod P(x)

    // The constants are stored in uint64_t pairs (with the pair ordering reversed depending upon bit reflection).
    // Note that some code is dependent upon the ordering of these struct members (for SIMD sequential memory reads)

    // The kp_2048 constant pairs (k2048 and k2112 [Rush!]) is for folding 2048 bits (256 bytes) in parallel
    // The kp_1536 constant pairs (k1536 and k1600) are for folding 1536 bits (192 bytes) in parallel
    // The kp_1024 constant pairs (k1024 and k1088) are for folding 1024 bits (128 bytes) in parallel
    // The kp_512 constant pairs (k512 and k576) are for folding 512 bits (64 bytes)
    // The kp_384 constant pair (k384 and k448) is for folding 384 bits (48 bytes)
    // The kp_256 constant pair (k256 and k320) is for folding 256 bits (32 bytes)
    // The kp_128 constant pair (k128 and k192) is for folding 128 bits (16 bytes)
    // The constants may also be used when combining the results from parallel folds
    // The k128 constant is also used to fold 64 bits and also compute CRC64 in one step prior to Barrett reduction
    // The kp_trailing array contains specific constants for folding into 1 to 15 bytes of trailing data
    // The k_reduce_32 constants are used for CRC32 only and have atypical bit reflection and constant packing
    // The kp_poly_mu constant pair (poly and mu) are used during Barrett reduction
    // Yeah, it's a Hungarian wart... I prepend "kp_" (for konstant pair) to the number of bits, sorry.

    // Aligned for a single avx512 load
    uint64_t kp_2048[8] mem_align(64);
    uint64_t kp_1536[8] mem_align(64);
    uint64_t kp_1024[8] mem_align(64);
    uint64_t kp_512[8] mem_align(64);

    // Group the 384, 256, and 128 bit constants to make them available for a single avx512 load
    uint64_t kp_384[2];
    uint64_t kp_256[2];
    uint64_t kp_128[2];

    uint64_t kp_trailing[16][2] mem_align(16); // Constants for folding the possible trailing lengths (up to 15 bytes)
    uint64_t k_reduce_32[4] mem_align(16); // Constants for optimizing CRC32/CRC32c modular reduction
    uint64_t kp_poly_mu[2] mem_align(16); // The CRC polynomial and Barrett reduction mu value

    // multiplication table for "shifting" crcs (appending virtual zeroes)
    // There are 16 arrays containing 16 pairs of constants for the possible values of each 4 bit nibble in the shift length
    // The max byte length is 2^61-1 since we need to multiply the length by 8 to convert bytes to bits
    uint64_t shift_factors[16][16][2] mem_align(16);

    uint8_t padding[16]; // Makes the compiler happy

} crc_constants_t;

/* Computes the (bit-reflected) constants for the specified (x^64 bit implied) polynomial. */
static void crc64_compute_reflected_constants(uint64_t POLY64, crc_constants_t cc[1]) {

    __uint128_t X_64 = ((__uint128_t) 1U) << 64;
    __uint128_t POLY65 = X_64 | POLY64;

    memset(cc, 0, sizeof(crc_constants_t));

    // The constant pair ordering is reversed since it simplifies processing for a bit-reflected polynomial
    cc->kp_poly_mu[1] = reflect_64((uint64_t) (POLY65 >> 1));
    cc->kp_poly_mu[0] = reflect_64((uint64_t) ((X_64 | compute_mu(POLY64, 64)) >> 1));

    cc->kp_128[1] = reflect_64((uint64_t) pow_mod_p(POLY65, 2, 128 - 1));
    cc->kp_128[0] = reflect_64((uint64_t) pow_mod_p(POLY65, 2, 128 + 64 - 1));

    cc->kp_256[1] = reflect_64((uint64_t) pow_mod_p(POLY65, 2, 256 - 1));
    cc->kp_256[0] = reflect_64((uint64_t) pow_mod_p(POLY65, 2, 256 + 64 - 1));

    cc->kp_384[1] = reflect_64((uint64_t) pow_mod_p(POLY65, 2, 384 - 1));
    cc->kp_384[0] = reflect_64((uint64_t) pow_mod_p(POLY65, 2, 384 + 64 - 1));

    // Store multiple copies for avx2 and avx512 with vpclmulqdq to support loading 256 and 512 bit registers
    cc->kp_512[1] = cc->kp_512[3] = cc->kp_512[5] = cc->kp_512[7] = reflect_64((uint64_t) pow_mod_p(POLY65, 2, 512 - 1));
    cc->kp_512[0] = cc->kp_512[2] = cc->kp_512[4] = cc->kp_512[6] = reflect_64((uint64_t) pow_mod_p(POLY65, 2, 512 + 64 - 1));

    cc->kp_1024[1] = cc->kp_1024[3] = cc->kp_1024[5] = cc->kp_1024[7] = reflect_64((uint64_t) pow_mod_p(POLY65, 2, 1024 - 1));
    cc->kp_1024[0] = cc->kp_1024[2] = cc->kp_1024[4] = cc->kp_1024[6] = reflect_64((uint64_t) pow_mod_p(POLY65, 2, 1024 + 64 - 1));

    cc->kp_1536[1] = cc->kp_1536[3] = cc->kp_1536[5] = cc->kp_1536[7] = reflect_64((uint64_t) pow_mod_p(POLY65, 2, 1536 - 1));
    cc->kp_1536[0] = cc->kp_1536[2] = cc->kp_1536[4] = cc->kp_1536[6] = reflect_64((uint64_t) pow_mod_p(POLY65, 2, 1536 + 64 - 1));

    cc->kp_2048[1] = cc->kp_2048[3] = cc->kp_2048[5] = cc->kp_2048[7] = reflect_64((uint64_t) pow_mod_p(POLY65, 2, 2048 - 1));
    cc->kp_2048[0] = cc->kp_2048[2] = cc->kp_2048[4] = cc->kp_2048[6] = reflect_64((uint64_t) pow_mod_p(POLY65, 2, 2048 + 64 - 1));

    // Store an array of constants for each possible trailing length from 1-15 bytes
    for (unsigned len = 1; len < 16; len++) {
        unsigned shift = len * 8;
        cc->kp_trailing[len][1] = reflect_64((uint64_t) pow_mod_p(POLY65, 2, 64 + shift - 1));
        cc->kp_trailing[len][0] = reflect_64((uint64_t) pow_mod_p(POLY65, 2, 64 + shift + 64 - 1));
    }

    // Pre-compute "shift" multiplication lookup table for each 4 bit nibble of possible input lengths (in bytes) up to 2^61-1
    for (unsigned nibble = 0; nibble < 16; nibble++) {
        cc->shift_factors[nibble][0][0] = 0; // unused - length zero is a no-op
        cc->shift_factors[nibble][0][1] = 0; // unused - length zero is a no-op
        for (__uint128_t len = 1; len < 16; len++) {
            // Compute the power of x corresponding to the length in each nibble (plus 3 to convert bytes to bits)
            __uint128_t exponent = (len << (nibble * 4 + 3)) - 1; // subtract one to compensate for bit-reflection
            // Determine the factor we will use to multiply (shift) the crc
            cc->shift_factors[nibble][len][1] = reflect_64((uint64_t) pow_mod_p(POLY65, 2, exponent));
            // Determine the factor we will use to fold the low register bits to make it congruent with the shifted crc
            cc->shift_factors[nibble][len][0] = reflect_64((uint64_t) pow_mod_p(POLY65, 2, exponent + 64));
        }
    }

}

int main(void) {

    uint64_t poly = 0xad93d23594c93659;
    uint64_t poly_reflected = reflect_64(poly);

     printf("reflected 0x%016llx,\n", poly_reflected);

    uint64_t table[8][256];
    crc64_init_slice_table_reflected(poly_reflected, table);
    crc64_big_init(table);

    printf("static uint64_t crc64nvme_table[8][256] = {\n");
    printf("\\\n{");
    for (uint32_t j = 0; j < 8; j++) {
        for (uint32_t i = 0; i <= 0xff; i++) {
            if (i % 4 == 0) printf("\n    ");
            printf("0x%016llx", table[j][i]);
            if (i != 0xff) printf(", "); else printf("  ");
            if (i % 4 == 3) printf("// [%u][0x%02x]", j, i-3);
            if (i == 0xff) {
                printf("\n  }");
                if (j < 7) printf(",\n  {");
            }
        }
    }
    printf("\n};\n\n");

    crc_constants_t foo;
    crc64_compute_reflected_constants(poly, &foo);

    printf("checksums_constants aws_checksums_crc64nvme_constants = {\n");
    printf(".x2048 = {\n");
    printf("0x%016llx,\n", foo.kp_2048[0]);
    printf("0x%016llx, // x^2112 mod P(x) / x^2048 mod P(x)\n", foo.kp_2048[1]);
    printf("0x%016llx,\n", foo.kp_2048[2]);
    printf("0x%016llx, // duplicated 3 times to support 64 byte avx512 loads\n", foo.kp_2048[3]);
    printf("0x%016llx,\n", foo.kp_2048[4]);
    printf("0x%016llx,\n", foo.kp_2048[5]);
    printf("0x%016llx,\n", foo.kp_2048[6]);
    printf("0x%016llx\n", foo.kp_2048[7]);
    printf("},\n");

    printf(".x1536 = {\n");
    printf("0x%016llx,\n", foo.kp_1536[0]);
    printf("0x%016llx, // x^1600 mod P(x) / x^1536 mod P(x)\n", foo.kp_1536[1]);
    printf("0x%016llx,\n", foo.kp_1536[2]);
    printf("0x%016llx, // duplicated 3 times to support 64 byte avx512 loads\n", foo.kp_1536[3]);
    printf("0x%016llx,\n", foo.kp_1536[4]);
    printf("0x%016llx,\n", foo.kp_1536[5]);
    printf("0x%016llx,\n", foo.kp_1536[6]);
    printf("0x%016llx\n", foo.kp_1536[7]);
    printf("},\n");

    printf(".x1024 = {\n");
    printf("0x%016llx,\n", foo.kp_1024[0]);
    printf("0x%016llx, // x^1088 mod P(x) / x^1024 mod P(x)\n", foo.kp_1024[1]);
    printf("0x%016llx,\n", foo.kp_1024[2]);
    printf("0x%016llx, // duplicated 3 times to support 64 byte avx512 loads\n", foo.kp_1024[3]);
    printf("0x%016llx,\n", foo.kp_1024[4]);
    printf("0x%016llx,\n", foo.kp_1024[5]);
    printf("0x%016llx,\n", foo.kp_1024[6]);
    printf("0x%016llx\n", foo.kp_1024[7]);
    printf("},\n");

    printf(".x512 = {\n");
    printf("0x%016llx,\n", foo.kp_512[0]);
    printf("0x%016llx, // x^576 mod P(x) / x^512 mod P(x)\n", foo.kp_512[1]);
    printf("0x%016llx,\n", foo.kp_512[2]);
    printf("0x%016llx, // duplicated 3 times to support 64 byte avx512 loads\n", foo.kp_512[3]);
    printf("0x%016llx,\n", foo.kp_512[4]);
    printf("0x%016llx,\n", foo.kp_512[5]);
    printf("0x%016llx,\n", foo.kp_512[6]);
    printf("0x%016llx\n", foo.kp_512[7]);
    printf("},\n");

    printf(".x384 = {0x%016llx, 0x%016llx}, //  x^448 mod P(x) / x^384 mod P(x)\n", foo.kp_384[0], foo.kp_384[1]);
    
    printf(".x256 = {0x%016llx, 0x%016llx}, //  x^320 mod P(x) / x^256 mod P(x)\n", foo.kp_256[0], foo.kp_256[1]);

    printf(".x128 = {0x%016llx, 0x%016llx}, //  x^192 mod P(x) / x^128 mod P(x)\n", foo.kp_128[0], foo.kp_128[1]);

    printf(".mu_poly = {0x%016llx, 0x%016llx}, // Barrett mu / polynomial P(x) (bit-reflected)\n", foo.kp_poly_mu[0], foo.kp_poly_mu[1]);

    printf(".trailing = \n {");
    printf("// trailing input constants for data lengths of 1-15 bytes \n");
    printf("{0x%016llx, 0x%016llx}, // 1 trailing bytes:  x^72 mod P(x) /   x^8 mod P(x)\n", foo.kp_trailing[1][0], foo.kp_trailing[1][1]);
    printf("{0x%016llx, 0x%016llx}, // 2 trailing bytes:  x^80 mod P(x) /  x^15 mod P(x)\n", foo.kp_trailing[2][0], foo.kp_trailing[2][1]);
    printf("{0x%016llx, 0x%016llx}, // 3 trailing bytes:  x^88 mod P(x) /  x^24 mod P(x)\n", foo.kp_trailing[3][0], foo.kp_trailing[3][1]);
    printf("{0x%016llx, 0x%016llx}, // 4 trailing bytes:  x^96 mod P(x) /  x^32 mod P(x)\n", foo.kp_trailing[4][0], foo.kp_trailing[4][1]);
    printf("{0x%016llx, 0x%016llx}, // 5 trailing bytes: x^104 mod P(x) /  x^40 mod P(x)\n", foo.kp_trailing[5][0], foo.kp_trailing[5][1]);
    printf("{0x%016llx, 0x%016llx}, // 6 trailing bytes: x^110 mod P(x) /  x^48 mod P(x)\n", foo.kp_trailing[6][0], foo.kp_trailing[6][1]);
    printf("{0x%016llx, 0x%016llx}, // 7 trailing bytes: x^110 mod P(x) /  x^56 mod P(x)\n", foo.kp_trailing[7][0], foo.kp_trailing[7][1]);
    printf("{0x%016llx, 0x%016llx}, // 8 trailing bytes: x^120 mod P(x) /  x^64 mod P(x)\n", foo.kp_trailing[8][0], foo.kp_trailing[8][1]);
    printf("{0x%016llx, 0x%016llx}, // 9 trailing bytes: x^128 mod P(x) /  x^72 mod P(x)\n", foo.kp_trailing[9][0], foo.kp_trailing[9][1]);
    printf("{0x%016llx, 0x%016llx}, // 10 trailing bytes: x^144 mod P(x) /  x^80 mod P(x)\n", foo.kp_trailing[10][0], foo.kp_trailing[10][1]);
    printf("{0x%016llx, 0x%016llx}, // 11 trailing bytes: x^152 mod P(x) /  x^88 mod P(x)\n", foo.kp_trailing[11][0], foo.kp_trailing[11][1]);
    printf("{0x%016llx, 0x%016llx}, // 12 trailing bytes: x^160 mod P(x) /  x^96 mod P(x)\n", foo.kp_trailing[12][0], foo.kp_trailing[12][1]);
    printf("{0x%016llx, 0x%016llx}, // 13 trailing bytes: x^168 mod P(x) / x^104 mod P(x)\n", foo.kp_trailing[13][0], foo.kp_trailing[13][1]);
    printf("{0x%016llx, 0x%016llx}, // 14 trailing bytes: x^176 mod P(x) / x^112 mod P(x)\n", foo.kp_trailing[14][0], foo.kp_trailing[14][1]);
    printf("{0x%016llx, 0x%016llx}, // 15 trailing bytes: x^184 mod P(x) / x^120 mod P(x)\n", foo.kp_trailing[15][0], foo.kp_trailing[15][1]);
    
    return 0;
}
