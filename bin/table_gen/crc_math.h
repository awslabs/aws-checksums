/*
 * crc_math.h
 *
 * A collection of utility functions used for polynomial modular arithmetic.
 */

#ifndef LIBS3CHECKSUMSNATIVE_CRC_MATH_H_
#define LIBS3CHECKSUMSNATIVE_CRC_MATH_H_

#include <stdint.h>

#pragma GCC diagnostic ignored "-Wunused-function"

/** Reflects the bits in a 32 bit integer. */
__attribute__ ((noinline))
static uint32_t reflect_32(uint32_t b) {
    // See: Hacker's Delight Chapter 7.
    b = ((b >> 1) & 0x55555555U) | ((b & 0x55555555U) << 1);
    b = ((b >> 2) & 0x33333333U) | ((b & 0x33333333U) << 2);
    b = ((b >> 4) & 0x0F0F0F0FU) | ((b & 0x0F0F0F0FU) << 4);
    b = ((b >> 8) & 0x00FF00FFU) | ((b & 0x00FF00FFU) << 8);
    b = (b >> 16) | (b << 16);
    return b;
}

/** Reflects the bits in a 64 bit integer. */
static inline uint64_t reflect_64(uint64_t b) {
    uint64_t hi = reflect_32((uint32_t) (b >> 32));
    uint64_t lo = reflect_32((uint32_t) b);
    return (lo << 32) | hi;
/*
    // Alternate approach: see Hacker's Delight Chapter 7.
    b = (b & 0xFFFFFFFF00000000UL) >> 32 | (b & 0x00000000FFFFFFFFUL) << 32;
    b = (b & 0xFFFF0000FFFF0000UL) >> 16 | (b & 0x0000FFFF0000FFFFUL) << 16;
    b = (b & 0xFF00FF00FF00FF00UL) >> 8 | (b & 0x00FF00FF00FF00FFUL) << 8;
    b = (b & 0xF0F0F0F0F0F0F0F0UL) >> 4 | (b & 0x0F0F0F0F0F0F0F0FUL) << 4;
    b = (b & 0xCCCCCCCCCCCCCCCCUL) >> 2 | (b & 0x3333333333333333UL) << 2;
    b = (b & 0xAAAAAAAAAAAAAAAAUL) >> 1 | (b & 0x5555555555555555UL) << 1;
    return b;
*/
}

/** Return the position of the most significant set bit - returns -1 if x == 0 */
static inline int msb_128(const __uint128_t x) {
    // __builtin_clzll returns the number of leading zeros (from MSB end) - undefined for x==0 !!!
    if (x >> 64) {
        return 127 - __builtin_clzll((uint64_t) (x >> 64));
    }
    return x ? 63 - __builtin_clzll((uint64_t) x) : -1;
}

/** Return the position of the least significant set bit - returns -1 if x == 0 */
static inline int lsb_128(const __uint128_t x) {
    // __builtin_ctzll returns the number of trailing zeros (from LSB end) - undefined for x==0 !!!
    if ((uint64_t) x) {
        return __builtin_ctzll((uint64_t) x);
    }
    return (x >> 64) ? 64 + __builtin_ctzll((uint64_t) (x >> 64)) : -1;
}

/** Returns 2^n (127 >= n >= 0) */
static inline __uint128_t pow_2(const int n) {
    return ((__uint128_t) 1) << n;
}

/** Returns a 128-bit mask with only the highest bit set matching the highest bit from the provided value (undefined for zero) */
static inline __uint128_t msb_mask(const __uint128_t x) {
    return pow_2(msb_128(x));
}

/**
 * Performs carryless multiplication of two polynomial factors and returns their (unreduced) product.
 * This is a slow reference function for initialization and/or testing.
 */
static __uint128_t clmul(uint64_t a, uint64_t b) {
    if (!a || !b) return 0;
    uint64_t x = (b < a) ? b : a;
    __uint128_t y = (b < a) ? a : b;
    __uint128_t product = 0;
    while (x) {
        if (x & 1) {
            product ^= y;
        }
        x >>= 1;
        y <<= 1;
    }
    return product;
}

/**
 * Performs Barrett modular reduction
 * @param degree the nominal degree of the field generating polynomial e.g. 32 for CRC32, 64 for CRC64
 * @param poly the field generating polynomial with the highest bit (i.e. x^32 or x^64) implied
 * @param mu the value of mu used in Barrett modular reduction
 * @param input the input value to reduce
 * @return the reduced value
 * This is a slow reference function for initialization and/or testing.
 */
static uint64_t reduce_normal(int degree, uint64_t poly, uint64_t mu, __uint128_t input) {
    __uint64_t mask = (uint64_t) ((__uint128_t) 1UL << degree) - 1;
    __uint128_t mul_by_mu = clmul((uint64_t) ((input >> degree) & mask), mu);
    __uint128_t mul_by_poly = clmul((uint64_t) (((input ^ mul_by_mu) >> degree) & mask), poly & mask);
    return (uint64_t) ((input ^ mul_by_poly) & mask);
}

/**
 * Performs Barrett modular reduction on a bit-reflected input value
 * @param degree the nominal degree of the field generating polynomial e.g. 32 for CRC32, 64 for CRC64
 * @param poly the bit-reflected field generating polynomial with the highest bit (i.e. x^32 or x^64) implied
 * @param mu the value of mu used in Barrett modular reduction
 * @param input the input value to reduce
 * @return the reduced value
 * This is a slow reference function for initialization and/or testing.
 */
static uint64_t reduce_reflected(int degree, uint64_t poly, uint64_t mu, __uint128_t input) {
    __uint64_t mask = (uint64_t) ((__uint128_t) 1UL << degree) - 1;
    __uint128_t mul_by_mu = clmul((uint64_t) (input & mask), mu);
    __uint128_t mul_by_poly = clmul((uint64_t) (mul_by_mu & mask), poly & mask);
    return (uint64_t) ((((input ^ mul_by_poly) >> degree) ^ mul_by_mu) & mask);
}

/**
 * Multiply two bit-reflected polynomials (a and b) modulo the specified bit-reflected field generating poly.
 * The bit-reflected poly must be full degree (e.g. 65-bits for a degree 64 field)
 * This is a slow reference function for initialization and/or testing.
 */
static __uint128_t multiply_mod_p_reflected(const __uint128_t poly, __uint128_t a, __uint128_t b) {

    if (!a || !b) return 0;
    __uint128_t hi_bit = msb_mask(poly) >> 1;
    // Choose the factor with the most trailing zero bits so the loop can exit soonest
    int swap = lsb_128(b) > lsb_128(a);
    __uint128_t x = swap ? b : a;
    __uint128_t y = swap ? a : b;
    __uint128_t product = 0;
    // Loop through the bits in the x factor
    while (x) {
        // Every iteration will keep doubling the y factor using right shifts (it's bit-reflected)
        if (y & 1) {
            // But when the field degree bit is set, first reduce using the field polynomial
            y ^= poly;
        }
        y >>= 1;

        if (x & hi_bit) {
            product ^= y;
            // Clear the bit in x so the loop will quit when there are no more bits set
            x ^= hi_bit;
        }

        // Advance to test the next lowest bit in x
        hi_bit >>= 1;
    }
    return product;
}

/**
 * Multiply two polynomials (a and b) modulo the specified field generating poly.
 * The (non bit-reflected) poly must be full degree (e.g. 65-bits for a degree 64 field)
 * This is a slow reference function for initialization and/or testing.
 */
static __uint128_t multiply_mod_p(const __uint128_t poly, __uint128_t a, __uint128_t b) {

    if (!a || !b) return 0;
    __uint128_t mask = msb_mask(poly);
    __uint128_t x = (b < a) ? b : a;
    __uint128_t y = (b < a) ? a : b;
    __uint128_t product = 0;
    // Loop through the bits in the x factor
    while (x) {
        if (x & 1) {
            product ^= y;
        }

        // Every iteration will keep doubling the y factor using left shifts
        y <<= 1;
        if (y & mask) {
            // reduce with the field polynomial when the shift causes the field degree bit to be set
            y ^= poly;
        }

        // Advance loop to test the next highest bit in x
        x >>= 1;
    }
    return product;
}

/**
 * Raise a base to a power modulo the field polynomial using the square and multiply method.
 * The (non bit-reflected) poly must be full degree (e.g. 65-bits for a degree 64 field)
 * e.g. pow_mod_p(P(x), 2, 256) to obtain x^256 mod P(x)
 * This is a slow reference function for initialization and/or testing.
 */
static __uint128_t pow_mod_p(const __uint128_t poly, __uint128_t base, __uint128_t exp) {

    if (!exp) return 1;
    __uint128_t result = 1;
    while (exp) {
        if (exp & 1) {
            result = multiply_mod_p(poly, base, result);
        }
        exp >>= 1;
        if (exp) {
            base = multiply_mod_p(poly, base, base);
        }
    }
    return result;
}

/**
 * Compute x^(2n) / P(x) where P(x) is a polynomial of degree n.
 * This is the mu constant required for Barrett reduction.
 * Note: the x^n bit in the polynomial should NOT be set!
 * e.g. although a degree 64 poly is 65 bits long, just pass the low 64 bits
 */
__attribute__ ((noinline))
static __uint128_t compute_mu(__uint128_t poly, int degree) {

    __uint128_t mu = 0;
    __uint128_t accumulator = poly << degree;
    __uint128_t mask = ((__uint128_t) 1) << (2 * degree - 1);
    for (int i = degree - 1; i >= 0; i--) {
        if (accumulator & mask) {
            mu ^= ((__uint128_t) 1) << i;
            accumulator ^= mask;
            accumulator ^= (poly << i);
        }
        mask >>= 1;
    }
    return mu;
}

#endif // LIBS3CHECKSUMSNATIVE_CRC_MATH_H_
