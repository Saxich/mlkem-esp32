/*
 * Constant-time comparison and buffer zeroization
 *
 * Licensing: GPL-3.0-or-later (see LICENSE and CREDITS.md)
 *
 * Base implementation: pq-crystals/kyber reference (CC0-1.0 OR Apache-2.0)
 *   https://github.com/pq-crystals/kyber
 *   Used under CC0-1.0.
 *
 * Modifications:
 *   - cmov: adapted to allow substitution of the conditional move with an
 *     inline Xtensa assembly implementation for ESP32 (Xtensa LX6).
 *   - buffer_zeroize: added for explicit zeroing of sensitive intermediate
 *     buffers per FIPS 203 Section 3.3.
 *
 * See CREDITS.md for full attribution.
 */

#include <stddef.h>
#include <stdint.h>
#include "verify.h"

/*************************************************
* Name:        cmov
*
* Description: Copy len bytes from x to r if b is 1;
*              don't modify x if b is 0. Requires b to be in {0,1};
*              assumes two's complement representation of negative integers.
*              Runs in constant time.
*
* Arguments:   uint8_t *r:       pointer to output byte array
*              const uint8_t *x: pointer to input byte array
*              size_t len:       Amount of bytes to be copied
*              uint8_t b:        Condition bit; has to be in {0,1}
**************************************************/
void cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b)
{
#if defined(__GNUC__) || defined(__clang__)
    __asm__("" : "+r"(b));
#endif
    uint32_t mask = -(uint32_t)b;
#ifdef __XTENSA__
    size_t i = 0;

    // head: align r to 4 bytes
    while (len && ((uintptr_t)r & 3)) {
        *r ^= mask & (*r ^ *x);
        r++; x++; len--;
    }

    // body: 4 bytes at a time
    size_t n = len >> 2;
    uint32_t *rp = (uint32_t*)r;
    const uint32_t *xp = (const uint32_t*)x;
    for(i = 0; i < n; i++) {
        uint32_t rv, xv;
        __asm__ __volatile__(
            "l32i %0, %2, 0\n"
            "l32i %1, %3, 0\n"
            "xor  %1, %1, %0\n"
            "and  %1, %1, %4\n"
            "xor  %0, %0, %1\n"
            "s32i %0, %2, 0\n"
            : "=&r"(rv), "=&r"(xv)
            : "r"(rp+i), "r"(xp+i), "r"(mask)
            : "memory"
        );
    }

    // tail: remaining bytes
    for(i = n*4; i < len; i++)
        r[i] ^= mask & (r[i] ^ x[i]);
#else
    for(size_t i = 0; i < len; i++)
        r[i] ^= mask & (r[i] ^ x[i]);
#endif
}

/*************************************************
* Name:        cmov_int16
*
* Description: Copy input v to *r if b is 1, don't modify *r if b is 0. 
*              Requires b to be in {0,1};
*              Runs in constant time.
*
* Arguments:   int16_t *r:       pointer to output int16_t
*              int16_t v:        input int16_t 
*              uint8_t b:        Condition bit; has to be in {0,1}
**************************************************/
void cmov_int16(int16_t *r, int16_t v, uint16_t b)
{
  b = -b;
  *r ^= b & ((*r) ^ v);
}


/*************************************************
 * Name:        buffer_zeroize
 *
 * Description: Force-zeroize a buffer using volatile writes to prevent
 *              compiler from optimizing away the zeroing of sensitive
 *              intermediate values. Processes memory in three phases:
 *              unaligned head bytes, aligned 32-bit words, and remaining
 *              tail bytes for maximum throughput on 32-bit architectures.
 *
 * Arguments:   - void *ptr:    pointer to buffer to be zeroed
 *              - size_t len:   number of bytes to zero
 *
 * Specification: FIPS 203, Section 3.3 - Destruction of intermediate values
 **************************************************/
void buffer_zeroize(void *ptr, size_t len)
{
    uintptr_t addr = (uintptr_t)ptr;
    volatile uint32_t *p32;
    volatile uint8_t  *p8;

    // head: align to 4 bytes
    p8 = (volatile uint8_t *)ptr;
    while (len && (addr & 3)) {
        *p8++ = 0;
        addr++;
        len--;
    }

    // body: 4 bytes at a time
    p32 = (volatile uint32_t *)p8;
    while (len >= 4) {
        *p32++ = 0;
        len -= 4;
    }

    // tail: remaining bytes
    p8 = (volatile uint8_t *)p32;
    while (len--) *p8++ = 0;
}