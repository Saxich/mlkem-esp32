/* ntt.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 *
 * Original source: wolfSSL/wolfssl — wc_mlkem_poly.c
 *   https://github.com/wolfSSL/wolfssl
 * Modified by Michal Saxa, 2026 — extracted NTT and polynomial arithmetic,
 *   adapted for standalone ML-KEM implementation on ESP32;
 *   added wrappers for inline Xtensa assembly multiply operations.
 * See CREDITS.md for full attribution.
 */

#include <stdint.h>
#include "params.h"
#include "ntt.h"
#include "reduce.h"
#include "xt_mul.h"
#ifdef TIMEANALYSIS
    #include "../test_time/timing.h"
#endif


/*************************************************
* Name:        ntt
*
* Description: Inplace number-theoretic transform (NTT) in Rq.
*              input is in standard order, output is in bitreversed order
*
* Arguments:   - int16_t r[256]: pointer to input/output vector of elements of Zq
**************************************************/


/* Zetas for NTT. */
const int16_t zetas[MLKEM_N / 2] = {
    2285, 2571, 2970, 1812, 1493, 1422,  287,  202,
    3158,  622, 1577,  182,  962, 2127, 1855, 1468,
     573, 2004,  264,  383, 2500, 1458, 1727, 3199,
    2648, 1017,  732,  608, 1787,  411, 3124, 1758,
    1223,  652, 2777, 1015, 2036, 1491, 3047, 1785,
     516, 3321, 3009, 2663, 1711, 2167,  126, 1469,
    2476, 3239, 3058,  830,  107, 1908, 3082, 2378,
    2931,  961, 1821, 2604,  448, 2264,  677, 2054,
    2226,  430,  555,  843, 2078,  871, 1550,  105,
     422,  587,  177, 3094, 3038, 2869, 1574, 1653,
    3083,  778, 1159, 3182, 2552, 1483, 2727, 1119,
    1739,  644, 2457,  349,  418,  329, 3173, 3254,
     817, 1097,  603,  610, 1322, 2044, 1864,  384,
    2114, 3193, 1218, 1994, 2455,  220, 2142, 1670,
    2144, 1799, 2051,  794, 1819, 2475, 2459,  478,
    3221, 3021,  996,  991,  958, 1869, 1522, 1628
};       

/* Number-Theoretic Transform.
 *
 * FIPS 203, Algorithm 9: NTT(f)
 * Computes the NTT representation f_hat of the given polynomial f element of
 * R_q.
 *   1: f_hat <- f
 *   2: i <- 1
 *   3: for (len <- 128; len >= 2; len <- len/2)
 *   4:     for (start <- 0; start < 256; start <- start + 2.len)
 *   5:         zeta <- zetas^BitRev_7(i) mod q
 *   6:         i <- i + 1
 *   7:         for (j <- start; j < start + len; j++)
 *   8:             t <- zeta.f[j+len]
 *   9:             f_hat[j+len] <- f_hat[j] - t
 *  10:             f_hat[j] <- f_hat[j] - t
 *  11:         end for
 *  12:     end for
 *  13: end for
 *  14: return f_hat
 *
 * @param  [in, out]  r  Polynomial to transform.
 */
void ntt(int16_t r[256]) {
    unsigned int len, k = 1, j, start;

    /* Layer 1: len = 128 */
    {
        int16_t zeta = zetas[k++];
        for (j = 0; j < 128; ++j) {
            int32_t p = XT_MUL16S(zeta, r[j + 128]);
            int16_t t = MLKEM_MONT_RED(p);
            int16_t rj = r[j];
            r[j + 128] = rj - t;
            r[j]       = rj + t;
        }
    }

    /* Layers 2..6: len = 64 down to 4 */
    for (len = 64; len >= 4; len >>= 1) {
        for (start = 0; start < 256; start = j + len) {
            int16_t zeta = zetas[k++];
            for (j = start; j < start + len; ++j) {
                int32_t p = XT_MUL16S(zeta, r[j + len]);
                int16_t t = MLKEM_MONT_RED(p);
                int16_t rj = r[j];
                r[j + len] = rj - t;
                r[j]       = rj + t;
            }
        }
    }

    /* Layer 7 (len=2): merge Barrett reduction — eliminates separate O(N) pass */
    for (start = 0; start < 256; start = j + 2) {
        int16_t zeta = zetas[k++];
        j = start;
        /* Unrolled: exactly 2 iterations when len==2 */
        {
            int32_t p0 = XT_MUL16S(zeta, r[j + 2]);
            int16_t t0 = MLKEM_MONT_RED(p0);
            int16_t rj0 = r[j];
            int16_t hi0 = rj0 - t0;
            int16_t lo0 = rj0 + t0;

            int32_t p1 = XT_MUL16S(zeta, r[j + 3]);
            int16_t t1 = MLKEM_MONT_RED(p1);
            int16_t rj1 = r[j + 1];
            int16_t hi1 = rj1 - t1;
            int16_t lo1 = rj1 + t1;

            r[j]     = MLKEM_BARRETT_RED(lo0);
            r[j + 1] = MLKEM_BARRETT_RED(lo1);
            r[j + 2] = MLKEM_BARRETT_RED(hi0);
            r[j + 3] = MLKEM_BARRETT_RED(hi1);
        }
        j += 2;
    }
}

/*************************************************
* Name:        invntt_tomont
*
* Description: Inplace inverse number-theoretic transform in Rq and
*              multiplication by Montgomery factor 2^16.
*              Input is in bitreversed order, output is in standard order
*
* Arguments:   - int16_t r[256]: pointer to input/output vector of elements of Zq
**************************************************/

/* Zetas for inverse NTT. */
const int16_t zetas_inv[MLKEM_N / 2] = {
    1701, 1807, 1460, 2371, 2338, 2333,  308,  108,
    2851,  870,  854, 1510, 2535, 1278, 1530, 1185,
    1659, 1187, 3109,  874, 1335, 2111,  136, 1215,
    2945, 1465, 1285, 2007, 2719, 2726, 2232, 2512,
      75,  156, 3000, 2911, 2980,  872, 2685, 1590,
    2210,  602, 1846,  777,  147, 2170, 2551,  246,
    1676, 1755,  460,  291,  235, 3152, 2742, 2907,
    3224, 1779, 2458, 1251, 2486, 2774, 2899, 1103,
    1275, 2652, 1065, 2881,  725, 1508, 2368,  398,
     951,  247, 1421, 3222, 2499,  271,   90,  853,
    1860, 3203, 1162, 1618,  666,  320,    8, 2813,
    1544,  282, 1838, 1293, 2314,  552, 2677, 2106,
    1571,  205, 2918, 1542, 2721, 2597, 2312,  681,
     130, 1602, 1871,  829, 2946, 3065, 1325, 2756,
    1861, 1474, 1202, 2367, 3147, 1752, 2707,  171,
    3127, 3042, 1907, 1836, 1517,  359,  758, 1441
};

/* Inverse Number-Theoretic Transform.
 *
 * FIPS 203, Algorithm 10: NTT^-1(f_hat)
 * Computes the polynomial f element of R_q that corresponds to the given NTT
 * representation f element of T_q.
 *   1: f <- f_hat
 *   2: i <- 127
 *   3: for (len <- 2; len <= 128 ; len <- 2.len)
 *   4:     for (start <- 0; start < 256; start <- start + 2.len)
 *   5:         zeta <- zetas^BitRev_7(i) mod q
 *   6:         i <- i - 1
 *   7:         for (j <- start; j < start + len; j++)
 *   8:             t <- f[j]
 *   9:             f[j] < t + f[j + len]
 *  10:             f[j + len] <- zeta.(f[j+len] - t)
 *  11:         end for
 *  12:     end for
 *  13: end for
 *  14: f <- f.3303 mod q
 *  15: return f
 *
 * @param  [in, out]  r  Polynomial to transform.
 */
void invntt(int16_t r[256]) {
    unsigned int len;
    unsigned int k;
    unsigned int j;
    unsigned int start;
    int16_t zeta;
    int16_t zeta2;

    k = 0;

    /* Layer 1 (len=2): unrolled + merged Barrett reduction */
    for (start = 0; start < MLKEM_N; start = j + 2) {
        zeta = zetas_inv[k++];
        j = start;
        /* Unrolled: exactly 2 iterations when len==2 */
        {
            int16_t rj0  = r[j];
            int16_t rjl0 = r[j + 2];
            int16_t t0   = rj0 + rjl0;
            int16_t d0   = rj0 - rjl0;
            int16_t rj1  = r[j + 1];
            int16_t rjl1 = r[j + 3];
            int16_t t1   = rj1 + rjl1;
            int16_t d1   = rj1 - rjl1;
            r[j]     = MLKEM_BARRETT_RED(t0);
            r[j + 1] = MLKEM_BARRETT_RED(t1);
            r[j + 2] = MLKEM_MONT_RED(XT_MUL16S(zeta, d0));
            r[j + 3] = MLKEM_MONT_RED(XT_MUL16S(zeta, d1));
        }
        j += 2;
    }

    /* Layers 2..6: len = 4 up to MLKEM_N/4 */
    for (len = 4; len <= MLKEM_N / 4; len <<= 1) {
        for (start = 0; start < MLKEM_N; start = j + len) {
            zeta = zetas_inv[k++];
            for (j = start; j < start + len; ++j) {
                int16_t rj  = r[j];
                int16_t rjl = r[j + len];
                int16_t t   = rj + rjl;
                r[j]        = MLKEM_BARRETT_RED(t);
                rjl         = rj - rjl;
                r[j + len]  = MLKEM_MONT_RED(XT_MUL16S(zeta, rjl));
            }
        }
    }

    /* Final layer (len=128) + scaling: merge zeta2 multiply into same pass */
    zeta  = zetas_inv[126];
    zeta2 = zetas_inv[127];
    for (j = 0; j < MLKEM_N / 2; ++j) {
        int16_t rj  = r[j];
        int16_t rjl = r[j + MLKEM_N / 2];
        int16_t t   = rj + rjl;
        int16_t d   = rj - rjl;
        r[j]               = MLKEM_MONT_RED(XT_MUL16S(zeta2, t));
        r[j + MLKEM_N / 2] = MLKEM_MONT_RED(XT_MUL16S(zeta2, MLKEM_MONT_RED(XT_MUL16S(zeta, d))));
    }
}

/* Multiplication of polynomials in Zq[X]/(X^2-zeta).
 *
 * Used for multiplication of elements in Rq in NTT domain.
 *
 * FIPS 203, Algorithm 12: BaseCaseMultiply(a0, a1, b0, b1, zeta)
 * Computes the product of two degree-one polynomials with respect to a
 * quadratic modulus.
 *   1: c0 <- a0.b0 + a1.b1.zeta
 *   2: c1 <- a0.b1 + a1.b0
 *   3: return (c0, c1)
 *
 * @param  [out]  r     Result polynomial.
 * @param  [in]   a     First factor.
 * @param  [in]   b     Second factor.
 * @param  [in]   zeta  Integer defining the reduction polynomial.
 */
void basemul(int16_t* r, const int16_t* a, const int16_t* b, int16_t zeta)
{
    int16_t a0 = a[0];
    int16_t a1 = a[1];
    int16_t b0 = b[0];
    int16_t b1 = b[1];

    /* Step 1: c0 = a0*b0 + a1*b1*zeta */
    int32_t p1 = XT_MUL16S(a0, b0);
    int16_t r0 = MLKEM_MONT_RED(XT_MUL16S(a1, b1));
    int32_t p2 = XT_MUL16S(zeta, r0);
    r[0] = MLKEM_MONT_RED(p2 + p1);

    /* Step 2: c1 = a0*b1 + a1*b0 */
    r[1] = MLKEM_MONT_RED(XT_MUL16S(a0, b1) + XT_MUL16S(a1, b0));
}



/*************************************************
* Name:        basemul_acc
*
* Description: Multiplication of polynomials in Zq[X]/(X^2-zeta)
*              used for multiplication of elements in Rq in NTT domain.
*              Accumulating version
*              Recreated from mlkem-c-embedded basemul_acc to fit wolfSSL style.
*
* Arguments:   - int16_t* r: pointer to the output polynomial
*              - const int16_t* a: pointer to the first factor
*              - const int16_t* b: pointer to the second factor
*              - int16_t zeta: integer defining the reduction polynomial
**************************************************/
void basemul_acc(int16_t* r, const int16_t* a, const int16_t* b, int16_t zeta)
{
    int16_t a0 = a[0];
    int16_t a1 = a[1];
    int16_t b0 = b[0];
    int16_t b1 = b[1];

    /* Step 1: c0 = a0*b0 + a1*b1*zeta */
    int32_t p1 = XT_MUL16S(a0, b0);
    int16_t t  = MLKEM_MONT_RED(XT_MUL16S(a1, b1));
    int32_t p2 = XT_MUL16S(zeta, t);
    r[0] += MLKEM_MONT_RED(p2 + p1);

    /* Step 2: c1 = a0*b1 + a1*b0 */
    r[1] += MLKEM_MONT_RED(XT_MUL16S(a0, b1) + XT_MUL16S(a1, b0));
}