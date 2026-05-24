/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef NTT_H
#define NTT_H

#include <stdint.h>
#include "params.h"
#include "reduce.h"
#include "xt_mul.h"

#define zetas MLKEM_NAMESPACE(zetas)
extern const int16_t zetas[128];

#define ntt MLKEM_NAMESPACE(ntt)
void ntt(int16_t poly[256]);

#define invntt MLKEM_NAMESPACE(invntt)
void invntt(int16_t poly[256]);

/* basemul / basemul_acc are inlined into hot loops (poly_basemul_montgomery,
 * poly_basemul_acc_montgomery) to eliminate call/ret pairs
 * and let the scheduler interleave their bodies. */
#define basemul MLKEM_NAMESPACE(basemul)
static inline __attribute__((always_inline))
void basemul(int16_t* r, const int16_t* a, const int16_t* b, int16_t zeta)
{
    int16_t a0 = a[0];
    int16_t a1 = a[1];
    int16_t b0 = b[0];
    int16_t b1 = b[1];

    /* c0 = a0*b0 + a1*b1*zeta */
    int32_t p1 = XT_MUL16S(a0, b0);
    int16_t r0 = MLKEM_MONT_RED(XT_MUL16S(a1, b1));
    int32_t p2 = XT_MUL16S(zeta, r0);
    r[0] = MLKEM_MONT_RED(p2 + p1);

    /* c1 = a0*b1 + a1*b0 */
    r[1] = MLKEM_MONT_RED(XT_MUL16S(a0, b1) + XT_MUL16S(a1, b0));
}

#define basemul_acc MLKEM_NAMESPACE(basemul_acc)
static inline __attribute__((always_inline))
void basemul_acc(int16_t* r, const int16_t* a, const int16_t* b, int16_t zeta)
{
    int16_t a0 = a[0];
    int16_t a1 = a[1];
    int16_t b0 = b[0];
    int16_t b1 = b[1];

    /* c0 += a0*b0 + a1*b1*zeta */
    int32_t p1 = XT_MUL16S(a0, b0);
    int16_t t  = MLKEM_MONT_RED(XT_MUL16S(a1, b1));
    int32_t p2 = XT_MUL16S(zeta, t);
    r[0] += MLKEM_MONT_RED(p2 + p1);

    /* c1 += a0*b1 + a1*b0 */
    r[1] += MLKEM_MONT_RED(XT_MUL16S(a0, b1) + XT_MUL16S(a1, b0));
}

#endif
