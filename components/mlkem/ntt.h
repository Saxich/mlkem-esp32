/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef NTT_H
#define NTT_H

#include <stdint.h>
#include "params.h"

#define zetas MLKEM_NAMESPACE(zetas)
extern const int16_t zetas[128];

#define ntt MLKEM_NAMESPACE(ntt)
void ntt(int16_t poly[256]);

#define invntt MLKEM_NAMESPACE(invntt)
void invntt(int16_t poly[256]);

#define basemul MLKEM_NAMESPACE(basemul)
// void basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta);
void basemul(int16_t* r, const int16_t* a, const int16_t* b, int16_t zeta);

#define basemul_acc MLKEM_NAMESPACE(basemul_acc)
void basemul_acc(int16_t* r, const int16_t* a, const int16_t* b, int16_t zeta);

#define basemul_cached MLKEM_NAMESPACE(basemul_cached)
void basemul_cached(int16_t* r, const int16_t* a, const int16_t* b, int16_t b1_zeta);

#define basemul_acc_cached MLKEM_NAMESPACE(basemul_acc_cached)
void basemul_acc_cached(int16_t* r, const int16_t* a, const int16_t* b, int16_t b1_zeta);

#endif
