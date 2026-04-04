/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SYMMETRIC_H
#define SYMMETRIC_H

#include <stddef.h>
#include <stdint.h>
#include "params.h"

#include "fips202.h"

typedef keccak_state xof_state;

#define shake128_absorb MLKEM_NAMESPACE(mlkem_shake128_absorb)
void shake128_absorb(keccak_state *s,
                           const uint8_t seed[MLKEM_SYMBYTES],
                           uint8_t x,
                           uint8_t y);

#define shake256_prf MLKEM_NAMESPACE(mlkem_shake256_prf)
void shake256_prf(uint8_t *out, size_t outlen, const uint8_t key[MLKEM_SYMBYTES], uint8_t nonce);


#define shake256_rkprf MLKEM_NAMESPACE(shake256_rkprf)
void shake256_rkprf(uint8_t *out, const uint8_t *key, const uint8_t *input);

#define XOF_BLOCKBYTES SHAKE128_RATE

#define hash_h(OUT, IN, INBYTES) sha3_256(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) sha3_512(OUT, IN, INBYTES)
#define xof_absorb(STATE, SEED, X, Y) shake128_absorb(STATE, SEED, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define prf(OUT, OUTBYTES, KEY, NONCE) shake256_prf(OUT, OUTBYTES, KEY, NONCE)
#define kdf(OUT, IN, INBYTES) shake256(OUT, MLKEM_SSBYTES, IN, INBYTES)
#define rkprf(OUT, KEY, INPUT) shake256_rkprf(OUT, KEY, INPUT)


#endif /* SYMMETRIC_H */
