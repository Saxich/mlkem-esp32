#include <stddef.h>
#include <stdint.h>
#include "params.h"
#include "symmetric.h"
#include "fips202.h"
#include <string.h>

/*
 * SHAKE-based symmetric primitives for ML-KEM
 *
 * Licensing: GPL-3.0-or-later (see LICENSE and CREDITS.md)
 *
 * Base implementation: pq-crystals/kyber reference (CC0-1.0 OR Apache-2.0)
 *   https://github.com/pq-crystals/kyber
 *   Used under CC0-1.0.
 *
 * shake128_absorb and shake256_prf absorb directly into the sponge state
 * without intermediate buffers, enabled by the bufferless XKCP absorption
 * interface in fips202.c.
 * shake256_rkprf cannot use direct absorption because its input (key || ciphertext)
 * exceeds a single SHAKE256 rate block, requiring a temporary buffer.
 *
 * See CREDITS.md for full attribution.
 */

/*************************************************
* Name:        shake128_absorb
*
* Description: Absorb step of the SHAKE128 specialized for the Kyber context.
*              Absorbs seed and two additional bytes directly without
*              allocating a temporary buffer.
*
* Arguments:   - keccak_state *state: pointer to (uninitialized) output Keccak state
*              - const uint8_t *seed: pointer to MLKEM_SYMBYTES input to be absorbed into state
*              - uint8_t x: additional byte of input
*              - uint8_t y: additional byte of input
**************************************************/
void shake128_absorb(keccak_state *state,
                     const uint8_t seed[MLKEM_SYMBYTES],
                     uint8_t x,
                     uint8_t y)
{
    shake128_absorb_direct(state, seed, x, y);
}

/*************************************************
* Name:        shake256_prf
*
* Description: Usage of SHAKE256 as a PRF, concatenates secret and public input
*              and then generates outlen bytes of SHAKE256 output.
*              Absorbs key and nonce directly without allocating a temporary buffer.
*
* Arguments:   - uint8_t *out: pointer to output
*              - size_t outlen: number of requested output bytes
*              - const uint8_t *key: pointer to the key (of length MLKEM_SYMBYTES)
*              - uint8_t nonce: single-byte nonce (public PRF input)
**************************************************/
void shake256_prf(uint8_t *out, size_t outlen,
                  const uint8_t key[MLKEM_SYMBYTES], uint8_t nonce)
{
    shake256_prf_direct(out, outlen, key, nonce);
}

/*************************************************
* Name:        shake256_rkprf
*
* Description: Usage of SHAKE256 as a PRF for implicit rejection in decapsulation.
*              Concatenates a 32-byte key with the ciphertext and produces
*              MLKEM_SSBYTES of output. Absorbs inputs directly without
*              allocating a temporary buffer, saving MLKEM_SYMBYTES +
*              MLKEM_CIPHERTEXTBYTES bytes of stack space.
*
* Arguments:   - uint8_t *out:         pointer to output (MLKEM_SSBYTES bytes)
*              - const uint8_t *key:   pointer to the key (MLKEM_SYMBYTES bytes)
*              - const uint8_t *input: pointer to the ciphertext (MLKEM_CIPHERTEXTBYTES bytes)
**************************************************/
void shake256_rkprf(uint8_t *out, const uint8_t *key, const uint8_t *input)
{
    keccak_state state;
    uint8_t buf[MLKEM_SYMBYTES + MLKEM_CIPHERTEXTBYTES];
    memcpy(buf, key, MLKEM_SYMBYTES);
    memcpy(buf + MLKEM_SYMBYTES, input, MLKEM_CIPHERTEXTBYTES);
    shake256_absorb_once(&state, buf, sizeof(buf));
    shake256_squeeze(out, MLKEM_SSBYTES, &state);
}