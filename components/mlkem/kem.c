/*
 * ML-KEM key encapsulation mechanism — crypto_kem_keypair, crypto_kem_enc, crypto_kem_dec
 *
 * Licensing: GPL-3.0-or-later (see LICENSE and CREDITS.md)
 *
 * Base implementation: pq-crystals/kyber reference (CC0-1.0 OR Apache-2.0)
 *   https://github.com/pq-crystals/kyber
 *
 * Modifications:
 *
 *   - randombytes() calls replaced with a wrapper over the ESP32 hardware TRNG,
 *     substituting the reference PRNG with a true random number generator.
 *
 *   - Ciphertext comparison in crypto_kem_dec avoids allocating a temporary
 *     MLKEM_CIPHERTEXTBYTES-sized buffer; instead the comparison result is
 *     passed directly into indcpa_enc via the cmp_out parameter. Idea and
 *     code based on pq-code-package/mlkem-c-embedded.
 *
 *   - Sensitive intermediate buffers are explicitly zeroed after use per
 *     FIPS 203 Section 3.3. Approach inspired by pq-code-package/mlkem-native.
 *
 * See CREDITS.md for full attribution.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "params.h"
#include "kem.h"
#include "indcpa.h"
#include "verify.h"
#include "symmetric.h"
#include "randombytes.h"
#include "stdio.h"

/*************************************************
* Name:        crypto_kem_keypair_derand
*
* Description: Deterministic keypair generation for KAT
*              Uses provided randomness instead of RNG
*
* Arguments:   - uint8_t *pk: output public key
*              - uint8_t *sk: output secret key  
*              - const uint8_t *coins: input randomness (d || z)
**************************************************/
int crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins)
{   

    // only dualcore can fail
    if (indcpa_keypair(pk, sk, coins) != 0)
        return 1;
    // Copy public key to secret key
    memcpy(sk+MLKEM_INDCPA_SECRETKEYBYTES, pk, MLKEM_PUBLICKEYBYTES);
    // Hash public key
    hash_h(sk + MLKEM_SECRETKEYBYTES - 2*MLKEM_SYMBYTES, pk, MLKEM_PUBLICKEYBYTES);
    /* Value z for pseudo-random output on reject */
    memcpy(sk + MLKEM_SECRETKEYBYTES - MLKEM_SYMBYTES, coins + MLKEM_SYMBYTES, MLKEM_SYMBYTES);

    return 0;
}


/*************************************************
* Name:        crypto_kem_keypair
*
* Description: Generates public and private key
*              for CCA-secure MLKEM key encapsulation mechanism
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                (an already allocated array of MLKEM_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key
*                (an already allocated array of MLKEM_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_keypair(uint8_t *pk,
                       uint8_t *sk)
{
  int ret;

  VAR_ALIGN uint8_t coins[2*MLKEM_SYMBYTES];
  esp_randombytes(coins, 2*MLKEM_SYMBYTES);
  ret = crypto_kem_keypair_derand(pk, sk, coins);


  // Nicenie medzivysledkov podla FIP203 Section 3.3
  buffer_zeroize(coins, sizeof(coins));

  return ret;
}

/*************************************************
* Name:        crypto_kem_enc_derand
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - uint8_t *ct: pointer to output cipher text
*                (an already allocated array of MLKEM_CIPHERTEXTBYTES bytes)
*              - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of MLKEM_SSBYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                (an already allocated array of MLKEM_PUBLICKEYBYTES bytes)
*              - const uint8_t *coins: pointer to input randomness
*                (an already allocated array filled with MLKEM_SYMBYTES random bytes)
**
* Returns 0 (success)
**************************************************/

int crypto_kem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins)
{   
    int ret = 0; // 0 to switch properly inside indcpa_enc

    VAR_ALIGN uint8_t buf[2*MLKEM_SYMBYTES]; //nerobilo zmen
    /* Will contain key, coins */
    VAR_ALIGN uint8_t kr[2*MLKEM_SYMBYTES]; //nerobilo zmen
    
    // Copy message (m is the random input for KAT)
    memcpy(buf, coins, MLKEM_SYMBYTES);
    
    // Multitarget countermeasure for coins + contributory KEM
    hash_h(buf + MLKEM_SYMBYTES, pk, MLKEM_PUBLICKEYBYTES);
    hash_g(kr, buf, 2*MLKEM_SYMBYTES);
    
    /* coins are in kr+MLKEM_SYMBYTES */
    //check return value if dualcore
    ret = indcpa_enc(ct, buf, pk, kr + MLKEM_SYMBYTES, ENC_ONLY);
    
    // Hash ciphertext -> treba zero
    // hash_h(kr + MLKEM_SYMBYTES, ct, MLKEM_CIPHERTEXTBYTES);
    
    memcpy(ss, kr, MLKEM_SYMBYTES);

    // Nicenie medzivysledkov podla FIP203 Section 3.3
    buffer_zeroize(buf, sizeof(buf));
    buffer_zeroize(kr, sizeof(kr));

    return ret;
}

/*************************************************
* Name:        crypto_kem_enc
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - uint8_t *ct: pointer to output cipher text
*                (an already allocated array of MLKEM_CIPHERTEXTBYTES bytes)
*              - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of MLKEM_SSBYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                (an already allocated array of MLKEM_PUBLICKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_enc(uint8_t *ct,
                   uint8_t *ss,
                   const uint8_t *pk)
{
  // init_rng();
  int ret = 0;

  VAR_ALIGN uint8_t coins[MLKEM_SYMBYTES];
  esp_randombytes(coins, MLKEM_SYMBYTES);

  /* Don't release system RNG output */
  // hash_h(buf, buf, MLKEM_SYMBYTES)s  // buf[32:64] = H(pk)
  ret = crypto_kem_enc_derand(ct, ss, pk, coins);


  // Nicenie medzivysledkov podla FIP203 Section 3.3
  buffer_zeroize(coins, sizeof(coins));

  // shutdown_rng(); 
  return ret;
}

/*************************************************
* Name:        crypto_kem_dec
*
* Description: Generates shared secret for given
*              cipher text and private key
*
* Arguments:   - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of MLKEM_SSBYTES bytes)
*              - uint8_t *ct: pointer to input cipher text
*                (an already allocated array of MLKEM_CIPHERTEXTBYTES bytes)
                 ct je posielane do cmp verzie indcpa_enc, ktory zdielany s normalnym, const ct je zarucena nizsie volanymi funkciami
*              - const uint8_t *sk: pointer to input private key
*                (an already allocated array of MLKEM_SECRETKEYBYTES bytes)
*
* Returns 0.
*
* On failure, ss will contain a pseudo-random value.
**************************************************/
int crypto_kem_dec(uint8_t *ss,
                   uint8_t *ct,
                   const uint8_t *sk)
{

  // nepouziva rng

  int ret = 0;
  unsigned int cmp_out;
  VAR_ALIGN uint8_t buf[2*MLKEM_SYMBYTES]; //ide do hash_g a load64
  /* Will contain key, coins */
  VAR_ALIGN uint8_t kr[2*MLKEM_SYMBYTES]; //ide do hash_g a store64
  // #ifdef SPEED_CODE
    // uint8_t cmp[MLKEM_CIPHERTEXTBYTES];
  // #endif
  const uint8_t *pk = sk+MLKEM_INDCPA_SECRETKEYBYTES;

  // 1. Decrypt ciphertext to get m'
  ret = indcpa_dec(buf, ct, sk);   // buf = m'

  if (ret != 0) {
    buffer_zeroize(buf, sizeof(buf));
    buffer_zeroize(kr, sizeof(kr));
    return ret;
  }

  /* Multitarget countermeasure for coins + contributory KEM */
  // 2. Append public key hash h
  memcpy(buf+MLKEM_SYMBYTES, sk+MLKEM_SECRETKEYBYTES-2*MLKEM_SYMBYTES, MLKEM_SYMBYTES);   // buf = m' || h
  // 3. Derive key and re-encryption coins
  hash_g(kr, buf, 2*MLKEM_SYMBYTES);  // kr = G(m' || h) = (K, r')

  // #ifdef SPEED_CODE
  // //   // 4. Re-encrypt to verify
  // //   //check return value if dualcore
  //   fail = indcpa_enc(cmp, buf, pk, kr+MLKEM_SYMBYTES, ENC_ONLY);   // cmp = Enc(m', r')
  // //   // 5. Constant-time comparison
  //   cmp_out = verify(ct, cmp, MLKEM_CIPHERTEXTBYTES);  // fail = (ct != cmp)
  // #else // (STACK_CODE)
    // pqm4 approach, prepisuje povodny cp, compilator warning, setri 1088b
    /* coins are in kr+MLKEM_SYMBYTES */
    ret = indcpa_enc(ct, buf, pk, kr + MLKEM_SYMBYTES, ENC_CMP(cmp_out));
  // #endif


  /* overwrite coins in kr with H(c) */
  // hash_h(kr+MLKEM_SYMBYTES, ct, MLKEM_CIPHERTEXTBYTES);
  // 6. Compute rejection key (always)
  rkprf(ss,sk+MLKEM_SECRETKEYBYTES-MLKEM_SYMBYTES,ct);  // ss = K̄ = PRF(z || ct)

  /* Overwrite pre-k with z on re-encryption failure */
  // cmov(kr, sk+MLKEM_SECRETKEYBYTES-MLKEM_SYMBYTES, MLKEM_SYMBYTES, fail);
  // equevalen with
  // 7. Constant-time selection
  cmov(ss,kr,MLKEM_SYMBYTES,!cmp_out);

  // Nicenie medzivysledkov podla FIP203 Section 3.3
  buffer_zeroize(buf, sizeof(buf));
  buffer_zeroize(kr, sizeof(kr));

  return ret;
}


