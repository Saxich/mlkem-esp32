/*
 * Polynomial vector operations — compression, encoding, arithmetic
 *
 * Licensing: GPL-3.0-or-later (see LICENSE and CREDITS.md)
 *
 * Base implementation: pq-crystals/kyber reference (CC0-1.0 OR Apache-2.0)
 *   https://github.com/pq-crystals/kyber
 *   Used under CC0-1.0.
 *
 * Additions:
 *   - cmp_polyvec_compress (SPEED_CODE): created to support cmp_indcpa_enc;
 *     inspired by cmp_poly_packcompress from pq-code-package/mlkem-c-embedded.
 *   - polyvec_basemul_acc_montgomery: added for data type compatibility with
 *     the NTT and polynomial functions derived from wolfSSL.
 *
 * See CREDITS.md for full attribution.
 */

#include <stdint.h>
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#ifdef TIMEANALYSIS
    #include "../test_time/timing.h"
#endif
#include "reduce.h"



/*************************************************
* Name:        polyvec_ntt
*
* Description: Apply forward NTT to all elements of a vector of polynomials
*
* Arguments:   - polyvec *r: pointer to in/output vector of polynomials
**************************************************/
void polyvec_ntt(polyvec *r)
{
  unsigned int i;
  for(i=0;i<MLKEM_K;i++)
    poly_ntt(&r->vec[i]);
}

/*************************************************
* Name:        polyvec_tobytes
*
* Description: Serialize vector of polynomials
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                            (needs space for MLKEM_POLYVECBYTES)
*              - const polyvec *a: pointer to input vector of polynomials
**************************************************/
void polyvec_tobytes(uint8_t r[MLKEM_POLYVECBYTES], const polyvec *a)
{
  unsigned int i;
  for(i=0;i<MLKEM_K;i++)
    poly_tobytes(r+i*MLKEM_POLYBYTES, &a->vec[i]);
}

#ifdef SPEED_CODE
/*************************************************
* Name:        polyvec_compress
*
* Description: Compress and serialize vector of polynomials
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                            (needs space for MLKEM_POLYVECCOMPRESSEDBYTES)
*              - const polyvec *a: pointer to input vector of polynomials
**************************************************/
void polyvec_compress(uint8_t r[MLKEM_POLYVECCOMPRESSEDBYTES], const polyvec *a)
{

  unsigned int i,j,k;

#if (MLKEM_POLYVECCOMPRESSEDBYTES == (MLKEM_K * 352))
  uint16_t t[8];
  for(i=0;i<MLKEM_K;i++) {
    for(j=0;j<MLKEM_N/8;j++) {
      for(k=0;k<8;k++) {
        t[k]  = a->vec[i].coeffs[8*j+k];
        t[k] += ((int16_t)t[k] >> 15) & MLKEM_Q;
        t[k]  = ((((uint32_t)t[k] << 11) + MLKEM_Q/2)/MLKEM_Q) & 0x7ff;
      }

      r[ 0] = (t[0] >>  0);
      r[ 1] = (t[0] >>  8) | (t[1] << 3);
      r[ 2] = (t[1] >>  5) | (t[2] << 6);
      r[ 3] = (t[2] >>  2);
      r[ 4] = (t[2] >> 10) | (t[3] << 1);
      r[ 5] = (t[3] >>  7) | (t[4] << 4);
      r[ 6] = (t[4] >>  4) | (t[5] << 7);
      r[ 7] = (t[5] >>  1);
      r[ 8] = (t[5] >>  9) | (t[6] << 2);
      r[ 9] = (t[6] >>  6) | (t[7] << 5);
      r[10] = (t[7] >>  3);
      r += 11;
    }
  }
#elif (MLKEM_POLYVECCOMPRESSEDBYTES == (MLKEM_K * 320))
  uint16_t t[4];
  for(i=0;i<MLKEM_K;i++) {
    for(j=0;j<MLKEM_N/4;j++) {
      for(k=0;k<4;k++) {
        t[k]  = a->vec[i].coeffs[4*j+k];
        t[k] += ((int16_t)t[k] >> 15) & MLKEM_Q;
        t[k]  = ((((uint32_t)t[k] << 10) + MLKEM_Q/2)/ MLKEM_Q) & 0x3ff;
      }

      r[0] = (t[0] >> 0);
      r[1] = (t[0] >> 8) | (t[1] << 2);
      r[2] = (t[1] >> 6) | (t[2] << 4);
      r[3] = (t[2] >> 4) | (t[3] << 6);
      r[4] = (t[3] >> 2);
      r += 5;
    }
  }
#else
#error "MLKEM_POLYVECCOMPRESSEDBYTES needs to be in {320*MLKEM_K, 352*MLKEM_K}"
#endif

}

/*************************************************
* Name:        cmp_polyvec_compress
*
* Description: Compress and serialize vector of polynomials
*
* Arguments:   - const uint8_t *r: pointer to output byte array
*                            (needs space for MLKEM_POLYVECCOMPRESSEDBYTES)
*              - const polyvec *a: pointer to input vector of polynomials
**************************************************/
int cmp_polyvec_compress(const uint8_t r[MLKEM_POLYVECCOMPRESSEDBYTES], const polyvec *a)
{
  unsigned char rc = 0;
  unsigned int i, j, k;
#if (MLKEM_POLYVECCOMPRESSEDBYTES == (MLKEM_K * 352))
  uint16_t t[8];
  for (i = 0; i < MLKEM_K; i++) {
    for (j = 0; j < MLKEM_N / 8; j++) {
      for (k = 0; k < 8; k++) {
        t[k]  = a->vec[i].coeffs[8*j+k];
        t[k] += ((int16_t)t[k] >> 15) & MLKEM_Q;
        t[k]  = ((((uint32_t)t[k] << 11) + MLKEM_Q/2) / MLKEM_Q) & 0x7ff;
      }
      uint8_t b0  = (t[0] >> 0);
      uint8_t b1  = (t[0] >> 8) | (t[1] << 3);
      uint8_t b2  = (t[1] >> 5) | (t[2] << 6);
      uint8_t b3  = (t[2] >> 2);
      uint8_t b4  = (t[2] >> 10) | (t[3] << 1);
      uint8_t b5  = (t[3] >> 7)  | (t[4] << 4);
      uint8_t b6  = (t[4] >> 4)  | (t[5] << 7);
      uint8_t b7  = (t[5] >> 1);
      uint8_t b8  = (t[5] >> 9)  | (t[6] << 2);
      uint8_t b9  = (t[6] >> 6)  | (t[7] << 5);
      uint8_t b10 = (t[7] >> 3);
      rc |= r[ 0] ^ b0;
      rc |= r[ 1] ^ b1;
      rc |= r[ 2] ^ b2;
      rc |= r[ 3] ^ b3;
      rc |= r[ 4] ^ b4;
      rc |= r[ 5] ^ b5;
      rc |= r[ 6] ^ b6;
      rc |= r[ 7] ^ b7;
      rc |= r[ 8] ^ b8;
      rc |= r[ 9] ^ b9;
      rc |= r[10] ^ b10;
      r += 11;
    }
  }
#elif (MLKEM_POLYVECCOMPRESSEDBYTES == (MLKEM_K * 320))
  uint16_t t[4];
  for (i = 0; i < MLKEM_K; i++) {
    for (j = 0; j < MLKEM_N / 4; j++) {
      for (k = 0; k < 4; k++) {
        t[k]  = a->vec[i].coeffs[4*j+k];
        t[k] += ((int16_t)t[k] >> 15) & MLKEM_Q;
        t[k]  = ((((uint32_t)t[k] << 10) + MLKEM_Q/2) / MLKEM_Q) & 0x3ff;
      }
      uint8_t b0 = (t[0] >> 0);
      uint8_t b1 = (t[0] >> 8) | (t[1] << 2);
      uint8_t b2 = (t[1] >> 6) | (t[2] << 4);
      uint8_t b3 = (t[2] >> 4) | (t[3] << 6);
      uint8_t b4 = (t[3] >> 2);
      rc |= r[0] ^ b0;
      rc |= r[1] ^ b1;
      rc |= r[2] ^ b2;
      rc |= r[3] ^ b3;
      rc |= r[4] ^ b4;
      r += 5;
    }
  }
#else
#error "MLKEM_POLYVECCOMPRESSEDBYTES needs to be in {320*MLKEM_K, 352*MLKEM_K}"
#endif
  return rc;
}


/*************************************************
* Name:        polyvec_decompress
*
* Description: De-serialize and decompress vector of polynomials;
*              approximate inverse of polyvec_compress
*
* Arguments:   - polyvec *r:       pointer to output vector of polynomials
*              - const uint8_t *a: pointer to input byte array
*                                  (of length MLKEM_POLYVECCOMPRESSEDBYTES)
**************************************************/
void polyvec_decompress(polyvec *r, const uint8_t a[MLKEM_POLYVECCOMPRESSEDBYTES])
{

  unsigned int i,j,k;

#if (MLKEM_POLYVECCOMPRESSEDBYTES == (MLKEM_K * 352))
  uint16_t t[8];
  for(i=0;i<MLKEM_K;i++) {
    for(j=0;j<MLKEM_N/8;j++) {
      t[0] = (a[0] >> 0) | ((uint16_t)a[ 1] << 8);
      t[1] = (a[1] >> 3) | ((uint16_t)a[ 2] << 5);
      t[2] = (a[2] >> 6) | ((uint16_t)a[ 3] << 2) | ((uint16_t)a[4] << 10);
      t[3] = (a[4] >> 1) | ((uint16_t)a[ 5] << 7);
      t[4] = (a[5] >> 4) | ((uint16_t)a[ 6] << 4);
      t[5] = (a[6] >> 7) | ((uint16_t)a[ 7] << 1) | ((uint16_t)a[8] << 9);
      t[6] = (a[8] >> 2) | ((uint16_t)a[ 9] << 6);
      t[7] = (a[9] >> 5) | ((uint16_t)a[10] << 3);
      a += 11;

      for(k=0;k<8;k++)
        r->vec[i].coeffs[8*j+k] = ((uint32_t)(t[k] & 0x7FF)*MLKEM_Q + 1024) >> 11;
    }
  }
#elif (MLKEM_POLYVECCOMPRESSEDBYTES == (MLKEM_K * 320))
  uint16_t t[4];
  for(i=0;i<MLKEM_K;i++) {
    for(j=0;j<MLKEM_N/4;j++) {
      t[0] = (a[0] >> 0) | ((uint16_t)a[1] << 8);
      t[1] = (a[1] >> 2) | ((uint16_t)a[2] << 6);
      t[2] = (a[2] >> 4) | ((uint16_t)a[3] << 4);
      t[3] = (a[3] >> 6) | ((uint16_t)a[4] << 2);
      a += 5;

      for(k=0;k<4;k++)
        r->vec[i].coeffs[4*j+k] = ((uint32_t)(t[k] & 0x3FF)*MLKEM_Q + 512) >> 10;
    }
  }
#else
#error "MLKEM_POLYVECCOMPRESSEDBYTES needs to be in {320*MLKEM_K, 352*MLKEM_K}"
#endif

}

/*************************************************
* Name:        polyvec_frombytes
*
* Description: De-serialize vector of polynomials;
*              inverse of polyvec_tobytes
*
* Arguments:   - uint8_t *r:       pointer to output byte array
*              - const polyvec *a: pointer to input vector of polynomials
*                                  (of length MLKEM_POLYVECBYTES)
**************************************************/
void polyvec_frombytes(polyvec *r, const uint8_t a[MLKEM_POLYVECBYTES])
{
  unsigned int i;
  for(i=0;i<MLKEM_K;i++)
    poly_frombytes(&r->vec[i], a+i*MLKEM_POLYBYTES);
}

/*************************************************
* Name:        polyvec_invntt_tomont
*
* Description: Apply inverse NTT to all elements of a vector of polynomials
*              and multiply by Montgomery factor 2^16
*
* Arguments:   - polyvec *r: pointer to in/output vector of polynomials
**************************************************/
void polyvec_invntt_tomont(polyvec *r)
{
  unsigned int i;
  for(i=0;i<MLKEM_K;i++)
    poly_invntt_tomont(&r->vec[i]);
}


/*************************************************
 * Name:        polyvec_basemul_acc_montgomery_inside
 *
 * Description: Computes the inner product of two polynomial vectors in the
 *              NTT domain and accumulates the result into r. The first
 *              element initializes r, subsequent elements accumulate.
 *              Results are in Montgomery representation (scaled by 2^-16).
 *
 * Arguments:   - int16_t *r:        pointer to output polynomial
 *              - const int16_t *a:  pointer to first input vector (flat array)
 *              - const int16_t *b:  pointer to second input vector (flat array)
 *              - unsigned int k:    number of polynomials in the vector
 **************************************************/
static void polyvec_basemul_acc_montgomery_inside(int16_t* r, const int16_t* a, const int16_t* b, unsigned int k)
{
    unsigned int i;
    poly_basemul_montgomery(r, a, b);
    for (i = 1; i < k; i++)
        poly_basemul_acc_montgomery(r, a + i*MLKEM_N, b + i*MLKEM_N);
}

/*************************************************
 * Name:        polyvec_basemul_acc_montgomery
 *
 * Description: Wrapper around polyvec_basemul_acc_montgomery_inside for use
 *              with polyvec and poly types. Computes the inner product of two
 *              polynomial vectors in the NTT domain with MLKEM_K elements.
 *              Results are in Montgomery representation (scaled by 2^-16).
 *
 * Arguments:   - poly *r:           pointer to output polynomial
 *              - const polyvec *a:  pointer to first input polynomial vector
 *              - const polyvec *b:  pointer to second input polynomial vector
 **************************************************/
void polyvec_basemul_acc_montgomery(poly *r, const polyvec *a, const polyvec *b)
{
  polyvec_basemul_acc_montgomery_inside(r->coeffs, a->vec->coeffs, b->vec->coeffs, MLKEM_K);
}


/*************************************************
* Name:        polyvec_reduce
*
* Description: Applies Barrett reduction to each coefficient
*              of each element of a vector of polynomials;
*              for details of the Barrett reduction see comments in reduce.c
*
* Arguments:   - polyvec *r: pointer to input/output polynomial
**************************************************/
void polyvec_reduce(polyvec *r)
{
  unsigned int i;
  for(i=0;i<MLKEM_K;i++)
    poly_reduce(&r->vec[i]);
}

/*************************************************
* Name:        polyvec_add
*
* Description: Add vectors of polynomials
*
* Arguments: - polyvec *r: pointer to output vector of polynomials
*            - const polyvec *a: pointer to first input vector of polynomials
*            - const polyvec *b: pointer to second input vector of polynomials
**************************************************/
void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b)
{
  unsigned int i;
  for(i=0;i<MLKEM_K;i++)
    poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
}

#endif //(SPEED_CODE)