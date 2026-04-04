/*
 * Matrix generation and matrix-vector multiplication
 *
 * Licensing: GPL-3.0-or-later (see LICENSE and CREDITS.md)
 *
 * SPEED variant — pq-crystals/kyber reference (CC0-1.0 OR Apache-2.0)
 *   https://github.com/pq-crystals/kyber
 *   Functions originate from the reference implementation, relocated from
 *   indcpa.c into this file for clarity. Matrix A and its transpose AT are
 *   generated element-wise via gen_a_elements, enabling flexible reuse across
 *   security parameter sets and parallel generation across both ESP32 cores.
 *
 * STACK variant — pq-code-package/mlkem-c-embedded (Apache-2.0 OR CC0-1.0)
 *   https://github.com/pq-code-package/mlkem-c-embedded
 *   Performs memory-efficient matrix-vector multiplication row by row; at
 *   any point only a single element of A (or A^T) exists in memory,
 *   significantly reducing peak stack usage.
 *
 * Buffer zeroing:
 *   Sensitive intermediate buffers are explicitly zeroed after use per
 *   FIPS 203 Section 3.3. Approach inspired by pq-code-package/mlkem-native.
 *   https://github.com/pq-code-package/mlkem-native
 *
 * See CREDITS.md for full attribution.
 */


#include "ntt.h"
#include "poly.h"
#include "polyvec.h"
#include "symmetric.h"
#include "matrix.h"
#include "verify.h"




#ifdef STACK_CODE

//odstranenie int add rozdelenim matacc_inner pridava ~0.3% rychlosti, neimplementovane
static void doublebasemul(int16_t r[4], const int16_t b[4], const int16_t a[4], int k, int add) {
    if (!add) {
        basemul(r, a, b, zetas[64 + k]);
        basemul(&r[2], &a[2], &b[2], -zetas[64 + k]);
    } else {
        basemul_acc(r, a, b, zetas[64 + k]);
        basemul_acc(&r[2], &a[2], &b[2], -zetas[64 + k]);
    }
}

/*************************************************
 * Name:        matacc_inner
 *
 * Description: Generates a single polynomial of A or A^T on-the-fly via XOF
 *              and rejection sampling, multiplies it with the input polynomial
 *              b using doublebasemul in groups of 4 coefficients, and
 *              accumulates the result into r. Intermediate buffers are
 *              zeroized after use per FIPS 203 §3.3.
 *
 * Arguments:   - poly *r:                    pointer to output polynomial to accumulate in
 *              - const poly *b:              pointer to input polynomial to multiply with
 *              - unsigned char i:            index < MLKEM_K of the row of A or A^T
 *              - unsigned char j:            index < MLKEM_K of the column of A or A^T
 *              - const unsigned char *seed:  pointer to the public seed used to generate A
 *              - int transposed:             if non-zero, generate A^T instead of A
 *              - int add:                    if non-zero, accumulate into r; if zero, initialize r first
 **************************************************/
static void matacc_inner(poly *r, const poly *b, unsigned char i, unsigned char j, const unsigned char *seed, int transposed, int add) {
    xof_state state; //tu neni aligned
    unsigned int ctr, ctr2;
    VAR_ALIGN int16_t ax[4];
    VAR_ALIGN uint8_t buf[XOF_BLOCKBYTES];

    if (transposed) {
        xof_absorb(&state, seed, i, j);
    } else {
        xof_absorb(&state, seed, j, i);
    }

    ctr = 0;
    ctr2 = 0;
    do {
        xof_squeezeblocks(buf, 1, &state);
        unsigned int pos;
        uint16_t val0, val1;

        pos = 0;
        while (ctr < MLKEM_N && pos + 3 <= XOF_BLOCKBYTES) {
            val0 = ((buf[pos + 0] >> 0) | ((uint16_t)buf[pos + 1] << 8)) & 0xFFF;
            val1 = ((buf[pos + 1] >> 4) | ((uint16_t)buf[pos + 2] << 4)) & 0xFFF;
            pos += 3;

            if (val0 < MLKEM_Q) {
                ax[ctr2] = val0;
                ctr++;
                ctr2++;
            }
            if (ctr2 == 4) {
                doublebasemul(r->coeffs + ctr - 4, b->coeffs + ctr - 4, ax, (ctr - 4) / 4, add);
                ctr2 = 0;
            }

            if (ctr < MLKEM_N && val1 < MLKEM_Q) {
                ax[ctr2] = val1;
                ctr++;
                ctr2++;
            }
            if (ctr2 == 4) {
                doublebasemul(r->coeffs + ctr - 4, b->coeffs + ctr - 4, ax, (ctr - 4) / 4, add);
                ctr2 = 0;
            }
        }

    } while (ctr < MLKEM_N);

    // Nicenie medzivysledkov podla FIP203 Section 3.3
    buffer_zeroize(ax,    sizeof(ax));
    buffer_zeroize(buf,   sizeof(buf));
    buffer_zeroize(&state, sizeof(state));
}

/*************************************************
 * Name:        matacc
 *
 * Description: Multiplies a row of A or A^T, generated on-the-fly,
 *              with a vector of polynomials and accumulates into the result.
 *
 * Arguments:   - poly *r:                    pointer to output polynomial to accumulate in
 *              - polyvec *b:                 pointer to input vector of polynomials to multiply with
 *              - unsigned char i:            index < MLKEM_K of the row of A or A^T
 *              - const unsigned char *seed:  pointer to the public seed used to generate A
 *              - int transposed:             if non-zero, generate A^T instead of A
 **************************************************/
void matacc(poly *r, const polyvec *b, unsigned char i, const unsigned char *seed, int transposed) {
    int j = 0;
    matacc_inner(r, &b->vec[j], i, j, seed, transposed, 0);
    for (j = 1; j < MLKEM_K; j++) {
        matacc_inner(r, &b->vec[j], i, j, seed, transposed, 1);
    }
}

/*************************************************
 * Name:        matacc_xtreme
 *
 * Description: Generates secret vector s on-the-fly from coins, converts each
 *              element to NTT domain, then multiplies a row of A or A^T with
 *              it and accumulates into the result. Avoids storing the full
 *              secret polyvec by reusing a single working polynomial buffer.
 *
 * Arguments:   - poly *r:                    pointer to output polynomial to accumulate in
 *              - poly *mag:                  pointer to working buffer for the current secret poly
 *              - unsigned char i:            index < MLKEM_K of the row of A or A^T
 *              - const unsigned char *seed:  pointer to the public seed used to generate A
 *              - const unsigned char *coins: pointer to randomness used to generate the secret
 *              - int transposed:             if non-zero, generate A^T instead of A
 **************************************************/
void matacc_xtreme(poly *r, poly *mag, unsigned char i, const unsigned char *seed, const unsigned char *coins, int transposed){
    int j = 0;
    poly_getnoise_eta1(mag, coins, j); 
    poly_ntt(mag);
    matacc_inner(r, mag, i, j, seed, transposed, 0);  
    for (j = 1; j < MLKEM_K; j++) {
        poly_getnoise_eta1(mag, coins, j); 
        poly_ntt(mag);
        matacc_inner(r, mag, i, j, seed, transposed, 1);
    }
}
#endif // STACK_CODE


// migrovane z indcpa.c, gen_matrix postaven na referencnom kode 
#ifdef SPEED_CODE

/*************************************************
* Name:        rej_uniform
*
* Description: Run rejection sampling on uniform random bytes to generate
*              uniform random integers mod q
*
* Arguments:   - int16_t *r: pointer to output buffer
*              - unsigned int len: requested number of 16-bit integers (uniform mod q)
*              - const uint8_t *buf: pointer to input buffer (assumed to be uniformly random bytes)
*              - unsigned int buflen: length of input buffer in bytes
*
* Returns number of sampled 16-bit integers (at most len)
**************************************************/
static unsigned int rej_uniform(int16_t *r,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen)
{
  unsigned int ctr, pos;
  uint16_t val0, val1;

  ctr = pos = 0;
  while(ctr < len && pos + 3 <= buflen) {
    val0 = ((buf[pos+0] >> 0) | ((uint16_t)buf[pos+1] << 8)) & 0xFFF;
    val1 = ((buf[pos+1] >> 4) | ((uint16_t)buf[pos+2] << 4)) & 0xFFF;
    pos += 3;

    if(val0 < MLKEM_Q)
      r[ctr++] = val0;
    if(ctr < len && val1 < MLKEM_Q)
      r[ctr++] = val1;
  }

  return ctr;
}

#define GEN_MATRIX_NBLOCKS ((12*MLKEM_N/8*(1 << 12)/MLKEM_Q + XOF_BLOCKBYTES)/XOF_BLOCKBYTES)

/*************************************************
* Name:        gen_matrix_elements
*
* Description: Deterministically generate a subset of matrix A (or its
*              transpose) entries from a seed. Elements are indexed linearly
*              from start_element to stop_element (inclusive), where element
*              idx corresponds to row idx/MLKEM_K and column idx%MLKEM_K.
*              Entries are polynomials that look uniformly random, generated
*              via rejection sampling on the output of a XOF.
*              Intermediate buffers are zeroized after use per FIPS 203 §3.3.
*
* Arguments:   - polyvec *a:              pointer to output matrix A
*              - const uint8_t *seed:     pointer to input seed (MLKEM_SYMBYTES)
*              - const int start_element: first linear element index to generate
*              - const int stop_element:  last linear element index to generate
*              - int transposed:          if non-zero, generate A^T instead of A
**************************************************/
void gen_matrix_elements(polyvec *a, const uint8_t seed[MLKEM_SYMBYTES], const int start_element, const int stop_element, int transposed)
{
    VAR_ALIGN uint8_t buf[GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES]; 
    xof_state state;

    for (uint8_t idx = start_element; idx <= stop_element; idx++) {
        unsigned int i = idx / MLKEM_K;
        unsigned int j = idx % MLKEM_K;
        unsigned int ctr, buflen;

        if (transposed)
            xof_absorb(&state, seed, i, j);
        else
            xof_absorb(&state, seed, j, i);

        xof_squeezeblocks(buf, GEN_MATRIX_NBLOCKS, &state);
        buflen = GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES;
        ctr = rej_uniform(a[i].vec[j].coeffs, MLKEM_N, buf, buflen);
        while (ctr < MLKEM_N) {
            xof_squeezeblocks(buf, 1, &state);
            buflen = XOF_BLOCKBYTES;
            ctr += rej_uniform(a[i].vec[j].coeffs + ctr, MLKEM_N - ctr, buf, buflen);
        }
    }

    // Nicenie medzivysledkov podla FIP203 Section 3.3
    buffer_zeroize(buf, sizeof(buf));
    buffer_zeroize(&state, sizeof(state));
}

#endif // SPEED_CODE



