/*
 * IND-CPA secure public-key encryption scheme — indcpa_keypair, indcpa_enc, indcpa_dec
 *
 * Licensing: GPL-3.0-or-later (see LICENSE and CREDITS.md)
 *
 * Base implementation: pq-crystals/kyber reference (CC0-1.0 OR Apache-2.0)
 *   https://github.com/pq-crystals/kyber
 *
 * Build variants (selected at compile time):
 *
 *   SPEED
 *     Reference implementation optimized for
 *     execution time.
 *
 *   SPEED_DUALCORE
 *     Dual-core task mapping () is based on timing measurements 
 *     of functions called from indcpa; initial usage of dualcore
 *     inspired by fsegatz/kybesp32.
 *
 *   STACK
 *     Derived from pq-code-package/mlkem-c-embedded (Apache-2.0 OR CC0-1.0).
 *     https://github.com/pq-code-package/mlkem-c-embedded
 *     Uses matacc-based matrix-vector multiplication to reduce peak stack usage.
 *
 *   STACK_EXTREME
 *     Extends STACK by generating the noise vector on-the-fly during
 *     matrix-vector multiplication, eliminating the noise vector buffer entirely.
 *     Stack footprint is constant across all parameter sets (K=2,3,4).
 *     Integrated via the modified matacc_extreme function in matrix.c.
 *
 *   STACK_DUALCORE
 *     Parallelizes the matrix-vector multiplication of STACK across both ESP32
 *     cores in a single pass. Includes minor adjustments to handle odd K
 *     (MLKEM_K == 3) where rows cannot be evenly distributed between cores.
 * 
 * gen_a_elements:
 *   Custom implementation for element-wise generation of matrix A and its
 *   transpose AT. Generates individual elements on demand rather than the
 *   full matrix at once, enabling parallel generation of matrix rows across
 *   both ESP32 cores.
 * 
 * indcpa_cmp:
 *   Implicit rejection check (ciphertext comparison) integrated directly into
 *   every indcpa_enc call for code simplicity. Idea and code from
 *   pq-code-package/mlkem-c-embedded.
 *
 * Buffer zeroing:
 *   Sensitive intermediate buffers are explicitly zeroed after use per
 *   FIPS 203 Section 3.3. Approach inspired by pq-code-package/mlkem-native.
 *   https://github.com/pq-code-package/mlkem-native
 *
 * See CREDITS.md for full attribution. See thesis repository for partitioning
 * analysis and timing measurements [to be added to repository].
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "params.h"
#include "indcpa.h"
#include "polyvec.h"
#include "poly.h"
#include "ntt.h"
#include "symmetric.h"
#include "randombytes.h"
#include "verify.h"
#include "matrix.h"

#ifdef TIMEANALYSIS
    #include "../test_time/timing.h"
#endif


#ifdef DUALCORE_CODE
  #include "freertos/FreeRTOS.h"
  #include "freertos/task.h"
  #include "task_settings.h"

  static void delay_cycles(uint32_t cycles)
  {
      uint32_t start = xthal_get_ccount();
      while ((xthal_get_ccount() - start) < cycles) {
          // busywait
      }
  }
#endif


// pack/unpack wrappers
#ifdef SPEED_CODE
/*************************************************
* Name:        pack_pk
*
* Description: Serialize the public key as concatenation of the
*              serialized vector of polynomials pk
*              and the public seed used to generate the matrix A.
*
* Arguments:   uint8_t *r: pointer to the output serialized public key
*              polyvec *pk: pointer to the input public-key polyvec
*              const uint8_t *seed: pointer to the input public seed
**************************************************/
static void pack_pk(uint8_t r[MLKEM_INDCPA_PUBLICKEYBYTES],
                    polyvec *pk,
                    const uint8_t seed[MLKEM_SYMBYTES])
{
  polyvec_tobytes(r, pk);
  memcpy(r+MLKEM_POLYVECBYTES, seed, MLKEM_SYMBYTES);
}

/*************************************************
* Name:        unpack_pk
*
* Description: De-serialize public key from a byte array;
*              approximate inverse of pack_pk
*
* Arguments:   - polyvec *pk: pointer to output public-key polynomial vector
*              - uint8_t *seed: pointer to output seed to generate matrix A
*              - const uint8_t *packedpk: pointer to input serialized public key
**************************************************/
static void unpack_pk(polyvec *pk,
                      uint8_t seed[MLKEM_SYMBYTES],
                      const uint8_t packedpk[MLKEM_INDCPA_PUBLICKEYBYTES])
{
  polyvec_frombytes(pk, packedpk);
  memcpy(seed, packedpk+MLKEM_POLYVECBYTES, MLKEM_SYMBYTES);
}

/*************************************************
* Name:        pack_sk
*
* Description: Serialize the secret key
*
* Arguments:   - uint8_t *r: pointer to output serialized secret key
*              - polyvec *sk: pointer to input vector of polynomials (secret key)
**************************************************/
static void pack_sk(uint8_t r[MLKEM_INDCPA_SECRETKEYBYTES], polyvec *sk)
{
  polyvec_tobytes(r, sk);
}

/*************************************************
* Name:        unpack_sk
*
* Description: De-serialize the secret key; inverse of pack_sk
*
* Arguments:   - polyvec *sk: pointer to output vector of polynomials (secret key)
*              - const uint8_t *packedsk: pointer to input serialized secret key
**************************************************/
static void unpack_sk(polyvec *sk, const uint8_t packedsk[MLKEM_INDCPA_SECRETKEYBYTES])
{
  polyvec_frombytes(sk, packedsk);
}

/*************************************************
* Name:        pack_ciphertext
*
* Description: Serialize the ciphertext as concatenation of the
*              compressed and serialized vector of polynomials b
*              and the compressed and serialized polynomial v
*
* Arguments:   uint8_t *r: pointer to the output serialized ciphertext
*              poly *pk: pointer to the input vector of polynomials b
*              poly *v: pointer to the input polynomial v
**************************************************/
static void pack_ciphertext(uint8_t r[MLKEM_INDCPA_BYTES], polyvec *b, poly *v)
{
  polyvec_compress(r, b);
  poly_compress(r+MLKEM_POLYVECCOMPRESSEDBYTES, v);
}

/*************************************************
* Name:        cmp_pack_ciphertext
*
* Description: Serialize the ciphertext as concatenation of the
*              compressed and serialized vector of polynomials b
*              and the compressed and serialized polynomial v
*
* Arguments:   uint8_t *r: pointer to the output serialized ciphertext
*              poly *pk: pointer to the input vector of polynomials b
*              poly *v: pointer to the input polynomial v
**************************************************/
static void cmp_pack_ciphertext(volatile uint64_t *rc, const uint8_t r[MLKEM_INDCPA_BYTES], polyvec *b, poly *v)
{
  *rc |= cmp_polyvec_compress(r, b);
  *rc |= cmp_poly_compress(r+MLKEM_POLYVECCOMPRESSEDBYTES, v);
}

static void cmp_pack_ciphertext_b(volatile uint64_t *rc, const uint8_t r[MLKEM_INDCPA_BYTES], polyvec *b)
{
  *rc |= cmp_polyvec_compress(r, b);
}

static void cmp_pack_ciphertext_v(volatile uint64_t *rc, const uint8_t r[MLKEM_INDCPA_BYTES], poly *v)
{
  *rc |= cmp_poly_compress(r + MLKEM_POLYVECCOMPRESSEDBYTES, v);
}

// #ifdef SPEED
/*************************************************
* Name:        unpack_ciphertext
*
* Description: De-serialize and decompress ciphertext from a byte array;
*              approximate inverse of pack_ciphertext
*
* Arguments:   - polyvec *b: pointer to the output vector of polynomials b
*              - poly *v: pointer to the output polynomial v
*              - const uint8_t *c: pointer to the input serialized ciphertext
**************************************************/
static void unpack_ciphertext(polyvec *b, poly *v, const uint8_t c[MLKEM_INDCPA_BYTES])
{
  polyvec_decompress(b, c);
  poly_decompress(v, c+MLKEM_POLYVECCOMPRESSEDBYTES);
}
// #endif

#endif //(SPEED_CODE)


/*************************************************
* Name:        indcpa_keypair
*
* Description: Deterministic IND-CPA keypair generation
*              Uses provided randomness instead of RNG
*
* Arguments:   - uint8_t *pk: output public key
*              - uint8_t *sk: output secret key
*              - const uint8_t *coins: input randomness (32 bytes)
**************************************************/
#if defined(SPEED_DUALCORE)

typedef struct IndcpaKeypairData_t {
  uint8_t * pk;
  uint8_t * sk;
  uint8_t buf[2*MLKEM_SYMBYTES];
  polyvec a[MLKEM_K], e, pkpv, skpv;

  TaskHandle_t main_task_handle;
  TaskHandle_t support_task_handle;
} GenericIndcpaKeypairData_t __attribute__((aligned(XSTRUCT_ALIGN_VAL)));


void indcpa_keypair_SUPPORT_CORE(void *xStruct) {
  GenericIndcpaKeypairData_t *data = (GenericIndcpaKeypairData_t *) xStruct;
  const uint8_t *publicseed = data->buf;
  #if (MLKEM_K != 3)
    const uint8_t *noiseseed  = data->buf + MLKEM_SYMBYTES;
  #endif

  // Wait for Core MAIN to finish hash_g, if mlkem 3, waiting till 1st sampling is done
  #if (MLKEM_K != 3)
    portMEMORY_BARRIER();
    ulTaskNotifyTake(pdFALSE, portMAX_DELAY);
  #endif

  // --- Noise  ---
  #if (MLKEM_K != 3)
    // uint8_t nonce = MLKEM_K; 
    for (unsigned int i = 0; i < MLKEM_K; i++){
      poly_getnoise_eta1(&data->skpv.vec[i], noiseseed, i);
    }
  #endif

  // --- NTT  ---
  #if (MLKEM_K == 3)
    // Wait for Core MAIN to finish 1st sampling after hash_g
    // dalsie waity sem, ak zacne buggovat
    ulTaskNotifyTake(pdFALSE, portMAX_DELAY);
    portMEMORY_BARRIER();
    poly_ntt(&data->skpv.vec[0]);
    ulTaskNotifyTake(pdFALSE, portMAX_DELAY);
    portMEMORY_BARRIER();
    poly_ntt(&data->skpv.vec[1]);
    ulTaskNotifyTake(pdFALSE, portMAX_DELAY);
    portMEMORY_BARRIER();
    poly_ntt(&data->skpv.vec[2]);
    ulTaskNotifyTake(pdFALSE, portMAX_DELAY);
    portMEMORY_BARRIER();
    poly_ntt(&data->e.vec[0]);

    //not signaling NTT is ready, MAIN needs also elements
  #else  //(MLKEM_K == 2 || MLKEM_K == 4)

    polyvec_ntt(&data->skpv);

    // Signal Core MAIN NTT is ready for MVM
    portMEMORY_BARRIER();
    xTaskNotifyGive(data->main_task_handle);

  #endif


  // --- Parallel gen_a


  #if (MLKEM_K == 3)
      // rozpolim a poslem signal uz v polke pre K3
    // Signal Core MAIN NTT is ready for MVM
    // Signal Core MAIN NTT and needed elements of matrix are ready
    gen_a_elements(data->a, publicseed, CORE1_START_ELEMENT, 6);
      portMEMORY_BARRIER();
      xTaskNotifyGive(data->main_task_handle);
    gen_a_elements(data->a, publicseed, 7, CORE1_END_ELEMENT);
  #else
    gen_a_elements(data->a, publicseed, CORE1_START_ELEMENT, CORE1_END_ELEMENT);
  #endif




  /*====================== Druha cast========================*/
  // // Signal Core MAIN that gen a is done
  // portMEMORY_BARRIER();
  // xTaskNotifyGive(data->main_task_handle);
  // // Wait for Core MAIN to finish gen a
  // portMEMORY_BARRIER();
  // ulTaskNotifyTake(pdFALSE, portMAX_DELAY);  

  // tu sa obe jadra pockaju

  // --- Matrix-vector multiplication (Core SUPPORT) ---
  #if (MLKEM_K == 3)

    // Wait for Core MAIN to finish NTT
    portMEMORY_BARRIER();
    ulTaskNotifyTake(pdFALSE, portMAX_DELAY);  
    
    // full MVP poly 2
    // for (unsigned int i = CORE1_MVM_START; i <= CORE1_MVM_END; i++) {
      // A*s
      polyvec_basemul_acc_montgomery(&data->pkpv.vec[2], &data->a[2], &data->skpv);
      poly_tomont(&data->pkpv.vec[2]);
      //+e
      poly_add(&data->pkpv.vec[2], &data->pkpv.vec[2], &data->e.vec[2]);
      //reduckcia mod q
      poly_reduce(&data->pkpv.vec[2]);
    // }  
    // Wait for Core MAIN to prepare poly 1
    ulTaskNotifyTake(pdFALSE, portMAX_DELAY);  
    portMEMORY_BARRIER();
    //finish poly 0
    poly_tomont(&data->pkpv.vec[0]);
    poly_add(&data->pkpv.vec[0], &data->pkpv.vec[0], &data->e.vec[0]);
    poly_reduce(&data->pkpv.vec[0]);
  #else 

    // Wait for Core MAIN to finish vector e
    portMEMORY_BARRIER();
    ulTaskNotifyTake(pdFALSE, portMAX_DELAY);  

    // full MVP per Core
    for (unsigned int i = CORE1_MVM_START; i <= CORE1_MVM_END; i++) {
      // A*s
      polyvec_basemul_acc_montgomery(&data->pkpv.vec[i], &data->a[i], &data->skpv);
      poly_tomont(&data->pkpv.vec[i]);
      //+e
      poly_add(&data->pkpv.vec[i], &data->pkpv.vec[i], &data->e.vec[i]);
      //reduckcia mod q
      poly_reduce(&data->pkpv.vec[i]);
    }
  #endif


  // Signal Core MAIN that MVM is done
  portMEMORY_BARRIER();
  xTaskNotifyGive(data->main_task_handle);

  pack_sk(data->sk, &data->skpv);

  // Signal Core MAIN that pack_sk is done
  portMEMORY_BARRIER();
  xTaskNotifyGive(data->main_task_handle);

  vTaskDelete(NULL);
}

int indcpa_keypair(uint8_t pk[MLKEM_INDCPA_PUBLICKEYBYTES],
                           uint8_t sk[MLKEM_INDCPA_SECRETKEYBYTES],
                           const uint8_t coins[MLKEM_SYMBYTES]) {

  GenericIndcpaKeypairData_t xStruct = { .pk = pk, .sk = sk };
  xStruct.main_task_handle = xTaskGetCurrentTaskHandle();

  BaseType_t xReturned = xTaskCreatePinnedToCore(
      indcpa_keypair_SUPPORT_CORE,
      "indcpa_keypair_SUPPORT_CORE",
      INDCPA_STACK_KEYPAIR,
      (void *) &xStruct,
      MLKEM_TASK_PRIORITY,
      &xStruct.support_task_handle,
      (BaseType_t) MLKEM_SUPPORT_CORE);

  if (xReturned != pdPASS) return 1;

  const uint8_t *publicseed = xStruct.buf;
  const uint8_t *noiseseed  = xStruct.buf + MLKEM_SYMBYTES;

  // --- hash_g (serial, must precede everything) ---
  memcpy(xStruct.buf, coins, MLKEM_SYMBYTES);
  xStruct.buf[MLKEM_SYMBYTES] = MLKEM_K;
  hash_g(xStruct.buf, xStruct.buf, MLKEM_SYMBYTES + 1);
  

  // Signal Core SUPPORT hash_g is done
  #if (MLKEM_K != 3)
    portMEMORY_BARRIER();
    xTaskNotifyGive(xStruct.support_task_handle);
  #endif

  // --- Noise  ---
  #if (MLKEM_K == 3)
    poly_getnoise_eta1(&xStruct.skpv.vec[0], noiseseed, 0);
    // Signal Core SUPPORT to start coookin NTT
    // getnoise je na esp32 pomalsia ako prislusna NTT, preto dalsie notifye nie su teoreticky potrebne
      portMEMORY_BARRIER();
      xTaskNotifyGive(xStruct.support_task_handle);
    poly_getnoise_eta1(&xStruct.skpv.vec[1], noiseseed, 1);
      portMEMORY_BARRIER();
      xTaskNotifyGive(xStruct.support_task_handle);
    poly_getnoise_eta1(&xStruct.skpv.vec[2], noiseseed, 2);
      portMEMORY_BARRIER();
      xTaskNotifyGive(xStruct.support_task_handle);
    poly_getnoise_eta1(&xStruct.e.vec[0], noiseseed, 3);
      portMEMORY_BARRIER();
      xTaskNotifyGive(xStruct.support_task_handle);
    // posledne 2 sa robia na Core MAIN, netreba signalizovat
    poly_getnoise_eta1(&xStruct.e.vec[1], noiseseed, 4);
    poly_getnoise_eta1(&xStruct.e.vec[2], noiseseed, 5);
  #else  //(MLKEM_K == 2 || MLKEM_K == 4)
    for (unsigned int i = 0; i < MLKEM_K; i++){
      poly_getnoise_eta1(&xStruct.e.vec[i], noiseseed, MLKEM_K+i);
    }
  #endif

  // --- NTT  ---
  #if (MLKEM_K == 3)
    poly_ntt(&xStruct.e.vec[1]);
    poly_ntt(&xStruct.e.vec[2]);

    // Signal Core SUPPORT NTT is ready for MVM, SUPPORT doesnt need elements of main for initial ntt
    portMEMORY_BARRIER();
    xTaskNotifyGive(xStruct.support_task_handle);


  #else  //(MLKEM_K == 2 || MLKEM_K == 4)

    polyvec_ntt(&xStruct.e);

    // Signal Core SUPPORT NTT is ready for MVM
    portMEMORY_BARRIER();
    xTaskNotifyGive(xStruct.support_task_handle);

  #endif


  // --- Parallel gen_a
  gen_a_elements(xStruct.a, publicseed, CORE0_START_ELEMENT, CORE0_END_ELEMENT);


  /*====================== Druha cast========================*/
  // // Signal Core SUPPORT that gen a is done
  // portMEMORY_BARRIER();
  // xTaskNotifyGive(xStruct.support_task_handle);
  // // Wait for Core SUPPORT to finish gen a 
  // portMEMORY_BARRIER();
  // ulTaskNotifyTake(pdFALSE, portMAX_DELAY); 

  // tu sa obe jadra pockaju

  // --- Matrix-vector multiplication (Core MAIN) ---
  #if (MLKEM_K == 3)

  // Wait for Core SUPPORT to finish gen a and NTT
  portMEMORY_BARRIER();
  ulTaskNotifyTake(pdFALSE, portMAX_DELAY); 

  // alternatie mapping for K==3
  // full poly MVP is 44978 cycles, basemul poly itself is 25939 c
  // Core SUP does full MVP of poly 2 and wait for basemul of poly 0 to continiu poly 0
  // Core MAIN does basemul of polys 0 and 1, then finish poly 1.
  // before last 3 same calls of each Core, in average, Core MAIN is 51878c abd SUPP is 44928c vs original 89956:44978 ratio in normal split
  // benchmark result: this split is 13600cycles faster (-1%), adds 2400b on HEAP (+18,7%). Average values for evaluation could be reason for smaller then expected gain.
    // basemul poly 0
    polyvec_basemul_acc_montgomery(&xStruct.pkpv.vec[0], &xStruct.a[0], &xStruct.skpv);
    // Signal Core SUPPORT it can finish poly 0, corrective, small percentage of KAT failed without
    portMEMORY_BARRIER();
    xTaskNotifyGive(xStruct.support_task_handle);
    // full MVP poly 1
    polyvec_basemul_acc_montgomery(&xStruct.pkpv.vec[1], &xStruct.a[1], &xStruct.skpv);
    // around this time Core SUPPORT did full MVP poly 2 and can continue finihsing poly 0
    poly_tomont(&xStruct.pkpv.vec[1]);
    poly_add(&xStruct.pkpv.vec[1], &xStruct.pkpv.vec[1], &xStruct.e.vec[1]);
    poly_reduce(&xStruct.pkpv.vec[1]);
    // vyskusane posunutie reduckie row2 na hlavny core
    // v teoriu by to malo znizit gap cakania MAIN,, ktory je bez bariery ~10958cyc, no v praxi spomaluje +0.6%
    // poly_reduce(&xStruct.pkpv.vec[2]);
  #else

    // Wait for Core SUPPORT to finish vector s (pkpvs)
    portMEMORY_BARRIER();
    ulTaskNotifyTake(pdFALSE, portMAX_DELAY); 

    // full MVP per Core
    for (unsigned int i = CORE0_MVM_START; i <= CORE0_MVM_END; i++) {
      // A*s
      polyvec_basemul_acc_montgomery(&xStruct.pkpv.vec[i], &xStruct.a[i], &xStruct.skpv);
      poly_tomont(&xStruct.pkpv.vec[i]);
      //+e
      poly_add(&xStruct.pkpv.vec[i], &xStruct.pkpv.vec[i], &xStruct.e.vec[i]);
      //reduckcia mod q
      poly_reduce(&xStruct.pkpv.vec[i]);
    }
  #endif

  // Wait for Core SUPPORT to finish MVC part
  portMEMORY_BARRIER();
  ulTaskNotifyTake(pdFALSE, portMAX_DELAY); 

  pack_pk(pk, &xStruct.pkpv, publicseed);

  // Wait for Core SUPPORT to finish pack_sk
  portMEMORY_BARRIER();
  ulTaskNotifyTake(pdFALSE, portMAX_DELAY);  

  // Nicenie medzivysledkov podla FIP203 Section 3.3
  buffer_zeroize(xStruct.buf,    sizeof(xStruct.buf));
  buffer_zeroize(&xStruct.a,     sizeof(xStruct.a));
  buffer_zeroize(&xStruct.pkpv,  sizeof(xStruct.pkpv));
  buffer_zeroize(&xStruct.skpv,  sizeof(xStruct.skpv));
  buffer_zeroize(&xStruct.e,     sizeof(xStruct.e));

  //end of indcpa_keypair
  return 0;
}

#elif defined(SPEED)
int indcpa_keypair(uint8_t pk[MLKEM_INDCPA_PUBLICKEYBYTES],
                                   uint8_t sk[MLKEM_INDCPA_SECRETKEYBYTES],
                                   const uint8_t coins[MLKEM_SYMBYTES])
{
  unsigned int i;
  VAR_ALIGN uint8_t buf[2*MLKEM_SYMBYTES]; //ide do hash_g store64 a load64 
  const uint8_t *publicseed = buf;
  const uint8_t *noiseseed = buf+MLKEM_SYMBYTES;
  unsigned int nonce = 0;
  polyvec a[MLKEM_K], e, pkpv, skpv;

  memcpy(buf, coins, MLKEM_SYMBYTES);
  buf[MLKEM_SYMBYTES] = MLKEM_K;
  hash_g(buf, buf, MLKEM_SYMBYTES+1);
  
  gen_a_elements(a, publicseed, SC_MATRX_STRT_EL, SC_MATRX_END_EL);

  for(i=0;i<MLKEM_K;i++)
    poly_getnoise_eta1(&skpv.vec[i], noiseseed, nonce++);
  for(i=0;i<MLKEM_K;i++)
    poly_getnoise_eta1(&e.vec[i], noiseseed, nonce++);

  polyvec_ntt(&skpv);
  polyvec_ntt(&e);

  // --- Matrix-vector multiplication ---
  for (i = 0; i < MLKEM_K; i++) {
    // A*s
    polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a[i], &skpv);
    poly_tomont(&pkpv.vec[i]);
    //+e
    poly_add(&pkpv.vec[i], &pkpv.vec[i], &e.vec[i]);
    //reduckcia mod q
    poly_reduce(&pkpv.vec[i]);
  }

  pack_sk(sk, &skpv);
  pack_pk(pk, &pkpv, publicseed);

  // Nicenie medzivysledkov podla FIP203 Section 3.3
  buffer_zeroize(buf,   sizeof(buf));
  buffer_zeroize(&skpv, sizeof(skpv));
  buffer_zeroize(&e,    sizeof(e));
  buffer_zeroize(&a,    sizeof(a));
  buffer_zeroize(&pkpv, sizeof(pkpv));
  buffer_zeroize(&nonce, sizeof(nonce));

  return 0;
}

#elif defined(STACK_DUALCORE) 
// nova schema
typedef struct {
    uint8_t *pk;
    uint8_t *sk;
    uint8_t buf[2 * MLKEM_SYMBYTES];
    polyvec skpv;
    TaskHandle_t main_task_handle;
    TaskHandle_t support_task_handle;
} IndcpaKeypairData_t __attribute__((aligned(XSTRUCT_ALIGN_VAL)));

void indcpa_keypair_SUPPORT_CORE(void *xStruct)
{
    IndcpaKeypairData_t *data = (IndcpaKeypairData_t *)xStruct;
    const uint8_t *publicseed = data->buf;
    const uint8_t *noiseseed  = data->buf + MLKEM_SYMBYTES;
    poly pkp; //potreuje pre vlastny vysledok produktu matrix pred balenim
    unsigned int i;

    ulTaskNotifyTake(pdFALSE, portMAX_DELAY);
    portMEMORY_BARRIER();

    // split 1:1 pre K=2,4, urob 1 pre K=3
    for(i = MLKEM_K - 1; i < MLKEM_K; i++)
        poly_getnoise_eta1(&data->skpv.vec[i], noiseseed, (uint8_t)i);
    for(i = MLKEM_K - 1; i < MLKEM_K; i++)
        poly_ntt(&data->skpv.vec[i]);

    // Signal Core MAIN that NTT is done
    portMEMORY_BARRIER();
    xTaskNotifyGive(data->main_task_handle);
    // Wait for Core MAIN to finish NTT
    portMEMORY_BARRIER();
    ulTaskNotifyTake(pdFALSE, portMAX_DELAY); 

    // bod3
#if (MLKEM_K == 3)
    matacc(&pkp, &data->skpv, 1, publicseed, 0);
    poly_invntt_tomont(&pkp);
    poly_addnoise_eta1(&pkp, noiseseed, (uint8_t)(MLKEM_K + 1));
    poly_ntt(&pkp);
    poly_reduce(&pkp);
    poly_tobytes(data->pk + 1 * MLKEM_POLYBYTES, &pkp);
    polyvec_tobytes(data->sk, &data->skpv);
    memcpy(data->pk + MLKEM_POLYVECBYTES, publicseed, MLKEM_SYMBYTES);
#else
    for (unsigned int i = MLKEM_K / 2; i < MLKEM_K; i++) {
        matacc(&pkp, &data->skpv, i, publicseed, 0);
        poly_invntt_tomont(&pkp);
        poly_addnoise_eta1(&pkp, noiseseed, (uint8_t)(MLKEM_K + i));
        poly_ntt(&pkp);
        poly_reduce(&pkp);
        poly_tobytes(data->pk + i * MLKEM_POLYBYTES, &pkp);
    }
#endif
    
    // Nicenie medzivysledkov podla FIP203 Section 3.3
    buffer_zeroize(&pkp, sizeof(pkp));

    portMEMORY_BARRIER();
    xTaskNotifyGive(data->main_task_handle);
    vTaskDelete(NULL);
}

int indcpa_keypair(uint8_t pk[MLKEM_INDCPA_PUBLICKEYBYTES],
                           uint8_t sk[MLKEM_INDCPA_SECRETKEYBYTES],
                           const uint8_t coins[MLKEM_SYMBYTES])
{
    IndcpaKeypairData_t xStruct = { .pk = pk, .sk = sk };
    xStruct.main_task_handle = xTaskGetCurrentTaskHandle();

    BaseType_t xReturned = xTaskCreatePinnedToCore(
        indcpa_keypair_SUPPORT_CORE,
        "indcpa_keypair_SUPPORT_CORE",
        INDCPA_STACK_KEYPAIR, (void *)&xStruct,
        MLKEM_TASK_PRIORITY,
        &xStruct.support_task_handle,
        (BaseType_t)MLKEM_SUPPORT_CORE);

    if (xReturned != pdPASS) return 1;

    const uint8_t *publicseed = xStruct.buf;
    const uint8_t *noiseseed  = xStruct.buf + MLKEM_SYMBYTES;
    poly pkp;
    unsigned int i;

    // bod1
    memcpy(xStruct.buf, coins, MLKEM_SYMBYTES);
    xStruct.buf[MLKEM_SYMBYTES] = MLKEM_K;
    hash_g(xStruct.buf, xStruct.buf, MLKEM_SYMBYTES + 1);
    
    // Signal Core SUPPORT to start its noise and NTT
    portMEMORY_BARRIER();
    xTaskNotifyGive(xStruct.support_task_handle);

    // split 1:1 pre K=2,4, urob 2 pre K=3
    for (i = 0; i < MLKEM_K - 1; i++)
        poly_getnoise_eta1(&xStruct.skpv.vec[i], noiseseed, (uint8_t)i);
    for (i = 0; i < MLKEM_K - 1; i++)
        poly_ntt(&xStruct.skpv.vec[i]);
    
    // Signal Core SUPPORT that NTT is done
    portMEMORY_BARRIER();
    xTaskNotifyGive(xStruct.support_task_handle);
    // Wait for Core SUPPORT to NTT is done
    portMEMORY_BARRIER();
    ulTaskNotifyTake(pdFALSE, portMAX_DELAY); 

    // bod3
#if (MLKEM_K == 3)
    for (unsigned int i = 0; i < 3; i += 2) {
        matacc(&pkp, &xStruct.skpv, i, publicseed, 0);
        poly_invntt_tomont(&pkp);
        poly_addnoise_eta1(&pkp, noiseseed, (uint8_t)(MLKEM_K + i));
        poly_ntt(&pkp);
        poly_reduce(&pkp);
        poly_tobytes(pk + i * MLKEM_POLYBYTES, &pkp);
    }
#else
    for (unsigned int i = 0; i < MLKEM_K / 2; i++) {
        matacc(&pkp, &xStruct.skpv, i, publicseed, 0);
        poly_invntt_tomont(&pkp);
        poly_addnoise_eta1(&pkp, noiseseed, (uint8_t)(MLKEM_K + i));
        poly_ntt(&pkp);
        poly_reduce(&pkp);
        poly_tobytes(pk + i * MLKEM_POLYBYTES, &pkp);
    }
#endif

    ulTaskNotifyTake(pdFALSE, portMAX_DELAY);
    portMEMORY_BARRIER();

#if !(MLKEM_K == 3)
    // bod4
    polyvec_tobytes(sk, &xStruct.skpv);
    memcpy(pk + MLKEM_POLYVECBYTES, publicseed, MLKEM_SYMBYTES);
#endif

    // Nicenie medzivysledkov podla FIP203 Section 3.3
    buffer_zeroize(&pkp,        sizeof(pkp));
    buffer_zeroize(&xStruct.skpv, sizeof(xStruct.skpv));
    buffer_zeroize(xStruct.buf,   sizeof(xStruct.buf));


    return 0;
}

#elif defined(STACK_XTREME) 
int indcpa_keypair(uint8_t pk[MLKEM_INDCPA_PUBLICKEYBYTES],
                           uint8_t sk[MLKEM_INDCPA_SECRETKEYBYTES],
                           const uint8_t coins[MLKEM_SYMBYTES])
{ 
    unsigned int i;
    VAR_ALIGN uint8_t buf[2 * MLKEM_SYMBYTES];
    const uint8_t *publicseed = buf;
    const uint8_t *noiseseed = buf + MLKEM_SYMBYTES;
    unsigned int nonce = 0;
    poly pkp;
    poly mag;
    poly *skp = &mag;
    
    //bod1
    memcpy(buf, coins, MLKEM_SYMBYTES);
    buf[MLKEM_SYMBYTES] = MLKEM_K;
    hash_g(buf, buf, MLKEM_SYMBYTES + 1);

    // matrix-vector multiplication
    //bod 3
    nonce = (MLKEM_K); //correction for not iterating
    for (i = 0; i < MLKEM_K; i++) {

        matacc_xtreme(&pkp, &mag, i, publicseed, noiseseed, 0);
        poly_invntt_tomont(&pkp);
        poly_addnoise_eta1(&pkp, noiseseed, nonce++);
        poly_ntt(&pkp);
        poly_reduce(&pkp);
        poly_tobytes(pk + i * MLKEM_POLYBYTES, &pkp);

    }

    //bod4
    for(i=0;i<MLKEM_K;i++) {
      poly_getnoise_eta1(skp, noiseseed, i);
      poly_ntt(skp);
      poly_tobytes(sk+i*MLKEM_POLYBYTES, skp);
    }

    memcpy(pk + MLKEM_POLYVECBYTES, publicseed, MLKEM_SYMBYTES);

    // Nicenie medzivysledkov podla FIP203 Section 3.3
    buffer_zeroize(buf,   sizeof(buf));
    buffer_zeroize(&pkp,  sizeof(pkp));
    buffer_zeroize(&mag,  sizeof(mag));
    buffer_zeroize(&nonce, sizeof(nonce));

    return 0;
}

#elif defined(STACK)
int indcpa_keypair(uint8_t pk[MLKEM_INDCPA_PUBLICKEYBYTES],
                           uint8_t sk[MLKEM_INDCPA_SECRETKEYBYTES],
                           const uint8_t coins[MLKEM_SYMBYTES])
{ 
    unsigned int i;
    VAR_ALIGN uint8_t buf[2 * MLKEM_SYMBYTES];
    const uint8_t *publicseed = buf;
    const uint8_t *noiseseed = buf + MLKEM_SYMBYTES;
    unsigned int nonce = 0;
    polyvec skpv;
    poly pkp;
    
    //bod1
    memcpy(buf, coins, MLKEM_SYMBYTES);
    buf[MLKEM_SYMBYTES] = MLKEM_K;
    hash_g(buf, buf, MLKEM_SYMBYTES + 1);

    //bod2
    for (i = 0; i < MLKEM_K; i++) {
        poly_getnoise_eta1(&skpv.vec[i], noiseseed, nonce++);
    }
    polyvec_ntt(&skpv);

    // matrix-vector multiplication
    //bod 3
    for (i = 0; i < MLKEM_K; i++) {

        matacc(&pkp, &skpv, i, publicseed, 0);
        poly_invntt_tomont(&pkp);
        poly_addnoise_eta1(&pkp, noiseseed, nonce++);
        poly_ntt(&pkp);
        poly_reduce(&pkp);
        poly_tobytes(pk + i * MLKEM_POLYBYTES, &pkp);

    }

    //bod4
    polyvec_tobytes(sk, &skpv);
    memcpy(pk + MLKEM_POLYVECBYTES, publicseed, MLKEM_SYMBYTES);

    // Nicenie medzivysledkov podla FIP203 Section 3.3
    buffer_zeroize(buf,   sizeof(buf));
    buffer_zeroize(&skpv, sizeof(skpv));
    buffer_zeroize(&pkp,  sizeof(pkp));
    buffer_zeroize(&nonce, sizeof(nonce));

    return 0;
}
#else 
  #error "chyba prepinacov pre indcpa_keypair"
#endif //STACK_DUALCORE

/*************************************************
* Name:        indcpa_enc
*
* Description: Encryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *c: pointer to output ciphertext
*                            (of length MLKEM_INDCPA_BYTES bytes)
*              - const uint8_t *m: pointer to input message
*                                  (of length MLKEM_INDCPA_MSGBYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                                   (of length MLKEM_INDCPA_PUBLICKEYBYTES)
*              - const uint8_t *coins: pointer to input random coins used as seed
*                                      (of length MLKEM_SYMBYTES) to deterministically
*                                      generate all randomness
**************************************************/
#if defined(SPEED_DUALCORE)
typedef struct IndcpaEncData_t
{
  uint8_t * c;
  const uint8_t *m;
  const uint8_t *pk;
  const uint8_t *coins;
  uint8_t seed[MLKEM_SYMBYTES];
  polyvec sp, pkpv, ep, at[MLKEM_K], b;
  poly v, k, epp;
  TaskHandle_t main_task_handle;     // Handle for main core task
  TaskHandle_t support_task_handle;  // Handle for support core task

  volatile uint64_t rc_supp;
  const unsigned int *cmp_out;

} GenericIndcpaEncData_t __attribute__((aligned(XSTRUCT_ALIGN_VAL)));

void indcpa_enc_dual_derand_SUPPORT_CORE(void *xStruct) {
  GenericIndcpaEncData_t * data = (GenericIndcpaEncData_t *) xStruct;
  

#if  (MLKEM_K == 3)

  // decode m and pk
  // unpack_pk(&data->pkpv, data->seed, data->pk);

  // noise r [2]
  poly_getnoise_eta1(data->sp.vec+2, data->coins, 2);

  // NTT(r) [2]
  poly_ntt(&data->sp.vec[2]);
  // noise e2
  poly_getnoise_eta2(&data->epp, data->coins, 6);

  // noise e1 [1],[2]
  poly_getnoise_eta2(data->ep.vec+1, data->coins, 4);
  poly_getnoise_eta2(data->ep.vec+2, data->coins, 5);


  // --- Parallel gen_at
  gen_at_elements(data->at, data->seed, CORE1_START_ELEMENT, 5);
  // Signal Core MAIN NTT r,e1 and b[1] is ready
  portMEMORY_BARRIER();
  xTaskNotifyGive(data->main_task_handle);
  gen_at_elements(data->at, data->seed, 6, CORE1_END_ELEMENT);

  /*====================== Druha cast========================*/

  // Wait for Core MAIN to finish its part of NTT
  ulTaskNotifyTake(pdFALSE, portMAX_DELAY);  
  portMEMORY_BARRIER();

  //at*r = b[2]
  polyvec_basemul_acc_montgomery(&data->b.vec[2], &data->at[2], &data->sp);
  // NTT^-1 ar [2]
  poly_invntt_tomont(&data->b.vec[2]);

  

  // Signal Core MAIN its part of NTT^-1 ar is done, Core MAIN can add
  portMEMORY_BARRIER();
  xTaskNotifyGive(data->main_task_handle);

  // t^T x r
  polyvec_basemul_acc_montgomery(&data->v, &data->pkpv, &data->sp);
  // NTT^-1 t
  poly_invntt_tomont(&data->v);

  //decode m NTT^-1(tr)+e2+m
  poly_frommsg(&data->k, data->m);

  // t+e2
  poly_add(&data->v, &data->v, &data->epp);

  poly_add(&data->v, &data->v, &data->k);

  poly_reduce(&data->v);

#else

  // Wait for Core MAIN to unpack_pk
  // ulTaskNotifyTake(pdFALSE, portMAX_DELAY);  // Wait: pkpv ready
  // portMEMORY_BARRIER();

  unsigned int i;


  // noise r a e1
  // i=2,3
  for(i = MLKEM_K /2 ; i < MLKEM_K; i++)
    poly_getnoise_eta1(data->sp.vec+i, data->coins, i);
  for(i = MLKEM_K /2 ; i < MLKEM_K; i++)
    poly_getnoise_eta2(data->ep.vec+i, data->coins, MLKEM_K+i); //noise [1], [2,3]

  //jadra sa necakaju, noice pre NTT(r) na Core MAIN je zamerne pocitany pred maticou, v tomto okamihu je davno hotovy
  
  // --- NTT(r)  ---
  for(i = MLKEM_K /2 ; i < MLKEM_K; i++)
    poly_ntt(&data->sp.vec[i]);

  // Signal Core MAIN that NTT is ready for MVM
  portMEMORY_BARRIER();
  xTaskNotifyGive(data->main_task_handle);

  // --- Parallel gen_at
  gen_at_elements(data->at, data->seed, CORE1_START_ELEMENT, CORE1_END_ELEMENT);


  /*====================== Druha cast========================*/

  // Wait for Core MAIN finishin NTT pre gen a
  ulTaskNotifyTake(pdFALSE, portMAX_DELAY);  
  portMEMORY_BARRIER();

  // --- Matrix-vector multiplication (Core SUPPORT) ---
  for(i = MLKEM_K /2 ; i < MLKEM_K; i++)
    //at*r = b
    polyvec_basemul_acc_montgomery(&data->b.vec[i], &data->at[i], &data->sp);

  poly_getnoise_eta2(&data->epp, data->coins, 2 * MLKEM_K); ;

  #if (MLKEM_K == 2)
    // decode m 
    poly_frommsg(&data->k, data->m);
  #endif

  // Signal Core MAIN it can do matrix aritmatics over poly v
  portMEMORY_BARRIER();
  xTaskNotifyGive(data->main_task_handle);

  // NTT^-1 b,  b[2]b[3]/b[2 pre K2/4
  // prve na tomto jadre, lebo na tomto jadre pokracuje aj dalsia praca s nimi
  for(i = MLKEM_K /2 ; i < MLKEM_K; i++)
    poly_invntt_tomont(&data->b.vec[i]); // NTT^-1 ar

  // Wait for Core MAIN to finish its part of invNTT ar
  ulTaskNotifyTake(pdFALSE, portMAX_DELAY);  
  portMEMORY_BARRIER();


  // poly_add(&data->v, &data->v, &data->epp);

  // b +e1
  polyvec_add(&data->b, &data->b, &data->ep);
  polyvec_reduce(&data->b);

#endif

#if (MLKEM_K == 3)
  // pack_ct v
  if (data->cmp_out != ENC_ONLY){
      cmp_pack_ciphertext_v(&data->rc_supp, data->c, &data->v);
    }
  else {
    poly_compress(data->c+MLKEM_POLYVECCOMPRESSEDBYTES, &data->v);
  }
#else
  //pack_ct b
  if (data->cmp_out != ENC_ONLY){
    cmp_pack_ciphertext_b(&data->rc_supp, data->c, &data->b);
  } else {
    polyvec_compress(data->c, &data->b);
  }
#endif
  // Signal Core MAIN that SUPPORT is done
  portMEMORY_BARRIER();
  xTaskNotifyGive(data->main_task_handle);

  vTaskDelete(NULL);    
}

int indcpa_enc( uint8_t c[MLKEM_INDCPA_BYTES],
                const uint8_t m[MLKEM_INDCPA_MSGBYTES],
                const uint8_t pk[MLKEM_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[MLKEM_SYMBYTES],
                unsigned int *cmp_out)
{
  GenericIndcpaEncData_t xStruct = { 
    .c = c, 
    .m = m, 
    .pk = pk, 
    .coins = coins,
    .rc_supp = 0,
    .cmp_out = cmp_out
  };
  volatile uint64_t rc = 0;

  xStruct.main_task_handle = xTaskGetCurrentTaskHandle();

  // Create task on support core
  BaseType_t xReturned = xTaskCreatePinnedToCore(
                  indcpa_enc_dual_derand_SUPPORT_CORE,
                  "indcpa_enc_dual_derand_SUPPORT_CORE",
                  INDCPA_STACK_ENC,
                  ( void * ) &xStruct,
                  MLKEM_TASK_PRIORITY,
                  &xStruct.support_task_handle,
                  (BaseType_t) MLKEM_SUPPORT_CORE);

  if (xReturned != pdPASS) return 1;

#if  (MLKEM_K == 3)

  // decode m and pk
  unpack_pk(&xStruct.pkpv, xStruct.seed, xStruct.pk);

  // noise r [0],[1]
  poly_getnoise_eta1(xStruct.sp.vec, xStruct.coins, 0); 
  poly_getnoise_eta1(xStruct.sp.vec+1, xStruct.coins, 1);

  // NTT(r) [0],[1]
  poly_ntt(&xStruct.sp.vec[0]);
  poly_ntt(&xStruct.sp.vec[1]);

  // Signal Core SUPPORT NTT r is ready for MVM, support doesnt need e1
  portMEMORY_BARRIER();
  xTaskNotifyGive(xStruct.support_task_handle);

  // noise e1 [0]
  poly_getnoise_eta2(xStruct.ep.vec, xStruct.coins, 3);

  // --- Parallel gen_at
  gen_at_elements(xStruct.at, xStruct.seed, CORE0_START_ELEMENT, CORE0_END_ELEMENT);

  /*====================== Druha cast========================*/

  // Wait for Core SUPPORT to finish its part, e2 and matrix
  ulTaskNotifyTake(pdFALSE, portMAX_DELAY);  
  portMEMORY_BARRIER();

  //at*r = b [0],[1] + NTT^-1 ar [0],[1]
  polyvec_basemul_acc_montgomery(&xStruct.b.vec[0], &xStruct.at[0], &xStruct.sp);
  // polku druheho riadku robi Core SUPPORT, NTT je pred dalsim basemulom, aby ho stihol dogenerovat
  // nakoniec nie je potrebne, ziaden z rozsireneho vektora KAT testu nezlyhal pri tomto, rychlojesom rozlozeni
  polyvec_basemul_acc_montgomery(&xStruct.b.vec[1], &xStruct.at[1], &xStruct.sp);
  poly_invntt_tomont(&xStruct.b.vec[0]);
  poly_invntt_tomont(&xStruct.b.vec[1]);

  // Wait for Core SUPPORT to finish its part of NTT^-1 ar
  ulTaskNotifyTake(pdFALSE, portMAX_DELAY);  
  portMEMORY_BARRIER();

  // NTT^-1 ar +e1
  polyvec_add(&xStruct.b, &xStruct.b, &xStruct.ep);
  polyvec_reduce(&xStruct.b);

#else

  unpack_pk(&xStruct.pkpv, xStruct.seed, xStruct.pk);

  // Signal Core SUPPPORT it can start gen at
  // portMEMORY_BARRIER(); 
  // xTaskNotifyGive(xStruct.support_task_handle);  
  
  unsigned int i;

  // noise r a e1
  // i=0,1
  for(i = 0; i < MLKEM_K / 2; i++)
    //eta1 je 2x pomalsia ako eta2 pre K=2, preto ju rozdistribovat na obe jadra
    poly_getnoise_eta1(xStruct.sp.vec+i, xStruct.coins, i); //noise [0], [0,1]
  for(i = 0; i < MLKEM_K / 2; i++)
    poly_getnoise_eta2(xStruct.ep.vec+i, xStruct.coins, MLKEM_K+i);

  // --- NTT(r)  ---
  for(i = 0; i < MLKEM_K / 2; i++)
    poly_ntt(&xStruct.sp.vec[i]);

  // Signal Core SUPPORT NTT is ready for MVM
  portMEMORY_BARRIER();
  xTaskNotifyGive(xStruct.support_task_handle);

  // --- Parallel gen_at
  gen_at_elements(xStruct.at, xStruct.seed, CORE0_START_ELEMENT, CORE0_END_ELEMENT);

  /*====================== Druha cast========================*/

  // Wait for Core SUPPORT finishin NTT pre gen a
  ulTaskNotifyTake(pdFALSE, portMAX_DELAY);  
  portMEMORY_BARRIER();

  // --- Matrix-vector multiplication (Core MAIN) ---
  for(i = 0; i < MLKEM_K / 2; i++)
    //at*r = b
    polyvec_basemul_acc_montgomery(&xStruct.b.vec[i], &xStruct.at[i], &xStruct.sp);

  // NTT^-1 ar b[0]b[1]/b[2 pre K2/4
  for(i = 0; i < MLKEM_K / 2; i++)
    poly_invntt_tomont(&xStruct.b.vec[i]); // NTT^-1 ar

  // Signal Core SUPPORT that its part of NTT^-1 ar is done
  portMEMORY_BARRIER();
  xTaskNotifyGive(xStruct.support_task_handle);

  // t^T x r
  polyvec_basemul_acc_montgomery(&xStruct.v, &xStruct.pkpv, &xStruct.sp);

  // NTT^-1 t
  poly_invntt_tomont(&xStruct.v);

  #if (MLKEM_K == 4)
    // decode m 
    poly_frommsg(&xStruct.k, xStruct.m);
  #endif 

  // Wait for Core SUPPORT to finish e2 (+message if K!=4)
  ulTaskNotifyTake(pdFALSE, portMAX_DELAY);  
  portMEMORY_BARRIER();

  // t + e2
  poly_add(&xStruct.v, &xStruct.v, &xStruct.epp);

  // decod m musi byt dokonceny
  // #if (MLKEM_K == 2)
  //   ulTaskNotifyTake(pdFALSE, portMAX_DELAY);  
  //   portMEMORY_BARRIER();
  // #endif
  // t + e2 +m
  poly_add(&xStruct.v, &xStruct.v, &xStruct.k);

  poly_reduce(&xStruct.v);

#endif


  //pack_ct rozdeleny na obe jadra
  #if (MLKEM_K == 3)
    //pack_ct b
    if (cmp_out != ENC_ONLY){
      cmp_pack_ciphertext_b(&xStruct.rc_supp, xStruct.c, &xStruct.b);
    }
    else {
      polyvec_compress(xStruct.c, &xStruct.b);
    }
  
  #else
    // pack_ct v
    if (cmp_out != ENC_ONLY){
      // cmp_pack_ciphertext(&rc, xStruct.c, &xStruct.b, &xStruct.v);
      cmp_pack_ciphertext_v(&rc, xStruct.c, &xStruct.v);
    }
    else {
      // pack_ciphertext(xStruct.c, &xStruct.b, &xStruct.v);
      // pack_ct v
      poly_compress(xStruct.c+MLKEM_POLYVECCOMPRESSEDBYTES, &xStruct.v);
    }
  #endif

  // Wait for Core SUPPORT to finish
  ulTaskNotifyTake(pdFALSE, portMAX_DELAY);  
  portMEMORY_BARRIER();
  
  //comparison for cmp_enc for decrypt
  if (cmp_out != ENC_ONLY){
    rc |= xStruct.rc_supp;
    rc = ~rc + 1;
    rc >>= 63;
    *cmp_out = (unsigned int)rc;
  }

  // Nicenie medzivysledkov podla FIP203 Section 3.3
  buffer_zeroize(&xStruct.sp,   sizeof(xStruct.sp));
  buffer_zeroize(&xStruct.ep,   sizeof(xStruct.ep));
  buffer_zeroize(&xStruct.epp,  sizeof(xStruct.epp));
  buffer_zeroize(&xStruct.k,    sizeof(xStruct.k));
  buffer_zeroize(&xStruct.pkpv, sizeof(xStruct.pkpv));
  buffer_zeroize(&xStruct.at,   sizeof(xStruct.at));
  buffer_zeroize(&xStruct.b,    sizeof(xStruct.b));
  buffer_zeroize(&xStruct.v,    sizeof(xStruct.v));
  buffer_zeroize(&xStruct.seed, sizeof(xStruct.seed));

  return 0;

}

#elif defined(SPEED)
int indcpa_enc( uint8_t c[MLKEM_INDCPA_BYTES],
                const uint8_t m[MLKEM_INDCPA_MSGBYTES],
                const uint8_t pk[MLKEM_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[MLKEM_SYMBYTES],
                unsigned int *cmp_out)
{
  volatile uint64_t rc = 0;
  unsigned int i;
  VAR_ALIGN uint8_t seed[MLKEM_SYMBYTES];
  uint8_t nonce = 0;
  polyvec sp, pkpv, ep, at[MLKEM_K], b;
  poly v, k, epp; 
  /*
  Preklad
  sp == r
  ep = e1
  epp == e2
  pkpv == t
  */
  unpack_pk(&pkpv, seed, pk);
  gen_at_elements(at, seed, SC_MATRX_STRT_EL, SC_MATRX_END_EL);

  //decode m into k
  poly_frommsg(&k, m);

  for(i=0;i<MLKEM_K;i++)
    //r
    poly_getnoise_eta1(sp.vec+i, coins, nonce++);
  for(i=0;i<MLKEM_K;i++)
    //e1
    poly_getnoise_eta2(ep.vec+i, coins, nonce++);
  //e2
  poly_getnoise_eta2(&epp, coins, nonce++);

  //NTT(r)
  polyvec_ntt(&sp);

  // matrix-vector multiplication
  for(i=0;i<MLKEM_K;i++)
    //at*r = b
    polyvec_basemul_acc_montgomery(&b.vec[i], &at[i], &sp);
  // t*r
  polyvec_basemul_acc_montgomery(&v, &pkpv, &sp);

  // NTT^-1 ar
  polyvec_invntt_tomont(&b);
  // NTT^-1 t
  poly_invntt_tomont(&v);

  // NTT^-1 ar +e1
  polyvec_add(&b, &b, &ep);

  // NTT^-1(tr)+e2
  poly_add(&v, &v, &epp);
  //NTT^-1(tr)+e2+m
  poly_add(&v, &v, &k);

  polyvec_reduce(&b);
  poly_reduce(&v);

  //compress, encode
  if (cmp_out != ENC_ONLY){
    cmp_pack_ciphertext(&rc, c, &b, &v);
    rc = ~rc + 1;
    rc >>= 63;
    *cmp_out  = (unsigned int)rc;   // 0 = match, 1 = mismatch
  }
  else {
    pack_ciphertext(c, &b, &v);
  }

  // Nicenie medzivysledkov podla FIP203 Section 3.3
  buffer_zeroize(&sp,   sizeof(sp));
  buffer_zeroize(&ep,   sizeof(ep));
  buffer_zeroize(&epp,  sizeof(epp));
  buffer_zeroize(&k,    sizeof(k));
  buffer_zeroize(&pkpv, sizeof(pkpv));
  buffer_zeroize(&at,   sizeof(at));
  buffer_zeroize(&b,    sizeof(b));
  buffer_zeroize(&v,    sizeof(v));
  buffer_zeroize(seed,  sizeof(seed));


  return 0;
}

#elif defined(STACK_DUALCORE)

typedef struct {
    unsigned int *cmp_out;
    volatile uint64_t rc;
    uint8_t          *c;
    const uint8_t    *m;
    const uint8_t    *pk;
    const uint8_t    *coins;
    polyvec           sp;
    // poly              b_support;
// #if (MLKEM_K == 3)
//     poly              v;
// #endif
    TaskHandle_t      main_task_handle;
    TaskHandle_t      support_task_handle;
} IndcpaEncData_t __attribute__((aligned(XSTRUCT_ALIGN_VAL)));


void indcpa_enc_SUPPORT_CORE(void *xStruct)
{
    IndcpaEncData_t *data = (IndcpaEncData_t *)xStruct;
    const uint8_t   *seed = data->pk + MLKEM_POLYVECBYTES;
    unsigned int i;
    poly b_support; // ked je deklarovany tu, je skryty pod HEAP

    // bod1
    // split 1:1 pre K=2,4, urob 1 pre K=3
    for(i = MLKEM_K - 1; i < MLKEM_K; i++)
        poly_getnoise_eta1(&data->sp.vec[i], data->coins, (uint8_t)i);
    for(i = MLKEM_K - 1; i < MLKEM_K; i++)
        poly_ntt(&data->sp.vec[i]);

    // Signal Core MAIN that NTT is done
    portMEMORY_BARRIER();
    xTaskNotifyGive(data->main_task_handle);
    // Wait for Core MAIN to finish NTT
    portMEMORY_BARRIER();
    ulTaskNotifyTake(pdFALSE, portMAX_DELAY); 

    //Core SUPPORT potrebuje vlastny poly pre akumulaciu produktu matrix vodu 2 + poly v ak zrychlenie K=3

// #if (MLKEM_K == 3)
//     // bod2 i=1
//     matacc(&b_support, &data->sp, 1, seed, 1);
//     poly_invntt_tomont(&b_support);
//     poly_addnoise_eta2(&b_support, data->coins, (uint8_t)(MLKEM_K + 1));
//     poly_reduce(&b_support);
//     // poly_packcompress
//     if (data->cmp_out != ENC_ONLY){
//       data->rc |= cmp_poly_packcompress(data->c, &b_support, 1);
//     }
//     else {
//       poly_packcompress(data->c, &b_support, 1);
//     }
//     // bod3
//     poly_frombytes(&b_support, data->pk);
//     poly_basemul(data->v.coeffs, b_support.coeffs, data->sp.vec[0].coeffs);
//     for (i = 1; i < MLKEM_K; i++) {
//         poly_frombytes(&b_support, data->pk + i * MLKEM_POLYBYTES);
//         poly_basemul_acc(data->v.coeffs, b_support.coeffs, data->sp.vec[i].coeffs);
//     }
// #else
    // for (i = MLKEM_K / 2; i < MLKEM_K; i++) {
    // // split 1:1 pre K=2,4, urob 1 pre K=3
    for(i = MLKEM_K - 1; i < MLKEM_K; i++){
        matacc(&b_support, &data->sp, i, seed, 1);
        poly_invntt_tomont(&b_support);
        poly_addnoise_eta2(&b_support, data->coins, (uint8_t)(MLKEM_K + i));
        poly_reduce(&b_support);
        // poly_packcompress
        if (data->cmp_out != ENC_ONLY){
          data->rc |= cmp_poly_packcompress(data->c, &b_support, i);
        }
        else {
          poly_packcompress(data->c, &b_support, i);
        }
    }
// #endif
    // Signal Core MAIN that MVM is done here

    // Nicenie medzivysledkov podla FIP203 Section 3.3
    buffer_zeroize(&b_support, sizeof(b_support));

    portMEMORY_BARRIER();
    xTaskNotifyGive(data->main_task_handle);
    vTaskDelete(NULL);
}


int indcpa_enc( uint8_t c[MLKEM_INDCPA_BYTES],
                const uint8_t m[MLKEM_INDCPA_MSGBYTES],
                const uint8_t pk[MLKEM_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[MLKEM_SYMBYTES],
                unsigned int *cmp_out)

{
    IndcpaEncData_t xStruct = { .c = c, .m = m, .pk = pk, .coins = coins, .rc = 0, .cmp_out = cmp_out};
    xStruct.main_task_handle = xTaskGetCurrentTaskHandle();

    BaseType_t xReturned = xTaskCreatePinnedToCore(
        indcpa_enc_SUPPORT_CORE, "indcpa_enc_SUPPORT_CORE",
        INDCPA_STACK_ENC, (void *)&xStruct,
        MLKEM_TASK_PRIORITY,
        &xStruct.support_task_handle,
        (BaseType_t)MLKEM_SUPPORT_CORE);

    if (xReturned != pdPASS) return 1;

    const uint8_t *seed = pk + MLKEM_POLYVECBYTES;
    unsigned int i;
    poly *v = &xStruct.sp.vec[0];
    poly b;

    //mlkem_k=3 fast potrebujem navyse poly v, pretoze nemoze reuse maincorom stale pouzivane sp.vec[x] - rata matrix
    // +512b, preto zakomentovane

    // split 1:1 pre K=2,4, urob 2 pre K=3
    for (i = 0; i < MLKEM_K - 1; i++)
        poly_getnoise_eta1(&xStruct.sp.vec[i], xStruct.coins, (uint8_t)i);
    for (i = 0; i < MLKEM_K - 1; i++)
        poly_ntt(&xStruct.sp.vec[i]);
    
    // Signal Core SUPPORT that NTT is done
    portMEMORY_BARRIER();
    xTaskNotifyGive(xStruct.support_task_handle);
    // Wait for Core SUPPORT to NTT is done
    portMEMORY_BARRIER();
    ulTaskNotifyTake(pdFALSE, portMAX_DELAY); 

    // bod2
// #if (MLKEM_K == 3)
//     for (i = 0; i < 3; i += 2) {
//         matacc(&b, &xStruct.sp, i, seed, 1);
//         poly_invntt_tomont(&b);
//         poly_addnoise_eta2(&b, coins, (uint8_t)(MLKEM_K + i));
//         poly_reduce(&b);
//         if (cmp_out != ENC_ONLY){
//           xStruct.rc |= cmp_poly_packcompress(c, &b, i);
//         }
//         else {
//           poly_packcompress(c, &b, i);
//         }
//     }
// #else
      // for (i = 0; i < MLKEM_K / 2; i++) {
      // split 1:1 pre K=2,4, urob 2 pre K=3
      for (i = 0; i < MLKEM_K - 1; i++) {
        matacc(&b, &xStruct.sp, i, seed, 1);
        poly_invntt_tomont(&b);
        poly_addnoise_eta2(&b, coins, (uint8_t)(MLKEM_K + i));
        poly_reduce(&b);
        if (cmp_out != ENC_ONLY){
          xStruct.rc |= cmp_poly_packcompress(c, &b, i);
        }
        else {
          poly_packcompress(c, &b, i);
        }
    }
// #endif

    ulTaskNotifyTake(pdFALSE, portMAX_DELAY);   // caka na support
    portMEMORY_BARRIER();

// #if (MLKEM_K == 3)
//     // bod4 — bod3 uz dokoncil support, vysledok v xStruct.v
//     poly_invntt_tomont(&xStruct.v);
//     poly_addnoise_eta2(&xStruct.v, coins, (uint8_t)(2 * MLKEM_K));
//     poly_frommsg(&b, m);
//     poly_add(&xStruct.v, &xStruct.v, &b);
//     poly_reduce(&xStruct.v);
//     // poly_compress
//     if (cmp_out != ENC_ONLY){
//       xStruct.rc |= cmp_poly_compress(c + MLKEM_POLYVECCOMPRESSEDBYTES, &xStruct.v);
//       xStruct.rc = ~xStruct.rc + 1;
//       xStruct.rc >>= 63;
//       *cmp_out  = (unsigned int)xStruct.rc;   // 0 = match, 1 = mismatch
//     }
//     else {
//       poly_compress(c + MLKEM_POLYVECCOMPRESSEDBYTES, &xStruct.v);
//     }
// #else
    // bod3 + bod4
    // nie je v loope lebo selfaliasing v-cka
    poly_frombytes(&b, pk);
    poly_basemul(v->coeffs, b.coeffs, xStruct.sp.vec[0].coeffs);
    for (i = 1; i < MLKEM_K; i++) {
        poly_frombytes(&b, pk + i * MLKEM_POLYBYTES);
        poly_basemul_acc(v->coeffs, b.coeffs, xStruct.sp.vec[i].coeffs);
    }
    poly_invntt_tomont(v);
    poly_addnoise_eta2(v, coins, (uint8_t)(2 * MLKEM_K));
    poly_frommsg(&b, m);
    poly_add(v, v, &b);
    poly_reduce(v);
    if (cmp_out != ENC_ONLY){
      xStruct.rc |= cmp_poly_compress(c + MLKEM_POLYVECCOMPRESSEDBYTES, v);
      xStruct.rc = ~xStruct.rc + 1;
      xStruct.rc >>= 63;
      *cmp_out  = (unsigned int)xStruct.rc;   // 0 = match, 1 = mismatch
    }
    else {
      poly_compress(c + MLKEM_POLYVECCOMPRESSEDBYTES, v);
    }
// #endif

    // Nicenie medzivysledkov podla FIP203 Section 3.3
    buffer_zeroize(&xStruct.sp, sizeof(xStruct.sp));
    buffer_zeroize(&b,          sizeof(b));

    return 0;
}
#elif defined(STACK_XTREME)
int indcpa_enc( uint8_t c[MLKEM_INDCPA_BYTES],
                const uint8_t m[MLKEM_INDCPA_MSGBYTES],
                const uint8_t pk[MLKEM_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[MLKEM_SYMBYTES],
                unsigned int *cmp_out)
{   
    volatile uint64_t rc = 0;
    poly sp;                    
    poly mag;                
    poly *b = &sp;
    poly *k = &sp;
    poly *v = &mag;          
    const unsigned char *seed = pk + MLKEM_POLYVECBYTES;
    int i,j,l;
    unsigned char nonce = 0;


    // //bod 1
    // buffrujem jeden poly, lebo mam volnu pamat a zrychlim tak matrix
    // nebufrovanie a pouzitie matrix_opt2 nam usetri len 16b
    // poly_getnoise_eta1(&sp, coins, nonce++);
    // poly_ntt(&sp);
    // nonce+=(MLKEM_K-1); //correction for not iterating
    nonce+=(MLKEM_K); //correction for not iterating

    //bod 2
    // matrix-vector multiplication
    // for (i = 0; i < MLKEM_K; i++) {
    //     matrix_opt(&b, &sp, &mag, i, seed, coins, 1);
    //     poly_invntt_tomont(&b); 
    //     poly_addnoise_eta2(&b, coins, nonce++);
    //     poly_reduce(&b);
    //     poly_packcompress(c, &b, i);
    // }
    for (i = 0; i < MLKEM_K; i++) {
        matacc_xtreme(b, &mag, i, seed, coins, 1);
        poly_invntt_tomont(b); 
        poly_addnoise_eta2(b, coins, nonce++);
        poly_reduce(b);
        if (cmp_out != ENC_ONLY){
          rc |= cmp_poly_packcompress(c, b, i);
        }
        else {
          poly_packcompress(c, b, i);
        }
    }

    //bod 3
    // lava linia algoritmu
    // toto je bottleneck, potrebujem 3 polys
    // nahradit poly pkp rozkladom na koeficienty
    // poly_frombytes(pkp, pk); //vie ist na 2 koefs
    // poly_basemul(v->coeffs, pkp->coeffs, sp.coeffs);  // vie ist na koef
    // for (i = 1; i < MLKEM_K; i++) {
    //     poly_getnoise_eta1(&sp, coins, i);  // vie ist na koed
    //     poly_ntt(&sp); //vie ist na koef
    //     poly_frombytes(pkp, pk + i * MLKEM_POLYBYTES);
    //     poly_basemul_acc(v->coeffs, pkp->coeffs, sp.coeffs);
    // }
    for (i = 0; i < MLKEM_K; i++) {
        poly_getnoise_eta1(&sp, coins, i);
        poly_ntt(&sp);
        const uint8_t *pk_i = pk + i * MLKEM_POLYBYTES;
        const int16_t *zeta = zetas + 64;
        int16_t pkp_pair[2];
        for (j = 0; j < MLKEM_N; j += 2) {
            l = j / 2;
            pkp_pair[0] = ((pk_i[3*l+0]     ) | ((uint16_t)pk_i[3*l+1] << 8)) & 0xFFF;
            pkp_pair[1] = ((pk_i[3*l+1] >> 4) | ((uint16_t)pk_i[3*l+2] << 4)) & 0xFFF;
            int16_t z = zeta[(j % 16) / 4];
            if ((j % 4) >= 2) z = -z;
            if (i == 0) basemul    (v->coeffs + j, pkp_pair, sp.coeffs + j, z);
            else         basemul_acc(v->coeffs + j, pkp_pair, sp.coeffs + j, z);
            if ((j % 16) == 14) zeta += 4;
        }
    }


    //bod 4
    poly_invntt_tomont(v);
    poly_addnoise_eta2(v, coins, nonce++);

    poly_frommsg(k, m);
    poly_add(v, v, k);
    poly_reduce(v);

    if (cmp_out != ENC_ONLY){
      rc |= cmp_poly_compress(c + MLKEM_POLYVECCOMPRESSEDBYTES, v);
      rc = ~rc + 1;
      rc >>= 63;
      *cmp_out = (unsigned int)rc;   // 0 = match, 1 = mismatch
    }
    else {
      poly_compress(c + MLKEM_POLYVECCOMPRESSEDBYTES, v);
    }

    // Nicenie medzivysledkov podla FIP203 Section 3.3
    buffer_zeroize(&sp,  sizeof(sp));
    buffer_zeroize(&mag, sizeof(mag));

    return 0;
}
#elif defined(STACK)
int indcpa_enc( uint8_t c[MLKEM_INDCPA_BYTES],
                const uint8_t m[MLKEM_INDCPA_MSGBYTES],
                const uint8_t pk[MLKEM_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[MLKEM_SYMBYTES],
                unsigned int *cmp_out)
{ 
    volatile uint64_t rc = 0; //pre zabranienie opt kompilatorom
    polyvec sp;
    poly b;
    poly *pkp = &b;
    poly *k = &b;
    poly *v = &sp.vec[0];
    const unsigned char *seed = pk + MLKEM_POLYVECBYTES;
    int i;
    unsigned char nonce = 0;

    //bod 1
    for (i = 0; i < MLKEM_K; i++) {
        poly_getnoise_eta1(sp.vec + i, coins, nonce++);
    }
    polyvec_ntt(&sp);

    //bod 2
    // matrix-vector multiplication
    for (i = 0; i < MLKEM_K; i++) {
        matacc(&b, &sp, i, seed, 1);
        poly_invntt_tomont(&b);

        poly_addnoise_eta2(&b, coins, nonce++);
        poly_reduce(&b);
        if (cmp_out != ENC_ONLY){
          rc |= cmp_poly_packcompress(c, &b, i);
        }
        else {
          poly_packcompress(c, &b, i);
        }
    }

    //bod 3
    poly_frombytes(pkp, pk);
    poly_basemul(v->coeffs, pkp->coeffs, sp.vec[0].coeffs);
    for (i = 1; i < MLKEM_K; i++) {
        poly_frombytes(pkp, pk + i * MLKEM_POLYBYTES);
        poly_basemul_acc(v->coeffs, pkp->coeffs, sp.vec[i].coeffs);
    }
    //bod 4
    poly_invntt_tomont(v);
    poly_addnoise_eta2(v, coins, nonce++);

    poly_frommsg(k, m);
    poly_add(v, v, k);
    poly_reduce(v);

    if (cmp_out != ENC_ONLY){
      rc |= cmp_poly_compress(c + MLKEM_POLYVECCOMPRESSEDBYTES, v);
      rc = ~rc + 1;
      rc >>= 63;
      *cmp_out  = (unsigned int)rc;   // 0 = match, 1 = mismatch
    }
    else {
      poly_compress(c + MLKEM_POLYVECCOMPRESSEDBYTES, v);
    }

    // Nicenie medzivysledkov podla FIP203 Section 3.3
    buffer_zeroize(&sp, sizeof(sp));
    buffer_zeroize(&b,  sizeof(b));

    return 0;

}
#else 
  #error "chyba prepinacov pre indcpa_enc"
#endif

/*************************************************
* Name:        indcpa_dec
*
* Description: Decryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *m: pointer to output decrypted message
*                            (of length MLKEM_INDCPA_MSGBYTES)
*              - const uint8_t *c: pointer to input ciphertext
*                                  (of length MLKEM_INDCPA_BYTES)
*              - const uint8_t *sk: pointer to input secret key
*                                   (of length MLKEM_INDCPA_SECRETKEYBYTES)
**************************************************/
#if defined(SPEED_DUALCORE)
typedef struct IndcpaDecData_t
{
  uint8_t * m;
  const uint8_t *c;
  const uint8_t *sk;
  
  polyvec b, skpv;
  poly v, mp;
  TaskHandle_t main_task_handle;     
  TaskHandle_t support_task_handle;  
} GenericIndcpaDecData_t __attribute__((aligned(XSTRUCT_ALIGN_VAL)));

void indcpa_dec_dual_derand_SUPPORT_CORE(void *xStruct) {
  GenericIndcpaDecData_t * data = (GenericIndcpaDecData_t *) xStruct;
    

    unpack_sk(&data->skpv, data->sk);
    // 2nd smaller part of unpack_ciphertext()
    poly_decompress(&data->v, data->c+MLKEM_POLYVECCOMPRESSEDBYTES);

    // Wait for Core MAIN to unpack_ciphertext
    ulTaskNotifyTake(pdFALSE, portMAX_DELAY);  // Wait: pkpv ready
    portMEMORY_BARRIER();

    // Split supp
    // K=2,3 -> i=1, K=4-> i=1,3
    unsigned int i;
    for (i = 1; i < MLKEM_K; i += 2)
      poly_ntt(&data->b.vec[i]);
    

    // Signal Core MAIN that NTT is done
    portMEMORY_BARRIER();
    xTaskNotifyGive(data->main_task_handle);
    

    vTaskDelete(NULL);    
}

int indcpa_dec(uint8_t m[MLKEM_INDCPA_MSGBYTES],
                const uint8_t c[MLKEM_INDCPA_BYTES],
                const uint8_t sk[MLKEM_INDCPA_SECRETKEYBYTES])
{
  GenericIndcpaDecData_t xStruct = {
    .m = m, 
    .c = c, 
    .sk = sk
  };
  
  xStruct.main_task_handle = xTaskGetCurrentTaskHandle();
  
  BaseType_t xReturned = xTaskCreatePinnedToCore(
                  indcpa_dec_dual_derand_SUPPORT_CORE,      
                  "indcpa_dec_dual_derand_SUPPORT_CORE",        
                  INDCPA_STACK_DEC,      
                  ( void * ) &xStruct,    
                  MLKEM_TASK_PRIORITY, 
                  &xStruct.support_task_handle,
                  (BaseType_t) MLKEM_SUPPORT_CORE); 
  
  if (xReturned != pdPASS) return 1;

  // vyskusat delenem prakticky vyrovna
  // unpack_ciphertext(&xStruct.b, &xStruct.v, xStruct.c);
  // 1st bigger part of unpack_ciphertext()
  polyvec_decompress(&xStruct.b, xStruct.c);

  // Signal Core SUPPPORT it can NTT
  portMEMORY_BARRIER(); 
  xTaskNotifyGive(xStruct.support_task_handle); 
  
  // Split main
  // K=2 -> i=0, K=3,4-> i=0,2
  unsigned int i;
  for (i = 0; i < MLKEM_K; i += 2) 
    poly_ntt(&xStruct.b.vec[i]);
    

  // Wait for Core SUPPORT to finish NTT
  ulTaskNotifyTake(pdFALSE, portMAX_DELAY);  
  portMEMORY_BARRIER();



  polyvec_basemul_acc_montgomery(&xStruct.mp, &xStruct.skpv, &xStruct.b);
  poly_invntt_tomont(&xStruct.mp);
  poly_sub(&xStruct.mp, &xStruct.v, &xStruct.mp);
  poly_reduce(&xStruct.mp);
  poly_tomsg(xStruct.m, &xStruct.mp);

  // Nicenie medzivysledkov podla FIP203 Section 3.3
  buffer_zeroize(&xStruct.skpv, sizeof(xStruct.skpv));
  buffer_zeroize(&xStruct.b,    sizeof(xStruct.b));
  buffer_zeroize(&xStruct.v,    sizeof(xStruct.v));
  buffer_zeroize(&xStruct.mp,   sizeof(xStruct.mp));

  return 0;

} 
#elif defined(SPEED)
int indcpa_dec(uint8_t m[MLKEM_INDCPA_MSGBYTES],
                const uint8_t c[MLKEM_INDCPA_BYTES],
                const uint8_t sk[MLKEM_INDCPA_SECRETKEYBYTES])
{
  polyvec b, skpv;
  poly v, mp;

  unpack_ciphertext(&b, &v, c);
  unpack_sk(&skpv, sk);

  polyvec_ntt(&b);
  polyvec_basemul_acc_montgomery(&mp, &skpv, &b);
  poly_invntt_tomont(&mp);

  poly_sub(&mp, &v, &mp);
  poly_reduce(&mp);

  poly_tomsg(m, &mp);

  // Nicenie medzivysledkov podla FIP203 Section 3.3
  buffer_zeroize(&skpv, sizeof(skpv));
  buffer_zeroize(&b,    sizeof(b));
  buffer_zeroize(&v,    sizeof(v));
  buffer_zeroize(&mp,   sizeof(mp));

  return 0;
}
#elif defined(STACK_DUALCORE)

typedef struct IndcpaDecData_t
{
  uint8_t        *m;
  const uint8_t  *c;
  const uint8_t  *sk;

  poly            mp_support;  
  TaskHandle_t    main_task_handle;
  TaskHandle_t    support_task_handle;
} IndcpaDecData_t __attribute__((aligned(XSTRUCT_ALIGN_VAL)));

static void indcpa_dec_SUPPORT_CORE(void *xArg)
{
  IndcpaDecData_t *data = (IndcpaDecData_t *)xArg;

  poly bp;

  //bod1
  poly_unpackdecompress(&bp, data->c, 1);
  poly_ntt(&bp);
  poly_frombytes_basemul(&data->mp_support, &bp, data->sk + 1 * MLKEM_POLYBYTES);

  #if (MLKEM_K == 4)
    poly_unpackdecompress(&bp, data->c, 3);
    poly_ntt(&bp);
    poly_frombytes_basemul_acc(&data->mp_support, &bp, data->sk + 3 * MLKEM_POLYBYTES);
  #endif 

  // Nicenie medzivysledkov podla FIP203 Section 3.3
  buffer_zeroize(&bp, sizeof(bp));

  // Signal Core MAIN it is done
  portMEMORY_BARRIER();
  xTaskNotifyGive(data->main_task_handle);

  vTaskDelete(NULL);
}


int indcpa_dec(uint8_t        m[MLKEM_INDCPA_MSGBYTES],
               const uint8_t  c[MLKEM_INDCPA_BYTES],
               const uint8_t  sk[MLKEM_INDCPA_SECRETKEYBYTES])
{
  IndcpaDecData_t xStruct = {
    .m  = m,
    .c  = c,
    .sk = sk,
  };

  xStruct.main_task_handle = xTaskGetCurrentTaskHandle();

  /* launch support core to handle index 0 */
  BaseType_t xReturned = xTaskCreatePinnedToCore(
      indcpa_dec_SUPPORT_CORE,
      "indcpa_dec_SUPPORT_CORE",
      INDCPA_STACK_DEC,
      (void *)&xStruct,
      MLKEM_TASK_PRIORITY,
      &xStruct.support_task_handle,
      (BaseType_t)MLKEM_SUPPORT_CORE);

  if (xReturned != pdPASS) return 1;

  poly mp, bp;
  poly *v = &bp;

  //bod1
  poly_unpackdecompress(&bp, c, 0);
  poly_ntt(&bp);
  poly_frombytes_basemul(&mp, &bp, sk);

  #if (MLKEM_K > 2)
    poly_unpackdecompress(&bp, c, 2);
    poly_ntt(&bp);
    poly_frombytes_basemul_acc(&mp, &bp, sk + 2 * MLKEM_POLYBYTES);
  #endif 

  // Wait for Core SUPPORT to finish NTT
  ulTaskNotifyTake(pdFALSE, portMAX_DELAY);
  portMEMORY_BARRIER();

  // Merge Core SUPPORT work
  for (int j = 0; j < MLKEM_N; j++)
    mp.coeffs[j] += xStruct.mp_support.coeffs[j];

  //bod3
  poly_invntt_tomont(&mp);
  poly_decompress(v, c + MLKEM_POLYVECCOMPRESSEDBYTES);
  poly_sub(&mp, v, &mp);
  poly_reduce(&mp);

  poly_tomsg(m, &mp);

  // Nicenie medzivysledkov podla FIP203 Section 3.3
  buffer_zeroize(&mp,                   sizeof(mp));
  buffer_zeroize(&bp,                   sizeof(bp));
  buffer_zeroize(&xStruct.mp_support,   sizeof(xStruct.mp_support));

  return 0;
}
#elif defined(STACK) || defined(STACK_XTREME)
// paralelizacia mozna - body 1a a 1b rozhodit na jadra
int __attribute__ ((noinline)) indcpa_dec(uint8_t m[MLKEM_INDCPA_MSGBYTES],
        const uint8_t c[MLKEM_INDCPA_BYTES],
        const uint8_t sk[MLKEM_INDCPA_SECRETKEYBYTES]) 
{
    poly mp, bp;
    poly *v = &bp;

    //bod1a
    poly_unpackdecompress(&bp, c, 0);
    poly_ntt(&bp);
    poly_frombytes_basemul(&mp, &bp, sk);

    //bod1b
    for (int i = 1; i < MLKEM_K; i++) {
        poly_unpackdecompress(&bp, c, i);
        poly_ntt(&bp);
        poly_frombytes_basemul_acc(&mp,  &bp, sk + i * MLKEM_POLYBYTES);
    }

    //bod3
    poly_invntt_tomont(&mp);
    poly_decompress(v, c + MLKEM_POLYVECCOMPRESSEDBYTES);
    poly_sub(&mp, v, &mp);
    poly_reduce(&mp);

    poly_tomsg(m, &mp);

    // Nicenie medzivysledkov podla FIP203 Section 3.3
    buffer_zeroize(&mp, sizeof(mp));
    buffer_zeroize(&bp, sizeof(bp));

    return 0;
}
#else 
  #error "chyba prepinacov pre indcpa_dec"
#endif
