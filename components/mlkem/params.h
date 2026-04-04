/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef PARAMS_H
#define PARAMS_H

#include "user_settings.h"  // single point of truth, always first

#ifndef MLKEM_K
    #define MLKEM_K 3 
#endif

/* ===== PROPAGATION ===== */
#ifdef STACK_DUALCORE
    #undef  STACK
#endif

#ifdef STACK_XTREME
    #undef  STACK
#endif

#ifdef SPEED_DUALCORE
    #undef  SPEED
#endif

/* ===== INTERNAL CODE SWITCHES ===== */
#if (defined(STACK) || defined(STACK_DUALCORE) || defined(STACK_XTREME))
    #define STACK_CODE
#else
    #undef STACK_CODE
#endif

#if defined(SPEED) || defined(SPEED_DUALCORE)
    #define SPEED_CODE
#else
    #undef SPEED_CODE 
#endif

#if defined(STACK_DUALCORE) || defined(SPEED_DUALCORE)
    #define DUALCORE_CODE
#else
    #undef DUALCORE_CODE
#endif

/* ===== MUTUAL EXCLUSION GUARDS ===== */
#if defined(STACK_XTREME) && defined(STACK_DUALCORE)
    #error "STACK_XTREME and STACK_DUALCORE are mutually exclusive"
#endif

#if defined(STACK_CODE) && defined(SPEED_CODE)
    #error "STACK and SPEED modes are mutually exclusive"
#endif

/* ===== FALLBACK: default to SPEED_CODE if nothing selected ===== */
#if !defined(STACK_CODE) && !defined(SPEED_CODE)
    #define SPEED_CODE
    #define SPEED     
#endif


/* ===== MODE NAME ===== */
#if defined(STACK_XTREME)
    #define CRYPTO_ALGMODE "STACK XTREME"
#elif defined(STACK_DUALCORE)
    #define CRYPTO_ALGMODE "STACK DUALCORE"
#elif defined(STACK)
    #define CRYPTO_ALGMODE "STACK"
#elif defined(SPEED_DUALCORE)
    #define CRYPTO_ALGMODE "SPEED DUALCORE"
#else
    #define CRYPTO_ALGMODE "SPEED"
#endif

#if (TEST_TO_TURN == 2)
    #define TIMEANALYSIS 1
#endif // TEST_TO_TURN == 2

#ifndef TEST_TO_TURN
    #define TEST_TO_TURN 1
#endif


#if   (MLKEM_K == 2)
#define MLKEM_NAMESPACE(s) bakalarka_mlkem512_##s
#elif (MLKEM_K == 3)
#define MLKEM_NAMESPACE(s) bakalarka_mlkem768_##s
#elif (MLKEM_K == 4)
#define MLKEM_NAMESPACE(s) bakalarka_mlkem1024_##s
#else
#error "MLKEM_K must be in {2,3,4}"
#endif


#if   (MLKEM_K == 2)
#define CRYPTO_ALGNAME "ML-KEM 512"
#elif (MLKEM_K == 3)
#define CRYPTO_ALGNAME "ML-KEM 768"
#elif (MLKEM_K == 4)
#define CRYPTO_ALGNAME "ML-KEM 1024"
#endif


#define MLKEM_N             256
#define MLKEM_Q             3329
#define MLKEM_Q_HALF        (MLKEM_Q / 2)
#define MLKEM_QINV       62209
#define MLKEM_V          (((1U << 26) + (MLKEM_Q / 2)) / MLKEM_Q)  
#define MLKEM_F          ((1ULL << 32) % MLKEM_Q)                      

#define MLKEM_SYMBYTES 32   /* size in bytes of hashes, and seeds */
#define MLKEM_SSBYTES  32   /* size in bytes of shared key */

#define MLKEM_POLYBYTES     384
#define MLKEM_POLYVECBYTES  (MLKEM_K * MLKEM_POLYBYTES)

#if MLKEM_K == 2
#define MLKEM_ETA1 3
#define MLKEM_POLYCOMPRESSEDBYTES    128
#define MLKEM_POLYVECCOMPRESSEDBYTES (MLKEM_K * 320)
#elif MLKEM_K == 3
#define MLKEM_ETA1 2
#define MLKEM_POLYCOMPRESSEDBYTES    128
#define MLKEM_POLYVECCOMPRESSEDBYTES (MLKEM_K * 320)
#elif MLKEM_K == 4
#define MLKEM_ETA1 2
#define MLKEM_POLYCOMPRESSEDBYTES    160
#define MLKEM_POLYVECCOMPRESSEDBYTES (MLKEM_K * 352)
#endif

#define MLKEM_ETA2 2

#define MLKEM_INDCPA_MSGBYTES       (MLKEM_SYMBYTES)
#define MLKEM_INDCPA_PUBLICKEYBYTES (MLKEM_POLYVECBYTES + MLKEM_SYMBYTES)
#define MLKEM_INDCPA_SECRETKEYBYTES (MLKEM_POLYVECBYTES)
#define MLKEM_INDCPA_BYTES          (MLKEM_POLYVECCOMPRESSEDBYTES + MLKEM_POLYCOMPRESSEDBYTES)

#define MLKEM_PUBLICKEYBYTES  (MLKEM_INDCPA_PUBLICKEYBYTES)
/* 32 bytes of additional space to save H(pk) */
#define MLKEM_SECRETKEYBYTES  (MLKEM_INDCPA_SECRETKEYBYTES + MLKEM_INDCPA_PUBLICKEYBYTES + 2*MLKEM_SYMBYTES)
#define MLKEM_CIPHERTEXTBYTES (MLKEM_INDCPA_BYTES)

// from mlkem-native alignment implementation
#define XSTRUCT_ALIGN_VAL 32
#define VAR_ALIGN __attribute__((aligned(4)))

#endif