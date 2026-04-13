#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H
// #ifdef __cplusplus
// extern "C" {
// #endif



/* 
    ladenie
*/

/*SHA3*/
// #define SHA3_BY_SPEC //-32b stack, +0.5ms speed, +500b image, neviem aky nasledok s small
// #define WOLFSSL_SHA3_SMALL //-~300b stack, +1.3ms speed, -4500b image

/*MLKEM*/
// #define WOLFSSL_MLKEM_MAKEKEY_SMALL_MEM  //+50b stack, +0ms speed, +100b image
// #define WOLFSSL_MLKEM_ENCAPSULATE_SMALL_MEM //-5700b heap, +192b stack, +0.1ms (gen+0), +912b image
// #define WOLFSSL_MLKEM_CACHE_A //+8208b stack, +0.0ms, +128b image - nepouzitelne pre nas test, jelikoz nevykonavam loop(gen->enc->dec) ale samostane loop

/*MLKEM polz*/
// #define WOLFSSL_MLKEM_NO_LARGE_CODE  //+~0.2ms, -7012b image
// #define WOLFSSL_MLKEM_SMALL   //~+0.4ms, -74028b image
// #define WOLFSSL_SMALL_STACK  //+780b heap, -176b stack,  ~+0.05ms speed, -56b image
// #define WOLFSSL_MLKEM_NTT_UNROLL  // +~0.03ms, -2556b iamge
// #define WOLFSSL_MLKEM_INVNTT_UNROLL // +0ms, -1256 iamge

#define OPT_BALANCED

#ifdef OPT_SPEED
#endif

#ifdef OPT_LOW_RAM /*stack+heap*/
    #define WOLFSSL_SHA3_SMAL
    #define WOLFSSL_MLKEM_ENCAPSULATE_SMALL_MEM
    #define SHA3_BY_SPEC //extremne spomaluke
    #define WOLFSSL_MLKEM_NO_LARGE_CODE //11684, 6148
#endif

#ifdef OPT_IMAGE_SIZE
    #define WOLFSSL_SHA3_SMALL
    #define WOLFSSL_MLKEM_NO_LARGE_CODE  
    #define WOLFSSL_MLKEM_SMALL   
    // #define WOLFSSL_SMALL_STACK  //vyradenen lebo pridava +780b heap, +900b image pri kombinacii
    #define WOLFSSL_MLKEM_NTT_UNROLL  
    #define WOLFSSL_MLKEM_INVNTT_UNROLL 
#endif

#ifdef OPT_BALANCED
    #define WOLFSSL_MLKEM_ENCAPSULATE_SMALL_MEM
    #define WOLFSSL_MLKEM_NO_LARGE_CODE
    #define WOLFSSL_MLKEM_NTT_UNROLL
    #define WOLFSSL_MLKEM_INVNTT_UNROLL
#endif




/* ESP-IDF + wolfSSL povinne */
#define WOLFSSL_USER_SETTINGS
#define WOLFCRYPT_ONLY
#define SINGLE_THREADED
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256
#define WOLFSSL_HAVE_MLKEM
#define WOLFSSL_WC_MLKEM  
#define NO_SPHINCS_PLUS   
/* esp_random RNG*/  
#define WOLFSSL_ESPIDF
/* bezpecnostna verzia ML-KEM*/           
#if USE_MLKEM_512
    #define WOLFSSL_WC_ML_KEM_512
#elif USE_MLKEM_1024
    #define WOLFSSL_WC_ML_KEM_1024
#else
    #define WOLFSSL_WC_ML_KEM_768     //  default
#endif

// #define WOLFSSL_SHA3
// #define WOLFSSL_SHAKE128
// #define WOLFSSL_SHAKE256
// #undef WOLFSSL_LIBOQS
// #define WOLFSSL_MLKEM_EXPERIMENTAL     /* explicitly marks it as experimental */
// #define WOLFCRYPT_HAVE_MLKEM_NATIVE  /* Forces native impl (key for v6.1+) */
// #define WOLFSSL_HAVE_PQ      /* General PQ suite */
// #define NO_LIBOQS     
// #define WOLFSSL_ESPIDF
// #define WOLFSSL_ESPWROOM32
// #define NO_WOLFSSL_MEMORY
// #define HAVE_HASHDRBG
// #define USE_FAST_MATH
// #define TFM_TIMING_RESISTANT
// #define WC_RNG_SEED_CB
// #define WOLFSSL_ESP32_CRYPT

// #undef WC_NO_HARDEN   /* removes side-channel warning */
// #ifdef __cplusplus

// #define WOLFSSL_ESP32_CRYPT
// #define WC_RNG_SEED_CB        /* tells wolfSSL to use ESP32 TRNG */
// }
// #endif
#endif