#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

// =============================================================================
// ML-KEM security level selection
// =============================================================================
// Set MLKEM_VERSION to one of: 512, 768, or 1024.
//   512  — NIST Level 1 (~AES-128)  
//   768  — NIST Level 3 (~AES-192) 
//   1024 — NIST Level 5 (~AES-256) 
#define MLKEM_VERSION  768

// =============================================================================
// Optimization profile — uncomment exactly one
// =============================================================================
// OPT_SPEED      — maximum speed; default wolfSSL behaviour, no size reductions
// OPT_STACK    — minimize stack+heap; slower and larger flash image
// OPT_SIZE — minimize flash image; slightly more RAM, slightly slower
// OPT_BALANCED   — best overall trade-off for ESP32
// =============================================================================
// #define OPT_SPEED
// #define OPT_STACK
// #define OPT_SIZE
#define OPT_BALANCED

// =============================================================================
// DO NOT EDIT BELOW THIS LINE
// =============================================================================

#if MLKEM_VERSION != 512 && MLKEM_VERSION != 768 && MLKEM_VERSION != 1024
    #error "MLKEM_VERSION must be 512, 768, or 1024"
#endif

// =============================================================================
// Optimization profile implementations
// =============================================================================
#ifdef OPT_SPEED
    // Speed is the default wolfSSL behaviour — no extra flags needed.
#endif

#ifdef OPT_STACK   /* minimizes combined stack + heap */
    #define WOLFSSL_SHA3_SMALL
    #define WOLFSSL_MLKEM_ENCAPSULATE_SMALL_MEM
    #define SHA3_BY_SPEC                    // extremely slow
    #define WOLFSSL_MLKEM_NO_LARGE_CODE
#endif

#ifdef OPT_SIZE   /* minimizes flash footprint */
    #define WOLFSSL_SHA3_SMALL
    #define WOLFSSL_MLKEM_NO_LARGE_CODE
    #define WOLFSSL_MLKEM_SMALL
    // WOLFSSL_SMALL_STACK excluded: adds +780B heap and +900B flash when
    // combined with the other flags above, negating the image-size benefit
    #define WOLFSSL_MLKEM_NTT_UNROLL
    #define WOLFSSL_MLKEM_INVNTT_UNROLL
#endif

#ifdef OPT_BALANCED  
    #define WOLFSSL_MLKEM_ENCAPSULATE_SMALL_MEM
    #define WOLFSSL_MLKEM_NO_LARGE_CODE
    #define WOLFSSL_MLKEM_NTT_UNROLL
    #define WOLFSSL_MLKEM_INVNTT_UNROLL
#endif

// =============================================================================
// wolfSSL / ESP-IDF mandatory settings
// =============================================================================
#define WOLFSSL_USER_SETTINGS
#define WOLFCRYPT_ONLY
#define SINGLE_THREADED
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256
#define WOLFSSL_HAVE_MLKEM
#define WOLFSSL_WC_MLKEM
#define NO_SPHINCS_PLUS
#define WOLFSSL_ESPIDF              /* use esp_random() as the RNG source */

/* Enable only the wolfSSL ML-KEM variant matching the selected level */
#if MLKEM_VERSION == 512
    #define WOLFSSL_WC_ML_KEM_512
#elif MLKEM_VERSION == 1024
    #define WOLFSSL_WC_ML_KEM_1024
#else
    #define WOLFSSL_WC_ML_KEM_768
#endif

// =============================================================================
// Derived key/ciphertext sizes for the selected level
// =============================================================================
#if MLKEM_VERSION == 512
    #define MLKEM_LEVEL               WC_ML_KEM_512
    #define CRYPTO_PUBLICKEYBYTES     WC_ML_KEM_512_PUBLIC_KEY_SIZE      // 800
    #define CRYPTO_SECRETKEYBYTES     WC_ML_KEM_512_PRIVATE_KEY_SIZE     // 1632
    #define CRYPTO_CIPHERTEXTBYTES    WC_ML_KEM_512_CIPHER_TEXT_SIZE     // 768
#elif MLKEM_VERSION == 1024
    #define MLKEM_LEVEL               WC_ML_KEM_1024
    #define CRYPTO_PUBLICKEYBYTES     WC_ML_KEM_1024_PUBLIC_KEY_SIZE     // 1568
    #define CRYPTO_SECRETKEYBYTES     WC_ML_KEM_1024_PRIVATE_KEY_SIZE    // 3168
    #define CRYPTO_CIPHERTEXTBYTES    WC_ML_KEM_1024_CIPHER_TEXT_SIZE    // 1568
#else  /* 768 */
    #define MLKEM_LEVEL               WC_ML_KEM_768
    #define CRYPTO_PUBLICKEYBYTES     WC_ML_KEM_768_PUBLIC_KEY_SIZE      // 1184
    #define CRYPTO_SECRETKEYBYTES     WC_ML_KEM_768_PRIVATE_KEY_SIZE     // 2400
    #define CRYPTO_CIPHERTEXTBYTES    WC_ML_KEM_768_CIPHER_TEXT_SIZE     // 1088
#endif

#define CRYPTO_BYTES  32 

#endif /* WOLFSSL_USER_SETTINGS_H */
