/*
 * Known Answer Test (KAT) for ML-KEM (FIPS 203)
 *
 * Copyright (C) 2026 Michal Saxa
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * KAT vectors: post-quantum-cryptography/KAT (public domain / CC0)
 *   https://github.com/post-quantum-cryptography/KAT/tree/main/MLKEM
 *   Accessed: 2025-11-07
 *
 * See CREDITS.md for full attribution.
 * 
 */

#include <stdio.h>
#include <string.h>
#include "kem.h"
#include "indcpa.h"
#include "fips202.h"


// Embedded KAT data
static const char kat_input_data[] =
#include "kat_input_vectors.inc"
;

static const char kat_output_hash_data[] =
#if MLKEM_K == 2
#include "kat_512_output_hash.inc"
#elif MLKEM_K == 3
#include "kat_768_output_hash.inc"
#elif MLKEM_K == 4
#include "kat_1024_output_hash.inc"
#endif
;

// Print hex data
void print_hex_field(const char *name, const uint8_t *data, size_t len) {
    printf("%s = ", name);
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

static uint8_t hex_char_to_byte(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

static void hex_string_to_bytes(uint8_t *out, const char *hex, size_t len) {
    for (size_t i = 0; i < len; i++)
        out[i] = (hex_char_to_byte(hex[2*i]) << 4) | hex_char_to_byte(hex[2*i + 1]);
}

static int read_kat_line(FILE *fp, uint8_t *out, size_t len) {
    char line[2048];
    if (fgets(line, sizeof(line), fp) == NULL) return -1;
    size_t line_len = strlen(line);
    if (line_len && (line[line_len-1] == '\n' || line[line_len-1] == '\r'))
        line[--line_len] = '\0';
    if (line_len < len * 2) return -1;
    hex_string_to_bytes(out, line, len);
    return 0;
}

void generate_kat_output(void) {
    FILE *fp_input;
    FILE *fp_hash;
    char line[256];
    int count = 0;
    int passed_count = 0;
    int compared_count = 0;
    int input_vector_sets = 0;
    int output_hash_sets = 0;

#ifndef KAT_TEST_AUTOMAT
    printf("\nAlgorithm: %s\n", CRYPTO_ALGNAME);
    printf("Mode: %s\n\n", CRYPTO_ALGMODE);
#endif

    // Open input vectors
    fp_input = fmemopen((void *)kat_input_data, sizeof(kat_input_data) - 1, "r");
    if (fp_input == NULL) {
#ifndef KAT_TEST_AUTOMAT
        printf("ERROR: cannot open embedded KAT input data\n");
#endif
        return;
    }

    // Open output hashes
    fp_hash = fmemopen((void *)kat_output_hash_data, sizeof(kat_output_hash_data) - 1, "r");
    if (fp_hash == NULL) {
#ifndef KAT_TEST_AUTOMAT
        printf("ERROR: cannot open embedded KAT output hash data\n");
#endif
        fclose(fp_input);
        return;
    }

    // Count input vector sets
    FILE *fp_count = fmemopen((void *)kat_input_data, sizeof(kat_input_data) - 1, "r");
    while (fgets(line, sizeof(line), fp_count) != NULL) {
        if (strncmp(line, "count = ", 8) == 0) input_vector_sets++;
    }
    fclose(fp_count);

    // Count output hash sets
    fp_count = fmemopen((void *)kat_output_hash_data, sizeof(kat_output_hash_data) - 1, "r");
    while (fgets(line, sizeof(line), fp_count) != NULL) {
        if (strncmp(line, "count = ", 8) == 0) output_hash_sets++;
    }
    fclose(fp_count);

#ifndef KAT_TEST_AUTOMAT
    printf("Input vector sets: %d\n", input_vector_sets);
    printf("Output hash sets: %d\n\n", output_hash_sets);
#endif

    // Process test vectors
    while (fgets(line, sizeof(line), fp_input) != NULL) {
        uint8_t d[MLKEM_SYMBYTES];
        uint8_t z[MLKEM_SYMBYTES];
        uint8_t coins[2*MLKEM_SYMBYTES];
        uint8_t pk[CRYPTO_PUBLICKEYBYTES];
        uint8_t sk[CRYPTO_SECRETKEYBYTES];
        uint8_t m[MLKEM_SYMBYTES];
        uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
        uint8_t ss_enc[CRYPTO_BYTES];
        uint8_t ss_dec[CRYPTO_BYTES];
        
        uint8_t pk_hash[32];
        uint8_t sk_hash[32];
        uint8_t ct_hash[32];
        uint8_t ss_hash[32];
        
        uint8_t ref_pk_hash[32];
        uint8_t ref_sk_hash[32];
        uint8_t ref_ct_hash[32];
        uint8_t ref_ss_hash[32];

        if (strncmp(line, "count = ", 8) == 0) {
            int pk_match = 0, sk_match = 0, ct_match = 0, ss_match = 0;

#ifndef KAT_TEST_AUTOMAT            
            printf("Testing vector set %d...\n", count);
#endif
            
            // Read input vectors (z, d, m)
            if (read_kat_line(fp_input, z, MLKEM_SYMBYTES)) break;
            if (read_kat_line(fp_input, d, MLKEM_SYMBYTES)) break;
            if (read_kat_line(fp_input, m, MLKEM_SYMBYTES)) break;

            // Read reference hashes from output file
            char hash_line[256];
            int hash_found = 0;
            while (fgets(hash_line, sizeof(hash_line), fp_hash) != NULL) {
                if (strncmp(hash_line, "count = ", 8) == 0) {
                    hash_found = 1;
                    break;
                }
            }
            
            if (!hash_found || 
                read_kat_line(fp_hash, ref_pk_hash, 32) ||
                read_kat_line(fp_hash, ref_sk_hash, 32) ||
                read_kat_line(fp_hash, ref_ct_hash, 32) ||
                read_kat_line(fp_hash, ref_ss_hash, 32)) {
#ifndef KAT_TEST_AUTOMAT
                printf("ERROR: Cannot read reference hashes for count %d\n", count);
#endif
                break;
            }
            
            compared_count++;

            // Generate keypair
            memcpy(coins, d, MLKEM_SYMBYTES);
            memcpy(coins + MLKEM_SYMBYTES, z, MLKEM_SYMBYTES);
            crypto_kem_keypair_derand(pk, sk, coins);
            
            // Hash public key and compare
            sha3_256(pk_hash, pk, CRYPTO_PUBLICKEYBYTES);
            pk_match = (memcmp(pk_hash, ref_pk_hash, 32) == 0);
            
#ifndef KAT_TEST_AUTOMAT
            if (!pk_match) {
                printf("  FAIL: pk hash mismatch\n");
            }
#endif
            
            // Hash secret key and compare
            sha3_256(sk_hash, sk, CRYPTO_SECRETKEYBYTES);
            sk_match = (memcmp(sk_hash, ref_sk_hash, 32) == 0);
            
#ifndef KAT_TEST_AUTOMAT
            if (!sk_match) {
                printf("  FAIL: sk hash mismatch\n");
            }
#endif

            // Encapsulate
            crypto_kem_enc_derand(ct, ss_enc, pk, m);
            
            // Hash ciphertext and compare
            sha3_256(ct_hash, ct, CRYPTO_CIPHERTEXTBYTES);
            ct_match = (memcmp(ct_hash, ref_ct_hash, 32) == 0);
            
#ifndef KAT_TEST_AUTOMAT
            if (!ct_match) {
                printf("  FAIL: ct hash mismatch\n");
            }
#endif
            
            // Hash shared secret and compare
            sha3_256(ss_hash, ss_enc, CRYPTO_BYTES);
            ss_match = (memcmp(ss_hash, ref_ss_hash, 32) == 0);
            
#ifndef KAT_TEST_AUTOMAT
            if (!ss_match) {
                printf("  FAIL: ss hash mismatch\n");
            }
#endif

            // Decapsulate and verify
            crypto_kem_dec(ss_dec, ct, sk);
#ifndef KAT_TEST_AUTOMAT
            if (memcmp(ss_enc, ss_dec, CRYPTO_BYTES)) {
                printf("  ERROR: Encapsulation/decapsulation mismatch!\n");
            }
#endif

            // Check if all hashes match
            if (pk_match && sk_match && ct_match && ss_match) {
#ifndef KAT_TEST_AUTOMAT
                printf("Vector set %d PASSED\n", count);
#endif
                passed_count++;
            }
#ifndef KAT_TEST_AUTOMAT
            else {
                printf("Vector set %d FAILED\n", count);
            }
            
            printf("\n");
#endif
            count++;

        }

        // preskrateny test nepouzivaj vsetky vektory
        #if(TEST_TO_TURN == 4)
            if (count==100)
                break;
        #endif
    }

    fclose(fp_input);
    fclose(fp_hash);

#ifdef KAT_TEST_AUTOMAT
    printf("Automated KAT for %s  %d\n", CRYPTO_ALGMODE, MLKEM_K);
    printf("%s\n", (passed_count == compared_count && compared_count > 0) ? "PASSED" : "FAILED");
#else
    // Final summary
    printf("\n========== TEST SUMMARY ==========\n");
    printf("Input vector sets: %d\n", input_vector_sets);
    printf("Output hash sets: %d\n", output_hash_sets);
    printf("Compared vector sets: %d\n", compared_count);
    printf("Passed: %d / %d\n", passed_count, compared_count);
    
    if (input_vector_sets != output_hash_sets) {
        int not_compared = abs(input_vector_sets - output_hash_sets);
        printf("WARNING: %d vector sets were not compared (mismatch in input/output counts)\n", not_compared);
    }
    
    printf("==================================\n");
    if (passed_count == compared_count && compared_count > 0) {
        printf("\nALL TESTS PASSED!\n");
    } else {
        printf("\nSOME TESTS FAILED\n");
    }
    printf("==================================\n");
#endif
}



void compare_known_vector(void) {
    FILE *fp_input;
    FILE *fp_hash;
    char line[256];

#ifdef KAT_TEST_AUTOMAT
    printf("Automated KAT for %s  %d\n", CRYPTO_ALGMODE, MLKEM_K);
#else
#if MLKEM_K == 2
    printf("\n# ML-KEM-512 SINGLE VECTOR TEST\n\n");
#elif MLKEM_K == 3
    printf("\n# ML-KEM-768 SINGLE VECTOR TEST\n\n");
#elif MLKEM_K == 4
    printf("\n# ML-KEM-1024 SINGLE VECTOR TEST\n\n");
#endif
#endif

    // Open input vectors
    fp_input = fmemopen((void *)kat_input_data, sizeof(kat_input_data) - 1, "r");
    if (fp_input == NULL) {
#ifndef KAT_TEST_AUTOMAT
        printf("ERROR: cannot open embedded KAT input data\n");
#endif
        return;
    }

    // Open output hashes
    fp_hash = fmemopen((void *)kat_output_hash_data, sizeof(kat_output_hash_data) - 1, "r");
    if (fp_hash == NULL) {
#ifndef KAT_TEST_AUTOMAT
        printf("ERROR: cannot open embedded KAT output hash data\n");
#endif
        fclose(fp_input);
        return;
    }

    // Read until we find the first "count = " line
    while (fgets(line, sizeof(line), fp_input) != NULL) {
        if (strncmp(line, "count = ", 8) == 0) {
            uint8_t d[MLKEM_SYMBYTES];
            uint8_t z[MLKEM_SYMBYTES];
            uint8_t coins[2*MLKEM_SYMBYTES];
            uint8_t pk[CRYPTO_PUBLICKEYBYTES];
            uint8_t sk[CRYPTO_SECRETKEYBYTES];
            uint8_t m[MLKEM_SYMBYTES];
            uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
            uint8_t ss_enc[CRYPTO_BYTES];
            uint8_t ss_dec[CRYPTO_BYTES];

            uint8_t pk_hash[32];
            uint8_t sk_hash[32];
            uint8_t ct_hash[32];
            uint8_t ss_hash[32];

            uint8_t ref_pk_hash[32];
            uint8_t ref_sk_hash[32];
            uint8_t ref_ct_hash[32];
            uint8_t ref_ss_hash[32];

            int pk_match = 0, sk_match = 0, ct_match = 0, ss_match = 0;

#ifndef KAT_TEST_AUTOMAT
            printf("=== Reading Input Vectors (count = 0) ===\n");
#endif

            // Read input vectors (z, d, m)
            if (read_kat_line(fp_input, z, MLKEM_SYMBYTES)) {
#ifndef KAT_TEST_AUTOMAT
                printf("ERROR: Failed to read z\n");
#endif
                break;
            }
#ifndef KAT_TEST_AUTOMAT
            print_hex_field("z (input)", z, MLKEM_SYMBYTES);
#endif

            if (read_kat_line(fp_input, d, MLKEM_SYMBYTES)) {
#ifndef KAT_TEST_AUTOMAT
                printf("ERROR: Failed to read d\n");
#endif
                break;
            }
#ifndef KAT_TEST_AUTOMAT
            print_hex_field("d (input)", d, MLKEM_SYMBYTES);
#endif

            if (read_kat_line(fp_input, m, MLKEM_SYMBYTES)) {
#ifndef KAT_TEST_AUTOMAT
                printf("ERROR: Failed to read m\n");
#endif
                break;
            }
#ifndef KAT_TEST_AUTOMAT
            print_hex_field("m (input)", m, MLKEM_SYMBYTES);
#endif

            // Read reference hashes from output file
            char hash_line[256];
            int hash_found = 0;
            while (fgets(hash_line, sizeof(hash_line), fp_hash) != NULL) {
                if (strncmp(hash_line, "count = ", 8) == 0) {
                    hash_found = 1;
                    break;
                }
            }

            if (!hash_found ||
                read_kat_line(fp_hash, ref_pk_hash, 32) ||
                read_kat_line(fp_hash, ref_sk_hash, 32) ||
                read_kat_line(fp_hash, ref_ct_hash, 32) ||
                read_kat_line(fp_hash, ref_ss_hash, 32)) {
#ifndef KAT_TEST_AUTOMAT
                printf("ERROR: Cannot read reference hashes\n");
#endif
                break;
            }

            // ========== KEYGEN ==========
#ifndef KAT_TEST_AUTOMAT
            printf("\n=== KEYGEN ===\n");
#endif
            memcpy(coins, d, MLKEM_SYMBYTES);
            memcpy(coins + MLKEM_SYMBYTES, z, MLKEM_SYMBYTES);
            crypto_kem_keypair_derand(pk, sk, coins);

            // Hash and compare
            sha3_256(pk_hash, pk, CRYPTO_PUBLICKEYBYTES);
            sha3_256(sk_hash, sk, CRYPTO_SECRETKEYBYTES);

#ifndef KAT_TEST_AUTOMAT
            printf("\n--- KEYGEN Hash Comparison ---\n");
            print_hex_field("pk_hash (computed)", pk_hash, 32);
            print_hex_field("pk_hash (reference)", ref_pk_hash, 32);
#endif
            pk_match = (memcmp(pk_hash, ref_pk_hash, 32) == 0);
#ifndef KAT_TEST_AUTOMAT
            printf("pk_hash match: %s\n", pk_match ? "PASS" : "FAIL");

            print_hex_field("sk_hash (computed)", sk_hash, 32);
            print_hex_field("sk_hash (reference)", ref_sk_hash, 32);
#endif
            sk_match = (memcmp(sk_hash, ref_sk_hash, 32) == 0);
#ifndef KAT_TEST_AUTOMAT
            printf("sk_hash match: %s\n", sk_match ? "PASS" : "FAIL");
#endif

            // ========== ENCAPSULATION ==========
#ifndef KAT_TEST_AUTOMAT
            printf("\n=== ENCAPSULATION ===\n");
#endif
            crypto_kem_enc_derand(ct, ss_enc, pk, m);

            // Hash and compare
            sha3_256(ct_hash, ct, CRYPTO_CIPHERTEXTBYTES);
            sha3_256(ss_hash, ss_enc, CRYPTO_BYTES);

#ifndef KAT_TEST_AUTOMAT
            printf("\n--- ENCAPSULATION Hash Comparison ---\n");
            print_hex_field("ct_hash (computed)", ct_hash, 32);
            print_hex_field("ct_hash (reference)", ref_ct_hash, 32);
#endif
            ct_match = (memcmp(ct_hash, ref_ct_hash, 32) == 0);
#ifndef KAT_TEST_AUTOMAT
            printf("ct_hash match: %s\n", ct_match ? "PASS" : "FAIL");

            print_hex_field("ss_hash (computed)", ss_hash, 32);
            print_hex_field("ss_hash (reference)", ref_ss_hash, 32);
#endif
            ss_match = (memcmp(ss_hash, ref_ss_hash, 32) == 0);
#ifndef KAT_TEST_AUTOMAT
            printf("ss_hash match: %s\n", ss_match ? "PASS" : "FAIL");
#endif

            // ========== DECAPSULATION ==========
#ifndef KAT_TEST_AUTOMAT
            printf("\n=== DECAPSULATION ===\n");
#endif
            crypto_kem_dec(ss_dec, ct, sk);

            int ss_enc_dec_match = (memcmp(ss_enc, ss_dec, CRYPTO_BYTES) == 0);
#ifndef KAT_TEST_AUTOMAT
            printf("ss_enc == ss_dec: %s\n", ss_enc_dec_match ? "PASS" : "FAIL");
#endif

#ifdef KAT_TEST_AUTOMAT
            printf("%s\n", (pk_match && sk_match && ct_match && ss_match && ss_enc_dec_match) ? "PASSED" : "FAILED");
#else
            // ========== SUMMARY ==========
            printf("\n========== TEST SUMMARY ==========\n");
            printf("pk_hash: %s\n", pk_match ? "PASS" : "FAIL");
            printf("sk_hash: %s\n", sk_match ? "PASS" : "FAIL");
            printf("ct_hash: %s\n", ct_match ? "PASS" : "FAIL");
            printf("ss_hash: %s\n", ss_match ? "PASS" : "FAIL");
            printf("enc/dec consistency: %s\n", ss_enc_dec_match ? "PASS" : "FAIL");

            if (pk_match && sk_match && ct_match && ss_match && ss_enc_dec_match) {
                printf("\nALL TESTS PASSED!\n");
            } else {
                printf("\nSOME TESTS FAILED\n");
            }
            printf("==================================\n");
#endif

            // Only process first vector set, so break here
            break;
        }
    }

    fclose(fp_input);
    fclose(fp_hash);
}