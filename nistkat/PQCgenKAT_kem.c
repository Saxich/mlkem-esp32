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
#include <stdlib.h>
#include "../kem.h"
#include "../indcpa.h"
#include "../fips202.h"


// Embedded KAT data
static const char kat_input_data[] =
#include "kat_input_vectors.inc"
;

static const char kat_output_hash_data[] =
#if KYBER_K == 2
#include "kat_512_output_hash.inc"
#elif KYBER_K == 3
#include "kat_768_output_hash.inc"
#elif KYBER_K == 4
#include "kat_1024_output_hash.inc"
#endif
;

// Print hex data
static void print_hex_field(const char *name, const uint8_t *data, size_t len) {
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
    
#if KYBER_K == 2
    printf("\n# ML-KEM-512 KAT TEST\n\n");
#elif KYBER_K == 3
    printf("\n# ML-KEM-768 KAT TEST\n\n");
#elif KYBER_K == 4
    printf("\n# ML-KEM-1024 KAT TEST\n\n");
#endif

    // Open input vectors
    fp_input = fmemopen((void *)kat_input_data, sizeof(kat_input_data) - 1, "r");
    if (fp_input == NULL) {
        printf("ERROR: cannot open embedded KAT input data\n");
        return;
    }

    // Open output hashes
    fp_hash = fmemopen((void *)kat_output_hash_data, sizeof(kat_output_hash_data) - 1, "r");
    if (fp_hash == NULL) {
        printf("ERROR: cannot open embedded KAT output hash data\n");
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

    printf("Input vector sets: %d\n", input_vector_sets);
    printf("Output hash sets: %d\n\n", output_hash_sets);

    // Process test vectors
    while (fgets(line, sizeof(line), fp_input) != NULL) {
        uint8_t d[KYBER_SYMBYTES];
        uint8_t z[KYBER_SYMBYTES];
        uint8_t coins[2*KYBER_SYMBYTES];
        uint8_t pk[CRYPTO_PUBLICKEYBYTES];
        uint8_t sk[CRYPTO_SECRETKEYBYTES];
        uint8_t m[KYBER_SYMBYTES];
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
            
            printf("Testing vector set %d...\n", count);
            
            // Read input vectors (z, d, m)
            if (read_kat_line(fp_input, z, KYBER_SYMBYTES)) break;
            if (read_kat_line(fp_input, d, KYBER_SYMBYTES)) break;
            if (read_kat_line(fp_input, m, KYBER_SYMBYTES)) break;

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
                printf("ERROR: Cannot read reference hashes for count %d\n", count);
                break;
            }
            
            compared_count++;

            // Generate keypair
            memcpy(coins, d, KYBER_SYMBYTES);
            memcpy(coins + KYBER_SYMBYTES, z, KYBER_SYMBYTES);
            crypto_kem_keypair_derand(pk, sk, coins);
            
            // Hash public key and compare
            sha3_256(pk_hash, pk, CRYPTO_PUBLICKEYBYTES);
            pk_match = (memcmp(pk_hash, ref_pk_hash, 32) == 0);
            
            // print_hex_field("computed_pk", pk, CRYPTO_PUBLICKEYBYTES);
            // print_hex_field("computed_pk_hash", pk_hash, 32);
            // print_hex_field("reference_pk_hash", ref_pk_hash, 32);
            
            if (!pk_match) {
                printf("  FAIL: pk hash mismatch\n");
            }
            
            // Hash secret key and compare
            sha3_256(sk_hash, sk, CRYPTO_SECRETKEYBYTES);
            sk_match = (memcmp(sk_hash, ref_sk_hash, 32) == 0);
            
            // print_hex_field("computed_sk", sk, CRYPTO_SECRETKEYBYTES);
            // print_hex_field("computed_sk_hash", sk_hash, 32);
            // print_hex_field("reference_sk_hash", ref_sk_hash, 32);
            
            if (!sk_match) {
                printf("  FAIL: sk hash mismatch\n");
            }

            // Encapsulate
            crypto_kem_enc_derand(ct, ss_enc, pk, m);
            
            // Hash ciphertext and compare
            sha3_256(ct_hash, ct, CRYPTO_CIPHERTEXTBYTES);
            ct_match = (memcmp(ct_hash, ref_ct_hash, 32) == 0);
            
            // print_hex_field("computed_ct", ct, CRYPTO_CIPHERTEXTBYTES);
            // print_hex_field("computed_ct_hash", ct_hash, 32);
            // print_hex_field("reference_ct_hash", ref_ct_hash, 32);
            
            if (!ct_match) {
                printf("  FAIL: ct hash mismatch\n");
            }
            
            // Hash shared secret and compare
            sha3_256(ss_hash, ss_enc, CRYPTO_BYTES);
            ss_match = (memcmp(ss_hash, ref_ss_hash, 32) == 0);
            
            // print_hex_field("computed_ss", ss_enc, CRYPTO_BYTES);
            // print_hex_field("computed_ss_hash", ss_hash, 32);
            // print_hex_field("reference_ss_hash", ref_ss_hash, 32);
            
            if (!ss_match) {
                printf("  FAIL: ss hash mismatch\n");
            }

            // Decapsulate and verify
            crypto_kem_dec(ss_dec, ct, sk);
            if (memcmp(ss_enc, ss_dec, CRYPTO_BYTES)) {
                printf("  ERROR: Encapsulation/decapsulation mismatch!\n");
            }

            // Check if all hashes match
            if (pk_match && sk_match && ct_match && ss_match) {
                printf("Vector set %d PASSED\n", count);
                passed_count++;
            } else {
                printf("Vector set %d FAILED\n", count);
            }
            
            printf("\n");
            count++;
        }
    }

    fclose(fp_input);
    fclose(fp_hash);

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
    
    if (passed_count == compared_count && compared_count > 0) {
        printf("\n✓ ALL TESTS PASSED!\n");
    } else {
        printf("\n✗ SOME TESTS FAILED\n");
    }
    printf("==================================\n");
}


int main(void) {
    generate_kat_output();
    return 0;
}
