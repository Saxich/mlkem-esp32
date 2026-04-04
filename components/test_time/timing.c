/*
 * ML-KEM timing measurement — ESP32 cycle counter profiling
 *
 * Copyright (C) 2026 Michal Saxa
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "../test_time/timing.h"
#include "kem.h"
#include <stdio.h>
#include <string.h>

// =========================================================================
// KEYGEN stat globals  (indcpa_keypair_derand order)
// =========================================================================
timing_stats_t stats_memcpy               = {0, 0};  // 1
timing_stats_t stats_hash_g               = {0, 0};  // 2
timing_stats_t stats_gen_a                = {0, 0};  // 3
timing_stats_t stats_poly_getnoise_eta1   = {0, 0};  // 4  shared with enc
timing_stats_t stats_ntt                  = {0, 0};  // 5  polyvec_ntt, shared with enc
timing_stats_t stats_basemul              = {0, 0};  // 6  polyvec_basemul_acc_montgomery, shared with enc
timing_stats_t stats_poly_tomont          = {0, 0};  // 7
timing_stats_t stats_polyvec_add          = {0, 0};  // 8  shared with enc
timing_stats_t stats_polyvec_reduce       = {0, 0};  // 9  shared with enc
timing_stats_t stats_pack_sk              = {0, 0};  // 10
timing_stats_t stats_pack_pk              = {0, 0};  // 11

// =========================================================================
// ENC-only stat globals  (indcpa_enc order)
// =========================================================================
timing_stats_t stats_unpack_pk            = {0, 0};  // 1
timing_stats_t stats_poly_frommsg         = {0, 0};  // 2
timing_stats_t stats_gen_at               = {0, 0};  // 3
timing_stats_t stats_poly_getnoise_eta2   = {0, 0};  // 5
timing_stats_t stats_invntt               = {0, 0};  // 8  polyvec_invntt_tomont
timing_stats_t stats_poly_invntt          = {0, 0};  // 9  poly_invntt_tomont
timing_stats_t stats_poly_add             = {0, 0};  // 11
timing_stats_t stats_poly_reduce          = {0, 0};  // 13
timing_stats_t stats_pack_ciphertext      = {0, 0};  // 14

// =========================================================================
// DEC-only stat globals  (indcpa_dec order)
// =========================================================================
timing_stats_t stats_unpack_ciphertext = {0, 0};
timing_stats_t stats_unpack_sk         = {0, 0};
timing_stats_t stats_poly_sub          = {0, 0};
timing_stats_t stats_poly_tomsg        = {0, 0};

// =========================================================================
// Operation profiles
// =========================================================================
operation_profile_t profile_keypair = {0};
operation_profile_t profile_enc     = {0};
operation_profile_t profile_dec     = {0};

// =========================================================================
void reset_timing_stats(void) {
    // keygen
    stats_memcpy             = (timing_stats_t){0, 0};
    stats_hash_g             = (timing_stats_t){0, 0};
    stats_gen_a              = (timing_stats_t){0, 0};
    stats_poly_getnoise_eta1 = (timing_stats_t){0, 0};
    stats_ntt                = (timing_stats_t){0, 0};
    stats_basemul            = (timing_stats_t){0, 0};
    stats_poly_tomont        = (timing_stats_t){0, 0};
    stats_polyvec_add        = (timing_stats_t){0, 0};
    stats_polyvec_reduce     = (timing_stats_t){0, 0};
    stats_pack_sk            = (timing_stats_t){0, 0};
    stats_pack_pk            = (timing_stats_t){0, 0};
    // enc-only
    stats_unpack_pk          = (timing_stats_t){0, 0};
    stats_poly_frommsg       = (timing_stats_t){0, 0};
    stats_gen_at             = (timing_stats_t){0, 0};
    stats_poly_getnoise_eta2 = (timing_stats_t){0, 0};
    stats_invntt             = (timing_stats_t){0, 0};
    stats_poly_invntt        = (timing_stats_t){0, 0};
    stats_poly_add           = (timing_stats_t){0, 0};
    stats_poly_reduce        = (timing_stats_t){0, 0};
    stats_pack_ciphertext    = (timing_stats_t){0, 0};
    // dec-only
    stats_unpack_ciphertext = (timing_stats_t){0, 0};
    stats_unpack_sk         = (timing_stats_t){0, 0};
    stats_poly_sub          = (timing_stats_t){0, 0};
    stats_poly_tomsg        = (timing_stats_t){0, 0};
}

// =========================================================================
void save_current_profile(operation_profile_t *profile,
                          const char *op_name,
                          uint32_t iterations,
                          uint64_t total_cycles) {
    strncpy(profile->operation_name, op_name, sizeof(profile->operation_name) - 1);
    profile->iterations   = iterations;
    profile->total_cycles = total_cycles;

    int operation_type = -1;
    if      (strcmp(op_name, "keypair") == 0) operation_type = 0;
    else if (strcmp(op_name, "enc")     == 0) operation_type = 1;
    else if (strcmp(op_name, "dec")     == 0) operation_type = 2;

    profile->total_cycles_table = (operation_type >= 0)
                                  ? get_reference_cycles(operation_type) : 0;

    // keygen snapshot
    profile->memcpy             = stats_memcpy;
    profile->hash_g             = stats_hash_g;
    profile->gen_a              = stats_gen_a;
    profile->poly_getnoise_eta1 = stats_poly_getnoise_eta1;
    profile->ntt                = stats_ntt;
    profile->basemul            = stats_basemul;
    profile->poly_tomont        = stats_poly_tomont;
    profile->polyvec_add        = stats_polyvec_add;
    profile->polyvec_reduce     = stats_polyvec_reduce;
    profile->pack_sk            = stats_pack_sk;
    profile->pack_pk            = stats_pack_pk;
    // enc-only snapshot
    profile->unpack_pk          = stats_unpack_pk;
    profile->poly_frommsg       = stats_poly_frommsg;
    profile->gen_at             = stats_gen_at;
    profile->poly_getnoise_eta2 = stats_poly_getnoise_eta2;
    profile->invntt             = stats_invntt;
    profile->poly_invntt        = stats_poly_invntt;
    profile->poly_add           = stats_poly_add;
    profile->poly_reduce        = stats_poly_reduce;
    profile->pack_ciphertext    = stats_pack_ciphertext;
    // dec-only snapshot                        
    profile->unpack_ciphertext = stats_unpack_ciphertext;
    profile->unpack_sk         = stats_unpack_sk;
    profile->poly_sub          = stats_poly_sub;
    profile->poly_tomsg        = stats_poly_tomsg;
}

// =========================================================================
// Sum of all measured leaf cycles for coverage calculation
// =========================================================================
static uint64_t get_measured_cycles(const operation_profile_t *p) {
    return p->memcpy.cumulative_cycles
         + p->hash_g.cumulative_cycles
         + p->gen_a.cumulative_cycles
         + p->poly_getnoise_eta1.cumulative_cycles
         + p->ntt.cumulative_cycles
         + p->basemul.cumulative_cycles
         + p->poly_tomont.cumulative_cycles
         + p->polyvec_add.cumulative_cycles
         + p->polyvec_reduce.cumulative_cycles
         + p->pack_sk.cumulative_cycles
         + p->pack_pk.cumulative_cycles
         + p->unpack_pk.cumulative_cycles
         + p->poly_frommsg.cumulative_cycles
         + p->gen_at.cumulative_cycles
         + p->poly_getnoise_eta2.cumulative_cycles
         + p->invntt.cumulative_cycles
         + p->poly_invntt.cumulative_cycles
         + p->poly_add.cumulative_cycles
         + p->poly_reduce.cumulative_cycles
         + p->pack_ciphertext.cumulative_cycles
         + p->unpack_ciphertext.cumulative_cycles
         + p->unpack_sk.cumulative_cycles
         + p->poly_sub.cumulative_cycles
         + p->poly_tomsg.cumulative_cycles;
}

// =========================================================================
#define PRINT_SINGLE_STAT(profile, stat_name, cpu_freq) do { \
    if (profile.stat_name.call_count > 0) { \
        uint64_t cumulative_total = profile.stat_name.cumulative_cycles; \
        uint64_t avg_cyc = cumulative_total / profile.stat_name.call_count; \
        float calls_per_op = (float)profile.stat_name.call_count / profile.iterations; \
        float pct = (cumulative_total * 100.0f) / profile.total_cycles_table; \
        float pct2 = (profile.stat_name.cumulative_cycles * 100.0f) / profile.measured_cycles; \
        float total_ms = cumulative_total * 1000.0f / (cpu_freq); \
        float avg_us = avg_cyc * 1000000.0f / (cpu_freq); \
        printf("  %-8s: %6lu calls (%5.1f/op) | %10llu cyc (%6.2f ms) | %5.1f%% | %5.1f%% | avg=%7llu cyc (%6.2f us)\n", \
               profile.operation_name, \
               (unsigned long)profile.stat_name.call_count, \
               calls_per_op, \
               cumulative_total, \
               total_ms, \
               pct, \
               pct2, \
               avg_cyc, \
               avg_us); \
    } \
} while(0)

#define PRINT_FUNCTION_HEADER(name) \
    printf("\n[%s]\n", name)

// =========================================================================
void print_timing_report(uint32_t cpu_freq_hz) {
    printf("\n");
    printf("================================================================================\n");
    printf("                          TIMING ANALYSIS REPORT\n");
    printf("================================================================================\n");
    printf("\nAlgorithmus: %s\n", CRYPTO_ALGNAME);
    printf("CPU_FREQUENCY: %lu MHz\n\n", cpu_freq_hz / 1000000);

    printf("--------------------------------------------------------------------------------\n");
    printf("                           OPERATION SUMMARIES\n");
    printf("--------------------------------------------------------------------------------\n");

    for (int op_idx = 0; op_idx < 3; op_idx++) {
        operation_profile_t *p = (op_idx == 0) ? &profile_keypair
                               : (op_idx == 1) ? &profile_enc
                                               : &profile_dec;
        if (p->iterations == 0) continue;

        p->measured_cycles     = get_measured_cycles(p);
        float    total_ms     = p->total_cycles * 1000.0f / cpu_freq_hz;
        float    avg_ms       = total_ms / p->iterations;
        int64_t  overhead_abs = (int64_t)p->total_cycles - (int64_t)p->total_cycles_table;
        float    overhead_rel = (((float)p->total_cycles / (float)p->total_cycles_table) * 100.0f) - 100.0f;
        float    coverage     = (p->measured_cycles * 100.0f) / p->total_cycles_table;
        // if (overhead_abs < 0) {overhead_abs = 0; overhead_rel = 0;}

        printf("\nOPERATION: %s\n", p->operation_name);
        printf("  Iterations:                        %lu\n",   (unsigned long)p->iterations);
        printf("  Total cycles of operation:         %llu (%.2f ms total, %.2f ms avg)\n", p->total_cycles, total_ms, avg_ms);
        printf("  Table cycles for operation:        %llu\n",  p->total_cycles_table);
        printf("  Overhead produced by test:         %lld -> %.2f%%\n", overhead_abs, overhead_rel);
        printf("  Cycles measured in functions:      %llu\n",  p->measured_cycles);
        printf("  Coverage:                          %.2f%%\n", coverage);
    }

    // =====================================================================
    printf("\n");
    printf("--------------------------------------------------------------------------------\n");
    printf("                      INDCPA_KEYPAIR FUNCTIONS (in order)\n");
    printf("--------------------------------------------------------------------------------\n");
    printf("Format:            calls (calls/op) |    total_cycles (ms) | %%time of all |  %%time of measured | avg_cycles (us)\n");

    PRINT_FUNCTION_HEADER("memcpy");
    PRINT_SINGLE_STAT(profile_keypair, memcpy, cpu_freq_hz);

    PRINT_FUNCTION_HEADER("hash_g");
    PRINT_SINGLE_STAT(profile_keypair, hash_g, cpu_freq_hz);

    PRINT_FUNCTION_HEADER("gen_a");
    PRINT_SINGLE_STAT(profile_keypair, gen_a, cpu_freq_hz);

    PRINT_FUNCTION_HEADER("poly_getnoise_eta1");
    PRINT_SINGLE_STAT(profile_keypair, poly_getnoise_eta1, cpu_freq_hz);

    PRINT_FUNCTION_HEADER("polyvec_ntt");
    PRINT_SINGLE_STAT(profile_keypair, ntt, cpu_freq_hz);

    PRINT_FUNCTION_HEADER("polyvec_basemul_acc_montgomery");
    PRINT_SINGLE_STAT(profile_keypair, basemul, cpu_freq_hz);

    PRINT_FUNCTION_HEADER("poly_tomont");
    PRINT_SINGLE_STAT(profile_keypair, poly_tomont, cpu_freq_hz);

    PRINT_FUNCTION_HEADER("polyvec_add");
    PRINT_SINGLE_STAT(profile_keypair, polyvec_add, cpu_freq_hz);

    PRINT_FUNCTION_HEADER("polyvec_reduce");
    PRINT_SINGLE_STAT(profile_keypair, polyvec_reduce, cpu_freq_hz);

    PRINT_FUNCTION_HEADER("pack_sk");
    PRINT_SINGLE_STAT(profile_keypair, pack_sk, cpu_freq_hz);

    PRINT_FUNCTION_HEADER("pack_pk");
    PRINT_SINGLE_STAT(profile_keypair, pack_pk, cpu_freq_hz);


    printf("--------------------------------------------------------------------------------\n");
    printf("                      INDCPA_ENC FUNCTIONS (in order)\n");
    printf("--------------------------------------------------------------------------------\n");
    printf("Format:            calls (calls/op) |    total_cycles (ms) | %%time of all |  %%time of measured | avg_cycles (us)\n");

    PRINT_FUNCTION_HEADER("unpack_pk");
    PRINT_SINGLE_STAT(profile_enc, unpack_pk, cpu_freq_hz);

    PRINT_FUNCTION_HEADER("poly_frommsg");
    PRINT_SINGLE_STAT(profile_enc, poly_frommsg, cpu_freq_hz);

    PRINT_FUNCTION_HEADER("gen_at");
    PRINT_SINGLE_STAT(profile_enc, gen_at, cpu_freq_hz);

    PRINT_FUNCTION_HEADER("poly_getnoise_eta1");
    PRINT_SINGLE_STAT(profile_enc, poly_getnoise_eta1, cpu_freq_hz);

    PRINT_FUNCTION_HEADER("poly_getnoise_eta2");
    PRINT_SINGLE_STAT(profile_enc, poly_getnoise_eta2, cpu_freq_hz);

    PRINT_FUNCTION_HEADER("polyvec_ntt");
    PRINT_SINGLE_STAT(profile_enc, ntt, cpu_freq_hz);

    PRINT_FUNCTION_HEADER("polyvec_basemul_acc_montgomery");
    PRINT_SINGLE_STAT(profile_enc, basemul, cpu_freq_hz);

    PRINT_FUNCTION_HEADER("polyvec_invntt_tomont");
    PRINT_SINGLE_STAT(profile_enc, invntt, cpu_freq_hz);

    PRINT_FUNCTION_HEADER("poly_invntt_tomont");
    PRINT_SINGLE_STAT(profile_enc, poly_invntt, cpu_freq_hz);

    PRINT_FUNCTION_HEADER("polyvec_add");
    PRINT_SINGLE_STAT(profile_enc, polyvec_add, cpu_freq_hz);

    PRINT_FUNCTION_HEADER("poly_add");
    PRINT_SINGLE_STAT(profile_enc, poly_add, cpu_freq_hz);

    PRINT_FUNCTION_HEADER("polyvec_reduce");
    PRINT_SINGLE_STAT(profile_enc, polyvec_reduce, cpu_freq_hz);

    PRINT_FUNCTION_HEADER("poly_reduce");
    PRINT_SINGLE_STAT(profile_enc, poly_reduce, cpu_freq_hz);

    PRINT_FUNCTION_HEADER("pack_ciphertext");
    PRINT_SINGLE_STAT(profile_enc, pack_ciphertext, cpu_freq_hz);

    printf("--------------------------------------------------------------------------------\n");
    printf("                      INDCPA_DEC FUNCTIONS (in order)\n");
    printf("--------------------------------------------------------------------------------\n");
    printf("Format:            calls (calls/op) |    total_cycles (ms) | %%time of all |  %%time of measured | avg_cycles (us)\n");

    PRINT_FUNCTION_HEADER("unpack_ciphertext");
    PRINT_SINGLE_STAT(profile_dec, unpack_ciphertext, cpu_freq_hz);

    PRINT_FUNCTION_HEADER("unpack_sk");
    PRINT_SINGLE_STAT(profile_dec, unpack_sk, cpu_freq_hz);

    PRINT_FUNCTION_HEADER("polyvec_ntt");
    PRINT_SINGLE_STAT(profile_dec, ntt, cpu_freq_hz);

    PRINT_FUNCTION_HEADER("polyvec_basemul_acc_montgomery");
    PRINT_SINGLE_STAT(profile_dec, basemul, cpu_freq_hz);

    PRINT_FUNCTION_HEADER("poly_invntt_tomont");
    PRINT_SINGLE_STAT(profile_dec, poly_invntt, cpu_freq_hz);

    PRINT_FUNCTION_HEADER("poly_sub");
    PRINT_SINGLE_STAT(profile_dec, poly_sub, cpu_freq_hz);

    PRINT_FUNCTION_HEADER("poly_reduce");
    PRINT_SINGLE_STAT(profile_dec, poly_reduce, cpu_freq_hz);

    PRINT_FUNCTION_HEADER("poly_tomsg");
    PRINT_SINGLE_STAT(profile_dec, poly_tomsg, cpu_freq_hz);

}

// =========================================================================
void timing_analysis_test(void) {
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t key_a[CRYPTO_BYTES];
    uint8_t key_b[CRYPTO_BYTES];

    uint32_t freq_hz = CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ * 1000000;

    printf("\n=== TIMING ANALYSIS TEST ===\n");
    printf("Iterations per operation: %d\n", ITERATIONS_PER_OPERATION);
    printf("Warmup iterations: %d\n\n", WARMUP_ITERATIONS);

    // Warmup
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        crypto_kem_keypair(pk, sk);
        crypto_kem_enc(ct, key_b, pk);
        crypto_kem_dec(key_a, ct, sk);
    }
    printf("Warmup complete.\n\n");

    // =========================================================================
    // PHASE 1: KEYPAIR
    // =========================================================================
    printf("  [1/3] Keypair profiling...\n");
    reset_timing_stats();
    uint64_t keypair_total = 0;
    for (int i = 0; i < ITERATIONS_PER_OPERATION; i++) {
        esp_cpu_cycle_count_t start = esp_cpu_get_cycle_count();
        crypto_kem_keypair(pk, sk);
        esp_cpu_cycle_count_t end = esp_cpu_get_cycle_count();
        keypair_total += (end - start);
    }
    save_current_profile(&profile_keypair, "keypair", ITERATIONS_PER_OPERATION, keypair_total);
    printf("        Keypair profiling complete.\n");

    // =========================================================================
    // PHASE 2: ENCAPSULATION
    // =========================================================================
    printf("  [2/3] Encapsulation profiling...\n");
    reset_timing_stats();
    uint64_t enc_total = 0;
    for (int i = 0; i < ITERATIONS_PER_OPERATION; i++) {
        esp_cpu_cycle_count_t start = esp_cpu_get_cycle_count();
        crypto_kem_enc(ct, key_b, pk);
        esp_cpu_cycle_count_t end = esp_cpu_get_cycle_count();
        enc_total += (end - start);
    }
    save_current_profile(&profile_enc, "enc", ITERATIONS_PER_OPERATION, enc_total);
    printf("        Encapsulation profiling complete.\n");

    // =========================================================================
    // PHASE 3: DECAPSULATION
    // =========================================================================
    printf("  [3/3] Decapsulation profiling...\n");
    reset_timing_stats();
    uint64_t dec_total = 0;
    for (int i = 0; i < ITERATIONS_PER_OPERATION; i++) {
        esp_cpu_cycle_count_t start = esp_cpu_get_cycle_count();
        crypto_kem_dec(key_a, ct, sk);
        esp_cpu_cycle_count_t end = esp_cpu_get_cycle_count();
        dec_total += (end - start);
    }
    save_current_profile(&profile_dec, "dec", ITERATIONS_PER_OPERATION, dec_total);
    printf("        Decapsulation profiling complete.\n\n");

    // =========================================================================
    // REPORT
    // =========================================================================
    print_timing_report(freq_hz);

    printf("--------------------------------------------------------------------------------\n");
    printf("                      INTEGRITY CHECK\n");
    printf("--------------------------------------------------------------------------------\n");
    if (memcmp(key_a, key_b, CRYPTO_BYTES) == 0)
        printf("[INTEGRITY CHECK: PASSED] Keys match.\n");
    else
        printf("[INTEGRITY CHECK: FAILED] Keys do not match!\n");
}