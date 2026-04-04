/*
 * ML-KEM timing measurement — ESP32 cycle counter profiling
 *
 * Copyright (C) 2026 Michal Saxa
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef TIMING_H
#define TIMING_H
/*
Prototyp meraca

  #ifdef TIMEANALYSIS
  esp_cpu_cycle_count_t start = esp_cpu_get_cycle_count();
  #endif

  called_funtion();

  #ifdef TIMEANALYSIS
  esp_cpu_cycle_count_t end = esp_cpu_get_cycle_count();
  stats_memcpy.cumulative_cycles += (end - start);
  stats_memcpy.call_count++;
  #endif
*/
#include <stdint.h>
#include "esp_cpu.h"
#include "params.h"

#define ITERATIONS_PER_OPERATION 1000
#define WARMUP_ITERATIONS 10

typedef struct {
    uint64_t cumulative_cycles;
    uint32_t call_count;
} timing_stats_t;

// =========================================================================
// KEYGEN stats  (indcpa_keypair_derand order)
// =========================================================================
extern timing_stats_t stats_memcpy;                       // 1
extern timing_stats_t stats_hash_g;                       // 2
extern timing_stats_t stats_gen_a;                        // 3
extern timing_stats_t stats_poly_getnoise_eta1;           // 4  shared with enc
extern timing_stats_t stats_ntt;                          // 5  polyvec_ntt, shared with enc
extern timing_stats_t stats_basemul;                      // 6  polyvec_basemul_acc_montgomery, shared with enc
extern timing_stats_t stats_poly_tomont;                  // 7
extern timing_stats_t stats_polyvec_add;                  // 8  shared with enc
extern timing_stats_t stats_polyvec_reduce;               // 9  shared with enc
extern timing_stats_t stats_pack_sk;                      // 10
extern timing_stats_t stats_pack_pk;                      // 11

// =========================================================================
// ENC-only stats  (indcpa_enc order)
// =========================================================================
extern timing_stats_t stats_unpack_pk;                    // 1
extern timing_stats_t stats_poly_frommsg;                 // 2
extern timing_stats_t stats_gen_at;                       // 3
extern timing_stats_t stats_poly_getnoise_eta2;           // 5
extern timing_stats_t stats_invntt;                       // 8  polyvec_invntt_tomont
extern timing_stats_t stats_poly_invntt;                  // 9  poly_invntt_tomont
extern timing_stats_t stats_poly_add;                     // 11
extern timing_stats_t stats_poly_reduce;                  // 13
extern timing_stats_t stats_pack_ciphertext;              // 14

// =========================================================================
// DEC-only stats  (indcpa_dec order)
// =========================================================================
extern timing_stats_t stats_unpack_ciphertext;   // 1
extern timing_stats_t stats_unpack_sk;           // 2
extern timing_stats_t stats_poly_sub;            // 6
extern timing_stats_t stats_poly_tomsg;          // 8

// =========================================================================
typedef struct {
    char     operation_name[16];
    uint32_t iterations;
    uint64_t total_cycles;    // pocet cyklov celej operacie pri jej volani
    uint64_t measured_cycles;   // pocet cyklov nemeraných vnutri operacia
    uint64_t total_cycles_table;  // pocet cyklov pre operaciu meranych beenchmarkom

    // --- KEYGEN order ---
    timing_stats_t memcpy;
    timing_stats_t hash_g;
    timing_stats_t gen_a;
    timing_stats_t poly_getnoise_eta1;
    timing_stats_t ntt;
    timing_stats_t basemul;
    timing_stats_t poly_tomont;
    timing_stats_t polyvec_add;
    timing_stats_t polyvec_reduce;
    timing_stats_t pack_sk;
    timing_stats_t pack_pk;

    // --- ENC-only ---
    timing_stats_t unpack_pk;
    timing_stats_t poly_frommsg;
    timing_stats_t gen_at;
    timing_stats_t poly_getnoise_eta2;
    timing_stats_t invntt;
    timing_stats_t poly_invntt;
    timing_stats_t poly_add;
    timing_stats_t poly_reduce;
    timing_stats_t pack_ciphertext;

    // --- DEC-only ---
    timing_stats_t unpack_ciphertext;
    timing_stats_t unpack_sk;
    timing_stats_t poly_sub;
    timing_stats_t poly_tomsg;

} operation_profile_t;

extern operation_profile_t profile_keypair;
extern operation_profile_t profile_enc;
extern operation_profile_t profile_dec;

// =========================================================================
// Reference cycle tables  K=2,3,4 -> index 0,1,2
// =========================================================================
static const uint64_t TOTAL_CYCLES_KEYGEN_TABLE[3] = {
    859112,   // K=2
    1379178,  // K=3
    2135678   // K=4
};
static const uint64_t TOTAL_CYCLES_ENC_TABLE[3] = {
    948155,   // K=2
    1522645,  // K=3
    2292123   // K=4
};
static const uint64_t TOTAL_CYCLES_DEC_TABLE[3] = {
    1150210,  // K=2
    1792363,  // K=3
    2627935   // K=4
};

static inline uint64_t get_reference_cycles(int operation_type) {
    int k_idx = MLKEM_K - 2;
    switch (operation_type) {
        case 0: return TOTAL_CYCLES_KEYGEN_TABLE[k_idx] * ITERATIONS_PER_OPERATION;
        case 1: return TOTAL_CYCLES_ENC_TABLE[k_idx]    * ITERATIONS_PER_OPERATION;
        case 2: return TOTAL_CYCLES_DEC_TABLE[k_idx]    * ITERATIONS_PER_OPERATION;
        default: return 1;
    }
}

void reset_timing_stats(void);
void save_current_profile(operation_profile_t *profile, const char *op_name,
                          uint32_t iterations, uint64_t total_cycles);
void print_timing_report(uint32_t cpu_freq_hz);
void timing_analysis_test(void);

#endif // TIMING_H