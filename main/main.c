/*
 * ML-KEM (FIPS 203) — main entry point for ESP32
 *
 * Copyright (C) 2026 Michal Saxa
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "user_settings.h"
#include "params.h"
#include <stdio.h> 
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "indcpa.h" 
#include "kem.h"
#include "task_settings.h"
#include "esp_task_wdt.h"
//pre performance test
#include "esp_system.h"
#include <math.h>

// KAT test
#include "kat.h"
// keccak
#include "fips202.h"
// time analysis
#ifdef TIMEANALYSIS
    #include "../test_time/timing.h"
#endif


#if MLKEM_K == 3
    #define REF_AVG_KEYPAIR       1967560UL
    #define REF_AVG_ENCAPS        2320610UL
    #define REF_AVG_DECAPS        2797063UL
#elif MLKEM_K == 4
    #define REF_AVG_KEYPAIR       3073129UL
    #define REF_AVG_ENCAPS        3483190UL
    #define REF_AVG_DECAPS        4082284UL
#else   //k=2
    #define REF_AVG_KEYPAIR       1184300UL
    #define REF_AVG_ENCAPS        1430747UL
    #define REF_AVG_DECAPS        1792887UL
#endif

/*      
*    Structs and makros
*/

// Number of iterations makros
#define WARMUP_ITER       10

#define REDUCE 1

#define PERF_KEYPAIR_ITER 200 / REDUCE
#define PERF_ENC_ITER     200 / REDUCE
#define PERF_DEC_ITER     200 / REDUCE

#define MEM_COMBINED_ITER   100  / REDUCE
#define MEM_TASK_SIZE     40000

#define INTEGRITY_ITER    100 / REDUCE

// Performance data structure
typedef struct {
    uint32_t min;
    uint32_t max;
    float avg;
    float stddev;
} measur_stats_t;

// Memory tracking structure 
typedef struct {
    uint32_t heap_free_initial;  //set by heap_monitor_start
    uint32_t heap_peak_used;     //set by heap_monitor_stop
    uint32_t stack_peak_used;    // Corrected by overhead = total_stack-overhead
    uint32_t total_stack;
    uint32_t overhead;  //used in 
} mem_stats_t;

// Memory tracking structure, store usage computed in loop for each operation and iteration
typedef struct {
    uint32_t heap_used[MEM_COMBINED_ITER];
    uint32_t stack_used[MEM_COMBINED_ITER];
    uint32_t heap_free_initial;  //set by heap_monitor_start
} mem_tracer_t;

static uint32_t mem_benchmark_iter = 0;
mem_tracer_t mem_keygen_tracker = {0};
mem_tracer_t mem_encaps_tracker = {0};
mem_tracer_t mem_decaps_tracker = {0};


// Test data
typedef struct {
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss_enc[CRYPTO_BYTES];
    uint8_t ss_dec[CRYPTO_BYTES];
}mlkem_vectors_t;
static mlkem_vectors_t vectors = {0};




/*      
*    Support functions 
*/
static inline void heap_monitor_start(mem_tracer_t *mem_trac){
// Initialize heap monitoring
    // Reset the minimum free heap tracker
    heap_caps_monitor_local_minimum_free_size_start();
    mem_trac->heap_free_initial = heap_caps_get_free_size(MALLOC_CAP_8BIT);
}

static inline void heap_monitor_stop(mem_tracer_t *mem_trac){
 // Finalize heap monitoring and calculate peak usage   
    uint32_t actual_minimum_heap = heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT);
    
    // Calculate peak heap consumption
    if (mem_trac->heap_free_initial >= actual_minimum_heap) {
        mem_trac->heap_used[mem_benchmark_iter] = mem_trac->heap_free_initial - actual_minimum_heap;
    } else {
        mem_trac->heap_used[mem_benchmark_iter] = 0;
    }
}

void cal_perf_stats(const uint32_t *cycles, const int count, measur_stats_t *stats) {
    uint64_t sum = 0;
    uint32_t min_val = cycles[0];
    uint32_t max_val = cycles[0];
    
    // Calculate min, max, sum
    for(int i = 0; i < count; i++) {
        sum += cycles[i];
        if(cycles[i] < min_val) min_val = cycles[i];
        if(cycles[i] > max_val) max_val = cycles[i];
    }
    
    stats->min = min_val;
    stats->max = max_val;
    stats->avg = (float)sum / count;
    
    // Calculate standard deviation
    float variance_sum = 0;
    for(int i = 0; i < count; i++) {
        float diff = cycles[i] - stats->avg;
        variance_sum += diff * diff;
    }
    stats->stddev = sqrtf(variance_sum / (count - 1)); 
}

void print_perf_stats(const char *operation, measur_stats_t *stats, uint32_t freq_hz) {

    uint32_t ref = 0;

    if (strcmp(operation, "Keypair Generation") == 0) {
        ref = REF_AVG_KEYPAIR;
    } else if (strcmp(operation, "Encapsulation") == 0) {
        ref = REF_AVG_ENCAPS;
    } else if (strcmp(operation, "Decapsulation") == 0) {
        ref = REF_AVG_DECAPS;
    }
    float diff = 0.0f;
    if (ref != 0) {
        diff = ((float)stats->avg - (float)ref) * 100.0f / (float)ref;
    }



    printf("[Performance] %s:\n", operation);
    // printf("  Min:    %7lu cycles (%7.3f ms)\n", 
    //        stats->min, stats->min * 1000.0f / freq_hz);
    // printf("  Max:    %7lu cycles (%7.3f ms)\n", 
    //        stats->max, stats->max * 1000.0f / freq_hz);
    #ifndef TEST_AUTOMAT
        printf("  Avg:    %7.0f cycles (%7.3f ms)\n", 
            stats->avg, stats->avg * 1000.0f / freq_hz);
    #endif        
    // printf("  StdDev: %7.0f cycles (%7.3f ms)\n", 
    //        stats->stddev, stats->stddev * 1000.0f / freq_hz);.
    
    #ifdef TEST_AUTOMAT
        printf("[Raw - min max avg stddev]:\n");        
        printf("%7lu %7lu %7.0f %7.0f\n", 
            stats->min, stats->max, stats->avg, stats->stddev);
    #endif       

    #ifndef TEST_AUTOMAT
    if (ref != 0) {
        printf("  RefAvg: %7lu cycles  (%+6.2f%%)\n", ref, diff);
    }
    #endif    


}

void print_mem_stats(const char *operation, measur_stats_t *stack_stats, measur_stats_t *heap_stats){
    printf("[Memory] %s:\n", operation);
    
    // Stack statistics
    // printf("  Stack:\n");
    // printf("    Min:    %7lu bytes\n", stack_stats->min);
    // printf("    Max:    %7lu bytes\n", stack_stats->max);
    // printf("    Avg:    %7.0f bytes\n", stack_stats->avg);
    // printf("    StdDev: %7.0f bytes\n", stack_stats->stddev);
    
    // // Heap statistics
    // printf("  Heap:\n");
    // printf("    Min:    %7lu bytes\n", heap_stats->min);
    // printf("    Max:    %7lu bytes\n", heap_stats->max);
    // printf("    Avg:    %7.0f bytes\n", heap_stats->avg);
    // printf("    StdDev: %7.0f bytes\n", heap_stats->stddev);
    
    // Raw output for easy parsing
    // printf("[Raw - Stack/Heap: min max avg stddev]:\n");        
    // printf("%7lu %7lu %7.0f %7.0f\n", 
    //        stack_stats->min, stack_stats->max, stack_stats->avg, stack_stats->stddev);
    
    // printf("[Raw - Heap: min max avg stddev]:\n");        
    // printf("%7lu %7lu %7.0f %7.0f\n", 
    //        heap_stats->min, heap_stats->max, heap_stats->avg, heap_stats->stddev);

    // #ifdef TEST_AUTOMAT
        printf("[Raw - stackmax heapmax]:\n");   
        printf("%7lu %7lu\n", stack_stats->max, heap_stats->max);   
    // #endif
    
    printf("\n");
}


/*      
*    Tests 
*/
void perf_test(void *pvParameters) {
    TaskHandle_t parentHandle = (TaskHandle_t)pvParameters;
    // configASSERT((uint32_t)pvParameters == 1);
    fflush(stdout);

    uint32_t freq_hz = CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ * 1000000;

    // Allocate arrays to store individual measurements
    uint32_t *keypair_cycles = malloc(PERF_KEYPAIR_ITER * sizeof(uint32_t));
    uint32_t *enc_cycles = malloc(PERF_ENC_ITER * sizeof(uint32_t));
    uint32_t *dec_cycles = malloc(PERF_DEC_ITER * sizeof(uint32_t));
    
    if(!keypair_cycles || !enc_cycles || !dec_cycles) {
        printf("ERROR: Failed to allocate measurement arrays!\n");
        return;
    }

    // ========== WARM UP ============
    for(int i = 0; i < WARMUP_ITER; i++) {
        crypto_kem_keypair(vectors.pk, vectors.sk);
        crypto_kem_enc(vectors.ct, vectors.ss_enc, vectors.pk);
        crypto_kem_dec(vectors.ss_dec, vectors.ct, vectors.sk);
    }
    

    // ========== KEYPAIR GENERATION ==========
    for(int i = 0; i < PERF_KEYPAIR_ITER; i++) {

        esp_cpu_cycle_count_t start = esp_cpu_get_cycle_count();
        crypto_kem_keypair(vectors.pk, vectors.sk);
        esp_cpu_cycle_count_t end = esp_cpu_get_cycle_count();
        
        keypair_cycles[i] = end - start;
        
    }

    // // ========== ENCAPSULATION ==========
    for(int i = 0; i < PERF_ENC_ITER; i++) {
        crypto_kem_keypair(vectors.pk, vectors.sk);
        
        esp_cpu_cycle_count_t start = esp_cpu_get_cycle_count();
        crypto_kem_enc(vectors.ct, vectors.ss_enc, vectors.pk);
        esp_cpu_cycle_count_t end = esp_cpu_get_cycle_count();

        enc_cycles[i] = end - start;
    }
    
    // ========== DECAPSULATION ==========
    for(int i = 0; i < PERF_DEC_ITER; i++) {
        crypto_kem_keypair(vectors.pk, vectors.sk);
        crypto_kem_enc(vectors.ct, vectors.ss_enc, vectors.pk);
        
        esp_cpu_cycle_count_t start = esp_cpu_get_cycle_count();
        crypto_kem_dec(vectors.ss_dec, vectors.ct, vectors.sk);
        esp_cpu_cycle_count_t end = esp_cpu_get_cycle_count();
        
        dec_cycles[i] = end - start;
    
    }

    // Results
    measur_stats_t keypair_stats;
    measur_stats_t enc_stats;
    measur_stats_t dec_stats;
    cal_perf_stats(keypair_cycles, PERF_KEYPAIR_ITER, &keypair_stats);
    cal_perf_stats(enc_cycles, PERF_ENC_ITER, &enc_stats);
    cal_perf_stats(dec_cycles, PERF_DEC_ITER, &dec_stats);
    print_perf_stats("Keypair Generation", &keypair_stats, freq_hz);
    printf("\n");
    print_perf_stats("Encapsulation", &enc_stats, freq_hz);
    printf("\n");
    print_perf_stats("Decapsulation", &dec_stats, freq_hz);
    printf("\n");
    

    // Free measurement arrays
    free(keypair_cycles);
    free(enc_cycles);
    free(dec_cycles);

    // ========== INTEGRITY CHECK ==========
    printf("========================================\n");
    printf(" INTEGRITY CHECK\n");
    printf("========================================\n");

    int failures = 0;

    for(int i = 0; i < INTEGRITY_ITER; i++) {


        crypto_kem_keypair(vectors.pk, vectors.sk);
        crypto_kem_enc(vectors.ct, vectors.ss_enc, vectors.pk);
        crypto_kem_dec(vectors.ss_dec, vectors.ct, vectors.sk);

        if(memcmp(vectors.ss_enc, vectors.ss_dec, CRYPTO_BYTES)) {
            failures++;
        }

        // taskYIELD();
    }

    if(failures == 0) {
        printf("[Integrity] PASSED: All %d keys matched successfully - THIS IS NOT KAT TEST!\n", INTEGRITY_ITER);
    } else {
        printf("[Integrity] FAILED %d/%d key mismatches detected!\n", failures, INTEGRITY_ITER);
    }
    printf("\n");

    fflush(stdout);
    xTaskNotifyGive(parentHandle);  // Notify parent we're done
    vTaskDelay(pdMS_TO_TICKS(100));
    vTaskDelete(NULL);
}


static void mem_keygen_test(void *pvParameters) {

    TaskHandle_t parentHandle = (TaskHandle_t)pvParameters;
    
    // Start of measuring stack and heap
    UBaseType_t baseline_stack = uxTaskGetStackHighWaterMark(NULL);
    heap_monitor_start(&mem_keygen_tracker);
        // Measured function wrapper
        crypto_kem_keypair(vectors.pk, vectors.sk);
    // Stop of measuring stack and heap
    heap_monitor_stop(&mem_keygen_tracker);
    UBaseType_t after_stack = uxTaskGetStackHighWaterMark(NULL);
    
    mem_keygen_tracker.stack_used[mem_benchmark_iter] = 
        (baseline_stack - after_stack) * sizeof(StackType_t);
    
    
    xTaskNotifyGive(parentHandle); 
    vTaskDelete(NULL);
}

static void mem_encaps_test(void *pvParameters) {

    TaskHandle_t parentHandle = (TaskHandle_t)pvParameters;
    
    // Start of measuring stack and heap
    UBaseType_t baseline_stack = uxTaskGetStackHighWaterMark(NULL);
    heap_monitor_start(&mem_encaps_tracker);
        // Measured function wrapper
        crypto_kem_enc(vectors.ct, vectors.ss_enc, vectors.pk);
    // Stop of measuring stack and heap
    heap_monitor_stop(&mem_encaps_tracker);
    UBaseType_t after_stack = uxTaskGetStackHighWaterMark(NULL);
    
    mem_encaps_tracker.stack_used[mem_benchmark_iter] = 
        (baseline_stack - after_stack) * sizeof(StackType_t);
    
    
    xTaskNotifyGive(parentHandle); 
    vTaskDelete(NULL);
}

static void mem_decaps_test(void *pvParameters) {

    TaskHandle_t parentHandle = (TaskHandle_t)pvParameters;
    
    // Start of measuring stack and heap
    UBaseType_t baseline_stack = uxTaskGetStackHighWaterMark(NULL);
    heap_monitor_start(&mem_decaps_tracker);
        // Measured function wrapper
        crypto_kem_dec(vectors.ss_dec, vectors.ct, vectors.sk);
    // Stop of measuring stack and heap
    heap_monitor_stop(&mem_decaps_tracker);
    UBaseType_t after_stack = uxTaskGetStackHighWaterMark(NULL);
    
    mem_decaps_tracker.stack_used[mem_benchmark_iter] = 
        (baseline_stack - after_stack) * sizeof(StackType_t);
    
    
    xTaskNotifyGive(parentHandle); 
    vTaskDelete(NULL);
}



void bechmark_suite(void){

        // Disable so dont need tto yield test loops
        esp_task_wdt_deinit();
        BaseType_t xReturned;
        TaskHandle_t xHandle = NULL;
        TaskHandle_t parentHandle = xTaskGetCurrentTaskHandle();

        printf("***START OF ESP32 OUTPUT***\n");
        fflush(stdout);

        printf("\n");
        printf("========================================\n");
        printf(" CONFIG INFO\n");
        printf("========================================\n");

        uint32_t freq_hz = CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ * 1000000;
        printf("CPU Frequency: %lu Hz (%.3f MHz)\n", freq_hz, freq_hz / 1e6f);
        
         printf("Algorithm: %s\n", CRYPTO_ALGNAME);
         printf("Mode: %s\n", CRYPTO_ALGMODE);

        // ==== MEMORY ====
        printf("========================================\n");
        printf(" MEMORY BENCHMARK\n");
        // printf("========================================\n");
    
        mem_benchmark_iter = 0;
        for (int i = 0; i < MEM_COMBINED_ITER; i++) {
            xReturned = xTaskCreatePinnedToCore(
                            mem_keygen_test, 
                            "MEM_GEN_TASK", 
                            MEM_TASK_SIZE, 
                            (void*)parentHandle, 
                            MLKEM_TASK_PRIORITY,
                            &xHandle, 
                            MLKEM_MAIN_CORE);
            if(xReturned == pdPASS) {
                ulTaskNotifyTake(pdTRUE, portMAX_DELAY);  // Wait for notification
            } else {
                printf("fail\n");
                abort();
            }
            vTaskDelay(pdMS_TO_TICKS(100));

            xReturned = xTaskCreatePinnedToCore(
                            mem_encaps_test, 
                            "MEM_ENC_TASK", 
                            MEM_TASK_SIZE, 
                            (void*)parentHandle, 
                            MLKEM_TASK_PRIORITY,
                            &xHandle, 
                            MLKEM_MAIN_CORE);
            if(xReturned == pdPASS) {
                ulTaskNotifyTake(pdTRUE, portMAX_DELAY);  // Wait for notification
            } else {
                printf("fail\n");
                abort();
            }
            vTaskDelay(pdMS_TO_TICKS(100));

            xReturned = xTaskCreatePinnedToCore(
                            mem_decaps_test, 
                            "MEM_DEC_TASK", 
                            MEM_TASK_SIZE, 
                            (void*)parentHandle, 
                            MLKEM_TASK_PRIORITY,
                            &xHandle, 
                            MLKEM_MAIN_CORE);
            if(xReturned == pdPASS) {
                ulTaskNotifyTake(pdTRUE, portMAX_DELAY);  // Wait for notification
            } else {
                printf("fail\n");
                abort();
            }
            vTaskDelay(pdMS_TO_TICKS(100));

            // end of loop
            mem_benchmark_iter++;
        }


        // Print of stats
        measur_stats_t mem_keypair_stack, mem_keypair_heap;
        cal_perf_stats(mem_keygen_tracker.stack_used, MEM_COMBINED_ITER, &mem_keypair_stack);
        cal_perf_stats(mem_keygen_tracker.heap_used, MEM_COMBINED_ITER, &mem_keypair_heap);
        print_mem_stats("Keypair", &mem_keypair_stack, &mem_keypair_heap);

        measur_stats_t mem_encaps_stack, mem_encaps_heap;
        cal_perf_stats(mem_encaps_tracker.stack_used, MEM_COMBINED_ITER, &mem_encaps_stack);
        cal_perf_stats(mem_encaps_tracker.heap_used, MEM_COMBINED_ITER, &mem_encaps_heap);
        print_mem_stats("Encapsulation", &mem_encaps_stack, &mem_encaps_heap);

        measur_stats_t mem_decaps_stack, mem_decaps_heap;
        cal_perf_stats(mem_decaps_tracker.stack_used, MEM_COMBINED_ITER, &mem_decaps_stack);
        cal_perf_stats(mem_decaps_tracker.heap_used, MEM_COMBINED_ITER, &mem_decaps_heap);
        print_mem_stats("Decapsulation", &mem_decaps_stack, &mem_decaps_heap);



        // ==== PERFORMANCE ====
        printf("========================================\n");
        printf(" PERFORMANCE BENCHMARK\n");
        printf("========================================\n");
        xReturned = xTaskCreatePinnedToCore(
                perf_test, 
                "PERF_TASK", 
                MLKEM_API_STACK_SIZE, 
                (void*)parentHandle,  // ← Pass parent handle
                MLKEM_TASK_PRIORITY,
                &xHandle, 
                MLKEM_MAIN_CORE);
                    
        // if(xReturned != pdPASS) {
        //     printf("Performance task creation failed\n");
        // }
        if(xReturned == pdPASS) {
            ulTaskNotifyTake(pdTRUE, portMAX_DELAY);  // Wait for notification
            // printf("Performance test completed\n\n");
        }

        printf("***END OF ESP32 OUTPUT***\n");
        fflush(stdout);

}



/*      
*    dalsie testy 
*/

// generate_vectors
void generate_vectors(void *pvParameters) {
    (void)pvParameters;

    printf("\n***START VECTOR GENERATOR***\n");

    #if MLKEM_K == 2
    printf("\nML-KEM 512 Vectors:\n");
    #elif MLKEM_K == 3
    printf("\nML-KEM 768 Vectors:\n");
    #elif MLKEM_K == 4
    printf("\nML-KEM 1024 Vectors:\n");
    #endif

    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t key_enc[CRYPTO_BYTES];
    uint8_t key_dec[CRYPTO_BYTES];

    // Generate keypair
    crypto_kem_keypair(pk, sk);
    printf("[1] Generated Keypair\n");
    // Encapsulate random key
    crypto_kem_enc(ct, key_enc, pk);
    printf("[2] Encapsulated shared key\n");
    // Decapsulate shared key
    crypto_kem_dec(key_dec, ct, sk);
    printf("[3] Decapsulated shared key\n\n");

    // Print results
    print_hex_field("pk", pk, CRYPTO_PUBLICKEYBYTES);
    print_hex_field("sk", sk, CRYPTO_SECRETKEYBYTES);
    print_hex_field("ct", ct, CRYPTO_CIPHERTEXTBYTES);
    print_hex_field("ss", key_enc, CRYPTO_BYTES);
    print_hex_field("ss_dec", key_dec, CRYPTO_BYTES);

    // Verify integrity
    if (memcmp(key_enc, key_dec, CRYPTO_BYTES) == 0)
        printf("\n[OK] Shared keys match!\n");
    else
        printf("\n[FAIL] Shared keys DO NOT match!\n");

    printf("\n***END VECTOR GENERATOR***\n");

    fflush(stdout);
    vTaskDelay(pdMS_TO_TICKS(100));
    vTaskDelete(NULL);
}

// kat_output_test
void kat_output_test(void *pvParameters) {
    configASSERT((uint32_t)pvParameters == 1);

    printf("***START OF ESP32 OUTPUT***\n");
    fflush(stdout);

    // Main KAT test function
    generate_kat_output();
    // compare_known_vector();

    printf("***END OF ESP32 OUTPUT***\n");

    fflush(stdout);
    vTaskDelay(pdMS_TO_TICKS(100));
    vTaskDelete(NULL);
}

// timing
void timing_analysis_test_wrapper(void *pvParameters){

    #ifdef TIMEANALYSIS
        configASSERT((uint32_t)pvParameters == 1);
        printf("***START OF ESP32 PROGRAM***\n");
        fflush(stdout);

        timing_analysis_test();

        printf("\n***END OF ESP32 PROGRAM***\n");
    #endif 

    fflush(stdout);
    vTaskDelay(pdMS_TO_TICKS(100));

    vTaskDelete(NULL);
}



double compute_entropy(uint8_t *data, size_t len) {
    int freq[256] = {0};

    // Count occurrences
    for (size_t i = 0; i < len; i++) {
        freq[data[i]]++;
    }

    double entropy = 0.0;

    // Compute entropy
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / len;
            entropy -= p * log2(p);
        }
    }

    return entropy; // bits per byte
}


void app_main(void)
{
    // Disable watchdog, otherwise ong tasks not resetting watchdogs trigger 
    esp_task_wdt_deinit();
    BaseType_t xReturned;
    TaskHandle_t xHandle = NULL;

    switch(TEST_TO_TURN) {

        case 1:
            bechmark_suite();
            break;
        case 2:
            printf("Starting Timing Analysis Test...\n");
            xReturned = xTaskCreatePinnedToCore(
                            timing_analysis_test_wrapper, 
                            "TIMING_TEST", 
                            90000,
                            (void*)1, 
                            MLKEM_TASK_PRIORITY,
                            &xHandle, 
                            MLKEM_MAIN_CORE);
            
            if (xReturned != pdPASS) {
                printf("Timing analysis test task creation failed\n");
            }        
            break;
        case 3:
            printf("Starting KAT test...\n");
            xReturned = xTaskCreatePinnedToCore(
                            kat_output_test, "KAT_TEST", MLKEM_API_STACK_SIZE,
                            (void*)1, MLKEM_TASK_PRIORITY,
                            &xHandle, MLKEM_MAIN_CORE);
            if(xReturned != pdPASS) {
                printf("KAT test task creation failed\n");
            }
            break;
        case 4:
            printf("Starting KAT test...\n");
            xReturned = xTaskCreatePinnedToCore(
                            kat_output_test, "KAT_TEST", MLKEM_API_STACK_SIZE,
                            (void*)1, MLKEM_TASK_PRIORITY,
                            &xHandle, MLKEM_MAIN_CORE);
            if(xReturned != pdPASS) {
                printf("KAT test task creation failed\n");
            }
            bechmark_suite();
            break;
        case 10:
            printf("Starting generating vectors...\n");
            xReturned = xTaskCreatePinnedToCore(
                            generate_vectors, "VECTOR_GEN", MLKEM_API_STACK_SIZE,
                            (void*)1, MLKEM_TASK_PRIORITY, &xHandle, MLKEM_MAIN_CORE);
            break;
            
        default:
            printf("Chosen test number not valid\n");
            break;


    }
}



