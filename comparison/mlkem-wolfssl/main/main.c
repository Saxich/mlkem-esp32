#include "user_settings.h"          // MUST BE FIRST LINE IN THE FILE
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/mlkem.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>  
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/version.h>

#include <stdio.h> 
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "taskpriorities.h"
#include "esp_task_wdt.h"
#include "esp_system.h"
#include <math.h>


static WC_RNG g_rng;

// =============================================================================
// konfiguracia urovne
// =============================================================================
#define USE_MLKEM_512    0
#define USE_MLKEM_768    1
#define USE_MLKEM_1024   0

#if (USE_MLKEM_512 + USE_MLKEM_768 + USE_MLKEM_1024) != 1
    #error "Exactly one ML-KEM level must be set to 1"
#endif

#if USE_MLKEM_512 == 1
    #define MLKEM_LEVEL               WC_ML_KEM_512
    #define CRYPTO_PUBLICKEYBYTES     WC_ML_KEM_512_PUBLIC_KEY_SIZE      // 800
    #define CRYPTO_SECRETKEYBYTES     WC_ML_KEM_512_PRIVATE_KEY_SIZE     // 1632
    #define CRYPTO_CIPHERTEXTBYTES    WC_ML_KEM_512_CIPHER_TEXT_SIZE     // 768
#elif USE_MLKEM_1024 == 1
    #define MLKEM_LEVEL               WC_ML_KEM_1024
    #define CRYPTO_PUBLICKEYBYTES     WC_ML_KEM_1024_PUBLIC_KEY_SIZE     // 1568
    #define CRYPTO_SECRETKEYBYTES     WC_ML_KEM_1024_PRIVATE_KEY_SIZE    // 3168
    #define CRYPTO_CIPHERTEXTBYTES    WC_ML_KEM_1024_CIPHER_TEXT_SIZE    // 1568
#else  /* default = ML-KEM-768 */
    #define MLKEM_LEVEL               WC_ML_KEM_768
    #define CRYPTO_PUBLICKEYBYTES     WC_ML_KEM_768_PUBLIC_KEY_SIZE      // 1184
    #define CRYPTO_SECRETKEYBYTES     WC_ML_KEM_768_PRIVATE_KEY_SIZE     // 2400
    #define CRYPTO_CIPHERTEXTBYTES    WC_ML_KEM_768_CIPHER_TEXT_SIZE     // 1088
#endif

#define CRYPTO_BYTES                  32   // always 32 bytes shared secret
// =============================================================================
//  Api pre moj main
// =============================================================================
static int crypto_kem_keypair(uint8_t *pk, uint8_t *sk)
{
    MlKemKey key;
    int ret;

    // Initialize key with: key pointer, type, heap, devId
    ret = wc_MlKemKey_Init(&key, MLKEM_LEVEL, NULL, INVALID_DEVID);
    if (ret != 0) {
        return ret;
    }

    // Generate keypair
    ret = wc_MlKemKey_MakeKey(&key, &g_rng);
    if (ret != 0) {
        wc_MlKemKey_Free(&key);
        return ret;
    }

    // Encode public key - takes LENGTH by value (not pointer!)
    ret = wc_MlKemKey_EncodePublicKey(&key, pk, CRYPTO_PUBLICKEYBYTES);
    if (ret != 0) {
        wc_MlKemKey_Free(&key);
        return ret;
    }

    // Encode private key - takes LENGTH by value (not pointer!)
    ret = wc_MlKemKey_EncodePrivateKey(&key, sk, CRYPTO_SECRETKEYBYTES);
    wc_MlKemKey_Free(&key);
    return ret;
}

static int crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    MlKemKey key;
    int ret;

    ret = wc_MlKemKey_Init(&key, MLKEM_LEVEL, NULL, INVALID_DEVID);
    if (ret != 0) {
        return ret;
    }

    // Decode the public key from Bob
    ret = wc_MlKemKey_DecodePublicKey(&key, pk, CRYPTO_PUBLICKEYBYTES);
    if (ret != 0) {
        wc_MlKemKey_Free(&key);
        return ret;
    }

    // Encapsulate - signature is (key, ct, ss, rng) - NO length parameters!
    ret = wc_MlKemKey_Encapsulate(&key, ct, ss, &g_rng);
    wc_MlKemKey_Free(&key);
    return ret;
}

static int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    MlKemKey key;
    int ret;

    ret = wc_MlKemKey_Init(&key, MLKEM_LEVEL, NULL, INVALID_DEVID);
    if (ret != 0) {
        return ret;
    }

    // Decode the private key
    ret = wc_MlKemKey_DecodePrivateKey(&key, sk, CRYPTO_SECRETKEYBYTES);
    if (ret != 0) {
        wc_MlKemKey_Free(&key);
        return ret;
    }

    // Decapsulate - signature is (key, ss, ct, ct_len)
    ret = wc_MlKemKey_Decapsulate(&key, ss, ct, CRYPTO_CIPHERTEXTBYTES);
    wc_MlKemKey_Free(&key);
    return ret;
}




/*      
*    Structs and makros
*/

// Number of iterations makros
#define WARMUP_ITER       10

#define PERF_KEYPAIR_ITER 200
#define PERF_ENC_ITER     200
#define PERF_DEC_ITER     200

#define MEM_COMBINED_ITER   100
#define MEM_TASK_SIZE     40000

#define INTEGRITY_ITER    100

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
} mlkem_vectors_t;

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

    printf("[Performance] %s:\n", operation);
    // printf("  Min:    %7lu cycles (%7.3f ms)\n", 
    //        stats->min, stats->min * 1000.0f / freq_hz);
    // printf("  Max:    %7lu cycles (%7.3f ms)\n", 
    //        stats->max, stats->max * 1000.0f / freq_hz);
    // printf("  Avg:    %7.0f cycles (%7.3f ms)\n", 
    //        stats->avg, stats->avg * 1000.0f / freq_hz);
    // printf("  StdDev: %7.0f cycles (%7.3f ms)\n", 
    //        stats->stddev, stats->stddev * 1000.0f / freq_hz);
    printf("[Raw - min max avg stddev]:\n");        
    printf("%7lu %7lu %7.0f %7.0f\n", 
           stats->min, stats->max, stats->avg, stats->stddev);

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
    printf("[Raw - Stack/Heap: min max avg stddev]:\n");        
    printf("%7lu %7lu %7.0f %7.0f\n", 
           stack_stats->min, stack_stats->max, stack_stats->avg, stack_stats->stddev);
    
    // printf("[Raw - Heap: min max avg stddev]:\n");        
    printf("%7lu %7lu %7.0f %7.0f\n", 
           heap_stats->min, heap_stats->max, heap_stats->avg, heap_stats->stddev);
    printf("[Raw - stackmax heapmax]:\n");   
    printf("%7lu %7lu\n", stack_stats->max, heap_stats->max);   
    
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

        printf("\n");
        printf("========================================\n");
        printf(" CONFIG INFO\n");
        printf("========================================\n");

        uint32_t freq_hz = CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ * 1000000;
        printf("CPU Frequency: %lu Hz (%.3f MHz)\n", freq_hz, freq_hz / 1e6f);
        
        #if USE_MLKEM_768 == 1
            printf("Algorithm: ML-KEM 768\n");
        #elif USE_MLKEM_1024 == 1
            printf("Algorithm: ML-KEM 1024\n");
        #else
            printf("Algorithm: ML-KEM 512\n");
        #endif

        // ==== MEMORY ====
        printf("========================================\n");
        printf(" MEMORY BENCHMARK\n");
        printf("========================================\n");
    
        mem_benchmark_iter = 0;
        for (int i = 0; i < MEM_COMBINED_ITER; i++) {
            xReturned = xTaskCreatePinnedToCore(
                            mem_keygen_test, 
                            "MEM_GEN_TASK", 
                            MEM_TASK_SIZE, 
                            (void*)parentHandle, 
                            MAIN_TASK_PRIORITY,
                            &xHandle, 
                            0);
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
                            MAIN_TASK_PRIORITY,
                            &xHandle, 
                            0);
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
                            MAIN_TASK_PRIORITY,
                            &xHandle, 
                            0);
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
                TASK_STACK, 
                (void*)parentHandle,  // ← Pass parent handle
                MAIN_TASK_PRIORITY,
                &xHandle, 
                0);
                    
        // if(xReturned != pdPASS) {
        //     printf("Performance task creation failed\n");
        // }
        if(xReturned == pdPASS) {
            ulTaskNotifyTake(pdTRUE, portMAX_DELAY);  // Wait for notification
            // printf("Performance test completed\n\n");
        }

}



void app_main(void)
{

    // RNG init 
    int ret = wc_InitRng(&g_rng);
    if (ret != 0) {
        printf("RNG init failed: %d\n", ret);
        return;
    }

    bechmark_suite();

}