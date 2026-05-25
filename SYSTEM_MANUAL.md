# SYSTEM MANUAL — mlkem-esp32

---

## 1. Requirements

- ESP32
- ESP-IDF v6.0 — [Install ESP-IDF and Tools](https://docs.espressif.com/projects/vscode-esp-idf-extension/en/latest/installation.html) — must be installed and activated so that `idf.py` is available on PATH before running any commands in this manual
- Git, Bash (WSL, Git Bash, or Linux/macOS terminal)

---

## 2. Why API Functions Must Be Called from a Pinned Task

**API functions must not be called directly from `app_main`.** ML-KEM operations are computationally intensive and require a dedicated, core-pinned FreeRTOS task with a sufficiently large stack. Without pinning, FreeRTOS may migrate the task between cores at any time, which causes undefined behavior — including infinite loops and system lockup — regardless of whether a single-core or dual-core variant is used. The dual-core variants additionally require the calling task to remain on a fixed core for the inter-core synchronization to function correctly.

Always use `xTaskCreatePinnedToCore`:

```c
xTaskCreatePinnedToCore(
    my_function,          // task function
    "TASK_NAME",          // name 
    MLKEM_API_STACK_SIZE, // stack size — defined in task_settings.h
    (void*)parentHandle,  // input parameter — typically the parent task handle
    MLKEM_TASK_PRIORITY,  // priority — defined in task_settings.h
    &xHandle,             // output handle
    MLKEM_MAIN_CORE       // core — defined in task_settings.h
);
```

All constants (`MLKEM_API_STACK_SIZE`, `MLKEM_TASK_PRIORITY`, `MLKEM_MAIN_CORE`) are defined in [components/mlkem/task_settings.h](components/mlkem/task_settings.h). Adjust them there to fit your use case.

> **Recommendation:** To preserve dual-core integrity, use `MLKEM_MAIN_CORE` — never hardcode `0` or `1`.

When a task finishes, it notifies the parent and deletes itself:

```c
void my_function(void *pvParameters) {
    TaskHandle_t parentHandle = (TaskHandle_t)pvParameters;

    // ... your code ...

    xTaskNotifyGive(parentHandle);  // release parent
    vTaskDelete(NULL);              // delete self
}
```

Official documentation: [xTaskCreatePinnedToCore — ESP-IDF docs](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/system/freertos_idf.html)

---

## 3. API Functions and Input Buffers

Header file: [components/mlkem/kem.h](components/mlkem/kem.h)

Three basic ML-KEM operations:

```c
// 1. Key generation
crypto_kem_keypair(pk, sk);

// 2. Encapsulation — sending side
crypto_kem_enc(ct, ss_enc, pk);

// 3. Decapsulation — receiving side
crypto_kem_dec(ss_dec, ct, sk);

// Verification — ss_enc and ss_dec must match
if (memcmp(ss_enc, ss_dec, CRYPTO_BYTES) == 0) { /* OK */ }
```

Always use macros for buffer sizes — **never hardcoded values**. The macros adjust automatically based on the selected `MLKEM_K`:

```c
uint8_t pk[CRYPTO_PUBLICKEYBYTES];
uint8_t sk[CRYPTO_SECRETKEYBYTES];
uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
uint8_t ss_enc[CRYPTO_BYTES];
uint8_t ss_dec[CRYPTO_BYTES];
```

| Macro | ML-KEM-512 (K=2) | ML-KEM-768 (K=3) | ML-KEM-1024 (K=4) |
|---|---|---|---|
| `CRYPTO_PUBLICKEYBYTES` | 800 | 1184 | 1568 |
| `CRYPTO_SECRETKEYBYTES` | 1632 | 2400 | 3168 |
| `CRYPTO_CIPHERTEXTBYTES` | 768 | 1088 | 1568 |
| `CRYPTO_BYTES` | 32 | 32 | 32 |

---

## 4. Crypto System Configuration — user_settings.h

Everything is configured in a single file: [main/user_settings.h](main/user_settings.h)

### Security level — MLKEM_K

```c
#define MLKEM_K 2   // ML-KEM-512  — 128-bit security
#define MLKEM_K 3   // ML-KEM-768  — 192-bit security
#define MLKEM_K 4   // ML-KEM-1024 — 256-bit security
```

### Implementation mode

Define **exactly one**. If none is defined, `SPEED` is used.
| Mode | Description |
|---|---|
| `SPEED` | Single-core, optimized for execution time |
| `SPEED_DUALCORE` | Dual-core, matrix generation parallelized across both cores |
| `STACK` | Single-core, reduced stack — row-by-row matrix multiplication |
| `STACK_DUALCORE` | Dual-core, reduced stack |
| `STACK_XTREME` | Single-core, minimal stack — noise vector generated on-the-fly |

### Tests — TEST_TO_TURN

Set `TEST_TO_TURN` in `main/user_settings.h` to select which test runs on boot.

| Value | Test | Description |
|---|---|---|
| `1` | Benchmark suite | Runs memory benchmark, performance benchmark, and integrity check sequentially. Each operation (KeyGen, Encaps, Decaps) is measured over 100 iterations for memory and 200 iterations for performance, preceded by 10 warm-up iterations. Reports peak stack and heap usage and CPU cycle statistics (min, max, avg, stddev). Integrity check performs 100 full KeyGen → Encaps → Decaps round trips and verifies that both parties derive the same shared secret. |
| `3` | KAT test | Runs the algorithm against known answer vectors generated on the ESP32. Computes SHA3-256 hashes of the output and compares them against reference hashes stored in flash. |
| `4` | KAT test + benchmark suite | Runs the KAT test followed by the full benchmark suite. Running both together may affect memory and performance measurements due to residual heap fragmentation from the KAT test. |
| `10` | Vector generator | Performs a single KeyGen → Encaps → Decaps round trip and prints the resulting (pk, sk, ct, ss) vectors as hex to stdout. |

---

## 5. Set the ESP32 target

```bash
idf.py set-target esp32
```

---

## 6. Set Compiler Optimization Level

By default, ESP-IDF uses the **Debug** optimization level (`-Og`), which produces slower code. For accurate benchmarks, switch to `-Os`:

```bash
idf.py menuconfig
```

Navigate to:

```
Component config → Compiler options → Optimization Level → Optimize for size (-Os)
```

Save and exit (`S` → `Q`).

> **Note:** Always use `-Os` when running performance or memory benchmarks. `-Os` has been verified as the fastest option on ESP32 for this codebase — it produces tighter code that fits better in the instruction cache than `-O2`.

This applies to both the main project and any comparison implementations. For installation instructions of each comparison implementation, see the README in its respective subdirectory under [comparison/](comparison/).

---

## 7. Set CPU Frequency

```bash
idf.py menuconfig
```

Navigate to:

```
Component config → ESP System Settings → CPU frequency
```

Select the desired frequency (80 / 160 / 240 MHz) and save.

---

## 8. Build, Flash, Monitor

```bash
idf.py build
idf.py flash monitor          # auto-detect port
idf.py flash monitor -p COM3  # specify port manually
```

---

## 9. ESP32 Hardware TRNG

For maximum entropy quality, ensure Wi-Fi or BT is initialized when using the cryptosystem. The ESP32 hardware RNG (`WDEV_RND_REG`) operates without RF but with reduced entropy sourcing.

Reference: [ESP32 Technical Reference Manual, Section 18 — Random Number Generator](https://www.espressif.com/sites/default/files/documentation/esp32_technical_reference_manual_en.pdf)


