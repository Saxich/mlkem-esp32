# USER MANUAL — mlkem-esp32

---

## 1. Requirements

- ESP32
- ESP-IDF v6.0 — [Install ESP-IDF and Tools](https://docs.espressif.com/projects/vscode-esp-idf-extension/en/latest/installation.html)

---

## 2. Why API Functions Must Be Called from a Pinned Task

**API functions must not be called directly from `app_main`.** On ESP32 (dual-core), FreeRTOS can migrate a task created with `xTaskCreate` to any core at any time. The mlkem-esp32 dual-core implementation assumes the main task and the support task run on specific cores — if this is violated, the support task waits for synchronization that never arrives, causing the program to loop and hang.

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

If you are using the repository without modifications, set `TEST_TO_TURN` to one of the following:

| Value | What it does |
|---|---|
| `1` | Memory benchmark + performance benchmark + integrity check |
| `2` | Timing analysis of individual functions |
| `3` | KAT test — verifies output against NIST known answer vectors |
| `4` | KAT test + benchmark combined, memory performnace can be negatively affected |
| `10` | Generates test vectors (pk, sk, ct, ss) to stdout |

---

## 5. Set CPU Frequency

```bash
idf.py menuconfig
```

Navigate to:

```
Component config → ESP System Settings → CPU frequency
```

Select the desired frequency (80 / 160 / 240 MHz) and save.

---

## 6. Build, Flash, Monitor

```bash
idf.py set-target esp32
idf.py build
idf.py flash monitor          # auto-detect port
idf.py flash monitor -p COM3  # specify port manually
```

---

## 7. ESP32 Hardware TRNG

For maximum entropy quality, ensure Wi-Fi or BT is initialized when using the cryptosystem. The ESP32 hardware RNG (`WDEV_RND_REG`) operates without RF but with reduced entropy sourcing.

Reference: [ESP32 Technical Reference Manual, Section 18 — Random Number Generator](https://www.espressif.com/sites/default/files/documentation/esp32_technical_reference_manual_en.pdf)

