# ML-KEM on ESP32 with wolfSSL (ESP-IDF v6.0)

Benchmark of ML-KEM-512/768/1024 (CRYSTALS-Kyber / FIPS 203) on ESP32 using wolfSSL v5.8.4.

---

## Disclaimer

wolfSSL is licensed under the **GNU General Public License v2 (or later)**. This project uses wolfSSL as a third-party library. wolfSSL is the property of wolfSSL Inc. — this repository does not claim ownership of wolfSSL or any of its source code. See [wolfSSL's license](https://github.com/wolfSSL/wolfssl/blob/master/COPYING) for details.

---

## Prerequisites

- [ESP-IDF v6.0](https://docs.espressif.com/projects/esp-idf/en/v6.0/esp32/get-started/index.html) installed and activated (`idf.py` in PATH)
- ESP32 board
- Git, Bash (WSL, Git Bash, or Linux/macOS terminal)

---

## Installation

### 1. Place project files

Copy the contents of the `mlkem-wolfssl` folder into your desired working directory:

```bash
cp -r mlkem-wolfssl/ /path/to/your/destination/
cd /path/to/your/destination/
```

> The folder may be renamed — what matters is that `main/`, `components/`, `CMakeLists.txt`, `setup_wolfssl.sh`, and `sdkconfig` are all present at the root level.

### 2. Download and patch wolfSSL

```bash
bash setup_wolfssl.sh
```

This will:
- Clone wolfSSL v5.8.4-stable into `components/wolfssl/`
- Patch `settings.h` for ESP-IDF v6.0 FreeRTOS include paths
- Write the correct `CMakeLists.txt` for the wolfssl component (IDF v6.0 compatible)

### 3. Set the ESP32 target

```bash
idf.py set-target esp32
```

### 4. Configure optimization level (important for accurate benchmarks)

```bash
idf.py menuconfig
```

Navigate to:

```
Component config
  → Compiler options
    → Optimization Level
      → (●) Optimize for performance (-O2)
```

> **Default is "Debug" (`-Og`) which is slower than `-O2`.**
> Always use "Optimize for performance" when running benchmarks.

Save and exit (`S` → `Q`).

### 5. Select ML-KEM security level

Edit [main/main.c](main/main.c) lines 23–25:

```c
#define USE_MLKEM_512    0
#define USE_MLKEM_768    1   // ← change this
#define USE_MLKEM_1024   0
```

Exactly one must be `1`.

### 6. Build

```bash
idf.py build
```

### 7. Flash and monitor

```bash
idf.py flash monitor -p COMx   # Windows (e.g. COM5)
idf.py flash monitor -p /dev/ttyUSB0   # Linux/macOS
```

---

## Notes on ESP-IDF v6.0 compatibility

wolfSSL's Espressif hardware acceleration (`PERIPH_AES_MODULE`, `PERIPH_SHA_MODULE`) was removed from the ESP32 `shared_periph_module_t` enum in IDF v6.0. The build disables these with:

```
-DNO_WOLFSSL_ESP32_CRYPT_AES
-DNO_WOLFSSL_ESP32_CRYPT_HASH
```

This has **no impact on ML-KEM performance** — ML-KEM uses SHA3/SHAKE128/SHAKE256, which have no hardware acceleration on ESP32 in any IDF version.

---

## Output format

```
[Performance] Keypair Generation:
[Raw - min max avg stddev]:
 123456  125000  123800    450

[Performance] Encapsulation:
...

[Performance] Decapsulation:
...

[Integrity] PASSED: All 100 keys matched successfully
```

Cycles are measured with `esp_cpu_get_cycle_count()`. Divide by CPU frequency (printed at start) to get milliseconds.