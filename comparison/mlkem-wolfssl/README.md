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

### 4. Configure menuconfig (optional)

```bash
idf.py menuconfig
```

**Optimization level** *(TODO: decide which)*

```
Component config
  → Compiler options
    → Optimization Level
      → (●) Optimize for performance (-O2)
```

> Default is "Debug" (`-Og`). You may switch to `-O2`, but results at `-Og` are still valid benchmarks.

**CPU frequency** *(optional)*

```
(Top)
  → Component config
    → ESP System Settings
      → CPU frequency
```

Save and exit (`S` → `Q`).

### 5. Select ML-KEM security level

Edit `MLKEM_VERSION` at the top of [main/user_settings.h](main/user_settings.h):

```c
#define MLKEM_VERSION  768   // set to 512, 768, or 1024
```

| Value | NIST Level | Public key | Ciphertext |
|-------|-----------|-----------|------------|
| 512   | 1 (~AES-128) | 800 B  | 768 B  |
| 768   | 3 (~AES-192) | 1184 B | 1088 B |
| 1024  | 5 (~AES-256) | 1568 B | 1568 B |

An invalid value will produce a compile-time error.

### 6. Select optimization profile

Edit the active `OPT_` define directly below `MLKEM_VERSION` in [main/user_settings.h](main/user_settings.h):

```c
// #define OPT_SPEED       // max speed; default wolfSSL behaviour
// #define OPT_STACK     // minimize stack + heap
// #define OPT_SIZE  // minimize flash footprint
#define OPT_BALANCED       // recommended: best speed/RAM/flash trade-off
```

Uncomment exactly one profile. `OPT_BALANCED` is the default and recommended setting for benchmarks.

> Performance comparisons across all profiles are available in [results_mods/graphs/](results_mods/graphs/).

### 7. Build

```bash
idf.py build
```

### 8. Flash and monitor

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