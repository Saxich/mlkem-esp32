# Kyber on ESP32 with kybesp32 (ESP-IDF v6.0)

Benchmark of Kyber512/768/1024 on ESP32 using [kybesp32](https://github.com/fsegatz/kybesp32) — an ESP32-native implementation with optional dual-core acceleration via FreeRTOS tasks.

---

## Disclaimer

kybesp32 is licensed under **MIT**. This project uses kybesp32 as a third-party library. The kybesp32 source code is the property of its authors — this repository does not claim ownership of it. See [kybesp32 license](https://github.com/fsegatz/kybesp32/blob/main/License.md) for details.

---

## Prerequisites

- [ESP-IDF v6.0](https://docs.espressif.com/projects/esp-idf/en/v6.0/esp32/get-started/index.html) installed and activated (`idf.py` in PATH)
- ESP32 board
- Git, Bash (WSL, Git Bash, or Linux/macOS terminal)

---

## Installation

### 1. Place project files

Copy the contents of the `kybesp32` folder into your desired working directory:

```bash
cp -r kybesp32/ /path/to/your/destination/
cd /path/to/your/destination/
```

> The folder may be renamed — what matters is that `main/`, `CMakeLists.txt`, and `setup_kybesp32.sh` are all present at the root level.

### 2. Download kybesp32 components

```bash
bash setup_kybesp32.sh
```

This will:
- Clone fsegatz/kybesp32 at a pinned commit into a temporary directory
- Copy the entire `components/` tree into the project
- Patch `indcpa.c`: fix `TaskFunction_t` return type on all dual-core task functions to `void` (required for ESP-IDF v6.0 — see [Known issues](#known-issues))

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

### 5. Select Kyber security level and dual-core mode

Both are configured in the root [CMakeLists.txt](CMakeLists.txt):

```cmake
# Kyber security level: 2=Kyber512, 3=Kyber768, 4=Kyber1024
add_compile_definitions("KYBER_K=3")

# Dual-core acceleration (0=single-core, 1=dual-core)
add_compile_definitions("INDCPA_KEYPAIR_DUAL=1")
add_compile_definitions("INDCPA_ENC_DUAL=1")
add_compile_definitions("INDCPA_DEC_DUAL=1")
```

After changing any flag, delete the build directory and rebuild:

```bash
rm -rf build/
idf.py build
```

### 6. Build

```bash
idf.py build
```

### 7. Flash and monitor

```bash
idf.py flash monitor -p COMx          # Windows (e.g. COM5)
idf.py flash monitor -p /dev/ttyUSB0  # Linux/macOS
```

---

## Dual-core mode

When any `INDCPA_*_DUAL=1` flag is set, the corresponding indcpa operation spawns two FreeRTOS tasks — one pinned to each ESP32 core — and synchronises them with counting semaphores:


> **Priority requirement**: benchmark tasks run at `MAIN_TASK_PRIORITY=11`, indcpa subtasks at `INDCPA_SUBTASK_PRIORITY=10`. Main must be strictly above subtasks — if inverted, the first subtask preempts the caller before the second is created, destroying parallelism and making dual-core slower than single-core.


---

## What the benchmark measures

The firmware runs three test suites automatically on boot:

**Memory benchmark** (100 iterations each):
- Stack peak usage — measured via `uxTaskGetStackHighWaterMark()` in a dedicated FreeRTOS task
- Heap peak usage — measured via `heap_caps_monitor_local_minimum_free_size_start/stop()`
- Each operation (KeyGen, Encapsulation, Decapsulation) runs in its own task of size `MEM_TASK_SIZE = 40000` bytes

> In dual-core mode heap measurements include the stack allocations of the two indcpa subtasks (~40 KB per operation).

**Performance benchmark** (200 iterations each):
- Cycle counts measured with `esp_cpu_get_cycle_count()`
- Preceded by 10 warm-up iterations

**Integrity check** (100 iterations):
- Full KeyGen → Encapsulation → Decapsulation round trip
- Verifies that shared secrets match: `ss_enc == ss_dec`

---

## Output format

```
========================================
 CONFIG INFO
========================================
CPU Frequency: 240000000 Hz (240.000 MHz)
Algorithm: Kyber768

========================================
 MEMORY BENCHMARK
========================================
[Memory] Keypair:
[Raw - Stack/Heap: min max avg stddev]:
   2048    2048    2048       0
      0       0       0       0
[Raw - stackmax heapmax]:
   2048       0

[Memory] Encapsulation:
...

[Memory] Decapsulation:
...

========================================
 PERFORMANCE BENCHMARK
========================================
[Performance] Keypair Generation:
[Raw - min max avg stddev]:
 123456  125000  123800    450

[Performance] Encapsulation:
...

[Performance] Decapsulation:
...

========================================
 INTEGRITY CHECK
========================================
[Integrity] PASSED: All 100 keys matched successfully - THIS IS NOT KAT TEST!
```

Cycles are measured with `esp_cpu_get_cycle_count()`. Divide by CPU frequency (printed at start) to get milliseconds.


---

## Known issues

### `TaskFunction_t` return type (ESP-IDF v6.0)

`TaskFunction_t` is `typedef void (*TaskFunction_t)(void *)` — a pointer-to-function type. In the upstream source, the six dual-core task functions are declared with `TaskFunction_t` as their return type, which the compiler interprets as functions returning a function pointer rather than plain `void` functions. This causes a build error with `xTaskCreatePinnedToCore` in ESP-IDF v6.0. The setup script patches all six to `void` automatically.

### `KYBER_90S` flag

`kem.h` uses `#ifdef KYBER_90S` while `symmetric.h` uses `#if (KYBER_90S == 1)`. Defining `KYBER_90S=0` satisfies the `symmetric.h` check (standard variant) but still triggers `#ifdef` in `kem.h`, producing the wrong algorithm name in output. The flag must be either **defined** (90s variant) or **absent** (standard variant) — never set to `0`.

---

## Component structure

```
components/
├── kem/            ← KEM API (crypto_kem_keypair / enc / dec)
├── indcpa/         ← IND-CPA core with optional dual-core paths
├── common/
│   ├── params.h    ← KYBER_K and all derived size constants
│   └── taskpriorities.h  ← MAIN_TASK_PRIORITY=11, INDCPA_SUBTASK_PRIORITY=10
├── poly/ polyvec/ ntt/ cbd/ reduce/ verify/  ← polynomial arithmetic
├── fips202/        ← SHA-3 / SHAKE (standard variant)
├── symmetric/      ← SHAKE or AES-256-CTR wrapper (selected by KYBER_90S)
├── aes256ctr/ sha2/  ← 90s variant primitives
├── randombytes/    ← esp_fill_random() wrapper
└── kex/            ← key exchange (not used in benchmark)
```
