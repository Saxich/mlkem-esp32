# ML-KEM on ESP32 with pq-code-package/mlkem-c-embedded (ESP-IDF v6.0)

Benchmark of ML-KEM-512/768/1024 on ESP32 using the embedded C implementation from [pq-code-package/mlkem-c-embedded](https://github.com/pq-code-package/mlkem-c-embedded).

---

## Disclaimer

pq-code-package/mlkem-c-embedded is released under **Apache License 2.0**. This project uses it as a third-party library. The source code is the property of its authors — this repository does not claim ownership of it. See [mlkem-c-embedded license](https://github.com/pq-code-package/mlkem-c-embedded/blob/main/LICENSE) for details.

---

## Prerequisites

- [ESP-IDF v6.0](https://docs.espressif.com/projects/esp-idf/en/v6.0/esp32/get-started/index.html) installed and activated (`idf.py` in PATH)
- ESP32 board
- Git, Bash (WSL, Git Bash, or Linux/macOS terminal)

---

## Installation

### 1. Place project files

Copy the contents of the `mlkem-c-embedded` folder into your desired working directory:

```bash
cp -r mlkem-c-embedded/ /path/to/your/destination/
cd /path/to/your/destination/
```

> The folder may be renamed — what matters is that `main/`, `CMakeLists.txt`, and `setup_mlkem_c_embedded.sh` are all present at the root level.

### 2. Download mlkem-c-embedded sources

```bash
bash setup_mlkem_c_embedded.sh
```

This will:
- Clone pq-code-package/mlkem-c-embedded at a pinned commit into a temporary directory
- Copy `mlkem/`, `fips202/`, and `hal/` source trees into the project root

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

The parameter set is configured in a single place — the root [CMakeLists.txt](CMakeLists.txt):

```cmake
# Manually set parameter (2, 3, or 4)
set(MLKEM_K 4)
```


After changing, delete the build directory and rebuild:

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

## What the benchmark measures

The firmware runs three test suites automatically on boot:

**Memory benchmark** (100 iterations each):
- Stack peak usage — measured via `uxTaskGetStackHighWaterMark()` in a dedicated FreeRTOS task
- Heap peak usage — measured via `heap_caps_monitor_local_minimum_free_size_start/stop()`
- Each operation (KeyGen, Encapsulation, Decapsulation) runs in its own task of size `MEM_TASK_SIZE = 40000` bytes

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
Algorithm: ML-KEM-1024

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

> The integrity check verifies internal consistency only — it is **not** a Known Answer Test (KAT).

---

## Project structure

```
mlkem-c-embedded/
├── CMakeLists.txt                  ← root project file, set MLKEM_K here
├── setup_mlkem_c_embedded.sh       ← downloads mlkem-c-embedded sources
├── main/
│   ├── CMakeLists.txt              ← component registration and compile definitions
│   ├── main.c                      ← benchmark application
│   ├── mlkem_native.h              ← ML-KEM API wrapper
│   └── taskpriorities.h
├── mlkem/                          ← copied by setup script
│   ├── kem.c / kem.h               ← KEM API (keypair / enc / dec)
│   ├── indcpa.c / indcpa.h         ← IND-CPA core
│   ├── poly.c / polyvec.c          ← polynomial arithmetic
│   ├── ntt.c / reduce.c            ← NTT and modular reduction
│   ├── matacc.c                    ← matrix-vector multiplication
│   ├── cbd.c / verify.c            ← sampling and constant-time comparison
│   ├── symmetric-shake.c           ← SHAKE-based PRF/KDF wrappers
│   └── params.h / api.h            ← compile-time parameters and size constants
├── fips202/                        ← copied by setup script
│   ├── fips202.c / fips202.h       ← SHA-3 / SHAKE (Keccak)
│   └── keccakf1600.c               ← Keccak-f[1600] permutation
└── hal/                            ← copied by setup script
    └── randombytes.c               ← ESP32 RNG via esp_fill_random()
```

> `MLKEM_K` is injected at compile time via `target_compile_definitions` and controls which parameter set is active.
