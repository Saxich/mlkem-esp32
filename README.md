# mlkem-bakalarka

Optimized implementation of **ML-KEM (FIPS 203)** for the ESP32 microcontroller, developed as part of a bachelor thesis. The project provides multiple build variants targeting different trade-offs between execution speed and stack memory usage, including dual-core parallelization exploiting the ESP32's Xtensa LX6 dual-core architecture.

## Parameter Sets

| Variant | K | Security | Public Key | Ciphertext |
|---------|---|----------|------------|------------|
| ML-KEM-512  | 2 | 128-bit | 800 B  | 768 B  |
| ML-KEM-768  | 3 | 192-bit | 1184 B | 1088 B |
| ML-KEM-1024 | 4 | 256-bit | 1568 B | 1568 B |

Selected via `MLKEM_K` in `main/user_settings.h`.

## Build Variants

Selected by defining exactly one macro in `main/user_settings.h`:

| Macro | Description |
|-------|-------------|
| `SPEED` | Reference implementation (pq-crystals/kyber), optimized for execution time |
| `SPEED_DUALCORE` | SPEED variant with matrix generation parallelized across both ESP32 cores, task split based on per-function timing analysis |
| `STACK` | Memory-efficient implementation based on mlkem-c-embedded; row-by-row matrix-vector multiplication, only one matrix element exists in memory at a time |
| `STACK_XTREME` | Extends STACK by generating the noise vector on-the-fly during matrix multiplication, eliminating the noise buffer entirely; constant peak stack across all K values |
| `STACK_DUALCOR4E` | Parallelizes the STACK matrix-vector multiplication across both cores in a single pass; adjusts for odd K (ML-KEM-768) where rows cannot be evenly split |

## Performance


## Memory Usage


## Tests and Benchmarks


## Key Implementation Details


## Requirements

- ESP32
- ESP-IDF development framework

## Build

This project uses the ESP-IDF CMake build system:

```bash
idf.py set-target esp32
idf.py build
idf.py flash monitor
```

Configure the build variant and test mode in `main/user_settings.h` before building.

## License

This project is licensed under **GNU General Public License v3.0 or later** (GPL-3.0-or-later).

The full license text is in [LICENSE](LICENSE).

**Note:** wolfSSL components are licensed under GPL-3.0-or-later. All other components (pq-crystals/kyber, mlkem-c-embedded, mlkem-native, XKCP) are under permissive Apache-2.0 or CC0 licenses compatible with GPL-3.0-or-later. See [CREDITS.md](CREDITS.md) for full attribution.
