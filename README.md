# mlkem-esp32

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

Optimized implementation of **ML-KEM (FIPS 203)** for the ESP32 microcontroller, developed as part of a bachelor thesis. The project provides multiple build variants targeting different trade-offs between execution speed and stack memory usage, including dual-core parallelization exploiting the ESP32's Xtensa LX6 dual-core architecture.

> For setup, configuration, build instructions, and usage see [SYSTEM_MANUAL.md](SYSTEM_MANUAL.md).

## Optimization Variants

Selected by defining exactly one macro in `main/user_settings.h`:


| Macro | Description |
|-------|-------------|
| `SPEED` | Reference implementation (pq-crystals/kyber) optimized for execution time; uses XKCP SHA-3, wolfSSL NTT/InvNTT, and further optimizations |
| `SPEED_DUALCORE` | SPEED variant with matrix generation parallelized across both ESP32 cores, task split based on per-function timing analysis |
| `STACK` | Memory-efficient implementation based on mlkem-c-embedded; row-by-row matrix-vector multiplication with only one matrix element in memory at a time, combined with the speed optimizations from SPEED |
| `STACK_XTREME` | Extends STACK by generating the noise vector on-the-fly during matrix multiplication, eliminating the noise buffer entirely; constant peak stack across all K values |
| `STACK_DUALCORE` | Parallelizes the STACK matrix-vector multiplication across both cores |

## Implementation Details

> For more details see the thesis *(will be added)*.

### Implemented Tests

See [SYSTEM_MANUAL.md](SYSTEM_MANUAL.md) for configuration and usage details.

- **Memory benchmark** — measures peak stack and heap usage per operation (KeyGen, Encaps, Decaps)
- **Performance benchmark** — measures CPU cycle counts per operation
- **Integrity check** — full KeyGen → Encaps → Decaps round trip; verifies that both parties derive the same shared secret
- **KAT test** — verifies output against known answer vectors generated on the ESP32; input vectors from [post-quantum-cryptography/KAT](https://github.com/post-quantum-cryptography/KAT/tree/main/MLKEM), output stored as SHA3-256 hashes
- **Random vector generation** — generates random (pk, sk, ct, ss) tuples to stdout

### Key Optimizations

- **Dual-core parallelization** — matrix generation and matrix-vector multiplication are split across both Xtensa LX6 cores
- **32-bit interleaved KECCAK** — FIPS 203 hashing uses a 32-bit interleaved Keccak layout
- **WolfSSL NTT/InvNTT** — fast number-theoretic transform and inverse NTT from wolfSSL used for polynomial multiplication
- **Row-by-row matrix-vector multiplication** — only one matrix element exists in memory at a time, reducing peak stack usage (STACK variants)
- **On-the-fly noise vector generation** — noise vector is generated during matrix multiplication instead of buffered, eliminating the noise buffer entirely (STACK_XTREME)
- **Constant peak stack across all security levels** — STACK_XTREME achieves the same peak stack regardless of ML-KEM-512/768/1024 parameter set

### Security Features

- **Sensitive intermediate value zeroization** — all local buffers containing secret material (polynomials, seeds, noise vectors) are zeroed after use via `buffer_zeroize`, which uses `volatile` writes to prevent compiler removal as dead code (per FIPS 203 §3.3)
- **SP 800-90C RBG1 construction** — `esp_randombytes()` is backed by CTR_DRBG(AES-256) seeded exclusively from the ESP32 hardware TRNG via the PSA Crypto API; no software seed, no fixed entropy source
- **Error propagation** — dual-core task creation failures are caught and propagated up through PKE return values to the KEM API level

## Experiments

Complete measurement data for all benchmarked and implemented variants is available in [results/](results/). The directory contains:

- [results/benchmark_raw_data/](results/benchmark_raw_data/) — raw CSV files with CPU cycle counts and memory usage for all optimization variants and comparison implementations across all security levels (512/768/1024)
- [results/benchmark_graphs/](results/benchmark_graphs/) — generated graphs visualizing speed and memory comparisons
- [results/time_analysis/](results/time_analysis/) — per-function cycle counts and call counts for ML-KEM and K-PKE functions, measured on the reference implementation before any optimizations
- [results/comparison_Og_Os_O2/](results/comparison_Og_Os_O2/) — side-by-side comparison of `-Og`, `-Os`, and `-O2` compiler flags across all variants; includes raw benchmark logs and generated reports with average cycle counts and peak stack usage with percentage deltas
- [results/wolffssl_profiles/](results/wolffssl_profiles/) — comparison of wolfSSL's four built-in optimization profiles (`OPT_SIZE`, `OPT_STACK`, `OPT_SPEED`, `OPT_BALANCED`) for ML-KEM-768; CPU cycle counts, peak stack and heap usage per operation, and flash binary size

> **Timing analysis** (per-function cycle counts used to determine the dual-core task split) is on the [`time-analysis`](../../tree/time-analysis) branch.

## Comparison

The [comparison/](comparison/) directory contains separate ESP-IDF projects for benchmarking other cryptographic libraries against this implementation. Each project includes a setup script that downloads the upstream library at a pinned commit or tag, and a README with the exact menuconfig settings (optimization level, CPU frequency, security level) needed to reproduce the measurements.

| Project | Upstream library | Pinned version | Setup script |
|---------|-----------------|----------------|--------------|
| [mlkem-ref](comparison/mlkem-ref/) | [pq-crystals/kyber](https://github.com/pq-crystals/kyber) | commit `4768bd3` | `setup_kyber_ref.sh` |
| [mlkem-wolfssl](comparison/mlkem-wolfssl/) | [wolfSSL](https://github.com/wolfSSL/wolfssl) | tag `v5.8.4-stable` | `setup_wolfssl.sh` |
| [mlkem-native](comparison/mlkem-native/) | [pq-code-package/mlkem-native](https://github.com/pq-code-package/mlkem-native) | tag `v1.0.0` | `setup_mlkem-native.sh` |
| [mlkem-c-embedded](comparison/mlkem-c-embedded/) | [pq-code-package/mlkem-c-embedded](https://github.com/pq-code-package/mlkem-c-embedded) | commit `bfc7cf8` | `setup_mlkem_c_embedded.sh` |
| [kybesp32](comparison/kybesp32/) | [fsegatz/kybesp32](https://github.com/fsegatz/kybesp32) | commit `e638fd9` | `setup_kybesp32.sh` |

## System Manual and Tests

See [SYSTEM_MANUAL.md](SYSTEM_MANUAL.md) for setup, configuration, build instructions, implemented tests, and their usage.

Automated scripts for performance and memory benchmarking are available in [automat_scripts/](automat_scripts/). See [automat_scripts/README.md](automat_scripts/README.md) for execution instructions.

The [nistkat/](nistkat/) directory contains KAT vectors generated on the ESP32, covering all three ML-KEM security levels (512/768/1024). Input vectors are taken from the [post-quantum-cryptography/KAT](https://github.com/post-quantum-cryptography/KAT/tree/main/MLKEM) project (1000 sets per security level); output vectors are stored as SHA3-256 hashes to fit within flash constraints. The directory is structured as a drop-in replacement for the `nistkat` directory in the pq-crystals/kyber reference implementation, enabling independent verification of correctness. See [nistkat/README.md](nistkat/README.md) for details.

## Requirements

- [ESP-IDF v6.0](https://docs.espressif.com/projects/esp-idf/en/v6.0/esp32/get-started/index.html) installed and activated (`idf.py` in PATH)
- ESP32 board
- Git, Bash (WSL, Git Bash, or Linux/macOS terminal)

## License

This project is licensed under **GNU General Public License v3.0 or later** (GPL-3.0-or-later).

The full license text is in [LICENSE](LICENSE).

**Note:** wolfSSL components are licensed under GPL-3.0-or-later. All other components (pq-crystals/kyber, mlkem-c-embedded, mlkem-native, XKCP, fsegatz/kybesp32) are under permissive Apache-2.0, CC0, or MIT licenses compatible with GPL-3.0-or-later. See [CREDITS.md](CREDITS.md) for full attribution.
