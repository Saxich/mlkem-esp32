# mlkem-esp32

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

Optimized implementation of **ML-KEM (FIPS 203)** for the ESP32 microcontroller, developed as part of a bachelor thesis. The project provides multiple build variants targeting different trade-offs between execution speed and stack memory usage, including dual-core parallelization exploiting the ESP32's Xtensa LX6 dual-core architecture.

> For setup, configuration, build instructions, and usage see [USER_MANUAL.md](USER_MANUAL.md).

## Optimization Variants

Selected by defining exactly one macro in `main/user_settings.h`:

| Macro | Description |
|-------|-------------|
| `SPEED` | Reference implementation (pq-crystals/kyber), optimized for execution time |
| `SPEED_DUALCORE` | SPEED variant with matrix generation parallelized across both ESP32 cores, task split based on per-function timing analysis |
| `STACK` | Memory-efficient implementation based on mlkem-c-embedded; row-by-row matrix-vector multiplication, only one matrix element exists in memory at a time |
| `STACK_XTREME` | Extends STACK by generating the noise vector on-the-fly during matrix multiplication, eliminating the noise buffer entirely; constant peak stack across all K values |
| `STACK_DUALCORE` | Parallelizes the STACK matrix-vector multiplication across both cores in a single pass; adjusts for odd K (ML-KEM-768) where rows cannot be evenly split |

## Key Implementation Details

- **Dual-core parallelization** — matrix generation and matrix-vector multiplication are split across both Xtensa LX6 cores
- **32-bit interleaved KECCAK** — FIPS 203 hashing uses a 32-bit interleaved Keccak layout
- **WolfSSL NTT/InvNTT** — fast number-theoretic transform and inverse NTT from wolfSSL used for polynomial multiplication
- **Row-by-row matrix-vector multiplication** — only one matrix element exists in memory at a time,  reducing peak stack usage (STACK variants)
- **On-the-fly noise vector generation** — noise vector is generated during matrix multiplication instead of buffered, eliminating the noise buffer entirely (STACK_XTREME)
- **Constant peak stack across all security levels** — STACK_XTREME achieves the same peak stack regardless of ML-KEM-512/768/1024 parameter set

> For more details see the thesis *(will be added)*.

## Performance

Raw benchmark data and graphs are in [results/](results/).

Values are CPU cycle counts, independent of the ESP32 clock frequency. To convert to execution time:

```
time (ms) = cycles / (frequency_MHz × 1 000 000) × 1 000
```

For example, at 240 MHz: `1 000 000 cycles ≈ 4.17 ms`

### ML-KEM-512 (CPU Cycles)

| Implementation   | KeyGen    | Encaps    | Decaps    |
|------------------|-----------|-----------|-----------|
| STACK_XTREME     | 1 312 863 | 1 297 128 | 1 433 532 |
| STACK            | 991 390   | 969 362   | 1 105 280 |
| STACK_DUALCORE   | 635 134   | 655 168   | 758 499   |
| SPEED            | 900 633   | 959 734   | 1 101 751 |
| SPEED_DUALCORE   | 595 407   | 604 102   | 705 116   |

### ML-KEM-768 (CPU Cycles)

| Implementation   | KeyGen    | Encaps    | Decaps    |
|------------------|-----------|-----------|-----------|
| STACK_XTREME     | 2 103 850 | 2 111 585 | 2 300 446 |
| STACK            | 1 554 969 | 1 551 066 | 1 740 655 |
| STACK_DUALCORE   | 1 134 687 | 1 173 374 | 1 325 200 |
| SPEED            | 1 402 554 | 1 519 286 | 1 720 593 |
| SPEED_DUALCORE   | 895 984   | 919 390   | 1 071 052 |

### ML-KEM-1024 (CPU Cycles)

| Implementation   | KeyGen    | Encaps    | Decaps    |
|------------------|-----------|-----------|-----------|
| STACK_XTREME     | 3 330 759 | 3 324 406 | 3 570 561 |
| STACK            | 2 353 201 | 2 333 260 | 2 580 282 |
| STACK_DUALCORE   | 1 456 371 | 1 883 122 | 2 043 528 |
| SPEED            | 2 131 075 | 2 266 275 | 2 528 627 |
| SPEED_DUALCORE   | 1 267 083 | 1 316 023 | 1 502 311 |

## Memory Usage

Raw measurement data and graphs are in [results/](results/).

### Parameter Sets

| Variant | K | Security | Public Key | Ciphertext |
|---------|---|----------|------------|------------|
| ML-KEM-512  | 2 | 128-bit | 800 B  | 768 B  |
| ML-KEM-768  | 3 | 192-bit | 1184 B | 1088 B |
| ML-KEM-1024 | 4 | 256-bit | 1568 B | 1568 B |

Input buffers are not included in measurements. Heap is non-zero only for DUALCORE variants (task stack allocated for the second core).

### ML-KEM-512 (bytes)

| Implementation   | Operation | Stack | Heap  | Total  |
|------------------|-----------|-------|-------|--------|
| SPEED_DUALCORE   | KeyGen    | 6 176 | 1 896 | 8 072  |
| SPEED_DUALCORE   | Encaps    | 8 864 | 1 896 | 10 760 |
| SPEED_DUALCORE   | Decaps    | 8 816 | 1 896 | 10 712 |
| SPEED            | KeyGen    | 6 144 | 0     | 6 144  |
| SPEED            | Encaps    | 8 768 | 0     | 8 768  |
| SPEED            | Decaps    | 8 720 | 0     | 8 720  |
| STACK_DUALCORE   | KeyGen    | 2 320 | 2 152 | 4 472  |
| STACK_DUALCORE   | Encaps    | 2 416 | 2 152 | 4 568  |
| STACK_DUALCORE   | Decaps    | 2 368 | 2 152 | 4 520  |
| STACK            | KeyGen    | 2 416 | 0     | 2 416  |
| STACK            | Encaps    | 2 352 | 0     | 2 352  |
| STACK            | Decaps    | 2 304 | 0     | 2 304  |
| STACK_XTREME     | KeyGen    | 1 968 | 0     | 1 968  |
| STACK_XTREME     | Encaps    | 1 904 | 0     | 1 904  |
| STACK_XTREME     | Decaps    | 1 856 | 0     | 1 856  |

### ML-KEM-768 (bytes)

| Implementation   | Operation | Stack  | Heap  | Total  |
|------------------|-----------|--------|-------|--------|
| SPEED_DUALCORE   | KeyGen    | 10 288 | 1 896 | 12 184 |
| SPEED_DUALCORE   | Encaps    | 13 472 | 1 896 | 15 368 |
| SPEED_DUALCORE   | Decaps    | 13 424 | 1 896 | 15 320 |
| SPEED            | KeyGen    | 10 432 | 0     | 10 432 |
| SPEED            | Encaps    | 13 376 | 0     | 13 376 |
| SPEED            | Decaps    | 13 328 | 0     | 13 328 |
| STACK_DUALCORE   | KeyGen    | 2 816  | 2 152 | 4 968  |
| STACK_DUALCORE   | Encaps    | 2 912  | 2 152 | 5 064  |
| STACK_DUALCORE   | Decaps    | 2 864  | 2 152 | 5 016  |
| STACK            | KeyGen    | 2 976  | 0     | 2 976  |
| STACK            | Encaps    | 2 848  | 0     | 2 848  |
| STACK            | Decaps    | 2 800  | 0     | 2 800  |
| STACK_XTREME     | KeyGen    | 1 968  | 0     | 1 968  |
| STACK_XTREME     | Encaps    | 1 840  | 0     | 1 840  |
| STACK_XTREME     | Decaps    | 1 920  | 0     | 1 920  |

### ML-KEM-1024 (bytes)

| Implementation   | Operation | Stack  | Heap  | Total  |
|------------------|-----------|--------|-------|--------|
| SPEED_DUALCORE   | KeyGen    | 15 392 | 1 896 | 17 288 |
| SPEED_DUALCORE   | Encaps    | 19 104 | 1 896 | 21 000 |
| SPEED_DUALCORE   | Decaps    | 19 056 | 1 896 | 20 952 |
| SPEED            | KeyGen    | 15 552 | 0     | 15 552 |
| SPEED            | Encaps    | 19 008 | 0     | 19 008 |
| SPEED            | Decaps    | 18 960 | 0     | 18 960 |
| STACK_DUALCORE   | KeyGen    | 3 328  | 2 152 | 5 480  |
| STACK_DUALCORE   | Encaps    | 3 424  | 2 152 | 5 576  |
| STACK_DUALCORE   | Decaps    | 3 376  | 2 152 | 5 528  |
| STACK            | KeyGen    | 3 488  | 0     | 3 488  |
| STACK            | Encaps    | 3 552  | 0     | 3 552  |
| STACK            | Decaps    | 3 504  | 0     | 3 504  |
| STACK_XTREME     | KeyGen    | 1 968  | 0     | 1 968  |
| STACK_XTREME     | Encaps    | 2 032  | 0     | 2 032  |
| STACK_XTREME     | Decaps    | 2 064  | 0     | 2 064  |


## Comparison

The [comparison/](comparison/) directory contains separate ESP-IDF projects for benchmarking other cryptographic libraries against this implementation.

- **wolfSSL** — see [comparison/mlkem-wolfssl/README_wolfssl.md](comparison/mlkem-wolfssl/README_wolfssl.md) for setup and benchmarking instructions
- **mlkem-native** — see [comparison/mlkem-native/README_mlkem-native.md](comparison/mlkem-native/README_mlkem-native.md) for setup and benchmarking instructions

## User Manual and Tests

See [USER_MANUAL.md](USER_MANUAL.md) for setup, configuration, build instructions, implemented tests, and their usage.

Automated scripts for performance and memory benchmarking are available in [automat_scripts/](automat_scripts/). See [README_AUTOMAT.md](automat_scripts/README_AUTOMAT.md) for execution instructions.

## Requirements

- ESP32
- ESP-IDF v6.0

## License

This project is licensed under **GNU General Public License v3.0 or later** (GPL-3.0-or-later).

The full license text is in [LICENSE](LICENSE).

**Note:** wolfSSL components are licensed under GPL-3.0-or-later. All other components (pq-crystals/kyber, mlkem-c-embedded, mlkem-native, XKCP, fsegatz/kybesp32) are under permissive Apache-2.0, CC0, or MIT licenses compatible with GPL-3.0-or-later. See [CREDITS.md](CREDITS.md) for full attribution.
