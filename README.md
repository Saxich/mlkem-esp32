# mlkem-esp32 — K-PKE Time Analysis Branch

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

This branch extends the main ML-KEM ESP32 implementation with **per-function timing analysis of the K-PKE (Kyber Public Key Encryption) primitives** — `KeyGen`, `Enc`, and `Dec`. Each internal function is individually timed using the ESP32 CPU cycle counter, allowing fine-grained breakdown of where cycles are spent across all three ML-KEM security levels (512 / 768 / 1024).

## How to use

Set `TEST_TO_TURN 2` in [main/user_settings.h](main/user_settings.h):

```c
#define TEST_TO_TURN  2
```

The build system automatically forces `SPEED` / `SPEED_CODE` when `TEST_TO_TURN == 2` — no manual mode selection is needed. Any STACK or DUALCORE macro defined in `user_settings.h` is silently ignored.

Select the desired ML-KEM parameter set with `MLKEM_K` (2 = ML-KEM-512, 3 = ML-KEM-768, 4 = ML-KEM-1024):

```c
#define MLKEM_K 3
```

Build and flash normally with `idf.py build flash monitor`. Timing results are printed over serial after each K-PKE operation.

## Build and configuration

For full setup, toolchain requirements, flashing instructions, and serial output configuration see [SYSTEM_MANUAL.md](SYSTEM_MANUAL.md).

## License

This project is licensed under **GNU General Public License v3.0 or later** (GPL-3.0-or-later). See [LICENSE](LICENSE).
