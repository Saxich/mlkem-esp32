# Credits and Attributions

This project is based on and incorporates code from the following projects:

---

## pq-crystals/kyber
- URL: https://github.com/pq-crystals/kyber/tree/main/ref
- Accessed: 2026-01-02
- License: CC0-1.0 OR Apache-2.0
- Usage: Fork; base for the ML-KEM reference implementation 

---

## fsegatz/kybesp32
- URL: https://github.com/fsegatz/kybesp32
- Accessed: 2026-01-02
- License: MIT
- Usage: Project structure, idea for dual-core usage and foundation for the implementation of dual-core

---

## pq-code-package/mlkem-c-embedded
- URL: https://github.com/pq-code-package/mlkem-c-embedded/tree/main
- Accessed: 2026-02-22
- License: Apache-2.0 OR CC0-1.0
- Usage: matacc and its mapping in indcpa and related functions, mechanism of indcpa_cmp implemented into indcpa functions

---

## wolfSSL
- URL: https://github.com/wolfSSL/wolfssl
- Accessed: 2026-01-02
- License: GPL-3.0-or-later
- Usage: Polynomial functions and NTT operations, optimized chi operation of Keccak permutation

---

## XKCP
- URL: https://github.com/XKCP/XKCP
- Accessed: 2026-04-04
- License: CC0-1.0
- Usage: FIPS 202 (SHA-3/SHAKE), Keccak permutation, and belonging code

---

## pq-code-package/mlkem-native
- URL: https://github.com/pq-code-package/mlkem-native
- Accessed: 2026-04-04
- License: Apache-2.0
- Usage: Inspiration for explicit zeroing of sensitive intermediate buffers per FIPS 203 Section 3.3

---

## KAT Test Vectors
- URL: https://github.com/post-quantum-cryptography/KAT/tree/main/MLKEM
- Accessed: 2025-11-07
- License: Public domain / CC0
- Usage: Known Answer Test vectors for test_kat
