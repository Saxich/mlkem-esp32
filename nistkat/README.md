# NIST KAT Verification Directory

This directory serves for verifying the Known Answer Test (KAT) vectors generated for the ESP32 microcontroller.

It contains 1000 input vectors and 1000 corresponding output vectors for each security level (ML-KEM-512, ML-KEM-768, ML-KEM-1024).

This entire `nistkat` directory can be used as a drop-in replacement for the original `nistkat` directory found in the reference implementation at [pq-crystals/kyber/tree/main/ref/nistkat](https://github.com/pq-crystals/kyber/tree/main/ref/nistkat).

After substitution, running `make nistkat` in the reference implementation root will compile binaries `PQCgenKAT_kemXXX` inside the `nistkat` directory. Executing these binaries runs new KAT test against the test vectors using the reference implementation. A successful test result is considered proof of the correctness of the test vectors and of the correctness of their use in testing on the microcontroller.

## Credits

- **KAT vectors**: [post-quantum-cryptography/KAT](https://github.com/post-quantum-cryptography/KAT/tree/main/MLKEM) (public domain / CC0) — Accessed: 2025-11-07
- **Reference implementation**: [pq-crystals/kyber](https://github.com/pq-crystals/kyber/tree/main/ref/nistkat)
