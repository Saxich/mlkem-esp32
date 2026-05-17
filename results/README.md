# results

This directory contains complete measurement data for all benchmarked and implemented ML-KEM variants on ESP32.

## Subdirectories

- [benchmark_raw_data/](benchmark_raw_data/) — raw CSV files with CPU cycle counts and memory usage measurements for all optimization variants and comparison implementations across all ML-KEM security levels (512/768/1024)
- [benchmark_graphs/](benchmark_graphs/) — generated graphs visualizing speed and memory comparisons across implementations and security levels
- [time_analysis/mlkem_functions/](time_analysis/mlkem_functions/) — results of the timing analysis of independent ML-KEM algorithm functions (call counts and cumulative cycle counts per function)
- [time_analysis/kpke_functions/](time_analysis/kpke_functions/) — results of the timing analysis of functions called by the K-PKE algorithm for all three ML-KEM security levels (512/768/1024)
- [comparison_Og_Os_O2/](comparison_Og_Os_O2/) — side-by-side comparisons of the `-Og`, `-Os` and `-O2` compiler optimization flags across all implemented variants and ML-KEM security levels; contains the three raw benchmark logs (`benchmark_Og.txt`, `benchmark_Os.txt`, `benchmark_O2.txt`) and two generated comparison reports reporting average cycles and peak stack usage with percentage deltas: `comparison_Og_os.txt` (-Og vs -Os) and `comparison_Os_O2.txt` (-Os vs -O2)
- [wolffssl_profiles/](wolffssl_profiles/) — comparison of wolfSSL's four built-in optimization profiles (`OPT_SIZE`, `OPT_STACK`, `OPT_SPEED`, `OPT_BALANCED`) for ML-KEM-768; includes CPU cycle counts, peak stack and heap usage per operation, and flash binary size
- [kyber_sha3_s90/](kyber_sha3_s90/) — direct head-to-head measurement of Kyber (SHA-3) against Kyber-90s (SHA-2 + AES) on `kybesp32`, covering all combinations of single-/dual-core, hardware SHA accelerator on/off, and hardware AES accelerator on/off, under identical hardware, ESP-IDF version, and optimization flags; isolates the actual impact of the 90s variant under controlled conditions

> **Note:** The `time_analysis` results were measured on the reference implementation **before** any optimizations were applied to mlkem-esp32. Running the time analysis tests on the current version of mlkem-esp32 will not produce the same results.
