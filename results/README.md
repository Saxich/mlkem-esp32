# results

This directory contains complete measurement data for all benchmarked and implemented ML-KEM variants on ESP32.

## Subdirectories

- [benchmark_raw_data/](benchmark_raw_data/) — raw CSV files with CPU cycle counts and memory usage measurements for all optimization variants and comparison implementations across all ML-KEM security levels (512/768/1024)
- [benchmark_graphs/](benchmark_graphs/) — generated graphs visualizing speed and memory comparisons across implementations and security levels
- [time_analysis/mlkem_functions/](time_analysis/mlkem_functions/) — results of the timing analysis of independent ML-KEM algorithm functions (call counts and cumulative cycle counts per function)
- [time_analysis/kpke_functions/](time_analysis/kpke_functions/) — results of the timing analysis of functions called by the K-PKE algorithm for all three ML-KEM security levels (512/768/1024)
