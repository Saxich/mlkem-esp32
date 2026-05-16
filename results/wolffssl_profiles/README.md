# wolfSSL Build Profile Comparison

Benchmarks of wolfSSL's four built-in optimization profiles for ML-KEM-768 on ESP32. Each profile is a predefined set of compile-time flags that trades off between binary size, RAM usage, and execution speed.

## Profiles

| Profile | Description |
|---------|-------------|
| `OPT_SIZE` | Minimize flash binary size |
| `OPT_STACK` | Minimize RAM usage |
| `OPT_SPEED` | Maximize execution speed |
| `OPT_BALANCED` | Balanced trade-off |

## Contents

- [raw_data/wolfssl_speed_data.csv](raw_data/wolfssl_speed_data.csv) — CPU cycle counts (KeyGen, Encaps, Decaps) per profile
- [raw_data/wolfssl_memory_data.csv](raw_data/wolfssl_memory_data.csv) — peak stack and heap usage in bytes per operation per profile
- [raw_data/wolfssl_image_data.csv](raw_data/wolfssl_image_data.csv) — flash binary size in bytes per profile
- [graphs/wolfssl_speed_768.png](graphs/wolfssl_speed_768.png) — speed comparison graph
- [graphs/wolfssl_mem_768.png](graphs/wolfssl_mem_768.png) — memory comparison graph
- [graphs/wolfssl_image_768.png](graphs/wolfssl_image_768.png) — image size comparison graph
