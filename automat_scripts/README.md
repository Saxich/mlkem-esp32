# Automation Scripts

## Requirements

These scripts must be run from the **ESP-IDF terminal** (not a regular PowerShell or venv),  
so that `idf.py` is available on PATH.

On Windows, open the **ESP-IDF CMD** or **ESP-IDF PowerShell** shortcut installed with Espressif tools.

## Configuration

Before running, check the constants at the top of `automat.py`:

| Variable | Description |
|---|---|
| `PORT` | Serial port of the ESP32 — **change as needed** (e.g. `COM3`, `COM5`) |
| `KAT_CONFIG["variants"]` | Uncomment the variants to test in KAT mode |
| `BENCHMARK_CONFIG["variants"]` | Uncomment the variants to test in benchmark mode |
| `K_VALUES` | List of ML-KEM parameter sets (`2`, `3`, `4`) |

## Usage

Run from the `automat_scripts/` directory:

```bash
# KAT tests
python automat.py kat

# Benchmarks
python automat.py benchmark

# With full idf.py output (build errors, flash log, serial dump)
python automat.py kat --debug
python automat.py benchmark --debug
```

## Output

Logs are saved to `automat_scripts/logs/` (gitignored) with a timestamp in the filename:

```
logs/kat_2026-04-12_14-30-05.txt
logs/benchmark_2026-04-12_14-30-05.txt
```

Each run produces a new file — existing logs are never overwritten.
