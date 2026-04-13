#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Automation script for ML-KEM ESP32 (esp-idf)
#
# For each combination of K and variant defined below, this script:
#   1. Overwrites main/user_settings.h with the appropriate defines
#   2. Builds and flashes the firmware via idf.py
#   3. Captures serial output between ***START/END OF ESP32 OUTPUT*** markers
#   4. Writes results to automat_scripts/logs/<mode>_<timestamp>.txt
#   5. Restores the original user_settings.h when done (even on error)
#
# Usage:
#   python automat.py kat                # run KAT tests
#   python automat.py benchmark          # run benchmarks
#   python automat.py kat --debug        # also print all idf.py output to console
#   python automat.py benchmark --debug
#
# Must be run from an ESP-IDF environment (idf.py must be on PATH).
# Output logs are written to automat_scripts/logs/ (gitignored).

import argparse
import subprocess
import shutil
import os
import signal
import time
import threading
from datetime import datetime

SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
LOGS_DIR     = os.path.join(SCRIPT_DIR, "logs")

SETTINGS_PATH = os.path.join(PROJECT_ROOT, "main", "user_settings.h")
BACKUP_PATH   = SETTINGS_PATH + ".bak"
PORT          = "COM4"

START_MARKER = "***START OF ESP32 OUTPUT***"
END_MARKER   = "***END OF ESP32 OUTPUT***"

# --- mode configs -----------------------------------------------------------

KAT_CONFIG = {
    "test_to_turn": 3,
    "variants": [
        "SPEED",
        "SPEED_DUALCORE",
        "STACK_XTREME",
        "STACK",
        "STACK_DUALCORE",
    ],
    "k_values": [2, 3, 4], # [2, 3, 4],
    "timeout": 120,
}

BENCHMARK_CONFIG = {
    "test_to_turn": 1,
    "variants": [
        "SPEED",
        "SPEED_DUALCORE",
        "STACK_XTREME",
        "STACK",
        "STACK_DUALCORE",
    ],
    "k_values": [2, 3, 4], # [2, 3, 4],
    "timeout": 300,  
}

# ----------------------------------------------------------------------------


def make_user_settings(k: int, variant: str, cfg: dict) -> str:
    lines = [
        "/* SPDX-License-Identifier: GPL-3.0-or-later */",
        "#ifndef BAKALARKA_USER_SETTINGS_H",
        "#define BAKALARKA_USER_SETTINGS_H",
        f"#define MLKEM_K {k}",
    ]
    for v in cfg["variants"]:
        if v == variant:
            lines.append(f"#define {v}")
        else:
            lines.append(f"// #define {v}")
    lines.append(f"#define TEST_TO_TURN  {cfg['test_to_turn']}")
    lines.append("#define TEST_AUTOMAT")
    lines += ["#endif", ""]
    return "\n".join(lines)


def write_settings(k: int, variant: str, cfg: dict):
    with open(SETTINGS_PATH, "w") as f:
        f.write(make_user_settings(k, variant, cfg))


def run_flash_and_capture(cfg: dict, debug: bool = False) -> str:
    """Flash the board and capture only the lines between the markers."""
    cmd = ["idf.py", "flash", "monitor", "-p", PORT]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        shell=True,
        cwd=PROJECT_ROOT,
    )

    captured_lines = []
    inside = False
    done = threading.Event()

    def reader():
        nonlocal inside
        for raw_line in proc.stdout:
            line = raw_line.rstrip("\r\n")
            if START_MARKER in line:
                inside = True
                continue
            if END_MARKER in line:
                inside = False
                done.set()
                break
            if inside:
                captured_lines.append(line)
            elif debug:
                print(f"  [idf] {line}", flush=True)
        done.set()  # safety in case END_MARKER never arrives

    t = threading.Thread(target=reader, daemon=True)
    t.start()

    done.wait(timeout=cfg["timeout"])

    # Kill entire process tree (shell=True spawns cmd.exe → idf.py; proc.kill()
    # only kills cmd.exe, leaving idf.py holding COM4)
    if os.name == "nt":
        try:
            subprocess.call(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            proc.kill()
    else:
        try:
            proc.send_signal(signal.SIGINT)
        except Exception:
            pass

    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()

    t.join(timeout=5)
    time.sleep(2)  # let COM4 be released before next flash

    return "\n".join(captured_lines)


def run_kat(cfg: dict, output_file: str, timestamp: str, debug: bool):
    variants  = cfg["variants"]
    k_values  = cfg["k_values"]
    total     = len(k_values) * len(variants)
    current   = 0
    results   = []

    try:
        for variant in variants:
            for k in k_values:
                current += 1
                label = f"K={k} {variant}"
                print(f"\n[{current}/{total}] Flashing {label} ...")

                write_settings(k, variant, cfg)
                output = run_flash_and_capture(cfg, debug=debug)

                results.append((label, output))
                print(f"  Captured: {repr(output)}")
    finally:
        _restore_settings()

    with open(output_file, "w") as f:
        f.write("ML-KEM KAT Automated Test Results\n")
        f.write(f"Run at: {timestamp}\n")
        f.write(f"Port:   {PORT}\n")
        f.write("=" * 50 + "\n\n")

        all_passed = True
        for label, output in results:
            passed = "PASSED" in output
            if not passed:
                all_passed = False
            status = "PASSED" if passed else "FAILED"
            f.write(f"[{label}]  {status}\n")
            if output:
                for line in output.splitlines():
                    f.write(f"  {line}\n")
            else:
                f.write("  (no output captured)\n")
            f.write("\n")

        f.write("=" * 50 + "\n")
        f.write(f"OVERALL: {'ALL PASSED' if all_passed else 'SOME FAILED'}\n")

    print(f"\nResults written to {output_file}")
    print("\n========== SUMMARY ==========")
    for label, output in results:
        status = "PASSED" if "PASSED" in output else "FAILED"
        print(f"  {label:<30} {status}")
    print("=" * 30)


def run_benchmark(cfg: dict, output_file: str, timestamp: str, debug: bool):
    variants = cfg["variants"]
    k_values = cfg["k_values"]
    total    = len(k_values) * len(variants)
    current  = 0
    results  = []

    try:
        for variant in variants:
            for k in k_values:
                current += 1
                label = f"K={k} {variant}"
                print(f"\n[{current}/{total}] Flashing {label} ...")

                write_settings(k, variant, cfg)
                output = run_flash_and_capture(cfg, debug=debug)

                results.append((label, output))
                preview_lines = output.splitlines()[:6]
                for pl in preview_lines:
                    print(f"  {pl}")
                if len(output.splitlines()) > 6:
                    print(f"  ... ({len(output.splitlines())} lines total)")
    finally:
        _restore_settings()

    with open(output_file, "w") as f:
        f.write("ML-KEM Benchmark Automated Results\n")
        f.write(f"Run at: {timestamp}\n")
        f.write(f"Port:   {PORT}\n")
        f.write("=" * 50 + "\n\n")

        for label, output in results:
            f.write(f"[{label}]\n")
            if output.strip():
                for line in output.splitlines():
                    f.write(f"  {line}\n")
            else:
                f.write("  (no output captured)\n")
            f.write("\n")

        f.write("=" * 50 + "\n")
        f.write("DONE\n")

    print(f"\nResults written to {output_file}")
    print("\n========== SUMMARY ==========")
    for label, output in results:
        status = "OK" if output.strip() else "NO OUTPUT"
        print(f"  {label:<30} {status}")
    print("=" * 30)


def _restore_settings():
    if os.path.exists(BACKUP_PATH):
        shutil.copy2(BACKUP_PATH, SETTINGS_PATH)
        print(f"\nRestored original {SETTINGS_PATH}")
    else:
        print(f"\nNo backup found, {SETTINGS_PATH} left as last written variant.")


def main():
    parser = argparse.ArgumentParser(description="ML-KEM ESP32 automation")
    parser.add_argument("mode", choices=["kat", "benchmark"], help="Test mode to run")
    parser.add_argument("--debug", action="store_true", help="Print all idf.py output to console")
    args = parser.parse_args()

    os.makedirs(LOGS_DIR, exist_ok=True)

    if os.path.exists(SETTINGS_PATH):
        shutil.copy2(SETTINGS_PATH, BACKUP_PATH)
        print(f"\nBacked up {SETTINGS_PATH} -> {BACKUP_PATH}")
    else:
        print(f"\nWARNING: {SETTINGS_PATH} not found, no backup created.")

    timestamp   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ts_file     = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_file = os.path.join(LOGS_DIR, f"{args.mode}_{ts_file}.txt")

    if args.mode == "kat":
        run_kat(KAT_CONFIG, output_file, timestamp, args.debug)
    else:
        run_benchmark(BENCHMARK_CONFIG, output_file, timestamp, args.debug)


if __name__ == "__main__":
    main()
