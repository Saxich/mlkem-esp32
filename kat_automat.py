#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# KAT automation script for ML-KEM ESP32 (esp-idf)
# Tests all 15 combinations: K={2,3,4} x variant={SPEED, SPEED_DUALCORE, STACK_XTREME, STACK, STACK_DUALCORE}

import subprocess
import shutil
import os
import signal
import time
import threading
from datetime import datetime

SETTINGS_PATH = os.path.join("main", "user_settings.h")
BACKUP_PATH   = SETTINGS_PATH + ".bak"
OUTPUT_FILE   = "kat_automated_output.txt"
PORT          = "COM4"
TEST_TO_TURN  = 3

START_MARKER  = "***START OF ESP32 KAT OUTPUT***"
END_MARKER    = "***END OF ESP32 KAT OUTPUT***"

VARIANTS = [
    "SPEED",
    "SPEED_DUALCORE",
    "STACK_XTREME",
    "STACK",
    "STACK_DUALCORE",
]

K_VALUES = [2, 3, 4]


def make_user_settings(k: int, variant: str) -> str:
    lines = [
        "/* SPDX-License-Identifier: GPL-3.0-or-later */",
        "#ifndef BAKALARKA_USER_SETTINGS_H",
        "#define BAKALARKA_SETTINGS_H",
        f"#define MLKEM_K {k}",
    ]
    for v in VARIANTS:
        if v == variant:
            lines.append(f"#define {v}")
        else:
            lines.append(f"// #define {v}")
    lines += [
        f"#define TEST_TO_TURN  {TEST_TO_TURN}",
        "#define KAT_TEST_AUTOMAT",
        "#endif",
        "",
    ]
    return "\n".join(lines)


def write_settings(k: int, variant: str):
    content = make_user_settings(k, variant)
    with open(SETTINGS_PATH, "w") as f:
        f.write(content)


def run_flash_and_capture(k: int, variant: str) -> str:
    """Flash the board and capture only the lines between the markers."""
    cmd = ["idf.py", "flash", "monitor", "-p", PORT]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        shell=True,
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
        done.set()  # safety in case END_MARKER never arrives

    t = threading.Thread(target=reader, daemon=True)
    t.start()

    # Wait for end marker (generous timeout — flash + boot can be slow)
    done.wait(timeout=120)

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


def main():
    # Backup original settings if it exists
    if os.path.exists(SETTINGS_PATH):
        shutil.copy2(SETTINGS_PATH, BACKUP_PATH)
        print(f"\nBacked up {SETTINGS_PATH} -> {BACKUP_PATH}")
    else:
        print(f"\nWARNING: {SETTINGS_PATH} not found, no backup created.")

    results = []
    total   = len(K_VALUES) * len(VARIANTS)
    current = 0

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        for variant in VARIANTS:
            for k in K_VALUES:
                current += 1
                label = f"K={k} {variant}"
                print(f"\n[{current}/{total}] Flashing {label} ...")

                write_settings(k, variant)

                output = run_flash_and_capture(k, variant)

                results.append((label, output))
                print(f"  Captured: {repr(output)}")

    finally:
        # Always restore original settings
        if os.path.exists(BACKUP_PATH):
            shutil.copy2(BACKUP_PATH, SETTINGS_PATH)
            print(f"\nRestored original {SETTINGS_PATH}")
        else:
            print(f"\nNo backup found, {SETTINGS_PATH} left as last written variant.")

    # Write output file
    with open(OUTPUT_FILE, "w") as f:
        f.write(f"ML-KEM KAT Automated Test Results\n")
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

    print(f"\nResults written to {OUTPUT_FILE}")

    # Also print summary to console
    print("\n========== SUMMARY ==========")
    for label, output in results:
        status = "PASSED" if "PASSED" in output else "FAILED"
        print(f"  {label:<30} {status}")
    print("=" * 30)


if __name__ == "__main__":
    main()