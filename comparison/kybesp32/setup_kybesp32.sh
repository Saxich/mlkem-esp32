#!/bin/bash

# kybesp32 ESP32 Setup Script
# Integrates the ESP32-native Kyber implementation from fsegatz/kybesp32

set -e

echo "========================================"
echo " kybesp32 Setup for ESP32 (ESP-IDF v6.0)"
echo "========================================"
echo ""

# Check if we're in the right directory
if [ ! -f "CMakeLists.txt" ]; then
    echo "Error: Run this from the project root (comparison/kybesp32/)"
    exit 1
fi

# Clone fsegatz/kybesp32
echo "Cloning fsegatz/kybesp32 repository..."
if [ -d "kybesp32-temp" ]; then
    rm -rf kybesp32-temp
fi

# Pin to a specific commit for reproducibility.
# To update: replace KYBESP32_COMMIT with the desired commit hash.
KYBESP32_COMMIT="e638fd9254caff885c439161a67a65644b1529df"

git clone https://github.com/fsegatz/kybesp32.git kybesp32-temp
git -C kybesp32-temp checkout "${KYBESP32_COMMIT}"

# Copy all components
echo "Copying kybesp32 components..."
mkdir -p components
cp -r kybesp32-temp/components/. components/

# Patch 1: dual-task functions are declared with return type TaskFunction_t,
# which is a pointer-to-function typedef (void(*)(void*)).  Using it as a return
# type makes the compiler see them as functions returning a function pointer rather
# than plain void functions, causing an incompatible-pointer-type error with
# xTaskCreatePinnedToCore in ESP-IDF v6.0.  Replace all six occurrences with void.
echo "Patching indcpa.c (TaskFunction_t return type -> void)..."
sed -i 's/^TaskFunction_t \(indcpa_keypair_dual_0\)/void \1/' components/indcpa/indcpa.c
sed -i 's/^TaskFunction_t \(indcpa_keypair_dual_1\)/void \1/' components/indcpa/indcpa.c
sed -i 's/^TaskFunction_t \(indcpa_enc_dual_0\)/void \1/'     components/indcpa/indcpa.c
sed -i 's/^TaskFunction_t \(indcpa_enc_dual_1\)/void \1/'     components/indcpa/indcpa.c
sed -i 's/^TaskFunction_t \(indcpa_dec_dual_0\)/void \1/'     components/indcpa/indcpa.c
sed -i 's/^TaskFunction_t \(indcpa_dec_dual_1\)/void \1/'     components/indcpa/indcpa.c

# Clean up
echo "Cleaning up..."
rm -rf kybesp32-temp

echo ""
echo "kybesp32 components copied successfully!"
echo ""
echo "Next steps:"
echo "   idf.py set-target esp32"
echo "   idf.py menuconfig (for optimisation and frequency set)"
echo "   idf.py build"
echo "   idf.py flash monitor -p COMx"
echo ""
