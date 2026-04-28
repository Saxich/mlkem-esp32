#!/bin/bash

# mlkem-c-embedded ESP32 Setup Script
# Downloads source files from pq-code-package/mlkem-c-embedded on GitHub

set -e

echo "========================================"
echo " mlkem-c-embedded Setup for ESP32 (ESP-IDF v6.0)"
echo "========================================"
echo ""

# Check if we're in the right directory
if [ ! -f "CMakeLists.txt" ]; then
    echo "Error: Run this from the project root (comparison/mlkem-c-embedded/)"
    exit 1
fi

# Clone pq-code-package/mlkem-c-embedded
echo "Cloning pq-code-package/mlkem-c-embedded repository..."
if [ -d "mlkem-c-embedded-temp" ]; then
    rm -rf mlkem-c-embedded-temp
fi

# Pin to a specific commit for reproducibility.
# To update: replace MLKEM_C_EMBEDDED_COMMIT with the desired commit hash.
MLKEM_C_EMBEDDED_COMMIT="bfc7cf826aaec934cf3f6213592fbb6036be4018"

git clone https://github.com/pq-code-package/mlkem-c-embedded.git mlkem-c-embedded-temp
git -C mlkem-c-embedded-temp checkout "${MLKEM_C_EMBEDDED_COMMIT}"

# Copy source directories needed for the ESP32 build
echo "Copying ML-KEM source files..."
cp -r mlkem-c-embedded-temp/mlkem   ./mlkem
cp -r mlkem-c-embedded-temp/fips202 ./fips202
cp -r mlkem-c-embedded-temp/hal     ./hal

# Clean up
echo "Cleaning up..."
rm -rf mlkem-c-embedded-temp

echo ""
echo "mlkem-c-embedded sources copied successfully!"
echo ""
echo "Next steps:"
echo "   idf.py set-target esp32"
echo "   idf.py menuconfig (Compiler options → Optimize for performance)"
echo "   idf.py build"
echo "   idf.py flash monitor -p COMx"
echo ""
