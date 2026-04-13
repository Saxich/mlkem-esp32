#!/bin/bash

# ML-KEM ESP32 Setup Script
# Properly integrates mlkem-native from pq-code-package

set -e

echo "========================================"
echo " mlkem-native Setup for ESP32 (ESP-IDF v6.0)"
echo "========================================"
echo ""

# Check if we're in the right directory
if [ ! -f "CMakeLists.txt" ]; then
    echo "Error: Run this from the project root"
    exit 1
fi

# Clone mlkem-native
echo "Cloning mlkem-native repository..."
if [ -d "mlkem-native-temp" ]; then
    rm -rf mlkem-native-temp
fi

# urpavene po stiahnuti, pre bc uprav a over, pridany --branch
git clone --depth 1 --branch v1.0.0 https://github.com/pq-code-package/mlkem-native.git mlkem-native-temp

# Copy needed files
echo "Copying ML-KEM source files..."
mkdir -p components/mlkem_native/src
mkdir -p components/mlkem_native/include

# Copy all mlkem source files
cp -r mlkem-native-temp/mlkem/* components/mlkem_native/

# Generate ESP32 randombytes implementation
echo "Generating randombytes.c for ESP32..."
cat > components/mlkem_native/randombytes.c << 'EOF'
#include <stddef.h>
#include <stdint.h>
#include "esp_random.h"

void randombytes(uint8_t *out, size_t outlen)
{
    esp_fill_random(out, outlen);
}
EOF

# Generate component CMakeLists.txt
# mlkem_native.c is a Single Compilation Unit (SCU) that already #includes
# all src/*.c files, so only it and randombytes.c need to be compiled.
#
# NOTE: MLKEM_PARAMETER_SET is defined once in the root CMakeLists.txt.
#   - PUBLIC macros apply to the library and all consumers.
#   - INTERFACE macros apply only to consumers (mlkem_native.h requires
#     MLK_CONFIG_API_XXX to NOT be defined during the library's own build).
echo "Generating component CMakeLists.txt..."
cat > components/mlkem_native/CMakeLists.txt << 'EOF'
idf_component_register(
    SRCS
        "mlkem_native.c"
        "randombytes.c"
    INCLUDE_DIRS
        "."
    PRIV_INCLUDE_DIRS
        "src"
        "src/fips202"
        "src/native"
        "src/fips202/native"
    PRIV_REQUIRES
        esp_system
        freertos
)

target_compile_options(${COMPONENT_LIB} PRIVATE
    -Wno-unused-function
)

# ML-KEM configuration (internal build macros)
target_compile_definitions(${COMPONENT_LIB} PUBLIC
    MLK_CONFIG_PARAMETER_SET=${MLKEM_PARAMETER_SET}
    MLK_CONFIG_USE_NATIVE_BACKEND_ARITH=0
    MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202=0
)

# API-side macros required by mlkem_native.h consumers (must NOT be set during library build)
target_compile_definitions(${COMPONENT_LIB} INTERFACE
    MLK_CONFIG_API_PARAMETER_SET=${MLKEM_PARAMETER_SET}
    MLK_CONFIG_API_NAMESPACE_PREFIX=PQCP_MLKEM_NATIVE_MLKEM${MLKEM_PARAMETER_SET}
)
EOF

# Clean up
echo "Cleaning up..."
rm -rf mlkem-native-temp

echo ""
echo "ML-KEM native files copied successfully!"
echo ""
echo "Next steps:"
echo "   idf.py set-target esp32"
echo "   idf.py menuconfig (for optimisation and frequency set)"
echo "   idf.py build"
echo "   idf.py flash monitor -p COMx"
echo ""
