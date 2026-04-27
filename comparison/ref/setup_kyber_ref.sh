#!/bin/bash

# Kyber (pq-crystals/kyber) ESP32 Setup Script
# Integrates the ref implementation into an ESP-IDF component

set -e

echo "========================================"
echo " kyber/ref Setup for ESP32 (ESP-IDF v6.0)"
echo "========================================"
echo ""

# Check if we're in the right directory
if [ ! -f "CMakeLists.txt" ]; then
    echo "Error: Run this from the project root (comparison/ref/)"
    exit 1
fi

# Clone pq-crystals/kyber
echo "Cloning pq-crystals/kyber repository..."
if [ -d "kyber-temp" ]; then
    rm -rf kyber-temp
fi

# Pin to a specific commit for reproducibility.
KYBER_COMMIT="4768bd37c02f9c40a46cb49d4d1f4d5e612bb882"

git clone https://github.com/pq-crystals/kyber.git kyber-temp
git -C kyber-temp checkout "${KYBER_COMMIT}"

# Copy ref source files
echo "Copying Kyber ref source files..."
mkdir -p components/kyber_ref

cp kyber-temp/ref/kem.c              components/kyber_ref/
cp kyber-temp/ref/indcpa.c           components/kyber_ref/
cp kyber-temp/ref/polyvec.c          components/kyber_ref/
cp kyber-temp/ref/poly.c             components/kyber_ref/
cp kyber-temp/ref/ntt.c              components/kyber_ref/
cp kyber-temp/ref/cbd.c              components/kyber_ref/
cp kyber-temp/ref/reduce.c           components/kyber_ref/
cp kyber-temp/ref/verify.c           components/kyber_ref/
cp kyber-temp/ref/fips202.c          components/kyber_ref/
cp kyber-temp/ref/symmetric-shake.c  components/kyber_ref/

cp kyber-temp/ref/params.h           components/kyber_ref/
cp kyber-temp/ref/kem.h              components/kyber_ref/
cp kyber-temp/ref/indcpa.h           components/kyber_ref/
cp kyber-temp/ref/polyvec.h          components/kyber_ref/
cp kyber-temp/ref/poly.h             components/kyber_ref/
cp kyber-temp/ref/ntt.h              components/kyber_ref/
cp kyber-temp/ref/cbd.h              components/kyber_ref/
cp kyber-temp/ref/reduce.h           components/kyber_ref/
cp kyber-temp/ref/verify.h           components/kyber_ref/
cp kyber-temp/ref/symmetric.h        components/kyber_ref/
cp kyber-temp/ref/fips202.h          components/kyber_ref/
cp kyber-temp/ref/api.h              components/kyber_ref/
cp kyber-temp/ref/randombytes.h      components/kyber_ref/

# Generate ESP32 randombytes implementation
echo "Generating randombytes.c for ESP32..."
cat > components/kyber_ref/randombytes.c << 'EOF'
#include <stddef.h>
#include <stdint.h>
#include "esp_random.h"

void randombytes(uint8_t *out, size_t outlen)
{
    esp_fill_random(out, outlen);
}
EOF

# Generate component CMakeLists.txt
echo "Generating component CMakeLists.txt..."
cat > components/kyber_ref/CMakeLists.txt << 'EOF'
idf_component_register(
    SRCS
        "kem.c"
        "indcpa.c"
        "polyvec.c"
        "poly.c"
        "ntt.c"
        "cbd.c"
        "reduce.c"
        "verify.c"
        "fips202.c"
        "symmetric-shake.c"
        "randombytes.c"
    INCLUDE_DIRS
        "."
    PRIV_REQUIRES
        esp_system
        freertos
)

target_compile_options(${COMPONENT_LIB} PRIVATE
    -Wno-unused-result
    -Wno-redundant-decls
)

target_compile_definitions(${COMPONENT_LIB} PUBLIC
    KYBER_K=${KYBER_K_VALUE}
)
EOF

# Clean up
echo "Cleaning up..."
rm -rf kyber-temp

echo ""
echo "Kyber ref files copied successfully!"
echo ""
echo "Next steps:"
echo "   idf.py set-target esp32"
echo "   idf.py menuconfig (for optimisation and frequency set)"
echo "   idf.py build"
echo "   idf.py flash monitor -p COMx"
echo ""
