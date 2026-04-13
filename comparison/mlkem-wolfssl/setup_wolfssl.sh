#!/bin/bash
# Setup wolfSSL for ESP32 with correct FreeRTOS includes (ESP-IDF v6.0 compatible)
# Works on Linux and macOS

echo "========================================"
echo " wolfSSL Setup for ESP32 (ESP-IDF v6.0)"
echo "========================================"
echo ""

# Create components directory if it doesn't exist
mkdir -p components

# Remove old wolfssl if exists
if [ -d "components/wolfssl" ]; then
    echo "Removing old wolfSSL..."
    rm -rf components/wolfssl
fi

# Clone specific stable version
echo "Downloading wolfSSL v5.8.4-stable..."
cd components || exit 1
git clone --depth 1 --branch v5.8.4-stable https://github.com/wolfSSL/wolfssl.git

if [ $? -ne 0 ]; then
    echo "ERROR: Failed to clone wolfSSL!"
    cd ..
    exit 1
fi

cd wolfssl || exit 1

# === PATCH settings.h to use correct ESP-IDF v5+ FreeRTOS paths ===
SETTINGS_FILE="wolfssl/wolfcrypt/settings.h"

if [ ! -f "$SETTINGS_FILE" ]; then
    echo "ERROR: $SETTINGS_FILE not found! Something went wrong with cloning."
    cd ../../..
    exit 1
fi

echo "Patching $SETTINGS_FILE for ESP-IDF FreeRTOS compatibility..."

# Use sed to replace the old includes with the correct ones
# This works on both GNU sed (Linux) and BSD sed (macOS)
sed -i.bak \
    -e 's|#include "FreeRTOS.h"|#include "freertos/FreeRTOS.h"|' \
    -e 's|#include <task.h>|#include "freertos/task.h"|' \
    "$SETTINGS_FILE"

# Remove backup file created by BSD sed (macOS)
[ -f "${SETTINGS_FILE}.bak" ] && rm "${SETTINGS_FILE}.bak"

echo "Patched: Replaced outdated FreeRTOS includes with ESP-IDF v5+ paths"

# === Create proper CMakeLists.txt ===
echo ""
echo "Creating CMakeLists.txt for wolfSSL component..."
cat > CMakeLists.txt << 'EOF'
file(GLOB WOLFSSL_SOURCES
    wolfcrypt/src/*.c
    src/*.c
    wolfcrypt/src/port/Espressif/*.c
)

list(FILTER WOLFSSL_SOURCES EXCLUDE REGEX ".*test\.c$")

idf_component_register(
    SRCS ${WOLFSSL_SOURCES}
    INCLUDE_DIRS "." "wolfssl" "../../main"
    PRIV_REQUIRES freertos esp_hal_clock
)

target_compile_options(${COMPONENT_LIB} PRIVATE
    -DWOLFSSL_USER_SETTINGS
    -DWOLFSSL_ESPWROOM32
    -DWOLFSSL_ESPIDF
    -DHAVE_KYBER
    -DWOLFSSL_WC_KYBER
    -DWOLFSSL_EXPERIMENTAL_SETTINGS
    -DWC_NO_HARDEN
    -DNO_WOLFSSL_ESP32_CRYPT_AES
    -DNO_WOLFSSL_ESP32_CRYPT_HASH
    -w
    -Wno-error=cpp
)

target_link_libraries(${COMPONENT_LIB} PUBLIC m)
EOF

cd ../..

echo ""
echo "========================================"
echo " Setup Complete Successfully!"
echo "========================================"
echo ""
echo "wolfSSL v5.8.4 downloaded and patched for ESP-IDF v5+"
echo "Location: components/wolfssl"
echo ""
echo "Applied fix in settings.h:"
echo "   #include \"FreeRTOS.h\"   →   #include \"freertos/FreeRTOS.h\""
echo "   #include <task.h>         →   #include \"freertos/task.h\""
echo ""
echo "Next steps:"
echo "   idf.py set-target esp32"
echo "   idf.py build"
echo "   idf.py flash monitor -p COMx"
echo ""
echo "Enjoy ML-KEM on your ESP32!"
echo ""