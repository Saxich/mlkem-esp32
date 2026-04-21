/*
 * ESP32 random number generation wrapper
 *
 * Copyright (C) 2026 Michal Saxa
 * Licensing: GPL-3.0-or-later (see LICENSE and CREDITS.md)
 *
 * Provides esp_randombytes() used by ML-KEM KeyGen and Encaps to obtain
 * random bytes. Internally uses the PSA Crypto RNG subsystem
 * (CTR_DRBG(AES-256) seeded from the ESP32 hardware TRNG), initialized
 * lazily on first call.
 *
 * NOTE: For maximum entropy quality, ensure Wi-Fi or Bluetooth is
 * initialized before any call to esp_randombytes(). The ESP32 hardware
 * TRNG (WDEV_RND_REG) operates without RF but with reduced entropy
 * sourcing. If neither RF subsystem is available, entropy can be
 * supplemented by calling bootloader_random_enable() prior to use.
 * See: ESP32 Technical Reference Manual, Section 18 — Random Number Generator
 *   https://www.espressif.com/sites/default/files/documentation/esp32_technical_reference_manual_en.pdf
 *
 * See CREDITS.md for full attribution.
 */

#include "psa/crypto.h"
#include <assert.h>

static int psa_initialized = 0;

static void esp_randombytes_init(void) {
    if (psa_initialized) return;
    psa_status_t status = psa_crypto_init();
    assert(status == PSA_SUCCESS);
    psa_initialized = 1;
}

void esp_randombytes(uint8_t *out, size_t len) {
    esp_randombytes_init();
    psa_generate_random(out, len);
}