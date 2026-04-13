/*
 * ESP32 hardware TRNG wrapper
 *
 * Licensing: GPL-3.0-or-later (see LICENSE and CREDITS.md)
 *
 * Based on fsegatz/kybesp32 (MIT License)
 *   https://github.com/fsegatz/kybesp32
 *
 * NOTE: For maximum entropy quality, ensure Wi-Fi or BT is initialized
 * before calling this function. ESP32 hardware RNG (WDEV_RND_REG)
 * operates without RF but with reduced entropy sourcing.
 * See: ESP32 Technical Reference Manual, Section 18 — Random Number Generator
 *   https://www.espressif.com/sites/default/files/documentation/esp32_technical_reference_manual_en.pdf
 * 
 * See CREDITS.md for full attribution.
 */

#include "esp_random.h"

void esp_randombytes(uint8_t *out, size_t len) 
{   
    esp_fill_random(out, len);
}

