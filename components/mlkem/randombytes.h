/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

#include <stddef.h>
#include <stdint.h>


void esp_randombytes(uint8_t *out, size_t len);

// #if (TEST_TO_TURN == 6)
// void esp_randombytes_opt(uint8_t *out, size_t len);
// void esp_randombytes_wifi(uint8_t *out, size_t len) ;
// void esp_randombytes_bt(uint8_t *out, size_t len) ;
// #endif



#endif