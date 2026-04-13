/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

#include <stddef.h>
#include <stdint.h>


void esp_randombytes(uint8_t *out, size_t len);



#endif