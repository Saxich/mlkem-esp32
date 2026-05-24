/* reduce.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 *
 * Original source: wolfSSL/wolfssl — wc_mlkem_poly.c
 *   https://github.com/wolfSSL/wolfssl
 * Modified by Michal Saxa, 2026 — reimplemented as header-only macros;
 *   MLKEM_BARRETT_RED: replaced truncation with explicit round-to-nearest
 *   correction to fix KAT test failures caused by floor rounding;
 *   both reduction macros use inline Xtensa assembly wrappers (xt_mul.h).
 * 
 * See CREDITS.md for full attribution.
 */

#ifndef REDUCE_H
#define REDUCE_H

#include <stdint.h>
#include "params.h"
#include "xt_mul.h"

#define MONT -1044 // 2^16 mod q
#define QINV -3327 // q^-1 mod 2^16


#define MLKEM_BARRETT_RED(a) ({ \
    int32_t _a = (int32_t)(a); \
    int32_t _t = XT_MUL16S((int16_t)(_a >> 5), (int16_t)MLKEM_V); \
    _t += (1 << 25) >> 5; \
    _t  = _t >> 21; \
    (int16_t)(_a - XT_MUL16S((int16_t)_t, (int16_t)MLKEM_Q)); \
})

#define MLKEM_MONT_RED(a) ({ \
    int32_t _a = (a); \
    int16_t _u = (int16_t)_a; \
    int32_t _t = XT_MUL16S(_u, (int16_t)MLKEM_QINV); \
    _t = XT_MUL16S((int16_t)_t, (int16_t)MLKEM_Q); \
    (int16_t)((_a - _t) >> 16); \
})


#endif
