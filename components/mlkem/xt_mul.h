/*
 * Inline Xtensa assembly wrappers for 16-bit multiply instructions
 *
 * Copyright (C) 2026 Michal Saxa
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef _XTENSA_XT_MUL_H
#define _XTENSA_XT_MUL_H

#ifdef __XTENSA__

static inline __attribute__((always_inline)) int32_t XT_MUL16S(int16_t s, int16_t t) {
    int32_t res;
    __asm__ __volatile__("mul16s %0, %1, %2" : "=r"(res) : "r"(s), "r"(t));
    return res;
}

static inline __attribute__((always_inline)) uint32_t XT_MUL16U(uint16_t s, uint16_t t) {
    uint32_t res;
    __asm__ __volatile__("mul16u %0, %1, %2" : "=r"(res) : "r"(s), "r"(t));
    return res;
}

static inline __attribute__((always_inline)) int32_t XT_MULL(int32_t s, int32_t t) {
    int32_t res;
    __asm__ __volatile__("mull %0, %1, %2" : "=r"(res) : "r"(s), "r"(t));
    return res;
}

static inline __attribute__((always_inline)) uint32_t XT_MULUH(uint32_t s, uint32_t t) {
    uint32_t res;
    __asm__ __volatile__("muluh %0, %1, %2" : "=r"(res) : "r"(s), "r"(t));
    return res;
}

static inline __attribute__((always_inline)) int32_t XT_MULSH(int32_t s, int32_t t) {
    int32_t res;
    __asm__ __volatile__("mulsh %0, %1, %2" : "=r"(res) : "r"(s), "r"(t));
    return res;
}

#else
/* Fallback pre non-Xtensa */
#define XT_MUL16S(s, t) ((int32_t)(int16_t)(s) * (int32_t)(int16_t)(t))
#define XT_MUL16U(s, t) ((uint32_t)(uint16_t)(s) * (uint32_t)(uint16_t)(t))
#define XT_MULL(s, t)   ((int32_t)(s) * (int32_t)(t))
#define XT_MULUH(s, t)  ((uint32_t)(((uint64_t)(s) * (uint64_t)(t)) >> 32))
#define XT_MULSH(s, t)  ((int32_t)(((int64_t)(s) * (int64_t)(t)) >> 32))
#endif /* __XTENSA__ */

#endif /* _XTENSA_XT_MUL_H */