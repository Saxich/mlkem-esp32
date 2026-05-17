/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef BAKALARKA_USER_SETTINGS_H
#define BAKALARKA_USER_SETTINGS_H

/*
 * ML-KEM security level selection:
 *   2 = ML-KEM-512
 *   3 = ML-KEM-768
 *   4 = ML-KEM-1024
 */
#define MLKEM_K 3


/*
 * Optimization variant selection
 * Choose exactly ONE option.
 *
 * If none is selected, SPEED is enabled automatically.
 */

// #define SPEED
#define SPEED_DUALCORE

// #define STACK_XTREME
// #define STACK
// #define STACK_DUALCORE


/*
 * Test selection:
 *   1  = Benchmark task (speed + memory)
 *   3  = KAT test
 *   4  = KAT test + benchmark
 *   10 = Generate vectors
 */
#define TEST_TO_TURN  1


#endif