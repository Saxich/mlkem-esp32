/*
 * FreeRTOS task stack size configuration for ML-KEM operations on ESP32
 *
 * Copyright (C) 2026 Michal Saxa
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

// API task size, modify according your implementation needs
#if MLKEM_K == 2
    #define MLKEM_API_STACK_SIZE 20000
#elif MLKEM_K == 3
    #define MLKEM_API_STACK_SIZE 25000
#elif MLKEM_K == 4
    #define MLKEM_API_STACK_SIZE 40000 
#else
    #error "Unsupported MLKEM_K value"
#endif


// same for both main and suport indcpa task
#define MLKEM_TASK_PRIORITY 10

#define MLKEM_MAIN_CORE 0
#define MLKEM_SUPPORT_CORE (!MLKEM_MAIN_CORE)



#if defined(SPEED_DUALCORE)
// 1345(overflow), 1360(heap je 1768), 1400(1768), 1418(1832), 1477(1896), 1506(1896), 1564 (1960), 1630 (2024), 2048 (2408)
    //1496 = 1360*1,10 margin
    #define INDCPA_STACK_KEYPAIR 1496  
// 1350 (overflow), 1360 (heap je 1768), 1400(1768), 1500(1896), 1600(1960), 1760(2152), 2048(2408) 
    // 1496 = 1360*1,10 margin
    #define INDCPA_STACK_ENC 1496
// 525 (overflow), 550
// indcpa_dec support task vie ist na 550, v praxi to nevytvori rozdiel, 
// indcpa_dec je v ramci mlkem dacaps volany pred indpca_enc, ktory spotrebuje 1496, dec je tak v jeho tieni a vo vysledku spotreba celeho procesu decaps musi byt spotreba enc
    #define INDCPA_STACK_DEC INDCPA_STACK_ENC
#endif


#if defined(STACK_DUALCORE)
// 1580(overflow), 1590(1960), 1634(2024), 1748(2152), 1772(2152), 2048(2408)
    // 1748 = 1590*1,10 margin
    #define INDCPA_STACK_KEYPAIR 1748
// 1580(overflow), 1590(1960), 1634(2024), 1748(2152), 1772(2152), 2048(2408)
    // 1748 = 1590*1,10 margin
    #define INDCPA_STACK_ENC 1748  
    #define INDCPA_STACK_DEC INDCPA_STACK_ENC
#endif
