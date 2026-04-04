/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef INDCPA_H
#define INDCPA_H

#include <stdint.h>
#include "params.h"
#include "polyvec.h"

#define indcpa_dec MLKEM_NAMESPACE(indcpa_dec)
int indcpa_dec(uint8_t m[MLKEM_INDCPA_MSGBYTES],
                const uint8_t c[MLKEM_INDCPA_BYTES],
                const uint8_t sk[MLKEM_INDCPA_SECRETKEYBYTES]);


#define indcpa_keypair MLKEM_NAMESPACE(indcpa_keypair)
int indcpa_keypair(uint8_t pk[MLKEM_INDCPA_PUBLICKEYBYTES],
                           uint8_t sk[MLKEM_INDCPA_SECRETKEYBYTES],
                           const uint8_t coins[MLKEM_SYMBYTES]);      
                

#define ENC_ONLY          NULL
#define ENC_CMP(result)   (&(result))   // pass address of variable

#define indcpa_enc MLKEM_NAMESPACE(indcpa_enc)
int indcpa_enc(uint8_t c[MLKEM_INDCPA_BYTES],
               const uint8_t m[MLKEM_INDCPA_MSGBYTES],
               const uint8_t pk[MLKEM_INDCPA_PUBLICKEYBYTES],
               const uint8_t coins[MLKEM_SYMBYTES],
               unsigned int *cmp_out);


#endif
