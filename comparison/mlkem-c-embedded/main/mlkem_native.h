// SPDX-License-Identifier: Apache-2.0
#ifndef MLKEM_NATIVE_H
#define MLKEM_NATIVE_H

// This header provides a unified interface to the ML-KEM implementation
// regardless of which parameter set is selected via Kconfig

#include "kem.h"

// The kem.h header already provides:
// - crypto_kem_keypair(pk, sk)
// - crypto_kem_enc(ct, ss, pk)
// - crypto_kem_dec(ss, ct, sk)
// - CRYPTO_PUBLICKEYBYTES
// - CRYPTO_SECRETKEYBYTES
// - CRYPTO_CIPHERTEXTBYTES
// - CRYPTO_BYTES

// MLK_CONFIG_PARAMETER_SET is defined via CMake based on Kconfig selection
// and is used in main.c for display purposes

#endif // MLKEM_NATIVE_H
