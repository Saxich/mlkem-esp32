cmake_minimum_required(VERSION 3.16)

# All compile definitions must be set before the IDF include.

# Kyber security level: 2=Kyber512, 3=Kyber768, 4=Kyber1024
add_compile_definitions("KYBER_K=3")

# Dual-core acceleration for indcpa operations (indcpa.c):
#   0 = single-core (standard)
#   1 = split work across both ESP32 cores using FreeRTOS tasks
add_compile_definitions("INDCPA_KEYPAIR_DUAL=1")
add_compile_definitions("INDCPA_ENC_DUAL=1")
add_compile_definitions("INDCPA_DEC_DUAL=1")

# Kyber variant:
#   standard — SHAKE128/SHAKE256/SHA3-256/SHA3-512 (fips202): leave line below commented out
#   90s      — AES-256-CTR + SHA-256/SHA-512 (aes256ctr + sha2): uncomment line below
# NOTE: kem.h uses #ifdef KYBER_90S, so defining it as 0 still triggers the 90s name.
#       The flag must be either defined (90s) or absent (standard) — not set to 0.
#add_compile_definitions("KYBER_90S")

# Hardware-accelerated SHA via mbedtls (symmetric.h, only used when KYBER_90S=1):
#   0 = software SHA-256/SHA-512 (sha2 component)
#   1 = mbedtls_sha256 / mbedtls_sha512
add_compile_definitions("SHA_ACC=0")

# Hardware-accelerated AES via mbedtls (aes256ctr, only used when KYBER_90S=1):
#   0 = software AES-256-CTR
#   1 = hardware AES-256-CTR
add_compile_definitions("AES_ACC=0")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

project(kybesp32)
