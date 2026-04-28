# SPDX-License-Identifier: Apache-2.0
# Main component CMakeLists.txt

# Collect all ML-KEM source files
set(MLKEM_SRCS
    "../mlkem/cbd.c"
    "../mlkem/indcpa.c"
    "../mlkem/kem.c"
    "../mlkem/matacc.c"
    "../mlkem/ntt.c"
    "../mlkem/poly.c"
    "../mlkem/polyvec.c"
    "../mlkem/reduce.c"
    "../mlkem/symmetric-shake.c"
    "../mlkem/verify.c"
)

# Collect FIPS202 (Keccak/SHA3) source files
set(FIPS202_SRCS
    "../fips202/fips202.c"
    "../fips202/keccakf1600.c"
)

# HAL source files
set(HAL_SRCS
    "../hal/randombytes.c"
)

# Main application
set(MAIN_SRCS
    "main.c"
)

# Register the component
idf_component_register(
    SRCS ${MAIN_SRCS} ${MLKEM_SRCS} ${FIPS202_SRCS} ${HAL_SRCS} 
    INCLUDE_DIRS "." "../mlkem" "../fips202" "../hal"
)


# Derive parameter set from K
math(EXPR MLK_PARAMETER_SET "${MLKEM_K} * 256")

target_compile_definitions(${COMPONENT_LIB} PUBLIC
    MLKEM_K=${MLKEM_K}
    MLK_CONFIG_PARAMETER_SET=${MLK_PARAMETER_SET}
    RISCV
    __riscv
)

target_compile_options(${COMPONENT_LIB} PRIVATE
    -Wall
    -Wextra
)
