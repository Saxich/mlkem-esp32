idf_component_register(
    SRCS
        "kem.c"
        "indcpa.c"
        "poly.c"
        "polyvec.c"
        "ntt.c"
       
        "cbd.c"
        "verify.c"
        "randombytes.c"
        "matrix.c"
    INCLUDE_DIRS
        "."
        "../../main"
    PRIV_REQUIRES
        bootloader_support
        test_time
        fips202
        esp_rom
        # esp_wifi
        # bt
)