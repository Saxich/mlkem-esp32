idf_component_register(
    SRCS
        "fips202.c"
        "symmetric-shake.c"
    INCLUDE_DIRS
        "."
        "../../main" #user_settings.h
        "../mlkem"  #params.h
    PRIV_REQUIRES
        bootloader_support
)