idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES kyber_ref esp_system
)

target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-unused-result)
