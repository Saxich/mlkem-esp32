idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES kem esp_system
)

target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-unused-result)
