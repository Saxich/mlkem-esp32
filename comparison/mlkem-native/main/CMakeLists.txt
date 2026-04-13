idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES mlkem_native esp_system
)

target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-unused-result)
