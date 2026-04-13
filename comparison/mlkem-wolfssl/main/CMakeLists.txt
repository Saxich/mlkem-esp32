idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES wolfssl
)

target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-error=cpp)
