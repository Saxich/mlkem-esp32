cmake_minimum_required(VERSION 3.16)

# ML-KEM security level: 512, 768, or 1024.
set(MLKEM_PARAMETER_SET 1024)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

project(mlkem_native)
