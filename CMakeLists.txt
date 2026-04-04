
# CMakeLists in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.5)

# add_compile_options(-O3)
# add_compile_options(-fmax-errors=1)

# pre generevoanie .s
# add_compile_options(-save-temps)
# add_compile_options(-Wno-address)
# add_compile_options(-Wno-tautological-compare)


include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(bakalarka)