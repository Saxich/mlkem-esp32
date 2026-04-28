cmake_minimum_required(VERSION 3.16)

# Manually set parameter (2, 3, or 4)
set(MLKEM_K 4)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

project(mlkem_c_embedded)
