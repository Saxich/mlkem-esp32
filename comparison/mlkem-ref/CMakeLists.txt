cmake_minimum_required(VERSION 3.16)

# Kyber security level: 2=Kyber512, 3=Kyber768, 4=Kyber1024
set(KYBER_K_VALUE 3)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

project(kyber_ref)
