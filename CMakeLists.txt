cmake_minimum_required(VERSION 3.26)
project(killer_trash)

set(CMAKE_CXX_STANDARD 20)

include_directories(src)

add_executable(killer_trash src/main.cpp
        src/core/bundle.cpp
        src/core/bundle.h
        src/core/target.cpp
        src/core/target.h
        src/utils/process.cpp
        src/utils/process.h
        src/utils/crypto_crc32.cpp
        src/utils/crypto_crc32.h)
