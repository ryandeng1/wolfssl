# CMakeList.txt
#
# Copyright (C) 2006-2020 wolfSSL Inc.
#
# This file is part of wolfSSL. (formerly known as CyaSSL)
#
# Usage:
# $ mkdir build
# $ cd build
# $ cmake ..
# $ cmake --build .

# To build library only and not build examples and test apps use:
# $ cmake .. -DBUILD_TESTS=NO

# To build with debugging use:
# $ cmake .. -DCMAKE_BUILD_TYPE=Debug

####################################################
# Project
####################################################

cmake_minimum_required(VERSION 3.0)
project(wolfssl C CXX)

####################################################
# Dependencies
####################################################

find_package(Threads)

# N-for-1 start
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
cmake_minimum_required(VERSION 2.6)
project("mbed TLS" C CXX)

find_package(Threads REQUIRED)
find_package(rpclib REQUIRED)
find_path(RELIC_INCLUDE_DIR relic/relic.h)
find_library(RELIC_LIBRARY NAMES relic REQUIRED)

include (FindPackageHandleStandardArgs)
find_package_handle_standard_args(RELIC DEFAULT_MSG RELIC_INCLUDE_DIR RELIC_LIBRARY)

if(RELIC_FOUND)
        set(RELIC_LIBRARIES ${RELIC_LIBRARY})
        set(RELIC_INCLUDE_DIRS ${RELIC_INCLUDE_DIR})
endif()

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
find_package(OpenSSL REQUIRED)
find_package(GMP REQUIRED)
find_package(Boost REQUIRED COMPONENTS system)
include_directories(${OPENSSL_INCLUDE_DIR} ${Boost_INCLUDE_DIRS} ${GMP_INCLUDE_DIR})


SET(CMAKE_C_FLAGS "-pthread -march=native -maes -mrdseed -lssl -lcrypto")

set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -std=c++11")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -ggdb -O0")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -O3")


# rpc client/server
# find_package(rpclib REQUIRED)
# include_directories(include/ /usr/local/include/)
# link_directories(/usr/local/lib/)
# add_executable(server library/rpc/rpc_server.cpp)
# target_link_libraries(server rpc ${OPENSSL_LIBRARIES} ${Boost_LIBRARIES} ${GMP_LIBRARIES})

# Building client
# add_executable(client library/rpc/rpc_client.cpp)
# target_link_libraries(client rpc ${OPENSSL_LIBRARIES} ${Boost_LIBRARIES} ${GMP_LIBRARIES})

# N-for-1 end

####################################################
# Compiler
####################################################
# Let CMake choose default compiler

if(APPLE)
    # Silence ranlib warning "has no symbols"
    set(CMAKE_C_ARCHIVE_CREATE   "<CMAKE_AR> Scr <TARGET> <LINK_FLAGS> <OBJECTS>")
    set(CMAKE_CXX_ARCHIVE_CREATE "<CMAKE_AR> Scr <TARGET> <LINK_FLAGS> <OBJECTS>")
    set(CMAKE_C_ARCHIVE_FINISH   "<CMAKE_RANLIB> -no_warning_for_no_symbols -c <TARGET>")
    set(CMAKE_CXX_ARCHIVE_FINISH "<CMAKE_RANLIB> -no_warning_for_no_symbols -c <TARGET>")
endif()

####################################################
# Cross Compile Example
####################################################

#set(CMAKE_SYSTEM_NAME Linux)
#set(CMAKE_SYSTEM_PROCESSOR arm)
#set(CMAKE_C_COMPILER "/opt/arm-linux-musleabihf-cross/bin/arm-linux-musleabihf-gcc")
#set(CMAKE_CXX_COMPILER "/opt/arm-linux-musleabihf-cross/bin/arm-linux-musleabihf-g++")
#set(CMAKE_SYSROOT "/opt/arm-linux-musleabihf-cross/arm-linux-musleabihf/")
# Example for setting CFLAGS
#set(CMAKE_C_FLAGS "-std=gnu89 ${CMAKE_C_FLAGS}")
# Example for map file and custom linker script
#set(CMAKE_EXE_LINKER_FLAGS " -Xlinker -Map=output.map -T\"${CMAKE_CURRENT_SOURCE_DIR}/linker.ld\"")

####################################################
# Build Options
####################################################

option(BUILD_TESTS "Build test applications" YES)

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/wolfssl/options.h")
    # Copy generated ./options.h
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/wolfssl/options.h 
                   ${CMAKE_CURRENT_SOURCE_DIR}/user_settings.h)
else()
   # Use template
   configure_file(${CMAKE_CURRENT_SOURCE_DIR}/wolfssl/options.h.in 
                  ${CMAKE_CURRENT_SOURCE_DIR}/user_settings.h)
endif()

add_definitions(-DWOLFSSL_USER_SETTINGS)
add_definitions(-DWOLFSSL_IGNORE_FILE_WARN)
if(CMAKE_USE_PTHREADS_INIT)
  add_definitions(-DHAVE_PTHREAD)
endif()

####################################################
# Library Target
####################################################

add_library(wolfssl
    src/bio.c
    src/crl.c
    src/internal.c
    src/keys.c
    src/ocsp.c
    src/sniffer.c
    src/ssl.c
    src/tls.c
    src/tls13.c
    src/wolfio.c
    wolfcrypt/src/aes_external.cpp
    wolfcrypt/src/aes.c
    wolfcrypt/src/arc4.c
    wolfcrypt/src/asm.c
    wolfcrypt/src/asn.c
    wolfcrypt/src/async.c
    wolfcrypt/src/blake2b.c
    wolfcrypt/src/blake2s.c
    wolfcrypt/src/camellia.c
    wolfcrypt/src/chacha.c
    wolfcrypt/src/chacha20_poly1305.c
    wolfcrypt/src/cmac.c
    wolfcrypt/src/coding.c
    wolfcrypt/src/compress.c
    wolfcrypt/src/cpuid.c
    wolfcrypt/src/cryptocb.c
    wolfcrypt/src/curve25519.c
    wolfcrypt/src/curve448.c
    wolfcrypt/src/des3.c
    wolfcrypt/src/dh.c
    wolfcrypt/src/dsa.c
    wolfcrypt/src/ecc.c
    wolfcrypt/src/ecc_fp.c
    wolfcrypt/src/ed25519.c
    wolfcrypt/src/ed448.c
    wolfcrypt/src/error.c
    wolfcrypt/src/evp.c
    wolfcrypt/src/fe_448.c
    wolfcrypt/src/fe_low_mem.c
    wolfcrypt/src/fe_operations.c
    wolfcrypt/src/fips.c
    wolfcrypt/src/fips_test.c
    wolfcrypt/src/ge_448.c
    wolfcrypt/src/ge_low_mem.c
    wolfcrypt/src/ge_operations.c
    wolfcrypt/src/hash.c
    wolfcrypt/src/hc128.c
    wolfcrypt/src/hmac.c
    wolfcrypt/src/idea.c
    wolfcrypt/src/integer.c
    wolfcrypt/src/logging.c
    wolfcrypt/src/md2.c
    wolfcrypt/src/md4.c
    wolfcrypt/src/md5.c
    wolfcrypt/src/memory.c
    wolfcrypt/src/misc.c
    wolfcrypt/src/pkcs12.c
    wolfcrypt/src/pkcs7.c
    wolfcrypt/src/poly1305.c
    wolfcrypt/src/pwdbased.c
    wolfcrypt/src/rabbit.c
    wolfcrypt/src/random.c
    wolfcrypt/src/ripemd.c
    wolfcrypt/src/rsa.c
    wolfcrypt/src/selftest.c
    wolfcrypt/src/sha.c
    wolfcrypt/src/sha256.c
    wolfcrypt/src/sha3.c
    wolfcrypt/src/sha512.c
    wolfcrypt/src/signature.c
    wolfcrypt/src/sp_arm32.c
    wolfcrypt/src/sp_arm64.c
    wolfcrypt/src/sp_armthumb.c
    wolfcrypt/src/sp_c32.c
    wolfcrypt/src/sp_c64.c
    wolfcrypt/src/sp_cortexm.c
    wolfcrypt/src/sp_dsp32.c
    wolfcrypt/src/sp_int.c
    wolfcrypt/src/sp_x86_64.c
    wolfcrypt/src/srp.c
    wolfcrypt/src/tfm.c
    wolfcrypt/src/wc_dsp.c
    wolfcrypt/src/wc_encrypt.c
    wolfcrypt/src/wc_pkcs11.c
    wolfcrypt/src/wc_port.c
    wolfcrypt/src/wolfcrypt_first.c
    wolfcrypt/src/wolfcrypt_last.c
    wolfcrypt/src/wolfevent.c
    wolfcrypt/src/wolfmath.c
)

####################################################
# Include Directories
####################################################

target_include_directories(wolfssl
    PUBLIC
        $<INSTALL_INTERFACE:wolfssl>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/wolfssl>
        ${CMAKE_CURRENT_SOURCE_DIR}/. # Needed for user_settings.h to be visible
)

####################################################
# Link Libraries
####################################################

if(WIN32)
    # For Windows link ws2_32
    target_link_libraries(wolfssl PUBLIC $<$<PLATFORM_ID:Windows>:ws2_32>)
else()
    # DH requires math (m) library
    target_link_libraries(wolfssl PUBLIC m)
endif()

####################################################
# Tests and Examples
####################################################

# Optionally build example and test applications
if(BUILD_TESTS)
    # Build wolfCrypt test
    add_executable(wolfcrypttest
        ${CMAKE_CURRENT_SOURCE_DIR}/wolfcrypt/test/test.c)
    target_link_libraries(wolfcrypttest wolfssl)

    # Build wolfCrypt benchmark
    add_executable(wolfcryptbench
        ${CMAKE_CURRENT_SOURCE_DIR}/wolfcrypt/benchmark/benchmark.c)
    target_link_libraries(wolfcryptbench wolfssl)

    # Build wolfSSL Client example
    add_executable(client
        ${CMAKE_CURRENT_SOURCE_DIR}/examples/client/client.c)
    target_link_libraries(client wolfssl)

    # Build wolfSSL Server example
    add_executable(server
        ${CMAKE_CURRENT_SOURCE_DIR}/examples/server/server.c)
    target_link_libraries(server wolfssl)

    # Build Echo Client Example
    add_executable(echoclient
        ${CMAKE_CURRENT_SOURCE_DIR}/examples/echoclient/echoclient.c)
    target_link_libraries(echoclient wolfssl)

    # Build Echo Server Example
    add_executable(echoserver
        ${CMAKE_CURRENT_SOURCE_DIR}/examples/echoserver/echoserver.c)
    target_link_libraries(echoserver wolfssl)

    # Build TLS benchmark example
    add_executable(tls_bench
        ${CMAKE_CURRENT_SOURCE_DIR}/examples/benchmark/tls_bench.c)
    target_link_libraries(tls_bench wolfssl)
    target_link_libraries(tls_bench Threads::Threads)

    # Build Unit Tests
    add_executable(unit_test
        tests/api.c
        tests/hash.c
        tests/srp.c
        tests/suites.c
        tests/unit.c
        examples/server/server.c
        examples/client/client.c
    )
    target_compile_options(unit_test PUBLIC "-DNO_MAIN_DRIVER")
    target_link_libraries(unit_test wolfssl)
    target_link_libraries(unit_test Threads::Threads)
endif()

# TODO: Add install() for library, headers and test applications
