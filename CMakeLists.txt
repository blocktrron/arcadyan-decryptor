cmake_minimum_required(VERSION 3.28)
project(arcadyan_decryptor C)

set(CMAKE_C_STANDARD 23)

#Find and link the OpenSSL library
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
link_libraries(${OPENSSL_LIBRARIES})

add_executable(arcadyan_decryptor main.c)
