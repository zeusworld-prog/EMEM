cmake_minimum_required(VERSION 3.16)
project(mmap C)

set(CMAKE_C_STANDARD 99)

add_executable(mmap mkmemefs.c)