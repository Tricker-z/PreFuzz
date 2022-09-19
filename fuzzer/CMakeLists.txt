cmake_minimum_required(VERSION 3.0)
project(PreFuzzer)

set(CMAKE_C_STANDARD 99)

add_executable(fuzz fuzz.c)
