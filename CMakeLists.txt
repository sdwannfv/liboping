cmake_minimum_required(VERSION 3.19)
project(oping C)

set(CMAKE_C_STANDARD 99)

add_executable(oping liboping.c oping.c config.h oping.h)
target_link_libraries(oping m)