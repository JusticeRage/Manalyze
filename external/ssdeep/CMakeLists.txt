cmake_minimum_required (VERSION 2.6)
project (ssdeep)

add_library(ssdeep fuzzy.cpp edit_dist.cpp)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64") 
    add_definitions(-fPIC) 
endif()

