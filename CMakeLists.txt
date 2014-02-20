cmake_minimum_required (VERSION 2.6)

project (SGStatic)
include_directories(${PROJECT_SOURCE_DIR}/external)
add_executable(SGStatic main.cpp)
add_subdirectory(external/pe-parse)
target_link_libraries(SGStatic pe-parser-library)
