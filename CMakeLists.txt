cmake_minimum_required (VERSION 2.6)

find_package(Boost REQUIRED)

project (SGStatic)
include_directories(
			${PROJECT_SOURCE_DIR}/external
			${Boost_INCLUDE_DIRS}
                   )
add_executable(SGStatic main.cpp pe.cpp nt_values.cpp)

# pe-parse depencency
add_subdirectory(external/pe-parse)

# yara dependency
add_subdirectory(external/yara)

target_link_libraries(SGStatic 
			       pe-parser-library 
			       yara
                     )


