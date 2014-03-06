cmake_minimum_required (VERSION 2.6)

find_package(Boost REQUIRED)

project (SGStatic)
include_directories(
						${PROJECT_SOURCE_DIR}/external
						${Boost_INCLUDE_DIRS}
                   )

add_executable(SGStatic main.cpp pe.cpp nt_values.cpp)

set (BUILD_SHARED_LIBS FALSE) # should force the libraries to be static

if (WIN32)
			add_definitions(/D_CRT_SECURE_NO_WARNINGS) # Please don't complain about fopen()
            set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -MTd")
            set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -MTd")
            set (CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -MT")
            set (CMAKE_CXX_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -MT")
endif()

# yara dependency
add_subdirectory(external/yara)

target_link_libraries(
						SGStatic 
						yara
                     )


