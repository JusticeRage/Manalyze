cmake_minimum_required (VERSION 2.6)

project (sgstatic)

set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)  
set(Boost_USE_STATIC_RUNTIME ON)
find_package(Boost REQUIRED COMPONENTS regex system filesystem)

include_directories(
						${PROJECT_SOURCE_DIR}/external
						${Boost_INCLUDE_DIRS}
                   )

add_executable(sgstatic main.cpp pe.cpp nt_values.cpp utils.cpp imports.cpp dump.cpp resources.cpp)

if (WIN32)
			add_definitions(/D_CRT_SECURE_NO_WARNINGS) # Please don't complain about fopen()
			set (BUILD_SHARED_LIBS FALSE)
            set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -MTd")
            set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -MTd")
            set (CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -MT")
            set (CMAKE_CXX_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -MT")
			
			add_definitions(-DBOOST_ALL_NO_LIB) # Problems with autolink and MSVC
endif()

# yara dependency
add_subdirectory(external/yara)

target_link_libraries(
						sgstatic 
						yara
						${Boost_LIBRARIES}
                     )


