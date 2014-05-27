cmake_minimum_required (VERSION 2.6)

project (sgstatic)

#set(Boost_USE_STATIC_LIBS ON)
#set(Boost_USE_MULTITHREADED ON)  
#set(Boost_USE_STATIC_RUNTIME ON)
find_package(Boost REQUIRED COMPONENTS regex system filesystem program_options)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/bin)


include_directories(
						${PROJECT_SOURCE_DIR}
						${PROJECT_SOURCE_DIR}/external
						${Boost_INCLUDE_DIRS}
                   )

# Shared library containing the PE parsing code.
add_library(sgpe SHARED pe.cpp pe.cpp nt_values.cpp utils.cpp imports.cpp dump.cpp resources.cpp section.cpp
			yara_wrapper.cpp color.cpp ssdeep.cpp hashes.cpp)

add_executable(sgstatic main.cpp yara_wrapper.cpp ssdeep.cpp hashes.cpp color.cpp
			   plugin_framework/dynamic_library.cpp plugin_framework/plugin_manager.cpp # Plugin system
			   plugins/yara/plugins_yara.cpp plugins/plugin_packer_detection.cpp) # Bundled plugins

if (WIN32)
			add_definitions(/D_CRT_SECURE_NO_WARNINGS) # Please stop complaining about fopen()
			set (BUILD_SHARED_LIBS FALSE)
            #set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -MDd")
            #set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -MDd")
            #set (CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -MD")
            #set (CMAKE_CXX_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -MD")
			
			add_definitions(-DBOOST_ALL_NO_LIB -DNOMINMAX -DBOOST_PROGRAM_OPTIONS_DYN_LINK) # Problems with autolink and MSVC + don't hide std::min and std::max.

			set_target_properties(sgpe PROPERTIES COMPILE_DEFINITIONS "SGPE_EXPORT")
			
			# Windows only plugins:
			add_library(plugin_authenticode SHARED plugins/plugin_authenticode.cpp)
			target_link_libraries(plugin_authenticode sgpe hash-library ${Boost_LIBRARIES}) #TODO: Find a way to share this code.
else()
			target_link_libraries(sgstatic dl)

            if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64") 
                add_definitions(-fPIC) 
            endif()
endif()

# yara dependency
add_subdirectory(external/yara)

# SSDeep dependency
add_subdirectory(external/ssdeep)

# hash-library dependency
add_subdirectory(external/hash-library)

target_link_libraries(
						sgpe 
						yara
                        ssdeep
						hash-library
						${Boost_LIBRARIES}
                     )

target_link_libraries(
						sgstatic 
						sgpe
						yara
						${Boost_LIBRARIES}
                     )


