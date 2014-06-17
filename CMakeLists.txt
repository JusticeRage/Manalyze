cmake_minimum_required (VERSION 2.6)

project (sgstatic)

if (WIN32)
	set(Boost_USE_STATIC_LIBS ON)
	set(Boost_USE_MULTITHREADED ON)  
	set(Boost_USE_STATIC_RUNTIME ON)
endif()
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

add_library(sgpe SHARED pe.cpp nt_values.cpp utils.cpp imports.cpp dump.cpp resources.cpp section.cpp ssdeep.cpp hashes.cpp color.cpp)

add_executable(sgstatic main.cpp color.cpp
			   plugin_framework/dynamic_library.cpp plugin_framework/plugin_manager.cpp # Plugin system
			   plugins/yara/plugins_yara.cpp plugins/plugin_packer_detection.cpp) # Bundled plugins

if (WIN32)
			add_definitions(/D_CRT_SECURE_NO_WARNINGS) # Please don't complain about fopen()
			set_target_properties(sgpe PROPERTIES COMPILE_DEFINITIONS "SGPE_EXPORT") # Export the PE parsing functions
			set (BUILD_SHARED_LIBS FALSE)
            set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -MTd")
            set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -MTd")
            set (CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -MT")
            set (CMAKE_CXX_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -MT")
			
			add_definitions(-DBOOST_ALL_NO_LIB -DNOMINMAX) # Problems with autolink and MSVC + don't hide std::min and std::max.
			
			# Windows only plugins:
			add_library(plugin_authenticode SHARED plugins/plugin_authenticode.cpp)
			target_link_libraries(plugin_authenticode sgpe hash-library ${Boost_LIBRARIES}) #TODO: Find a way to share this code.
else()
			target_link_libraries(sgstatic dl)
endif()

# yara dependency
add_subdirectory(external/yara)

# SSDeep dependency
add_subdirectory(external/ssdeep)

# hash-library dependency
add_subdirectory(external/hash-library)

target_link_libraries(sgpe yara ssdeep hash-library ${Boost_LIBRARIES})

target_link_libraries(
						sgstatic 
						sgpe
						yara
                        ssdeep
						hash-library
						${Boost_LIBRARIES}
                     )


