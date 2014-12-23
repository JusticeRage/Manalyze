cmake_minimum_required (VERSION 2.8)

project (sgstatic)

if (WIN32)
	set(Boost_USE_STATIC_LIBS ON)
	set(Boost_USE_MULTITHREADED ON)  
	set(Boost_USE_STATIC_RUNTIME ON)
endif()

find_package(Boost REQUIRED COMPONENTS regex system filesystem program_options)
find_package(Git REQUIRED)

# Download or update external projects
if (EXISTS external/yara)
    message("Updating yara...")
    execute_process(COMMAND ${GIT_EXECUTABLE} --git-dir=external/yara/.git fetch)
    execute_process(COMMAND ${GIT_EXECUTABLE} --git-dir=external/yara/.git --work-tree=external/yara merge origin/master)

    message("Updating hash-library...")
    execute_process(COMMAND ${GIT_EXECUTABLE} --git-dir=external/hash-library/.git fetch)
    execute_process(COMMAND ${GIT_EXECUTABLE} --git-dir=external/hash-library/.git --work-tree=external/hash-library merge origin/master)
else()
    message("Checking out yara...")
    execute_process(COMMAND ${GIT_EXECUTABLE} clone https://github.com/JusticeRage/yara.git external/yara)
    message("Checking out hash-library...")
    execute_process(COMMAND ${GIT_EXECUTABLE} clone https://github.com/JusticeRage/hash-library.git external/hash-library)
endif()

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/bin)


include_directories(
						${PROJECT_SOURCE_DIR}
						${PROJECT_SOURCE_DIR}/external
						${PROJECT_SOURCE_DIR}/plugins
						${Boost_INCLUDE_DIRS}
                   )

add_library(sgpe SHARED pe.cpp nt_values.cpp utils.cpp imports.cpp resources.cpp section.cpp color.cpp)

add_executable(sgstatic main.cpp color.cpp config_parser.cpp output_formatter.cpp dump.cpp
			   plugin_framework/dynamic_library.cpp plugin_framework/plugin_manager.cpp # Plugin system
			   plugins/yara/plugins_yara.cpp plugins/plugin_packer_detection.cpp plugins/plugin_imports.cpp plugins/plugin_resources.cpp) # Bundled plugins

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
			target_link_libraries(plugin_authenticode sgpe hash-library ${Boost_LIBRARIES})
else()
			target_link_libraries(sgstatic dl)
endif()

# VirusTotal plugin
add_library(plugin_virustotal SHARED plugins/plugin_virustotal/plugin_virustotal.cpp 
									 color.cpp # TODO: Share color.cpp
									 plugins/plugin_virustotal/json_spirit/json_spirit_reader.cpp 
									 plugins/plugin_virustotal/json_spirit/json_spirit_value.cpp)
target_link_libraries(plugin_virustotal sgpe hash-library ${Boost_LIBRARIES})

# yara dependency
add_subdirectory(external/yara)

# hash-library dependency
add_subdirectory(external/hash-library)

target_link_libraries(sgpe yara hash-library ${Boost_LIBRARIES})

target_link_libraries(
						sgstatic 
						sgpe
						yara
						hash-library
						${Boost_LIBRARIES}
                     )


