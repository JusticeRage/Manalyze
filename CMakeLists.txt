cmake_minimum_required (VERSION 2.8)

project (manalyze)

option(GitHub "GitHub" ON)

if (WIN32)
	set(Boost_USE_STATIC_LIBS ON)
	set(Boost_USE_MULTITHREADED ON)
	set(Boost_USE_STATIC_RUNTIME ON)
endif()

find_package(Boost REQUIRED COMPONENTS regex system filesystem program_options)
if (GitHub STREQUAL ON)
	find_package(Git REQUIRED)
endif()

# Download or update external projects
if (EXISTS external/yara AND GitHub STREQUAL ON)
    message("Updating yara...")
    execute_process(COMMAND ${GIT_EXECUTABLE} --git-dir=external/yara/.git fetch)
    execute_process(COMMAND ${GIT_EXECUTABLE} --git-dir=external/yara/.git --work-tree=external/yara merge origin/master)

    message("Updating hash-library...")
    execute_process(COMMAND ${GIT_EXECUTABLE} --git-dir=external/hash-library/.git fetch)
    execute_process(COMMAND ${GIT_EXECUTABLE} --git-dir=external/hash-library/.git --work-tree=external/hash-library merge origin/master)
elseif (GitHub STREQUAL ON)
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
						${PROJECT_SOURCE_DIR}/external/yara/include
						${PROJECT_SOURCE_DIR}/plugins
						${Boost_INCLUDE_DIRS}
                   )

add_library(manape SHARED pe.cpp nt_values.cpp utils.cpp imports.cpp resources.cpp section.cpp)

add_library(manacommons SHARED color.cpp output_tree_node.cpp plugin_framework/result.cpp)

add_executable(manalyze main.cpp config_parser.cpp output_formatter.cpp dump.cpp
			   plugin_framework/dynamic_library.cpp plugin_framework/plugin_manager.cpp # Plugin system
			   plugins/yara/plugins_yara.cpp plugins/plugin_packer_detection.cpp plugins/plugin_imports.cpp plugins/plugin_resources.cpp) # Bundled plugins

if (WIN32)
			add_definitions(/D_CRT_SECURE_NO_WARNINGS) # Please don't complain about fopen()
			add_definitions(/D_WINSOCK_DEPRECATED_NO_WARNINGS) # Don't complain about ASIO's WSASocket functions either.
			set_target_properties(manape PROPERTIES COMPILE_DEFINITIONS "MANAPE_EXPORT") # Export the PE parsing functions
			set_target_properties(manacommons PROPERTIES COMPILE_DEFINITIONS "MANACOMMONS_EXPORT") # Export core functions
			set (BUILD_SHARED_LIBS FALSE)
            set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -MTd")
            set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -MTd")
            set (CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -MT")
            set (CMAKE_CXX_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -MT")

			add_definitions(-DBOOST_ALL_NO_LIB -DNOMINMAX) # Problems with autolink and MSVC + don't hide std::min and std::max.

			# Windows only plugins:
			add_library(plugin_authenticode SHARED plugins/plugin_authenticode.cpp)
			target_link_libraries(plugin_authenticode manape hash-library manacommons ${Boost_LIBRARIES})
else()
            if (CMAKE_BUILD_TYPE MATCHES "[Dd][Ee][Bb][Uu][Gg]")
                add_definitions("/D_DEBUG")
				set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
            endif()
			target_link_libraries(manalyze dl)
			set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
endif()

# VirusTotal plugin
add_library(plugin_virustotal SHARED plugins/plugin_virustotal/plugin_virustotal.cpp
									 plugins/plugin_virustotal/json_spirit/json_spirit_reader.cpp
									 plugins/plugin_virustotal/json_spirit/json_spirit_value.cpp)
target_link_libraries(plugin_virustotal manape hash-library manacommons ${Boost_LIBRARIES})

# yara dependency
add_subdirectory(external/yara)

# hash-library dependency
add_subdirectory(external/hash-library)

target_link_libraries(manape yara hash-library manacommons ${Boost_LIBRARIES})

target_link_libraries(
						manalyze
						manacommons
						manape
						yara
						hash-library
						${Boost_LIBRARIES}
                     )


