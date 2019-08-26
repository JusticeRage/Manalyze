cmake_minimum_required (VERSION 2.8)

project (manalyze)

option(GitHub "Allow checking out third-party projects from GitHub" ON)
option(Tests "Generate unit tests" OFF)

if (WIN32)
    set(Boost_USE_STATIC_LIBS ON)
    set(Boost_USE_MULTITHREADED ON)
    set(Boost_USE_STATIC_RUNTIME ON)
endif()

if (GitHub MATCHES [Oo][Nn])
    find_package(Git REQUIRED)
endif()
if (NOT Tests MATCHES [Oo][Nn])
    find_package(Boost REQUIRED COMPONENTS regex system filesystem program_options)
else()
    find_package(Boost REQUIRED COMPONENTS regex system filesystem program_options unit_test_framework)
endif()

find_package(OpenSSL)
if (OPENSSL_FOUND)
    add_definitions(-DWITH_OPENSSL) # Enable OpenSSL if it was found.
else()
    message("Building without OpenSSL.")
endif()

# Download or update external projects
if (EXISTS external/yara AND GitHub MATCHES [Oo][Nn])
    message("Updating yara...")
    execute_process(COMMAND ${GIT_EXECUTABLE} --git-dir=external/yara/.git fetch)
    execute_process(COMMAND ${GIT_EXECUTABLE} --git-dir=external/yara/.git --work-tree=external/yara merge origin/master)

    message("Updating hash-library...")
    execute_process(COMMAND ${GIT_EXECUTABLE} --git-dir=external/hash-library/.git fetch)
    execute_process(COMMAND ${GIT_EXECUTABLE} --git-dir=external/hash-library/.git --work-tree=external/hash-library merge origin/master)
elseif (GitHub MATCHES [Oo][Nn])
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
                        ${PROJECT_SOURCE_DIR}/include
                        ${PROJECT_SOURCE_DIR}/external
                        ${PROJECT_SOURCE_DIR}/external/yara/include
                        ${PROJECT_SOURCE_DIR}/plugins
                        ${Boost_INCLUDE_DIRS}
                   )
# Explicitly add OpenSSL include directories if it has been found.
if(OPENSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIR})
endif()

add_definitions(-DWITH_MANACOMMONS) # Use functions from manacommons.
add_library(manape SHARED manape/pe.cpp manape/nt_values.cpp manape/utils.cpp manape/imports.cpp manape/resources.cpp manape/section.cpp manape/imported_library.cpp)

add_library(manacommons SHARED manacommons/color.cpp manacommons/output_tree_node.cpp manacommons/escape.cpp manacommons/base64.cpp manacommons/plugin_framework/result.cpp)

add_executable(manalyze src/main.cpp src/config_parser.cpp src/output_formatter.cpp src/dump.cpp src/import_hash.cpp
               src/plugin_framework/dynamic_library.cpp src/plugin_framework/plugin_manager.cpp # Plugin system
               plugins/plugins_yara.cpp plugins/plugin_packer_detection.cpp plugins/plugin_imports.cpp plugins/plugin_resources.cpp plugins/plugin_mitigation.cpp plugins/plugin_overlay.cpp) # Bundled plugins

if (WIN32)
            add_definitions(/D_CRT_SECURE_NO_WARNINGS) # Please don't complain about fopen()
            add_definitions(/D_WINSOCK_DEPRECATED_NO_WARNINGS) # Don't complain about ASIO's WSASocket functions either.
            add_definitions(/D_SCL_SECURE_NO_WARNINGS) # And finally don't complain about std::_Copy_impl used by Karma.
			add_definitions(/bigobj) # Needed by JSON Spirit Reader with VS2019
            set_target_properties(manape PROPERTIES COMPILE_DEFINITIONS "MANAPE_EXPORT") # Export the PE parsing functions
            set_target_properties(manacommons PROPERTIES COMPILE_DEFINITIONS "MANACOMMONS_EXPORT") # Export core functions
            set (BUILD_SHARED_LIBS FALSE)
            set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -MTd")
            set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -MTd")
            set (CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -MT")
            set (CMAKE_CXX_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -MT")

            add_definitions(-DBOOST_ALL_NO_LIB -DNOMINMAX) # Problems with autolink and MSVC + don't hide std::min and std::max.

            # Windows only plugins:
            add_library(plugin_authenticode SHARED plugins/plugin_authenticode/plugin_authenticode.cpp
                                                   plugins/plugin_authenticode/commons.cpp)
            target_link_libraries(plugin_authenticode manape hash-library manacommons yara ${Boost_LIBRARIES})
else()
            string (REGEX MATCH "BSD" IS_BSD ${CMAKE_SYSTEM_NAME}) # Detect if we are compiling on a BSD system.

            if (CMAKE_BUILD_TYPE MATCHES "[Dd][Ee][Bb][Uu][Gg]")
                add_definitions("/D_DEBUG")
                set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
                if (Tests MATCHES [Oo][Nn]) # Add coverage option if unit tests were requested.
                    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --coverage")
                    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage")
                endif()
            endif()

            if (NOT IS_BSD) # No need to link against dl on BSD.
                target_link_libraries(manalyze dl)
            endif()
            set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
            
            # Compile the *nix authenticode plugin if OpenSSL was found.
            if (OPENSSL_FOUND)
                add_library(plugin_authenticode SHARED plugins/plugin_authenticode/plugin_authenticode_openssl.cpp 
                                                       plugins/plugin_authenticode/commons.cpp
                                                       plugins/plugin_authenticode/asn1.cpp
                                                       plugins/plugin_authenticode/pe_authenticode_digest.cpp)
                target_link_libraries(plugin_authenticode ${OPENSSL_LIBRARIES})
            endif()
endif()

# VirusTotal plugin
add_library(plugin_virustotal SHARED plugins/plugin_virustotal/plugin_virustotal.cpp
                                     plugins/plugin_virustotal/json_spirit/json_spirit_reader.cpp
                                     plugins/plugin_virustotal/json_spirit/json_spirit_value.cpp)
target_link_libraries(plugin_virustotal manape hash-library manacommons ${Boost_LIBRARIES})
if (OPENSSL_FOUND)
    target_link_libraries(plugin_virustotal ${OPENSSL_LIBRARIES})
endif()

# yara dependency
add_subdirectory(external/yara)

# hash-library dependency
add_subdirectory(external/hash-library)

if (Tests MATCHES [Oo][Nn])
    add_subdirectory(test)
endif()

target_link_libraries(manape manacommons ${Boost_LIBRARIES})

target_link_libraries(
                        manalyze
                        manacommons
                        manape
                        yara
                        hash-library
                        ${Boost_LIBRARIES}
                     )

# make install command for linux machines:
if ("${CMAKE_SYSTEM}" MATCHES "Linux")

    # Copy binaries
    install(TARGETS manalyze manacommons manape
            RUNTIME DESTINATION /usr/local/bin
            LIBRARY DESTINATION /usr/local/lib
            ARCHIVE DESTINATION /usr/local/lib/static)

    # Copy the yara_rules folder to /etc/manalyze.
    install(DIRECTORY bin/yara_rules 
            DESTINATION /etc/manalyze)

    # Copy the plugins to /etc/manalyze.
    install(DIRECTORY bin/
            DESTINATION /etc/manalyze
            FILES_MATCHING PATTERN "libplugin_*.so")

    # Copy the configuration file template.
    install(FILES bin/manalyze.conf
            DESTINATION /etc/manalyze)

    # Run ldconfig.
    execute_process(COMMAND ldconfig)
endif()
