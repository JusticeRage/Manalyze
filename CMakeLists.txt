cmake_minimum_required (VERSION 3.12)

project (manalyze LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(GNUInstallDirs)

set(MANALYZE_INSTALL_CONFIG_SUBDIR "${CMAKE_INSTALL_SYSCONFDIR}/manalyze")
set(MANALYZE_INSTALL_DATA_SUBDIR "${CMAKE_INSTALL_DATADIR}/manalyze")
set(MANALYZE_INSTALL_PLUGIN_SUBDIR "${CMAKE_INSTALL_LIBDIR}/manalyze/plugins")

if (IS_ABSOLUTE "${MANALYZE_INSTALL_CONFIG_SUBDIR}")
    set(MANALYZE_INSTALL_CONFIG_DIR "${MANALYZE_INSTALL_CONFIG_SUBDIR}")
else()
    set(MANALYZE_INSTALL_CONFIG_DIR "${CMAKE_INSTALL_PREFIX}/${MANALYZE_INSTALL_CONFIG_SUBDIR}")
endif()

if (IS_ABSOLUTE "${MANALYZE_INSTALL_DATA_SUBDIR}")
    set(MANALYZE_INSTALL_DATA_DIR "${MANALYZE_INSTALL_DATA_SUBDIR}")
else()
    set(MANALYZE_INSTALL_DATA_DIR "${CMAKE_INSTALL_PREFIX}/${MANALYZE_INSTALL_DATA_SUBDIR}")
endif()

if (IS_ABSOLUTE "${MANALYZE_INSTALL_PLUGIN_SUBDIR}")
    set(MANALYZE_INSTALL_PLUGIN_DIR "${MANALYZE_INSTALL_PLUGIN_SUBDIR}")
else()
    set(MANALYZE_INSTALL_PLUGIN_DIR "${CMAKE_INSTALL_PREFIX}/${MANALYZE_INSTALL_PLUGIN_SUBDIR}")
endif()

option(GitHub "Allow checking out third-party projects from GitHub" ON)
option(Tests "Generate unit tests" OFF)
option(MANALYZE_BUILD_VIRUSTOTAL "Build VirusTotal plugin (requires Boost::system)" ON)

if (WIN32)
    set(Boost_USE_STATIC_LIBS ON)
    set(Boost_USE_MULTITHREADED ON)
    set(Boost_USE_STATIC_RUNTIME ON)
endif()

if (APPLE)
    set(CMAKE_MACOSX_RPATH 1)
endif()

if (GitHub MATCHES [Oo][Nn])
    find_package(Git REQUIRED)
endif()
set(MANALYZE_BOOST_REQUIRED_COMPONENTS "")
if (MANALYZE_BUILD_VIRUSTOTAL)
    list(APPEND MANALYZE_BOOST_REQUIRED_COMPONENTS system)
endif()
if (Tests MATCHES [Oo][Nn])
    list(APPEND MANALYZE_BOOST_REQUIRED_COMPONENTS unit_test_framework)
endif()
if (MANALYZE_BOOST_REQUIRED_COMPONENTS)
    if (POLICY CMP0167)
        cmake_policy(PUSH)
        cmake_policy(SET CMP0167 NEW)
        find_package(Boost CONFIG QUIET COMPONENTS ${MANALYZE_BOOST_REQUIRED_COMPONENTS})
        cmake_policy(POP)
    endif()
    if (NOT Boost_FOUND)
        if (POLICY CMP0167)
            cmake_policy(PUSH)
            cmake_policy(SET CMP0167 OLD)
        endif()
        find_package(Boost QUIET COMPONENTS ${MANALYZE_BOOST_REQUIRED_COMPONENTS})
        if (POLICY CMP0167)
            cmake_policy(POP)
        endif()
    endif()
else()
    find_package(Boost QUIET)
endif()

set(MANALYZE_BOOST_TEST_LIBS "")
if (Tests MATCHES [Oo][Nn])
    if (NOT Boost_UNIT_TEST_FRAMEWORK_FOUND)
        message(FATAL_ERROR "Boost unit_test_framework is required to build tests.")
    endif()
    list(APPEND MANALYZE_BOOST_TEST_LIBS Boost::unit_test_framework)
endif()

set(MANALYZE_BOOST_VT_LIBS "")
if (MANALYZE_BUILD_VIRUSTOTAL)
    if (NOT Boost_SYSTEM_FOUND)
        message(WARNING "Boost::system not found; VirusTotal plugin will not be built.")
        set(MANALYZE_BUILD_VIRUSTOTAL OFF)
    else()
        list(APPEND MANALYZE_BOOST_VT_LIBS Boost::system)
    endif()
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
add_library(manape SHARED manape/pe.cpp manape/nt_values.cpp manape/utils.cpp manape/imports.cpp manape/resources.cpp manape/section.cpp manape/imported_library.cpp manape/ordinals.cpp)

add_library(manacommons SHARED manacommons/color.cpp manacommons/output_tree_node.cpp manacommons/escape.cpp manacommons/base64.cpp manacommons/plugin_framework/result.cpp manacommons/paths.cpp)
target_compile_definitions(manacommons PRIVATE
    MANALYZE_INSTALL_CONFIG_DIR="${MANALYZE_INSTALL_CONFIG_DIR}"
    MANALYZE_INSTALL_DATA_DIR="${MANALYZE_INSTALL_DATA_DIR}"
    MANALYZE_INSTALL_PLUGIN_DIR="${MANALYZE_INSTALL_PLUGIN_DIR}"
    MANALYZE_INSTALL_CONFIG_SUBDIR="${MANALYZE_INSTALL_CONFIG_SUBDIR}"
    MANALYZE_INSTALL_DATA_SUBDIR="${MANALYZE_INSTALL_DATA_SUBDIR}"
    MANALYZE_INSTALL_PLUGIN_SUBDIR="${MANALYZE_INSTALL_PLUGIN_SUBDIR}"
)
target_link_libraries(manacommons)

add_executable(manalyze src/main.cpp src/cli.cpp src/config_parser.cpp src/output_formatter.cpp src/dump.cpp src/import_hash.cpp
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
            target_link_libraries(plugin_authenticode manape hash-library manacommons yara)
else()
            string (REGEX MATCH "BSD" IS_BSD ${CMAKE_SYSTEM_NAME}) # Detect if we are compiling on a BSD system.

            if (CMAKE_BUILD_TYPE MATCHES "[Dd][Ee][Bb][Uu][Gg]")
                add_compile_definitions(_DEBUG)
                set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
                if (Tests MATCHES [Oo][Nn]) # Add coverage option if unit tests were requested.
                    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --coverage")
                    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage")
                endif()
            endif()

            if (NOT IS_BSD) # No need to link against dl on BSD.
                target_link_libraries(manalyze dl)
            endif()
            set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-rpath='$ORIGIN'")

            # Compile the *nix authenticode plugin if OpenSSL was found.
            if (OPENSSL_FOUND)
                add_library(plugin_authenticode SHARED plugins/plugin_authenticode/plugin_authenticode_openssl.cpp 
                                                       plugins/plugin_authenticode/commons.cpp
                                                       plugins/plugin_authenticode/asn1.cpp
                                                       plugins/plugin_authenticode/pe_authenticode_digest.cpp)
                target_link_libraries(plugin_authenticode manacommons manape hash-library yara ${OPENSSL_LIBRARIES})
            endif()
endif()

# VirusTotal plugin
if (MANALYZE_BUILD_VIRUSTOTAL)
    add_library(plugin_virustotal SHARED plugins/plugin_virustotal/plugin_virustotal.cpp
                                         plugins/plugin_virustotal/json_spirit/json_spirit_reader.cpp
                                         plugins/plugin_virustotal/json_spirit/json_spirit_value.cpp)
    target_link_libraries(plugin_virustotal manape hash-library manacommons ${MANALYZE_BOOST_VT_LIBS})
    if (OPENSSL_FOUND)
        target_link_libraries(plugin_virustotal ${OPENSSL_LIBRARIES})
    endif()
endif()

# yara dependency
add_subdirectory(external/yara)

# hash-library dependency
add_subdirectory(external/hash-library)

if (Tests MATCHES [Oo][Nn])
    add_subdirectory(test)
endif()

target_link_libraries(manape manacommons)

target_link_libraries(
                        manalyze
                        manacommons
                        manape
                        yara
                        hash-library
                     )

# make install command for linux machines:
if ("${CMAKE_SYSTEM}" MATCHES "Linux")

    # Copy binaries
    install(TARGETS manalyze manacommons manape
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

    # Copy the yara_rules folder to /etc/manalyze.
    install(DIRECTORY bin/yara_rules 
            DESTINATION ${MANALYZE_INSTALL_DATA_SUBDIR})

    # Copy the plugins to the standard libdir location.
    if (TARGET plugin_virustotal)
        install(TARGETS plugin_virustotal
                LIBRARY DESTINATION ${MANALYZE_INSTALL_PLUGIN_SUBDIR})
    endif()
    if (TARGET plugin_authenticode)
        install(TARGETS plugin_authenticode
                LIBRARY DESTINATION ${MANALYZE_INSTALL_PLUGIN_SUBDIR})
    endif()

    # Copy the configuration file template.
    install(FILES bin/manalyze.conf
            DESTINATION ${MANALYZE_INSTALL_CONFIG_SUBDIR})
endif()

# Uninstall target using install_manifest.txt
if (NOT TARGET uninstall)
    add_custom_target(uninstall
        COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/uninstall.cmake
        COMMENT "Removing installed files listed in install_manifest.txt"
    )
endif()
