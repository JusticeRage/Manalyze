cmake_minimum_required (VERSION 3.12)
project (manalyze-tests LANGUAGES CXX)
include_directories(${PROJECT_SOURCE_DIR}/include)
if (NOT APPLE)
	find_package(Threads)
endif()

add_executable(manalyze-tests fixtures.cpp hash-library.cpp pe.cpp imports.cpp resources.cpp section.cpp escape.cpp encoding.cpp base64.cpp utils.cpp cli.cpp config_parser.cpp output_formatter.cpp windows_macro_compat.cpp work_budget.cpp
                               ../src/import_hash.cpp ../src/cli.cpp ../src/config_parser.cpp ../src/output_formatter.cpp)
add_dependencies(manalyze-tests manalyze)

add_library(manape-parser-test-static STATIC ${MANAPE_SOURCES})
target_compile_definitions(manape-parser-test-static
	PUBLIC MANAPE_STATIC
	PRIVATE MANALYZE_PARSER_TESTING)
target_link_libraries(manape-parser-test-static PUBLIC manacommons)

add_executable(manalyze-parser-tests parser_amplification.cpp fixtures.cpp)
target_compile_definitions(manalyze-parser-tests PRIVATE
	MANAPE_STATIC MANALYZE_PARSER_TESTING)
target_link_libraries(manalyze-parser-tests
	manape-parser-test-static manacommons ${MANALYZE_BOOST_TEST_LIBS})

add_executable(parser-amplification-benchmark parser_amplification_benchmark.cpp)
target_link_libraries(parser-amplification-benchmark manape)
if (Threads_FOUND)
	target_link_libraries(manalyze-parser-tests Threads::Threads)
endif()

if (OPENSSL_FOUND AND NOT WIN32)
	target_sources(manalyze-tests PRIVATE plugin_authenticode.cpp)
	add_dependencies(manalyze-tests plugin_authenticode)
	target_link_libraries(manalyze-tests plugin_authenticode OpenSSL::Crypto)
endif()

target_link_libraries(
						manalyze-tests
						manacommons
						manape
						yara
						hash-library
						${MANALYZE_BOOST_TEST_LIBS}
                     )

if (Threads_FOUND)
	target_link_libraries(manalyze-tests Threads::Threads)
endif()

if (WIN32)
            set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -MTd")
            set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -MTd")
            set (CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -MT")
            set (CMAKE_CXX_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -MT")
			set_target_properties(hash-library PROPERTIES COMPILE_DEFINITIONS "HASHLIB_EXPORT")
else()
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
        add_definitions(-fPIC)
    endif()
endif()
