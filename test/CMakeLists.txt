cmake_minimum_required (VERSION 3.12)
project (manalyze-tests LANGUAGES CXX)
include_directories(${PROJECT_SOURCE_DIR}/include)
if (NOT APPLE)
	find_package(Threads)
endif()

add_executable(manalyze-tests fixtures.cpp hash-library.cpp pe.cpp imports.cpp resources.cpp section.cpp escape.cpp encoding.cpp base64.cpp utils.cpp cli.cpp config_parser.cpp output_formatter.cpp
                              ../src/import_hash.cpp ../src/cli.cpp ../src/config_parser.cpp ../src/output_formatter.cpp)

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
