cmake_minimum_required (VERSION 3.12)
project (manalyze-tests LANGUAGES CXX)
include_directories(${PROJECT_SOURCE_DIR}/include)
find_package(Threads REQUIRED)

add_executable(manalyze-tests fixtures.cpp hash-library.cpp pe.cpp imports.cpp resources.cpp section.cpp escape.cpp encoding.cpp base64.cpp utils.cpp cli.cpp
                              ../src/import_hash.cpp ../src/cli.cpp)

target_link_libraries(
						manalyze-tests
						manacommons
						manape
						yara
						hash-library
						${MANALYZE_BOOST_TEST_LIBS}
                        Threads::Threads
                     )

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
