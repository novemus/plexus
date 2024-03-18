message("***** plexus *****")

cmake_minimum_required(VERSION 3.10)

project(plexus)
project(${PROJECT_NAME} VERSION 2.2)

set(Boost_USE_STATIC_LIBS ON)

add_subdirectory(wormhole)

include(GNUInstallDirs)

set(SOURCES utils.cpp exec.cpp smime.cpp udp.cpp tcp.cpp email.cpp stun.cpp binder.cpp plexus.cpp main.cpp wormhole/logger.cpp wormhole/tubus/channel.cpp)
add_definitions(-DBOOST_BIND_GLOBAL_PLACEHOLDERS)

if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /std:c++17")
    add_definitions(
        -D_CRT_NO_VA_START_VALIDATION
        -D_CRT_SECURE_NO_WARNINGS
        -D_WIN32_WINNT=0x0600
        -D_WINSOCK_DEPRECATED_NO_WARNINGS
        -D_SILENCE_CXX17_ALLOCATOR_VOID_DEPRECATION_WARNING
        -D_SILENCE_CXX17_OLD_ALLOCATOR_MEMBERS_DEPRECATION_WARNING
        -DBOOST_COROUTINES_NO_DEPRECATION_WARNING
    )
endif()

if(BUILD_TESTING)
    find_package(Boost REQUIRED COMPONENTS system thread regex filesystem program_options coroutine unit_test_framework)
else()
    find_package(Boost REQUIRED COMPONENTS system thread regex filesystem program_options coroutine)
endif()

message("* Boost Version: ${Boost_VERSION}")
message("* Boost Include Dirs: ${Boost_INCLUDE_DIRS}")
message("* Boost Librariy Dirs: ${Boost_LIBRARY_DIRS}")
message("* Boost Libraries: ${Boost_LIBRARIES}")

include_directories(${Boost_INCLUDE_DIRS})
include_directories(wormhole)
link_directories(${Boost_LIBRARY_DIRS})

find_package(OpenSSL REQUIRED)

message("* OpenSSL Version: ${OPENSSL_VERSION}")
message("* OpenSSL Include Dir: ${OPENSSL_INCLUDE_DIR}")
message("* OpenSSL Libraries: ${OPENSSL_LIBRARIES}")

add_executable(${PROJECT_NAME} ${SOURCES})

set_target_properties(${PROJECT_NAME} PROPERTIES DEBUG_POSTFIX "d")

target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto OpenSSL::SSL)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU" OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -Wall -Wno-unused-const-variable -fvisibility=hidden")
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    find_package(Threads REQUIRED)
    target_link_libraries(${PROJECT_NAME} Threads::Threads)
    target_link_libraries(${PROJECT_NAME} Boost::system Boost::thread Boost::regex Boost::filesystem Boost::program_options Boost::coroutine)
endif()

if(APPLE AND Boost_USE_STATIC_LIBS)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden")
    cmake_policy(PUSH)
    cmake_policy(SET CMP0074 NEW)
    find_package(ICU REQUIRED COMPONENTS data)
    cmake_policy(POP)
    get_filename_component(ICU_LIBDATA_DIR "${ICU_DATA_LIBRARY}" DIRECTORY)
    set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "-L${ICU_LIBDATA_DIR}")
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION ${PROJECT_NAME}-${${PROJECT_NAME}_VERSION}/${CMAKE_INSTALL_BINDIR})
    install(FILES $<TARGET_PDB_FILE:${PROJECT_NAME}> CONFIGURATIONS "Debug" "RelWithDebInfo" DESTINATION ${PROJECT_NAME}-${${PROJECT_NAME}_VERSION}/${CMAKE_INSTALL_BINDIR})
elseif(CMAKE_INSTALL_PREFIX MATCHES "^(/usr)|(/usr/local)$")
    install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
else()
    install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION ${PROJECT_NAME}/${${PROJECT_NAME}_VERSION}/${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_TESTING)
    set(TESTS_NAME plexus_ut)
    set(TESTS_SOURCES utils.cpp smime.cpp udp.cpp tcp.cpp exec.cpp wormhole/logger.cpp
                    ./tests/utils_tests.cpp
                    ./tests/ssl_tests.cpp
                    ./tests/udp_tests.cpp
                    ./tests/tcp_tests.cpp
                    ./tests/smime_tests.cpp
                    ./tests/exec_tests.cpp)

    add_executable(${TESTS_NAME} ${TESTS_SOURCES})
    set_target_properties(${TESTS_NAME} PROPERTIES DEBUG_POSTFIX "d")
    target_link_libraries(${TESTS_NAME} OpenSSL::Crypto OpenSSL::SSL)

    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU" OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        target_link_libraries(${TESTS_NAME} Threads::Threads)
        target_link_libraries(${TESTS_NAME} Boost::system Boost::thread Boost::regex Boost::filesystem Boost::coroutine Boost::unit_test_framework)
    endif()

    if(APPLE AND Boost_USE_STATIC_LIBS)
        set_target_properties(${TESTS_NAME} PROPERTIES LINK_FLAGS "-L${ICU_LIBDATA_DIR}")
    endif()

    enable_testing()
    add_test(NAME ${TESTS_NAME} COMMAND ${TESTS_NAME} WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tests)
endif()

message("***** plexus done *****")
