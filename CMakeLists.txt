cmake_minimum_required(VERSION 3.10)

project(plexus)
project(${PROJECT_NAME} VERSION 2.1)

set(TESTS_NAME plexus_ut)
set(WORMHOLE_DIR wormhole)

add_subdirectory(${WORMHOLE_DIR})

set(SOURCES utils.cpp exec.cpp smime.cpp ssl.cpp udp.cpp tcp.cpp raw.cpp email.cpp stun.cpp puncher.cpp main.cpp wormhole/logger.cpp)
set(TESTS_SOURCES utils.cpp smime.cpp ssl.cpp udp.cpp tcp.cpp raw.cpp exec.cpp wormhole/logger.cpp
                 ./tests/utils_tests.cpp
                 ./tests/ssl_tests.cpp
                 ./tests/udp_tests.cpp
                 ./tests/tcp_tests.cpp
                 ./tests/smime_tests.cpp
                 ./tests/exec_tests.cpp
                 ./tests/icmp_tests.cpp)

add_definitions(-DBOOST_BIND_GLOBAL_PLACEHOLDERS)

if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    add_definitions(
        -D_CRT_NO_VA_START_VALIDATION
        -D_CRT_SECURE_NO_WARNINGS
        -D_WIN32_WINNT=0x0600
        -D_WINSOCK_DEPRECATED_NO_WARNINGS
    )
endif()

find_package(Boost COMPONENTS system thread program_options regex filesystem unit_test_framework REQUIRED)

message(status "** Boost Version: ${Boost_VERSION}")
message(status "** Boost Include Dirs: ${Boost_INCLUDE_DIRS}")
message(status "** Boost Librariy Dirs: ${Boost_LIBRARY_DIRS}")
message(status "** Boost Libraries: ${Boost_LIBRARIES}")

include_directories(${Boost_INCLUDE_DIRS})
include_directories(${WORMHOLE_DIR})
link_directories(${Boost_LIBRARY_DIRS})

find_package(OpenSSL REQUIRED)

message(status "** OpenSSL Version: ${OPENSSL_VERSION}")
message(status "** OpenSSL Include Dir: ${OPENSSL_INCLUDE_DIR}")
message(status "** OpenSSL Libraries: ${OPENSSL_LIBRARIES}")

add_executable(${PROJECT_NAME} ${SOURCES})
add_executable(${TESTS_NAME} ${TESTS_SOURCES})

target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto OpenSSL::SSL)
target_link_libraries(${TESTS_NAME} OpenSSL::Crypto OpenSSL::SSL)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    find_package(Threads REQUIRED)
    target_link_libraries(${PROJECT_NAME} Threads::Threads)
    target_link_libraries(${PROJECT_NAME} ${Boost_LIBRARIES})
    target_link_libraries(${TESTS_NAME} Threads::Threads)
    target_link_libraries(${TESTS_NAME} ${Boost_LIBRARIES})
endif()

install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin)

enable_testing()
add_test(NAME ${TESTS_NAME} COMMAND ${TESTS_NAME} WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tests)
