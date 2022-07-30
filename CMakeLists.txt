cmake_minimum_required(VERSION 3.10)

project(plexus)
project(${PROJECT_NAME} VERSION 1.0)

set(TESTS tests)

set(SOURCES email.cpp exec.cpp log.cpp smime.cpp ssl.cpp stun.cpp udp.cpp icmp.cpp utils.cpp main.cpp)
set(TESTS_SOURCES log.cpp smime.cpp ssl.cpp udp.cpp utils.cpp exec.cpp ./tests/utils_tests.cpp ./tests/log_tests.cpp ./tests/ssl_tests.cpp ./tests/udp_tests.cpp ./tests/smime_tests.cpp ./tests/exec_tests.cpp)

if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    add_definitions(
        -D_CRT_NO_VA_START_VALIDATION
        -D_CRT_SECURE_NO_WARNINGS
        -D_WIN32_WINNT=0x0600
        -D_WINSOCK_DEPRECATED_NO_WARNINGS
    )
endif()

find_package(Boost COMPONENTS system thread program_options unit_test_framework REQUIRED)

message(status "** Boost Version: ${Boost_VERSION}")
message(status "** Boost Include Dirs: ${Boost_INCLUDE_DIRS}")
message(status "** Boost Librariy Dirs: ${Boost_LIBRARY_DIRS}")
message(status "** Boost Libraries: ${Boost_LIBRARIES}")

include_directories(${Boost_INCLUDE_DIRS})
link_directories(${Boost_LIBRARY_DIRS})

find_package(OpenSSL REQUIRED)

message(status "** OpenSSL Version: ${OPENSSL_VERSION}")
message(status "** OpenSSL Include Dir: ${OPENSSL_INCLUDE_DIR}")
message(status "** OpenSSL Libraries: ${OPENSSL_LIBRARIES}")

add_executable(${PROJECT_NAME} ${SOURCES})
add_executable(${TESTS} ${TESTS_SOURCES})

target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto OpenSSL::SSL)
target_link_libraries(${TESTS} OpenSSL::Crypto OpenSSL::SSL)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    find_package(Threads REQUIRED)
    target_link_libraries(${PROJECT_NAME} Threads::Threads)
    target_link_libraries(${PROJECT_NAME} ${Boost_LIBRARIES})
    target_link_libraries(${TESTS} Threads::Threads)
    target_link_libraries(${TESTS} ${Boost_LIBRARIES})
endif()

install(TARGETS ${PROJECT_NAME})

enable_testing()
add_test(NAME ${TESTS} COMMAND ${TESTS} WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tests)
