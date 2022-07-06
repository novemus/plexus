cmake_minimum_required(VERSION 3.10)

project(plexus)

project(${PROJECT_NAME} VERSION 1.0)

set(SOURCES email.cpp exec.cpp log.cpp smime.cpp ssl.cpp stun.cpp udp.cpp utils.cpp main.cpp)

if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    add_definitions(
        -D_CRT_NO_VA_START_VALIDATION
        -D_CRT_SECURE_NO_WARNINGS
        -D_WIN32_WINNT=0x0600
        -D_WINSOCK_DEPRECATED_NO_WARNINGS
    )
endif()

find_package(Boost COMPONENTS system thread program_options REQUIRED)

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

target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto OpenSSL::SSL)