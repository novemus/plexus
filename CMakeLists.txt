message("***** plexus *****")

cmake_minimum_required(VERSION 3.16)

project(plexus)
project(${PROJECT_NAME} VERSION 3.1)

add_subdirectory(wormhole)

include(GNUInstallDirs)

set(PLEXUS_STATIC ${PROJECT_NAME}_static)
set(PLEXUS_SHARED ${PROJECT_NAME}_shared)

add_definitions(-DBOOST_BIND_GLOBAL_PLACEHOLDERS)

set(HEADERS plexus.h)
if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    set(PLEXUS_INSTALL_LIBDIR ${PROJECT_NAME}-${${PROJECT_NAME}_VERSION}/${CMAKE_INSTALL_LIBDIR})
    set(PLEXUS_INSTALL_CMAKEDIR ${PROJECT_NAME}-${${PROJECT_NAME}_VERSION}/${CMAKE_INSTALL_LIBDIR}/cmake)
    set(PLEXUS_INSTALL_INCLUDEDIR ${PROJECT_NAME}-${${PROJECT_NAME}_VERSION}/${CMAKE_INSTALL_INCLUDEDIR})
    set(CMAKE_STATIC_LIBRARY_SUFFIX "-static.lib")
    set(CMAKE_STATIC_LIBRARY_PREFIX "lib")
    set(CMAKE_SHARED_LIBRARY_PREFIX "lib")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /std:c++17")
    set(CMAKE_MAP_IMPORTED_CONFIG_RELWITHDEBINFO RELEASE)
    add_definitions(
        -D_CRT_NO_VA_START_VALIDATION
        -D_CRT_SECURE_NO_WARNINGS
        -D_WIN32_WINNT=0x0600
        -D_WINSOCK_DEPRECATED_NO_WARNINGS
        -D_SILENCE_CXX17_ALLOCATOR_VOID_DEPRECATION_WARNING
        -D_SILENCE_CXX17_OLD_ALLOCATOR_MEMBERS_DEPRECATION_WARNING
        -DBOOST_COROUTINES_NO_DEPRECATION_WARNING
    )
else()
    if(CMAKE_INSTALL_PREFIX MATCHES "^(/usr)|(/usr/local)$")
        if(APPLE)
            set(PLEXUS_INSTALL_LIBDIR ${CMAKE_INSTALL_LIBDIR})
            set(PLEXUS_INSTALL_CMAKEDIR ${CMAKE_INSTALL_LIBDIR}/cmake)
            set(PLEXUS_INSTALL_INCLUDEDIR ${CMAKE_INSTALL_INCLUDEDIR})
        elseif(CMAKE_INSTALL_LIBDIR MATCHES ${CMAKE_LIBRARY_ARCHITECTURE} OR CMAKE_INSTALL_PREFIX MATCHES "/usr/local")
            set(PLEXUS_INSTALL_LIBDIR ${CMAKE_INSTALL_LIBDIR}/${PROJECT_NAME}-${${PROJECT_NAME}_VERSION})
            set(PLEXUS_INSTALL_CMAKEDIR ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}-${${PROJECT_NAME}_VERSION})
            set(PLEXUS_INSTALL_INCLUDEDIR ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}-${${PROJECT_NAME}_VERSION})
        else()
            set(PLEXUS_INSTALL_LIBDIR ${CMAKE_INSTALL_LIBDIR}/${CMAKE_LIBRARY_ARCHITECTURE}/${PROJECT_NAME}-${${PROJECT_NAME}_VERSION})
            set(PLEXUS_INSTALL_CMAKEDIR ${CMAKE_INSTALL_LIBDIR}/${CMAKE_LIBRARY_ARCHITECTURE}/cmake/${PROJECT_NAME}-${${PROJECT_NAME}_VERSION})
            set(PLEXUS_INSTALL_INCLUDEDIR ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}-${${PROJECT_NAME}_VERSION})
        endif()
    else()
        set(PLEXUS_INSTALL_LIBDIR ${PROJECT_NAME}/${${PROJECT_NAME}_VERSION}/${CMAKE_INSTALL_LIBDIR})
        set(PLEXUS_INSTALL_CMAKEDIR ${PROJECT_NAME}/${${PROJECT_NAME}_VERSION}/${CMAKE_INSTALL_LIBDIR}/cmake)
        set(PLEXUS_INSTALL_INCLUDEDIR ${PROJECT_NAME}/${${PROJECT_NAME}_VERSION}/${CMAKE_INSTALL_INCLUDEDIR})
    endif()
endif()

string(REGEX REPLACE "[^/\\]+" ".." PLEXUS_INSTALL_CMAKEDIR_REVERSE ${PLEXUS_INSTALL_CMAKEDIR})

include_directories(wormhole)

set(Boost_USE_STATIC_LIBS ON)

if(BUILD_TESTING)
    find_package(Boost REQUIRED COMPONENTS system program_options coroutine unit_test_framework)
else()
    find_package(Boost REQUIRED COMPONENTS system program_options coroutine)
endif()

message("* Boost Version: ${Boost_VERSION}")
message("* Boost Include Dirs: ${Boost_INCLUDE_DIRS}")
message("* Boost Librariy Dirs: ${Boost_LIBRARY_DIRS}")
message("* Boost Libraries: ${Boost_LIBRARIES}")

include_directories(${Boost_INCLUDE_DIRS})
link_directories(${Boost_LIBRARY_DIRS})

find_package(OpenSSL REQUIRED)

message("* OpenSSL Version: ${OPENSSL_VERSION}")
message("* OpenSSL Include Dir: ${OPENSSL_INCLUDE_DIR}")
message("* OpenSSL Libraries: ${OPENSSL_LIBRARIES}")

include_directories(${OPENSSL_INCLUDE_DIR})

find_package(PkgConfig REQUIRED)

pkg_search_module(opendht REQUIRED IMPORTED_TARGET opendht>=3.2)
message("* opendht Include Dir: ${opendht_INCLUDEDIR}")
message("* opendht Lib Dir: ${opendht_LIBDIR}")
include_directories(${opendht_INCLUDE_DIR})
link_directories(${opendht_LIBDIR})

pkg_search_module(JsonCpp REQUIRED IMPORTED_TARGET jsoncpp)
message("* JsonCpp Include Dir: ${JsonCpp_INCLUDEDIR}")
message("* JsonCpp Lib Dir: ${JsonCpp_LIBDIR}")
include_directories(${JsonCpp_INCLUDE_DIR})
link_directories(${JsonCpp_LIBDIR})

pkg_search_module(libargon2 REQUIRED IMPORTED_TARGET libargon2)
message("* libargon2 Include Dir: ${libargon2_INCLUDEDIR}")
message("* libargon2 Lib Dir: ${libargon2_LIBDIR}")
include_directories(${libargon2_INCLUDE_DIR})
link_directories(${libargon2_LIBDIR})

pkg_search_module(fmt REQUIRED IMPORTED_TARGET fmt)
message("* fmt Include Dir: ${fmt_INCLUDEDIR}")
message("* fmt Lib Dir: ${fmt_LIBDIR}")
include_directories(${fmt_INCLUDE_DIR})
link_directories(${fmt_LIBDIR})

pkg_search_module(GnuTLS REQUIRED IMPORTED_TARGET gnutls)
message("* GnuTLS Include Dir: ${GnuTLS_INCLUDEDIR}")
message("* GnuTLS Lib Dir: ${GnuTLS_LIBDIR}")
include_directories(${GnuTLS_INCLUDE_DIR})
link_directories(${GnuTLS_LIBDIR})

pkg_search_module(nettle REQUIRED IMPORTED_TARGET nettle)
message("* nettle Include Dir: ${nettle_INCLUDEDIR}")
message("* nettle Lib Dir: ${nettle_LIBDIR}")
include_directories(${nettle_INCLUDE_DIR})
link_directories(${nettle_LIBDIR})

add_library(${PLEXUS_SHARED} SHARED utils.cpp exec.cpp smime.cpp udp.cpp tcp.cpp email.cpp dht.cpp stun.cpp binder.cpp plexus.cpp)
target_link_libraries(${PLEXUS_SHARED} PRIVATE ${TUBUS_SHARED} ${WORMHOLE_SHARED} Boost::coroutine OpenSSL::SSL OpenSSL::Crypto PkgConfig::opendht PkgConfig::fmt PkgConfig::libargon2 PkgConfig::GnuTLS PkgConfig::nettle PkgConfig::JsonCpp)
target_compile_definitions(${PLEXUS_SHARED} PRIVATE PLEXUS_EXPORTS)
set_target_properties(${PLEXUS_SHARED} PROPERTIES DEBUG_POSTFIX "d" IMPORT_PREFIX "lib")
set_target_properties(${PLEXUS_SHARED} PROPERTIES OUTPUT_NAME ${PROJECT_NAME})

add_library(${PLEXUS_STATIC} STATIC $<TARGET_OBJECTS:${PLEXUS_SHARED}>)
set_target_properties(${PLEXUS_STATIC} PROPERTIES DEBUG_POSTFIX "d")
set_target_properties(${PLEXUS_STATIC} PROPERTIES OUTPUT_NAME ${PROJECT_NAME})

add_executable(${PROJECT_NAME} main.cpp $<TARGET_OBJECTS:${PLEXUS_SHARED}>)
target_link_libraries(${PROJECT_NAME} PRIVATE ${TUBUS_STATIC} ${WORMHOLE_STATIC} Boost::coroutine Boost::program_options OpenSSL::SSL OpenSSL::Crypto PkgConfig::opendht PkgConfig::fmt PkgConfig::libargon2 PkgConfig::GnuTLS PkgConfig::nettle PkgConfig::JsonCpp)
set_target_properties(${PROJECT_NAME} PROPERTIES DEBUG_POSTFIX "d")

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU" OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -Wall -fPIC -fvisibility=hidden")
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    find_package(Threads REQUIRED)
    target_link_libraries(${PROJECT_NAME} PRIVATE Threads::Threads Boost::system)
    target_link_libraries(${PLEXUS_SHARED} PRIVATE Boost::system)
endif()

if(APPLE)
    cmake_policy(PUSH)
    cmake_policy(SET CMP0074 NEW)
    find_package(ICU REQUIRED COMPONENTS data)
    cmake_policy(POP)
    get_filename_component(ICU_LIBDATA_DIR "${ICU_DATA_LIBRARY}" DIRECTORY)
    set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "-L${ICU_LIBDATA_DIR}")
    set_target_properties(${PLEXUS_SHARED} PROPERTIES LINK_FLAGS "-L${ICU_LIBDATA_DIR}")
endif()

# install executable
if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION ${PROJECT_NAME}-${${PROJECT_NAME}_VERSION}/${CMAKE_INSTALL_BINDIR})
    install(FILES $<TARGET_PDB_FILE:${PROJECT_NAME}> CONFIGURATIONS "Debug" "RelWithDebInfo" DESTINATION ${PROJECT_NAME}-${${PROJECT_NAME}_VERSION}/${CMAKE_INSTALL_BINDIR})
elseif(CMAKE_INSTALL_PREFIX MATCHES "^(/usr)|(/usr/local)$")
    install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
else()
    install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION ${PROJECT_NAME}/${${PROJECT_NAME}_VERSION}/${CMAKE_INSTALL_BINDIR})
endif()

# install library
install(TARGETS ${PLEXUS_STATIC} DESTINATION ${PLEXUS_INSTALL_LIBDIR})
install(TARGETS ${PLEXUS_SHARED} DESTINATION ${PLEXUS_INSTALL_LIBDIR})

include(CMakePackageConfigHelpers)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/plexus-config-version.cmake"
    VERSION "${CMAKE_PROJECT_VERSION}"
    COMPATIBILITY AnyNewerVersion)

install(FILES ${HEADERS} DESTINATION ${PLEXUS_INSTALL_INCLUDEDIR}/${PROJECT_NAME})
configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/plexus-config.cmake.in "${CMAKE_CURRENT_BINARY_DIR}/plexus-config.cmake"
    INSTALL_DESTINATION ${PLEXUS_INSTALL_CMAKEDIR}
    PATH_VARS PLEXUS_INSTALL_CMAKEDIR_REVERSE PLEXUS_INSTALL_INCLUDEDIR PLEXUS_INSTALL_LIBDIR)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/plexus-config.cmake" "${CMAKE_CURRENT_BINARY_DIR}/plexus-config-version.cmake" DESTINATION ${PLEXUS_INSTALL_CMAKEDIR})
if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    install(FILES $<TARGET_PDB_FILE:${PLEXUS_SHARED}> CONFIGURATIONS "Debug" "RelWithDebInfo" DESTINATION ${PLEXUS_INSTALL_LIBDIR})
endif()

# build tests
if(BUILD_TESTING)
    set(PLEXUS_UT plexus_ut)
    add_executable(${PLEXUS_UT} tests/utils_tests.cpp
                                tests/ssl_tests.cpp
                                tests/udp_tests.cpp
                                tests/tcp_tests.cpp
                                tests/smime_tests.cpp
                                tests/exec_tests.cpp
                                tests/plexus_tests.cpp)
    target_link_libraries(${PLEXUS_UT} PRIVATE ${PLEXUS_STATIC} ${WORMHOLE_STATIC} ${TUBUS_STATIC} Boost::coroutine Boost::program_options Boost::unit_test_framework OpenSSL::SSL OpenSSL::Crypto PkgConfig::opendht PkgConfig::fmt PkgConfig::libargon2 PkgConfig::GnuTLS PkgConfig::nettle PkgConfig::JsonCpp)
    set_target_properties(${PLEXUS_UT} PROPERTIES DEBUG_POSTFIX "d")

    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU" OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        target_link_libraries(${PLEXUS_UT} PRIVATE Threads::Threads Boost::system)
    endif()

    if(APPLE)
        set_target_properties(${PLEXUS_UT} PROPERTIES LINK_FLAGS "-L${ICU_LIBDATA_DIR}")
    endif()

    enable_testing()
    add_test(NAME ${PLEXUS_UT} COMMAND ${PLEXUS_UT} WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tests)
endif()

message("***** plexus done *****")
