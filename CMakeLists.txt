message("***** plexus ***** ")

########## setup ##########

cmake_minimum_required(VERSION 3.21)

project(plexus VERSION 3.2.1 DESCRIPTION "The tool for connecting UDP applications via NAT" LANGUAGES CXX)

option(PLEXUS_USE_SHARED_LIB "Build shared library" ${BUILD_SHARED_LIBS})
option(PLEXUS_SKIP_TEST_RULES "Don't generate test rules" ON)
option(PLEXUS_SKIP_INSTALL_RULES "Don't generate install rules" OFF)
option(PLEXUS_SKIP_PACKAGE_RULES "Don't generate package rules" ON)

if (PLEXUS_USE_SHARED_LIB)
    set(BUILD_SHARED_LIBS ON)
endif()

########## dependencies ##########

if (NOT MSVC AND NOT BUILD_SHARED_LIBS)
    set(Boost_USE_STATIC_LIBS ON)
endif()

if(NOT PLEXUS_SKIP_TEST_RULES)
    find_package(Boost 1.80 CONFIG REQUIRED COMPONENTS system program_options coroutine unit_test_framework)
else()
    find_package(Boost 1.80 CONFIG REQUIRED COMPONENTS system program_options coroutine)
endif()

message("* Boost Version: ${Boost_VERSION}")
message("* Boost Include Dirs: ${Boost_INCLUDE_DIRS}")
message("* Boost Library Dirs: ${Boost_LIBRARY_DIRS}")
message("* Boost Libraries: ${Boost_LIBRARIES}")

find_package(OpenSSL REQUIRED)

message("* OpenSSL Version: ${OPENSSL_VERSION}")
message("* OpenSSL Include Dir: ${OPENSSL_INCLUDE_DIR}")
message("* OpenSSL Libraries: ${OPENSSL_LIBRARIES}")

find_package(tubus 1.2.3 REQUIRED COMPONENTS libtubus)

message("* tubus Version: ${tubus_VERSION}")
message("* tubus Include Dirs: ${tubus_INCLUDE_DIRS}")
message("* tubus Library: ${tubus_LIBRARY}")

find_package(wormhole 1.2.4 REQUIRED COMPONENTS libwormhole)

message("* wormhole Version: ${wormhole_VERSION}")
message("* wormhole Include Dirs: ${wormhole_INCLUDE_DIRS}")
message("* wormhole Library: ${wormhole_LIBRARY}")

find_package(opendht 3.2 REQUIRED)
find_package(fmt REQUIRED)

find_package(msgpackc-cxx QUIET CONFIG NAMES msgpackc-cxx msgpack)
if(msgpackc-cxx_FOUND)
  add_library(msgpack-cxx ALIAS msgpackc-cxx)
else()
  find_package(msgpack-cxx CONFIG REQUIRED)
endif()

find_package(PkgConfig REQUIRED)

pkg_search_module(GnuTLS REQUIRED IMPORTED_TARGET gnutls)

message("* GnuTLS Include Dir: ${GnuTLS_INCLUDEDIR}")
message("* GnuTLS Lib Dir: ${GnuTLS_LIBDIR}")

pkg_search_module(Nettle REQUIRED IMPORTED_TARGET nettle)

message("* Nettle Include Dir: ${Nettle_INCLUDEDIR}")
message("* Nettle Lib Dir: ${Nettle_LIBDIR}")

pkg_search_module(argon2 REQUIRED IMPORTED_TARGET libargon2)

message("* argon2 Include Dir: ${argon2_INCLUDEDIR}")
message("* argon2 Lib Dir: ${argon2_LIBDIR}")

pkg_search_module(Jsoncpp REQUIRED IMPORTED_TARGET jsoncpp)

message("* Jsoncpp Include Dir: ${Jsoncpp_INCLUDEDIR}")
message("* Jsoncpp Lib Dir: ${Jsoncpp_LIBDIR}")

########## build ##########

include(GenerateExportHeader)

set(BINPLEXUS ${PROJECT_NAME})
set(LIBPLEXUS lib${PROJECT_NAME})

add_executable(${BINPLEXUS})
add_executable(${PROJECT_NAME}::${BINPLEXUS} ALIAS ${BINPLEXUS})

add_library(${LIBPLEXUS})
add_library(${PROJECT_NAME}::${LIBPLEXUS} ALIAS ${LIBPLEXUS})

generate_export_header(${LIBPLEXUS} EXPORT_FILE_NAME "export_header/plexus/export.h")

if (NOT BUILD_SHARED_LIBS)
    target_compile_definitions(${LIBPLEXUS} PUBLIC LIBPLEXUS_STATIC_DEFINE)
endif()

set(SOURCES "${CMAKE_CURRENT_BINARY_DIR}/export_header/plexus/export.h"
    src/plexus/utils.h
    src/plexus/socket.h
    src/plexus/network.h
    src/plexus/features.h
    src/plexus/plexus.h
    src/plexus/utils.cpp
    src/plexus/exec.cpp
    src/plexus/smime.cpp
    src/plexus/udp.cpp
    src/plexus/tcp.cpp
    src/plexus/email.cpp
    src/plexus/dht.cpp
    src/plexus/stun.cpp
    src/plexus/binder.cpp
    src/plexus/plexus.cpp
    )

set(HEADERS "${CMAKE_CURRENT_BINARY_DIR}/export_header/plexus/export.h" src/plexus/plexus.h)

if(MSVC)
    set(CMAKE_STATIC_LIBRARY_PREFIX "lib")
    set(CMAKE_SHARED_LIBRARY_PREFIX "lib")
    set(CMAKE_STATIC_LIBRARY_SUFFIX "-static.lib")
    add_definitions(-D_WIN32_WINNT=0x0601)
endif()

if(NOT DEFINED CMAKE_BUILD_TYPE AND NOT DEFINED CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

if(NOT DEFINED CMAKE_CXX_VISIBILITY_PRESET)
    set(CMAKE_CXX_VISIBILITY_PRESET hidden)
endif()
if(NOT DEFINED CMAKE_VISIBILITY_INLINES_HIDDEN)
    set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)
endif()

target_sources(${LIBPLEXUS} PRIVATE ${SOURCES})
target_sources(${BINPLEXUS} PRIVATE $<TARGET_OBJECTS:${LIBPLEXUS}> src/plexus/main.cpp)

target_link_libraries(${LIBPLEXUS} PUBLIC tubus::libtubus PRIVATE wormhole::libwormhole Boost::coroutine OpenSSL::SSL OpenSSL::Crypto opendht fmt::fmt msgpack-cxx PkgConfig::GnuTLS PkgConfig::argon2 PkgConfig::Nettle PkgConfig::Jsoncpp "$<$<BOOL:${MSVC}>:Iphlpapi>")
target_link_libraries(${BINPLEXUS} PRIVATE tubus::libtubus wormhole::libwormhole Boost::coroutine Boost::program_options OpenSSL::SSL OpenSSL::Crypto opendht fmt::fmt msgpack-cxx PkgConfig::GnuTLS PkgConfig::argon2 PkgConfig::Nettle PkgConfig::Jsoncpp "$<$<BOOL:${MSVC}>:Iphlpapi>")

target_compile_features(${LIBPLEXUS} PRIVATE cxx_std_17)
target_compile_features(${BINPLEXUS} PRIVATE cxx_std_17)

target_include_directories(${BINPLEXUS} PRIVATE
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>"
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/export_header>"
        "${opendht_INCLUDEDIR}")

target_include_directories(${LIBPLEXUS} PUBLIC
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>"
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/export_header>"
        PRIVATE "${opendht_INCLUDEDIR}")

set_target_properties(${BINPLEXUS} PROPERTIES DEBUG_POSTFIX "d" COMPILE_FLAGS -DLIBPLEXUS_STATIC_DEFINE)
set_target_properties(${BINPLEXUS} PROPERTIES CXX_VISIBILITY_PRESET hidden VISIBILITY_INLINES_HIDDEN ON)
set_target_properties(${LIBPLEXUS} PROPERTIES DEBUG_POSTFIX "d" OUTPUT_NAME ${PROJECT_NAME} IMPORT_PREFIX "lib")
set_target_properties(${LIBPLEXUS} PROPERTIES SOVERSION ${PROJECT_VERSION_MAJOR} VERSION ${PROJECT_VERSION})
set_target_properties(${LIBPLEXUS} PROPERTIES CXX_VISIBILITY_PRESET hidden VISIBILITY_INLINES_HIDDEN ON)

########## install ##########

if(NOT PLEXUS_SKIP_INSTALL_RULES AND NOT CMAKE_SKIP_INSTALL_RULES)

    include(GNUInstallDirs)
    include(CMakePackageConfigHelpers)

    set(PLEXUS_INSTALL_CMAKEDIR "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}")

    configure_package_config_file(cmake/plexus-config.cmake.in plexus-config.cmake INSTALL_DESTINATION "${PLEXUS_INSTALL_CMAKEDIR}")

    write_basic_package_version_file(plexus-config-version.cmake COMPATIBILITY SameMajorVersion)

    install(TARGETS ${BINPLEXUS} RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" COMPONENT binary_files)

    install(TARGETS ${LIBPLEXUS} EXPORT plexus_export
        RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" COMPONENT runtime_files
        LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}" COMPONENT library_files
        ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}" COMPONENT archive_files
        INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

    set(TARGET_FILE plexus-shared-targets.cmake)

    if(NOT BUILD_SHARED_LIBS)
        set(TARGET_FILE plexus-static-targets.cmake)
    endif()

    install(EXPORT plexus_export COMPONENT cmake_files
        FILE ${TARGET_FILE}
        DESTINATION "${PLEXUS_INSTALL_CMAKEDIR}"
        NAMESPACE plexus::)

    install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/plexus-config.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/plexus-config-version.cmake"
        COMPONENT cmake_files
        DESTINATION "${PLEXUS_INSTALL_CMAKEDIR}")

    install(FILES ${HEADERS} DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}" COMPONENT header_files)

    if(MSVC)
        install(FILES "$<TARGET_PDB_FILE:${BINPLEXUS}>" COMPONENT pdb_files
            CONFIGURATIONS Debug RelWithDebInfo
            DESTINATION "${CMAKE_INSTALL_LIBDIR}"
            OPTIONAL)
        if(BUILD_SHARED_LIBS)
            install(FILES "$<TARGET_PDB_FILE:${LIBPLEXUS}>" COMPONENT pdb_files
                CONFIGURATIONS Debug RelWithDebInfo
                DESTINATION "${CMAKE_INSTALL_LIBDIR}"
                OPTIONAL)
        else()
            install(FILES "$<TARGET_FILE_DIR:${LIBPLEXUS}>/$<TARGET_FILE_PREFIX:${LIBPLEXUS}>$<TARGET_FILE_BASE_NAME:${LIBPLEXUS}>-static.pdb" COMPONENT pdb_files
                CONFIGURATIONS Debug RelWithDebInfo
                DESTINATION "${CMAKE_INSTALL_LIBDIR}"
                OPTIONAL)
        endif()
    endif()
endif()

########## tests ##########

if(NOT PLEXUS_SKIP_TEST_RULES)
    set(PLEXUS_TEST plexus_ut)
    add_executable(${PLEXUS_TEST} tests/utils_tests.cpp
                                  tests/ssl_tests.cpp
                                  tests/udp_tests.cpp
                                  tests/tcp_tests.cpp
                                  tests/smime_tests.cpp
                                  tests/exec_tests.cpp
                                  tests/plexus_tests.cpp)
    target_link_libraries(${PLEXUS_TEST} PRIVATE $<TARGET_OBJECTS:${LIBPLEXUS}> tubus::libtubus wormhole::libwormhole Boost::coroutine Boost::program_options Boost::unit_test_framework OpenSSL::SSL OpenSSL::Crypto opendht fmt::fmt msgpack-cxx PkgConfig::GnuTLS PkgConfig::argon2 PkgConfig::Nettle PkgConfig::Jsoncpp "$<$<BOOL:${MSVC}>:Iphlpapi>")

    target_include_directories(${PLEXUS_TEST} PRIVATE
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>"
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/export_header>"
        "${opendht_INCLUDEDIR}")

    target_compile_features(${PLEXUS_TEST} PRIVATE cxx_std_17)
    set_target_properties(${PLEXUS_TEST} PROPERTIES DEBUG_POSTFIX "d" COMPILE_FLAGS -DLIBPLEXUS_STATIC_DEFINE)

    enable_testing()
    add_test(NAME ${PLEXUS_TEST} COMMAND ${PLEXUS_TEST} WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/tests")
endif()

########## package ##########

if(NOT PLEXUS_SKIP_PACKAGE_RULES AND NOT PLEXUS_SKIP_INSTALL_RULES AND NOT CMAKE_SKIP_INSTALL_RULES)
    if(CMAKE_HOST_SYSTEM_NAME MATCHES "Linux")
        set(CPACK_PACKAGE_RELEASE "1")
        set(CPACK_PACKAGING_INSTALL_PREFIX "/opt")
        set(CPACK_COMPONENTS_ALL_IN_ONE_PACKAGE ON)
        cmake_host_system_information(RESULT DISTR QUERY DISTRIB_ID)
        if(DISTR MATCHES "(debian)|(ubuntu)|(kali)|(astra)")
            cmake_host_system_information(RESULT CPACK_DEBIAN_PACKAGE_RELEASE QUERY DISTRIB_VERSION_CODENAME)
            set(CPACK_DEBIAN_PACKAGE_RELEASE "${CPACK_PACKAGE_RELEASE}+${CPACK_DEBIAN_PACKAGE_RELEASE}")
            set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Community")
            set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
            set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
            set(CPACK_DEBIAN_PACKAGE_GENERATE_SHLIBS ON)
            set(CPACK_DEBIAN_DEBUGINFO_PACKAGE ON)
            set(CPACK_DEB_COMPONENT_INSTALL ON)
            add_custom_command(DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/linux/changelog"
                COMMAND gzip -cn9 "${CMAKE_CURRENT_SOURCE_DIR}/linux/changelog" > "${CMAKE_CURRENT_BINARY_DIR}/changelog.gz"
                OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/changelog.gz")
            add_custom_target(changelog ALL DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/changelog.gz")

            set(DEBIAN_DOC_FILES
                "${CMAKE_CURRENT_BINARY_DIR}/changelog.gz"
                "${CMAKE_CURRENT_SOURCE_DIR}/linux/copyright"
                "${CMAKE_CURRENT_SOURCE_DIR}/linux/README.Debian"
                )
            install(FILES ${DEBIAN_DOC_FILES} DESTINATION "${CMAKE_INSTALL_DATADIR}/doc/${BINPLEXUS}" COMPONENT bin_deb_files)
            if(BUILD_SHARED_LIBS)
                install(FILES ${DEBIAN_DOC_FILES} DESTINATION "${CMAKE_INSTALL_DATADIR}/doc/${LIBPLEXUS}" COMPONENT lib_deb_files)
            else()
                install(FILES ${DEBIAN_DOC_FILES} DESTINATION "${CMAKE_INSTALL_DATADIR}/doc/${LIBPLEXUS}-dev" COMPONENT dev_deb_files)
            endif()
        else()
            if (DISTR MATCHES "fedora")
                cmake_host_system_information(RESULT CPACK_RPM_PACKAGE_RELEASE QUERY DISTRIB_VERSION_ID)
                set(CPACK_RPM_PACKAGE_RELEASE "${CPACK_PACKAGE_RELEASE}.fc${CPACK_RPM_PACKAGE_RELEASE}")
            else()
                set(CPACK_RPM_PACKAGE_RELEASE "${CPACK_PACKAGE_RELEASE}")
            endif()

            set(CPACK_RPM_CHANGELOG_FILE ${CMAKE_CURRENT_SOURCE_DIR}/linux/changelog.rpm)
            set(CPACK_RPM_PACKAGE_VENDOR "Community")
            set(CPACK_RPM_PACKAGE_AUTOREQ "1")
            set(CPACK_RPM_PACKAGE_LICENSE "Apache 2.0")
            set(CPACK_RPM_COMPONENT_INSTALL ON)
            set(CPACK_RPM_BUILD_SOURCE_DIRS_PREFIX "/novemus/plexus")

            configure_file("${CMAKE_CURRENT_SOURCE_DIR}/cmake/rpm-binary.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/rpm-binary.cmake" @ONLY)
            configure_file("${CMAKE_CURRENT_SOURCE_DIR}/cmake/rpm-library.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/rpm-library.cmake" @ONLY)
            configure_file("${CMAKE_CURRENT_SOURCE_DIR}/cmake/rpm-devel.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/rpm-devel.cmake" @ONLY)
        endif()
    endif()

    if(NOT BUILD_SHARED_LIBS)
        set(DEVEL_DOC_FILES
            "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE.txt"
            "${CMAKE_CURRENT_SOURCE_DIR}/README.md"
            "${CMAKE_CURRENT_SOURCE_DIR}/CHANGELOG.md"
            )
        install(FILES ${DEVEL_DOC_FILES} DESTINATION "${CMAKE_INSTALL_DATADIR}/doc/${LIBPLEXUS}-dev" COMPONENT dev_doc_files)
    endif()

    include(CPack)
endif()
