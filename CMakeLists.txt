message("***** plexus ***** ")

########## setup ##########

cmake_minimum_required(VERSION 3.21)

project(plexus VERSION 3.1.2 DESCRIPTION "Tool for connecting applications via NAT" LANGUAGES CXX)

option(PLEXUS_USE_SHARED_LIB "Build shared library" ${BUILD_SHARED_LIBS})
option(PLEXUS_SKIP_TEST_RULES "Don't generate test rules" ON)
option(PLEXUS_SKIP_INSTALL_RULES "Don't generate install rules" OFF)
option(PLEXUS_SKIP_PACKAGE_RULES "Don't generate package rules" ON)

if (PLEXUS_USE_SHARED_LIB)
    set(BUILD_SHARED_LIBS ON)
endif()

########## dependencies ##########

if(NOT PLEXUS_SKIP_TEST_RULES)
    find_package(Boost REQUIRED COMPONENTS system program_options coroutine unit_test_framework)
else()
    find_package(Boost REQUIRED COMPONENTS system program_options coroutine)
endif()

message("* Boost Version: ${Boost_VERSION}")
message("* Boost Include Dirs: ${Boost_INCLUDE_DIRS}")
message("* Boost Library Dirs: ${Boost_LIBRARY_DIRS}")
message("* Boost Libraries: ${Boost_LIBRARIES}")

find_package(OpenSSL REQUIRED)

message("* OpenSSL Version: ${OPENSSL_VERSION}")
message("* OpenSSL Include Dir: ${OPENSSL_INCLUDE_DIR}")
message("* OpenSSL Libraries: ${OPENSSL_LIBRARIES}")

find_package(tubus REQUIRED COMPONENTS libtubus)

message("* tubus Version: ${tubus_VERSION}")
message("* tubus Include Dirs: ${tubus_INCLUDE_DIRS}")
message("* tubus Library: ${tubus_LIBRARY}")

find_package(wormhole REQUIRED COMPONENTS libwormhole)

message("* wormhole Version: ${wormhole_VERSION}")
message("* wormhole Include Dirs: ${wormhole_INCLUDE_DIRS}")
message("* wormhole Library: ${wormhole_LIBRARY}")

find_package(PkgConfig REQUIRED)

pkg_search_module(opendht REQUIRED IMPORTED_TARGET opendht>=3.2)

message("* opendht Include Dir: ${opendht_INCLUDEDIR}")
message("* opendht Lib Dir: ${opendht_LIBDIR}")

pkg_search_module(nettle REQUIRED IMPORTED_TARGET nettle)

message("* nettle Include Dir: ${nettle_INCLUDEDIR}")
message("* nettle Lib Dir: ${nettle_LIBDIR}")

pkg_search_module(fmt REQUIRED IMPORTED_TARGET fmt)

message("* fmt Include Dir: ${fmt_INCLUDEDIR}")
message("* fmt Lib Dir: ${fmt_LIBDIR}")

pkg_search_module(libargon2 REQUIRED IMPORTED_TARGET libargon2)

message("* libargon2 Include Dir: ${libargon2_INCLUDEDIR}")
message("* libargon2 Lib Dir: ${libargon2_LIBDIR}")

########## build ##########

include(GenerateExportHeader)

set(BINPLEXUS ${PROJECT_NAME})
set(LIBPLEXUS lib${PROJECT_NAME})

add_executable(${BINPLEXUS})
add_executable(${PROJECT_NAME}::${BINPLEXUS} ALIAS ${BINPLEXUS})

add_library(${LIBPLEXUS})
add_library(${PROJECT_NAME}::${LIBPLEXUS} ALIAS ${LIBPLEXUS})

set(EXPORT_FILE export_shared.h)

if(NOT BUILD_SHARED_LIBS)
    set(EXPORT_FILE export_static.h)
endif()

generate_export_header(${LIBPLEXUS} EXPORT_FILE_NAME ${CMAKE_CURRENT_BINARY_DIR}/export_header/plexus/${EXPORT_FILE})

set(SOURCES ${CMAKE_CURRENT_BINARY_DIR}/export_header/plexus/${EXPORT_FILE}
    src/plexus/export.h
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

set(HEADERS ${CMAKE_CURRENT_BINARY_DIR}/export_header/plexus/${EXPORT_FILE} src/plexus/export.h src/plexus/plexus.h)

if(NOT MSVC)
    add_definitions(-D_WIN32_WINNT=0x0601 -DINCL_EXTRA_HTON_FUNCTIONS)
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

target_link_libraries(${LIBPLEXUS} PRIVATE tubus::libtubus wormhole::libwormhole Boost::coroutine OpenSSL::SSL OpenSSL::Crypto PkgConfig::opendht PkgConfig::nettle PkgConfig::fmt PkgConfig::libargon2)
target_link_libraries(${BINPLEXUS} PRIVATE tubus::libtubus wormhole::libwormhole Boost::coroutine Boost::program_options OpenSSL::SSL OpenSSL::Crypto PkgConfig::opendht PkgConfig::nettle PkgConfig::fmt PkgConfig::libargon2)

target_compile_definitions(${LIBPLEXUS} PUBLIC "$<$<NOT:$<BOOL:${BUILD_SHARED_LIBS}>>:LIBPLEXUS_STATIC_DEFINE>")
target_compile_definitions(${BINPLEXUS} PUBLIC "$<$<NOT:$<BOOL:${BUILD_SHARED_LIBS}>>:LIBPLEXUS_STATIC_DEFINE>")

target_include_directories(${BINPLEXUS} PRIVATE
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>"
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/export_header>")

target_include_directories(${LIBPLEXUS} PUBLIC
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>"
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/export_header>")

set_target_properties(${BINPLEXUS} PROPERTIES DEBUG_POSTFIX "d")
set_target_properties(${LIBPLEXUS} PROPERTIES DEBUG_POSTFIX "d" OUTPUT_NAME ${PROJECT_NAME})
set_target_properties(${LIBPLEXUS} PROPERTIES SOVERSION ${PROJECT_VERSION_MAJOR} VERSION ${PROJECT_VERSION})

########## install ##########

if(NOT PLEXUS_SKIP_INSTALL_RULES AND NOT CMAKE_SKIP_INSTALL_RULES)

    include(GNUInstallDirs)
    include(CMakePackageConfigHelpers)

    if(MSVC)
        set(PLEXUS_INSTALL_BINDIR ${PROJECT_NAME}-${${PROJECT_NAME}_VERSION}/${CMAKE_INSTALL_BINDIR})
        set(PLEXUS_INSTALL_LIBDIR ${PROJECT_NAME}-${${PROJECT_NAME}_VERSION}/${CMAKE_INSTALL_LIBDIR})
        set(PLEXUS_INSTALL_CMAKEDIR ${PROJECT_NAME}-${${PROJECT_NAME}_VERSION}/${CMAKE_INSTALL_DATADIR}/cmake)
        set(PLEXUS_INSTALL_INCLUDEDIR ${PROJECT_NAME}-${${PROJECT_NAME}_VERSION}/${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME})
    else()
        if(CMAKE_INSTALL_PREFIX MATCHES "^(/usr)|(/usr/local)$")
            set(PLEXUS_INSTALL_BINDIR ${CMAKE_INSTALL_BINDIR})
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
            set(PLEXUS_INSTALL_BINDIR ${PROJECT_NAME}-${${PROJECT_NAME}_VERSION}/${CMAKE_INSTALL_BINDIR})
            set(PLEXUS_INSTALL_LIBDIR ${PROJECT_NAME}-${${PROJECT_NAME}_VERSION}/${CMAKE_INSTALL_LIBDIR}/${CMAKE_LIBRARY_ARCHITECTURE})
            set(PLEXUS_INSTALL_CMAKEDIR ${PROJECT_NAME}-${${PROJECT_NAME}_VERSION}/${CMAKE_INSTALL_LIBDIR}/${CMAKE_LIBRARY_ARCHITECTURE}/cmake)
            set(PLEXUS_INSTALL_INCLUDEDIR ${PROJECT_NAME}-${${PROJECT_NAME}_VERSION}/${CMAKE_INSTALL_INCLUDEDIR})
        endif()
    endif()

    configure_package_config_file(cmake/plexus-config.cmake.in plexus-config.cmake INSTALL_DESTINATION "${PLEXUS_INSTALL_CMAKEDIR}")

    write_basic_package_version_file(plexus-config-version.cmake COMPATIBILITY SameMajorVersion)

    install(TARGETS ${BINPLEXUS} EXPORT plexus_export RUNTIME DESTINATION ${PLEXUS_INSTALL_BINDIR} COMPONENT binary_files)

    install(TARGETS ${LIBPLEXUS} EXPORT plexus_export
        RUNTIME DESTINATION ${PLEXUS_INSTALL_LIBDIR} COMPONENT runtime_files
        LIBRARY DESTINATION ${PLEXUS_INSTALL_LIBDIR} COMPONENT library_files
        ARCHIVE DESTINATION ${PLEXUS_INSTALL_LIBDIR} COMPONENT archive_files
        INCLUDES DESTINATION ${PLEXUS_INSTALL_INCLUDEDIR})

    set(TARGET_FILE plexus-shared-targets.cmake)

    if(NOT BUILD_SHARED_LIBS)
        set(TARGET_FILE plexus-static-targets.cmake)
    endif()

    install(EXPORT plexus_export COMPONENT cmake_files
        FILE ${TARGET_FILE}
        DESTINATION ${PLEXUS_INSTALL_CMAKEDIR}
        NAMESPACE plexus::)

    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/plexus-config.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/plexus-config-version.cmake
        COMPONENT cmake_files
        DESTINATION ${PLEXUS_INSTALL_CMAKEDIR})

    install(FILES ${HEADERS} DESTINATION ${PLEXUS_INSTALL_INCLUDEDIR}/${PROJECT_NAME} COMPONENT header_files)

    if(MSVC)
        install(FILES "$<TARGET_PDB_FILE:${BINPLEXUS}>" COMPONENT pdb_files
            CONFIGURATIONS Debug RelWithDebInfo
            DESTINATION ${PLEXUS_INSTALL_BINDIR}
            OPTIONAL)
        if(BUILD_SHARED_LIBS)
            install(FILES "$<TARGET_PDB_FILE:${LIBPLEXUS}>" COMPONENT pdb_files
                CONFIGURATIONS Debug RelWithDebInfo
                DESTINATION ${PLEXUS_INSTALL_LIBDIR}
                OPTIONAL)
        else()
            install(FILES "$<TARGET_FILE_DIR:${LIBPLEXUS}>/$<TARGET_FILE_PREFIX:${LIBPLEXUS}>$<TARGET_FILE_BASE_NAME:${LIBPLEXUS}>-static.pdb" COMPONENT pdb_files
                CONFIGURATIONS Debug RelWithDebInfo
                DESTINATION ${PLEXUS_INSTALL_LIBDIR}
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
    target_link_libraries(${PLEXUS_TEST} PRIVATE tubus::libtubus wormhole::libwormhole plexus::libplexus Boost::coroutine Boost::program_options Boost::unit_test_framework OpenSSL::SSL OpenSSL::Crypto PkgConfig::opendht PkgConfig::nettle PkgConfig::fmt PkgConfig::libargon2)

    set_target_properties(${PLEXUS_TEST} PROPERTIES DEBUG_POSTFIX "d")

    enable_testing()
    add_test(NAME ${PLEXUS_TEST} COMMAND ${PLEXUS_TEST} WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tests)
endif()

########## package ##########

if(NOT PLEXUS_SKIP_PACKAGE_RULES AND NOT PLEXUS_SKIP_INSTALL_RULES AND NOT CMAKE_SKIP_INSTALL_RULES)
    set(_DOC_FILES_COMPONENT lib_doc_files)

    if(CMAKE_INSTALL_PREFIX MATCHES "^(/usr)|(/usr/local)$")
        set(_DOCDIR_PREFIX ${CMAKE_INSTALL_DOCDIR})
    else()
        set(_DOCDIR_PREFIX ${PROJECT_NAME}-${${PROJECT_NAME}_VERSION}/${CMAKE_INSTALL_DOCDIR})
    endif()

    set(BINPLEXUS_INSTALL_DOCDIR ${_DOCDIR_PREFIX}/${BINPLEXUS}-${${PROJECT_NAME}_VERSION})
    set(LIBPLEXUS_INSTALL_DOCDIR ${_DOCDIR_PREFIX}/${LIBPLEXUS}-${${PROJECT_NAME}_VERSION})

    if(CMAKE_HOST_SYSTEM_NAME MATCHES "Linux")
        cmake_host_system_information(RESULT _DISTRIB QUERY DISTRIB_ID)
        if(_DISTRIB MATCHES "(debian)|(ubuntu)|(kali)|(astra)")
            if(NOT BUILD_SHARED_LIBS)
                set(_DOC_FILES_COMPONENT dev_doc_files)
                set(LIBPLEXUS_INSTALL_DOCDIR "${LIBPLEXUS_INSTALL_DOCDIR}-dev")
            endif()
            add_custom_command(DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/debian/changelog"
                COMMAND gzip -cn9 "${CMAKE_CURRENT_SOURCE_DIR}/debian/changelog" > "${CMAKE_CURRENT_BINARY_DIR}/changelog.gz"
                OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/changelog.gz")
            add_custom_target(tubus_changelog ALL DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/changelog.gz")
            
            set(_DEBIAN_DOC_FILES
                ${CMAKE_CURRENT_BINARY_DIR}/changelog.gz
                ${CMAKE_CURRENT_SOURCE_DIR}/debian/copyright
                ${CMAKE_CURRENT_SOURCE_DIR}/debian/README.Debian
                )
            install(FILES ${_DEBIAN_DOC_FILES} DESTINATION ${LIBPLEXUS_INSTALL_DOCDIR} COMPONENT ${_DOC_FILES_COMPONENT})
            install(FILES ${_DEBIAN_DOC_FILES} DESTINATION ${BINPLEXUS_INSTALL_DOCDIR} COMPONENT bin_doc_files)
        endif()
    endif()

    if(NOT BUILD_SHARED_LIBS)
        set(_SOURCE_DOC_FILES
            ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE.txt
            ${CMAKE_CURRENT_SOURCE_DIR}/README.md
            ${CMAKE_CURRENT_SOURCE_DIR}/CHANGELOG.md
            )
        install(FILES ${_SOURCE_DOC_FILES} DESTINATION ${LIBPLEXUS_INSTALL_DOCDIR} COMPONENT ${_DOC_FILES_COMPONENT})
    endif()

    include(CPack)
endif()

message("***** plexus done ***** ")
