cmake_minimum_required(VERSION 3.16)

project(EmbeddedLogger
    VERSION     1.0.0
    DESCRIPTION "Embedded Linux Logger Library with UDP Transport"
    LANGUAGES   C CXX
)

add_compile_definitions(_GNU_SOURCE)

# ============================================================================
# Global C Standard
# ============================================================================
set(CMAKE_C_STANDARD          11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS        OFF)

# ============================================================================
# Compiler Options
# ============================================================================
set(LOGGER_WARN_FLAGS
    -Wall -Wextra -Wpedantic
    -Wformat=2 -Wshadow -Wconversion
    -Wno-unused-parameter
)

# ============================================================================
# Options
# ============================================================================
option(LOGGER_BUILD_TESTS     "Build GTest unit tests"           ON)
option(LOGGER_BUILD_APPS      "Build sender/receiver apps"       ON)
option(LOGGER_BUILD_SHARED    "Build shared library (.so)"       OFF)
option(LOGGER_ENABLE_SANITIZE "Enable AddressSanitizer in Debug" OFF)

if(LOGGER_ENABLE_SANITIZE AND CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(SANITIZE_FLAGS -fsanitize=address,undefined -fno-omit-frame-pointer)
else()
    set(SANITIZE_FLAGS "")
endif()

# ============================================================================
# Library Sources
# ============================================================================
set(LOGGER_SOURCES
    src/core/logger_core.c
    src/core/logger_storage.c
    src/core/logger_crash.c
    src/transport/logger_transport.c
    src/protection/logger_protection.c
    src/crypto/logger_crypto.c
)

set(LOGGER_HEADERS
    include/logger.h
    include/logger_storage.h
    include/logger_transport.h
    include/logger_crypto.h
    include/logger_protection.h
    include/logger_crash.h
)

# ============================================================================
# Static Library Target
# ============================================================================
add_library(logger_static STATIC ${LOGGER_SOURCES})
target_include_directories(logger_static
    PUBLIC  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:include>
)
target_compile_options(logger_static PRIVATE ${LOGGER_WARN_FLAGS} ${SANITIZE_FLAGS})
target_link_libraries(logger_static PUBLIC pthread)
set_target_properties(logger_static PROPERTIES
    OUTPUT_NAME "logger"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)

# ============================================================================
# Shared Library Target (optional)
# ============================================================================
if(LOGGER_BUILD_SHARED)
    add_library(logger_shared SHARED ${LOGGER_SOURCES})
    target_include_directories(logger_shared
        PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
               $<INSTALL_INTERFACE:include>
    )
    target_compile_options(logger_shared PRIVATE ${LOGGER_WARN_FLAGS})
    target_link_libraries(logger_shared PUBLIC pthread)
    set_target_properties(logger_shared PROPERTIES
        OUTPUT_NAME "logger"
        SOVERSION   1
        VERSION     1.0.0
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    )
endif()

# ============================================================================
# Applications
# ============================================================================
if(LOGGER_BUILD_APPS)
    add_subdirectory(apps/sender)
    add_subdirectory(apps/receiver)
endif()

# ============================================================================
# Unit Tests
# ============================================================================
if(LOGGER_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ============================================================================
# Install Rules
# ============================================================================
include(GNUInstallDirs)

install(TARGETS logger_static
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(FILES ${LOGGER_HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/logger
)

install(DIRECTORY config/
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/logger
    FILES_MATCHING PATTERN "*.ini"
)

# ============================================================================
# Summary
# ============================================================================
message(STATUS "")
message(STATUS "=== EmbeddedLogger ${PROJECT_VERSION} ===")
message(STATUS "  C Standard   : ${CMAKE_C_STANDARD}")
message(STATUS "  Build type   : ${CMAKE_BUILD_TYPE}")
message(STATUS "  Tests        : ${LOGGER_BUILD_TESTS}")
message(STATUS "  Apps         : ${LOGGER_BUILD_APPS}")
message(STATUS "  Shared lib   : ${LOGGER_BUILD_SHARED}")
message(STATUS "  Sanitizers   : ${LOGGER_ENABLE_SANITIZE}")
message(STATUS "")
