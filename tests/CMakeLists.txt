# tests/CMakeLists.txt

# ============================================================================
# Find / Fetch GTest
# ============================================================================
find_package(GTest QUIET)

if(NOT GTest_FOUND)
    include(FetchContent)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        v1.14.0
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
endif()

# ============================================================================
# Test Executable
# ============================================================================
add_executable(logger_tests test_logger.cpp)

target_link_libraries(logger_tests
    PRIVATE
        logger_static
        GTest::gtest
        GTest::gtest_main
        pthread
)

target_compile_options(logger_tests PRIVATE -Wall -Wextra)

set_target_properties(logger_tests PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# ============================================================================
# CTest Registration
# ============================================================================
include(GoogleTest)
gtest_discover_tests(logger_tests
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
)
