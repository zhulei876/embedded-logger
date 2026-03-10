# apps/sender/CMakeLists.txt
add_executable(log_sender sender_main.c)
target_link_libraries(log_sender PRIVATE logger_static)
target_compile_options(log_sender PRIVATE -Wall -Wextra)
set_target_properties(log_sender PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
