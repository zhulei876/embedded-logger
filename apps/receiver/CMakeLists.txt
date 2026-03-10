# apps/receiver/CMakeLists.txt
add_executable(log_receiver receiver_main.c)
target_link_libraries(log_receiver PRIVATE logger_static)
target_compile_options(log_receiver PRIVATE -Wall -Wextra)
set_target_properties(log_receiver PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
