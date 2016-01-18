# LimeCrypt Tests

cmake_minimum_required (VERSION 2.6.0)
include_directories("../include")

SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_executable(rsatests rsa_basic.cpp)
target_link_libraries(rsatests limecrypt gtest gtest_main)
add_test("LimeCrypt.RSA.Tests" rsatests)

add_custom_target(run_tests COMMAND ${CMAKE_CTEST_COMMAND}
                      DEPENDS rsatests)
