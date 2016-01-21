# LimeCrypt Tests

cmake_minimum_required (VERSION 2.6.0)
include_directories("../include")

SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_custom_target(run_tests)
macro(add_run_test test_name test_target)
    add_custom_target(${test_target}_runtest
        COMMAND ${test_target}
        DEPENDS ${test_target}
    )
    add_dependencies(run_tests ${test_target}_runtest)
    add_test(${test_name} ${test_target})
endmacro()

add_executable(rsatests rsa_basic.cpp)
target_link_libraries(rsatests limecrypt gtest gtest_main)
add_run_test("LimeCrypt.RSA.Tests" rsatests)

add_executable(aestests aes_basic.cpp)
target_link_libraries(aestests limecrypt gtest gtest_main)
add_run_test("LimeCrypt.AES.Tests" aestests)

add_executable(enctests enc_basic.cpp)
target_link_libraries(enctests limecrypt gtest gtest_main)
add_run_test("LimeCrypt.Encoding.Tests" enctests)

add_executable(errorhandlingtests errorhandling.cpp)
target_link_libraries(errorhandlingtests limecrypt gtest gtest_main)
add_run_test("LimeCrypt.ErrorHandling.Tests" errorhandlingtests)
