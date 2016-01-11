# CMake file for LimeCrypt examples
#
add_executable(example_rsa example_rsa.cpp)
target_link_libraries(example_rsa limecrypt)

add_executable(example_aes example_aes.cpp)
target_link_libraries(example_aes limecrypt)

