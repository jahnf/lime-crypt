# CMake file for lime-crypt library and examples
#
# OPTIONS:
#
# -DBUILD_EXAMPLES=1
#     Build the examples.

cmake_minimum_required(VERSION 2.8.3)
set(CMAKE_LEGACY_CYGWIN_WIN32 0)

set(BUILD_EXAMPLES 0 CACHE BOOL "Build the examples.")

project(lime-crypt)

# Set a default build type if none was specified
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(WARNING "Setting build type to 'Release' as none was specified.")
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
    # Set the possible values of build type for cmake-gui
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

add_subdirectory(crypto++)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR})

if(CMAKE_COMPILER_IS_GNUCC)
    # Add strip flag for release and minsize builds
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -s")
    set(CMAKE_CXX_FLAGS_MINSIZEREL "${CMAKE_CXX_FLAGS_MINSIZEREL} -s")
endif()

# Headers are added to make them show up in QtCreator or other IDEs
add_library(limecrypt STATIC src/limecrypt.cpp  include/limecrypt.h  src/limecrypt_p.h
                             src/lcpubkey.cpp   include/lcpubkey.h
                             src/lcaes.cpp      include/lcaes.h
                             src/lcencode.cpp   include/lcencode.h
                             )

# Link against crypto++ 
target_link_libraries(limecrypt cryptopp-minimal)

if(BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# If available, generate a target for creating the doxygen documentation
find_package(Doxygen)
if(DOXYGEN_FOUND)
    set(DOC_TARGET_NAME "doc")
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)
    add_custom_target(${DOC_TARGET_NAME}
        ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating API documentation with Doxygen" VERBATIM)
endif()
