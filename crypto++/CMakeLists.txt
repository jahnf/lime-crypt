# CMake file: Minimal cryptopp static lib for LimeCrypt
#

cmake_minimum_required(VERSION 2.8)

# Set a default build type if none was specified
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(WARNING "Setting build type to 'Release' as none was specified.")
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
    # Set the possible values of build type for cmake-gui
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

# all necessary source files from crypto++
set(CRYPTOPP_SOURCES_MINIMAL
    des.cpp       dessp.cpp         pssr.cpp      randpool.cpp  dll.cpp
    misc.cpp      gf2n.cpp          sha.cpp       gfpcrypt.cpp  modes.cpp
    ec2n.cpp      mqueue.cpp        algparam.cpp  rdtables.cpp  rijndael.cpp
    hex.cpp       nbtheory.cpp      ecp.cpp       hrtimer.cpp   rsa.cpp
    asn.cpp       cpu.cpp           hmac.cpp      oaep.cpp      winpipes.cpp
    osrng.cpp     rng.cpp           base64.cpp    cryptlib.cpp  gcm.cpp
    basecode.cpp  files.cpp         integer.cpp   queue.cpp     authenc.cpp
    default.cpp   filters.cpp       iterhash.cpp  pkcspad.cpp
    safer.cpp     fips140.cpp       pubkey.cpp    seed.cpp
    )

add_library(cryptopp-minimal STATIC ${CRYPTOPP_SOURCES_MINIMAL})

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    set_property(TARGET cryptopp-minimal APPEND PROPERTY COMPILE_DEFINITIONS "CRYPTOPP_DISABLE_ASM")
endif()
