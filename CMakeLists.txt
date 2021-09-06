cmake_minimum_required(VERSION 3.16)
project(FBS)

set(CMAKE_CXX_STANDARD 11)

include(ExternalProject)

set(CMAKE_INSTALL_PREFIX ${PROJECT_SOURCE_DIR}/install)

set(DEBUG OFF)

## Build PALISADE
ExternalProject_Add(PALISADE
        DOWNLOAD_COMMAND ""
        SOURCE_DIR ${PROJECT_SOURCE_DIR}/palisade-release
        CMAKE_ARGS
            -DWITH_NATIVEOPT=ON
            -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
            -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
            -DCMAKE_INSTALL_PREFIX:PATH=${PROJECT_SOURCE_DIR}/install
        )

ExternalProject_Get_Property(PALISADE install_dir)

include_directories(${PROJECT_SOURCE_DIR}/install/include/palisade)
include_directories(${PROJECT_SOURCE_DIR}/install/include/palisade/core)

include_directories(${PROJECT_SOURCE_DIR}/fbs/include/)
include_directories(${PROJECT_SOURCE_DIR}/test/include)

## Compile definition for benchmarks
#add_compile_definitions(MEASURE_TIME)

if (DEBUG)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fopenmp")
    ## In debug mode it is helpful to store the ring secret key, so we can decrypt RLWE/RGSW samples
    add_compile_definitions(WITH_SECRET_KEY)
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -march=native -fopenmp")
    ## In debug mode we disable noise, so computations are exact and such that implementation related mistakes
    ## are easier to debug
    add_compile_definitions(WITH_NOISE)
endif ()

set(PROJECT_SOURCES fbs/src/fbscontext.cpp fbs/src/fhew.cpp fbs/src/lwe.cpp fbs/src/ringswitching.cpp fbs/src/fbs.cpp test/include/error.h)
set(TEST_SOURCES test/src/implementation.cpp test/src/functions.cpp test/src/LUT.cpp test/src/error.cpp)

link_directories(${PROJECT_SOURCE_DIR}/install/lib)

message(STATUS "DIR is ${install_dir}")

add_library(FBSLib SHARED ${PROJECT_SOURCES})
target_link_libraries(FBSLib PALISADEbinfhe PALISADEcore)

add_executable(FBSTest test/main.cpp ${TEST_SOURCES})

target_include_directories(FBSTest PUBLIC ${PROJECT_SOURCE_DIR}/fbs/include/)
target_include_directories(FBSTest PUBLIC ${PROJECT_SOURCE_DIR}/test/include)

target_link_libraries(FBSTest PUBLIC PALISADEcore FBSLib)

set(NN_SOURCES NN/main.cpp NN/src/CRT.cpp NN/src/Utils.cpp NN/src/layers/Linear.cpp
 NN/src/layers/Convolve2d.cpp NN/src/layers/AveragePool2D.cpp
        NN/src/Tensor.cpp NN/src/PrebuildNetworks.cpp NN/src/ActivationFunctions.cpp NN/src/layers/Activation.cpp NN/src/Network.cpp NN/src/Dataset.cpp)

set(NN_HEADERS NN/include/Layer.h NN/include/Utils.h)

add_executable(NN ${NN_SOURCES})

target_include_directories(NN PUBLIC ${PROJECT_SOURCE_DIR}/fbs/include/)
target_include_directories(NN PUBLIC ${PROJECT_SOURCE_DIR}/test/include)
target_include_directories(NN PUBLIC ${PROJECT_SOURCE_DIR}/NN/include)

target_link_libraries(NN PUBLIC FBSLib)



