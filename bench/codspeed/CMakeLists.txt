# CodSpeed benchmarks for cursed-http (Google Benchmark through CodSpeed's codspeed-cpp fork).
#   cmake -S bench/codspeed -B build/codspeed -DCODSPEED_MODE=simulation
#   cmake --build build/codspeed -j
#   ./build/codspeed/cursed_http_bench
# Without -DCODSPEED_MODE it builds as plain Google Benchmark, for local timing.
cmake_minimum_required(VERSION 3.16)
include(FetchContent)

project(cursed_http_bench LANGUAGES C CXX)

if(NOT CMAKE_BUILD_TYPE)
  # optimized, with debug symbols for CodSpeed's flamegraphs
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O3 -g -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O3 -g -DNDEBUG")
set(CMAKE_CXX_STANDARD 17)

set(BENCHMARK_DOWNLOAD_DEPENDENCIES ON)
set(BENCHMARK_ENABLE_TESTING OFF)
set(BENCHMARK_ENABLE_GTEST_TESTS OFF)
FetchContent_Declare(
  google_benchmark
  GIT_REPOSITORY https://github.com/CodSpeedHQ/codspeed-cpp
  GIT_TAG v2.4.0
  SOURCE_SUBDIR google_benchmark
)
FetchContent_MakeAvailable(google_benchmark)

set(REPO_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../..)

# same target CPU as the Makefile's benchmarks: the native SIMD backend (AVX2 on x86-64, NEON on AArch64)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
  set(CH_MARCH -march=haswell)
else()
  set(CH_MARCH "")
endif()

add_library(cursed_http_fixtures STATIC fixtures.c client_fixtures.c resp_fixtures.c
            ${REPO_ROOT}/vendor/pico/picohttpparser.c)
target_include_directories(cursed_http_fixtures PRIVATE ${REPO_ROOT}/include ${REPO_ROOT}/tests ${REPO_ROOT}/bench
                                                         ${REPO_ROOT}/vendor/pico ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(cursed_http_fixtures PRIVATE ${CH_MARCH} -Wall -Wextra -Wno-unused-function
                                                    -Wno-unused-parameter -Wno-deprecated-declarations)
# the HTTP/2 server of the client benchmarks' recordings answers all 256 requests at once
set_source_files_properties(client_fixtures.c PROPERTIES COMPILE_DEFINITIONS H2_MAX_STREAMS=1000)

add_executable(cursed_http_bench bench.cpp)
target_include_directories(cursed_http_bench PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(cursed_http_bench PRIVATE cursed_http_fixtures benchmark::benchmark)
