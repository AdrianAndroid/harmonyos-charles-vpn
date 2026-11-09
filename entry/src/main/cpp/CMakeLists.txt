# HarmonyOS NEXT (API 26) Stage-app native module.
# Produces libcharles_vpn.so, registered to ArkTS as "charles_vpn".
cmake_minimum_required(VERSION 3.5.0)
project(charles_vpn LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(charles_vpn SHARED
    vpn_napi.cpp
    tun_proxy.cpp
    http_request.cpp
)

target_include_directories(charles_vpn PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_options(charles_vpn PRIVATE
    -Wall -Wextra -Wno-unused-parameter
    -fvisibility=hidden
)

# Official Node-API runtime and the hilog logging shim. Only portable POSIX,
# Node-API and hilog are used; there are no raw kernel/private system calls.
target_link_libraries(charles_vpn PUBLIC
    libace_napi.z.so
    libhilog_ndk.z.so
)

# On HarmonyOS/bionic pthread lives in libc. On host/other POSIX builds pull in
# the threads library explicitly.
if(NOT OHOS)
    find_package(Threads REQUIRED)
    target_link_libraries(charles_vpn PUBLIC Threads::Threads)
endif()
