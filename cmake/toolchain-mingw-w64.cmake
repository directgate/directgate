# CMake toolchain file for cross-compiling the directgate agent to Windows
# (x86_64) from Linux/macOS using a MinGW-w64 toolchain (gcc or llvm-mingw).
#
# Usage:
#   cmake -B build-win64 -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-mingw-w64.cmake \
#         [-DMINGW_TOOLCHAIN_ROOT=/path/to/llvm-mingw] \
#         [-DCMAKE_PREFIX_PATH=/path/to/win64-deps-prefix]
#   cmake --build build-win64
#
# MINGW_TOOLCHAIN_ROOT is optional; when unset, the x86_64-w64-mingw32-* tools
# are looked up in PATH (works with distro mingw64-* packages and llvm-mingw).

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

set(MINGW_TOOLCHAIN_ROOT "" CACHE PATH "Root of the MinGW-w64 toolchain (optional)")

if(MINGW_TOOLCHAIN_ROOT)
    set(_mingw_bin "${MINGW_TOOLCHAIN_ROOT}/bin/")
else()
    set(_mingw_bin "")
endif()

set(CMAKE_C_COMPILER   "${_mingw_bin}x86_64-w64-mingw32-gcc")
set(CMAKE_CXX_COMPILER "${_mingw_bin}x86_64-w64-mingw32-g++")
set(CMAKE_RC_COMPILER  "${_mingw_bin}x86_64-w64-mingw32-windres")

# Search headers/libraries only in the target environment, programs on host.
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

if(MINGW_TOOLCHAIN_ROOT)
    list(APPEND CMAKE_FIND_ROOT_PATH "${MINGW_TOOLCHAIN_ROOT}/x86_64-w64-mingw32")
endif()

# Cross-built dependencies (e.g. OpenSSL) live under CMAKE_PREFIX_PATH, which
# must also be a find root so find_package() can see it.
if(CMAKE_PREFIX_PATH)
    list(APPEND CMAKE_FIND_ROOT_PATH ${CMAKE_PREFIX_PATH})
endif()
