#!/bin/sh
# Build and run the registered smoke tests through CTest's Valgrind driver.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${BUILD_DIR:-$ROOT/build-valgrind}"
JOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"

command -v valgrind >/dev/null 2>&1 || {
    echo "valgrind is required" >&2
    exit 1
}

# Release builds compile the GPU encoder once per libavcodec major; set
# DIRECTGATE_HWENC_HEADERS to exercise that here too (see docs/building.md).
set -- -S "$ROOT" -B "$BUILD" -DDIRECTGATE_BUILD_TESTS=ON
if [ -n "${DIRECTGATE_HWENC_HEADERS:-}" ]; then
    set -- "$@" "-DDIRECTGATE_HWENC_HEADERS=$DIRECTGATE_HWENC_HEADERS"
fi
set -- "$@" -DCMAKE_BUILD_TYPE=RelWithDebInfo -DDIRECTGATE_ENABLE_SANITIZERS=OFF
cmake "$@"
cmake --build "$BUILD" -j "$JOBS"
BUILD="$(cd "$BUILD" && pwd)"

# CTest honors each test's timeout, skip code and environment, and reports
# every failure instead of stopping at the first nonzero executable exit.
ctest -S "$ROOT/tests/run-valgrind.cmake" \
    -D "DIRECTGATE_VALGRIND_BUILD_DIR=$BUILD" \
    --build-config RelWithDebInfo --verbose --output-on-failure --no-tests=error
