#!/bin/sh
# Build and run smoke tests with AddressSanitizer and UndefinedBehaviorSanitizer.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${BUILD_DIR:-$ROOT/build-sanitizers}"
JOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
CC="${CC:-clang}"
CXX="${CXX:-clang++}"

# Release builds compile the GPU encoder once per libavcodec major; set
# DIRECTGATE_HWENC_HEADERS to exercise that here too (see docs/building.md).
set -- -S "$ROOT" -B "$BUILD" -DDIRECTGATE_BUILD_TESTS=ON
if [ -n "${DIRECTGATE_HWENC_HEADERS:-}" ]; then
    set -- "$@" "-DDIRECTGATE_HWENC_HEADERS=$DIRECTGATE_HWENC_HEADERS"
fi
set -- "$@" -DDIRECTGATE_ENABLE_SANITIZERS=ON -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX"
cmake "$@"
cmake --build "$BUILD" -j "$JOBS"

ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=1:halt_on_error=1:strict_string_checks=1}" \
UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}" \
ctest --test-dir "$BUILD" --output-on-failure --no-tests=error
