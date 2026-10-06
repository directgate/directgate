#!/bin/sh
# Build and run smoke tests with GCC coverage; tests/report-coverage.py then
# reports the line and branch coverage they reached.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${BUILD_DIR:-$ROOT/build-coverage}"
JOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
CC="${CC:-gcc}"
CXX="${CXX:-g++}"

# Release builds compile the GPU encoder once per libavcodec major; set
# DIRECTGATE_HWENC_HEADERS to exercise that here too (see docs/building.md).
set -- -S "$ROOT" -B "$BUILD" -DDIRECTGATE_BUILD_TESTS=ON
if [ -n "${DIRECTGATE_HWENC_HEADERS:-}" ]; then
    set -- "$@" "-DDIRECTGATE_HWENC_HEADERS=$DIRECTGATE_HWENC_HEADERS"
fi
set -- "$@" -DDIRECTGATE_ENABLE_COVERAGE=ON -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX"
cmake "$@"
cmake --build "$BUILD" -j "$JOBS"

# Counts add up across runs, and a rebuilt object no longer matches the counts
# an earlier run left for it: start every run from none.
find "$BUILD" -name '*.gcda' -delete

ctest --test-dir "$BUILD" --output-on-failure --no-tests=error
