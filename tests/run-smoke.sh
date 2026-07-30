#!/bin/sh
# Build and run the smoke tests against the CMake setup (works on Linux/macOS).
# libxutils and libdatachannel come from the git submodules; each test links
# the xcommon library and inherits those deps transitively.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${BUILD_DIR:-$ROOT/build}"

# Number of parallel build jobs.
JOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"

# Configure (idempotent) with the smoke tests enabled.
# Release builds compile the GPU encoder once per libavcodec major; set
# DIRECTGATE_HWENC_HEADERS to exercise that here too (see docs/building.md).
set -- -S "$ROOT" -B "$BUILD" -DDIRECTGATE_BUILD_TESTS=ON
if [ -n "${DIRECTGATE_HWENC_HEADERS:-}" ]; then
    set -- "$@" "-DDIRECTGATE_HWENC_HEADERS=$DIRECTGATE_HWENC_HEADERS"
fi
cmake "$@"

# Build the library, binaries and test executables.
cmake --build "$BUILD" -j "$JOBS"

# Run every registered test, showing output for any that fail.
ctest --test-dir "$BUILD" --output-on-failure
