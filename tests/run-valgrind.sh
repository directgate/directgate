#!/bin/sh
# Build every smoke test and run each executable directly under Valgrind.
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
set -- "$@" -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake "$@"
cmake --build "$BUILD" -j "$JOBS"

TEST_LIST="$BUILD/valgrind-tests.txt"
find "$BUILD/tests" -maxdepth 1 -type f -perm -111 -name '*_smoke' -print | sort > "$TEST_LIST"
[ -s "$TEST_LIST" ] || {
    echo "no smoke test executables found" >&2
    exit 1
}

# Opening a GPU device makes libva dlopen the vendor's driver, and a driver
# that fails to initialise - the ordinary case on a hybrid box, where the
# first render node is not the one that encodes - keeps what it allocated on
# the way. Nothing this agent writes can free it, so the file below excuses
# that one stack and nothing above it.
SUPPRESSIONS="$ROOT/tests/valgrind.supp"

while IFS= read -r test; do
    echo "Valgrind: $(basename "$test")"
    valgrind \
        --leak-check=full \
        --show-leak-kinds=definite,indirect,possible \
        --errors-for-leak-kinds=definite,indirect,possible \
        --suppressions="$SUPPRESSIONS" \
        --track-origins=yes \
        --error-exitcode=1 \
        "$test"
done < "$TEST_LIST"
