#!/bin/sh
# Build and run the coverage-guided wire parser fuzzer (tests/fuzz_wire.c).
# The target recompiles the JSON, package, WebSocket, RTCP and SDP parsers with
# libFuzzer coverage on top of the ASan/UBSan build; xcommon supplies the rest.
#
# Environment:
#   FUZZ_TIME      wall clock seconds to fuzz for (default 60)
#   FUZZ_CORPUS    corpus directory, grown in place (default $BUILD/corpus)
#   FUZZ_ARTIFACTS where crash/leak/timeout reproducers land (default $BUILD/artifacts)
#   FUZZ_MERGE     set to 0 to keep every input instead of minimizing (default 1)
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${BUILD_DIR:-$ROOT/build-fuzz}"
JOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
CC="${CC:-clang}"
CXX="${CXX:-clang++}"

FUZZ_TIME="${FUZZ_TIME:-60}"
CORPUS="${FUZZ_CORPUS:-$BUILD/corpus}"
ARTIFACTS="${FUZZ_ARTIFACTS:-$BUILD/artifacts}"

# libFuzzer is a Clang feature and the target is only useful with the
# sanitizers on; tests/CMakeLists.txt rejects any other combination.
cmake -S "$ROOT" -B "$BUILD" \
    -DDIRECTGATE_BUILD_TESTS=ON \
    -DDIRECTGATE_ENABLE_SANITIZERS=ON \
    -DDIRECTGATE_BUILD_FUZZERS=ON \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX"

# Only the fuzz target and its dependencies. The smoke tests are built and run
# by run-smoke.sh / run-sanitizers.sh and would just cost time here.
cmake --build "$BUILD" --target fuzz_wire -j "$JOBS"

mkdir -p "$CORPUS" "$ARTIFACTS"

# -artifact_prefix keeps reproducers out of the working directory so a caller
# (CI) can collect them from one place. libFuzzer exits non-zero on a crash,
# leak or timeout and set -e stops here, which is what makes this a gate.
ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=1:halt_on_error=1:strict_string_checks=1}" \
UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}" \
"$BUILD/tests/fuzz_wire" "$CORPUS" \
    -max_total_time="$FUZZ_TIME" \
    -max_len=65536 \
    -print_final_stats=1 \
    -artifact_prefix="$ARTIFACTS/"

# Minimize before the corpus is stored: -merge=1 keeps only the inputs that
# still contribute coverage, so a corpus carried between runs starts them warm
# without growing without bound.
if [ "${FUZZ_MERGE:-1}" != "0" ]; then
    MERGED="$BUILD/corpus-min"
    rm -rf "$MERGED"
    mkdir -p "$MERGED"
    "$BUILD/tests/fuzz_wire" "$MERGED" "$CORPUS" -merge=1 -max_len=65536
    rm -rf "$CORPUS"
    mv "$MERGED" "$CORPUS"
fi
