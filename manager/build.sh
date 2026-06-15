#!/bin/sh
#
# DirectGate Manager build script.
#
# Produces standalone DirectGate Manager executables for the requested
# operating systems and copies them into ./dist with canonical names:
#
#   dist/directgate-manager-windows-x64.exe
#   dist/directgate-manager-macos-x64
#   dist/directgate-manager-linux-x64
#
# Each target is built independently. Targets that cannot be built on the
# current host fail loudly with an explanation -- they are never skipped
# silently.
#
# Usage:
#   ./build.sh --win
#   ./build.sh --mac
#   ./build.sh --linux
#   ./build.sh --win --mac --linux
#
set -e

# Resolve the directory this script lives in (the manager/ project root).
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"

DIST_DIR="$SCRIPT_DIR/dist"
TAURI_DIR="$SCRIPT_DIR/src-tauri"
HOST=$(uname -s)

BUILD_WIN=0
BUILD_MAC=0
BUILD_LINUX=0

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
info() { printf '==> %s\n' "$1"; }
fail() {
    printf 'Error: %s\n' "$1" >&2
    exit 1
}

usage() {
    cat <<'EOF'
DirectGate Manager build script

Usage: ./build.sh [--win] [--mac] [--linux]

  --win       Build Windows x64  -> dist/directgate-manager-windows-x64.exe
  --mac       Build macOS x64    -> dist/directgate-manager-macos-x64
  --linux     Build Linux x64    -> dist/directgate-manager-linux-x64
  -h, --help  Show this help

Targets may be combined, e.g.:  ./build.sh --win --linux
EOF
}

require_cmd() {
    # require_cmd <command> <error message>
    command -v "$1" >/dev/null 2>&1 || fail "$2"
}

preflight() {
    require_cmd node "Node.js was not found. Install Node.js 18+ (https://nodejs.org)."
    require_cmd npm "npm was not found. Install Node.js / npm (https://nodejs.org)."
    require_cmd cargo "Rust/cargo was not found. Install the Rust toolchain (https://rustup.rs)."
    require_cmd rustc "Rust compiler (rustc) was not found. Install the Rust toolchain (https://rustup.rs)."

    if [ ! -d "$SCRIPT_DIR/node_modules" ]; then
        info "Installing frontend dependencies (npm install)"
        npm install
    fi
}

# The default target triple of the active Rust toolchain (e.g. on a Fedora
# system without rustup, this is the only target that is installed).
host_default_target() {
    rustc -vV 2>/dev/null | sed -n 's/^host: //p'
}

# Return success if the given Rust target triple is installed via rustup.
have_rust_target() {
    command -v rustup >/dev/null 2>&1 || return 1
    rustup target list --installed 2>/dev/null | grep -qx "$1"
}

# Ensure a Rust target triple is available, installing it via rustup if needed.
# When rustup is absent (distro-packaged Rust), the host's own default target
# is already usable; any other triple requires rustup and fails clearly.
ensure_rust_target() {
    triple=$1
    if have_rust_target "$triple"; then
        return 0
    fi
    if command -v rustup >/dev/null 2>&1; then
        info "Adding Rust target $triple"
        rustup target add "$triple"
        return 0
    fi
    if [ "$triple" = "$(host_default_target)" ]; then
        info "Using the toolchain's native target $triple"
        return 0
    fi
    fail "Rust target '$triple' is not installed and 'rustup' was not found to add it.
       The active toolchain only provides '$(host_default_target)'.
       Install rustup (https://rustup.rs) and run: rustup target add $triple"
}

# Build the app for a target triple via the Tauri CLI (no installer bundle).
tauri_build() {
    triple=$1
    info "Building with: tauri build --no-bundle --target $triple"
    npm run tauri -- build --no-bundle --target "$triple"
}

# Copy the produced binary into dist/ with the canonical name.
copy_artifact() {
    triple=$1
    src_name=$2
    dest_name=$3
    src="$TAURI_DIR/target/$triple/release/$src_name"
    [ -f "$src" ] || fail "Expected build output was not found: $src"
    cp "$src" "$DIST_DIR/$dest_name"
    info "Produced dist/$dest_name"
}

# ---------------------------------------------------------------------------
# per-target builders
# ---------------------------------------------------------------------------
build_linux() {
    info "=== Linux x64 ==="
    case "$HOST" in
    Linux) : ;;
    *) fail "Building the Linux target requires a Linux host (current host: $HOST).
       Use a Linux machine or container." ;;
    esac

    require_cmd pkg-config "pkg-config is required for the Linux build.
       Install the WebKitGTK 4.1 development packages, e.g.:
         Debian/Ubuntu: apt install libwebkit2gtk-4.1-dev libgtk-3-dev pkg-config build-essential
         Fedora:        dnf install webkit2gtk4.1-devel gtk3-devel pkgconf-pkg-config"

    triple="x86_64-unknown-linux-gnu"
    ensure_rust_target "$triple"
    tauri_build "$triple"
    copy_artifact "$triple" "directgate-manager" "directgate-manager-linux-x64"
}

build_win() {
    info "=== Windows x64 ==="
    case "$HOST" in
    MINGW* | MSYS* | CYGWIN* | Windows_NT)
        triple="x86_64-pc-windows-msvc"
        ;;
    Linux | Darwin)
        triple="x86_64-pc-windows-gnu"
        require_cmd x86_64-w64-mingw32-gcc "Cross-compiling the Windows target from $HOST requires the MinGW-w64 toolchain
       (x86_64-w64-mingw32-gcc), which was not found. Install it with:
         Debian/Ubuntu: apt install gcc-mingw-w64-x86-64
         Fedora:        dnf install mingw64-gcc
         macOS:         brew install mingw-w64
       Note: Tauri Windows cross-builds are best-effort; building on a Windows
       host (target x86_64-pc-windows-msvc) is the supported path."
        ;;
    *)
        fail "Unsupported host for the Windows target: $HOST"
        ;;
    esac

    ensure_rust_target "$triple"
    tauri_build "$triple"
    copy_artifact "$triple" "directgate-manager.exe" "directgate-manager-windows-x64.exe"
}

build_mac() {
    info "=== macOS x64 ==="
    case "$HOST" in
    Darwin) : ;;
    *) fail "Building the macOS target requires a macOS host with the Xcode command line
       tools (current host: $HOST). Apple does not permit cross-compiling macOS
       applications from other platforms; build on a Mac." ;;
    esac

    require_cmd cc "A C compiler (Xcode command line tools) was not found.
       Install it with: xcode-select --install"

    triple="x86_64-apple-darwin"
    ensure_rust_target "$triple"
    tauri_build "$triple"
    copy_artifact "$triple" "directgate-manager" "directgate-manager-macos-x64"
}

# ---------------------------------------------------------------------------
# argument parsing
# ---------------------------------------------------------------------------
if [ "$#" -eq 0 ]; then
    usage
    exit 1
fi

for arg in "$@"; do
    case "$arg" in
    --win) BUILD_WIN=1 ;;
    --mac) BUILD_MAC=1 ;;
    --linux) BUILD_LINUX=1 ;;
    -h | --help)
        usage
        exit 0
        ;;
    *)
        printf 'Error: unknown argument: %s\n\n' "$arg" >&2
        usage
        exit 1
        ;;
    esac
done

# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------
preflight
mkdir -p "$DIST_DIR"

if [ "$BUILD_LINUX" -eq 1 ]; then build_linux; fi
if [ "$BUILD_WIN" -eq 1 ]; then build_win; fi
if [ "$BUILD_MAC" -eq 1 ]; then build_mac; fi

info "Done. Artifacts are in: $DIST_DIR"
