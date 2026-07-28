cmake_minimum_required(VERSION 3.21)
project(directgate LANGUAGES C CXX)

# ---------------------------------------------------------------------------
# Single cross-platform (Linux + macOS) build for the directgate agent and client.
# libxutils and libdatachannel are built from the bundled git submodules.
#
#   git submodule update --init --recursive
#   cmake -B build
#   cmake --build build          # builds submodules -> libxcommon -> binaries
#   sudo make -C build install    # installs the two binaries into /usr/bin
# ---------------------------------------------------------------------------

# Where the binaries land on `make install`. Absolute, so it ignores
# CMAKE_INSTALL_PREFIX. Linux drops them straight into /usr/bin; on macOS that
# path is read-only (SIP), so the writable, conventional /usr/local/bin is used.
if(APPLE)
    set(_directgate_default_bindir "/usr/local/bin")
elseif(WIN32)
    # No absolute system path on Windows: install under the chosen prefix
    # (e.g. C:\Program Files\directgate\bin).
    set(_directgate_default_bindir "bin")
else()
    set(_directgate_default_bindir "/usr/bin")
endif()
set(DIRECTGATE_INSTALL_BINDIR "${_directgate_default_bindir}" CACHE PATH "Install directory for directgate binaries")

# ---- Project layout -------------------------------------------------------
set(SRC_DIR        "${CMAKE_CURRENT_SOURCE_DIR}/src")
set(COMMON_DIR     "${SRC_DIR}/common")
set(AGENT_DIR       "${SRC_DIR}/agent")
set(CLIENT_DIR     "${SRC_DIR}/client")
set(LIBXUTILS_DIR  "${CMAKE_CURRENT_SOURCE_DIR}/libxutils")
set(DATACHANNEL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/libdatachannel")

if(NOT EXISTS "${LIBXUTILS_DIR}/CMakeLists.txt" OR NOT EXISTS "${DATACHANNEL_DIR}/CMakeLists.txt")
    message(FATAL_ERROR
        "Submodules are missing. Run: git submodule update --init --recursive")
endif()

set(CMAKE_C_STANDARD 11)

# ---- Security and diagnostics --------------------------------------------
option(DIRECTGATE_ENABLE_HARDENING "Enable compiler and linker hardening" ON)
option(DIRECTGATE_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(DIRECTGATE_DEBUG "Enable DirectGate debug mode" OFF)

# ---- Build tag -------------------------------------------------------------
# Identifies the build channel/architecture and is appended to the agent
# version string, e.g. 1.0.19-5-amd64_deb. Package builds pass it explicitly
# (-DDIRECTGATE_BUILD_TAG=amd64_deb); source builds fall back to <arch>_<os>
# (e.g. x86_64_linux, arm64_macos). Must stay a single [a-z][a-z0-9_]* token:
# the API parses the version as "MAJOR.MINOR.BUILD-PKG[-TAG]" and a tag that
# starts with a digit would be ambiguous against the numeric PKG part.
set(DIRECTGATE_BUILD_TAG "" CACHE STRING "Build channel tag appended to the agent version (e.g. amd64_deb)")
if(NOT DIRECTGATE_BUILD_TAG)
    string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" _dg_tag_arch)
    if(_dg_tag_arch STREQUAL "aarch64")
        set(_dg_tag_arch "arm64")
    endif()
    string(TOLOWER "${CMAKE_SYSTEM_NAME}" _dg_tag_os)
    if(_dg_tag_os STREQUAL "darwin")
        set(_dg_tag_os "macos")
    endif()
    string(REGEX REPLACE "[^a-z0-9_]" "_" _dg_tag_arch "${_dg_tag_arch}")
    string(REGEX REPLACE "[^a-z0-9_]" "_" _dg_tag_os "${_dg_tag_os}")
    set(DIRECTGATE_BUILD_TAG "${_dg_tag_arch}_${_dg_tag_os}")
endif()
if(NOT DIRECTGATE_BUILD_TAG MATCHES "^[a-z][a-z0-9_]*$")
    message(FATAL_ERROR "DIRECTGATE_BUILD_TAG must match [a-z][a-z0-9_]*, got: ${DIRECTGATE_BUILD_TAG}")
endif()
# Cap the length: the API truncates stored agent versions at 96 chars and the
# enroll request bodies are built in fixed 4 KiB buffers, so an oversized tag
# would fail at runtime in confusing ways instead of here.
string(LENGTH "${DIRECTGATE_BUILD_TAG}" _dg_tag_len)
if(_dg_tag_len GREATER 32)
    message(FATAL_ERROR "DIRECTGATE_BUILD_TAG must be at most 32 characters, got ${_dg_tag_len}: ${DIRECTGATE_BUILD_TAG}")
endif()
message(STATUS "DirectGate build tag: ${DIRECTGATE_BUILD_TAG}")

if(DIRECTGATE_ENABLE_HARDENING AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
    include(CheckPIESupported)
    check_pie_supported()

    add_compile_options(-fstack-protector-strong)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_link_options(-Wl,-z,relro -Wl,-z,now)
    elseif(WIN32)
        # PE hardening (MinGW): DEP, ASLR with high entropy on x64.
        add_link_options(-Wl,--nxcompat -Wl,--dynamicbase -Wl,--high-entropy-va)
    endif()
endif()

if(DIRECTGATE_ENABLE_HARDENING AND MSVC)
    # PE hardening (MSVC): stack cookies, Control Flow Guard, DEP, ASLR.
    add_compile_options(/GS /guard:cf)
    add_link_options(/GUARD:CF /NXCOMPAT /DYNAMICBASE /HIGHENTROPYVA)
endif()

if(DIRECTGATE_ENABLE_SANITIZERS)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        message(FATAL_ERROR "DIRECTGATE_ENABLE_SANITIZERS requires GCC or Clang")
    endif()

    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

# Add the directory of every linked library to the RPATH (mirrors old -rpath).
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH ON)

# ---- Dependencies ---------------------------------------------------------
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# OpenSSL. Homebrew keeps it keg-only on macOS, so point CMake at it.
if(APPLE)
    execute_process(
        COMMAND brew --prefix openssl
        OUTPUT_VARIABLE BREW_OPENSSL_PREFIX
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET)
    if(BREW_OPENSSL_PREFIX)
        set(OPENSSL_ROOT_DIR "${BREW_OPENSSL_PREFIX}")
    endif()
endif()
find_package(OpenSSL REQUIRED)

# libutil provides forkpty()/openpty() used by the agent PTY layer.
# Windows uses ConPTY from kernel32 instead, no extra library needed.
if(NOT WIN32)
    find_library(UTIL_LIBRARY NAMES util)
endif()

# ---- libdatachannel (submodule, WebRTC P2P) -------------------------------
# Built statically so the installed binaries are self-contained and don't need
# a system-wide libdatachannel.so. Examples/tests off; EXCLUDE_FROM_ALL keeps
# its install rules out of our `make install`.
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(NO_EXAMPLES ON CACHE BOOL "" FORCE)
set(NO_TESTS ON CACHE BOOL "" FORCE)
# Media transport (RTP/SRTP) is enabled so the desktop streaming pipeline can
# push H.264 over a negotiated WebRTC video track (see desktop.c / webrtc.c
# DirectGate_WebRTC_SendH264AnnexB). The bundled deps/libsrtp needs CMake >= 3.21,
# which is also the minimum declared by this project. WebSocket stays off
# because DirectGate does not use libdatachannel's WebSocket implementation.
set(NO_MEDIA OFF CACHE BOOL "" FORCE)
set(NO_WEBSOCKET ON CACHE BOOL "" FORCE)
if(WIN32)
    # The bundled libsrtp builds itself with -Werror and trips over benign
    # format warnings on Windows (winsock's ntohl returns u_long). Vendor
    # code must not fail our cross-build over its own warnings.
    set(ENABLE_WARNINGS_AS_ERRORS OFF CACHE BOOL "" FORCE)
endif()
add_subdirectory(${DATACHANNEL_DIR} EXCLUDE_FROM_ALL)

# ---- libxutils (submodule) ------------------------------------------------
# Built from its own CMakeLists (target name: xutils). EXCLUDE_FROM_ALL keeps
# its install rules out of our `make install`, while still building because the
# binaries depend on it. Added before the compile options below so it keeps its
# own flags untouched.
add_subdirectory(${LIBXUTILS_DIR} EXCLUDE_FROM_ALL)

# Header search paths shared by every component (matches the old -I flags).
# libdatachannel's headers come transitively from its target.
set(DIRECTGATE_INCLUDE_DIRS
    ${SRC_DIR}
    ${COMMON_DIR}
    ${LIBXUTILS_DIR}
    ${LIBXUTILS_DIR}/src
    ${LIBXUTILS_DIR}/src/crypt
    ${LIBXUTILS_DIR}/src/data
    ${LIBXUTILS_DIR}/src/net
    ${LIBXUTILS_DIR}/src/sys)

# ---- Build flags for our own targets --------------------------------------
if(MSVC)
    add_compile_options(/O2 /W3)
else()
    add_compile_options(-g -O2 -Wall -Wextra)
endif()
add_compile_definitions(_XCHECK_LOG)

if(WIN32)
    # Target Windows 10 1809+: required for ConPTY (CreatePseudoConsole).
    # WIN32_LEAN_AND_MEAN keeps windows.h from dragging in winsock.h, which
    # conflicts with the winsock2.h used by libxutils and libdatachannel.
    add_compile_definitions(_WIN32_WINNT=0x0A00 WIN32_LEAN_AND_MEAN NOMINMAX)

    if(NOT MSVC)
        # Self-contained binaries: statically link the MinGW runtime
        # (libc++/libstdc++, libunwind/libgcc, winpthread). Without this the
        # executable imports toolchain DLLs that exist only on the build
        # machine, and on a clean Windows host the loader kills the process
        # before main() with STATUS_DLL_NOT_FOUND - no output, no error.
        add_link_options(-static)
    endif()
endif()

if(DIRECTGATE_DEBUG)
    add_compile_definitions(DIRECTGATE_DEBUG)
endif()

if(NOT APPLE AND NOT WIN32)
    add_compile_definitions(_XUTILS_USE_GNU)
    if(DIRECTGATE_ENABLE_HARDENING)
        add_compile_definitions(_FORTIFY_SOURCE=2)
    endif()
endif()

# ---- libxcommon (shared protocol / auth / webrtc / transfer code) ---------
add_library(xcommon STATIC
    ${COMMON_DIR}/auth.c
    ${COMMON_DIR}/common.c
    ${COMMON_DIR}/e2e.c
    ${COMMON_DIR}/hkdf.c
    ${COMMON_DIR}/keyauth.c
    ${COMMON_DIR}/logger.c
    ${COMMON_DIR}/protocol.c
    ${COMMON_DIR}/siv.c
    ${COMMON_DIR}/srp.c
    ${COMMON_DIR}/transfer.c
    ${COMMON_DIR}/version.c
    ${COMMON_DIR}/webrtc.c
    ${COMMON_DIR}/websock.c)
target_include_directories(xcommon PUBLIC ${DIRECTGATE_INCLUDE_DIRS})
# Only version.c consumes the tag; PRIVATE keeps it out of dependents' flags.
target_compile_definitions(xcommon PRIVATE DIRECTGATE_BUILD_TAG="${DIRECTGATE_BUILD_TAG}")
target_link_libraries(xcommon PUBLIC
    xutils
    LibDataChannel::LibDataChannel
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads)

if(WIN32)
    # ws2_32/iphlpapi: Winsock and interface enumeration (libxutils, libjuice)
    # crypt32/bcrypt: certificate store and CNG entropy used by static OpenSSL
    target_link_libraries(xcommon PUBLIC ws2_32 iphlpapi crypt32 bcrypt)
else()
    target_link_libraries(xcommon PUBLIC m)
endif()

# ---- agent binary: directgate --------------------------------------------------
# The desktop controller lives under ${AGENT_DIR}/desktop and is cross-platform,
# split by concern: desktop.c (shared state/geometry), display.c (monitor
# enumeration + display mode), input.c (pointer/keyboard injection) and
# stream.c (frame timer/capture/control) all carry the X11 (Linux), macOS,
# Windows and a no-op fallback path inline behind #if guards. The platform
# capture/encode pipelines live in desktop_mac.m (ScreenCaptureKit/VideoToolbox, Apple
# only) and desktop_win.c (DXGI Desktop Duplication/Media Foundation, added below).
add_executable(directgate
    ${AGENT_DIR}/config.c
    ${AGENT_DIR}/desktop/desktop.c
    ${AGENT_DIR}/desktop/display.c
    ${AGENT_DIR}/desktop/input.c
    ${AGENT_DIR}/desktop/stream.c
    ${AGENT_DIR}/enroll.c
    ${AGENT_DIR}/files.c
    ${AGENT_DIR}/search.c
    ${AGENT_DIR}/session.c
    ${AGENT_DIR}/term.c
    ${AGENT_DIR}/directgate.c)
target_include_directories(directgate PRIVATE ${AGENT_DIR} ${AGENT_DIR}/desktop)
target_link_libraries(directgate PRIVATE xcommon)

# ---- desktop streaming backends (platform specific) -----------------------
if(APPLE)
    # macOS screen capture + VideoToolbox H.264 encoder. Compiled with ARC.
    # System-audio streaming: Opus encoder (opus.c, libopus dlopen'd) + the
    # cross-platform orchestrator (desktop/audio.c) + ScreenCaptureKit audio
    # capture (desktop/audio_mac.m, also ARC).
    target_sources(directgate PRIVATE
        ${AGENT_DIR}/desktop/desktop_mac.m
        ${AGENT_DIR}/desktop/opus.c
        ${AGENT_DIR}/desktop/audio.c
        ${AGENT_DIR}/desktop/audio_mac.m)
    set_source_files_properties(${AGENT_DIR}/desktop/desktop_mac.m ${AGENT_DIR}/desktop/audio_mac.m
        PROPERTIES COMPILE_OPTIONS "-fobjc-arc")
    target_link_libraries(directgate PRIVATE
        "-framework ApplicationServices"
        "-framework Carbon"
        "-framework Foundation"
        "-framework CoreMedia"
        "-framework CoreVideo"
        "-framework CoreGraphics"
        "-framework VideoToolbox"
        "-framework ScreenCaptureKit")
elseif(UNIX)
    # Linux X11 capture + XTest input (XTest is dlopen'd at runtime, hence dl).
    # The H.264 pipeline lives in desktop/desktop_linux.c (XShm capture) with
    # openh264.c (encoder, dlopen'd at runtime - only the vendored
    # API headers under src/agent/openh264 are needed at build time) and
    # yuv.c (BGRA scaling + I420 conversion). XShm needs Xext.
    find_package(X11 REQUIRED)
    target_sources(directgate PRIVATE
        ${AGENT_DIR}/desktop/desktop_linux.c
        ${AGENT_DIR}/desktop/openh264.c
        ${AGENT_DIR}/yuv.c)
    # System-audio streaming: Opus encoder (opus.c, libopus dlopen'd at runtime)
    # + cross-platform orchestrator (desktop/audio.c) + PulseAudio/PipeWire
    # monitor capture (desktop/audio_linux.c, libpulse-simple dlopen'd). All
    # runtime-only deps, so a host without them still streams video.
    target_sources(directgate PRIVATE
        ${AGENT_DIR}/desktop/opus.c
        ${AGENT_DIR}/desktop/audio.c
        ${AGENT_DIR}/desktop/audio_linux.c)
    # GPU H.264 encoding (desktop/hwenc.c): NVENC / VAAPI / QSV / AMF reached
    # through libavcodec, which is dlopen'd at runtime like OpenH264 - only
    # the headers are needed here, and only to get struct layouts right. The
    # loader refuses a runtime libavcodec whose major soname differs from the
    # one found now, so this is compiled against exactly what it accepts.
    # Without the headers the feature vanishes and the software encoder is
    # the only path; nothing about the package dependencies changes either
    # way, because the library is never linked.
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(LIBAV libavcodec libavutil)
    endif()
    if(LIBAV_FOUND)
        message(STATUS "GPU desktop encoding: enabled (libavcodec ${LIBAV_libavcodec_VERSION}, runtime dlopen)")
        target_sources(directgate PRIVATE ${AGENT_DIR}/desktop/hwenc.c)
        target_compile_definitions(directgate PRIVATE DIRECTGATE_HAVE_HWENC=1)
        target_include_directories(directgate PRIVATE ${LIBAV_INCLUDE_DIRS})
    else()
        message(STATUS "GPU desktop encoding: disabled (libavcodec headers not found)")
    endif()

    target_include_directories(directgate PRIVATE ${X11_INCLUDE_DIR} ${AGENT_DIR}/openh264)
    target_link_libraries(directgate PRIVATE ${X11_LIBRARIES} ${CMAKE_DL_LIBS})
    if(X11_Xrandr_FOUND)
        target_link_libraries(directgate PRIVATE ${X11_Xrandr_LIB})
    else()
        target_link_libraries(directgate PRIVATE Xrandr)
    endif()
    if(X11_Xext_FOUND)
        target_link_libraries(directgate PRIVATE ${X11_Xext_LIB})
    else()
        target_link_libraries(directgate PRIVATE Xext)
    endif()
endif()

if(WIN32)
    # Privilege-separation launcher (see src/agent/launcher.c): a tiny LocalSystem
    # supervisor that spawns the agent as shell.user via a logon token. Windows
    # only; the POSIX setuid model is unchanged.
    target_sources(directgate PRIVATE ${AGENT_DIR}/launcher.c)
    # advapi32: LookupAccountName + token queries. wtsapi32: WTSEnumerateSessions
    # / WTSQueryUserToken (shell.user logon token). userenv: CreateEnvironmentBlock.
    target_link_libraries(directgate PRIVATE advapi32 wtsapi32 userenv)

    # Windows desktop streaming: DXGI Desktop Duplication capture (GDI
    # fallback) in desktop/desktop_win.c with a Media Foundation H.264 encoder in
    # mfenc.c (mfplat.dll is loaded at runtime - N editions ship without
    # Media Foundation - so only static GUID archives are linked, no
    # mfplat import) and yuv.c (BGRA scaling + NV12 conversion).
    # user32/gdi32: monitors, SendInput, BitBlt. d3d11/dxgi: duplication.
    # ole32/oleaut32: COM apartment + VARIANT for ICodecAPI.
    # uuid/mfuuid/strmiids/dxguid: interface and media type GUIDs.
    target_sources(directgate PRIVATE
        ${AGENT_DIR}/desktop/desktop_win.c
        ${AGENT_DIR}/desktop/mfenc.c
        ${AGENT_DIR}/yuv.c)
    # System-audio streaming: Opus encoder (opus.c) + the cross-platform
    # orchestrator (desktop/audio.c) + WASAPI loopback capture
    # (desktop/audio_win.c). WASAPI GUIDs are instantiated locally via
    # initguid.h, so ole32 (already linked) is enough. Unlike Linux/macOS (which
    # dlopen libopus), Windows links it statically from the toolchain prefix
    # (like OpenSSL) so the self-contained exe never needs a runtime opus.dll -
    # DIRECTGATE_OPUS_STATIC switches opus.c to direct calls.
    # Force the static libopus.a: MSYS2 also ships an import lib (libopus.dll.a)
    # that find_library would otherwise prefer, reintroducing a runtime DLL and
    # breaking the self-contained-exe guarantee.
    set(_dg_saved_suffixes "${CMAKE_FIND_LIBRARY_SUFFIXES}")
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    find_library(DIRECTGATE_OPUS_LIB NAMES opus REQUIRED)
    set(CMAKE_FIND_LIBRARY_SUFFIXES "${_dg_saved_suffixes}")
    target_sources(directgate PRIVATE
        ${AGENT_DIR}/desktop/opus.c
        ${AGENT_DIR}/desktop/audio.c
        ${AGENT_DIR}/desktop/audio_win.c)
    target_compile_definitions(directgate PRIVATE DIRECTGATE_OPUS_STATIC=1)
    target_link_libraries(directgate PRIVATE
        user32 gdi32 d3d11 dxgi ole32 oleaut32 uuid mfuuid strmiids dxguid
        ${DIRECTGATE_OPUS_LIB})

    # App manifest (UTF-8 active code page) + version / company metadata.
    enable_language(RC)
    target_sources(directgate PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/misc/win/directgate.rc")
endif()

if(UTIL_LIBRARY)
    target_link_libraries(directgate PRIVATE ${UTIL_LIBRARY})
endif()

# ---- client binary: dgcli ------------------------------------------------
add_executable(dgcli
    ${CLIENT_DIR}/client.c
    ${CLIENT_DIR}/config.c
    ${CLIENT_DIR}/devices.c
    ${CLIENT_DIR}/relay.c)
target_include_directories(dgcli PRIVATE ${CLIENT_DIR})
target_link_libraries(dgcli PRIVATE xcommon)

if(WIN32)
    enable_language(RC)
    target_sources(dgcli PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/misc/win/dgcli.rc")
endif()

if(UTIL_LIBRARY)
    target_link_libraries(dgcli PRIVATE ${UTIL_LIBRARY})
endif()

# ---- install --------------------------------------------------------------
install(TARGETS directgate dgcli RUNTIME DESTINATION "${DIRECTGATE_INSTALL_BINDIR}")

# Also install a system service that runs the agent as the installing user,
# substituting the real user/home for the placeholders at install time:
#   Linux  -> systemd unit   (misc/directgate-agent.service)
#   macOS  -> launchd daemon (misc/io.directgate.agent.plist)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(DIRECTGATE_SYSTEMD_DIR "/etc/systemd/system" CACHE PATH "systemd unit install directory")
    set(DIRECTGATE_SERVICE_TEMPLATE "${CMAKE_CURRENT_SOURCE_DIR}/misc/directgate-agent.service")
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/install-service.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/install-service.cmake"
        @ONLY)
    install(SCRIPT "${CMAKE_CURRENT_BINARY_DIR}/install-service.cmake")
elseif(APPLE)
    set(DIRECTGATE_LAUNCHD_DIR "/Library/LaunchDaemons" CACHE PATH "launchd daemon install directory")
    set(DIRECTGATE_LAUNCHD_TEMPLATE "${CMAKE_CURRENT_SOURCE_DIR}/misc/io.directgate.agent.plist")
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/install-service-macos.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/install-service-macos.cmake"
        @ONLY)
    install(SCRIPT "${CMAKE_CURRENT_BINARY_DIR}/install-service-macos.cmake")
endif()

# ---- smoke tests (opt-in) -------------------------------------------------
# Off by default so the normal build stays lean. tests/run-smoke.sh turns it
# on. Each test links xcommon and thus inherits libxutils / libdatachannel /
# OpenSSL transitively.
option(DIRECTGATE_BUILD_TESTS "Build the smoke tests" OFF)
if(DIRECTGATE_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
