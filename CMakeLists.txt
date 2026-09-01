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
# FindOpenSSL adds ZLIB::ZLIB to OpenSSL::Crypto's link interface whenever
# OPENSSL_USE_STATIC_LIBS is on, because a static libcrypto may have been built
# with zlib support and nothing else can resolve it. The target has to exist by
# then or the link fails with "cannot find -lZLIB::ZLIB". Harmless for the
# normal dynamic build, which never references it.
find_package(ZLIB QUIET)
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

# libjuice keeps each ICE description in a fixed array and silently drops every
# remote candidate past the limit, which its own default sets at 30. A browser
# offered several TURN servers produces host, server-reflexive and relay
# candidates for each of them and goes past that easily, and the ones that fall
# off are whichever trickled in last - not the least useful. It still connects
# while a usable pair happens to land inside the limit, so the failure mode is
# a connection that works until the day it doesn't.
#
# 48 leaves comfortable headroom over what browsers actually send. The cost is
# the fixed array: a juice agent grows from ~67 KB to ~106 KB, so ~1.2 MB
# across the 32-session ceiling. The header guards the value with #ifndef, so
# this needs no patch to the vendored source.
foreach(_juice_target juice juice-static)
    if(TARGET ${_juice_target})
        target_compile_definitions(${_juice_target} PRIVATE ICE_MAX_CANDIDATES_COUNT=48)
    endif()
endforeach()

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
    #
    # That silent fallback is fine for a source build on a machine that simply
    # has no FFmpeg development package, but it is not acceptable for a
    # release artifact: the decision is baked in at compile time, so a package
    # built without the headers can never do GPU encoding on any host, no
    # matter what the user installs afterwards. The package builds turn this
    # on so a build image that has lost its FFmpeg headers fails here instead
    # of shipping a permanently software-only agent.
    #
    # One set of headers gets one major, and that is only ever right for the
    # hosts running the same one. DIRECTGATE_HWENC_HEADERS points at a
    # directory of per-major header trees (misc/ffmpeg-headers.sh builds
    # one); hwenc.c is then compiled once per tree and
    # desktop/hwenc_abi.c picks the variant whose library the host actually
    # has. A plain source build passes nothing and keeps the single
    # pkg-config variant below, compiled against whatever FFmpeg is installed.
    option(DIRECTGATE_REQUIRE_HWENC "Fail the build if GPU desktop encoding cannot be compiled in" OFF)
    option(DIRECTGATE_REQUIRE_WAYLAND "Fail the build if Wayland desktop streaming cannot be compiled in" OFF)
    set(DIRECTGATE_HWENC_HEADERS "" CACHE PATH
        "Directory of per-libavcodec-major FFmpeg header trees (<major>/libavcodec, <major>/libavutil)")

    set(DIRECTGATE_HWENC_ABIS "")
    if(DIRECTGATE_HWENC_HEADERS)
        file(GLOB _dg_hwenc_dirs RELATIVE "${DIRECTGATE_HWENC_HEADERS}" "${DIRECTGATE_HWENC_HEADERS}/*")
        foreach(_dg_abi IN LISTS _dg_hwenc_dirs)
            if(_dg_abi MATCHES "^[0-9]+$" AND
               EXISTS "${DIRECTGATE_HWENC_HEADERS}/${_dg_abi}/libavcodec/avcodec.h" AND
               EXISTS "${DIRECTGATE_HWENC_HEADERS}/${_dg_abi}/libavutil/avutil.h")
                list(APPEND DIRECTGATE_HWENC_ABIS "${_dg_abi}")
            endif()
        endforeach()

        list(SORT DIRECTGATE_HWENC_ABIS)
        if(NOT DIRECTGATE_HWENC_ABIS)
            message(FATAL_ERROR
                "DIRECTGATE_HWENC_HEADERS is set to '${DIRECTGATE_HWENC_HEADERS}' but holds no "
                "usable <major>/libavcodec + <major>/libavutil header tree. Run "
                "misc/ffmpeg-headers.sh to populate it.")
        endif()
    endif()

    find_package(PkgConfig QUIET)
    if(NOT DIRECTGATE_HWENC_ABIS AND PKG_CONFIG_FOUND)
        pkg_check_modules(LIBAV libavcodec libavutil)
        # Zero-copy on Wayland needs the GPU post-processor, which only
        # libavfilter exposes. Optional on purpose: without it the agent
        # builds and runs exactly as before, and DMA-BUF frames are simply
        # never asked for.
        pkg_check_modules(LIBAVFILTER libavfilter)
    endif()

    if(DIRECTGATE_HWENC_ABIS)
        message(STATUS "GPU desktop encoding: enabled for libavcodec ${DIRECTGATE_HWENC_ABIS} (runtime dlopen)")
        target_sources(directgate PRIVATE ${AGENT_DIR}/desktop/hwenc_abi.c)
        target_compile_definitions(directgate PRIVATE DIRECTGATE_HAVE_HWENC=1)

        # An object library per major: the same source has to be compiled with
        # a different include path each time, which a single target cannot
        # express. Linking xcommon carries the project's include directories
        # over without repeating them.
        foreach(_dg_abi IN LISTS DIRECTGATE_HWENC_ABIS)
            add_library(directgate_hwenc_${_dg_abi} OBJECT ${AGENT_DIR}/desktop/hwenc.c)
            target_include_directories(directgate_hwenc_${_dg_abi} BEFORE PRIVATE
                "${DIRECTGATE_HWENC_HEADERS}/${_dg_abi}")
            target_include_directories(directgate_hwenc_${_dg_abi} PRIVATE
                ${AGENT_DIR} ${AGENT_DIR}/desktop)
            target_compile_definitions(directgate_hwenc_${_dg_abi} PRIVATE
                DIRECTGATE_HAVE_HWENC=1
                DIRECTGATE_HWENC_ABI=${_dg_abi})

            # Per major, like everything else here: a header tree that
            # predates the script's libavfilter support still builds, it
            # just has no zero-copy path.
            if(EXISTS "${DIRECTGATE_HWENC_HEADERS}/${_dg_abi}/libavfilter/avfilter.h")
                target_compile_definitions(directgate_hwenc_${_dg_abi} PRIVATE
                    DIRECTGATE_HWENC_HAS_FILTER=1)
            else()
                message(STATUS
                    "GPU desktop encoding: libavcodec ${_dg_abi} has no libavfilter headers, "
                    "Wayland zero-copy disabled for it (re-run misc/ffmpeg-headers.sh)")
            endif()
            target_link_libraries(directgate_hwenc_${_dg_abi} PRIVATE xcommon)

            target_sources(directgate PRIVATE $<TARGET_OBJECTS:directgate_hwenc_${_dg_abi}>)
            target_compile_definitions(directgate PRIVATE DIRECTGATE_HWENC_HAS_${_dg_abi}=1)
        endforeach()
    elseif(LIBAV_FOUND)
        message(STATUS "GPU desktop encoding: enabled (libavcodec ${LIBAV_libavcodec_VERSION}, runtime dlopen)")
        target_sources(directgate PRIVATE ${AGENT_DIR}/desktop/hwenc.c)
        target_compile_definitions(directgate PRIVATE DIRECTGATE_HAVE_HWENC=1)
        target_include_directories(directgate PRIVATE ${LIBAV_INCLUDE_DIRS})

        if(LIBAVFILTER_FOUND)
            message(STATUS "Wayland zero-copy encoding: enabled (libavfilter ${LIBAVFILTER_VERSION} headers, runtime dlopen)")
            target_compile_definitions(directgate PRIVATE DIRECTGATE_HWENC_HAS_FILTER=1)
            target_include_directories(directgate PRIVATE ${LIBAVFILTER_INCLUDE_DIRS})
        else()
            message(STATUS "Wayland zero-copy encoding: disabled (libavfilter headers not found)")
        endif()
    elseif(DIRECTGATE_REQUIRE_HWENC)
        message(FATAL_ERROR
            "GPU desktop encoding was required but no libavcodec/libavutil headers "
            "were found. Point DIRECTGATE_HWENC_HEADERS at per-major header trees "
            "(misc/ffmpeg-headers.sh), install the FFmpeg development package for this "
            "build image (libavcodec-dev + libavutil-dev on Debian, ffmpeg-devel on "
            "RHEL), or configure with -DDIRECTGATE_REQUIRE_HWENC=OFF to accept a "
            "software-only agent.")
    else()
        message(STATUS "GPU desktop encoding: disabled (libavcodec headers not found)")
    endif()

    # Wayland desktop streaming (desktop/wayland_*.c + desktop/desktop_wayland.c).
    # A Wayland client cannot read the screen or synthesise input on its own,
    # so both come from xdg-desktop-portal over D-Bus and the pixels arrive
    # over PipeWire. Like libavcodec above, only the headers are used here:
    # libpipewire-0.3 and libdbus-1 are dlopen'd at runtime and never linked,
    # so this adds no package dependency and an X11 host without either
    # library runs exactly as it does today. Without the headers the feature
    # is simply absent and the X11 build is unchanged.
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(PIPEWIRE libpipewire-0.3)
        pkg_check_modules(DBUS dbus-1)
    endif()

    if(PIPEWIRE_FOUND AND DBUS_FOUND)
        message(STATUS "Wayland desktop streaming: enabled (PipeWire ${PIPEWIRE_VERSION} headers, runtime dlopen)")
        target_sources(directgate PRIVATE
            ${AGENT_DIR}/desktop/wayland_capture.c
            ${AGENT_DIR}/desktop/wayland_portal.c
            ${AGENT_DIR}/desktop/desktop_wayland.c)
        target_compile_definitions(directgate PRIVATE DIRECTGATE_DESKTOP_HAS_WAYLAND=1)
        # SYSTEM, so the warning settings this project builds itself with do
        # not apply to somebody else's headers. SPA is header-only and full of
        # designated-initializer macros that -Wmissing-field-initializers
        # objects to; those warnings are reported against the macro, which
        # lives in their header, so nothing this agent writes can silence them
        # and nothing it writes is what they are about.
        target_include_directories(directgate SYSTEM PRIVATE ${PIPEWIRE_INCLUDE_DIRS} ${DBUS_INCLUDE_DIRS})
    else()
        # Name what is missing and what installs it. "Headers not found" on its
        # own sends people looking at their Wayland session, which is working
        # fine - the gap is a build dependency, and it is only a header one.
        set(_dg_wl_missing "")
        if(NOT PIPEWIRE_FOUND)
            list(APPEND _dg_wl_missing "libpipewire-0.3")
        endif()
        if(NOT DBUS_FOUND)
            list(APPEND _dg_wl_missing "dbus-1")
        endif()
        if(NOT PKG_CONFIG_FOUND)
            set(_dg_wl_missing "pkg-config")
        endif()
        string(REPLACE ";" ", " _dg_wl_missing "${_dg_wl_missing}")

        # A released package must never be quietly X11-only: the machines it is
        # installed on decide whether they run Wayland, not the image it was
        # built in, and someone finding out from a stranger's desktop is far
        # too late. The packaging builds therefore ask for this and the build
        # stops here rather than shipping the feature missing.
        if(DIRECTGATE_REQUIRE_WAYLAND)
            message(FATAL_ERROR
                "Wayland desktop streaming was required but its headers were not found "
                "(missing: ${_dg_wl_missing}). Install the development packages in this "
                "build image (libpipewire-0.3-dev + libdbus-1-dev on Debian, "
                "pipewire-devel + dbus-devel on RHEL), or configure with "
                "-DDIRECTGATE_REQUIRE_WAYLAND=OFF to accept an X11-only agent. Only "
                "headers are needed; neither library is linked.")
        endif()

        message(STATUS "Wayland desktop streaming: disabled (missing: ${_dg_wl_missing})")
        message(STATUS "  Install the development packages to enable it, then re-run cmake:")
        message(STATUS "    Fedora/RHEL:   sudo dnf install pipewire-devel dbus-devel")
        message(STATUS "    Debian/Ubuntu: sudo apt install libpipewire-0.3-dev libdbus-1-dev")
        message(STATUS "    Arch:          sudo pacman -S libpipewire dbus")
        message(STATUS "  Only headers are needed; neither library is linked. X11 streaming is unaffected.")
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
    # desktop/elevated.c carries both halves of the elevated-UI bridge: the
    # agent-side client and the SYSTEM helper the launcher spawns into the
    # interactive session (--win-desktop-helper), which is what makes UAC
    # prompts, elevated windows and the lock screen reachable remotely.
    # wtsapi32: session lock state for the injection gate.
    target_sources(directgate PRIVATE
        ${AGENT_DIR}/desktop/desktop_win.c
        ${AGENT_DIR}/desktop/elevated.c
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
# Control-plane endpoints are baked in so a downloaded binary needs no config
# to sign in. A self-hosted or staging build overrides them here; a developer
# overrides them per-shell with the matching DIRECTGATE_* environment vars.
#
# Identity-provider configuration is deliberately absent: the API exchanges
# tokens on the client's behalf and the web app forwards the browser, so the
# only hosts the binary knows are our own.
set(DIRECTGATE_API_URL "https://api.directgate.io" CACHE STRING "Default control-plane API origin")
set(DIRECTGATE_WEB_URL "https://directgate.io" CACHE STRING "Default web app origin (hosts /cli-auth)")

add_executable(dgcli
    ${CLIENT_DIR}/client.c
    ${CLIENT_DIR}/config.c
    ${CLIENT_DIR}/devices.c
    ${CLIENT_DIR}/login.c
    ${CLIENT_DIR}/relay.c
    ${CLIENT_DIR}/webapi.c)
target_include_directories(dgcli PRIVATE ${CLIENT_DIR})
target_link_libraries(dgcli PRIVATE xcommon)
target_compile_definitions(dgcli PRIVATE
    DIRECTGATE_API_URL="${DIRECTGATE_API_URL}"
    DIRECTGATE_WEB_URL="${DIRECTGATE_WEB_URL}")

if(WIN32)
    enable_language(RC)
    target_sources(dgcli PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/misc/win/dgcli.rc")
    # ShellExecuteA() hands the sign-in URL to the default browser
    target_link_libraries(dgcli PRIVATE shell32)
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
