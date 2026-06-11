cmake_minimum_required(VERSION 3.16)
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
# Data channels only (no RTP/SRTP or WebSocket). Matches build.sh / pkg install_libdatachannel
# and avoids CMake 3.21+ required by bundled libsrtp when NO_MEDIA is off.
set(NO_MEDIA ON CACHE BOOL "" FORCE)
set(NO_WEBSOCKET ON CACHE BOOL "" FORCE)
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
add_executable(directgate
    ${AGENT_DIR}/config.c
    ${AGENT_DIR}/enroll.c
    ${AGENT_DIR}/files.c
    ${AGENT_DIR}/search.c
    ${AGENT_DIR}/session.c
    ${AGENT_DIR}/term.c
    ${AGENT_DIR}/directgate.c)
target_include_directories(directgate PRIVATE ${AGENT_DIR})
target_link_libraries(directgate PRIVATE xcommon)

if(WIN32)
    # ntdll: NtQueryInformationProcess used to read the shell cwd (term.c)
    target_link_libraries(directgate PRIVATE ntdll)

    # Manifest with UTF-8 active code page: ANSI APIs handle any file name
    enable_language(RC)
    target_sources(directgate PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/misc/win/app.rc")
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
    target_sources(dgcli PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/misc/win/app.rc")
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
