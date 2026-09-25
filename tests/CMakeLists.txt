# Smoke tests, registered with CTest. Enabled from the top level via
# -DDIRECTGATE_BUILD_TESTS=ON (tests/run-smoke.sh does this for you).
#
# Every test links the xcommon static library, which carries libxutils,
# libdatachannel (+ its static deps) and OpenSSL as transitive usage
# requirements, so the test binaries link exactly like the real components.
# The test sources include project headers by repo-root-relative path
# (e.g. #include "src/agent/config.h"), so the repo root is on the include path.

# directgate_smoke(<name> [extra .c sources ...])
function(directgate_smoke name)
    add_executable(${name} "${CMAKE_CURRENT_SOURCE_DIR}/${name}.c" ${ARGN})
    # Agent sources include their neighbour headers by bare name; keep both the
    # agent root (session.h, openh264.h, ...) and the desktop module directory
    # (desktop.h, priv.h) searchable, matching the agent binary's include path.
    target_include_directories(${name} PRIVATE "${CMAKE_SOURCE_DIR}" "${AGENT_DIR}" "${AGENT_DIR}/desktop")
    target_link_libraries(${name} PRIVATE xcommon)
    if(UTIL_LIBRARY)
        target_link_libraries(${name} PRIVATE ${UTIL_LIBRARY})
    endif()
    add_test(NAME ${name} COMMAND ${name})
    # A smoke test that blocks must fail, not burn a CI runner. The cap is far
    # above the slowest test (the enrollment retry backoff, ~3s) so it can only
    # trip on a genuine hang.
    set_tests_properties(${name} PROPERTIES TIMEOUT 120)
endfunction()

# Targets that compile session.c / directgate.c pull in the desktop module,
# which needs the same platform sources and libraries as the agent binary
# (see the matching block in the top-level CMakeLists).
function(directgate_smoke_desktop name)
    if(APPLE)
        target_sources(${name} PRIVATE
            ${AGENT_DIR}/desktop/desktop_mac.m
            ${AGENT_DIR}/desktop/opus.c
            ${AGENT_DIR}/desktop/audio.c
            ${AGENT_DIR}/desktop/audio_mac.m)
        set_source_files_properties(${AGENT_DIR}/desktop/desktop_mac.m ${AGENT_DIR}/desktop/audio_mac.m
            PROPERTIES COMPILE_OPTIONS "-fobjc-arc")
        target_link_libraries(${name} PRIVATE
            "-framework ApplicationServices"
            "-framework Carbon"
            "-framework Foundation"
            "-framework CoreMedia"
            "-framework CoreVideo"
            "-framework CoreGraphics"
            "-framework VideoToolbox"
            "-framework ScreenCaptureKit")
    elseif(UNIX)
        # Deliberately built without DIRECTGATE_HAVE_HWENC/hwenc.c: this is the
        # configuration a host without libavcodec headers gets, so the smoke
        # tests keep the software-only fallback path compiling and passing.
        target_sources(${name} PRIVATE
            ${AGENT_DIR}/desktop/desktop_linux.c
            ${AGENT_DIR}/desktop/openh264.c
            ${AGENT_DIR}/yuv.c
            ${AGENT_DIR}/desktop/opus.c
            ${AGENT_DIR}/desktop/audio.c
            ${AGENT_DIR}/desktop/audio_linux.c)
        target_include_directories(${name} PRIVATE ${X11_INCLUDE_DIR} ${AGENT_DIR}/openh264)
        target_link_libraries(${name} PRIVATE ${X11_LIBRARIES} ${CMAKE_DL_LIBS} Xrandr Xext)
    endif()
endfunction()

# Tests that only need libxcommon.
foreach(test
        base64_smoke
        collections_smoke
        common_utils_smoke
        common_prompt_smoke
        protocol_smoke
        crypto_smoke
        e2e_ccwin_smoke
        srp_smoke
        transfer_smoke
        transfer_bounds_smoke
        webrtc_config_smoke
        webrtc_lifecycle_smoke
        webrtc_peer_smoke
        webrtc_queue_smoke
        webrtc_static_smoke
        webrtc_rtcp_smoke
        webrtc_audio_smoke
        api_invalid_role_smoke
        keyauth_smoke
        keyauth_client_smoke
        files_static_smoke
        auth_logger_smoke
        log_privpath_smoke
        hash_vectors_smoke
        json_smoke
        json_limits_smoke
        proto_crypt_smoke
        protocol_builders_smoke
        siv_smoke
        sockpair_events_smoke
        sock_timeout_smoke
        str_buf_smoke
        xutils_bounds_smoke
        websock_frame_smoke
        websock_entropy_smoke
        term_priv_smoke
        term_io_smoke)
    directgate_smoke(${test})
endforeach()

# The peer round trip also executes the unmodified libdatachannel dependency.
# Keep it in the default suite and separately selectable for sanitizer reports.
set_tests_properties(webrtc_peer_smoke PROPERTIES LABELS "external-webrtc")

# OpenSSL 3 exposes AES-SIV through EVP. When available, use it as an
# independent differential oracle for the bundled portable implementation.
if(OPENSSL_VERSION VERSION_GREATER_EQUAL "3.0")
    directgate_smoke(crypto_siv_openssl_smoke)
endif()

# Agent tests that also compile specific agent sources.
directgate_smoke(enroll_smoke        ${AGENT_DIR}/config.c ${AGENT_DIR}/enroll.c)
directgate_smoke(enroll_edge_smoke   ${AGENT_DIR}/config.c ${AGENT_DIR}/enroll.c)
directgate_smoke(enroll_transport_smoke ${AGENT_DIR}/config.c ${AGENT_DIR}/enroll.c)
directgate_smoke(add_key_smoke       ${AGENT_DIR}/config.c ${AGENT_DIR}/enroll.c)
directgate_smoke(config_smoke        ${AGENT_DIR}/config.c ${AGENT_DIR}/enroll.c)
directgate_smoke(config_extra_smoke  ${AGENT_DIR}/config.c ${AGENT_DIR}/enroll.c)
directgate_smoke(config_args_smoke   ${AGENT_DIR}/config.c ${AGENT_DIR}/enroll.c)
directgate_smoke(keyfile_apply_smoke ${AGENT_DIR}/config.c ${AGENT_DIR}/enroll.c)
directgate_smoke(search_smoke        ${AGENT_DIR}/search.c ${AGENT_DIR}/files.c)
directgate_smoke(search_criteria_smoke)
directgate_smoke(yuv_smoke   ${AGENT_DIR}/yuv.c)
if(UNIX AND NOT APPLE)
    directgate_smoke(thread_failure_smoke)
    directgate_smoke(api_worker_failure_smoke)
    directgate_smoke(audio_linux_smoke)
    directgate_smoke(audio_lifecycle_smoke)
    target_link_libraries(audio_linux_smoke PRIVATE ${CMAKE_DL_LIBS})
    directgate_smoke(audio_linux_connection_smoke)
    target_link_libraries(audio_linux_connection_smoke PRIVATE ${CMAKE_DL_LIBS})
    # Leave room for libpulse's first-use initialization under Valgrind. The
    # backend's handshake deadline is still 3s; the test must also bound hangs.
    set_tests_properties(audio_linux_connection_smoke PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 30)

    directgate_smoke(openh264_smoke ${AGENT_DIR}/desktop/openh264.c)
    target_include_directories(openh264_smoke PRIVATE ${AGENT_DIR}/openh264)
    target_link_libraries(openh264_smoke PRIVATE ${CMAKE_DL_LIBS})
    set_tests_properties(openh264_smoke PROPERTIES SKIP_RETURN_CODE 77)

    # Opus encoder wrapper: skips (77) when libopus is absent, like openh264.
    directgate_smoke(opus_smoke ${AGENT_DIR}/desktop/opus.c)
    target_link_libraries(opus_smoke PRIVATE ${CMAKE_DL_LIBS} m)
    set_tests_properties(opus_smoke PROPERTIES SKIP_RETURN_CODE 77)

    # Multi-ABI GPU encoder selection, registered only when the build actually
    # produced per-major variants (DIRECTGATE_HWENC_HEADERS - the package
    # images always do). Links the same object libraries the agent does, so it
    # exercises the real dispatch against this host's libavcodec rather than a
    # stand-in.
    if(DIRECTGATE_HWENC_ABIS)
        directgate_smoke(hwenc_abi_smoke ${AGENT_DIR}/desktop/hwenc_abi.c)
        target_compile_definitions(hwenc_abi_smoke PRIVATE DIRECTGATE_HAVE_HWENC=1)
        target_link_libraries(hwenc_abi_smoke PRIVATE ${CMAKE_DL_LIBS})

        foreach(_dg_abi IN LISTS DIRECTGATE_HWENC_ABIS)
            target_sources(hwenc_abi_smoke PRIVATE $<TARGET_OBJECTS:directgate_hwenc_${_dg_abi}>)
            target_compile_definitions(hwenc_abi_smoke PRIVATE DIRECTGATE_HWENC_HAS_${_dg_abi}=1)
        endforeach()

        set_tests_properties(hwenc_abi_smoke PROPERTIES SKIP_RETURN_CODE 77)
    endif()

    # Compiles the X11 input unit directly (like files_static_smoke) to test
    # the browser-key -> keysym mapping; needs Xlib but no running X server.
    directgate_smoke(desktop_input_smoke)
    target_include_directories(desktop_input_smoke PRIVATE ${X11_INCLUDE_DIR})
    target_link_libraries(desktop_input_smoke PRIVATE ${X11_LIBRARIES} ${CMAKE_DL_LIBS})

    directgate_smoke(desktop_wheel_smoke)
    target_include_directories(desktop_wheel_smoke PRIVATE ${X11_INCLUDE_DIR})
    target_link_libraries(desktop_wheel_smoke PRIVATE ${X11_LIBRARIES} ${CMAKE_DL_LIBS})

    # Exercise the Wayland input branch even on X11-only CI runners. The
    # portal boundary is stubbed, so no compositor or PipeWire is needed.
    directgate_smoke(wayland_input_smoke)
    target_compile_definitions(wayland_input_smoke PRIVATE DIRECTGATE_DESKTOP_HAS_WAYLAND=1)
    target_include_directories(wayland_input_smoke PRIVATE ${X11_INCLUDE_DIR})
    target_link_libraries(wayland_input_smoke PRIVATE ${X11_LIBRARIES} ${CMAKE_DL_LIBS})

    if(DBUS_FOUND)
        # Serialize actual portal messages, without connecting to a desktop.
        directgate_smoke(wayland_portal_smoke)
        target_compile_definitions(wayland_portal_smoke PRIVATE DIRECTGATE_DESKTOP_HAS_WAYLAND=1)
        target_include_directories(wayland_portal_smoke SYSTEM PRIVATE ${DBUS_INCLUDE_DIRS})
        target_link_libraries(wayland_portal_smoke PRIVATE ${DBUS_LIBRARIES} ${CMAKE_DL_LIBS})
    endif()

    # Same idea for the adaptive bitrate controller: compiles desktop.c and
    # drives the policy with synthetic receiver reports, no encoder involved.
    directgate_smoke(desktop_abr_smoke)
    target_include_directories(desktop_abr_smoke PRIVATE ${X11_INCLUDE_DIR})
    target_link_libraries(desktop_abr_smoke PRIVATE ${X11_LIBRARIES} ${CMAKE_DL_LIBS})

    # Encode geometry, presets and the monitor table, from the same desktop.c.
    directgate_smoke(desktop_frame_smoke)
    target_include_directories(desktop_frame_smoke PRIVATE ${X11_INCLUDE_DIR})
    target_link_libraries(desktop_frame_smoke PRIVATE ${X11_LIBRARIES} ${CMAKE_DL_LIBS})

    # The browser-facing desktop control channel. Links the real capture module
    # set, then keeps the pipeline on raw RGBA so no display server is needed.
    directgate_smoke(desktop_control_smoke
        ${AGENT_DIR}/desktop/desktop.c
        ${AGENT_DIR}/desktop/display.c
        ${AGENT_DIR}/desktop/input.c
        ${AGENT_DIR}/desktop/stream.c)
    directgate_smoke_desktop(desktop_control_smoke)
endif()
directgate_smoke(enroll_prompt_smoke ${AGENT_DIR}/enroll.c)
directgate_smoke(files_smoke         ${AGENT_DIR}/files.c)
directgate_smoke(session_smoke       ${AGENT_DIR}/session.c)

# Client utility tests that compile the client-only implementation files.
directgate_smoke(client_devices_smoke ${CLIENT_DIR}/devices.c ${CLIENT_DIR}/webapi.c)
directgate_smoke(client_pick_smoke    ${CLIENT_DIR}/devices.c ${CLIENT_DIR}/webapi.c)
directgate_smoke(client_config_smoke  ${CLIENT_DIR}/config.c ${CLIENT_DIR}/devices.c ${CLIENT_DIR}/webapi.c)
directgate_smoke(client_login_smoke   ${CLIENT_DIR}/login.c ${CLIENT_DIR}/webapi.c)
directgate_smoke(client_relay_smoke   ${CLIENT_DIR}/relay.c ${CLIENT_DIR}/webapi.c)
directgate_smoke(client_webapi_smoke  ${CLIENT_DIR}/webapi.c)

# Compiles client.c itself (its main renamed away) to drive the static terminal I/O and inbound message gate.
if(NOT WIN32)
    directgate_smoke(client_io_smoke ${CLIENT_DIR}/config.c ${CLIENT_DIR}/devices.c ${CLIENT_DIR}/login.c
        ${CLIENT_DIR}/relay.c ${CLIENT_DIR}/webapi.c)
endif()

# The client sources include their neighbour headers by bare name
foreach(test
        client_devices_smoke
        client_pick_smoke
        client_config_smoke
        client_login_smoke
        client_relay_smoke
        client_webapi_smoke)
    target_include_directories(${test} PRIVATE ${CLIENT_DIR})
endforeach()

# Drives the file-manager handlers against a real session send path, so it
# needs the same source set as the lifecycle test.
directgate_smoke(session_files_smoke
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
directgate_smoke_desktop(session_files_smoke)
target_compile_definitions(session_files_smoke PRIVATE DIRECTGATE_TESTING)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(session_files_smoke PRIVATE -Wno-unused-function)
endif()

directgate_smoke(auth_flow_smoke
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
directgate_smoke_desktop(auth_flow_smoke)
target_compile_definitions(auth_flow_smoke PRIVATE DIRECTGATE_TESTING)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(auth_flow_smoke PRIVATE -Wno-unused-function)
endif()

directgate_smoke(connection_lifecycle_smoke
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
directgate_smoke_desktop(connection_lifecycle_smoke)
target_compile_definitions(connection_lifecycle_smoke PRIVATE DIRECTGATE_TESTING)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(connection_lifecycle_smoke PRIVATE -Wno-unused-function)
endif()

# Messages that end a session inside their own handler; needs the whole
# dispatch layer, and one case runs a real shell behind a PTY endpoint.
directgate_smoke(session_lifetime_smoke
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
directgate_smoke_desktop(session_lifetime_smoke)
target_compile_definitions(session_lifetime_smoke PRIVATE DIRECTGATE_TESTING)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(session_lifetime_smoke PRIVATE -Wno-unused-function)
endif()

# Optional coverage-guided parser fuzzing. Recompile only the parser units
# with libFuzzer coverage; xcommon supplies their ordinary dependencies.
option(DIRECTGATE_BUILD_FUZZERS "Build Clang libFuzzer wire parser target" OFF)
if(DIRECTGATE_BUILD_FUZZERS)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang" OR NOT DIRECTGATE_ENABLE_SANITIZERS)
        message(FATAL_ERROR "Fuzzing requires Clang and DIRECTGATE_ENABLE_SANITIZERS=ON")
    endif()
    add_executable(fuzz_wire fuzz_wire.c
        ${COMMON_DIR}/protocol.c ${COMMON_DIR}/webrtc.c
        ${CMAKE_SOURCE_DIR}/libxutils/src/data/json.c
        ${CMAKE_SOURCE_DIR}/libxutils/src/net/ws.c)
    target_include_directories(fuzz_wire PRIVATE ${CMAKE_SOURCE_DIR})
    target_link_libraries(fuzz_wire PRIVATE xcommon)
    target_compile_options(fuzz_wire PRIVATE -fsanitize=fuzzer-no-link)
    target_link_options(fuzz_wire PRIVATE -fsanitize=fuzzer)
endif()
