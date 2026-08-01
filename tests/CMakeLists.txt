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
        protocol_smoke
        crypto_smoke
        srp_smoke
        transfer_smoke
        webrtc_config_smoke
        webrtc_rtcp_smoke
        webrtc_audio_smoke
        api_invalid_role_smoke
        keyauth_smoke
        files_static_smoke
        auth_logger_smoke
        hash_vectors_smoke
        json_smoke
        proto_crypt_smoke
        protocol_builders_smoke
        siv_smoke
        sockpair_events_smoke
        str_buf_smoke
        websock_frame_smoke
        term_priv_smoke)
    directgate_smoke(${test})
endforeach()

# OpenSSL 3 exposes AES-SIV through EVP. When available, use it as an
# independent differential oracle for the bundled portable implementation.
if(OPENSSL_VERSION VERSION_GREATER_EQUAL "3.0")
    directgate_smoke(crypto_siv_openssl_smoke)
endif()

# Agent tests that also compile specific agent sources.
directgate_smoke(enroll_smoke        ${AGENT_DIR}/config.c ${AGENT_DIR}/enroll.c)
directgate_smoke(enroll_edge_smoke   ${AGENT_DIR}/config.c ${AGENT_DIR}/enroll.c)
directgate_smoke(add_key_smoke       ${AGENT_DIR}/config.c ${AGENT_DIR}/enroll.c)
directgate_smoke(config_smoke        ${AGENT_DIR}/config.c ${AGENT_DIR}/enroll.c)
directgate_smoke(config_extra_smoke  ${AGENT_DIR}/config.c ${AGENT_DIR}/enroll.c)
directgate_smoke(keyfile_apply_smoke ${AGENT_DIR}/config.c ${AGENT_DIR}/enroll.c)
directgate_smoke(search_smoke        ${AGENT_DIR}/search.c ${AGENT_DIR}/files.c)
directgate_smoke(yuv_smoke   ${AGENT_DIR}/yuv.c)
if(UNIX AND NOT APPLE)
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

    # Same idea for the adaptive bitrate controller: compiles desktop.c and
    # drives the policy with synthetic receiver reports, no encoder involved.
    directgate_smoke(desktop_abr_smoke)
    target_include_directories(desktop_abr_smoke PRIVATE ${X11_INCLUDE_DIR})
    target_link_libraries(desktop_abr_smoke PRIVATE ${X11_LIBRARIES} ${CMAKE_DL_LIBS})
endif()
directgate_smoke(enroll_prompt_smoke ${AGENT_DIR}/enroll.c)
directgate_smoke(files_smoke         ${AGENT_DIR}/files.c)
directgate_smoke(session_smoke       ${AGENT_DIR}/session.c)

# Client utility tests that compile the client-only implementation files.
directgate_smoke(client_devices_smoke ${CLIENT_DIR}/devices.c)
directgate_smoke(client_config_smoke  ${CLIENT_DIR}/config.c ${CLIENT_DIR}/devices.c)
directgate_smoke(client_relay_smoke   ${CLIENT_DIR}/relay.c)

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
