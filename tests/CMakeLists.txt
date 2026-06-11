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
    target_include_directories(${name} PRIVATE "${CMAKE_SOURCE_DIR}")
    target_link_libraries(${name} PRIVATE xcommon)
    if(UTIL_LIBRARY)
        target_link_libraries(${name} PRIVATE ${UTIL_LIBRARY})
    endif()
    add_test(NAME ${name} COMMAND ${name})
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
directgate_smoke(enroll_prompt_smoke ${AGENT_DIR}/enroll.c)
directgate_smoke(files_smoke         ${AGENT_DIR}/files.c)
directgate_smoke(session_smoke       ${AGENT_DIR}/session.c)

# Client utility tests that compile the client-only implementation files.
directgate_smoke(client_devices_smoke ${CLIENT_DIR}/devices.c)
directgate_smoke(client_config_smoke  ${CLIENT_DIR}/config.c ${CLIENT_DIR}/devices.c)
directgate_smoke(client_relay_smoke   ${CLIENT_DIR}/relay.c)

directgate_smoke(connection_lifecycle_smoke
    ${AGENT_DIR}/config.c
    ${AGENT_DIR}/enroll.c
    ${AGENT_DIR}/files.c
    ${AGENT_DIR}/search.c
    ${AGENT_DIR}/session.c
    ${AGENT_DIR}/term.c
    ${AGENT_DIR}/directgate.c)
target_compile_definitions(connection_lifecycle_smoke PRIVATE DIRECTGATE_TESTING)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(connection_lifecycle_smoke PRIVATE -Wno-unused-function)
endif()
