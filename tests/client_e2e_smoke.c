/*
 * dgcli, end to end, against an API and a relay-plus-host played by this test.
 *
 * The real client binary runs on a pseudo terminal the way a user runs it, in
 * a private $HOME so nothing touches the user's own config, and each scenario
 * is judged by what reaches the terminal, what reaches the servers and how the
 * process exits:
 *
 *   - a password session: device list, relay envelope, the password prompt,
 *     SRP with the host proving itself, shell output and input, a window
 *     resize, a keepalive, and a clean exit when the host closes the session
 *   - client keys: generating one, refusing to overwrite it, authorizing it on
 *     the device with -A, logging in with it, and falling back to the password
 *     when the host does not know the key
 *   - account sign-in: the loopback handoff (preflight, stray requests, a
 *     wrong origin and a wrong state are all refused), a pasted code, a
 *     provider error, whoami, a refresh of an expired session, logout, and
 *     "not signed in" without a terminal
 *   - the failures a script has to be able to see: unknown device, a device
 *     that cannot be connected, a wrong password, a config that does not load
 *   - a host that misbehaves: a challenge missing its parts, a proof that is
 *     not the host's, an auth error, a pre-logon host, a refused or already
 *     known key, sealed traffic that does not open or does not belong, plain
 *     traffic after the login, and a pushed file that tries to leave the
 *     working directory or replace one already there
 *   - a direct connection: the client's offer answered by the agent's own
 *     WebRTC code, and the session carried over the data channel
 *
 * The host side is real too: the agent's own SRP verifier and key-auth code
 * check the client, and everything after the login is sealed under the E2E
 * keys both halves derive.
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pty.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>

#include <openssl/crypto.h>

#include "src/common/protocol.h"
#include "src/common/srp.h"
#include "src/common/e2e.h"
#include "src/common/keyauth.h"
#include "src/common/webrtc.h"
#include "src/common/websock.h"

#include "tls_fixture.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "client_e2e_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

#define CLI_DEVICE_ID    "dev-cli-0001"
#define CLI_DEVICE_NAME  "Test Box"
#define CLI_ROUTING_KEY  "rk-cli-0123456789"
#define CLI_API_TOKEN    "api-token-cli"
#define CLI_SECRET       "cli device password"
#define CLI_SESSION_ID   5U
#define CLI_GREETING     "HELLO_FROM_HOST"
#define CLI_TYPED        "typed-by-user"
#define CLI_EMAIL        "user@example.test"

typedef enum {
    HOST_WAIT_ROLE = 0,
    HOST_WAIT_HELLO,
    HOST_WAIT_PROOF,
    HOST_WAIT_START,
    HOST_WAIT_TYPED,
    HOST_WAIT_PONG,
    HOST_WAIT_RESIZE,
    HOST_DONE
} host_stage_t;

/* How the host misbehaves in a scenario. */
typedef enum {
    FAULT_NONE = 0,
    FAULT_CHALLENGE_NO_B,
    FAULT_CHALLENGE_BAD_NONCE,
    FAULT_SEALED_BEFORE_AUTH,
    FAULT_NOT_A_MESSAGE,
    FAULT_WRONG_M2,
    FAULT_AUTH_ERROR,
    FAULT_PRE_LOGON,
    FAULT_ADD_KEY_REFUSED,
    FAULT_ADD_KEY_ALREADY,
    FAULT_ODDITIES,
    FAULT_SID_MISMATCH,
    FAULT_PLAIN_AFTER_AUTH,
    FAULT_BAD_INNER,
    FAULT_FILE_PUSH,
    FAULT_P2P
} host_fault_t;

#define CLI_PUSHED_TEXT "pushed by the host\n"

typedef struct {
    xapi_t api;
    uint16_t nApiPort;
    uint16_t nRelayPort;
    char sRelayUrl[128];
    char sJwt[512];
    char sSaltHex[DIRECTGATE_SRP_SALT_SIZE * 2 + 1];
    char sVerifier[2048];
    uint8_t salt[DIRECTGATE_SRP_SALT_SIZE];

    /* The host's identity, published through the API as agentPub. */
    uint8_t agentSeed[DIRECTGATE_KEYAUTH_ED25519_SEED_SIZE];
    uint8_t agentPub[DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE];
    char sAgentPubB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];

    /* Scenario inputs, set before the client starts. */
    char sAuthorizedKey[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    xatomic_t bShortSession;
    xatomic_t eFault;
    xatomic_t bEmptyList;
    xatomic_t bEnvelopeNoRk;

    /* Scenario outputs. */
    xatomic_t bStop;
    xatomic_t nDeviceLists;
    xatomic_t nConnects;
    xatomic_t nTokenRedeems;
    xatomic_t nRefreshes;
    xatomic_t bRoleOk;
    xatomic_t bAuthOk;
    xatomic_t bKeyAuthOk;
    xatomic_t bKeyRefused;
    xatomic_t bTerminalStarted;
    xatomic_t bInitialResize;
    xatomic_t bTypedSeen;
    xatomic_t bPongSeen;
    xatomic_t bResizeSeen;
    xatomic_t bAddKeySeen;
    xatomic_t bSendClose;
    xatomic_t bFileAcked;
    xatomic_t bWsPongSeen;
    xatomic_t bRtcConnected;
    xatomic_t bRtcTyped;
    char sAddedKey[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];

    /* The host's half of a direct connection, driven from the server thread. */
    directgate_webrtc_t rtc;
    xbool_t bRtcActive;
    xbool_t bRtcGreeted;

    host_stage_t eStage;
    xbool_t bKeyMethod;
    directgate_srp_t srp;
    directgate_keyauth_t keyauth;
    directgate_e2e_t e2e;
    xbyte_buffer_t typed;
    xapi_session_t *pRelay;
} cli_t;

static cli_t g_cli;

static uint16_t reserve_port(void)
{
    int nFd = socket(AF_INET, SOCK_STREAM, 0);
    if (nFd < 0) return 0;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    socklen_t nLen = sizeof(addr);
    uint16_t nPort = 0;

    if (bind(nFd, (struct sockaddr*)&addr, sizeof(addr)) == 0 &&
        getsockname(nFd, (struct sockaddr*)&addr, &nLen) == 0)
        nPort = ntohs(addr.sin_port);

    close(nFd);
    return nPort;
}

/* A compact JWT that carries the routing key, the way the API mints one. */
static void make_jwt(char *pOut, size_t nSize)
{
    const char *pHeader = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    char sPayload[128];
    snprintf(sPayload, sizeof(sPayload), "{\"rk\":\"%s\",\"role\":\"client\"}", CLI_ROUTING_KEY);

    size_t nHeader = strlen(pHeader);
    size_t nPayload = strlen(sPayload);
    char *pHeaderB64 = XBase64_UrlEncrypt((const uint8_t*)pHeader, &nHeader);
    char *pPayloadB64 = XBase64_UrlEncrypt((const uint8_t*)sPayload, &nPayload);

    snprintf(pOut, nSize, "%s.%s.c2lnbmF0dXJl", pHeaderB64 != NULL ? pHeaderB64 : "",
        pPayloadB64 != NULL ? pPayloadB64 : "");

    free(pHeaderB64);
    free(pPayloadB64);
}

static void reset_outputs(void)
{
    XSYNC_ATOMIC_SET(&g_cli.nDeviceLists, 0);
    XSYNC_ATOMIC_SET(&g_cli.nConnects, 0);
    XSYNC_ATOMIC_SET(&g_cli.nTokenRedeems, 0);
    XSYNC_ATOMIC_SET(&g_cli.nRefreshes, 0);
    XSYNC_ATOMIC_SET(&g_cli.bRoleOk, 0);
    XSYNC_ATOMIC_SET(&g_cli.bAuthOk, 0);
    XSYNC_ATOMIC_SET(&g_cli.bKeyAuthOk, 0);
    XSYNC_ATOMIC_SET(&g_cli.bKeyRefused, 0);
    XSYNC_ATOMIC_SET(&g_cli.bTerminalStarted, 0);
    XSYNC_ATOMIC_SET(&g_cli.bInitialResize, 0);
    XSYNC_ATOMIC_SET(&g_cli.bTypedSeen, 0);
    XSYNC_ATOMIC_SET(&g_cli.bPongSeen, 0);
    XSYNC_ATOMIC_SET(&g_cli.bResizeSeen, 0);
    XSYNC_ATOMIC_SET(&g_cli.bAddKeySeen, 0);
    XSYNC_ATOMIC_SET(&g_cli.bSendClose, 0);
    XSYNC_ATOMIC_SET(&g_cli.bShortSession, 0);
    XSYNC_ATOMIC_SET(&g_cli.eFault, FAULT_NONE);
    XSYNC_ATOMIC_SET(&g_cli.bEmptyList, 0);
    XSYNC_ATOMIC_SET(&g_cli.bEnvelopeNoRk, 0);
    XSYNC_ATOMIC_SET(&g_cli.bWsPongSeen, 0);
    XSYNC_ATOMIC_SET(&g_cli.bFileAcked, 0);
    XSYNC_ATOMIC_SET(&g_cli.bRtcConnected, 0);
    XSYNC_ATOMIC_SET(&g_cli.bRtcTyped, 0);
}

static host_fault_t fault(void)
{
    return (host_fault_t)XSYNC_ATOMIC_GET(&g_cli.eFault);
}

/* ---- the API ------------------------------------------------------------------ */

static int api_respond(xapi_session_t *pSession, uint16_t nCode, const char *pBody)
{
    xhttp_t handle;
    if (XHTTP_InitResponse(&handle, nCode, NULL) <= 0) return XAPI_DISCONNECT;

    if (XHTTP_AddHeader(&handle, "Content-Type", "application/json") < 0 ||
        XHTTP_Assemble(&handle, (const uint8_t*)pBody, strlen(pBody)) == NULL)
    {
        XHTTP_Clear(&handle);
        return XAPI_DISCONNECT;
    }

    XByteBuffer_AddBuff(&pSession->txBuffer, &handle.rawData);
    XHTTP_Clear(&handle);
    return XAPI_EnableEvent(pSession, XPOLLOUT);
}

static int api_account_token(xapi_session_t *pSession, const char *pAccess, const char *pRefresh)
{
    char sBody[512];
    snprintf(sBody, sizeof(sBody),
        "{\"accessToken\":\"%s\",\"refreshToken\":\"%s\",\"expiresAt\":%llu,\"email\":\"%s\",\"userId\":\"u-1\"}",
        pAccess, pRefresh, (unsigned long long)time(NULL) + 3600ULL, CLI_EMAIL);

    return api_respond(pSession, 200, sBody);
}

static int api_request(xapi_session_t *pSession)
{
    xhttp_t *pHandle = (xhttp_t*)pSession->pPacket;
    if (pHandle == NULL) return XAPI_DISCONNECT;

    const char *pBody = (const char*)XHTTP_GetBody(pHandle);
    if (pBody == NULL) pBody = "";

    /* Sign-in endpoints take no bearer token: they are how one is obtained. */
    if (strcmp(pHandle->sUri, "/api/v1/auth/cli/token") == 0)
    {
        XSYNC_ATOMIC_ADD(&g_cli.nTokenRedeems, 1);
        if ((strstr(pBody, "\"code\":\"good-code\"") != NULL || strstr(pBody, "\"code\":\"pasted-code\"") != NULL) &&
            strstr(pBody, "\"codeVerifier\":\"") != NULL)
            return api_account_token(pSession, "acct-access-1", "acct-refresh-1");

        return api_respond(pSession, 400, "{\"message\":\"that code is not valid\"}");
    }

    if (strcmp(pHandle->sUri, "/api/v1/auth/cli/refresh") == 0)
    {
        XSYNC_ATOMIC_ADD(&g_cli.nRefreshes, 1);
        if (strstr(pBody, "\"refreshToken\":\"acct-refresh-1\"") != NULL)
            return api_account_token(pSession, "acct-access-2", "acct-refresh-2");

        return api_respond(pSession, 401, "{\"message\":\"refresh token rejected\"}");
    }

    /* Everything else is made with the configured API token or an account token. */
    const char *pAuth = XHTTP_GetHeader(pHandle, "Authorization");
    if (pAuth == NULL || (strcmp(pAuth, "Bearer " CLI_API_TOKEN) != 0 &&
        strcmp(pAuth, "Bearer acct-access-1") != 0 && strcmp(pAuth, "Bearer acct-access-2") != 0))
        return api_respond(pSession, 401, "{\"message\":\"unauthorized\"}");

    char sList[2048];

    if (strcmp(pHandle->sUri, "/api/v1/devices") == 0)
    {
        XSYNC_ATOMIC_ADD(&g_cli.nDeviceLists, 1);
        if (XSYNC_ATOMIC_GET(&g_cli.bEmptyList)) return api_respond(pSession, 200, "{\"devices\":[]}");

        /* Two connectable devices - one of them has published no host key, and
           the API will not connect to it - one that is not paired, one whose
           enrollment expired, and one revoked (hidden). */
        snprintf(sList, sizeof(sList),
            "{\"devices\":["
            "{\"id\":\"%s\",\"name\":\"%s\",\"isOnline\":true,\"isOwner\":true,"
            "\"status\":\"PAIRED\",\"enrollmentStatus\":\"ACTIVE\",\"agentPub\":\"%s\"},"
            "{\"id\":\"dev-nokey\",\"name\":\"No Key Box\",\"isOnline\":false,\"isOwner\":true,"
            "\"status\":\"PAIRED\",\"enrollmentStatus\":\"ACTIVE\"},"
            "{\"id\":\"dev-unpaired\",\"name\":\"Unpaired Box\",\"status\":\"PENDING\"},"
            "{\"id\":\"dev-shared\",\"name\":\"Shared Box\",\"isOwner\":false,\"ownerEmail\":\"owner@example.test\","
            "\"status\":\"PAIRED\",\"enrollmentStatus\":\"EXPIRED\"},"
            "{\"id\":\"dev-gone\",\"name\":\"Gone\",\"status\":\"PAIRED\",\"revokedAt\":\"2026-01-01T00:00:00Z\"}"
            "]}", CLI_DEVICE_ID, CLI_DEVICE_NAME, g_cli.sAgentPubB64);

        return api_respond(pSession, 200, sList);
    }

    if (strcmp(pHandle->sUri, "/api/v1/sessions/connect") == 0)
    {
        if (strstr(pBody, CLI_DEVICE_ID) == NULL) return api_respond(pSession, 400, "{\"message\":\"unknown device\"}");

        XSYNC_ATOMIC_ADD(&g_cli.nConnects, 1);

        /* Without a routing key in the envelope the client has to take it from the JWT. */
        if (XSYNC_ATOMIC_GET(&g_cli.bEnvelopeNoRk))
            snprintf(sList, sizeof(sList),
                "{\"sessionId\":\"session-1\",\"relay\":{\"relayUrl\":\"%s\",\"browserJwt\":\"%s\"}}",
                g_cli.sRelayUrl, g_cli.sJwt);
        else
            snprintf(sList, sizeof(sList),
                "{\"sessionId\":\"session-1\",\"relay\":{\"relayUrl\":\"%s\",\"browserJwt\":\"%s\","
                "\"routingKey\":\"%s\",\"iceServers\":[\"stun:127.0.0.1:1\"]}}", g_cli.sRelayUrl, g_cli.sJwt,
                CLI_ROUTING_KEY);

        return api_respond(pSession, 200, sList);
    }

    return api_respond(pSession, 404, "{\"message\":\"not found\"}");
}

/* ---- the relay, standing in for the host too ------------------------------------ */

static int host_send(xapi_session_t *pSession, xjson_obj_t *pHeader, const uint8_t *pPayload, size_t nPayload)
{
    if (pHeader == NULL) return XAPI_DISCONNECT;

    xbyte_buffer_t packet;
    XByteBuffer_Init(&packet, XSTDNON, XFALSE);

    xbool_t bSealed = DirectGate_E2E_IsInitialized(&g_cli.e2e);
    if (bSealed) DirectGate_Proto_AddCC(pHeader, &g_cli.e2e, 0);

    int nStatus = XAPI_DISCONNECT;
    if (DirectGate_Proto_Build(&packet, pHeader, pPayload, nPayload, XFALSE) &&
        (!bSealed || DirectGate_Proto_EncryptPackage(&packet, &g_cli.e2e, CLI_SESSION_ID)))
        nStatus = DirectGate_WebSock_SendBuff(pSession, &packet);

    XJSON_FreeObject(pHeader);
    XByteBuffer_Clear(&packet);
    return nStatus;
}

/* Builds the packet host_send would, sealed under pE2E when it is given.
   The header is left to the caller. */
static int host_packet(xbyte_buffer_t *pPacket, xjson_obj_t *pHeader, const uint8_t *pPayload, size_t nPayload,
                       directgate_e2e_t *pE2E, uint32_t nOuterSessionId)
{
    XByteBuffer_Init(pPacket, XSTDNON, XFALSE);
    if (pHeader == NULL) return 0;
    if (pE2E != NULL) DirectGate_Proto_AddCC(pHeader, pE2E, 0);

    return DirectGate_Proto_Build(pPacket, pHeader, pPayload, nPayload, XFALSE) &&
        (pE2E == NULL || DirectGate_Proto_EncryptPackage(pPacket, pE2E, nOuterSessionId));
}

/* Sends in the clear whatever the session state, and frees the header. */
static int host_send_plain(xapi_session_t *pSession, xjson_obj_t *pHeader, const uint8_t *pPayload, size_t nPayload)
{
    xbyte_buffer_t packet;
    int nStatus = host_packet(&packet, pHeader, pPayload, nPayload, NULL, 0) ?
        DirectGate_WebSock_SendBuff(pSession, &packet) : XAPI_DISCONNECT;

    XJSON_FreeObject(pHeader);
    XByteBuffer_Clear(&packet);
    return nStatus;
}

/* Sealed under pE2E with the outer session id given, and the header freed. */
static int host_send_sealed(xapi_session_t *pSession, xjson_obj_t *pHeader, const uint8_t *pPayload, size_t nPayload,
                            directgate_e2e_t *pE2E, uint32_t nOuterSessionId)
{
    xbyte_buffer_t packet;
    int nStatus = host_packet(&packet, pHeader, pPayload, nPayload, pE2E, nOuterSessionId) ?
        DirectGate_WebSock_SendBuff(pSession, &packet) : XAPI_DISCONNECT;

    XJSON_FreeObject(pHeader);
    XByteBuffer_Clear(&packet);
    return nStatus;
}

/* A binary frame that is not a protocol message at all. */
static int host_send_bytes(xapi_session_t *pSession, const char *pBytes)
{
    if (XWS_AppendFrame(&pSession->txBuffer, (const uint8_t*)pBytes, strlen(pBytes), XWS_BINARY, XFALSE, XTRUE) != XWS_ERR_NONE)
        return XAPI_DISCONNECT;

    return XAPI_EnableEvent(pSession, XPOLLOUT);
}

static xjson_obj_t* webrtc_header(const char *pAction, const char *pField, const char *pValue)
{
    xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("webrtc", CLI_SESSION_ID);
    if (pHeader == NULL) return NULL;

    if (pAction != NULL) XJSON_AddString(pHeader, "action", pAction);
    if (pField != NULL) XJSON_AddString(pHeader, pField, pValue);
    return pHeader;
}

static int host_srp(xapi_session_t *pSession, const directgate_pkg_auth_t *pAuth)
{
    if (g_cli.eStage == HOST_WAIT_HELLO && strcmp(pAuth->pAction, "hello") == 0)
    {
        char sBHex[1024];
        char sNonceHex[(DIRECTGATE_SRP_NONCE_SIZE * 2) + 1];
        size_t nNonce = 0;

        DirectGate_SRP_Destroy(&g_cli.srp);
        if (pAuth->pDeviceId == NULL || strcmp(pAuth->pDeviceId, CLI_DEVICE_ID) != 0 ||
            !DirectGate_SRP_Init(&g_cli.srp) ||
            !DirectGate_SRP_LoadVerifier(&g_cli.srp, g_cli.salt, sizeof(g_cli.salt), g_cli.sVerifier) ||
            !DirectGate_SRP_HexToBytes(pAuth->pNonce, g_cli.srp.clientNonce, sizeof(g_cli.srp.clientNonce), &nNonce))
            return XAPI_DISCONNECT;

        xstrncpy(g_cli.srp.sDeviceId, sizeof(g_cli.srp.sDeviceId), pAuth->pDeviceId);
        if (!DirectGate_SRP_SetClientPublic(&g_cli.srp, pAuth->pA) ||
            !DirectGate_SRP_GenerateChallenge(&g_cli.srp, sBHex, sizeof(sBHex), sNonceHex, sizeof(sNonceHex)))
            return XAPI_DISCONNECT;

        /* Before any keys exist: something sealed, and something that is no message at all. */
        if (fault() == FAULT_SEALED_BEFORE_AUTH)
            return host_send(pSession, DirectGate_Proto_NewHeader("encrypted", CLI_SESSION_ID), (const uint8_t*)"xx", 2);
        if (fault() == FAULT_NOT_A_MESSAGE) return host_send_bytes(pSession, "this is not a protocol message");

        g_cli.eStage = HOST_WAIT_PROOF;
        return host_send(pSession, DirectGate_Proto_BuildAuthChallenge(g_cli.sSaltHex,
            fault() == FAULT_CHALLENGE_NO_B ? NULL : sBHex,
            fault() == FAULT_CHALLENGE_BAD_NONCE ? "zz" : sNonceHex,
            DIRECTGATE_SRP_SUITE, CLI_SESSION_ID), NULL, 0);
    }

    if (g_cli.eStage == HOST_WAIT_PROOF && strcmp(pAuth->pAction, "proof") == 0)
    {
        char sM2[128];
        if (pAuth->pM1 == NULL || !DirectGate_SRP_VerifyClientProof(&g_cli.srp, pAuth->pM1, sM2, sizeof(sM2)))
        {
            g_cli.eStage = HOST_DONE;
            return host_send(pSession, DirectGate_Proto_BuildAuthResult("failed", NULL, "invalid proof",
                CLI_SESSION_ID, XFALSE), NULL, 0);
        }

        /* An error the relay words itself, with a terminal escape the client must not pass through. */
        if (fault() == FAULT_AUTH_ERROR)
        {
            g_cli.eStage = HOST_DONE;
            return host_send(pSession, DirectGate_Proto_BuildAuthResult("error", NULL, "relay busy \x1b[31mred",
                CLI_SESSION_ID, XFALSE), NULL, 0);
        }

        /* A proof that is not the host's: whoever sent it does not hold the verifier. */
        if (fault() == FAULT_WRONG_M2) sM2[0] = (sM2[0] == 'a') ? 'b' : 'a';

        /* The result goes out in the clear, before the keys exist. */
        int nStatus = host_send(pSession, DirectGate_Proto_BuildAuthResult("ok", sM2, NULL, CLI_SESSION_ID,
            fault() == FAULT_PRE_LOGON), NULL, 0);
        if (nStatus < 0) return nStatus;

        DirectGate_E2E_Init(&g_cli.e2e);
        if (!DirectGate_E2E_DeriveFromSRP(&g_cli.e2e, g_cli.srp.K, sizeof(g_cli.srp.K), g_cli.srp.nonce,
                g_cli.srp.clientNonce, DIRECTGATE_SRP_NONCE_SIZE, CLI_DEVICE_ID, XTRUE))
            return XAPI_DISCONNECT;

        XSYNC_ATOMIC_SET(&g_cli.bAuthOk, 1);
        g_cli.eStage = HOST_WAIT_START;
    }

    return XAPI_CONTINUE;
}

static int host_key(xapi_session_t *pSession, const directgate_pkg_auth_t *pAuth)
{
    if (g_cli.eStage == HOST_WAIT_HELLO && strcmp(pAuth->pAction, "hello") == 0)
    {
        DirectGate_KeyAuth_Cleanse(&g_cli.keyauth);
        DirectGate_KeyAuth_Init(&g_cli.keyauth);

        if (!DirectGate_KeyAuth_AgentProcessHello(&g_cli.keyauth, pAuth->pDeviceId, pAuth->pClientPub,
                pAuth->pClientEph, pAuth->pNonce))
            return XAPI_DISCONNECT;

        const char *pAuthorized[1] = { g_cli.sAuthorizedKey };
        if (!g_cli.sAuthorizedKey[0] ||
            !DirectGate_KeyAuth_IsClientAuthorized(g_cli.keyauth.clientPubKey, pAuthorized, 1))
        {
            XSYNC_ATOMIC_SET(&g_cli.bKeyRefused, 1);
            g_cli.eStage = HOST_DONE;
            return host_send(pSession, DirectGate_Proto_BuildAuthResult("failed", NULL, "client not authorized",
                CLI_SESSION_ID, XFALSE), NULL, 0);
        }

        char sPub[DIRECTGATE_KEYAUTH_PUB_B64_SIZE], sEph[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
        char sNonce[(DIRECTGATE_KEYAUTH_NONCE_SIZE * 2) + 1];
        char sChallenge[(DIRECTGATE_KEYAUTH_CHALLENGE_SIZE * 2) + 1];
        char sSig[DIRECTGATE_KEYAUTH_SIG_B64_SIZE];

        if (!DirectGate_KeyAuth_AgentBuildChallenge(&g_cli.keyauth, g_cli.agentSeed, g_cli.agentPub,
                sPub, sizeof(sPub), sEph, sizeof(sEph), sNonce, sizeof(sNonce),
                sChallenge, sizeof(sChallenge), sSig, sizeof(sSig)))
            return XAPI_DISCONNECT;

        g_cli.eStage = HOST_WAIT_PROOF;
        return host_send(pSession, DirectGate_Proto_BuildAuthKeyChallenge(sPub, sEph, sNonce, sChallenge, sSig,
            CLI_SESSION_ID), NULL, 0);
    }

    if (g_cli.eStage == HOST_WAIT_PROOF && strcmp(pAuth->pAction, "proof") == 0)
    {
        if (pAuth->pClientSig == NULL || !DirectGate_KeyAuth_AgentVerifyProof(&g_cli.keyauth, pAuth->pClientSig) ||
            !DirectGate_KeyAuth_DeriveShared(&g_cli.keyauth))
            return XAPI_DISCONNECT;

        int nStatus = host_send(pSession, DirectGate_Proto_BuildAuthResult("ok", NULL, NULL, CLI_SESSION_ID, XFALSE), NULL, 0);
        if (nStatus < 0) return nStatus;

        DirectGate_E2E_Init(&g_cli.e2e);
        if (!DirectGate_E2E_DeriveFromKey(&g_cli.e2e, g_cli.keyauth.sharedSecret, sizeof(g_cli.keyauth.sharedSecret),
                g_cli.keyauth.localNonce, g_cli.keyauth.peerNonce, DIRECTGATE_KEYAUTH_NONCE_SIZE, CLI_DEVICE_ID, XTRUE))
            return XAPI_DISCONNECT;

        XSYNC_ATOMIC_SET(&g_cli.bKeyAuthOk, 1);
        XSYNC_ATOMIC_SET(&g_cli.bAuthOk, 1);
        g_cli.eStage = HOST_WAIT_START;
    }

    return XAPI_CONTINUE;
}

/* Pushes one file to the client the way a host does: start, one chunk, end with its hash. */
static int host_push_file(xapi_session_t *pSession, const char *pId, const char *pName, const char *pText)
{
    size_t nText = strlen(pText);
    uint8_t digest[XSHA256_DIGEST_SIZE];
    char sHex[XSHA256_DIGEST_SIZE * 2 + 1];

    XSHA256_Compute(digest, sizeof(digest), (const uint8_t*)pText, nText);
    for (size_t i = 0; i < sizeof(digest); i++) snprintf(sHex + (i * 2), 3, "%02x", digest[i]);

    int nStatus = host_send(pSession, DirectGate_Proto_BuildFileStart(pId, pName, nText, 1, 4096), NULL, 0);
    if (nStatus >= 0) nStatus = host_send(pSession, DirectGate_Proto_BuildFileChunk(pId, 0), (const uint8_t*)pText, nText);
    if (nStatus >= 0) nStatus = host_send(pSession, DirectGate_Proto_BuildFileEnd(pId, sHex), NULL, 0);
    return nStatus;
}

/* What a misbehaving host sends once the terminal is asked for. XAPI_CONTINUE
   goes on to the greeting; XAPI_NO_ACTION means the scenario carries on
   without one; anything below zero ends the connection. */
static int host_after_start(xapi_session_t *pSession)
{
    switch (fault())
    {
        case FAULT_ODDITIES:
        {
            /* Sealed under keys nobody agreed on: dropped, and the session goes on. */
            directgate_e2e_t stranger;
            uint8_t key[32], nonceA[DIRECTGATE_SRP_NONCE_SIZE], nonceB[DIRECTGATE_SRP_NONCE_SIZE];
            memset(key, 0x11, sizeof(key));
            memset(nonceA, 0x22, sizeof(nonceA));
            memset(nonceB, 0x33, sizeof(nonceB));
            DirectGate_E2E_Init(&stranger);
            DirectGate_E2E_DeriveFromSRP(&stranger, key, sizeof(key), nonceA, nonceB, sizeof(nonceA), CLI_DEVICE_ID, XTRUE);
            int nStatus = host_send_sealed(pSession, DirectGate_Proto_BuildKeepalive("ping", CLI_SESSION_ID), NULL, 0,
                &stranger, CLI_SESSION_ID);
            DirectGate_E2E_Clear(&stranger);

            /* Signalling the client cannot use, keepalives and commands that ask for nothing. */
            xjson_obj_t *sealed[] = {
                webrtc_header("answer", NULL, NULL),
                webrtc_header("ice", "candidate", "candidate:1 1 UDP 1 127.0.0.1 9 typ host"),
                webrtc_header("ice", NULL, NULL),
                webrtc_header("renegotiate", NULL, NULL),
                DirectGate_Proto_BuildKeepalive(NULL, CLI_SESSION_ID),
                DirectGate_Proto_BuildKeepalive("pong", CLI_SESSION_ID),
                DirectGate_Proto_BuildCmd("noop", NULL, NULL, NULL, CLI_SESSION_ID)
            };

            for (size_t i = 0; i < sizeof(sealed) / sizeof(sealed[0]); i++)
            {
                if (nStatus >= 0) nStatus = host_send(pSession, sealed[i], NULL, 0);
                else XJSON_FreeObject(sealed[i]);
            }

            /* Relay notices in the clear, one of them carrying a terminal escape. */
            xjson_obj_t *pNotice = DirectGate_Proto_BuildError("relay \x1b[2Jnotice", CLI_SESSION_ID);
            if (nStatus >= 0) nStatus = host_send_plain(pSession, pNotice, NULL, 0);
            else XJSON_FreeObject(pNotice);

            xjson_obj_t *pOpen = DirectGate_Proto_BuildStatus("open", CLI_SESSION_ID);
            if (nStatus >= 0) nStatus = host_send_plain(pSession, pOpen, NULL, 0);
            else XJSON_FreeObject(pOpen);

            /* A WebSocket ping, which a live client answers; the greeting and the close wait for the pong. */
            if (nStatus >= 0 && XWS_AppendFrame(&pSession->txBuffer, NULL, 0, XWS_PING, XFALSE, XTRUE) == XWS_ERR_NONE)
                nStatus = XAPI_EnableEvent(pSession, XPOLLOUT);

            return nStatus >= 0 ? XAPI_NO_ACTION : nStatus;
        }
        case FAULT_SID_MISMATCH:
        {
            /* Sealed for this session, but saying it belongs to another. */
            xjson_obj_t *pHeader = DirectGate_Proto_BuildData(CLI_SESSION_ID + 1);
            return host_send_sealed(pSession, pHeader, (const uint8_t*)"stray\r\n", 7, &g_cli.e2e, CLI_SESSION_ID);
        }
        case FAULT_PLAIN_AFTER_AUTH:
            return host_send_plain(pSession, DirectGate_Proto_BuildData(CLI_SESSION_ID), (const uint8_t*)"forged\r\n", 8);
        case FAULT_BAD_INNER:
            return host_send(pSession, DirectGate_Proto_NewHeader("bogus", CLI_SESSION_ID), NULL, 0);
        case FAULT_FILE_PUSH:
        {
            /* A name that tries to climb out of the working directory lands in it. */
            int nStatus = host_push_file(pSession, "push-1", "../" "pushed.txt", CLI_PUSHED_TEXT);

            /* The same name again must not replace what is there, and a file
               that is cancelled half way must not be left behind. */
            if (nStatus >= 0) nStatus = host_push_file(pSession, "push-2", "pushed.txt", "replaced\n");
            xjson_obj_t *partial[] = {
                DirectGate_Proto_BuildFileStart("push-3", "partial.txt", 8192, 2, 4096),
                DirectGate_Proto_BuildFileChunk("push-3", 0),
                DirectGate_Proto_BuildFileCancel("push-3", "changed my mind"),
                DirectGate_Proto_BuildFileAck("push-3", 1)
            };

            for (size_t i = 0; i < sizeof(partial) / sizeof(partial[0]); i++)
            {
                const uint8_t *pChunk = i == 1 ? (const uint8_t*)"half" : NULL;
                if (nStatus >= 0) nStatus = host_send(pSession, partial[i], pChunk, pChunk != NULL ? 4 : 0);
                else XJSON_FreeObject(partial[i]);
            }

            /* The greeting and the close wait for the client's receipt. */
            return nStatus >= 0 ? XAPI_NO_ACTION : nStatus;
        }
        case FAULT_P2P:
            /* The greeting waits for the direct connection. */
            return XAPI_NO_ACTION;
        default:
            break;
    }

    return XAPI_CONTINUE;
}

static int host_on_sealed(xapi_session_t *pSession, directgate_pkg_t *pPkg);

/* Signalling the host's own WebRTC produced: to the client, sealed, on the relay. */
static void host_rtc_signal_out(const char *pData, size_t nLen, void *pCtx)
{
    (void)pCtx;
    xjson_t json;
    if (g_cli.pRelay == NULL || !XJSON_Parse(&json, NULL, pData, nLen)) return;

    XJSON_AddU32(json.pRootObj, "sessionId", CLI_SESSION_ID);
    xbyte_buffer_t packet;
    if (host_packet(&packet, json.pRootObj, NULL, 0, &g_cli.e2e, CLI_SESSION_ID))
        DirectGate_WebSock_SendBuff(g_cli.pRelay, &packet);

    XByteBuffer_Clear(&packet);
    XJSON_Destroy(&json);
}

/* What the client sends over the data channel is read like relay traffic. */
static void host_rtc_data(const uint8_t *pData, size_t nLen, void *pCtx)
{
    (void)pCtx;
    directgate_pkg_t pkg;
    if (g_cli.pRelay == NULL || !DirectGate_Package_Parse(&pkg, pData, nLen)) return;

    if (pkg.header.pType != NULL && strcmp(pkg.header.pType, "encrypted") == 0)
    {
        xbool_t bTyped = XSYNC_ATOMIC_GET(&g_cli.bTypedSeen) != 0;
        host_on_sealed(g_cli.pRelay, &pkg);
        if (!bTyped && XSYNC_ATOMIC_GET(&g_cli.bTypedSeen)) XSYNC_ATOMIC_SET(&g_cli.bRtcTyped, 1);
    }

    DirectGate_Package_Clear(&pkg);
}

/* The client's offer and candidates, answered by the agent's own WebRTC code. */
static int host_rtc_signal_in(xjson_obj_t *pRoot)
{
    const char *pAction = XJSON_GetString(XJSON_GetObject(pRoot, "action"));
    if (pAction == NULL) return XAPI_CONTINUE;

    if (strcmp(pAction, "offer") == 0)
    {
        if (!g_cli.bRtcActive)
        {
            DirectGate_WebRTC_Init(&g_cli.rtc);
            g_cli.rtc.signalCb = host_rtc_signal_out;
            g_cli.rtc.dataCb = host_rtc_data;
            g_cli.bRtcActive = XTRUE;
            g_cli.bRtcGreeted = XFALSE;
        }

        const char *pSdp = XJSON_GetString(XJSON_GetObject(pRoot, "sdp"));
        return DirectGate_WebRTC_HandleOffer(&g_cli.rtc, pSdp, 0, XFALSE) == XSTDOK ? XAPI_CONTINUE : XAPI_DISCONNECT;
    }

    if (strcmp(pAction, "ice") == 0 && g_cli.bRtcActive)
        DirectGate_WebRTC_HandleIceCandidate(&g_cli.rtc, XJSON_GetString(XJSON_GetObject(pRoot, "candidate")),
            XJSON_GetString(XJSON_GetObject(pRoot, "sdpMid")), 0);

    return XAPI_CONTINUE;
}

/* Once the channel is up the host greets over it, so what reaches the terminal came the direct way. */
static void host_rtc_tick(void)
{
    if (!g_cli.bRtcActive) return;
    DirectGate_WebRTC_ProcessQueue(&g_cli.rtc);

    if (g_cli.bRtcGreeted || !DirectGate_WebRTC_IsConnected(&g_cli.rtc)) return;
    g_cli.bRtcGreeted = XTRUE;
    XSYNC_ATOMIC_SET(&g_cli.bRtcConnected, 1);

    const char *pGreeting = CLI_GREETING "\r\n";
    xjson_obj_t *pHeader = DirectGate_Proto_BuildData(CLI_SESSION_ID);
    xbyte_buffer_t packet;

    if (host_packet(&packet, pHeader, (const uint8_t*)pGreeting, strlen(pGreeting), &g_cli.e2e, CLI_SESSION_ID))
        DirectGate_WebRTC_Send(&g_cli.rtc, packet.pData, packet.nUsed);

    XJSON_FreeObject(pHeader);
    XByteBuffer_Clear(&packet);
}

static void host_rtc_stop(void)
{
    if (!g_cli.bRtcActive) return;
    DirectGate_WebRTC_Clear(&g_cli.rtc);
    g_cli.bRtcActive = XFALSE;
}

static int host_on_sealed(xapi_session_t *pSession, directgate_pkg_t *pPkg)
{
    xbyte_buffer_t inner;
    XByteBuffer_Init(&inner, XSTDNON, XFALSE);
    if (!DirectGate_Proto_DecryptPackage(&inner, pPkg, &g_cli.e2e))
    {
        XByteBuffer_Clear(&inner);
        return XAPI_DISCONNECT;
    }

    directgate_pkg_t msg;
    if (!DirectGate_Package_Parse(&msg, inner.pData, inner.nUsed))
    {
        XByteBuffer_Clear(&inner);
        return XAPI_DISCONNECT;
    }

    int nStatus = XAPI_CONTINUE;
    const char *pType = msg.header.pType != NULL ? msg.header.pType : "";
    xjson_obj_t *pRoot = msg.jsonHeader.pRootObj;

    if (strcmp(pType, "admin") == 0)
    {
        const char *pAction = XJSON_GetString(XJSON_GetObject(pRoot, "action"));
        const char *pPub = XJSON_GetString(XJSON_GetObject(pRoot, "clientPub"));

        if (pAction != NULL && strcmp(pAction, "add-key") == 0 && pPub != NULL)
        {
            xstrncpy(g_cli.sAddedKey, sizeof(g_cli.sAddedKey), pPub);
            XSYNC_ATOMIC_SET(&g_cli.bAddKeySeen, 1);

            /* Admin answers that are not the one asked for are passed over. */
            if (fault() == FAULT_ADD_KEY_ALREADY)
            {
                xjson_obj_t *pOther = DirectGate_Proto_BuildAdmin("key-list", NULL, "ok", NULL, CLI_SESSION_ID);
                xjson_obj_t *pNothing = DirectGate_Proto_BuildAdmin(NULL, NULL, NULL, NULL, CLI_SESSION_ID);
                nStatus = host_send(pSession, pOther, NULL, 0);
                if (nStatus >= 0) nStatus = host_send(pSession, pNothing, NULL, 0);
                else XJSON_FreeObject(pNothing);
            }

            const char *pResult = "ok";
            const char *pReason = NULL;

            if (fault() == FAULT_ADD_KEY_ALREADY) pResult = "already";
            if (fault() == FAULT_ADD_KEY_REFUSED)
            {
                pResult = "error";
                pReason = "keys are managed \x1b]0;owned\x07by policy";
            }

            xjson_obj_t *pAnswer = DirectGate_Proto_BuildAdmin("add-key-result", NULL, pResult, pReason, CLI_SESSION_ID);
            if (nStatus >= 0) nStatus = host_send(pSession, pAnswer, NULL, 0);
            else XJSON_FreeObject(pAnswer);
        }
    }
    else if (strcmp(pType, "cmd") == 0)
    {
        const char *pAction = XJSON_GetString(XJSON_GetObject(pRoot, "action"));
        const char *pMode = XJSON_GetString(XJSON_GetObject(pRoot, "mode"));

        if (g_cli.eStage == HOST_WAIT_START && pAction != NULL && strcmp(pAction, "start") == 0 &&
            pMode != NULL && strcmp(pMode, "terminal") == 0)
        {
            XSYNC_ATOMIC_SET(&g_cli.bTerminalStarted, 1);
            g_cli.eStage = HOST_WAIT_TYPED;

            /* A misbehaving host does its thing first; some faults end the session there. */
            nStatus = host_after_start(pSession);

            if (nStatus == XAPI_CONTINUE)
            {
                const char *pGreeting = CLI_GREETING "\r\n";
                nStatus = host_send(pSession, DirectGate_Proto_BuildData(CLI_SESSION_ID),
                    (const uint8_t*)pGreeting, strlen(pGreeting));

                /* Some scenarios only need the login: close right after the greeting. */
                if (nStatus >= 0 && XSYNC_ATOMIC_GET(&g_cli.bShortSession))
                    nStatus = host_send(pSession, DirectGate_Proto_BuildStatus("closed", CLI_SESSION_ID), NULL, 0);
            }
            else if (nStatus == XAPI_NO_ACTION) nStatus = XAPI_CONTINUE;
        }
    }
    else if (strcmp(pType, "file") == 0)
    {
        /* The client's receipt for a pushed file. */
        const char *pAction = XJSON_GetString(XJSON_GetObject(pRoot, "action"));
        const char *pId = XJSON_GetString(XJSON_GetObject(pRoot, "transferId"));
        if (pAction != NULL && strcmp(pAction, "ack") == 0 && pId != NULL && strcmp(pId, "push-1") == 0)
        {
            XSYNC_ATOMIC_SET(&g_cli.bFileAcked, 1);

            const char *pGreeting = CLI_GREETING "\r\n";
            xjson_obj_t *pData = DirectGate_Proto_BuildData(CLI_SESSION_ID);
            nStatus = host_send(pSession, pData, (const uint8_t*)pGreeting, strlen(pGreeting));
            if (nStatus >= 0) nStatus = host_send(pSession, DirectGate_Proto_BuildStatus("closed", CLI_SESSION_ID), NULL, 0);
        }
    }
    else if (strcmp(pType, "webrtc") == 0 && fault() == FAULT_P2P)
    {
        nStatus = host_rtc_signal_in(pRoot);
    }
    else if (strcmp(pType, "resize") == 0)
    {
        uint32_t nRows = XJSON_GetU32(XJSON_GetObject(pRoot, "rows"));
        uint32_t nCols = XJSON_GetU32(XJSON_GetObject(pRoot, "cols"));

        if (nRows == 30 && nCols == 100) XSYNC_ATOMIC_SET(&g_cli.bInitialResize, 1);
        if (g_cli.eStage == HOST_WAIT_RESIZE && nRows == 45 && nCols == 150)
        {
            XSYNC_ATOMIC_SET(&g_cli.bResizeSeen, 1);
            g_cli.eStage = HOST_DONE;
        }
    }
    else if (strcmp(pType, "data") == 0 && g_cli.eStage == HOST_WAIT_TYPED)
    {
        const directgate_pkg_data_t *pData = (const directgate_pkg_data_t*)msg.pPackage;
        if (pData != NULL && pData->pPayload != NULL && pData->nPayloadLength)
            XByteBuffer_Add(&g_cli.typed, pData->pPayload, pData->nPayloadLength);

        if (g_cli.typed.nUsed && strstr((const char*)g_cli.typed.pData, CLI_TYPED) != NULL)
        {
            XSYNC_ATOMIC_SET(&g_cli.bTypedSeen, 1);
            g_cli.eStage = HOST_WAIT_PONG;
            nStatus = host_send(pSession, DirectGate_Proto_BuildKeepalive("ping", CLI_SESSION_ID), NULL, 0);
        }
    }
    else if (strcmp(pType, "keepalive") == 0 && g_cli.eStage == HOST_WAIT_PONG)
    {
        const char *pAction = XJSON_GetString(XJSON_GetObject(pRoot, "action"));
        if (pAction != NULL && strcmp(pAction, "pong") == 0)
        {
            XSYNC_ATOMIC_SET(&g_cli.bPongSeen, 1);
            g_cli.eStage = HOST_WAIT_RESIZE;
        }
    }

    DirectGate_Package_Clear(&msg);
    XByteBuffer_Clear(&inner);
    return nStatus;
}

static int host_frame(xapi_session_t *pSession)
{
    xws_frame_t *pFrame = (xws_frame_t*)pSession->pPacket;
    if (pFrame == NULL) return XAPI_DISCONNECT;

    if (pFrame->eType == XWS_PONG)
    {
        XSYNC_ATOMIC_SET(&g_cli.bWsPongSeen, 1);
        if (fault() != FAULT_ODDITIES) return XAPI_CONTINUE;

        const char *pGreeting = CLI_GREETING "\r\n";
        xjson_obj_t *pData = DirectGate_Proto_BuildData(CLI_SESSION_ID);
        int nStatus = host_send(pSession, pData, (const uint8_t*)pGreeting, strlen(pGreeting));
        return nStatus >= 0 ? host_send(pSession, DirectGate_Proto_BuildStatus("closed", CLI_SESSION_ID), NULL, 0) : nStatus;
    }

    if (pFrame->eType != XWS_BINARY && pFrame->eType != XWS_TEXT) return XAPI_CONTINUE;

    directgate_pkg_t pkg;
    if (!DirectGate_Package_Parse(&pkg, XWebFrame_GetPayload(pFrame), XWebFrame_GetPayloadLength(pFrame)))
        return XAPI_DISCONNECT;

    int nStatus = XAPI_CONTINUE;
    const char *pType = pkg.header.pType != NULL ? pkg.header.pType : "";

    if (strcmp(pType, "role") == 0 && g_cli.eStage == HOST_WAIT_ROLE)
    {
        xjson_obj_t *pRoot = pkg.jsonHeader.pRootObj;
        const char *pRole = XJSON_GetString(XJSON_GetObject(pRoot, "role"));
        const char *pDevice = XJSON_GetString(XJSON_GetObject(pRoot, "deviceId"));
        const char *pToken = XJSON_GetString(XJSON_GetObject(pRoot, "accessToken"));

        if (pRole != NULL && strcmp(pRole, "client") == 0 && pDevice != NULL && strcmp(pDevice, CLI_DEVICE_ID) == 0 &&
            pToken != NULL && strcmp(pToken, g_cli.sJwt) == 0)
            XSYNC_ATOMIC_SET(&g_cli.bRoleOk, 1);

        /* The relay pairs the client with the host and hands it a session id. */
        g_cli.eStage = HOST_WAIT_HELLO;
        nStatus = host_send(pSession, DirectGate_Proto_BuildCmd("start", NULL, NULL, NULL, CLI_SESSION_ID), NULL, 0);
    }
    else if (strcmp(pType, "auth") == 0)
    {
        const directgate_pkg_auth_t *pAuth = (const directgate_pkg_auth_t*)pkg.pPackage;
        if (pAuth == NULL || pAuth->pAction == NULL) nStatus = XAPI_DISCONNECT;
        else
        {
            if (g_cli.eStage == HOST_WAIT_HELLO)
                g_cli.bKeyMethod = pAuth->pMethod != NULL && strcmp(pAuth->pMethod, "key") == 0;

            nStatus = g_cli.bKeyMethod ? host_key(pSession, pAuth) : host_srp(pSession, pAuth);
        }
    }
    else if (strcmp(pType, "encrypted") == 0)
    {
        nStatus = host_on_sealed(pSession, &pkg);
    }

    DirectGate_Package_Clear(&pkg);
    return nStatus;
}

static int service_callback(xapi_ctx_t *pCtx, xapi_session_t *pSession)
{
    xbool_t bRelay = pSession != NULL && pSession->eType == XAPI_WS;

    switch (pCtx->eCbType)
    {
        case XAPI_CB_ACCEPTED:
            if (bRelay)
            {
                /* Every client connection starts the host's script over. */
                host_rtc_stop();
                g_cli.pRelay = pSession;
                g_cli.eStage = HOST_WAIT_ROLE;
                g_cli.bKeyMethod = XFALSE;
                DirectGate_E2E_Clear(&g_cli.e2e);
                DirectGate_E2E_Init(&g_cli.e2e);
                XByteBuffer_Clear(&g_cli.typed);
            }
            return XAPI_SetEvents(pSession, XPOLLIN);
        case XAPI_CB_HANDSHAKE_REQUEST:
        {
            xhttp_t *pHandle = (xhttp_t*)pSession->pPacket;
            if (pHandle == NULL || strstr(pHandle->sUri, "rk=" CLI_ROUTING_KEY) == NULL) return XAPI_DISCONNECT;
            return XAPI_CONTINUE;
        }
        case XAPI_CB_READ:
            return bRelay ? host_frame(pSession) : api_request(pSession);
        case XAPI_CB_COMPLETE:
            return bRelay ? XAPI_CONTINUE : XAPI_DISCONNECT;
        case XAPI_CB_CLOSED:
            if (pSession == g_cli.pRelay) g_cli.pRelay = NULL;
            return XAPI_CONTINUE;
        case XAPI_CB_TICK:
            host_rtc_tick();
            if (g_cli.pRelay != NULL && XSYNC_ATOMIC_GET(&g_cli.bSendClose))
            {
                XSYNC_ATOMIC_SET(&g_cli.bSendClose, 0);
                host_send(g_cli.pRelay, DirectGate_Proto_BuildStatus("closed", CLI_SESSION_ID), NULL, 0);
            }
            return XAPI_CONTINUE;
        default:
            break;
    }

    return XAPI_CONTINUE;
}

static void* server_thread(void *pArg)
{
    (void)pArg;
    while (!XSYNC_ATOMIC_GET(&g_cli.bStop)) XAPI_Service(&g_cli.api, 20);
    return NULL;
}

static int add_listener(xapi_type_t eType, uint16_t nPort, const tls_fixture_t *pTls)
{
    xapi_endpoint_t endpt;
    XAPI_InitEndpoint(&endpt);

    endpt.eType = eType;
    endpt.eRole = XAPI_SERVER;
    endpt.pAddr = "127.0.0.1";
    endpt.nPort = nPort;
    endpt.pUri = eType == XAPI_WS ? "/websock" : NULL;
    endpt.bTLS = XTRUE;
    endpt.bForce = XTRUE;
    endpt.certs.pCertPath = pTls->sCert;
    endpt.certs.pKeyPath = pTls->sKey;

    return XAPI_AddEndpoint(&g_cli.api, &endpt) >= 0;
}

/* ---- the user's terminal -------------------------------------------------------- */

typedef struct {
    const char *pRoot;
    const char *pCert;
    /* When set, the client sees a display and finds programs here first. */
    const char *pDisplay;
    const char *pBinDir;
    int nMaster;
    pid_t nPid;
    char sScreen[65536];
    size_t nScreen;
} tty_t;

/* Returns how much was read. Every wait loop here counts its turns as time, and a terminal the client has closed
 * polls ready at once and reads nothing: such a turn waits out its time instead, or a loop that should have waited
 * seconds for the client to exit would give up within a millisecond of the hangup. */
static ssize_t tty_pump(tty_t *pTty, int nWaitMs)
{
    struct pollfd pfd = { pTty->nMaster, POLLIN, 0 };
    if (pTty->nMaster < 0 || poll(&pfd, 1, nWaitMs) <= 0 || !(pfd.revents & (POLLIN | POLLHUP))) return 0;

    size_t nRoom = sizeof(pTty->sScreen) - 1 - pTty->nScreen;
    if (nRoom < 4096)
    {
        /* Keep the tail: that is where the next answer appears. */
        size_t nKeep = sizeof(pTty->sScreen) / 2;
        memmove(pTty->sScreen, pTty->sScreen + pTty->nScreen - nKeep, nKeep);
        pTty->nScreen = nKeep;
        nRoom = sizeof(pTty->sScreen) - 1 - pTty->nScreen;
    }

    ssize_t nRead = read(pTty->nMaster, pTty->sScreen + pTty->nScreen, nRoom);
    if (nRead > 0) pTty->nScreen += (size_t)nRead;
    else usleep((useconds_t)nWaitMs * 1000U);

    pTty->sScreen[pTty->nScreen] = '\0';
    return nRead > 0 ? nRead : 0;
}

/* Reads what the client printed until pNeedle shows up or nTimeoutMs passes. */
static int tty_expect(tty_t *pTty, const char *pNeedle, uint32_t nTimeoutMs)
{
    for (uint32_t nWaited = 0; nWaited < nTimeoutMs; nWaited += 20)
    {
        pTty->sScreen[pTty->nScreen] = '\0';
        if (strstr(pTty->sScreen, pNeedle) != NULL) return 1;
        tty_pump(pTty, 20);
    }

    return strstr(pTty->sScreen, pNeedle) != NULL;
}

static int tty_type(tty_t *pTty, const char *pText)
{
    size_t nLen = strlen(pText);
    return write(pTty->nMaster, pText, nLen) == (ssize_t)nLen;
}

static int wait_flag(xatomic_t *pFlag, uint32_t nTimeoutMs, tty_t *pTty)
{
    for (uint32_t nWaited = 0; nWaited < nTimeoutMs; nWaited += 20)
    {
        if (XSYNC_ATOMIC_GET(pFlag)) return 1;
        tty_pump(pTty, 20);
    }

    return XSYNC_ATOMIC_GET(pFlag) != 0;
}

/* Starts dgcli with the given arguments. On a pseudo terminal unless bNoTty,
   in which case stdin is /dev/null and output still lands on the master. */
static int tty_start(tty_t *pTty, const char *const *pArgs, xbool_t bNoTty)
{
    struct winsize ws;
    memset(&ws, 0, sizeof(ws));
    ws.ws_row = 30;
    ws.ws_col = 100;

    pTty->nScreen = 0;
    pTty->sScreen[0] = '\0';
    pTty->nPid = forkpty(&pTty->nMaster, NULL, NULL, &ws);
    if (pTty->nPid < 0) return 0;

    if (pTty->nPid == 0)
    {
        /* A private home: dgcli's default config, session and key live under it. */
        setenv("HOME", pTty->pRoot, 1);
        if (chdir(pTty->pRoot) != 0) _exit(126);
        setenv("SSL_CERT_FILE", pTty->pCert, 1);
        unsetenv("SSL_CERT_DIR");
        unsetenv("DISPLAY");
        unsetenv("WAYLAND_DISPLAY");
        if (pTty->pDisplay != NULL) setenv("DISPLAY", pTty->pDisplay, 1);

        if (pTty->pBinDir != NULL)
        {
            char sPath[512];
            snprintf(sPath, sizeof(sPath), "%s:/usr/bin:/bin", pTty->pBinDir);
            setenv("PATH", sPath, 1);
        }

        unsetenv("DIRECTGATE_API_URL");
        unsetenv("DIRECTGATE_WEB_URL");

        if (bNoTty)
        {
            int nNull = open("/dev/null", O_RDONLY);
            if (nNull >= 0) dup2(nNull, STDIN_FILENO);
        }

        char *pArgv[32];
        size_t n = 0;
        pArgv[n++] = (char*)DIRECTGATE_CLIENT_BIN;
        for (size_t i = 0; pArgs[i] != NULL && n + 1 < sizeof(pArgv) / sizeof(pArgv[0]); i++) pArgv[n++] = (char*)pArgs[i];
        pArgv[n] = NULL;

        execv(DIRECTGATE_CLIENT_BIN, pArgv);
        _exit(127);
    }

    return 1;
}

/* Waits for dgcli to exit and hands back its exit code, or -1. */
static int tty_finish(tty_t *pTty, uint32_t nTimeoutMs)
{
    int nStatus = 0;
    pid_t nDone = 0;

    for (uint32_t nWaited = 0; nWaited < nTimeoutMs && (nDone = waitpid(pTty->nPid, &nStatus, WNOHANG)) == 0; nWaited += 20)
        tty_pump(pTty, 20);

    /* Whatever it printed last is still worth reading. */
    for (int i = 0; i < 10; i++)
    {
        if (tty_pump(pTty, 5) <= 0) break;
    }

    if (nDone != pTty->nPid)
    {
        kill(pTty->nPid, SIGKILL);
        waitpid(pTty->nPid, NULL, 0);
        nStatus = -1;
    }

    pTty->nPid = 0;
    close(pTty->nMaster);
    pTty->nMaster = -1;

    if (nStatus < 0 || !WIFEXITED(nStatus)) return -1;
    return WEXITSTATUS(nStatus);
}

static void write_file(const char *pPath, const char *pText)
{
    FILE *pFile = fopen(pPath, "w");
    if (pFile == NULL) return;
    fputs(pText, pFile);
    fclose(pFile);
}

/* ---- scenarios -------------------------------------------------------------------- */

/* A full password session driven the way a user drives it. */
static int scenario_password_session(tty_t *pTty, const char *pCfg)
{
    reset_outputs();
    const char *args[] = { "-c", pCfg, "-d", "test", "-v", "5", NULL };
    CHECK(tty_start(pTty, args, XFALSE), "start the client on a pseudo terminal");

    /* A unique name prefix picks the device; the password is asked for on the terminal. */
    CHECK(tty_expect(pTty, "Password for " CLI_DEVICE_NAME, 20000), "the client asks for the device password by name");
    CHECK(XSYNC_ATOMIC_GET(&g_cli.nDeviceLists) >= 1, "the client listed the account's devices first");
    CHECK(tty_type(pTty, CLI_SECRET "\n"), "type the password");

    CHECK(wait_flag(&g_cli.bAuthOk, 20000, pTty), "the password logs the client in and the host proves itself");
    CHECK(XSYNC_ATOMIC_GET(&g_cli.nConnects) == 1, "the relay envelope is fetched once, for the chosen device");
    CHECK(XSYNC_ATOMIC_GET(&g_cli.bRoleOk), "the client announces itself with the relay token from the envelope");
    CHECK(wait_flag(&g_cli.bTerminalStarted, 20000, pTty), "the client asks for a terminal after logging in");
    CHECK(wait_flag(&g_cli.bInitialResize, 5000, pTty), "the client reports the size of the terminal it runs in");
    CHECK(tty_expect(pTty, CLI_GREETING, 20000), "what the host prints appears on the user's terminal");

    CHECK(tty_type(pTty, CLI_TYPED "\r"), "type into the session");
    CHECK(wait_flag(&g_cli.bTypedSeen, 20000, pTty), "what the user types reaches the host");
    CHECK(wait_flag(&g_cli.bPongSeen, 20000, pTty), "the client answers the host's keepalive");

    struct winsize ws;
    memset(&ws, 0, sizeof(ws));
    ws.ws_row = 45;
    ws.ws_col = 150;
    CHECK(ioctl(pTty->nMaster, TIOCSWINSZ, &ws) == 0, "resize the terminal");
    kill(pTty->nPid, SIGWINCH);
    CHECK(wait_flag(&g_cli.bResizeSeen, 20000, pTty), "a window resize is sent to the host");

    XSYNC_ATOMIC_SET(&g_cli.bSendClose, 1);
    CHECK(tty_finish(pTty, 10000) == 0, "a session the host closes ends the client cleanly");
    return 0;
}

static int scenario_keys(tty_t *pTty, const char *pCfg, const char *pRoot)
{
    char sKey[256], sOther[256];
    snprintf(sKey, sizeof(sKey), "%s/.config/directgate/auth/key.json", pRoot);
    snprintf(sOther, sizeof(sOther), "%s/other-key.json", pRoot);

    /* Generating a key writes it privately and prints what to do with it. */
    reset_outputs();
    const char *gen[] = { "-c", pCfg, "-g", NULL };
    CHECK(tty_start(pTty, gen, XFALSE), "start a key generation");
    CHECK(tty_finish(pTty, 10000) == 0, "generating a client key succeeds");
    CHECK(strstr(pTty->sScreen, "Client key written to") != NULL, "the client says where the key went");

    struct stat st;
    CHECK(stat(sKey, &st) == 0 && (st.st_mode & 0077) == 0, "the key file is private to the user");

    directgate_client_key_t key;
    char sKeyPub[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    CHECK(DirectGate_KeyAuth_KeyLoad(&key, sKey) &&
        DirectGate_KeyAuth_Base64Encode(key.clientPub, sizeof(key.clientPub), sKeyPub, sizeof(sKeyPub)),
        "the generated key loads back");
    DirectGate_KeyAuth_KeyCleanse(&key);
    CHECK(strstr(pTty->sScreen, sKeyPub) != NULL, "the printed public key is the one in the file");

    /* An existing key is kept unless the user says otherwise. */
    const char *regen[] = { "-c", pCfg, "-g", NULL };
    CHECK(tty_start(pTty, regen, XFALSE), "start a second key generation");
    CHECK(tty_expect(pTty, "Overwrite it", 10000), "the client asks before replacing an existing key");
    CHECK(tty_type(pTty, "n\n"), "decline the overwrite");
    CHECK(tty_finish(pTty, 10000) == 0 && strstr(pTty->sScreen, "Keeping the existing key") != NULL,
        "declining keeps the existing key");

    /* -A authorizes the key on the device, proven with the password. */
    reset_outputs();
    const char *add[] = { "-c", pCfg, "-A", "-d", CLI_DEVICE_ID, NULL };
    CHECK(tty_start(pTty, add, XFALSE), "start a key authorization");
    CHECK(tty_expect(pTty, "Password for", 20000), "authorizing a key asks for the device password");
    CHECK(tty_type(pTty, CLI_SECRET "\n"), "type the password");
    CHECK(wait_flag(&g_cli.bAddKeySeen, 20000, pTty), "the client asks the host to authorize its key");
    CHECK(strcmp(g_cli.sAddedKey, sKeyPub) == 0, "the key sent for authorization is the one in the key file");
    CHECK(tty_finish(pTty, 10000) == 0 && strstr(pTty->sScreen, "Key authorized") != NULL,
        "an authorized key is reported and the client exits cleanly");
    CHECK(XSYNC_ATOMIC_GET(&g_cli.bTerminalStarted) == 0, "authorizing a key never opens a shell");

    /* With the key authorized, the client logs in without a password. */
    reset_outputs();
    xstrncpy(g_cli.sAuthorizedKey, sizeof(g_cli.sAuthorizedKey), sKeyPub);
    XSYNC_ATOMIC_SET(&g_cli.bShortSession, 1);
    const char *keyed[] = { "-c", pCfg, "-k", sKey, CLI_DEVICE_ID, NULL };
    CHECK(tty_start(pTty, keyed, XFALSE), "start a key login");
    CHECK(wait_flag(&g_cli.bKeyAuthOk, 20000, pTty), "an authorized key logs the client in");
    CHECK(tty_expect(pTty, CLI_GREETING, 20000), "the key login opens a shell");
    CHECK(tty_finish(pTty, 10000) == 0, "the key session ends cleanly");
    CHECK(strstr(pTty->sScreen, "Password for") == NULL, "a key login never asks for the password");

    /* A key the host does not know falls back to the password. */
    reset_outputs();
    const char *genOther[] = { "-c", pCfg, "-g", "-k", sOther, NULL };
    CHECK(tty_start(pTty, genOther, XFALSE) && tty_finish(pTty, 10000) == 0, "generate a second, unauthorized key");

    XSYNC_ATOMIC_SET(&g_cli.bShortSession, 1);
    const char *unknown[] = { "-c", pCfg, "-k", sOther, CLI_DEVICE_ID, NULL };
    CHECK(tty_start(pTty, unknown, XFALSE), "start a login with an unauthorized key");
    CHECK(wait_flag(&g_cli.bKeyRefused, 20000, pTty), "the host refuses a key it does not know");
    CHECK(tty_expect(pTty, "Password for", 20000), "a refused key falls back to the password");
    CHECK(tty_type(pTty, CLI_SECRET "\n"), "type the password");
    CHECK(tty_expect(pTty, CLI_GREETING, 20000), "the password fallback opens a shell");
    CHECK(tty_finish(pTty, 10000) == 0, "the fallback session ends cleanly");

    g_cli.sAuthorizedKey[0] = '\0';
    unlink(sOther);
    return 0;
}

/* Extracts port=<n> and state=<s> from the sign-in URL the client printed. */
static int parse_login_url(const char *pScreen, uint16_t *pPort, char *pState, size_t nStateSize)
{
    const char *pUrl = strstr(pScreen, "/cli-auth/start?");
    if (pUrl == NULL) return 0;

    const char *pPortAt = strstr(pUrl, "port=");
    const char *pStateAt = strstr(pUrl, "state=");
    if (pPortAt == NULL || pStateAt == NULL) return 0;

    *pPort = (uint16_t)atoi(pPortAt + 5);
    pStateAt += 6;

    size_t n = 0;
    while (pStateAt[n] != '\0' && pStateAt[n] != '&' && pStateAt[n] != ' ' && pStateAt[n] != '\r' &&
           pStateAt[n] != '\n' && n + 1 < nStateSize)
    {
        pState[n] = pStateAt[n];
        n++;
    }

    pState[n] = '\0';
    return *pPort != 0 && n > 0;
}

/* Plays the browser: sends one raw request to the loopback listener. */
static int loopback_send(uint16_t nPort, const char *pRequest, char *pReply, size_t nReplySize)
{
    int nFd = socket(AF_INET, SOCK_STREAM, 0);
    if (nFd < 0) return 0;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(nPort);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    int nOk = connect(nFd, (struct sockaddr*)&addr, sizeof(addr)) == 0 &&
        write(nFd, pRequest, strlen(pRequest)) == (ssize_t)strlen(pRequest);

    if (nOk && pReply != NULL && nReplySize > 0)
    {
        struct pollfd pfd = { nFd, POLLIN, 0 };
        size_t nGot = 0;
        while (nGot + 1 < nReplySize && poll(&pfd, 1, 3000) > 0)
        {
            ssize_t nRead = read(nFd, pReply + nGot, nReplySize - 1 - nGot);
            if (nRead <= 0) break;
            nGot += (size_t)nRead;
        }

        pReply[nGot] = '\0';
    }

    close(nFd);
    return nOk;
}

/* Leaves every port of the sign-in range in TIME_WAIT, the way a run of
   sign-ins that each answered a browser does for a minute afterwards. The
   accepted side closes first, so the wait is held on the listening port.
   Returns how many ports were put there. */
static int occupy_login_ports(void)
{
    int nOccupied = 0;

    for (uint16_t i = 0; i < 8; i++)
    {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons((uint16_t)(40777 + i));

        int nOne = 1;
        int nServer = socket(AF_INET, SOCK_STREAM, 0);
        int nClient = socket(AF_INET, SOCK_STREAM, 0);
        int nAccepted = -1;

        if (nServer >= 0 && nClient >= 0 &&
            setsockopt(nServer, SOL_SOCKET, SO_REUSEADDR, &nOne, sizeof(nOne)) == 0 &&
            bind(nServer, (struct sockaddr*)&addr, sizeof(addr)) == 0 && listen(nServer, 1) == 0 &&
            connect(nClient, (struct sockaddr*)&addr, sizeof(addr)) == 0 &&
            (nAccepted = accept(nServer, NULL, NULL)) >= 0)
        {
            close(nAccepted);
            usleep(10000);
            nOccupied++;
        }

        if (nClient >= 0) close(nClient);
        if (nServer >= 0) close(nServer);
    }

    return nOccupied;
}

static int scenario_login(tty_t *pTty, const char *pCfg, const char *pRoot)
{
    char sAuth[256];
    snprintf(sAuth, sizeof(sAuth), "%s/.config/directgate/auth/auth.json", pRoot);

    /* Signing in again within a minute of the last attempts must still find a port. */
    CHECK(occupy_login_ports() > 0, "leave the sign-in ports the way recent sign-ins do");

    /* The loopback handoff, with everything a hostile page could try on the way. */
    reset_outputs();
    const char *login[] = { "login", "-c", pCfg, "-B", NULL };
    CHECK(tty_start(pTty, login, XFALSE), "start a sign-in");
    CHECK(tty_expect(pTty, "state=", 10000), "the client prints the sign-in URL");

    uint16_t nPort = 0;
    char sState[128];
    CHECK(parse_login_url(pTty->sScreen, &nPort, sState, sizeof(sState)), "the URL names the loopback port and the state");
    CHECK(strstr(pTty->sScreen, "mode=paste") != NULL, "without a browser the sign-in page is asked to show the code");

    char sReply[4096];
    CHECK(loopback_send(nPort, "OPTIONS /callback HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", sReply, sizeof(sReply)) &&
        strstr(sReply, "204") != NULL, "a CORS preflight is answered without ending the sign-in");
    CHECK(loopback_send(nPort, "GET /favicon.ico HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", sReply, sizeof(sReply)),
        "a stray request is served without ending the sign-in");

    char sReq[1024];
    snprintf(sReq, sizeof(sReq), "POST /callback HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://evil.example\r\n"
        "Content-Type: application/json\r\nContent-Length: %zu\r\n\r\n{\"code\":\"good-code\",\"state\":\"%s\"}",
        strlen("{\"code\":\"good-code\",\"state\":\"\"}") + strlen(sState), sState);
    CHECK(loopback_send(nPort, sReq, sReply, sizeof(sReply)), "post a code from a foreign origin");

    snprintf(sReq, sizeof(sReq), "GET /callback?code=good-code&state=not-this-flow HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    CHECK(loopback_send(nPort, sReq, sReply, sizeof(sReply)), "redirect with another flow's state");
    CHECK(XSYNC_ATOMIC_GET(&g_cli.nTokenRedeems) == 0, "neither a foreign origin nor a foreign state is redeemed");

    snprintf(sReq, sizeof(sReq), "POST /callback HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://example.test\r\n"
        "Content-Type: application/json\r\nContent-Length: %zu\r\n\r\n{\"code\":\"good-code\",\"state\":\"%s\"}",
        strlen("{\"code\":\"good-code\",\"state\":\"\"}") + strlen(sState), sState);
    CHECK(loopback_send(nPort, sReq, sReply, sizeof(sReply)) && strstr(sReply, "\"ok\":true") != NULL,
        "the sign-in page's post from the right origin is accepted");

    CHECK(tty_finish(pTty, 20000) == 0, "a completed sign-in exits cleanly");
    CHECK(strstr(pTty->sScreen, "Signed in as " CLI_EMAIL) != NULL, "the client says who signed in");
    CHECK(XSYNC_ATOMIC_GET(&g_cli.nTokenRedeems) == 1, "the code is redeemed exactly once");

    struct stat st;
    CHECK(stat(sAuth, &st) == 0 && (st.st_mode & 0077) == 0, "the session is stored privately");

    /* whoami and devices use the stored session, not the configured token. */
    const char *whoami[] = { "whoami", "-c", pCfg, NULL };
    CHECK(tty_start(pTty, whoami, XFALSE) && tty_finish(pTty, 10000) == 0, "whoami succeeds");
    CHECK(strstr(pTty->sScreen, CLI_EMAIL) != NULL, "whoami prints the signed-in account");

    /* An expired session is refreshed before it is used. */
    write_file(sAuth, "{\"accessToken\":\"acct-access-1\",\"refreshToken\":\"acct-refresh-1\",\"expiresAt\":1000,"
        "\"email\":\"" CLI_EMAIL "\",\"userId\":\"u-1\"}");
    chmod(sAuth, 0600);

    reset_outputs();
    const char *devices[] = { "devices", "-c", pCfg, NULL };
    CHECK(tty_start(pTty, devices, XFALSE) && tty_finish(pTty, 10000) == 0, "devices succeeds");
    CHECK(XSYNC_ATOMIC_GET(&g_cli.nRefreshes) == 1, "an expired session is refreshed first");
    CHECK(strstr(pTty->sScreen, CLI_DEVICE_NAME) != NULL && strstr(pTty->sScreen, "Unpaired Box") != NULL,
        "devices lists every device the account can see");
    CHECK(strstr(pTty->sScreen, "Gone") == NULL, "a revoked device is not listed");

    xbyte_buffer_t saved;
    CHECK(XPath_LoadBuffer(sAuth, &saved) > 0, "reload the stored session");
    int bRotated = strstr((const char*)saved.pData, "acct-refresh-2") != NULL;
    XByteBuffer_Clear(&saved);
    CHECK(bRotated, "the refreshed session replaces the stored one");

    /* logout forgets it; afterwards, without a terminal, there is nobody to sign in. */
    const char *logout[] = { "logout", "-c", pCfg, NULL };
    CHECK(tty_start(pTty, logout, XFALSE) && tty_finish(pTty, 10000) == 0, "logout succeeds");
    CHECK(access(sAuth, F_OK) != 0, "logout removes the stored session");

    const char *noTty[] = { "whoami", "-c", pCfg, NULL };
    CHECK(tty_start(pTty, noTty, XTRUE), "start whoami without a terminal");
    CHECK(tty_finish(pTty, 10000) != 0, "without a session or a terminal the client fails");
    CHECK(strstr(pTty->sScreen, "Not signed in") != NULL, "the client says it is not signed in");

    /* A pasted code works where the loopback cannot be reached. */
    reset_outputs();
    CHECK(tty_start(pTty, login, XFALSE), "start a sign-in to paste into");
    CHECK(tty_expect(pTty, "paste the code", 10000), "the client asks for the code to be pasted");
    CHECK(tty_type(pTty, "pasted-code\n"), "paste the code");
    CHECK(tty_finish(pTty, 20000) == 0 && XSYNC_ATOMIC_GET(&g_cli.nTokenRedeems) == 1, "a pasted code signs the user in");

    /* The provider can refuse; the client must say so and fail. */
    CHECK(tty_start(pTty, login, XFALSE), "start a sign-in the provider refuses");
    CHECK(tty_expect(pTty, "state=", 10000) && parse_login_url(pTty->sScreen, &nPort, sState, sizeof(sState)),
        "the refused sign-in prints its URL");
    CHECK(loopback_send(nPort, "GET /callback?error=access_denied&error_description=user%20said%20no HTTP/1.1\r\n\r\n",
        sReply, sizeof(sReply)), "the provider redirects with an error");
    CHECK(tty_finish(pTty, 10000) != 0, "a refused sign-in fails");
    CHECK(strstr(pTty->sScreen, "user said no") != NULL, "the provider's reason is shown");

    /* With a display the client opens the browser itself. The opener here only
       writes down what it was given, which has to be the URL as one argument. */
    char sBin[256], sOpener[320], sOpened[320];
    snprintf(sBin, sizeof(sBin), "%s/bin", pRoot);
    snprintf(sOpener, sizeof(sOpener), "%s/xdg-open", sBin);
    snprintf(sOpened, sizeof(sOpened), "%s/opened-url", pRoot);
    CHECK(mkdir(sBin, 0700) == 0 || errno == EEXIST, "a directory for the fake browser opener");
    write_file(sOpener, "#!/bin/sh\n"
        "printf '%s|%s' \"$#\" \"$1\" > \"$HOME/opened-url.tmp\" && mv \"$HOME/opened-url.tmp\" \"$HOME/opened-url\"\n");
    CHECK(chmod(sOpener, 0700) == 0, "the fake opener is executable");

    reset_outputs();
    pTty->pDisplay = ":99";
    pTty->pBinDir = sBin;
    const char *browser[] = { "login", "-c", pCfg, NULL };
    CHECK(tty_start(pTty, browser, XFALSE), "start a sign-in with a display");
    pTty->pDisplay = NULL;
    pTty->pBinDir = NULL;

    xbyte_buffer_t opened;
    XByteBuffer_Init(&opened, XSTDNON, XFALSE);
    for (int i = 0; i < 500 && access(sOpened, F_OK) != 0; i++) tty_pump(pTty, 20);
    CHECK(XPath_LoadBuffer(sOpened, &opened) > 0, "the client opens the browser");
    char sOpenedText[1024];
    xstrncpy(sOpenedText, sizeof(sOpenedText), (const char*)opened.pData);
    XByteBuffer_Clear(&opened);
    CHECK(strncmp(sOpenedText, "1|https://", 10) == 0, "the browser is handed the URL as one argument, nothing else");
    CHECK(strstr(sOpenedText, "mode=paste") == NULL, "with a browser the sign-in page redirects straight back");
    CHECK(parse_login_url(sOpenedText, &nPort, sState, sizeof(sState)), "the opened URL names the port and the state");

    snprintf(sReq, sizeof(sReq), "GET /callback?code=good-code&state=%s HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", sState);
    CHECK(loopback_send(nPort, sReq, sReply, sizeof(sReply)), "the provider redirects back with the code");
    CHECK(tty_finish(pTty, 20000) == 0 && XSYNC_ATOMIC_GET(&g_cli.nTokenRedeems) == 1, "the browser sign-in completes");
    unlink(sOpened);

    /* A stored session the API will not refresh any more: the client signs in again and goes on. */
    write_file(sAuth, "{\"accessToken\":\"acct-access-0\",\"refreshToken\":\"acct-refresh-stale\",\"expiresAt\":1000,"
        "\"email\":\"" CLI_EMAIL "\",\"userId\":\"u-1\"}");
    chmod(sAuth, 0600);

    reset_outputs();
    const char *stale[] = { "devices", "-c", pCfg, "-B", NULL };
    CHECK(tty_start(pTty, stale, XFALSE), "start with a session that no longer refreshes");
    CHECK(tty_expect(pTty, "paste the code", 20000), "a session that cannot be refreshed leads to a new sign-in");
    CHECK(tty_type(pTty, "pasted-code\n"), "paste the code for the new sign-in");
    CHECK(tty_finish(pTty, 20000) == 0, "after signing in again the command goes on");
    CHECK(XSYNC_ATOMIC_GET(&g_cli.nRefreshes) == 1 && XSYNC_ATOMIC_GET(&g_cli.nTokenRedeems) == 1,
        "the refresh was tried once, then the new sign-in redeemed once");
    CHECK(strstr(pTty->sScreen, CLI_DEVICE_NAME) != NULL, "the devices are listed with the new session");

    /* A stored session that is not JSON is ignored, not trusted and not fatal. */
    write_file(sAuth, "{ this is not a session");
    chmod(sAuth, 0600);
    const char *corrupt[] = { "whoami", "-c", pCfg, NULL };
    CHECK(tty_start(pTty, corrupt, XTRUE), "start whoami over a corrupt session file");
    CHECK(tty_finish(pTty, 10000) != 0 && strstr(pTty->sScreen, "Not signed in") != NULL,
        "a corrupt session file counts as not signed in");

    unlink(sAuth);
    return 0;
}

static int scenario_failures(tty_t *pTty, const char *pCfg, const char *pRoot)
{
    /* Usage, and an unknown option. */
    const char *help[] = { "-h", NULL };
    CHECK(tty_start(pTty, help, XFALSE), "start with -h");
    CHECK(tty_finish(pTty, 10000) != 0 && strstr(pTty->sScreen, "Usage:") != NULL, "-h prints the usage");

    /* A device query nobody matches, and a device that cannot be connected. */
    const char *nomatch[] = { "-c", pCfg, "-d", "no-such-device", NULL };
    CHECK(tty_start(pTty, nomatch, XFALSE), "start with an unknown device");
    CHECK(tty_finish(pTty, 10000) != 0, "an unknown device fails");
    CHECK(strstr(pTty->sScreen, "No device matches") != NULL && strstr(pTty->sScreen, CLI_DEVICE_NAME) != NULL,
        "an unknown device lists the ones that exist");

    const char *unpaired[] = { "-c", pCfg, "-d", "dev-unpaired", NULL };
    CHECK(tty_start(pTty, unpaired, XFALSE), "start with an unpaired device");
    CHECK(tty_finish(pTty, 10000) != 0 && strstr(pTty->sScreen, "not paired") != NULL,
        "a device that is not paired is refused with the reason");

    const char *shared[] = { "-c", pCfg, "-d", "Shared", NULL };
    CHECK(tty_start(pTty, shared, XFALSE), "start with an expired shared device");
    CHECK(tty_finish(pTty, 10000) != 0 && strstr(pTty->sScreen, "enrollment expired") != NULL,
        "a device whose enrollment expired is refused with the reason");

    /* A wrong password ends the session and must not look like success. */
    reset_outputs();
    const char *wrong[] = { "-c", pCfg, "-d", CLI_DEVICE_ID, NULL };
    CHECK(tty_start(pTty, wrong, XFALSE), "start a login with a wrong password");
    CHECK(tty_expect(pTty, "Password for", 20000), "the password is asked for");
    CHECK(tty_type(pTty, "not the password\n"), "type a wrong password");
    int nExit = tty_finish(pTty, 20000);
    CHECK(strstr(pTty->sScreen, "Authentication failed") != NULL, "a wrong password is reported");
    CHECK(nExit != 0, "a failed login exits with an error");

    /* A config that does not load is an error, not a quiet success. */
    char sBad[256];
    snprintf(sBad, sizeof(sBad), "%s/broken.json", pRoot);
    write_file(sBad, "{ this is not json");
    const char *broken[] = { "-c", sBad, "devices", NULL };
    CHECK(tty_start(pTty, broken, XFALSE), "start with a broken config");
    CHECK(tty_finish(pTty, 10000) != 0, "a config that does not parse exits with an error");
    unlink(sBad);

    const char *missing[] = { "-c", "/nonexistent/dgcli.json", "devices", NULL };
    CHECK(tty_start(pTty, missing, XFALSE), "start with a missing config");
    CHECK(tty_finish(pTty, 10000) != 0, "a config that does not exist exits with an error");

    /* A relay the API names that is not a WebSocket endpoint, or names no host: never connected to.
       The key from the earlier scenarios signs in, so no password is asked first. */
    char sSavedRelay[sizeof(g_cli.sRelayUrl)];
    snprintf(sSavedRelay, sizeof(sSavedRelay), "%s", g_cli.sRelayUrl);
    static const char *pBadRelays[] = { "https://127.0.0.1:1/websock", "wss://" };

    for (size_t i = 0; i < sizeof(pBadRelays) / sizeof(pBadRelays[0]); i++)
    {
        snprintf(g_cli.sRelayUrl, sizeof(g_cli.sRelayUrl), "%s", pBadRelays[i]);
        const char *relay[] = { "-c", pCfg, "-d", CLI_DEVICE_ID, NULL };
        CHECK(tty_start(pTty, relay, XFALSE), "start against a relay that cannot be used");
        CHECK(tty_finish(pTty, 20000) != 0, "a relay that is not a usable WebSocket endpoint is refused");
        CHECK(strstr(pTty->sScreen, i == 0 ? "Unencrypted relay" : "Failed to parse URL") != NULL, "and says why");
    }

    snprintf(g_cli.sRelayUrl, sizeof(g_cli.sRelayUrl), "%s", sSavedRelay);
    return 0;
}

/* Starts a password login against a host set to misbehave, types the password
   when asked, and hands back the exit code. */
static int faulty_login(tty_t *pTty, const char *pCfg, host_fault_t eFault, const char *pExtra)
{
    reset_outputs();
    XSYNC_ATOMIC_SET(&g_cli.eFault, eFault);
    XSYNC_ATOMIC_SET(&g_cli.bShortSession, 1);

    const char *extra[] = { "-c", pCfg, "-v", "5", pExtra, CLI_DEVICE_ID, NULL };
    const char *plain[] = { "-c", pCfg, "-v", "5", CLI_DEVICE_ID, NULL };
    if (!tty_start(pTty, pExtra != NULL ? extra : plain, XFALSE)) return -2;
    if (!tty_expect(pTty, "Password for", 20000) || !tty_type(pTty, CLI_SECRET "\n")) return -3;
    return tty_finish(pTty, 20000);
}

static int scenario_bad_host(tty_t *pTty, const char *pCfg, const char *pRoot)
{
    /* Before the login: a host that cannot complete the exchange is never trusted. */
    CHECK(faulty_login(pTty, pCfg, FAULT_CHALLENGE_NO_B, NULL) != 0, "a challenge without its public value fails the login");
    CHECK(strstr(pTty->sScreen, "missing fields") != NULL, "a challenge missing its parts is reported");

    CHECK(faulty_login(pTty, pCfg, FAULT_CHALLENGE_BAD_NONCE, NULL) != 0, "a challenge with an unreadable nonce fails the login");
    CHECK(strstr(pTty->sScreen, "Invalid agent nonce") != NULL, "an unreadable nonce is reported");

    CHECK(faulty_login(pTty, pCfg, FAULT_SEALED_BEFORE_AUTH, NULL) != 0, "sealed traffic before any keys fails the login");
    CHECK(strstr(pTty->sScreen, "E2E not initialized") != NULL, "sealed traffic before the keys exist is reported");

    CHECK(faulty_login(pTty, pCfg, FAULT_NOT_A_MESSAGE, NULL) != 0, "bytes that are no message fail the login");
    CHECK(strstr(pTty->sScreen, "Invalid protocol message") != NULL, "a frame that is no message is reported");

    /* The host has to prove it holds the verifier; an "ok" alone is not enough. */
    CHECK(faulty_login(pTty, pCfg, FAULT_WRONG_M2, NULL) != 0, "a host that cannot prove itself fails the login");
    CHECK(strstr(pTty->sScreen, "server proof verification failed") != NULL, "a wrong host proof is reported");
    CHECK(XSYNC_ATOMIC_GET(&g_cli.bTerminalStarted) == 0, "nothing is sent to a host that did not prove itself");

    CHECK(faulty_login(pTty, pCfg, FAULT_AUTH_ERROR, NULL) != 0, "an auth error fails the login");
    CHECK(strstr(pTty->sScreen, "Authentication error: relay busy") != NULL, "the auth error is reported with its reason");
    CHECK(strstr(pTty->sScreen, "\x1b[31m") == NULL, "an escape sequence in the relay's words never reaches the terminal");

    /* A pre-logon host serves desktops only: there is no shell to give, and that is a failure. */
    CHECK(faulty_login(pTty, pCfg, FAULT_PRE_LOGON, NULL) != 0, "a host with nobody logged on is a failure, not a session");
    CHECK(strstr(pTty->sScreen, "Nobody is logged on") != NULL, "a pre-logon host is explained");
    CHECK(XSYNC_ATOMIC_GET(&g_cli.bTerminalStarted) == 0, "no shell is asked of a pre-logon host");

    /* After the login: traffic that does not belong ends the session as a failure. */
    CHECK(faulty_login(pTty, pCfg, FAULT_SID_MISMATCH, NULL) != 0, "sealed traffic for another session fails the session");
    CHECK(strstr(pTty->sScreen, "session id mismatch") != NULL, "a session id mismatch is reported");
    CHECK(strstr(pTty->sScreen, "stray") == NULL, "what was sealed for another session is never shown");

    CHECK(faulty_login(pTty, pCfg, FAULT_PLAIN_AFTER_AUTH, NULL) != 0, "plain traffic after the login fails the session");
    CHECK(strstr(pTty->sScreen, "Protocol violation") != NULL, "plain traffic after the login is reported");
    CHECK(strstr(pTty->sScreen, "forged") == NULL, "plain traffic after the login is never shown");

    CHECK(faulty_login(pTty, pCfg, FAULT_BAD_INNER, NULL) != 0, "a sealed message that is no message fails the session");
    CHECK(strstr(pTty->sScreen, "Failed to parse decrypted message") != NULL, "an unreadable sealed message is reported");

    /* Oddities that are survivable are survived: the greeting still arrives and the session ends cleanly. */
    CHECK(faulty_login(pTty, pCfg, FAULT_ODDITIES, NULL) == 0, "a session survives traffic it can drop");
    CHECK(strstr(pTty->sScreen, CLI_GREETING) != NULL, "the session goes on after the oddities");
    CHECK(strstr(pTty->sScreen, "Dropped undecryptable message") != NULL, "a message under the wrong keys is dropped");
    CHECK(strstr(pTty->sScreen, "Received server side error message: relay") != NULL, "a relay notice is shown");
    CHECK(strstr(pTty->sScreen, "\x1b[2J") == NULL, "an escape sequence in a relay notice never reaches the terminal");
    CHECK(XSYNC_ATOMIC_GET(&g_cli.bWsPongSeen), "the client answers the relay's WebSocket ping");

    /* A pushed file stays in the working directory, never replaces one, and a cancelled one is removed. */
    char sPushed[256], sClimbed[256], sPartial[256];
    snprintf(sPushed, sizeof(sPushed), "%s/pushed.txt", pRoot);
    snprintf(sClimbed, sizeof(sClimbed), "%s/../pushed.txt", pRoot);
    snprintf(sPartial, sizeof(sPartial), "%s/partial.txt", pRoot);

    CHECK(faulty_login(pTty, pCfg, FAULT_FILE_PUSH, NULL) == 0, "a session with pushed files ends cleanly");
    CHECK(XSYNC_ATOMIC_GET(&g_cli.bFileAcked), "a completed file is acknowledged to the host");

    xbyte_buffer_t pushed;
    CHECK(XPath_LoadBuffer(sPushed, &pushed) > 0, "the pushed file is in the working directory");
    int bSame = pushed.nUsed == strlen(CLI_PUSHED_TEXT) && memcmp(pushed.pData, CLI_PUSHED_TEXT, pushed.nUsed) == 0;
    XByteBuffer_Clear(&pushed);
    CHECK(bSame, "the pushed file holds what was sent, and a second push did not replace it");
    CHECK(access(sClimbed, F_OK) != 0, "a pushed name cannot climb out of the working directory");
    CHECK(access(sPartial, F_OK) != 0, "a cancelled file is not left behind");
    unlink(sPushed);

    /* Key authorization answered with a refusal, and with "already". */
    CHECK(faulty_login(pTty, pCfg, FAULT_ADD_KEY_REFUSED, "-A") != 0, "a refused key authorization is a failure");
    CHECK(strstr(pTty->sScreen, "Device refused the key: keys are managed") != NULL, "the refusal is reported with its reason");
    CHECK(strstr(pTty->sScreen, "\x1b]0;") == NULL, "an escape sequence in the refusal never reaches the terminal");

    CHECK(faulty_login(pTty, pCfg, FAULT_ADD_KEY_ALREADY, "-A") == 0, "a key that is already authorized is a success");
    CHECK(strstr(pTty->sScreen, "already authorized") != NULL, "an already authorized key is reported");
    return 0;
}

/* Waits for a prompt, forgets what was on screen so far, and answers it. */
static int tty_answer(tty_t *pTty, const char *pPrompt, const char *pAnswer)
{
    if (!tty_expect(pTty, pPrompt, 20000)) return 0;

    pTty->nScreen = 0;
    pTty->sScreen[0] = '\0';

    char sLine[512];
    snprintf(sLine, sizeof(sLine), "%s\n", pAnswer);
    return tty_type(pTty, sLine);
}

/* Setting dgcli up by hand: -i writes a config from prompts, -s keeps a local
   name for a device, -n connects by that name, and the arrow-key picker picks
   a device when none is named. */
static int scenario_local(tty_t *pTty, const char *pCfg, const char *pRoot)
{
    char sInit[256], sList[256], sApiUrl[128], sText[4096];
    snprintf(sInit, sizeof(sInit), "%s/init.json", pRoot);
    snprintf(sList, sizeof(sList), "%s/devices.txt", pRoot);
    snprintf(sApiUrl, sizeof(sApiUrl), "https://127.0.0.1:%u", (unsigned)g_cli.nApiPort);

    /* -i asks for everything a config holds and writes it privately. */
    const char *init[] = { "-c", sInit, "-i", NULL };
    CHECK(tty_start(pTty, init, XFALSE), "start a config init");
    CHECK(tty_answer(pTty, "API URL", sApiUrl), "init asks for the API");
    CHECK(tty_answer(pTty, "Signaling URL", ""), "init asks for the relay and takes the default");
    CHECK(tty_answer(pTty, "Device list path", sList), "init asks where the local device list lives");
    CHECK(tty_answer(pTty, "Log to screen", "y"), "init asks about logging to the screen");
    CHECK(tty_answer(pTty, "Log to file", "n"), "init asks about logging to a file");
    CHECK(tty_finish(pTty, 10000) == 0, "init succeeds");

    struct stat st;
    CHECK(stat(sInit, &st) == 0 && (st.st_mode & 0077) == 0, "the written config is private to the user");
    xbyte_buffer_t cfg;
    CHECK(XPath_LoadBuffer(sInit, &cfg) > 0, "the written config loads");
    xstrncpy(sText, sizeof(sText), (const char*)cfg.pData);
    XByteBuffer_Clear(&cfg);
    CHECK(strstr(sText, sApiUrl) != NULL && strstr(sText, sList) != NULL, "the config holds what was typed");

    /* A yes/no question answered with neither stops the init. */
    char sBadInit[256];
    snprintf(sBadInit, sizeof(sBadInit), "%s/bad-init.json", pRoot);
    const char *badInit[] = { "-c", sBadInit, "-i", NULL };
    CHECK(tty_start(pTty, badInit, XFALSE), "start an init answered wrongly");
    CHECK(tty_answer(pTty, "API URL", sApiUrl) && tty_answer(pTty, "Signaling URL", "") &&
        tty_answer(pTty, "Device list path", sList), "answer the first questions");
    CHECK(tty_answer(pTty, "Log to screen", "maybe"), "answer a yes/no question with neither");
    CHECK(tty_finish(pTty, 10000) != 0 && access(sBadInit, F_OK) != 0, "an unusable answer writes no config");

    /* -s keeps a name for a device id, and refuses to change it without -f. */
    const char *save[] = { "-c", sInit, "-s", "-n", "Home Box", NULL };
    CHECK(tty_start(pTty, save, XFALSE), "start saving a device name");
    CHECK(tty_answer(pTty, "Device ID", CLI_DEVICE_ID), "saving a name asks for the device id");
    CHECK(tty_finish(pTty, 10000) == 0, "saving a device name succeeds");
    CHECK(XPath_LoadBuffer(sList, &cfg) > 0, "the device list is written");
    int bListed = strstr((const char*)cfg.pData, "Home Box") != NULL && strstr((const char*)cfg.pData, CLI_DEVICE_ID) != NULL;
    XByteBuffer_Clear(&cfg);
    CHECK(bListed, "the device list holds the name and the id");

    const char *again[] = { "-c", sInit, "-s", "-n", "Home Box", "-d", "dev-other", NULL };
    CHECK(tty_start(pTty, again, XFALSE), "start saving the same name again");
    CHECK(tty_finish(pTty, 10000) != 0, "a name already in the list is not replaced without -f");

    const char *force[] = { "-c", sInit, "-s", "-f", "-n", "Home Box", "-d", CLI_DEVICE_ID, NULL };
    CHECK(tty_start(pTty, force, XFALSE), "start replacing the name with -f");
    CHECK(tty_finish(pTty, 10000) == 0, "-f replaces a name already in the list");

    /* -n connects by the saved name. The init config has no API token, so it
       borrows the one the other config uses through the environment. */
    reset_outputs();
    XSYNC_ATOMIC_SET(&g_cli.bShortSession, 1);
    const char *byName[] = { "-c", pCfg, "-p", sList, "-n", "Home Box", NULL };
    CHECK(tty_start(pTty, byName, XFALSE), "start a connection by saved name");
    CHECK(tty_answer(pTty, "Password for", CLI_SECRET), "a connection by saved name reaches the password");
    CHECK(tty_expect(pTty, CLI_GREETING, 20000), "a connection by saved name opens a shell on that device");
    CHECK(tty_finish(pTty, 10000) == 0, "the connection by saved name ends cleanly");

    /* No device named: the picker. Moving onto a device that cannot be
       connected and choosing it only says so; the first one can be chosen. */
    reset_outputs();
    XSYNC_ATOMIC_SET(&g_cli.bShortSession, 1);
    const char *pick[] = { "-c", pCfg, NULL };
    CHECK(tty_start(pTty, pick, XFALSE), "start without naming a device");
    CHECK(tty_expect(pTty, "Select a device", 20000), "the picker is shown");
    CHECK(tty_type(pTty, "\x1b[Bjk\x1b[F\x1b[AG"), "move through the list");
    xusleep(200000);
    CHECK(tty_type(pTty, "\r"), "choose the last device");
    CHECK(tty_expect(pTty, "cannot connect to this device", 10000), "a device that cannot be connected is not taken");
    CHECK(tty_type(pTty, "x\x1b[Zg\x1b[H\r"), "go back to the first device and choose it");
    CHECK(tty_answer(pTty, "Password for", CLI_SECRET), "the chosen device asks for its password");
    CHECK(tty_expect(pTty, CLI_GREETING, 20000), "the chosen device opens a shell");
    CHECK(tty_finish(pTty, 10000) == 0, "the picked session ends cleanly");

    /* Backing out of the picker connects to nothing. */
    reset_outputs();
    const char *quit[] = { "-c", pCfg, NULL };
    CHECK(tty_start(pTty, quit, XFALSE), "start the picker to back out of");
    CHECK(tty_expect(pTty, "Select a device", 20000), "the picker is shown again");
    CHECK(tty_type(pTty, "q"), "back out");
    tty_finish(pTty, 10000);
    CHECK(XSYNC_ATOMIC_GET(&g_cli.nConnects) == 0, "backing out of the picker connects to nothing");

    const char *escape[] = { "-c", pCfg, NULL };
    CHECK(tty_start(pTty, escape, XFALSE), "start the picker to escape from");
    CHECK(tty_expect(pTty, "Select a device", 20000), "the picker is shown once more");
    CHECK(tty_type(pTty, "\x1b"), "press Escape");
    tty_finish(pTty, 10000);
    CHECK(XSYNC_ATOMIC_GET(&g_cli.nConnects) == 0, "Escape backs out of the picker too");
    return 0;
}

/* What the client does when something it needs is not there. */
static int scenario_client_edges(tty_t *pTty, const char *pCfg, const char *pRoot)
{
    char sKey[256], sBadKey[256];
    snprintf(sKey, sizeof(sKey), "%s/.config/directgate/auth/key.json", pRoot);
    snprintf(sBadKey, sizeof(sBadKey), "%s/bad-key.json", pRoot);

    /* A key is offered only to a host that published one, since that is what the host is pinned to.
       With the default key the password is what is left; with -k nothing is, and it says so. */
    reset_outputs();
    const char *noHostKey[] = { "-c", pCfg, "No Key Box", NULL };
    CHECK(tty_start(pTty, noHostKey, XFALSE), "start a login to a device without a host key");
    CHECK(tty_expect(pTty, "looks offline", 20000), "a device that looks offline is still tried, with a warning");
    CHECK(tty_expect(pTty, "has not published a host key, using the password", 5000),
        "a device without a host key is not offered the default key");
    CHECK(tty_answer(pTty, "Password for", CLI_SECRET), "the password is asked for instead");
    CHECK(tty_finish(pTty, 20000) != 0, "a device the API will not connect to fails");
    CHECK(strstr(pTty->sScreen, "relay connection envelope") != NULL, "the refused connection is reported");

    const char *noHostKeyRequired[] = { "-c", pCfg, "-k", sKey, "No Key Box", NULL };
    CHECK(tty_start(pTty, noHostKeyRequired, XFALSE), "start a -k login to a device without a host key");
    CHECK(tty_finish(pTty, 20000) != 0, "a -k login to a device without a host key fails");
    CHECK(strstr(pTty->sScreen, "the key given with -k cannot be used") != NULL, "the reason is the missing host key");
    CHECK(strstr(pTty->sScreen, "using the password") == NULL && strstr(pTty->sScreen, "Password for") == NULL,
        "a -k login never promises or asks for the password");

    /* A key file that is not a key: with -k there is no quiet fallback. */
    write_file(sBadKey, "{ not a key");
    chmod(sBadKey, 0600);
    const char *badKey[] = { "-c", pCfg, "-k", sBadKey, CLI_DEVICE_ID, NULL };
    CHECK(tty_start(pTty, badKey, XFALSE), "start with an unusable key file");
    CHECK(tty_finish(pTty, 20000) != 0, "an unusable key named with -k fails");
    CHECK(strstr(pTty->sScreen, "refusing to fall back") != NULL, "the client says it will not fall back");
    unlink(sBadKey);

    /* -A needs a key to add. */
    char sMissingKey[256];
    snprintf(sMissingKey, sizeof(sMissingKey), "%s/no-such-key.json", pRoot);
    const char *noKey[] = { "-c", pCfg, "-A", "-k", sMissingKey, "-d", CLI_DEVICE_ID, NULL };
    CHECK(tty_start(pTty, noKey, XFALSE), "start authorizing a key that is not there");
    CHECK(tty_finish(pTty, 10000) != 0 && strstr(pTty->sScreen, "No client key at") != NULL,
        "authorizing a missing key says where the key would be and fails");

    /* No terminal to ask for the password on, and no key to use instead. */
    char sAside[300];
    snprintf(sAside, sizeof(sAside), "%s.aside", sKey);
    CHECK(rename(sKey, sAside) == 0, "put the default key aside");
    reset_outputs();
    const char *noTty[] = { "-c", pCfg, CLI_DEVICE_ID, NULL };
    CHECK(tty_start(pTty, noTty, XTRUE), "start a password login without a terminal");
    int nNoTty = tty_finish(pTty, 20000);
    CHECK(rename(sAside, sKey) == 0, "put the default key back");
    CHECK(nNoTty != 0 && strstr(pTty->sScreen, "password is required") != NULL,
        "without a terminal to type a password on, the client fails and says why");

    /* An account with nothing on it. */
    reset_outputs();
    XSYNC_ATOMIC_SET(&g_cli.bEmptyList, 1);
    const char *empty[] = { "-c", pCfg, NULL };
    CHECK(tty_start(pTty, empty, XFALSE), "start with an account that has no devices");
    CHECK(tty_finish(pTty, 20000) != 0 && strstr(pTty->sScreen, "No devices on this account yet") != NULL,
        "an account without devices says where to add one and fails");

    /* An envelope without a routing key is refused before the relay is contacted:
       the key is what every relay handshake has to carry. */
    reset_outputs();
    XSYNC_ATOMIC_SET(&g_cli.bEnvelopeNoRk, 1);
    const char *noRk[] = { "-c", pCfg, CLI_DEVICE_ID, NULL };
    CHECK(tty_start(pTty, noRk, XFALSE), "start with an envelope that has no routing key");
    CHECK(tty_finish(pTty, 20000) != 0, "an envelope without a routing key fails the connection");
    CHECK(strstr(pTty->sScreen, "missing relay.routingKey") != NULL, "the missing routing key is named");
    CHECK(XSYNC_ATOMIC_GET(&g_cli.bRoleOk) == 0, "the relay is never contacted without a routing key");
    return 0;
}

/* The client's offer answered by the agent's own WebRTC code over loopback:
   once the data channel is up the session runs over it, both ways. */
static int scenario_direct(tty_t *pTty, const char *pCfg)
{
    reset_outputs();
    XSYNC_ATOMIC_SET(&g_cli.eFault, FAULT_P2P);

    const char *args[] = { "-c", pCfg, "-v", "5", CLI_DEVICE_ID, NULL };
    CHECK(tty_start(pTty, args, XFALSE), "start a session that goes direct");
    CHECK(tty_expect(pTty, "Password for", 20000) && tty_type(pTty, CLI_SECRET "\n"), "log in");
    CHECK(wait_flag(&g_cli.bRtcConnected, 30000, pTty), "the client's offer becomes a direct connection");
    CHECK(tty_expect(pTty, CLI_GREETING, 20000), "what the host sends over the data channel reaches the terminal");

    CHECK(tty_type(pTty, CLI_TYPED "\r"), "type into the direct session");
    CHECK(wait_flag(&g_cli.bRtcTyped, 20000, pTty), "what the user types goes over the data channel");

    XSYNC_ATOMIC_SET(&g_cli.bSendClose, 1);
    CHECK(tty_finish(pTty, 10000) == 0, "a direct session the host closes ends cleanly");
    return 0;
}

int main(void)
{
    memset(&g_cli, 0, sizeof(g_cli));
    signal(SIGPIPE, SIG_IGN);

    if (access(DIRECTGATE_CLIENT_BIN, X_OK) != 0)
    {
        printf("client_e2e_smoke: client binary not built, skipping\n");
        return 77;
    }

    tls_fixture_t tls;
    CHECK(tls_fixture_begin(&tls), "create a TLS identity for the test endpoints");

    char sRoot[] = "/tmp/directgate_cli_e2e.XXXXXX";
    CHECK(mkdtemp(sRoot) != NULL, "create a working directory");

    g_cli.nApiPort = reserve_port();
    g_cli.nRelayPort = reserve_port();
    CHECK(g_cli.nApiPort && g_cli.nRelayPort && g_cli.nApiPort != g_cli.nRelayPort, "reserve two local ports");
    snprintf(g_cli.sRelayUrl, sizeof(g_cli.sRelayUrl), "wss://127.0.0.1:%u/websock", (unsigned)g_cli.nRelayPort);
    make_jwt(g_cli.sJwt, sizeof(g_cli.sJwt));

    memset(g_cli.salt, 0x4d, sizeof(g_cli.salt));
    for (size_t i = 0; i < sizeof(g_cli.salt); i++) snprintf(g_cli.sSaltHex + (i * 2), 3, "%02x", g_cli.salt[i]);
    CHECK(DirectGate_SRP_CreateVerifier(CLI_SECRET, g_cli.salt, sizeof(g_cli.salt), g_cli.sVerifier,
        sizeof(g_cli.sVerifier)), "create the host's SRP verifier");
    CHECK(DirectGate_KeyAuth_Ed25519Generate(g_cli.agentPub, g_cli.agentSeed) &&
        DirectGate_KeyAuth_Base64Encode(g_cli.agentPub, sizeof(g_cli.agentPub), g_cli.sAgentPubB64,
            sizeof(g_cli.sAgentPubB64)), "create the host's identity");

    XByteBuffer_Init(&g_cli.typed, XSTDNON, XFALSE);
    DirectGate_E2E_Init(&g_cli.e2e);
    DirectGate_KeyAuth_Init(&g_cli.keyauth);
    XAPI_Init(&g_cli.api, service_callback, &g_cli);
    CHECK(add_listener(XAPI_HTTP, g_cli.nApiPort, &tls), "start the API");
    CHECK(add_listener(XAPI_WS, g_cli.nRelayPort, &tls), "start the relay");

    xthread_t thread;
    CHECK(XThread_Create(&thread, server_thread, NULL, XFALSE) == XSTDOK, "start the server thread");

    char sCfg[256], sAcctCfg[256];
    snprintf(sCfg, sizeof(sCfg), "%s/dgcli.json", sRoot);
    snprintf(sAcctCfg, sizeof(sAcctCfg), "%s/dgcli-account.json", sRoot);

    char sText[1024];
    snprintf(sText, sizeof(sText), "{\"apiUrl\":\"https://127.0.0.1:%u\",\"apiToken\":\"%s\",\"webUrl\":\"https://example.test\","
        "\"log\":{\"toScreen\":true,\"toFile\":false}}\n", (unsigned)g_cli.nApiPort, CLI_API_TOKEN);
    write_file(sCfg, sText);

    /* No API token: this one has to sign in to an account. */
    snprintf(sText, sizeof(sText), "{\"apiUrl\":\"https://127.0.0.1:%u\",\"webUrl\":\"https://example.test\","
        "\"log\":{\"toScreen\":true,\"toFile\":false}}\n", (unsigned)g_cli.nApiPort);
    write_file(sAcctCfg, sText);

    tty_t tty;
    memset(&tty, 0, sizeof(tty));
    tty.nMaster = -1;
    tty.pRoot = sRoot;
    tty.pCert = tls.sCert;

    int nResult = scenario_password_session(&tty, sCfg);
    if (!nResult) nResult = scenario_keys(&tty, sCfg, sRoot);
    if (!nResult) nResult = scenario_login(&tty, sAcctCfg, sRoot);
    if (!nResult) nResult = scenario_failures(&tty, sCfg, sRoot);
    if (!nResult) nResult = scenario_bad_host(&tty, sCfg, sRoot);
    if (!nResult) nResult = scenario_direct(&tty, sCfg);
    if (!nResult) nResult = scenario_local(&tty, sCfg, sRoot);
    if (!nResult) nResult = scenario_client_edges(&tty, sCfg, sRoot);

    if (nResult != 0)
    {
        tty.sScreen[tty.nScreen] = '\0';
        fprintf(stderr, "---- client terminal ----\n%s\n-------------------------\n", tty.sScreen);
    }

    if (tty.nPid > 0)
    {
        kill(tty.nPid, SIGKILL);
        waitpid(tty.nPid, NULL, 0);
    }

    if (tty.nMaster >= 0) close(tty.nMaster);

    XSYNC_ATOMIC_SET(&g_cli.bStop, 1);
    XThread_Join(&thread);
    host_rtc_stop();
    XAPI_Destroy(&g_cli.api);
    DirectGate_WebRTC_Cleanup();

    DirectGate_SRP_Destroy(&g_cli.srp);
    DirectGate_KeyAuth_Cleanse(&g_cli.keyauth);
    DirectGate_E2E_Clear(&g_cli.e2e);
    XByteBuffer_Clear(&g_cli.typed);
    OPENSSL_cleanse(g_cli.agentSeed, sizeof(g_cli.agentSeed));

    /* Everything dgcli wrote lives under the private home. */
    char sCmd[512];
    snprintf(sCmd, sizeof(sCmd), "rm -rf '%s'", sRoot);
    if (system(sCmd) != 0) fprintf(stderr, "client_e2e_smoke: could not remove %s\n", sRoot);
    tls_fixture_end(&tls);

    if (nResult != 0) return 1;
    puts("client_e2e_smoke: OK");
    return 0;
}
