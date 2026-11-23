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

#include "src/common/transfer.h"
#include "src/client/remote.h"

#include "tls_fixture.h"
#include "webrtc_teardown.h"

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
    HOST_REMOTE,                    /* exec or file-manager mode: answers remote operations */
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

    /* Remote operations: what the host offers, what it was asked and what it was sent. */
    xatomic_t bOfferExec;
    xatomic_t bExecStarted;
    xatomic_t bExecSignalled;
    xatomic_t bUploadDone;
    xatomic_t nRemoteModes;
    char sExecCommand[256];
    char sExecSignal[16];
    char sExecCwd[256];
    uint32_t nExecTimeoutMs;
    uint32_t nExecOutputMax;
    xbool_t bExecOutputMax;
    xbool_t bExecStdin;
    char sManagerLast[600];
    char sRacePath[512];
    char sUploadId[64];
    xbyte_buffer_t execInput;
    xbyte_buffer_t upload;

    /* The host's half of a direct connection, driven from the server thread. */
    directgate_webrtc_t rtc;
    xbool_t bRtcActive;
    xbool_t bRtcGreeted;

    /* Remote operations: how the host meets the client's offer, and which way the operation's traffic came */
    int bRemoteRtc;                 /* The scenario drives remote operations: their offers are the host's to meet */
    int bNoRemote;                  /* The host's auth result offers commands but no remote sessions */
    int eRtcMode;                   /* HOST_RTC_* */
    int nRemoteRtcMsgs;             /* exec, manager and file messages that arrived over the data channel */
    int nRemoteRelayMsgs;           /* ... and over the relay */
    int bClientUnavailable;         /* The client said WebRTC is impossible */
    xbool_t bInRtcData;             /* Server thread: the message being handled came over the data channel */
    xbool_t bDropChannel;           /* Server thread: tear the channel down on the next tick, outside its own dispatch */
    uint64_t nSlowStartDueMs;       /* Server thread: when the deferred start of "slow-start" is confirmed */

    host_stage_t eStage;
    xbool_t bKeyMethod;
    directgate_srp_t srp;
    directgate_keyauth_t keyauth;
    directgate_e2e_t e2e;
    xbyte_buffer_t typed;
    xapi_session_t *pRelay;
} cli_t;

static cli_t g_cli;

#define HOST_RTC_ANSWER 0           /* Answered: the operation runs over the data channel */
#define HOST_RTC_REFUSE 1           /* Answered webrtc/unavailable, as an agent that cannot set WebRTC up */
#define HOST_RTC_IGNORE 2           /* Never answered: the client's own wait has to run out */

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
    XSYNC_ATOMIC_SET(&g_cli.bExecStarted, 0);
    XSYNC_ATOMIC_SET(&g_cli.eRtcMode, HOST_RTC_ANSWER);
    XSYNC_ATOMIC_SET(&g_cli.nRemoteRtcMsgs, 0);
    XSYNC_ATOMIC_SET(&g_cli.nRemoteRelayMsgs, 0);
    XSYNC_ATOMIC_SET(&g_cli.bClientUnavailable, 0);
    XSYNC_ATOMIC_SET(&g_cli.bExecSignalled, 0);
    XSYNC_ATOMIC_SET(&g_cli.bUploadDone, 0);
    XSYNC_ATOMIC_SET(&g_cli.nRemoteModes, 0);
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

    /* A remote operation is answered the way the agent answers it: over the data channel once it is open */
    xbool_t bChannel = (g_cli.eStage == HOST_REMOTE && g_cli.bRtcActive && DirectGate_WebRTC_IsConnected(&g_cli.rtc)) ?
        XTRUE : XFALSE;

    int nStatus = XAPI_DISCONNECT;
    if (DirectGate_Proto_Build(&packet, pHeader, pPayload, nPayload, XFALSE) &&
        (!bSealed || DirectGate_Proto_EncryptPackage(&packet, &g_cli.e2e, CLI_SESSION_ID)))
    {
        if (bChannel) nStatus = DirectGate_WebRTC_Send(&g_cli.rtc, packet.pData, packet.nUsed) == XSTDOK ?
            XAPI_CONTINUE : XAPI_DISCONNECT;
        else nStatus = DirectGate_WebSock_SendBuff(pSession, &packet);
    }

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
    if (XWS_WriteFrame(&pSession->txBuffer, (const uint8_t*)pBytes, strlen(pBytes), XWS_BINARY, XFALSE, XTRUE) != XWS_ERR_NONE)
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

/* A successful auth result, offering commands when the scenario says the host runs them. */
static xjson_obj_t* host_auth_ok(xjson_obj_t *pResult)
{
    if (pResult != NULL && XSYNC_ATOMIC_GET(&g_cli.bOfferExec)) XJSON_AddBool(pResult, "exec", XTRUE);
    if (pResult != NULL && XSYNC_ATOMIC_GET(&g_cli.bOfferExec) && !XSYNC_ATOMIC_GET(&g_cli.bNoRemote))
        XJSON_AddBool(pResult, "remote", XTRUE);
    return pResult;
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
        int nStatus = host_send(pSession, host_auth_ok(DirectGate_Proto_BuildAuthResult("ok", sM2, NULL, CLI_SESSION_ID,
            fault() == FAULT_PRE_LOGON)), NULL, 0);
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

        xjson_obj_t *pResult = host_auth_ok(DirectGate_Proto_BuildAuthResult("ok", NULL, NULL, CLI_SESSION_ID, XFALSE));
        int nStatus = host_send(pSession, pResult, NULL, 0);
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

static void write_file(const char *pPath, const char *pText);

/* ---- remote operations, as an agent answers them ---------------------------------- */

#define CLI_REMOTE_FILE_TEXT "hello from the host\n"

static int host_exec_output(xapi_session_t *pSession, const char *pStream, const uint8_t *pData, size_t nLength)
{
    xjson_obj_t *pHeader = DirectGate_Proto_BuildExec("output", NULL, NULL, CLI_SESSION_ID);
    if (pHeader != NULL) XJSON_AddString(pHeader, "stream", pStream);
    return host_send(pSession, pHeader, pData, nLength);
}

static int host_exec_exit(xapi_session_t *pSession, int nCode, const char *pSignal, xbool_t bTimedOut)
{
    xjson_obj_t *pHeader = DirectGate_Proto_BuildExec("exit", "ok", NULL, CLI_SESSION_ID);
    if (pHeader == NULL) return XAPI_DISCONNECT;

    XJSON_AddInt(pHeader, "exitCode", nCode);
    if (pSignal != NULL) XJSON_AddString(pHeader, "signal", pSignal);
    if (bTimedOut) XJSON_AddBool(pHeader, "timedOut", XTRUE);
    return host_send(pSession, pHeader, NULL, 0);
}

/* The commands this host knows, each standing for one behaviour a real program has. */
static int host_on_exec(xapi_session_t *pSession, const directgate_pkg_exec_t *pExec)
{
    const char *pAction = pExec->pAction != NULL ? pExec->pAction : "";
    const char *pCommand = g_cli.sExecCommand;

    if (strcmp(pAction, "start") == 0)
    {
        xstrncpy(g_cli.sExecCommand, sizeof(g_cli.sExecCommand), pExec->pCommand != NULL ? pExec->pCommand : "");
        xstrncpy(g_cli.sExecCwd, sizeof(g_cli.sExecCwd), pExec->pCwd != NULL ? pExec->pCwd : "");
        g_cli.nExecTimeoutMs = pExec->nTimeoutMs;
        g_cli.bExecOutputMax = pExec->bHasOutputMax && !pExec->bBadOutputMax;
        g_cli.nExecOutputMax = pExec->nOutputMax;
        g_cli.bExecStdin = pExec->bStdin;
        XByteBuffer_Clear(&g_cli.execInput);
        XByteBuffer_Init(&g_cli.execInput, XSTDNON, XFALSE);

        /* "slow-start" stands for a start whose confirmation is still on its way when the user presses Ctrl-C */
        int nStatus = XAPI_CONTINUE;
        if (strcmp(pCommand, "slow-start") == 0) g_cli.nSlowStartDueMs = XTime_GetMonoMs() + 300;
        else
        {
            xjson_obj_t *pStarted = DirectGate_Proto_BuildExec("started", "ok", NULL, CLI_SESSION_ID);
            if (pStarted != NULL) XJSON_AddInt(pStarted, "pid", 4242);
            nStatus = host_send(pSession, pStarted, NULL, 0);
        }

        XSYNC_ATOMIC_SET(&g_cli.bExecStarted, 1);
        if (nStatus < 0) return nStatus;

        if (strcmp(pCommand, "streams") == 0)
        {
            /* Terminal output has no place in a command's stdout: a host that sends some is not heard */
            nStatus = host_send(pSession, DirectGate_Proto_BuildData(CLI_SESSION_ID), (const uint8_t*)"INJECTED", 8);
            if (nStatus >= 0) nStatus = host_exec_output(pSession, "stdout", (const uint8_t*)"out-1\n", 6);
            if (nStatus >= 0) nStatus = host_exec_output(pSession, "stderr", (const uint8_t*)"err-1\n", 6);
            if (nStatus >= 0) nStatus = host_exec_output(pSession, "stdout", (const uint8_t*)"out-2\x1b[31m\n", 11);
            if (nStatus >= 0) nStatus = host_exec_exit(pSession, 0, NULL, XFALSE);
        }
        else if (strcmp(pCommand, "chatty") == 0 || strcmp(pCommand, "chatty-big") == 0)
        {
            /* A device that does not keep to outputMax: everything is sent, whatever the client asked for */
            static uint8_t sChunk[16384];
            memset(sChunk, 'a', sizeof(sChunk));
            int nChunks = strcmp(pCommand, "chatty-big") == 0 ? 13 : 3;

            for (int i = 0; i < nChunks && nStatus >= 0; i++)
                nStatus = host_exec_output(pSession, "stdout", sChunk, sizeof(sChunk));

            if (nStatus >= 0) nStatus = host_exec_output(pSession, "stderr", (const uint8_t*)"0123456789", 10);
            if (nStatus >= 0) nStatus = host_exec_exit(pSession, 0, NULL, XFALSE);
        }
        else if (strcmp(pCommand, "drop-channel") == 0)
        {
            /* The data channel goes while the command runs, as a peer-to-peer route that dies midway */
            if (nStatus >= 0) nStatus = host_exec_output(pSession, "stdout", (const uint8_t*)"before\n", 7);
            g_cli.bDropChannel = XTRUE;
        }
        else if (strcmp(pCommand, "fail 3") == 0) nStatus = host_exec_exit(pSession, 3, NULL, XFALSE);
        else if (strcmp(pCommand, "too slow") == 0) nStatus = host_exec_exit(pSession, 137, "KILL", XTRUE);
        else if (strcmp(pCommand, "refuse") == 0)
            nStatus = host_send(pSession, DirectGate_Proto_BuildExec("started", "failed",
                "cannot start the command: \x1b]0;x\x07nope", CLI_SESSION_ID), NULL, 0);
        else if (strcmp(pCommand, "vanish") == 0)
            nStatus = host_send(pSession, DirectGate_Proto_BuildStatus("closed", CLI_SESSION_ID), NULL, 0);
        else if (strcmp(pCommand, "echo-input") != 0 && strcmp(pCommand, "wait-for-signal") != 0 &&
                 strcmp(pCommand, "stubborn") != 0 && strcmp(pCommand, "drop-channel") != 0 &&
                 strcmp(pCommand, "slow-start") != 0)
            nStatus = host_exec_exit(pSession, 0, NULL, XFALSE);

        return nStatus;
    }

    if (strcmp(pAction, "input") == 0)
    {
        if (pExec->data.nPayloadLength) XByteBuffer_Add(&g_cli.execInput, pExec->data.pPayload, pExec->data.nPayloadLength);
        return XAPI_CONTINUE;
    }

    if (strcmp(pAction, "eof") == 0 && strcmp(pCommand, "echo-input") == 0)
    {
        int nStatus = host_exec_output(pSession, "stdout", g_cli.execInput.pData, g_cli.execInput.nUsed);
        if (nStatus >= 0) nStatus = host_exec_output(pSession, "stderr", (const uint8_t*)"warn\n", 5);
        if (nStatus >= 0) nStatus = host_exec_exit(pSession, 7, NULL, XFALSE);
        return nStatus;
    }

    if (strcmp(pAction, "signal") == 0)
    {
        xstrncpy(g_cli.sExecSignal, sizeof(g_cli.sExecSignal), pExec->pSignal != NULL ? pExec->pSignal : "");
        XSYNC_ATOMIC_SET(&g_cli.bExecSignalled, 1);

        /* "stubborn" stands for a program that ignores the signal: the client has to give up on its own */
        if (strcmp(pCommand, "wait-for-signal") == 0 || strcmp(pCommand, "slow-start") == 0)
            return host_exec_exit(pSession, 130, "INT", XFALSE);
    }

    return XAPI_CONTINUE;
}

static int host_manager_answer(xapi_session_t *pSession, const char *pAction, const char *pStatus, const char *pReason,
                               const char *pPath)
{
    return host_send(pSession, DirectGate_Proto_BuildManager(pAction, pStatus, pPath, pReason, CLI_SESSION_ID), NULL, 0);
}

static int host_on_manager(xapi_session_t *pSession, const directgate_pkg_manager_t *pMgr)
{
    const char *pAction = pMgr->pAction != NULL ? pMgr->pAction : "";
    const char *pPath = pMgr->pPath != NULL ? pMgr->pPath : "";

    const char *pTarget = xstrused(pMgr->pTargetPath) ? pMgr->pTargetPath : NULL;
    snprintf(g_cli.sManagerLast, sizeof(g_cli.sManagerLast), "%s %s%s%s%s", pAction, pPath,
        pTarget != NULL ? " " : "", pTarget != NULL ? pTarget : "", pMgr->bForce ? " force" : "");

    if (strcmp(pAction, "list") == 0)
    {
        if (strcmp(pPath, "/srv") != 0) return host_manager_answer(pSession, "list", "failed", "failed to read directory", pPath);

        const char *pListing = "{\"path\":\"/srv\",\"entries\":["
            "{\"name\":\"hello.txt\",\"type\":\"file\",\"permissions\":\"-rw-r--r--\",\"owner\":\"user\",\"group\":\"user\","
            "\"sizeBytes\":20,\"modified\":\"2026-11-22T10:00:00\"},"
            "{\"name\":\"logs\",\"type\":\"directory\",\"permissions\":\"drwxr-xr-x\",\"owner\":\"root\",\"group\":\"root\","
            "\"sizeBytes\":4096,\"modified\":\"2026-11-21T09:30:00\"}]}";

        xjson_obj_t *pHeader = DirectGate_Proto_BuildManager("list", "ok", "/srv", NULL, CLI_SESSION_ID);
        if (pHeader != NULL) XJSON_AddString(pHeader, "payloadType", "json");
        return host_send(pSession, pHeader, (const uint8_t*)pListing, strlen(pListing));
    }

    if (strcmp(pAction, "open") == 0)
    {
        if (strcmp(pPath, "/srv/hello.txt") != 0)
            return host_manager_answer(pSession, "open", "failed", "file not found or not a regular file", pPath);

        /* A local file appearing while the download runs: the client must not replace it */
        if (g_cli.sRacePath[0]) write_file(g_cli.sRacePath, "appeared meanwhile\n");

        int nStatus = host_push_file(pSession, "get-1", "hello.txt", CLI_REMOTE_FILE_TEXT);
        if (nStatus >= 0) nStatus = host_manager_answer(pSession, "open", "ok", NULL, pPath);
        return nStatus;
    }

    if (strcmp(pAction, "save") == 0)
    {
        if (strcmp(pPath, "/srv/exists.txt") == 0 && !pMgr->bForce)
            return host_manager_answer(pSession, "save", "exists", "file already exists", pPath);

        XByteBuffer_Clear(&g_cli.upload);
        XByteBuffer_Init(&g_cli.upload, XSTDNON, XFALSE);
        return host_manager_answer(pSession, "save", "ok", NULL, pPath);
    }

    if (strcmp(pAction, "rename") == 0 && xstrused(pMgr->pTargetPath) && strcmp(pMgr->pTargetPath, "/srv/taken") == 0)
        return host_manager_answer(pSession, "rename", "failed", "target already exists", pPath);

    if (strcmp(pAction, "delete") == 0 || strcmp(pAction, "mkdir") == 0 || strcmp(pAction, "rename") == 0)
        return host_manager_answer(pSession, pAction, "ok", NULL, xstrused(pMgr->pTargetPath) ? pMgr->pTargetPath : pPath);

    return host_manager_answer(pSession, pAction, "failed", "unsupported", pPath);
}

/* An upload, kept whole and checked against the hash the client sends at the end. */
static int host_on_upload(xapi_session_t *pSession, const directgate_pkg_file_t *pFile)
{
    const char *pAction = pFile->pAction != NULL ? pFile->pAction : "";
    const char *pId = pFile->transfer.pTransferId != NULL ? pFile->transfer.pTransferId : "";

    if (strcmp(pAction, "start") == 0)
    {
        xstrncpy(g_cli.sUploadId, sizeof(g_cli.sUploadId), pId);
        return XAPI_CONTINUE;
    }

    if (strcmp(pAction, "chunk") == 0 && strcmp(pId, g_cli.sUploadId) == 0)
    {
        if (pFile->data.nPayloadLength) XByteBuffer_Add(&g_cli.upload, pFile->data.pPayload, pFile->data.nPayloadLength);
        return XAPI_CONTINUE;
    }

    if (strcmp(pAction, "end") == 0 && strcmp(pId, g_cli.sUploadId) == 0)
    {
        uint8_t digest[XSHA256_DIGEST_SIZE];
        char sHex[XSHA256_DIGEST_SIZE * 2 + 1];
        XSHA256_Compute(digest, sizeof(digest), g_cli.upload.pData, g_cli.upload.nUsed);
        for (size_t i = 0; i < sizeof(digest); i++) snprintf(sHex + (i * 2), 3, "%02x", digest[i]);

        if (pFile->transfer.pSha256 == NULL || strcmp(pFile->transfer.pSha256, sHex) != 0)
            return host_send(pSession, DirectGate_Proto_BuildFileCancel(pId, "hash mismatch"), NULL, 0);

        XSYNC_ATOMIC_SET(&g_cli.bUploadDone, 1);
        return host_send(pSession, DirectGate_Proto_BuildFileAck(pId, 0), NULL, 0);
    }

    return XAPI_CONTINUE;
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
            if (nStatus >= 0 && XWS_WriteFrame(&pSession->txBuffer, NULL, 0, XWS_PING, XFALSE, XTRUE) == XWS_ERR_NONE)
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
        g_cli.bInRtcData = XTRUE;
        host_on_sealed(g_cli.pRelay, &pkg);
        g_cli.bInRtcData = XFALSE;
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
static void host_rtc_stop(void);

static void host_rtc_tick(void)
{
    if (g_cli.nSlowStartDueMs && XTime_GetMonoMs() >= g_cli.nSlowStartDueMs && g_cli.pRelay != NULL)
    {
        g_cli.nSlowStartDueMs = 0;
        xjson_obj_t *pStarted = DirectGate_Proto_BuildExec("started", "ok", NULL, CLI_SESSION_ID);
        if (pStarted != NULL) XJSON_AddInt(pStarted, "pid", 4243);
        host_send(g_cli.pRelay, pStarted, NULL, 0);
    }

    if (!g_cli.bRtcActive) return;
    if (g_cli.bDropChannel)
    {
        g_cli.bDropChannel = XFALSE;
        host_rtc_stop();
        return;
    }

    DirectGate_WebRTC_ProcessQueue(&g_cli.rtc);

    if (g_cli.bRtcGreeted || !DirectGate_WebRTC_IsConnected(&g_cli.rtc)) return;
    g_cli.bRtcGreeted = XTRUE;
    if (XSYNC_ATOMIC_GET(&g_cli.bRemoteRtc)) return;
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

    /* Which way an operation's own traffic came: the data channel, or the relay */
    if (g_cli.eStage == HOST_REMOTE && (!strcmp(pType, "exec") || !strcmp(pType, "manager") || !strcmp(pType, "file")))
    {
        if (g_cli.bInRtcData) XSYNC_ATOMIC_ADD(&g_cli.nRemoteRtcMsgs, 1);
        else XSYNC_ATOMIC_ADD(&g_cli.nRemoteRelayMsgs, 1);
    }

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
    else if (strcmp(pType, "webrtc") == 0 && XSYNC_ATOMIC_GET(&g_cli.bRemoteRtc))
    {
        const char *pAction = XJSON_GetString(XJSON_GetObject(pRoot, "action"));
        int eMode = XSYNC_ATOMIC_GET(&g_cli.eRtcMode);

        /* As the agent: WebRTC is set up for a session whose mode is active, and an offer before that waits unseen */
        if (pAction != NULL && strcmp(pAction, "unavailable") == 0) XSYNC_ATOMIC_SET(&g_cli.bClientUnavailable, 1);
        else if (g_cli.eStage != HOST_REMOTE) nStatus = XAPI_CONTINUE;
        else if (eMode == HOST_RTC_ANSWER) nStatus = host_rtc_signal_in(pRoot);
        else if (eMode == HOST_RTC_REFUSE && pAction != NULL && strcmp(pAction, "offer") == 0)
            nStatus = host_send(pSession, DirectGate_Proto_BuildWebRTC("unavailable", CLI_SESSION_ID), NULL, 0);
    }
    else if (strcmp(pType, "exec") == 0 && g_cli.eStage == HOST_REMOTE)
    {
        nStatus = host_on_exec(pSession, (const directgate_pkg_exec_t*)msg.pPackage);
    }
    else if (strcmp(pType, "manager") == 0 && g_cli.eStage == HOST_REMOTE)
    {
        nStatus = host_on_manager(pSession, (const directgate_pkg_manager_t*)msg.pPackage);
    }
    else if (strcmp(pType, "file") == 0 && g_cli.eStage == HOST_REMOTE)
    {
        nStatus = host_on_upload(pSession, (const directgate_pkg_file_t*)msg.pPackage);
    }
    else if (strcmp(pType, "cmd") == 0)
    {
        const char *pAction = XJSON_GetString(XJSON_GetObject(pRoot, "action"));
        const char *pMode = XJSON_GetString(XJSON_GetObject(pRoot, "mode"));

        if (g_cli.eStage == HOST_WAIT_START && pAction != NULL && strcmp(pAction, "start") == 0 &&
            pMode != NULL && (strcmp(pMode, "exec") == 0 || strcmp(pMode, "file-manager") == 0 || strcmp(pMode, "remote") == 0))
        {
            XSYNC_ATOMIC_ADD(&g_cli.nRemoteModes, 1);
            g_cli.eStage = HOST_REMOTE;
        }

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
/* ---- remote operations: dgcli the way a script or an AI agent runs it ------------------ */

/* No terminal, stdout and stderr kept apart, the exit code as the verdict. */
/* dgcli with its arguments, the input it reads, and anything the environment should add (NULL: nothing) */
static int cli_run_env(const tty_t *pTty, const char *const *pArgs, const char *pInput, size_t nInput,
                       const char *const *pExtraEnv, xexec_result_t *pResult)
{
    char *pArgv[32];
    size_t n = 0;
    pArgv[n++] = (char*)DIRECTGATE_CLIENT_BIN;
    for (size_t i = 0; pArgs[i] != NULL && n + 1 < sizeof(pArgv) / sizeof(pArgv[0]); i++) pArgv[n++] = (char*)pArgs[i];
    pArgv[n] = NULL;

    char sHome[600], sCert[600];
    snprintf(sHome, sizeof(sHome), "HOME=%s", pTty->pRoot);
    snprintf(sCert, sizeof(sCert), "SSL_CERT_FILE=%s", pTty->pCert);
    char *aEnv[8] = { sHome, sCert, (char*)"PATH=/usr/bin:/bin", NULL };
    for (size_t i = 0, n = 3; pExtraEnv != NULL && pExtraEnv[i] != NULL && n + 1 < 8; i++) aEnv[n++] = (char*)pExtraEnv[i];

    xexec_opts_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.pPath = DIRECTGATE_CLIENT_BIN;
    opts.ppArgv = pArgv;
    opts.ppEnv = aEnv;
    opts.pWorkDir = pTty->pRoot;

    XExec_ResultInit(pResult);
    if (XExec_Run(&opts, (const uint8_t*)pInput, pInput != NULL ? nInput : 0, 4U * 1024U * 1024U, 30000, pResult) != XSTDOK)
        return -1;

    /* Readable as strings, without counting the terminator */
    XByteBuffer_AddByte(&pResult->output, 0);
    XByteBuffer_AddByte(&pResult->errors, 0);
    pResult->output.nUsed--;
    pResult->errors.nUsed--;
    return pResult->bTimedOut ? -2 : pResult->nExitCode;
}

static int cli_run(const tty_t *pTty, const char *const *pArgs, const char *pInput, size_t nInput, xexec_result_t *pResult)
{
    return cli_run_env(pTty, pArgs, pInput, nInput, NULL, pResult);
}

static const char* out_of(const xbyte_buffer_t *pBuffer)
{
    return pBuffer->pData != NULL ? (const char*)pBuffer->pData : "";
}

/* dgcli started in the background, for the cases that signal it while it runs. */
static int cli_spawn(const tty_t *pTty, const char *const *pArgs, xexec_t *pExec)
{
    char *pArgv[32];
    size_t n = 0;
    pArgv[n++] = (char*)DIRECTGATE_CLIENT_BIN;
    for (size_t i = 0; pArgs[i] != NULL && n + 1 < sizeof(pArgv) / sizeof(pArgv[0]); i++) pArgv[n++] = (char*)pArgs[i];
    pArgv[n] = NULL;

    char sHome[600], sCert[600];
    snprintf(sHome, sizeof(sHome), "HOME=%s", pTty->pRoot);
    snprintf(sCert, sizeof(sCert), "SSL_CERT_FILE=%s", pTty->pCert);
    char *aEnv[] = { sHome, sCert, (char*)"PATH=/usr/bin:/bin", NULL };

    xexec_opts_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.pPath = DIRECTGATE_CLIENT_BIN;
    opts.ppArgv = pArgv;
    opts.ppEnv = aEnv;
    opts.pWorkDir = pTty->pRoot;
    opts.nFlags = XEXEC_STDOUT | XEXEC_STDERR | XEXEC_GROUP;

    return XExec_Spawn(pExec, &opts) == XSTDOK;
}

static int wait_atomic(xatomic_t *pFlag, uint32_t nTimeoutMs)
{
    for (uint32_t nWaited = 0; nWaited < nTimeoutMs && !XSYNC_ATOMIC_GET(pFlag); nWaited += 10) usleep(10000);
    return XSYNC_ATOMIC_GET(pFlag) != 0;
}

static int read_text(const char *pPath, char *pOut, size_t nSize)
{
    FILE *pFile = fopen(pPath, "rb");
    if (pFile == NULL) return 0;
    size_t nRead = fread(pOut, 1, nSize - 1, pFile);
    pOut[nRead] = '\0';
    fclose(pFile);
    return 1;
}

static int no_partial_downloads(const char *pRoot)
{
    char sCmd[700];
    snprintf(sCmd, sizeof(sCmd), "ls -a '%s' | grep -q dgpart", pRoot);
    return system(sCmd) != 0;
}

/* One request to the MCP server and its one-line answer, read within nTimeoutMs. */
static int mcp_call(xexec_t *pMcp, const char *pRequest, char *pReply, size_t nSize, uint32_t nTimeoutMs)
{
    size_t nLength = strlen(pRequest);
    if (write(pMcp->nStdIn, pRequest, nLength) != (ssize_t)nLength || write(pMcp->nStdIn, "\n", 1) != 1) return 0;

    size_t nUsed = 0;
    pReply[0] = '\0';

    for (uint32_t nWaited = 0; nWaited < nTimeoutMs && strchr(pReply, '\n') == NULL; nWaited += 20)
    {
        struct pollfd pfd = { pMcp->nStdOut, POLLIN, 0 };
        if (poll(&pfd, 1, 20) <= 0) continue;

        ssize_t nRead = read(pMcp->nStdOut, pReply + nUsed, nSize - 1 - nUsed);
        if (nRead <= 0) break;
        nUsed += (size_t)nRead;
        pReply[nUsed] = '\0';
    }

    return strchr(pReply, '\n') != NULL;
}

/* ---- dgcli session: many operations on one connection ------------------------------------------------- */

typedef struct {
    xexec_t exec;
    xbyte_buffer_t in;              /* What the session wrote, not taken yet */
    xbyte_buffer_t log;             /* Its stderr, drained so it never blocks on it */
} session_child_t;

static int session_start(session_child_t *pChild, tty_t *pTty, const char *pCfg, const char *pIdle)
{
    char *pArgv[] = { (char*)DIRECTGATE_CLIENT_BIN, (char*)"session", (char*)"-c", (char*)pCfg, (char*)"-t", (char*)pIdle,
                      (char*)CLI_DEVICE_ID, NULL };
    char sHome[600], sCert[600];
    snprintf(sHome, sizeof(sHome), "HOME=%s", pTty->pRoot);
    snprintf(sCert, sizeof(sCert), "SSL_CERT_FILE=%s", pTty->pCert);
    char *aEnv[] = { sHome, sCert, (char*)"PATH=/usr/bin:/bin", NULL };

    xexec_opts_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.pPath = DIRECTGATE_CLIENT_BIN;
    opts.ppArgv = pArgv;
    opts.ppEnv = aEnv;
    opts.pWorkDir = pTty->pRoot;
    opts.nFlags = XEXEC_STDIN | XEXEC_STDOUT | XEXEC_STDERR | XEXEC_GROUP;

    XByteBuffer_Init(&pChild->in, XSTDNON, XFALSE);
    XByteBuffer_Init(&pChild->log, XSTDNON, XFALSE);
    return XExec_Spawn(&pChild->exec, &opts) == XSTDOK;
}

static int session_fill(session_child_t *pChild, size_t nWant, uint32_t nTimeoutMs);

/* Its first line, once it is open */
static int session_ready(session_child_t *pChild)
{
    static const char sReady[] = "{\"ready\":true}\n";
    if (!session_fill(pChild, sizeof(sReady) - 1, 30000) || memcmp(pChild->in.pData, sReady, sizeof(sReady) - 1)) return 0;
    XByteBuffer_Advance(&pChild->in, sizeof(sReady) - 1);
    return 1;
}

/* Reads what the session writes into in, its stderr into log, until in holds nWant bytes or the time runs out */
static int session_fill(session_child_t *pChild, size_t nWant, uint32_t nTimeoutMs)
{
    uint64_t nDeadline = XTime_GetMonoMs() + nTimeoutMs;

    while (pChild->in.nUsed < nWant && XTime_GetMonoMs() < nDeadline)
    {
        struct pollfd pfd[2] = { { pChild->exec.nStdOut, POLLIN, 0 }, { pChild->exec.nStdErr, POLLIN, 0 } };
        if (poll(pfd, pChild->exec.nStdErr >= 0 ? 2 : 1, 50) <= 0) continue;

        uint8_t sBuffer[16384];
        if (pChild->exec.nStdErr >= 0 && (pfd[1].revents & (POLLIN | POLLHUP)))
        {
            ssize_t nRead = read(pChild->exec.nStdErr, sBuffer, sizeof(sBuffer));
            if (nRead > 0) XByteBuffer_Add(&pChild->log, sBuffer, (size_t)nRead);
            else
            {
                close(pChild->exec.nStdErr);
                pChild->exec.nStdErr = XSOCK_INVALID;
            }
        }

        if (pfd[0].revents & (POLLIN | POLLHUP))
        {
            ssize_t nRead = read(pChild->exec.nStdOut, sBuffer, sizeof(sBuffer));
            if (nRead <= 0) return 0;
            XByteBuffer_Add(&pChild->in, sBuffer, (size_t)nRead);
        }
    }

    return pChild->in.nUsed >= nWant;
}

/* One request, one answer: the answer's code, its stdout and stderr, and whether output was cut */
static int session_call(session_child_t *pChild, const char *pRequest, int *pCode, xbyte_buffer_t *pOut, xbyte_buffer_t *pErr,
                        int *pTruncated)
{
    size_t nLength = strlen(pRequest);
    if (write(pChild->exec.nStdIn, pRequest, nLength) != (ssize_t)nLength || write(pChild->exec.nStdIn, "\n", 1) != 1)
        return 0;

    /* The header line */
    uint64_t nDeadline = XTime_GetMonoMs() + 30000;
    const uint8_t *pNewline = NULL;
    while ((pNewline = pChild->in.nUsed ? memchr(pChild->in.pData, '\n', pChild->in.nUsed) : NULL) == NULL &&
           XTime_GetMonoMs() < nDeadline)
        if (!session_fill(pChild, pChild->in.nUsed + 1, 200) && pChild->exec.nStdOut < 0) return 0;
    if (pNewline == NULL) return 0;

    size_t nHeader = (size_t)(pNewline - pChild->in.pData) + 1;
    xjson_t json;
    if (!XJSON_Parse(&json, NULL, (const char*)pChild->in.pData, nHeader - 1)) return 0;
    *pCode = XJSON_GetInt(XJSON_GetObject(json.pRootObj, "exitCode"));
    size_t nOut = (size_t)XJSON_GetU64(XJSON_GetObject(json.pRootObj, "stdout"));
    size_t nErr = (size_t)XJSON_GetU64(XJSON_GetObject(json.pRootObj, "stderr"));
    *pTruncated = XJSON_GetBool(XJSON_GetObject(json.pRootObj, "truncated")) ? 1 : 0;
    XJSON_Destroy(&json);

    if (!session_fill(pChild, nHeader + nOut + nErr, 30000)) return 0;
    XByteBuffer_Reset(pOut);
    XByteBuffer_Reset(pErr);
    if (nOut) XByteBuffer_Add(pOut, pChild->in.pData + nHeader, nOut);
    if (nErr) XByteBuffer_Add(pErr, pChild->in.pData + nHeader + nOut, nErr);
    XByteBuffer_Advance(&pChild->in, nHeader + nOut + nErr);
    return 1;
}

static void session_stop(session_child_t *pChild)
{
    if (pChild->exec.nPid > 0 && !pChild->exec.bExited)
    {
        XExec_Kill(&pChild->exec, SIGKILL);
        XExec_Wait(&pChild->exec, XEXEC_WAIT_FOREVER);
    }

    XExec_Close(&pChild->exec);
    XByteBuffer_Clear(&pChild->in);
    XByteBuffer_Clear(&pChild->log);
}

static int scenario_session(tty_t *pTty, const char *pCfg)
{
    xbyte_buffer_t out, err;
    XByteBuffer_Init(&out, XSTDNON, XFALSE);
    XByteBuffer_Init(&err, XSTDNON, XFALSE);
    int nCode = -1, nTruncated = 0, nOk = 1;

    const char *sStreams = "out-1\nout-2\x1b[31m\n";
    session_child_t child;
    reset_outputs();
    CHECK(session_start(&child, pTty, pCfg, "600"), "start a session");
    CHECK(session_ready(&child), "the session says it is open before anything else");

    do
    {
        nOk = session_call(&child, "{\"argv\":[\"exec\",\"" CLI_DEVICE_ID "\",\"streams\"]}", &nCode, &out, &err, &nTruncated) &&
            nCode == 0 && out.nUsed == strlen(sStreams) && memcmp(out.pData, sStreams, out.nUsed) == 0 &&
            err.nUsed == 6 && memcmp(err.pData, "err-1\n", 6) == 0 && !nTruncated;
        if (!nOk) { fprintf(stderr, "client_e2e_smoke: a session runs a command and answers with its streams\n"); break; }

        nOk = session_call(&child, "{\"argv\":[\"exec\",\"-t\",\"9\",\"-C\",\"/srv\",\"" CLI_DEVICE_ID "\",\"fail\",\"3\"]}",
            &nCode, &out, &err, &nTruncated) && nCode == 3 && strcmp(g_cli.sExecCwd, "/srv") == 0 &&
            g_cli.nExecTimeoutMs == 9000;
        if (!nOk) { fprintf(stderr, "client_e2e_smoke: a session's second command runs with its own options\n"); break; }

        nOk = session_call(&child, "{\"argv\":[\"exec\",\"" CLI_DEVICE_ID "\",\"chatty\"],\"max\":1000}", &nCode, &out, &err,
            &nTruncated) && nCode == 0 && out.nUsed == 1000 && nTruncated;
        if (!nOk) { fprintf(stderr, "client_e2e_smoke: a session keeps no more of a stream than the request allows\n"); break; }

        nOk = session_call(&child, "{\"argv\":[\"exec\",\"" CLI_DEVICE_ID "\",\"echo-input\"],\"stdin\":\"fed\\n\"}", &nCode,
            &out, &err, &nTruncated) && nCode == 7 && out.nUsed == 4 && memcmp(out.pData, "fed\n", 4) == 0;
        if (!nOk) { fprintf(stderr, "client_e2e_smoke: a session's command reads the stdin of its request\n"); break; }

        nOk = session_call(&child, "{\"argv\":[\"cp\",\"" CLI_DEVICE_ID ":/srv/hello.txt\",\"-\"]}", &nCode, &out, &err,
            &nTruncated) && nCode == 0 && out.nUsed == strlen(CLI_REMOTE_FILE_TEXT) &&
            memcmp(out.pData, CLI_REMOTE_FILE_TEXT, out.nUsed) == 0;
        if (!nOk) { fprintf(stderr, "client_e2e_smoke: a session downloads a file into its answer\n"); break; }

        nOk = session_call(&child,
            "{\"argv\":[\"cp\",\"-\",\"" CLI_DEVICE_ID ":/srv/session.txt\"],\"stdin\":\"from a session\\n\"}",
            &nCode, &out, &err, &nTruncated) && nCode == 0 && g_cli.upload.nUsed == 15 &&
            memcmp(g_cli.upload.pData, "from a session\n", 15) == 0;
        if (!nOk) { fprintf(stderr, "client_e2e_smoke: a session uploads the stdin of its request\n"); break; }

        nOk = session_call(&child, "{\"argv\":[\"exec\",\"another-box\",\"ls\"]}", &nCode, &out, &err, &nTruncated) &&
            nCode == 255 && strstr(out_of(&err), "a session reaches its own device only") != NULL;
        if (!nOk) { fprintf(stderr, "client_e2e_smoke: a session refuses an operation on another device\n"); break; }

        nOk = session_call(&child, "not json", &nCode, &out, &err, &nTruncated) && nCode == 255 &&
            strstr(out_of(&err), "one line of JSON") != NULL;
        if (!nOk) { fprintf(stderr, "client_e2e_smoke: a session answers a malformed request and goes on\n"); break; }

        nOk = session_call(&child, "{\"argv\":[\"exec\",\"" CLI_DEVICE_ID "\",\"fail\",\"3\"]}", &nCode, &out, &err,
            &nTruncated) && nCode == 3;
        if (!nOk) { fprintf(stderr, "client_e2e_smoke: a session goes on after a refused request\n"); break; }

        nOk = XSYNC_ATOMIC_GET(&g_cli.nConnects) == 1 && XSYNC_ATOMIC_GET(&g_cli.nRemoteRtcMsgs) > 0 &&
            XSYNC_ATOMIC_GET(&g_cli.nRemoteRelayMsgs) == 0;
        if (!nOk) { fprintf(stderr, "client_e2e_smoke: one connection carries every operation, over the data channel\n"); break; }

        /* Its requests end: the session ends, cleanly */
        XExec_CloseStdIn(&child.exec);
        nOk = XExec_Wait(&child.exec, 10000) == XSTDOK && child.exec.nExitCode == 0;
        if (!nOk) { fprintf(stderr, "client_e2e_smoke: a session ends cleanly when its requests end\n"); break; }
    }
    while (0);

    if (!nOk) fprintf(stderr, "---- session stderr ----\n%.*s\n------------------------\n", (int)child.log.nUsed,
        child.log.pData != NULL ? (const char*)child.log.pData : "");
    session_stop(&child);
    CHECK(nOk, "a session serves its requests on one connection");

    /* Idle for longer than it may be: it ends on its own */
    reset_outputs();
    CHECK(session_start(&child, pTty, pCfg, "1"), "start a session that may idle for a second");
    CHECK(session_ready(&child), "the idle session opens");
    uint64_t nStart = XTime_GetMonoMs();
    CHECK(XExec_Wait(&child.exec, 20000) == XSTDOK && child.exec.nExitCode == 0, "an idle session ends by itself");
    CHECK(XTime_GetMonoMs() - nStart < 15000, "and soon after its idle time");
    session_stop(&child);

    /* An agent that offers no remote sessions: dgcli says so and fails, as for a command it cannot run */
    reset_outputs();
    XSYNC_ATOMIC_SET(&g_cli.bNoRemote, 1);
    CHECK(session_start(&child, pTty, pCfg, "600"), "start a session with an agent that keeps none");
    int bExited = XExec_Wait(&child.exec, 20000) == XSTDOK && child.exec.nExitCode == 255;
    session_fill(&child, 1, 500);
    int bNotReady = child.in.nUsed == 0;
    XSYNC_ATOMIC_SET(&g_cli.bNoRemote, 0);
    int bSaid = child.log.nUsed && strstr(out_of(&child.log), "cannot keep sessions") != NULL;
    session_stop(&child);
    CHECK(bExited && bSaid, "a session with an agent that keeps none fails and says why");
    CHECK(bNotReady, "and never says it is open, so nothing could have run on it");

    XByteBuffer_Clear(&out);
    XByteBuffer_Clear(&err);
    return 0;
}

/* The same operations through "dgcli mcp", the way an AI client drives them. */
static int scenario_mcp(tty_t *pTty, const char *pCfg)
{
    char *pArgv[] = { (char*)DIRECTGATE_CLIENT_BIN, (char*)"mcp", (char*)"-c", (char*)pCfg, NULL };
    char sHome[600], sCert[600];
    snprintf(sHome, sizeof(sHome), "HOME=%s", pTty->pRoot);
    snprintf(sCert, sizeof(sCert), "SSL_CERT_FILE=%s", pTty->pCert);
    char *aEnv[] = { sHome, sCert, (char*)"PATH=/usr/bin:/bin", NULL };

    xexec_opts_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.pPath = DIRECTGATE_CLIENT_BIN;
    opts.ppArgv = pArgv;
    opts.ppEnv = aEnv;
    opts.pWorkDir = pTty->pRoot;
    opts.nFlags = XEXEC_STDIN | XEXEC_STDOUT | XEXEC_GROUP;

    xexec_t mcp;
    CHECK(XExec_Spawn(&mcp, &opts) == XSTDOK, "start the MCP server");

    static char sReply[1024 * 1024];        /* An exec cut at the limit comes back twice: as text and as structure */
    int nOk = 1;

    do
    {
        nOk = mcp_call(&mcp, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\","
            "\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"test\"}}}",
            sReply, sizeof(sReply), 10000) && strstr(sReply, "\"protocolVersion\":\"2025-06-18\"") != NULL &&
            strstr(sReply, "\"tools\":{") != NULL;
        if (!nOk) { fprintf(stderr, "client_e2e_smoke: the MCP server answers initialize with its tools capability\n"); break; }

        /* A notification is never answered: the next line read is the next request's */
        const char *pNote = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n";
        if (write(mcp.nStdIn, pNote, strlen(pNote)) != (ssize_t)strlen(pNote)) { nOk = 0; break; }

        reset_outputs();
        nOk = mcp_call(&mcp, "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"exec\","
            "\"arguments\":{\"device\":\"" CLI_DEVICE_ID "\",\"command\":\"streams\"}}}", sReply, sizeof(sReply), 30000) &&
            strstr(sReply, "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":") == sReply &&
            strstr(sReply, "\"exitCode\":0,\"stdout\":\"out-1\\nout-2\\u001b[31m\\n\"") != NULL &&
            strstr(sReply, "\"isError\":false") != NULL && strstr(sReply, "\"truncated\":false") != NULL;
        if (!nOk) { fprintf(stderr, "client_e2e_smoke: exec through MCP returns the exit code and the escaped output\n"); break; }

        nOk = g_cli.bExecOutputMax && g_cli.nExecOutputMax == 128U * 1024U + 1U;
        if (!nOk) { fprintf(stderr, "client_e2e_smoke: exec through MCP asks the device for no more than it keeps\n"); break; }

        /* A device that sends past the limit anyway: what is kept is cut there, and the cut is reported */
        reset_outputs();
        nOk = mcp_call(&mcp, "{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"tools/call\",\"params\":{\"name\":\"exec\","
            "\"arguments\":{\"device\":\"" CLI_DEVICE_ID "\",\"command\":\"chatty-big\"}}}", sReply, sizeof(sReply), 30000) &&
            strstr(sReply, "\"truncated\":true") != NULL && strstr(sReply, "[output cut at 128 KB per stream]") != NULL &&
            strstr(sReply, "0123456789") != NULL;
        if (!nOk) { fprintf(stderr, "client_e2e_smoke: output past the limit through MCP is reported cut\n"); break; }

        reset_outputs();
        nOk = mcp_call(&mcp, "{\"jsonrpc\":\"2.0\",\"id\":\"three\",\"method\":\"tools/call\",\"params\":{\"name\":\"exec\","
            "\"arguments\":{\"device\":\"" CLI_DEVICE_ID "\",\"command\":\"fail 3\",\"cwd\":\"/srv\",\"timeout_seconds\":9}}}",
            sReply, sizeof(sReply), 30000) && strstr(sReply, "\"id\":\"three\"") != NULL &&
            strstr(sReply, "\"exitCode\":3") != NULL && strstr(sReply, "\"isError\":true") != NULL &&
            strcmp(g_cli.sExecCwd, "/srv") == 0 && g_cli.nExecTimeoutMs == 9000;
        if (!nOk) { fprintf(stderr, "client_e2e_smoke: a failing command through MCP is an error with its code\n"); break; }

        reset_outputs();
        nOk = mcp_call(&mcp, "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\","
            "\"arguments\":{\"device\":\"" CLI_DEVICE_ID "\",\"path\":\"/srv/hello.txt\"}}}", sReply, sizeof(sReply), 30000) &&
            strstr(sReply, "\"text\":\"hello from the host\\n\"") != NULL;
        if (!nOk) { fprintf(stderr, "client_e2e_smoke: read_file through MCP returns the file's text\n"); break; }

        reset_outputs();
        nOk = mcp_call(&mcp, "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"write_file\","
            "\"arguments\":{\"device\":\"" CLI_DEVICE_ID "\",\"path\":\"/srv/mcp.txt\",\"content\":\"written over MCP\\n\"}}}",
            sReply, sizeof(sReply), 30000) && strstr(sReply, "\"isError\":false") != NULL &&
            g_cli.upload.nUsed == 17 && memcmp(g_cli.upload.pData, "written over MCP\n", 17) == 0 &&
            strcmp(g_cli.sManagerLast, "save /srv/mcp.txt") == 0;
        if (!nOk) { fprintf(stderr, "client_e2e_smoke: write_file through MCP uploads the content\n"); break; }

        reset_outputs();
        nOk = mcp_call(&mcp, "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\",\"params\":{\"name\":\"list_devices\","
            "\"arguments\":{}}}", sReply, sizeof(sReply), 30000) &&
            strstr(sReply, "\"structuredContent\":{\"devices\":[") != NULL && strstr(sReply, CLI_DEVICE_ID) != NULL;
        if (!nOk) { fprintf(stderr, "client_e2e_smoke: list_devices through MCP returns structured devices\n"); break; }

        /* keep_open: one connection for many calls */
        reset_outputs();
        nOk = mcp_call(&mcp, "{\"jsonrpc\":\"2.0\",\"id\":20,\"method\":\"tools/call\",\"params\":{\"name\":\"exec\","
            "\"arguments\":{\"device\":\"" CLI_DEVICE_ID "\",\"command\":\"streams\",\"keep_open\":true}}}",
            sReply, sizeof(sReply), 30000) && strstr(sReply, "\"exitCode\":0,\"stdout\":\"out-1\\nout-2") != NULL;
        if (!nOk) { fprintf(stderr, "client_e2e_smoke: exec with keep_open runs on a session\n"); break; }

        nOk = mcp_call(&mcp, "{\"jsonrpc\":\"2.0\",\"id\":21,\"method\":\"tools/call\",\"params\":{\"name\":\"exec\","
            "\"arguments\":{\"device\":\"" CLI_DEVICE_ID "\",\"command\":\"fail 3\",\"keep_open\":true}}}",
            sReply, sizeof(sReply), 30000) && strstr(sReply, "\"exitCode\":3") != NULL &&
            strstr(sReply, "\"isError\":true") != NULL;
        if (!nOk) { fprintf(stderr, "client_e2e_smoke: a second call with keep_open runs on the same session\n"); break; }

        nOk = mcp_call(&mcp, "{\"jsonrpc\":\"2.0\",\"id\":22,\"method\":\"tools/call\",\"params\":{\"name\":\"exec\","
            "\"arguments\":{\"device\":\"" CLI_DEVICE_ID "\",\"command\":\"chatty-big\",\"keep_open\":true}}}",
            sReply, sizeof(sReply), 30000) && strstr(sReply, "\"truncated\":true") != NULL &&
            strstr(sReply, "[output cut at 128 KB per stream]") != NULL;
        if (!nOk) { fprintf(stderr, "client_e2e_smoke: output past the limit on a session is reported cut\n"); break; }

        nOk = mcp_call(&mcp, "{\"jsonrpc\":\"2.0\",\"id\":23,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\","
            "\"arguments\":{\"device\":\"" CLI_DEVICE_ID "\",\"path\":\"/srv/hello.txt\"}}}", sReply, sizeof(sReply), 30000) &&
            strstr(sReply, "\"text\":\"hello from the host\\n\"") != NULL &&
            XSYNC_ATOMIC_GET(&g_cli.nConnects) == 1;
        if (!nOk) { fprintf(stderr, "client_e2e_smoke: calls on a kept connection share one connect\n"); break; }

        /* That call had no keep_open: the session went with it, and the next call connects anew */
        nOk = mcp_call(&mcp, "{\"jsonrpc\":\"2.0\",\"id\":24,\"method\":\"tools/call\",\"params\":{\"name\":\"disconnect\","
            "\"arguments\":{\"device\":\"" CLI_DEVICE_ID "\"}}}", sReply, sizeof(sReply), 30000) &&
            strstr(sReply, "no open connection") != NULL;
        if (!nOk) { fprintf(stderr, "client_e2e_smoke: a call without keep_open closes the connection it used\n"); break; }

        nOk = mcp_call(&mcp, "{\"jsonrpc\":\"2.0\",\"id\":25,\"method\":\"tools/call\",\"params\":{\"name\":\"list_directory\","
            "\"arguments\":{\"device\":\"" CLI_DEVICE_ID "\",\"path\":\"/srv\",\"keep_open\":true}}}",
            sReply, sizeof(sReply), 30000) && strstr(sReply, "\"isError\":false") != NULL &&
            XSYNC_ATOMIC_GET(&g_cli.nConnects) == 2;
        if (!nOk) { fprintf(stderr, "client_e2e_smoke: the next keep_open call opens a new connection\n"); break; }

        nOk = mcp_call(&mcp, "{\"jsonrpc\":\"2.0\",\"id\":26,\"method\":\"tools/call\",\"params\":{\"name\":\"disconnect\","
            "\"arguments\":{\"device\":\"" CLI_DEVICE_ID "\"}}}", sReply, sizeof(sReply), 30000) &&
            strstr(sReply, "\"text\":\"disconnected\"") != NULL;
        if (!nOk) { fprintf(stderr, "client_e2e_smoke: disconnect closes a kept connection\n"); break; }

        nOk = mcp_call(&mcp, "{\"jsonrpc\":\"2.0\",\"id\":27,\"method\":\"tools/call\",\"params\":{\"name\":\"disconnect\","
            "\"arguments\":{}}}", sReply, sizeof(sReply), 30000) && strstr(sReply, "device is required") != NULL;
        if (!nOk) { fprintf(stderr, "client_e2e_smoke: disconnect needs its device\n"); break; }

        /* An agent that keeps no sessions: the call runs on a connection of its own instead */
        reset_outputs();
        XSYNC_ATOMIC_SET(&g_cli.bNoRemote, 1);
        nOk = mcp_call(&mcp, "{\"jsonrpc\":\"2.0\",\"id\":28,\"method\":\"tools/call\",\"params\":{\"name\":\"exec\","
            "\"arguments\":{\"device\":\"" CLI_DEVICE_ID "\",\"command\":\"fail 3\",\"keep_open\":true}}}",
            sReply, sizeof(sReply), 60000) && strstr(sReply, "\"exitCode\":3") != NULL;
        XSYNC_ATOMIC_SET(&g_cli.bNoRemote, 0);
        if (!nOk)
        {
            fprintf(stderr, "client_e2e_smoke: keep_open with an agent that keeps no sessions still runs the call\n");
            break;
        }

        reset_outputs();
        nOk = mcp_call(&mcp, "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"exec\","
            "\"arguments\":{\"device\":\"no-such-box\",\"command\":\"true\"}}}", sReply, sizeof(sReply), 30000) &&
            strstr(sReply, "\"isError\":true") != NULL && strstr(sReply, "No device matches") != NULL;
        if (!nOk) { fprintf(stderr, "client_e2e_smoke: a failure through MCP is an error result with dgcli's reason\n"); break; }
    }
    while (0);

    /* Closing its input ends the server */
    XExec_CloseStdIn(&mcp);
    int bExited = XExec_Wait(&mcp, 10000) == XSTDOK && mcp.nExitCode == 0;
    if (!bExited) XExec_Kill(&mcp, SIGKILL), XExec_Wait(&mcp, XEXEC_WAIT_FOREVER);
    XExec_Close(&mcp);

    if (!nOk) fprintf(stderr, "---- last MCP reply ----\n%s\n------------------------\n", sReply);
    CHECK(nOk, "the MCP tools work end to end");
    CHECK(bExited, "the MCP server exits cleanly when its input closes");
    return 0;
}

static int scenario_remote(tty_t *pTty, const char *pCfg, const char *pRoot)
{
    /* The key generated earlier, authorized on the device: no password is ever asked for */
    char sKey[256];
    snprintf(sKey, sizeof(sKey), "%s/.config/directgate/auth/key.json", pRoot);

    directgate_client_key_t key;
    CHECK(DirectGate_KeyAuth_KeyLoad(&key, sKey) &&
        DirectGate_KeyAuth_Base64Encode(key.clientPub, sizeof(key.clientPub), g_cli.sAuthorizedKey,
            sizeof(g_cli.sAuthorizedKey)), "the client key loads for the remote operations");
    DirectGate_KeyAuth_KeyCleanse(&key);

    xexec_result_t res;
    int nCode = 0;

    /* ---- exec ---- */

    /* An agent that does not offer commands is never sent one */
    reset_outputs();
    XSYNC_ATOMIC_SET(&g_cli.bOfferExec, 0);
    const char *noExec[] = { "exec", "-c", pCfg, CLI_DEVICE_ID, "uname", "-a", NULL };
    nCode = cli_run(pTty, noExec, NULL, 0, &res);
    CHECK(nCode == 255, "a command for an agent without exec fails as dgcli's own failure");
    CHECK(strstr(out_of(&res.errors), "cannot run commands") != NULL, "the client says the agent has to be updated");
    CHECK(XSYNC_ATOMIC_GET(&g_cli.bKeyAuthOk) && XSYNC_ATOMIC_GET(&g_cli.nRemoteModes) == 0,
        "a key logs in, and no command is sent to an agent that did not offer them");
    XExec_ResultClear(&res);

    XSYNC_ATOMIC_SET(&g_cli.bOfferExec, 1);

    /* Output keeps its streams, and stdout holds nothing but the command's own */
    reset_outputs();
    const char *streams[] = { "exec", "-c", pCfg, CLI_DEVICE_ID, "streams", NULL };
    nCode = cli_run(pTty, streams, NULL, 0, &res);
    CHECK(nCode == 0, "a command that succeeds makes dgcli exit 0");
    CHECK(strcmp(out_of(&res.output), "out-1\nout-2\x1b[31m\n") == 0,
        "stdout is exactly the command's stdout, byte for byte, with nothing of dgcli's own");
    CHECK(strstr(out_of(&res.errors), "err-1\n") != NULL, "the command's stderr goes to stderr");
    CHECK(strstr(out_of(&res.errors), "Password") == NULL, "no password is asked for");
    CHECK(XSYNC_ATOMIC_GET(&g_cli.nRemoteRtcMsgs) > 0 && XSYNC_ATOMIC_GET(&g_cli.nRemoteRelayMsgs) == 0,
        "a command's own traffic goes over the data channel, and none of it over the relay");
    CHECK(strstr(out_of(&res.errors), "RTC") == NULL, "nothing of dgcli's own reaches the command's stderr");
    XExec_ResultClear(&res);

    /* An agent that cannot set WebRTC up says so: the relay is taken at once, with nothing waited out */
    reset_outputs();
    XSYNC_ATOMIC_SET(&g_cli.eRtcMode, HOST_RTC_REFUSE);
    uint64_t nRefusedStart = XTime_GetMonoMs();
    nCode = cli_run(pTty, streams, NULL, 0, &res);
    uint64_t nRefusedMs = XTime_GetMonoMs() - nRefusedStart;
    CHECK(nCode == 0 && strcmp(out_of(&res.output), "out-1\nout-2\x1b[31m\n") == 0,
        "a command whose agent refuses WebRTC still runs, on the relay");
    CHECK(XSYNC_ATOMIC_GET(&g_cli.nRemoteRelayMsgs) > 0 && XSYNC_ATOMIC_GET(&g_cli.nRemoteRtcMsgs) == 0 &&
        XSYNC_ATOMIC_GET(&g_cli.bClientUnavailable), "the client tells the agent, and the relay carries the command");
    CHECK(nRefusedMs < DIRECTGATE_REMOTE_CHANNEL_WAIT_MS, "a refused offer is not waited out");
    XExec_ResultClear(&res);

    /* An offer nobody answers: only once the client's own wait runs out is the relay taken */
    reset_outputs();
    XSYNC_ATOMIC_SET(&g_cli.eRtcMode, HOST_RTC_IGNORE);
    const char *unanswered[] = { "exec", "-c", pCfg, CLI_DEVICE_ID, "fail", "3", NULL };
    uint64_t nIgnoredStart = XTime_GetMonoMs();
    nCode = cli_run(pTty, unanswered, NULL, 0, &res);
    uint64_t nIgnoredMs = XTime_GetMonoMs() - nIgnoredStart;
    CHECK(nCode == 3 && XSYNC_ATOMIC_GET(&g_cli.bClientUnavailable) && XSYNC_ATOMIC_GET(&g_cli.nRemoteRtcMsgs) == 0,
        "an unanswered offer ends with the client's word that WebRTC is impossible, and the relay");
    CHECK(nIgnoredMs >= DIRECTGATE_REMOTE_CHANNEL_WAIT_MS - 500, "the relay is not taken before the wait runs out");
    XExec_ResultClear(&res);

    /* The data channel goes while the command runs: what was in it cannot be known to have arrived */
    reset_outputs();
    const char *dropped[] = { "exec", "-c", pCfg, CLI_DEVICE_ID, "drop-channel", NULL };
    nCode = cli_run(pTty, dropped, NULL, 0, &res);
    CHECK(nCode == 255 && strstr(out_of(&res.errors), "the peer-to-peer connection was lost") != NULL,
        "a command whose data channel is lost fails, and says why");
    CHECK(XSYNC_ATOMIC_GET(&g_cli.nRemoteRelayMsgs) == 0, "nothing of it moves to the relay");
    XExec_ResultClear(&res);

    /* -o: no more of each stream than asked for, even from an agent that sends it all; nothing asked, nothing cut */
    reset_outputs();
    const char *limited[] = { "exec", "-c", pCfg, "-o", "5", CLI_DEVICE_ID, "chatty", NULL };
    nCode = cli_run(pTty, limited, NULL, 0, &res);
    CHECK(nCode == 0, "a command with an output limit exits with its own code");
    CHECK(g_cli.bExecOutputMax && g_cli.nExecOutputMax == 5, "the output limit reaches the host");
    CHECK(strcmp(out_of(&res.output), "aaaaa") == 0 && strcmp(out_of(&res.errors), "01234") == 0,
        "each stream is cut at the limit on this side too");
    XExec_ResultClear(&res);

    reset_outputs();
    const char *unlimited[] = { "exec", "-c", pCfg, CLI_DEVICE_ID, "chatty", NULL };
    nCode = cli_run(pTty, unlimited, NULL, 0, &res);
    CHECK(nCode == 0 && !g_cli.bExecOutputMax, "without -o the host is asked for no limit");
    CHECK(res.output.nUsed == 3U * 16384U && strcmp(out_of(&res.errors), "0123456789") == 0, "without -o nothing is cut");
    XExec_ResultClear(&res);

    /* Options before the device; the exit code is the command's; words that look like options are the command's */
    reset_outputs();
    const char *failing[] = { "exec", "-c", pCfg, "-t", "5", "-C", "/srv", CLI_DEVICE_ID, "fail", "3", NULL };
    nCode = cli_run(pTty, failing, NULL, 0, &res);
    CHECK(nCode == 3, "dgcli exits with the command's own exit code");
    CHECK(strcmp(g_cli.sExecCwd, "/srv") == 0 && g_cli.nExecTimeoutMs == 5000, "the directory and the timeout reach the host");
    XExec_ResultClear(&res);

    /* With the config at its default path, a command's own -c is still the command's */
    char sDefaultCfg[512], sCfgText[2048];
    snprintf(sDefaultCfg, sizeof(sDefaultCfg), "%s/.config/directgate/client.json", pRoot);
    CHECK(read_text(pCfg, sCfgText, sizeof(sCfgText)), "read the test config");
    write_file(sDefaultCfg, sCfgText);

    reset_outputs();
    const char *defaulted[] = { "exec", CLI_DEVICE_ID, "gcc", "-c", "x.c", NULL };
    nCode = cli_run(pTty, defaulted, NULL, 0, &res);
    unlink(sDefaultCfg);
    CHECK(nCode == 0 && strcmp(g_cli.sExecCommand, "gcc -c x.c") == 0,
        "a -c after the device is the command's, not a config for dgcli to load");
    XExec_ResultClear(&res);

    reset_outputs();
    const char *dashed[] = { "exec", "-c", pCfg, CLI_DEVICE_ID, "--", "gcc", "-c", "x.c", "-o", "x", NULL };
    nCode = cli_run(pTty, dashed, NULL, 0, &res);
    CHECK(nCode == 0 && strcmp(g_cli.sExecCommand, "gcc -c x.c -o x") == 0,
        "the command's own -c is not taken for dgcli's config, and the -- separator is not part of the command");
    XExec_ResultClear(&res);

    /* Piped stdin reaches the command, then its end of file */
    reset_outputs();
    const char *echo[] = { "exec", "-c", pCfg, CLI_DEVICE_ID, "echo-input", NULL };
    const char *pPiped = "piped line one\npiped line two\n";
    nCode = cli_run(pTty, echo, pPiped, strlen(pPiped), &res);
    CHECK(nCode == 7 && g_cli.bExecStdin, "a command reading piped input runs with stdin");
    CHECK(strcmp(out_of(&res.output), pPiped) == 0, "the piped input reached the command in full");
    CHECK(strstr(out_of(&res.errors), "warn") != NULL, "the command's warning arrives on stderr");
    XExec_ResultClear(&res);

    /* What a script must be able to tell apart: a timeout, a refusal, a session that ends under the command */
    reset_outputs();
    const char *slow[] = { "exec", "-c", pCfg, CLI_DEVICE_ID, "too", "slow", NULL };
    nCode = cli_run(pTty, slow, NULL, 0, &res);
    CHECK(nCode == 137 && strstr(out_of(&res.errors), "timed out") != NULL, "a command killed for its timeout says so");
    XExec_ResultClear(&res);

    reset_outputs();
    const char *refused[] = { "exec", "-c", pCfg, CLI_DEVICE_ID, "refuse", NULL };
    nCode = cli_run(pTty, refused, NULL, 0, &res);
    CHECK(nCode == 255 && strstr(out_of(&res.errors), "cannot start the command") != NULL,
        "a command the host could not start fails with the host's reason");
    CHECK(strchr(out_of(&res.errors), '\x1b') == NULL && strchr(out_of(&res.errors), '\x07') == NULL,
        "the host's reason reaches the terminal without its escape sequences");
    XExec_ResultClear(&res);

    reset_outputs();
    const char *vanish[] = { "exec", "-c", pCfg, CLI_DEVICE_ID, "vanish", NULL };
    nCode = cli_run(pTty, vanish, NULL, 0, &res);
    CHECK(nCode == 255 && strstr(out_of(&res.errors), "closed before the command finished") != NULL,
        "a session that ends before the exit is a failure, not a success");
    XExec_ResultClear(&res);

    /* Ctrl-C goes to the command, whose exit is still waited for */
    reset_outputs();
    xexec_t exec;
    const char *waiting[] = { "exec", "-c", pCfg, CLI_DEVICE_ID, "wait-for-signal", NULL };
    CHECK(cli_spawn(pTty, waiting, &exec), "start a command that waits for a signal");
    CHECK(wait_atomic(&g_cli.bExecStarted, 20000), "the command starts");
    CHECK(XExec_Kill(&exec, SIGINT) == XSTDOK, "interrupt the client");
    CHECK(wait_atomic(&g_cli.bExecSignalled, 10000) && strcmp(g_cli.sExecSignal, "INT") == 0,
        "the interrupt is forwarded to the command");
    CHECK(XExec_Wait(&exec, 10000) == XSTDOK && exec.nExitCode == 130, "dgcli exits with the interrupted command's code");
    XExec_Close(&exec);

    /* Ctrl-C while the start is still being confirmed: held, and sent the moment the command is known to run */
    reset_outputs();
    const char *slowStart[] = { "exec", "-c", pCfg, CLI_DEVICE_ID, "slow-start", NULL };
    CHECK(cli_spawn(pTty, slowStart, &exec), "start a command whose start is confirmed late");
    CHECK(wait_atomic(&g_cli.bExecStarted, 20000), "the command is asked for");
    CHECK(XExec_Kill(&exec, SIGINT) == XSTDOK, "interrupt the client before the start is confirmed");
    CHECK(wait_atomic(&g_cli.bExecSignalled, 10000) && strcmp(g_cli.sExecSignal, "INT") == 0,
        "an interrupt that came before the confirmed start is forwarded once the command runs");
    CHECK(XExec_Wait(&exec, 10000) == XSTDOK && exec.nExitCode == 130, "and dgcli exits with the command's code");
    XExec_Close(&exec);

    /* A command that ignores it: the second interrupt ends dgcli itself */
    reset_outputs();
    const char *stubborn[] = { "exec", "-c", pCfg, CLI_DEVICE_ID, "stubborn", NULL };
    CHECK(cli_spawn(pTty, stubborn, &exec), "start a command that ignores signals");
    CHECK(wait_atomic(&g_cli.bExecStarted, 20000), "the stubborn command starts");
    CHECK(XExec_Kill(&exec, SIGINT) == XSTDOK && wait_atomic(&g_cli.bExecSignalled, 10000), "the first interrupt is forwarded");
    CHECK(XExec_Wait(&exec, 500) == XSTDNON, "dgcli keeps waiting for a command that ignored the interrupt");
    CHECK(XExec_Kill(&exec, SIGINT) == XSTDOK, "interrupt the client again");
    CHECK(XExec_Wait(&exec, 10000) == XSTDOK && exec.nExitCode == 255, "the second interrupt ends dgcli as its own failure");
    XExec_Close(&exec);

    /* ---- the file manager: device:/path names the remote side, as scp does ---- */

    reset_outputs();
    const char *listJson[] = { "ls", "-c", pCfg, "-j", CLI_DEVICE_ID ":/srv", NULL };
    nCode = cli_run(pTty, listJson, NULL, 0, &res);
    CHECK(nCode == 0 && strstr(out_of(&res.output), "\"entries\":[") != NULL && strstr(out_of(&res.output), "hello.txt") != NULL,
        "ls -j <device>:<path> prints the listing as the host sent it");
    CHECK(strcmp(g_cli.sManagerLast, "list /srv") == 0, "the listing asked for is the one named");
    XExec_ResultClear(&res);

    reset_outputs();
    const char *listText[] = { "ls", "-c", pCfg, CLI_DEVICE_ID ":/srv", NULL };
    nCode = cli_run(pTty, listText, NULL, 0, &res);
    CHECK(nCode == 0 && strstr(out_of(&res.output), "-rw-r--r-- user     user") != NULL &&
        strstr(out_of(&res.output), " hello.txt\n") != NULL && strstr(out_of(&res.output), " logs\n") != NULL,
        "ls prints one line per entry, ls -l style");
    XExec_ResultClear(&res);

    reset_outputs();
    const char *listBad[] = { "ls", "-c", pCfg, CLI_DEVICE_ID ":/nope", NULL };
    nCode = cli_run(pTty, listBad, NULL, 0, &res);
    CHECK(nCode == 1 && strstr(out_of(&res.errors), "failed to read directory") != NULL && res.output.nUsed == 0,
        "a listing the host refuses fails with its reason and prints nothing");
    XExec_ResultClear(&res);

    /* ls on its own is the device list, as it always was */
    reset_outputs();
    const char *lsDevices[] = { "ls", "-c", pCfg, "-j", NULL };
    nCode = cli_run(pTty, lsDevices, NULL, 0, &res);
    CHECK(nCode == 0 && strncmp(out_of(&res.output), "{\"devices\":[", 12) == 0, "ls without a path lists the devices");
    XExec_ResultClear(&res);

    /* cp from the device: into a directory under the remote name, to a named file, and to stdout */
    char sLocal[512], sText[4096];
    snprintf(sLocal, sizeof(sLocal), "%s/hello.txt", pRoot);
    unlink(sLocal);
    reset_outputs();
    const char *get[] = { "cp", "-c", pCfg, CLI_DEVICE_ID ":/srv/hello.txt", ".", NULL };
    nCode = cli_run(pTty, get, NULL, 0, &res);
    CHECK(nCode == 0 && read_text(sLocal, sText, sizeof(sText)) && strcmp(sText, CLI_REMOTE_FILE_TEXT) == 0,
        "cp <device>:<file> <dir> writes the verified file under its remote name");
    XExec_ResultClear(&res);

    /* Nothing local is replaced without -f: refused before anything is fetched, then replaced with it */
    snprintf(sLocal, sizeof(sLocal), "%s/renamed.txt", pRoot);
    write_file(sLocal, "an older local copy\n");
    reset_outputs();
    const char *getNamed[] = { "cp", "-c", pCfg, CLI_DEVICE_ID ":/srv/hello.txt", "renamed.txt", NULL };
    nCode = cli_run(pTty, getNamed, NULL, 0, &res);
    CHECK(nCode == 1 && strstr(out_of(&res.errors), "exists; give -f to replace it") != NULL &&
        XSYNC_ATOMIC_GET(&g_cli.nConnects) == 0, "an existing local file is not replaced without -f, and nothing connects");
    CHECK(read_text(sLocal, sText, sizeof(sText)) && strcmp(sText, "an older local copy\n") == 0, "the local file is untouched");
    XExec_ResultClear(&res);

    reset_outputs();
    const char *getForced[] = { "cp", "-c", pCfg, "-f", CLI_DEVICE_ID ":/srv/hello.txt", "renamed.txt", NULL };
    nCode = cli_run(pTty, getForced, NULL, 0, &res);
    CHECK(nCode == 0 && read_text(sLocal, sText, sizeof(sText)) && strcmp(sText, CLI_REMOTE_FILE_TEXT) == 0,
        "cp -f replaces an existing local file with the download");
    XExec_ResultClear(&res);

    /* A local file that appears while the download runs is not replaced either: the commit refuses it */
    snprintf(sLocal, sizeof(sLocal), "%s/race.txt", pRoot);
    unlink(sLocal);
    xstrncpy(g_cli.sRacePath, sizeof(g_cli.sRacePath), sLocal);
    reset_outputs();
    const char *getRace[] = { "cp", "-c", pCfg, CLI_DEVICE_ID ":/srv/hello.txt", "race.txt", NULL };
    nCode = cli_run(pTty, getRace, NULL, 0, &res);
    g_cli.sRacePath[0] = '\0';
    CHECK(nCode == 1 && strstr(out_of(&res.errors), "exists; give -f to replace it") != NULL,
        "a destination that appeared during the download is refused at the commit");
    CHECK(read_text(sLocal, sText, sizeof(sText)) && strcmp(sText, "appeared meanwhile\n") == 0,
        "the file that appeared meanwhile is untouched");
    CHECK(no_partial_downloads(pRoot), "the refused download leaves no partial file behind");
    XExec_ResultClear(&res);

    /* A file system without hard links: the no-clobber falls back to a check right before the rename */
    char sMark[512], sMarkEnv[600];
    snprintf(sMark, sizeof(sMark), "%s/no-hardlinks.mark", pRoot);
    snprintf(sMarkEnv, sizeof(sMarkEnv), "SHIM_NO_HARDLINKS_MARK=%s", sMark);
    const char *pNoLinks[] = {
        "LD_PRELOAD=" DIRECTGATE_NO_HARDLINKS_SHIM, "ASAN_OPTIONS=verify_asan_link_order=0", sMarkEnv, NULL
    };
    unlink(sMark);

    snprintf(sLocal, sizeof(sLocal), "%s/nolinks.txt", pRoot);
    unlink(sLocal);
    reset_outputs();
    const char *getNoLinks[] = { "cp", "-c", pCfg, CLI_DEVICE_ID ":/srv/hello.txt", "nolinks.txt", NULL };
    nCode = cli_run_env(pTty, getNoLinks, NULL, 0, pNoLinks, &res);
    CHECK(access(sMark, F_OK) == 0, "the download tried a hard link and was refused one");
    CHECK(nCode == 0 && read_text(sLocal, sText, sizeof(sText)) && strcmp(sText, CLI_REMOTE_FILE_TEXT) == 0,
        "without hard links a download still lands, renamed into place");
    CHECK(no_partial_downloads(pRoot), "and leaves no partial file behind");
    XExec_ResultClear(&res);

    snprintf(sLocal, sizeof(sLocal), "%s/nolinks-race.txt", pRoot);
    unlink(sLocal);
    xstrncpy(g_cli.sRacePath, sizeof(g_cli.sRacePath), sLocal);
    reset_outputs();
    const char *getNoLinksRace[] = { "cp", "-c", pCfg, CLI_DEVICE_ID ":/srv/hello.txt", "nolinks-race.txt", NULL };
    nCode = cli_run_env(pTty, getNoLinksRace, NULL, 0, pNoLinks, &res);
    g_cli.sRacePath[0] = '\0';
    CHECK(nCode == 1 && strstr(out_of(&res.errors), "exists; give -f to replace it") != NULL &&
        read_text(sLocal, sText, sizeof(sText)) && strcmp(sText, "appeared meanwhile\n") == 0,
        "without hard links a file that appeared during the download is still not replaced");
    CHECK(no_partial_downloads(pRoot), "the refused download leaves no partial file behind");
    XExec_ResultClear(&res);

    reset_outputs();
    const char *getOut[] = { "cp", "-c", pCfg, CLI_DEVICE_ID ":/srv/hello.txt", "-", NULL };
    nCode = cli_run(pTty, getOut, NULL, 0, &res);
    CHECK(nCode == 0 && strcmp(out_of(&res.output), CLI_REMOTE_FILE_TEXT) == 0,
        "cp <device>:<file> - writes the file to stdout and nothing else");
    XExec_ResultClear(&res);

    reset_outputs();
    const char *getMissing[] = { "cp", "-c", pCfg, CLI_DEVICE_ID ":/srv/missing.txt", ".", NULL };
    nCode = cli_run(pTty, getMissing, NULL, 0, &res);
    snprintf(sLocal, sizeof(sLocal), "%s/missing.txt", pRoot);
    CHECK(nCode == 1 && strstr(out_of(&res.errors), "file not found") != NULL && access(sLocal, F_OK) != 0,
        "a missing remote file fails with the host's reason and leaves no local file");
    CHECK(no_partial_downloads(pRoot), "no partial download is left behind");
    XExec_ResultClear(&res);

    /* cp to the device: several chunks' worth, into a directory, from stdin, and over an existing file only with -f */
    size_t nBig = 300U * 1024U + 123U;
    char *pBig = (char*)malloc(nBig);
    CHECK(pBig != NULL, "an upload source");
    for (size_t i = 0; i < nBig; i++) pBig[i] = (char)('a' + (i * 7) % 26);

    snprintf(sLocal, sizeof(sLocal), "%s/upload.bin", pRoot);
    FILE *pFile = fopen(sLocal, "wb");
    CHECK(pFile != NULL && fwrite(pBig, 1, nBig, pFile) == nBig, "write the upload source");
    fclose(pFile);

    reset_outputs();
    const char *put[] = { "cp", "-c", pCfg, "upload.bin", CLI_DEVICE_ID ":/srv/dir/", NULL };
    nCode = cli_run(pTty, put, NULL, 0, &res);
    int bSame = g_cli.upload.nUsed == nBig && memcmp(g_cli.upload.pData, pBig, nBig) == 0;
    CHECK(nCode == 0 && XSYNC_ATOMIC_GET(&g_cli.bUploadDone), "a multi-chunk upload completes and is acknowledged");
    CHECK(bSame && strcmp(g_cli.sManagerLast, "save /srv/dir/upload.bin") == 0,
        "the upload lands under the local name in the remote directory, byte for byte");
    XExec_ResultClear(&res);
    free(pBig);

    reset_outputs();
    const char *putStdin[] = { "cp", "-c", pCfg, "-", CLI_DEVICE_ID ":/srv/notes.txt", NULL };
    const char *pNotes = "from a pipe\n";
    nCode = cli_run(pTty, putStdin, pNotes, strlen(pNotes), &res);
    CHECK(nCode == 0 && g_cli.upload.nUsed == strlen(pNotes) && memcmp(g_cli.upload.pData, pNotes, strlen(pNotes)) == 0,
        "cp - <device>:<file> uploads what arrives on stdin");
    XExec_ResultClear(&res);

    reset_outputs();
    const char *putNameless[] = { "cp", "-c", pCfg, "-", CLI_DEVICE_ID ":/srv/dir/", NULL };
    nCode = cli_run(pTty, putNameless, pNotes, strlen(pNotes), &res);
    CHECK(nCode == 1 && strstr(out_of(&res.errors), "give the remote file a name") != NULL &&
        XSYNC_ATOMIC_GET(&g_cli.nConnects) == 0, "stdin uploaded into a directory needs a name, before anything connects");
    XExec_ResultClear(&res);

    reset_outputs();
    const char *putExists[] = { "cp", "-c", pCfg, "upload.bin", CLI_DEVICE_ID ":/srv/exists.txt", NULL };
    nCode = cli_run(pTty, putExists, NULL, 0, &res);
    CHECK(nCode == 1 && strstr(out_of(&res.errors), "give -f") != NULL && !XSYNC_ATOMIC_GET(&g_cli.bUploadDone),
        "an existing remote file is not replaced without -f");
    XExec_ResultClear(&res);

    reset_outputs();
    const char *putForce[] = { "cp", "-c", pCfg, "-f", "upload.bin", CLI_DEVICE_ID ":/srv/exists.txt", NULL };
    nCode = cli_run(pTty, putForce, NULL, 0, &res);
    CHECK(nCode == 0 && strcmp(g_cli.sManagerLast, "save /srv/exists.txt force") == 0 && XSYNC_ATOMIC_GET(&g_cli.bUploadDone),
        "cp -f replaces an existing remote file");
    XExec_ResultClear(&res);

    reset_outputs();
    const char *putMissing[] = { "cp", "-c", pCfg, "no-such-file", CLI_DEVICE_ID ":/srv/x", NULL };
    nCode = cli_run(pTty, putMissing, NULL, 0, &res);
    CHECK(nCode == 1 && XSYNC_ATOMIC_GET(&g_cli.nConnects) == 0, "a missing upload source fails before anything connects");
    XExec_ResultClear(&res);

    /* Which side is remote has to be clear: exactly one */
    reset_outputs();
    const char *bothLocal[] = { "cp", "-c", pCfg, "a.txt", "b.txt", NULL };
    nCode = cli_run(pTty, bothLocal, NULL, 0, &res);
    CHECK(nCode == 255 && strstr(out_of(&res.errors), "exactly one side") != NULL, "a copy with no remote side is refused");
    XExec_ResultClear(&res);

    reset_outputs();
    const char *bothRemote[] = { "cp", "-c", pCfg, CLI_DEVICE_ID ":/a", CLI_DEVICE_ID ":/b", NULL };
    nCode = cli_run(pTty, bothRemote, NULL, 0, &res);
    CHECK(nCode == 255 && strstr(out_of(&res.errors), "exactly one side") != NULL && XSYNC_ATOMIC_GET(&g_cli.nConnects) == 0,
        "a copy between two remote paths is refused");
    XExec_ResultClear(&res);

    /* rm, mkdir, mv */
    reset_outputs();
    const char *rmFile[] = { "rm", "-c", pCfg, CLI_DEVICE_ID ":/srv/old", NULL };
    CHECK(cli_run(pTty, rmFile, NULL, 0, &res) == 0 && strcmp(g_cli.sManagerLast, "delete /srv/old") == 0,
        "rm deletes without recursing");
    XExec_ResultClear(&res);

    reset_outputs();
    const char *rmTree[] = { "rm", "-c", pCfg, "-r", CLI_DEVICE_ID ":/srv/old", NULL };
    CHECK(cli_run(pTty, rmTree, NULL, 0, &res) == 0 && strcmp(g_cli.sManagerLast, "delete /srv/old force") == 0,
        "rm -r asks for a recursive delete");
    XExec_ResultClear(&res);

    reset_outputs();
    const char *mk[] = { "mkdir", "-c", pCfg, CLI_DEVICE_ID ":/srv/new", NULL };
    CHECK(cli_run(pTty, mk, NULL, 0, &res) == 0 && strcmp(g_cli.sManagerLast, "mkdir /srv/new") == 0,
        "mkdir creates the directory");
    XExec_ResultClear(&res);

    reset_outputs();
    const char *mv[] = { "mv", "-c", pCfg, CLI_DEVICE_ID ":/srv/a", "/srv/b", NULL };
    CHECK(cli_run(pTty, mv, NULL, 0, &res) == 0 && strcmp(g_cli.sManagerLast, "rename /srv/a /srv/b") == 0,
        "mv renames, never moving aside into a made-up name");
    XExec_ResultClear(&res);

    reset_outputs();
    const char *mvSpec[] = { "mv", "-c", pCfg, CLI_DEVICE_ID ":/srv/a", CLI_DEVICE_ID ":/srv/c", NULL };
    CHECK(cli_run(pTty, mvSpec, NULL, 0, &res) == 0 && strcmp(g_cli.sManagerLast, "rename /srv/a /srv/c") == 0,
        "mv takes its target as <device>:<path> too");
    XExec_ResultClear(&res);

    reset_outputs();
    const char *mvOther[] = { "mv", "-c", pCfg, CLI_DEVICE_ID ":/srv/a", "other-box:/srv/c", NULL };
    nCode = cli_run(pTty, mvOther, NULL, 0, &res);
    CHECK(nCode == 255 && strstr(out_of(&res.errors), "same device") != NULL && XSYNC_ATOMIC_GET(&g_cli.nConnects) == 0,
        "mv between two devices is refused before anything connects");
    XExec_ResultClear(&res);

    reset_outputs();
    const char *mvTaken[] = { "mv", "-c", pCfg, CLI_DEVICE_ID ":/srv/a", "/srv/taken", NULL };
    nCode = cli_run(pTty, mvTaken, NULL, 0, &res);
    CHECK(nCode == 1 && strstr(out_of(&res.errors), "target already exists") != NULL, "mv onto an existing target fails");
    XExec_ResultClear(&res);

    /* Refused before connecting: a relative remote path, a path without its device, a missing device */
    reset_outputs();
    const char *relative[] = { "rm", "-c", pCfg, CLI_DEVICE_ID ":srv/old", NULL };
    nCode = cli_run(pTty, relative, NULL, 0, &res);
    CHECK(nCode == 255 && strstr(out_of(&res.errors), "absolute") != NULL && XSYNC_ATOMIC_GET(&g_cli.nConnects) == 0,
        "a relative remote path is refused before anything connects");
    XExec_ResultClear(&res);

    reset_outputs();
    const char *noDevice[] = { "rm", "-c", pCfg, "/srv/old", NULL };
    nCode = cli_run(pTty, noDevice, NULL, 0, &res);
    CHECK(nCode == 255 && strstr(out_of(&res.errors), "<device>:<path>") != NULL && XSYNC_ATOMIC_GET(&g_cli.nConnects) == 0,
        "a remote path without its device is refused, saying how to name it");
    XExec_ResultClear(&res);

    reset_outputs();
    const char *unknown[] = { "exec", "-c", pCfg, "no-such-box", "true", NULL };
    nCode = cli_run(pTty, unknown, NULL, 0, &res);
    CHECK(nCode == 255 && strstr(out_of(&res.errors), "No device matches") != NULL && res.output.nUsed == 0,
        "an unknown device fails on stderr, with stdout left empty");
    XExec_ResultClear(&res);

    /* The device list for a script */
    reset_outputs();
    const char *devJson[] = { "devices", "-c", pCfg, "-j", NULL };
    nCode = cli_run(pTty, devJson, NULL, 0, &res);
    CHECK(nCode == 0 && strncmp(out_of(&res.output), "{\"devices\":[", 12) == 0 &&
        strstr(out_of(&res.output), "\"id\":\"" CLI_DEVICE_ID "\"") != NULL &&
        strstr(out_of(&res.output), "\"connectable\":true") != NULL, "devices -j prints the list as JSON");
    XExec_ResultClear(&res);

    if (scenario_session(pTty, pCfg) != 0) return 1;

    int nMcp = scenario_mcp(pTty, pCfg);
    g_cli.sAuthorizedKey[0] = '\0';
    XSYNC_ATOMIC_SET(&g_cli.bOfferExec, 0);
    return nMcp;
}

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

    /* A sign-in signed out from another device: its access token has not run out, so it is used, but the API turns
       it down and the refresh token is gone. The client signs in again and goes on, as above. */
    static const char sSignedOut[] = "{\"accessToken\":\"acct-access-signed-out\",\"refreshToken\":\"acct-refresh-gone\","
        "\"expiresAt\":4102444800,\"email\":\"" CLI_EMAIL "\",\"userId\":\"u-1\"}";
    write_file(sAuth, sSignedOut);
    chmod(sAuth, 0600);

    reset_outputs();
    CHECK(tty_start(pTty, stale, XFALSE), "start with a session signed out from another device");
    CHECK(tty_expect(pTty, "paste the code", 20000), "a signed-out session leads to a new sign-in");
    CHECK(strstr(pTty->sScreen, "signed out, signing in again") != NULL, "and the client says why");
    CHECK(tty_type(pTty, "pasted-code\n"), "paste the code for the new sign-in");
    CHECK(tty_finish(pTty, 20000) == 0, "after signing in again the command goes on");
    CHECK(XSYNC_ATOMIC_GET(&g_cli.nRefreshes) == 1 && XSYNC_ATOMIC_GET(&g_cli.nTokenRedeems) == 1,
        "the refresh was tried once, then the new sign-in redeemed once");
    CHECK(strstr(pTty->sScreen, CLI_DEVICE_NAME) != NULL, "the devices are listed with the new session");
    CHECK(XPath_LoadBuffer(sAuth, &saved) > 0, "the new session is stored");
    bRotated = strstr((const char*)saved.pData, "acct-refresh-1") != NULL;
    XByteBuffer_Clear(&saved);
    CHECK(bRotated, "the new session replaces the signed-out one");

    /* Without a terminal there is nobody to sign in: it says how, and the dead session is not kept to fail again */
    write_file(sAuth, sSignedOut);
    chmod(sAuth, 0600);
    const char *signedOut[] = { "devices", "-c", pCfg, NULL };
    CHECK(tty_start(pTty, signedOut, XTRUE), "start without a terminal on a signed-out session");
    CHECK(tty_finish(pTty, 10000) != 0, "a signed-out session without a terminal fails");
    CHECK(strstr(pTty->sScreen, "Run 'dgcli login'") != NULL, "and says how to sign in again");
    CHECK(access(sAuth, F_OK) != 0, "the signed-out session is forgotten");

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
    XByteBuffer_Init(&g_cli.execInput, XSTDNON, XFALSE);
    XByteBuffer_Init(&g_cli.upload, XSTDNON, XFALSE);
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

    /* A log directory of its own: the default one is a system directory a CI runner cannot create, and a client that
       fails to says so on stderr - which the exec checks compare byte for byte */
    char sText[1024];
    snprintf(sText, sizeof(sText), "{\"apiUrl\":\"https://127.0.0.1:%u\",\"apiToken\":\"%s\",\"webUrl\":\"https://example.test\","
        "\"log\":{\"toScreen\":true,\"toFile\":false,\"path\":\"%s/logs\"}}\n", (unsigned)g_cli.nApiPort, CLI_API_TOKEN, sRoot);
    write_file(sCfg, sText);

    /* No API token: this one has to sign in to an account. */
    snprintf(sText, sizeof(sText), "{\"apiUrl\":\"https://127.0.0.1:%u\",\"webUrl\":\"https://example.test\","
        "\"log\":{\"toScreen\":true,\"toFile\":false,\"path\":\"%s/logs\"}}\n", (unsigned)g_cli.nApiPort, sRoot);
    write_file(sAcctCfg, sText);

    tty_t tty;
    memset(&tty, 0, sizeof(tty));
    tty.nMaster = -1;
    tty.pRoot = sRoot;
    tty.pCert = tls.sCert;

    int nResult = scenario_password_session(&tty, sCfg);
    if (!nResult) nResult = scenario_keys(&tty, sCfg, sRoot);
    if (!nResult)
    {
        /* Remote operations meet a host that answers their offers: their data runs over a real data channel */
        XSYNC_ATOMIC_SET(&g_cli.bRemoteRtc, 1);
        nResult = scenario_remote(&tty, sCfg, sRoot);
        XSYNC_ATOMIC_SET(&g_cli.bRemoteRtc, 0);
    }
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
    webrtc_cleanup_settled();

    DirectGate_SRP_Destroy(&g_cli.srp);
    DirectGate_KeyAuth_Cleanse(&g_cli.keyauth);
    DirectGate_E2E_Clear(&g_cli.e2e);
    XByteBuffer_Clear(&g_cli.typed);
    XByteBuffer_Clear(&g_cli.execInput);
    XByteBuffer_Clear(&g_cli.upload);
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
