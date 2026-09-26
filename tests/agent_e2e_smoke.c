/*
 * The real agent binary, end to end, against a relay and an enrollment API
 * played by this test.
 *
 * Everything else in the suite drives the agent's handlers in process. This is
 * the one place the whole program runs the way it does on a host: it parses
 * its command line, loads its config, refreshes its token over HTTPS, connects
 * to the relay over WSS with its routing key, sends its role, answers an SRP
 * login, runs a shell, feeds it more input than the pseudo terminal holds
 * while it is not reading, moves the session onto a direct WebRTC connection a
 * browser offers and runs the shell over it, refreshes a token that runs out mid-session and tells
 * the relay, answers the relay's pings and probes a relay that has gone quiet,
 * survives the relay dropping it, and - when the relay
 * claims the device was revoked - asks the API before believing it, clears
 * its enrollment when the API confirms, stops reconnecting and exits cleanly
 * on SIGTERM.
 *
 * Both endpoints use real TLS with a throwaway certificate the agent trusts
 * through SSL_CERT_FILE, so the production transport policy (no plain ws or
 * http) stays switched on.
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "src/common/protocol.h"
#include "src/common/srp.h"
#include "src/common/e2e.h"
#include "src/common/webrtc.h"
#include "src/common/websock.h"

#include "tls_fixture.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "agent_e2e_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

#define E2E_DEVICE_ID    "device-e2e"
#define E2E_ROUTING_KEY  "rk-e2e-0123456789"
#define E2E_SECRET       "e2e agent password"
#define E2E_SESSION_ID   7U
#define E2E_MARKER       "E2E_MARK_42"
#define E2E_FLOOD_CHUNK  32768
#define E2E_FLOOD_CHUNKS 8

typedef enum {
    RELAY_WAIT_ROLE = 0,
    RELAY_WAIT_CHALLENGE,
    RELAY_WAIT_RESULT,
    RELAY_WAIT_MARKER,
    RELAY_WAIT_CWD,
    RELAY_WAIT_PONG,
    RELAY_WAIT_READY,
    RELAY_WAIT_FLOOD,
    RELAY_WAIT_P2P,
    RELAY_IDLE
} relay_stage_t;

typedef struct {
    xapi_t api;
    uint16_t nApiPort;
    uint16_t nRelayPort;
    char sRelayUrl[128];

    /* Written by the server thread, polled by the test. */
    xatomic_t bStop;
    xatomic_t nApiRequests;
    xatomic_t bApiRevoked;
    xatomic_t nRelayConnections;
    xatomic_t nRejectedHandshakes;
    xatomic_t nRoles;
    xatomic_t bRoleTokenOk;
    xatomic_t bAuthOk;
    xatomic_t bMarkerSeen;
    xatomic_t bCwdSeen;
    xatomic_t bPongSeen;
    xatomic_t bFloodDone;
    xatomic_t bP2PConnected;
    xatomic_t bP2PSeen;
    xatomic_t bVerifySeen;
    xatomic_t bVerifyTokenOk;
    xatomic_t bWsPongSeen;
    xatomic_t bAgentPingSeen;
    xatomic_t bDropNow;
    xatomic_t bRevokeSent;

    /* Only touched by the server thread. */
    directgate_webrtc_t rtc;  /* the browser's half of a direct connection */
    xbool_t bRtcActive;
    xbool_t bRtcCommandSent;
    relay_stage_t eStage;
    directgate_srp_client_t client;
    directgate_e2e_t peer;
    char sBHex[2048];
    xbyte_buffer_t output;
    xapi_session_t *pRelaySession;
} e2e_t;

static e2e_t g_e2e;

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

/* ---- the enrollment API -------------------------------------------------------- */

static int api_respond(xapi_session_t *pSession)
{
    char sBody[1024];
    uint16_t nCode = 200;

    if (XSYNC_ATOMIC_GET(&g_e2e.bApiRevoked))
    {
        nCode = 401;
        snprintf(sBody, sizeof(sBody), "{\"code\":\"DEVICE_ENROLLMENT_REVOKED\",\"message\":\"revoked by the test\"}");
    }
    else
    {
        /* The first token runs out a few seconds into the session, inside the
           agent's 60s refresh skew, so the connected agent has to refresh it
           and tell the relay. Every later one lasts. */
        int nRequest = (int)XSYNC_ATOMIC_GET(&g_e2e.nApiRequests);
        snprintf(sBody, sizeof(sBody),
            "{\"accessToken\":\"access-%d\",\"refreshTokenRotated\":false,\"accessTokenExpiresIn\":%d,"
            "\"enrollmentExpiresAt\":\"2099-01-01T00:00:00Z\",\"relayUrl\":\"%s\",\"routingKey\":\"%s\","
            "\"deviceId\":\"%s\"}",
            nRequest, nRequest == 1 ? 63 : 3600, g_e2e.sRelayUrl, E2E_ROUTING_KEY, E2E_DEVICE_ID);
    }

    xhttp_t handle;
    if (XHTTP_InitResponse(&handle, nCode, NULL) <= 0) return XAPI_DISCONNECT;

    if (XHTTP_AddHeader(&handle, "Content-Type", "application/json") < 0 ||
        XHTTP_Assemble(&handle, (const uint8_t*)sBody, strlen(sBody)) == NULL)
    {
        XHTTP_Clear(&handle);
        return XAPI_DISCONNECT;
    }

    XByteBuffer_AddBuff(&pSession->txBuffer, &handle.rawData);
    XHTTP_Clear(&handle);
    return XAPI_EnableEvent(pSession, XPOLLOUT);
}

static int api_request(xapi_session_t *pSession)
{
    xhttp_t *pHandle = (xhttp_t*)pSession->pPacket;
    if (pHandle == NULL || strcmp(pHandle->sUri, "/api/v1/devices/refresh") != 0) return XAPI_DISCONNECT;

    /* The refresh token the config was written with, carried in the body. */
    const char *pBody = (const char*)XHTTP_GetBody(pHandle);
    size_t nBody = XHTTP_GetBodySize(pHandle);
    if (pBody == NULL || nBody == 0 || strstr(pBody, "\"refreshToken\":\"refresh-e2e\"") == NULL) return XAPI_DISCONNECT;

    XSYNC_ATOMIC_ADD(&g_e2e.nApiRequests, 1);
    return api_respond(pSession);
}

/* ---- the relay ------------------------------------------------------------------ */

static int relay_send(xapi_session_t *pSession, xjson_obj_t *pHeader, const uint8_t *pPayload, size_t nPayload)
{
    if (pHeader == NULL) return XAPI_DISCONNECT;

    xbyte_buffer_t packet;
    XByteBuffer_Init(&packet, XSTDNON, XFALSE);

    xbool_t bSealed = DirectGate_E2E_IsInitialized(&g_e2e.peer);
    if (bSealed) DirectGate_Proto_AddCC(pHeader, &g_e2e.peer, 0);

    int nStatus = XAPI_DISCONNECT;
    if (DirectGate_Proto_Build(&packet, pHeader, pPayload, nPayload, XFALSE) &&
        (!bSealed || DirectGate_Proto_EncryptPackage(&packet, &g_e2e.peer, E2E_SESSION_ID)))
        nStatus = DirectGate_WebSock_SendBuff(pSession, &packet);

    XJSON_FreeObject(pHeader);
    XByteBuffer_Clear(&packet);
    return nStatus;
}

/* What the relay says on its own behalf - verify, error, status - is never sealed. */
static int relay_send_plain(xapi_session_t *pSession, xjson_obj_t *pHeader)
{
    if (pHeader == NULL) return XAPI_DISCONNECT;

    xbyte_buffer_t packet;
    XByteBuffer_Init(&packet, XSTDNON, XFALSE);

    int nStatus = DirectGate_Proto_Build(&packet, pHeader, NULL, 0, XFALSE) ?
        DirectGate_WebSock_SendBuff(pSession, &packet) : XAPI_DISCONNECT;

    XJSON_FreeObject(pHeader);
    XByteBuffer_Clear(&packet);
    return nStatus;
}

static int relay_control(xapi_session_t *pSession, xws_frame_type_t eType)
{
    if (XWS_AppendFrame(&pSession->txBuffer, NULL, 0, eType, XFALSE, XTRUE) != XWS_ERR_NONE) return XAPI_DISCONNECT;
    return XAPI_EnableEvent(pSession, XPOLLOUT);
}

/* The agent's token update, answered the three ways a relay can: accepted,
   rejected, and with something the agent cannot make sense of. Then a ping,
   which a live agent answers. */
static int relay_on_verify(xapi_session_t *pSession, directgate_pkg_t *pPkg)
{
    xjson_obj_t *pRoot = pPkg->jsonHeader.pRootObj;
    const char *pAction = XJSON_GetString(XJSON_GetObject(pRoot, "action"));
    const char *pToken = XJSON_GetString(XJSON_GetObject(pRoot, "accessToken"));
    const char *pRequestId = XJSON_GetString(XJSON_GetObject(pRoot, "requestId"));
    if (pAction == NULL || strcmp(pAction, "update") != 0) return XAPI_CONTINUE;

    /* The token the API issued on the second request, not the one the session started with. */
    if (pToken != NULL && strcmp(pToken, "access-2") == 0 && pRequestId != NULL && strlen(pRequestId) == 16)
        XSYNC_ATOMIC_SET(&g_e2e.bVerifyTokenOk, 1);

    XSYNC_ATOMIC_SET(&g_e2e.bVerifySeen, 1);

    if (relay_send_plain(pSession, DirectGate_Proto_BuildVerify("ack", NULL, pRequestId, 4102444800ULL, "ok", NULL)) < 0 ||
        relay_send_plain(pSession, DirectGate_Proto_BuildVerify("ack", NULL, pRequestId, 0, "error", "token expired")) < 0 ||
        relay_send_plain(pSession, DirectGate_Proto_BuildVerify("ack", NULL, NULL, 0, NULL, NULL)) < 0 ||
        relay_send_plain(pSession, DirectGate_Proto_BuildVerify(NULL, NULL, NULL, 0, NULL, NULL)) < 0)
        return XAPI_DISCONNECT;

    return relay_control(pSession, XWS_PING);
}

/* Signalling the browser's WebRTC produced goes to the agent sealed, on the relay. */
static void browser_signal(const char *pData, size_t nLen, void *pCtx)
{
    (void)pCtx;
    xjson_t json;
    if (g_e2e.pRelaySession == NULL || !XJSON_Parse(&json, NULL, pData, nLen)) return;

    XJSON_AddU32(json.pRootObj, "sessionId", E2E_SESSION_ID);
    xbyte_buffer_t packet;
    XByteBuffer_Init(&packet, XSTDNON, XFALSE);
    DirectGate_Proto_AddCC(json.pRootObj, &g_e2e.peer, 0);

    if (DirectGate_Proto_Build(&packet, json.pRootObj, NULL, 0, XFALSE) &&
        DirectGate_Proto_EncryptPackage(&packet, &g_e2e.peer, E2E_SESSION_ID))
        DirectGate_WebSock_SendBuff(g_e2e.pRelaySession, &packet);

    XByteBuffer_Clear(&packet);
    XJSON_Destroy(&json);
}

/* What the agent sends over the data channel: sealed like relay traffic, shell output in it. */
static void browser_data(const uint8_t *pData, size_t nLen, void *pCtx)
{
    (void)pCtx;
    directgate_pkg_t pkg;
    if (!DirectGate_Package_Parse(&pkg, pData, nLen)) return;

    xbyte_buffer_t inner;
    XByteBuffer_Init(&inner, XSTDNON, XFALSE);

    directgate_pkg_t msg;
    if (DirectGate_Proto_DecryptPackage(&inner, &pkg, &g_e2e.peer) &&
        DirectGate_Package_Parse(&msg, inner.pData, inner.nUsed))
    {
        const directgate_pkg_data_t *pMsgData = (const directgate_pkg_data_t*)msg.pPackage;
        if (msg.header.pType != NULL && strcmp(msg.header.pType, "data") == 0 &&
            pMsgData != NULL && pMsgData->pPayload != NULL && pMsgData->nPayloadLength)
        {
            XByteBuffer_Add(&g_e2e.output, pMsgData->pPayload, pMsgData->nPayloadLength);
            if (strstr((const char*)g_e2e.output.pData, "P2P_9") != NULL) XSYNC_ATOMIC_SET(&g_e2e.bP2PSeen, 1);
        }

        DirectGate_Package_Clear(&msg);
    }

    XByteBuffer_Clear(&inner);
    DirectGate_Package_Clear(&pkg);
}

/* Once the channel is up the browser types over it; once the answer comes back over it, the session stops. */
static void browser_tick(void)
{
    if (!g_e2e.bRtcActive) return;
    DirectGate_WebRTC_ProcessQueue(&g_e2e.rtc);

    if (!g_e2e.bRtcCommandSent && DirectGate_WebRTC_IsConnected(&g_e2e.rtc))
    {
        g_e2e.bRtcCommandSent = XTRUE;
        XSYNC_ATOMIC_SET(&g_e2e.bP2PConnected, 1);

        const char *pLine = "echo P2P_$((4+5))\n";
        xjson_obj_t *pHeader = DirectGate_Proto_BuildData(E2E_SESSION_ID);
        xbyte_buffer_t packet;
        XByteBuffer_Init(&packet, XSTDNON, XFALSE);
        DirectGate_Proto_AddCC(pHeader, &g_e2e.peer, 0);

        if (DirectGate_Proto_Build(&packet, pHeader, (const uint8_t*)pLine, strlen(pLine), XFALSE) &&
            DirectGate_Proto_EncryptPackage(&packet, &g_e2e.peer, E2E_SESSION_ID))
            DirectGate_WebRTC_Send(&g_e2e.rtc, packet.pData, packet.nUsed);

        XJSON_FreeObject(pHeader);
        XByteBuffer_Clear(&packet);
    }

    if (g_e2e.eStage == RELAY_WAIT_P2P && XSYNC_ATOMIC_GET(&g_e2e.bP2PSeen) && g_e2e.pRelaySession != NULL)
    {
        g_e2e.eStage = RELAY_IDLE;
        relay_send(g_e2e.pRelaySession, DirectGate_Proto_BuildCmd("stop", NULL, NULL, NULL, E2E_SESSION_ID), NULL, 0);
    }
}

static void browser_stop(void)
{
    if (!g_e2e.bRtcActive) return;
    DirectGate_WebRTC_Clear(&g_e2e.rtc);
    g_e2e.bRtcActive = XFALSE;
}

static int relay_start_login(xapi_session_t *pSession)
{
    char sAHex[2048];
    char sNonceHex[(DIRECTGATE_SRP_NONCE_SIZE * 2) + 1];

    DirectGate_SRP_ClientCleanse(&g_e2e.client);
    if (!DirectGate_SRP_ClientInit(&g_e2e.client) ||
        !DirectGate_SRP_ClientGenerateA(&g_e2e.client, sAHex, sizeof(sAHex), sNonceHex, sizeof(sNonceHex)))
        return XAPI_DISCONNECT;

    g_e2e.eStage = RELAY_WAIT_CHALLENGE;
    return relay_send(pSession, DirectGate_Proto_BuildAuthHello(E2E_DEVICE_ID, sAHex, sNonceHex, E2E_SESSION_ID), NULL, 0);
}

static int relay_on_role(xapi_session_t *pSession, directgate_pkg_t *pPkg)
{
    xjson_obj_t *pRoot = pPkg->jsonHeader.pRootObj;
    const char *pRole = XJSON_GetString(XJSON_GetObject(pRoot, "role"));
    const char *pDevice = XJSON_GetString(XJSON_GetObject(pRoot, "deviceId"));
    const char *pToken = XJSON_GetString(XJSON_GetObject(pRoot, "accessToken"));

    /* The token must be the one the API just issued, not the stale one on disk. */
    if (pRole != NULL && strcmp(pRole, "agent") == 0 && pDevice != NULL && strcmp(pDevice, E2E_DEVICE_ID) == 0 &&
        pToken != NULL && strncmp(pToken, "access-", 7) == 0)
        XSYNC_ATOMIC_SET(&g_e2e.bRoleTokenOk, 1);

    XSYNC_ATOMIC_ADD(&g_e2e.nRoles, 1);
    int nRoles = (int)XSYNC_ATOMIC_GET(&g_e2e.nRoles);
    if (nRoles == 1) return relay_start_login(pSession);

    /* Second connection: claim the device was revoked. The agent must not act on
       this alone, only schedule a check against the API. */
    XSYNC_ATOMIC_SET(&g_e2e.bApiRevoked, 1);
    XSYNC_ATOMIC_SET(&g_e2e.bRevokeSent, 1);
    g_e2e.eStage = RELAY_IDLE;
    return relay_send(pSession, DirectGate_Proto_BuildError("device-revoked", 0), NULL, 0);
}

static int relay_on_auth(xapi_session_t *pSession, directgate_pkg_t *pPkg)
{
    xjson_obj_t *pRoot = pPkg->jsonHeader.pRootObj;
    const char *pAction = XJSON_GetString(XJSON_GetObject(pRoot, "action"));
    if (pAction == NULL) return XAPI_DISCONNECT;

    if (g_e2e.eStage == RELAY_WAIT_CHALLENGE && strcmp(pAction, "challenge") == 0)
    {
        const char *pSalt = XJSON_GetString(XJSON_GetObject(pRoot, "salt"));
        const char *pB = XJSON_GetString(XJSON_GetObject(pRoot, "B"));
        const char *pNonce = XJSON_GetString(XJSON_GetObject(pRoot, "nonce"));
        uint32_t nSuite = XJSON_GetU32(XJSON_GetObject(pRoot, "suite"));

        size_t nNonce = 0;
        char sM1[256];
        if (pB == NULL || !DirectGate_SRP_HexToBytes(pNonce, g_e2e.client.agentNonce,
                sizeof(g_e2e.client.agentNonce), &nNonce) ||
            !DirectGate_SRP_ClientComputeKey(&g_e2e.client, E2E_DEVICE_ID, E2E_SECRET, pSalt, pB, nSuite,
                sM1, sizeof(sM1))) return XAPI_DISCONNECT;

        xstrncpy(g_e2e.sBHex, sizeof(g_e2e.sBHex), pB);
        g_e2e.eStage = RELAY_WAIT_RESULT;
        return relay_send(pSession, DirectGate_Proto_BuildAuthProof(sM1, E2E_SESSION_ID), NULL, 0);
    }

    if (g_e2e.eStage == RELAY_WAIT_RESULT && strcmp(pAction, "result") == 0)
    {
        const char *pStatus = XJSON_GetString(XJSON_GetObject(pRoot, "status"));
        const char *pM2 = XJSON_GetString(XJSON_GetObject(pRoot, "M2"));

        if (pStatus == NULL || strcmp(pStatus, "ok") != 0 || pM2 == NULL ||
            !DirectGate_SRP_ClientVerifyM2(&g_e2e.client, g_e2e.sBHex, pM2)) return XAPI_DISCONNECT;

        DirectGate_E2E_Init(&g_e2e.peer);
        if (!DirectGate_E2E_DeriveFromSRP(&g_e2e.peer, g_e2e.client.K, sizeof(g_e2e.client.K),
                g_e2e.client.agentNonce, g_e2e.client.nonce, DIRECTGATE_SRP_NONCE_SIZE, E2E_DEVICE_ID, XFALSE))
            return XAPI_DISCONNECT;

        XSYNC_ATOMIC_SET(&g_e2e.bAuthOk, 1);
        g_e2e.eStage = RELAY_WAIT_MARKER;

        if (relay_send(pSession, DirectGate_Proto_BuildCmd("start", NULL, NULL, "terminal", E2E_SESSION_ID), NULL, 0) < 0)
            return XAPI_DISCONNECT;

        /* $((6*7)) proves a shell evaluated the line, rather than the echo of the typed input. */
        const char *pLine = "echo E2E_MARK_$((6*7))\n";
        return relay_send(pSession, DirectGate_Proto_BuildData(E2E_SESSION_ID), (const uint8_t*)pLine, strlen(pLine));
    }

    return XAPI_CONTINUE;
}

static int relay_on_sealed(xapi_session_t *pSession, directgate_pkg_t *pPkg)
{
    xbyte_buffer_t inner;
    XByteBuffer_Init(&inner, XSTDNON, XFALSE);

    if (!DirectGate_Proto_DecryptPackage(&inner, pPkg, &g_e2e.peer))
    {
        XByteBuffer_Clear(&inner);
        return XAPI_DISCONNECT;
    }

    directgate_pkg_t msg;
    int nStatus = XAPI_CONTINUE;

    if (!DirectGate_Package_Parse(&msg, inner.pData, inner.nUsed))
    {
        XByteBuffer_Clear(&inner);
        return XAPI_DISCONNECT;
    }

    const char *pType = msg.header.pType;
    xjson_obj_t *pRoot = msg.jsonHeader.pRootObj;

    if (g_e2e.eStage == RELAY_WAIT_MARKER && pType != NULL && strcmp(pType, "data") == 0)
    {
        const directgate_pkg_data_t *pData = (const directgate_pkg_data_t*)msg.pPackage;
        if (pData != NULL && pData->pPayload != NULL && pData->nPayloadLength)
            XByteBuffer_Add(&g_e2e.output, pData->pPayload, pData->nPayloadLength);

        /* The typed line echoes "$((6*7))"; only the shell's answer has the digits. */
        if (g_e2e.output.nUsed && strstr((const char*)g_e2e.output.pData, E2E_MARKER) != NULL)
        {
            XSYNC_ATOMIC_SET(&g_e2e.bMarkerSeen, 1);
            g_e2e.eStage = RELAY_WAIT_CWD;

            nStatus = relay_send(pSession, DirectGate_Proto_BuildResize(40, 120, 960, 640, E2E_SESSION_ID), NULL, 0);
            if (nStatus >= 0)
                nStatus = relay_send(pSession, DirectGate_Proto_BuildCmd("getcwd", NULL, NULL, NULL, E2E_SESSION_ID), NULL, 0);
        }
    }
    else if (g_e2e.eStage == RELAY_WAIT_CWD && pType != NULL && strcmp(pType, "cmd") == 0)
    {
        const char *pAction = XJSON_GetString(XJSON_GetObject(pRoot, "action"));
        const char *pPath = XJSON_GetString(XJSON_GetObject(pRoot, "path"));

        if (pAction != NULL && strcmp(pAction, "cwd") == 0 && pPath != NULL && pPath[0] == '/')
        {
            XSYNC_ATOMIC_SET(&g_e2e.bCwdSeen, 1);
            g_e2e.eStage = RELAY_WAIT_PONG;
            nStatus = relay_send(pSession, DirectGate_Proto_BuildKeepalive("ping", E2E_SESSION_ID), NULL, 0);
        }
    }
    else if (g_e2e.eStage == RELAY_WAIT_PONG && pType != NULL && strcmp(pType, "keepalive") == 0)
    {
        const char *pAction = XJSON_GetString(XJSON_GetObject(pRoot, "action"));
        if (pAction != NULL && strcmp(pAction, "pong") == 0)
        {
            XSYNC_ATOMIC_SET(&g_e2e.bPongSeen, 1);
            g_e2e.eStage = RELAY_WAIT_READY;
            XByteBuffer_Clear(&g_e2e.output);

            /* A shell that stops reading, then reads exactly what it was sent. Raw mode keeps the
               terminal from throwing input away, so the agent has to hold what the terminal cannot. */
            const char *pLine = "stty raw -echo; echo READY_$((3+4)); sleep 1; head -c 262144 >/dev/null; "
                "stty sane; echo FLOOD_$((2+3))\n";
            nStatus = relay_send(pSession, DirectGate_Proto_BuildData(E2E_SESSION_ID), (const uint8_t*)pLine, strlen(pLine));
        }
    }
    else if ((g_e2e.eStage == RELAY_WAIT_READY || g_e2e.eStage == RELAY_WAIT_FLOOD) && pType != NULL &&
             strcmp(pType, "data") == 0)
    {
        const directgate_pkg_data_t *pData = (const directgate_pkg_data_t*)msg.pPackage;
        if (pData != NULL && pData->pPayload != NULL && pData->nPayloadLength)
            XByteBuffer_Add(&g_e2e.output, pData->pPayload, pData->nPayloadLength);

        const char *pOutput = g_e2e.output.nUsed ? (const char*)g_e2e.output.pData : "";

        if (g_e2e.eStage == RELAY_WAIT_READY && strstr(pOutput, "READY_7") != NULL)
        {
            /* More than the terminal holds, all at once, while the shell sleeps. */
            static uint8_t flood[E2E_FLOOD_CHUNK];
            memset(flood, 'x', sizeof(flood));
            g_e2e.eStage = RELAY_WAIT_FLOOD;

            for (int i = 0; i < E2E_FLOOD_CHUNKS && nStatus >= 0; i++)
                nStatus = relay_send(pSession, DirectGate_Proto_BuildData(E2E_SESSION_ID), flood, sizeof(flood));
        }
        else if (g_e2e.eStage == RELAY_WAIT_FLOOD && strstr(pOutput, "FLOOD_5") != NULL)
        {
            /* Next the browser offers a direct connection, as a real one does once the terminal is up. */
            XSYNC_ATOMIC_SET(&g_e2e.bFloodDone, 1);
            g_e2e.eStage = RELAY_WAIT_P2P;
            XByteBuffer_Clear(&g_e2e.output);

            DirectGate_WebRTC_Init(&g_e2e.rtc);
            g_e2e.rtc.signalCb = browser_signal;
            g_e2e.rtc.dataCb = browser_data;
            g_e2e.bRtcActive = XTRUE;
            g_e2e.bRtcCommandSent = XFALSE;
            if (DirectGate_WebRTC_CreateOffer(&g_e2e.rtc) < 0) nStatus = XAPI_DISCONNECT;
        }
    }
    else if (g_e2e.eStage == RELAY_WAIT_P2P && pType != NULL && strcmp(pType, "webrtc") == 0 && g_e2e.bRtcActive)
    {
        /* The agent's answer and candidates, delivered to the browser's peer connection. */
        const char *pAction = XJSON_GetString(XJSON_GetObject(pRoot, "action"));
        if (pAction != NULL && strcmp(pAction, "answer") == 0)
            DirectGate_WebRTC_HandleAnswer(&g_e2e.rtc, XJSON_GetString(XJSON_GetObject(pRoot, "sdp")));
        else if (pAction != NULL && strcmp(pAction, "ice") == 0)
            DirectGate_WebRTC_HandleIceCandidate(&g_e2e.rtc, XJSON_GetString(XJSON_GetObject(pRoot, "candidate")),
                XJSON_GetString(XJSON_GetObject(pRoot, "sdpMid")), 0);
    }

    DirectGate_Package_Clear(&msg);
    XByteBuffer_Clear(&inner);
    return nStatus;
}

static int relay_frame(xapi_session_t *pSession)
{
    xws_frame_t *pFrame = (xws_frame_t*)pSession->pPacket;
    if (pFrame == NULL) return XAPI_DISCONNECT;

    if (pFrame->eType == XWS_PONG)
    {
        XSYNC_ATOMIC_SET(&g_e2e.bWsPongSeen, 1);
        return XAPI_CONTINUE;
    }

    /* A relay link the agent has heard nothing on for a while is probed, and answered. */
    if (pFrame->eType == XWS_PING)
    {
        XSYNC_ATOMIC_SET(&g_e2e.bAgentPingSeen, 1);
        return relay_control(pSession, XWS_PONG);
    }

    if (pFrame->eType != XWS_BINARY && pFrame->eType != XWS_TEXT) return XAPI_CONTINUE;

    const uint8_t *pPayload = XWebFrame_GetPayload(pFrame);
    size_t nPayload = XWebFrame_GetPayloadLength(pFrame);

    directgate_pkg_t pkg;
    if (pPayload == NULL || !DirectGate_Package_Parse(&pkg, pPayload, nPayload)) return XAPI_DISCONNECT;

    int nStatus = XAPI_CONTINUE;
    const char *pType = pkg.header.pType;

    if (pType != NULL && strcmp(pType, "role") == 0) nStatus = relay_on_role(pSession, &pkg);
    else if (pType != NULL && strcmp(pType, "auth") == 0) nStatus = relay_on_auth(pSession, &pkg);
    else if (pType != NULL && strcmp(pType, "encrypted") == 0) nStatus = relay_on_sealed(pSession, &pkg);
    else if (pType != NULL && strcmp(pType, "verify") == 0) nStatus = relay_on_verify(pSession, &pkg);

    DirectGate_Package_Clear(&pkg);
    return nStatus;
}

static int relay_handshake(xapi_session_t *pSession)
{
    xhttp_t *pHandle = (xhttp_t*)pSession->pPacket;

    /* The routing key rides on the query; a relay rejects a handshake without it. */
    if (pHandle == NULL || strstr(pHandle->sUri, "rk=" E2E_ROUTING_KEY) == NULL)
    {
        XSYNC_ATOMIC_ADD(&g_e2e.nRejectedHandshakes, 1);
        return XAPI_DISCONNECT;
    }

    return XAPI_CONTINUE;
}

static int service_callback(xapi_ctx_t *pCtx, xapi_session_t *pSession)
{
    xbool_t bRelay = pSession != NULL && pSession->eType == XAPI_WS;

    switch (pCtx->eCbType)
    {
        case XAPI_CB_ACCEPTED:
            if (bRelay)
            {
                /* A new relay connection starts the script over. */
                XSYNC_ATOMIC_ADD(&g_e2e.nRelayConnections, 1);
                DirectGate_E2E_Clear(&g_e2e.peer);
                DirectGate_E2E_Init(&g_e2e.peer);
                XByteBuffer_Clear(&g_e2e.output);
                g_e2e.eStage = RELAY_WAIT_ROLE;
                g_e2e.pRelaySession = pSession;
            }
            return XAPI_SetEvents(pSession, XPOLLIN);
        case XAPI_CB_HANDSHAKE_REQUEST:
            return relay_handshake(pSession);
        case XAPI_CB_READ:
            return bRelay ? relay_frame(pSession) : api_request(pSession);
        case XAPI_CB_COMPLETE:
            /* The API answers one request per connection. */
            return bRelay ? XAPI_CONTINUE : XAPI_DISCONNECT;
        case XAPI_CB_CLOSED:
            if (pSession == g_e2e.pRelaySession) g_e2e.pRelaySession = NULL;
            return XAPI_CONTINUE;
        case XAPI_CB_TICK:
            browser_tick();
            if (g_e2e.pRelaySession != NULL && XSYNC_ATOMIC_GET(&g_e2e.bDropNow))
            {
                XSYNC_ATOMIC_SET(&g_e2e.bDropNow, 0);
                XAPI_Disconnect(g_e2e.pRelaySession);
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
    while (!XSYNC_ATOMIC_GET(&g_e2e.bStop)) XAPI_Service(&g_e2e.api, 50);
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

    return XAPI_AddEndpoint(&g_e2e.api, &endpt) >= 0;
}

/* ---- the agent ---------------------------------------------------------------- */

static int write_config(const char *pPath, const char *pLogDir)
{
    uint8_t salt[DIRECTGATE_SRP_SALT_SIZE];
    memset(salt, 0x3c, sizeof(salt));

    char sSaltHex[DIRECTGATE_SRP_SALT_SIZE * 2 + 1];
    char sVerifier[2048];
    if (!DirectGate_SRP_CreateVerifier(E2E_SECRET, salt, sizeof(salt), sVerifier, sizeof(sVerifier))) return 0;
    for (size_t i = 0; i < sizeof(salt); i++) snprintf(sSaltHex + (i * 2), 3, "%02x", salt[i]);

    const char *pUser = getenv("USER");
    const char *pHome = getenv("HOME");

    FILE *pFile = fopen(pPath, "w");
    if (pFile == NULL) return 0;

    /* An access token that has already expired, so the agent has to refresh
       before it may connect at all. */
    fprintf(pFile,
        "{\n"
        "  \"relayUrl\": \"%s\",\n"
        "  \"routingKey\": \"%s\",\n"
        "  \"deviceId\": \"%s\",\n"
        "  \"log\": { \"toScreen\": true, \"toFile\": false, \"path\": \"%s\" },\n"
        "  \"shell\": { \"user\": \"%s\", \"home\": \"%s\" },\n"
        "  \"auth\": { \"srp\": { \"salt\": \"%s\", \"verifier\": \"%s\", \"suite\": %u } },\n"
        "  \"enrollment\": {\n"
        "    \"enrolled\": true,\n"
        "    \"apiUrl\": \"https://127.0.0.1:%u\",\n"
        "    \"accessToken\": \"stale-access\",\n"
        "    \"refreshToken\": \"refresh-e2e\",\n"
        "    \"accessTokenExp\": \"1000\",\n"
        "    \"refreshTokenExp\": \"4102444800\",\n"
        "    \"enrollmentExpiresAt\": \"2099-01-01T00:00:00Z\",\n"
        "    \"refreshSkewSec\": 60\n"
        "  }\n"
        "}\n",
        g_e2e.sRelayUrl, E2E_ROUTING_KEY, E2E_DEVICE_ID, pLogDir,
        pUser != NULL ? pUser : "root", pHome != NULL ? pHome : "/tmp",
        sSaltHex, sVerifier, (unsigned)DIRECTGATE_SRP_SUITE, (unsigned)g_e2e.nApiPort);

    fclose(pFile);
    return chmod(pPath, 0600) == 0;
}

static pid_t spawn_agent(const char *pCfgPath, const char *pCertPath, const char *pLogPath)
{
    pid_t nPid = fork();
    if (nPid != 0) return nPid;

    int nLog = open(pLogPath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (nLog >= 0)
    {
        dup2(nLog, STDOUT_FILENO);
        dup2(nLog, STDERR_FILENO);
        close(nLog);
    }

    setenv("SSL_CERT_FILE", pCertPath, 1);
    unsetenv("SSL_CERT_DIR");

    execl(DIRECTGATE_AGENT_BIN, DIRECTGATE_AGENT_BIN, "-c", pCfgPath, "-v", "5", (char*)NULL);
    _exit(127);
}

/* Waits up to nTimeoutMs for *pFlag to reach nWant, while the agent is alive. */
static int wait_for(xatomic_t *pFlag, xatomic_t nWant, uint32_t nTimeoutMs, pid_t nPid)
{
    for (uint32_t nWaited = 0; nWaited < nTimeoutMs; nWaited += 20)
    {
        if (XSYNC_ATOMIC_GET(pFlag) >= nWant) return 1;
        if (waitpid(nPid, NULL, WNOHANG) == nPid) return 0;
        xusleep(20000);
    }

    return XSYNC_ATOMIC_GET(pFlag) >= nWant;
}

static void dump_log(const char *pLogPath)
{
    FILE *pFile = fopen(pLogPath, "r");
    if (pFile == NULL) return;

    char sLine[512];
    fprintf(stderr, "---- agent log ----\n");
    while (fgets(sLine, sizeof(sLine), pFile) != NULL) fputs(sLine, stderr);
    fprintf(stderr, "-------------------\n");
    fclose(pFile);
}

static int run(const char *pRoot, const tls_fixture_t *pTls, pid_t *pPid)
{
    char sCfg[256], sLog[256];
    snprintf(sCfg, sizeof(sCfg), "%s/agent.json", pRoot);
    snprintf(sLog, sizeof(sLog), "%s/agent.log", pRoot);

    CHECK(write_config(sCfg, pRoot), "write the agent config");

    *pPid = spawn_agent(sCfg, pTls->sCert, sLog);
    CHECK(*pPid > 0, "start the agent");

    /* An expired token is refreshed before the relay is contacted at all. */
    CHECK(wait_for(&g_e2e.nApiRequests, 1, 20000, *pPid), "the agent refreshes its expired token before connecting");
    CHECK(wait_for(&g_e2e.nRoles, 1, 20000, *pPid), "the agent connects over WSS and announces itself");
    CHECK(XSYNC_ATOMIC_GET(&g_e2e.nRejectedHandshakes) == 0, "the agent's handshake carries its routing key");
    CHECK(XSYNC_ATOMIC_GET(&g_e2e.bRoleTokenOk), "the role carries the freshly issued access token, not the stale one");

    CHECK(wait_for(&g_e2e.bAuthOk, 1, 20000, *pPid), "an SRP login through the relay succeeds and the agent proves itself");
    CHECK(wait_for(&g_e2e.bMarkerSeen, 1, 20000, *pPid), "a shell started over the relay runs a command and returns its output");
    CHECK(wait_for(&g_e2e.bCwdSeen, 1, 20000, *pPid), "the agent reports the shell's working directory");
    CHECK(wait_for(&g_e2e.bPongSeen, 1, 20000, *pPid), "an encrypted keepalive is answered");
    CHECK(wait_for(&g_e2e.bFloodDone, 1, 30000, *pPid),
        "input the terminal cannot take at once is held and delivered whole, once the shell reads again");
    CHECK(wait_for(&g_e2e.bP2PConnected, 1, 30000, *pPid), "the browser's offer becomes a direct connection to the agent");
    CHECK(wait_for(&g_e2e.bP2PSeen, 1, 20000, *pPid), "the shell runs over the direct connection, input and output");

    /* The token issued at start runs out mid-session: refreshed, and the relay told. */
    CHECK(wait_for(&g_e2e.bVerifySeen, 1, 20000, *pPid), "a token that runs out mid-session is refreshed and sent to the relay");
    CHECK(XSYNC_ATOMIC_GET(&g_e2e.bVerifyTokenOk), "the relay is sent the newly issued token with a request id");
    CHECK(XSYNC_ATOMIC_GET(&g_e2e.nApiRequests) == 2, "one refresh at start and one mid-session, no more");
    CHECK(wait_for(&g_e2e.bWsPongSeen, 1, 10000, *pPid), "the agent answers the relay's ping, through every verify answer");

    /* Nothing more from the relay: after its idle limit the agent asks whether the link is alive. */
    CHECK(wait_for(&g_e2e.bAgentPingSeen, 1, 30000, *pPid), "an agent that hears nothing from the relay probes it");
    CHECK(XSYNC_ATOMIC_GET(&g_e2e.nRelayConnections) == 1, "an answered probe keeps the same relay connection");

    /* The relay goes away; the agent comes back on its own. */
    XSYNC_ATOMIC_SET(&g_e2e.bDropNow, 1);
    CHECK(wait_for(&g_e2e.nRelayConnections, 2, 30000, *pPid), "the agent reconnects after the relay drops it");
    CHECK(wait_for(&g_e2e.nRoles, 2, 20000, *pPid), "the reconnected agent announces itself again");
    CHECK(wait_for(&g_e2e.bRevokeSent, 1, 5000, *pPid), "the relay claims the device was revoked");

    /* The claim alone changes nothing on disk: only the API may end an enrollment. */
    int nApiBefore = (int)XSYNC_ATOMIC_GET(&g_e2e.nApiRequests);
    XSYNC_ATOMIC_SET(&g_e2e.bDropNow, 1);
    CHECK(wait_for(&g_e2e.nApiRequests, nApiBefore + 1, 30000, *pPid) || XSYNC_ATOMIC_GET(&g_e2e.bApiRevoked),
        "a relay's revocation claim makes the agent ask the API");

    /* Once the API confirms, the agent stops dialing and forgets the enrollment. */
    int nConnections = (int)XSYNC_ATOMIC_GET(&g_e2e.nRelayConnections);
    xusleep(6000 * 1000);
    CHECK((int)XSYNC_ATOMIC_GET(&g_e2e.nRelayConnections) == nConnections,
        "a confirmed revocation stops the agent from reconnecting");
    CHECK(waitpid(*pPid, NULL, WNOHANG) == 0, "a revoked agent stays up, idle, instead of crashing");

    xbyte_buffer_t cfg;
    CHECK(XPath_LoadBuffer(sCfg, &cfg) > 0, "reload the agent config");
    int bCleared = strstr((const char*)cfg.pData, "refresh-e2e") == NULL;
    XByteBuffer_Clear(&cfg);
    CHECK(bCleared, "a confirmed revocation removes the refresh token from the config");

    /* SIGTERM ends the service loop and the process exits cleanly. */
    CHECK(kill(*pPid, SIGTERM) == 0, "signal the agent to stop");
    int nStatus = 0;
    for (int i = 0; i < 200 && waitpid(*pPid, &nStatus, WNOHANG) == 0; i++) xusleep(50000);
    CHECK(WIFEXITED(nStatus) && WEXITSTATUS(nStatus) == 0, "the agent exits cleanly on SIGTERM");
    *pPid = 0;

    unlink(sCfg);
    unlink(sLog);
    return 0;
}

int main(void)
{
    memset(&g_e2e, 0, sizeof(g_e2e));
    signal(SIGPIPE, SIG_IGN);

    if (access(DIRECTGATE_AGENT_BIN, X_OK) != 0)
    {
        printf("agent_e2e_smoke: agent binary not built, skipping\n");
        return 77;
    }

    tls_fixture_t tls;
    CHECK(tls_fixture_begin(&tls), "create a TLS identity for the test endpoints");

    char sRoot[] = "/tmp/directgate_e2e.XXXXXX";
    CHECK(mkdtemp(sRoot) != NULL, "create a working directory");

    g_e2e.nApiPort = reserve_port();
    g_e2e.nRelayPort = reserve_port();
    CHECK(g_e2e.nApiPort && g_e2e.nRelayPort && g_e2e.nApiPort != g_e2e.nRelayPort, "reserve two local ports");
    snprintf(g_e2e.sRelayUrl, sizeof(g_e2e.sRelayUrl), "wss://127.0.0.1:%u/websock", (unsigned)g_e2e.nRelayPort);

    XByteBuffer_Init(&g_e2e.output, XSTDNON, XFALSE);
    DirectGate_E2E_Init(&g_e2e.peer);
    XAPI_Init(&g_e2e.api, service_callback, &g_e2e);
    CHECK(add_listener(XAPI_HTTP, g_e2e.nApiPort, &tls), "start the enrollment API");
    CHECK(add_listener(XAPI_WS, g_e2e.nRelayPort, &tls), "start the relay");

    xthread_t thread;
    CHECK(XThread_Create(&thread, server_thread, NULL, XFALSE) == XSTDOK, "start the server thread");

    pid_t nPid = 0;
    int nResult = run(sRoot, &tls, &nPid);

    if (nPid > 0)
    {
        kill(nPid, SIGKILL);
        waitpid(nPid, NULL, 0);
    }

    if (nResult != 0)
    {
        char sLog[256];
        snprintf(sLog, sizeof(sLog), "%s/agent.log", sRoot);
        dump_log(sLog);
    }

    XSYNC_ATOMIC_SET(&g_e2e.bStop, 1);
    XThread_Join(&thread);
    browser_stop();
    DirectGate_WebRTC_Cleanup();
    XAPI_Destroy(&g_e2e.api);

    DirectGate_SRP_ClientCleanse(&g_e2e.client);
    DirectGate_E2E_Clear(&g_e2e.peer);
    XByteBuffer_Clear(&g_e2e.output);

    char sPath[256];
    snprintf(sPath, sizeof(sPath), "%s/agent.log", sRoot);
    unlink(sPath);
    snprintf(sPath, sizeof(sPath), "%s/agent.json", sRoot);
    unlink(sPath);
    rmdir(sRoot);
    tls_fixture_end(&tls);

    if (nResult != 0) return 1;
    puts("agent_e2e_smoke: OK");
    return 0;
}
