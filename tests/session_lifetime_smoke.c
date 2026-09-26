/*
 * Session lifetime across the dispatch layer.
 *
 * Every case here is a message that ends - or used to end - a session in the middle of the handler that is
 * processing it. The handlers used to carry on through the freed session: a gate whose refusal value was the
 * same number as its pass value, a stop command that wrote its bookkeeping after the stop freed the session,
 * a handshake refresh that disconnected the very socket whose callback it ran in. None of those fail loudly
 * in a plain build; under ASan and Valgrind (both run this in CI) every one of them is a use-after-free, and
 * the cases that have an observable side effect (a directory created, a byte written) assert it by value.
 *
 * The session is wired to a real xapi_session_t with XPOLLOUT already set, so DirectGate_Session_Send runs
 * to completion without an event loop; the one case that needs a registered PTY endpoint builds a real one.
 */

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "src/agent/directgate.h"
#include "src/agent/files.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "session_lifetime_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

/* Every back-off and stagger here is far shorter than this, and a deadline on
   the wall clock lands decades beyond it: it is the bound that tells the two
   clocks apart. */
#define DIRECTGATE_TEST_HOUR_MS 3600000ULL

int DirectGate_ServiceCallback(xapi_ctx_t *pCtx, xapi_session_t *pApiSession);

/* Not in api.h: creates the event loop without registering anything on it. */
xevents_t* XAPI_GetOrCreateEvents(xapi_t *pApi);

typedef struct {
    directgate_cfg_t cfg;
    directgate_conn_t conn;
    xapi_session_t api;
    directgate_e2e_t peer;
} fixture_t;

static void drain(fixture_t *pFix)
{
    XByteBuffer_Clear(&pFix->api.txBuffer);
    XByteBuffer_Init(&pFix->api.txBuffer, XSTDNON, XFALSE);
}

/* Frames a header (sealed with the browser half of the E2E context when pPeer is given) and hands it to the
   agent exactly as a relay frame would arrive. */
static int deliver(fixture_t *pFix, xjson_obj_t *pHeader, const directgate_e2e_t *pPeerKeys,
                   const uint8_t *pPayload, size_t nPayload)
{
    xbyte_buffer_t packet;
    XByteBuffer_Init(&packet, XSTDNON, XFALSE);
    if (pHeader == NULL) return XSTDERR;

    uint32_t nSessionId = XJSON_GetU32(XJSON_GetObject(pHeader, "sessionId"));
    if (pPeerKeys != NULL) DirectGate_Proto_AddCC(pHeader, &pFix->peer, 0);

    int nStatus = XSTDERR;
    if (DirectGate_Proto_Build(&packet, pHeader, pPayload, nPayload, XFALSE) &&
        (pPeerKeys == NULL || DirectGate_Proto_EncryptPackage(&packet, &pFix->peer, nSessionId)))
        nStatus = DirectGate_TestHandleTransportMessage(&pFix->api, packet.pData, packet.nUsed);

    XJSON_FreeObject(pHeader);
    XByteBuffer_Clear(&packet);
    return nStatus;
}

/* Brings up both halves of an E2E context for pSession, the agent in the host role. */
static int seal_session(fixture_t *pFix, directgate_session_t *pSession)
{
    uint8_t sKey[32], sAgentNonce[DIRECTGATE_SRP_NONCE_SIZE], sClientNonce[DIRECTGATE_SRP_NONCE_SIZE];
    for (size_t i = 0; i < sizeof(sKey); i++) sKey[i] = (uint8_t)(i + 7);
    for (size_t i = 0; i < sizeof(sAgentNonce); i++) sAgentNonce[i] = (uint8_t)(0x30 + i);
    for (size_t i = 0; i < sizeof(sClientNonce); i++) sClientNonce[i] = (uint8_t)(0x50 + i);

    DirectGate_E2E_Init(&pFix->peer);
    return DirectGate_E2E_DeriveFromSRP(&pSession->e2e, sKey, sizeof(sKey), sAgentNonce, sClientNonce,
               DIRECTGATE_SRP_NONCE_SIZE, "dev-life", XTRUE) &&
           DirectGate_E2E_DeriveFromSRP(&pFix->peer, sKey, sizeof(sKey), sAgentNonce, sClientNonce,
               DIRECTGATE_SRP_NONCE_SIZE, "dev-life", XFALSE);
}

static directgate_session_t* new_session(fixture_t *pFix, uint32_t nSessionId, xbool_t bAuthenticated)
{
    directgate_session_t *pSession = DirectGate_SessionMgr_Create(&pFix->conn.mgr, nSessionId);
    if (pSession == NULL) return NULL;

    pSession->pWsSession = &pFix->api;
    pSession->bAuthenticated = bAuthenticated;
    return pSession;
}

/* Reads the manager answer the session queued, unwrapping the encrypted envelope. Returns 0 when there is none. */
static int take_manager_reply(fixture_t *pFix, char *pAction, char *pStatus, char *pPath, size_t nSize)
{
    if (pFix->api.txBuffer.nUsed == 0) return 0;

    xws_frame_t frame;
    if (XWebFrame_ParseData(&frame, pFix->api.txBuffer.pData, pFix->api.txBuffer.nUsed) != XWS_FRAME_COMPLETE)
    {
        XWebFrame_Clear(&frame);
        return 0;
    }

    xbyte_buffer_t outer, inner;
    XByteBuffer_Init(&outer, XSTDNON, XFALSE);
    XByteBuffer_Init(&inner, XSTDNON, XFALSE);
    XByteBuffer_Add(&outer, XWebFrame_GetPayload(&frame), XWebFrame_GetPayloadLength(&frame));
    XWebFrame_Clear(&frame);

    int nOk = 0;
    directgate_pkg_t pkg;

    if (DirectGate_Package_Parse(&pkg, outer.pData, outer.nUsed))
    {
        if (DirectGate_Proto_DecryptPackage(&inner, &pkg, &pFix->peer))
        {
            directgate_pkg_t innerPkg;
            if (DirectGate_Package_Parse(&innerPkg, inner.pData, inner.nUsed))
            {
                xjson_obj_t *pRoot = innerPkg.jsonHeader.pRootObj;
                const char *pGot[3] = {
                    XJSON_GetString(XJSON_GetObject(pRoot, "action")),
                    XJSON_GetString(XJSON_GetObject(pRoot, "status")),
                    XJSON_GetString(XJSON_GetObject(pRoot, "path"))
                };

                xstrncpy(pAction, nSize, pGot[0] != NULL ? pGot[0] : "");
                xstrncpy(pStatus, nSize, pGot[1] != NULL ? pGot[1] : "");
                xstrncpy(pPath, nSize, pGot[2] != NULL ? pGot[2] : "");
                DirectGate_Package_Clear(&innerPkg);
                nOk = 1;
            }
        }

        DirectGate_Package_Clear(&pkg);
    }

    XByteBuffer_Clear(&outer);
    XByteBuffer_Clear(&inner);
    drain(pFix);
    return nOk;
}

/* Turns the event loop until the session has queued an answer, for at most five seconds. */
static int service_until_reply(fixture_t *pFix, xapi_t *pApi)
{
    for (int i = 0; i < 500 && pFix->api.txBuffer.nUsed == 0; i++)
        XAPI_Service(pApi, 10);

    return pFix->api.txBuffer.nUsed > 0;
}

static xjson_obj_t* manager_header(const char *pAction, const char *pPath, uint32_t nSessionId)
{
    xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("manager", nSessionId);
    if (pHeader == NULL) return NULL;

    XJSON_AddString(pHeader, "action", pAction);
    XJSON_AddString(pHeader, "path", pPath);
    return pHeader;
}

static xjson_obj_t* file_start_header(uint32_t nSessionId)
{
    xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("file", nSessionId);
    if (pHeader == NULL) return NULL;

    XJSON_AddString(pHeader, "action", "start");
    XJSON_AddString(pHeader, "transferId", "t-life");
    XJSON_AddString(pHeader, "name", "planted.bin");
    XJSON_AddString(pHeader, "size", "4");
    XJSON_AddU32(pHeader, "chunks", 1);
    XJSON_AddU32(pHeader, "chunkSize", 65536);
    return pHeader;
}

static xbool_t path_exists(const char *pPath)
{
    struct stat st;
    return stat(pPath, &st) == 0 ? XTRUE : XFALSE;
}

int main(void)
{
    char sRoot[] = "/tmp/directgate_session_lifetime.XXXXXX";
    CHECK(mkdtemp(sRoot) != NULL, "a scratch directory can be created");

    char sPreAuthDir[512], sWrongModeDir[512], sPlanted[512];
    snprintf(sPreAuthDir, sizeof(sPreAuthDir), "%s/preauth", sRoot);
    snprintf(sWrongModeDir, sizeof(sWrongModeDir), "%s/wrongmode", sRoot);
    snprintf(sPlanted, sizeof(sPlanted), "%s/planted.bin", sRoot);

    fixture_t fix;
    memset(&fix, 0, sizeof(fix));
    xstrncpy(fix.cfg.auth.sSaltHex, sizeof(fix.cfg.auth.sSaltHex),
        "0000000000000000000000000000000000000000000000000000000000000000");
    xstrncpy(fix.cfg.auth.sVerifierHex, sizeof(fix.cfg.auth.sVerifierHex), "configured");
    xstrncpy(fix.cfg.sDeviceId, sizeof(fix.cfg.sDeviceId), "dev-life");
    fix.cfg.nKAInterval = 25;

    fix.conn.pCfg = &fix.cfg;
    DirectGate_SessionMgr_Init(&fix.conn.mgr, &fix.cfg);

    fix.api.pSessionData = &fix.conn;
    fix.api.sock.nFD = XSOCK_INVALID;
    fix.api.eRole = XAPI_CLIENT;
    fix.api.nEvents = XPOLLOUT;
    XByteBuffer_Init(&fix.api.txBuffer, XSTDNON, XFALSE);
    fix.conn.pWsSession = &fix.api;

    /* ---- pre-auth messages on a session that has not authenticated ------------------------------ */

    /* The gate closes (and frees) an unauthenticated session, and every one of these handlers used to go on
       using it afterwards: the resize wrote the window size into it, the manager request listed and created
       paths through it. The session has to be gone and nothing may have been done on its behalf. */
    {
        CHECK(new_session(&fix, 21, XFALSE) != NULL, "an unauthenticated session for resize");
        CHECK(deliver(&fix, DirectGate_Proto_BuildResize(40, 120, 0, 0, 21), NULL, NULL, 0) == XAPI_CONTINUE,
            "a pre-auth resize is not fatal to the relay link");
        CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 21) == NULL, "a pre-auth resize ends that session");

        CHECK(new_session(&fix, 22, XFALSE) != NULL, "an unauthenticated session for data");
        const uint8_t sKeys[] = "id\n";
        CHECK(deliver(&fix, DirectGate_Proto_BuildData(22), NULL, sKeys, sizeof(sKeys) - 1) == XAPI_CONTINUE,
            "pre-auth terminal data is not fatal to the relay link");
        CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 22) == NULL, "pre-auth terminal data ends that session");

        CHECK(new_session(&fix, 23, XFALSE) != NULL, "an unauthenticated session for a manager request");
        CHECK(deliver(&fix, manager_header("mkdir", sPreAuthDir, 23), NULL, NULL, 0) == XAPI_CONTINUE,
            "a pre-auth manager request is not fatal to the relay link");
        CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 23) == NULL, "a pre-auth manager request ends that session");
        CHECK(!path_exists(sPreAuthDir), "a pre-auth manager request must not touch the filesystem");

        CHECK(new_session(&fix, 24, XFALSE) != NULL, "an unauthenticated session for a file transfer");
        CHECK(deliver(&fix, file_start_header(24), NULL, NULL, 0) == XAPI_CONTINUE,
            "a pre-auth file start is not fatal to the relay link");
        CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 24) == NULL, "a pre-auth file start ends that session");
        CHECK(!path_exists(sPlanted), "a pre-auth file start must not create a file");
        drain(&fix);
    }

    /* ---- authenticated session in the wrong mode ------------------------------------------------ */

    /* A session in terminal or desktop mode is refused every file-manager action. The refusal used to be
       XAPI_CONTINUE, which is XSTDOK, so the handler ran anyway - on a pre-logon Windows agent that meant a
       desktop-only session doing file operations as LocalSystem. */
    {
        directgate_session_t *pSession = new_session(&fix, 31, XTRUE);
        CHECK(pSession != NULL, "an authenticated session in terminal mode");
        CHECK(seal_session(&fix, pSession), "the terminal session gets its E2E keys");
        pSession->eActiveMode = DIRECTGATE_SESSION_MODE_TERMINAL;

        CHECK(deliver(&fix, manager_header("mkdir", sWrongModeDir, 31), &fix.peer, NULL, 0) == XAPI_CONTINUE,
            "a manager request on a terminal session is not fatal");
        CHECK(!path_exists(sWrongModeDir), "a terminal session must not be able to create directories");
        CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 31) == pSession, "the refusal leaves the session alive");

        CHECK(deliver(&fix, file_start_header(31), &fix.peer, NULL, 0) == XAPI_CONTINUE,
            "a file start on a terminal session is not fatal");
        CHECK(!path_exists(sPlanted), "a terminal session must not be able to start an upload");

        pSession->eActiveMode = DIRECTGATE_SESSION_MODE_DESKTOP;
        CHECK(deliver(&fix, DirectGate_Proto_BuildResize(50, 132, 0, 0, 31), &fix.peer, NULL, 0) == XAPI_CONTINUE,
            "a terminal resize on a desktop session is not fatal");
        CHECK(!pSession->term.bHaveWinSize, "a desktop session must not take a terminal resize");

        DirectGate_SessionMgr_Remove(&fix.conn.mgr, pSession);
        drain(&fix);
    }

    /* ---- one bad frame is dropped, not fatal ------------------------------------------------------ */
    {
        const uint8_t sGarbage[] = { 0xff, 0xff, 0xff, 0x7f, '{', '}' };
        CHECK(DirectGate_TestHandleTransportMessage(&fix.api, sGarbage, sizeof(sGarbage)) == XAPI_CONTINUE,
            "a malformed frame must not tear down every session on the relay link");
    }

    /* ---- the search pipe's write end outlives its event ------------------------------------------ */

    /* The search worker writes to the write end until it is joined. Closing that end when the read end's
       event went away let a still-running worker write into whatever reused the descriptor number. */
    {
        directgate_session_t *pSession = new_session(&fix, 41, XTRUE);
        CHECK(pSession != NULL, "a session for the search pipe");
        CHECK(pSession->search.nPipeFds[0] != XSOCK_INVALID && pSession->search.nPipeFds[1] != XSOCK_INVALID,
            "the session has a search notification pair");

        XSOCKET nReadFd = pSession->search.nPipeFds[0];
        XSOCKET nWriteFd = pSession->search.nPipeFds[1];

        xapi_session_t searchEvent;
        memset(&searchEvent, 0, sizeof(searchEvent));
        searchEvent.eRole = XAPI_CUSTOM;
        searchEvent.pSessionData = pSession;
        searchEvent.sock.nFD = nReadFd;

        xapi_ctx_t ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.eCbType = XAPI_CB_CLOSED;
        DirectGate_ServiceCallback(&ctx, &searchEvent);

        CHECK(pSession->search.nPipeFds[0] == XSOCK_INVALID, "the read end is handed to the event loop");
        CHECK(pSession->search.nPipeFds[1] == nWriteFd, "the write end stays with the search until it is joined");
        CHECK(fcntl((int)nWriteFd, F_GETFD) != -1, "the write end is still an open descriptor");

        /* The event loop would have closed the read end with its endpoint. */
        close((int)nReadFd);
        DirectGate_SessionMgr_Remove(&fix.conn.mgr, pSession);
        CHECK(fcntl((int)nWriteFd, F_GETFD) == -1 && errno == EBADF, "the search teardown closes the write end");
    }

    /* ---- keepalive stagger survives its first pass ------------------------------------------------ */
    {
        directgate_session_t *pSession = new_session(&fix, 1, XTRUE);
        CHECK(pSession != NULL, "a session for the keepalive stagger");
        pSession->webrtc.bConnected = XTRUE;
        pSession->webrtc.nDataChannelID = 0;

        DirectGate_TestCheckWebRTCKeepalive(&fix.conn);
        uint64_t nFirstPing = pSession->nLastKAPingMs;
        CHECK(nFirstPing > XTime_GetMonoMs(), "the first ping is staggered into the future");
        CHECK(nFirstPing < XTime_GetMonoMs() + DIRECTGATE_TEST_HOUR_MS, "the stagger is on the monotonic clock");

        DirectGate_TestCheckWebRTCKeepalive(&fix.conn);
        CHECK(pSession->nLastKAPingMs == nFirstPing,
            "a future ping stamp must not be mistaken for a stalled loop and reset to now");

        pSession->webrtc.bConnected = XFALSE;
        pSession->webrtc.nDataChannelID = -1;
        DirectGate_SessionMgr_Remove(&fix.conn.mgr, pSession);
    }

    /* ---- a failed data channel send only falls back when the channel is really gone -------------- */
    {
        directgate_webrtc_t rtc;
        DirectGate_WebRTC_Init(&rtc);
        rtc.bConnected = XTRUE;
        rtc.nDataChannelID = 987654;

        DirectGate_WebRTC_NoteSendFailure(&rtc);
        CHECK(!rtc.bConnected, "a send failure on a channel that is not open falls back to the relay");

        rtc.nDataChannelID = -1;
        DirectGate_WebRTC_Clear(&rtc);
    }

    /* ---- in-session token refresh backs off --------------------------------------------------------- */

    /* A refresh is a blocking HTTP call on the event loop. With the API unreachable it used to be retried on
       every loop pass - stalling every live session and hammering the API ten times a second. */
    {
        fix.conn.bRoleSent = XTRUE;
        fix.cfg.enroll.bEnrolled = XTRUE;
        fix.cfg.enroll.nRefreshSkewSec = 120;
        fix.cfg.enroll.nAccessTokenExp = (uint64_t)time(NULL) + 60U;
        xstrncpy(fix.cfg.enroll.sAccessToken, sizeof(fix.cfg.enroll.sAccessToken), "still-usable");
        xstrncpy(fix.cfg.enroll.sRefreshToken, sizeof(fix.cfg.enroll.sRefreshToken), "refresh");
        xstrncpy(fix.cfg.enroll.sApiUrl, sizeof(fix.cfg.enroll.sApiUrl), "https://127.0.0.1:1");

        CHECK(DirectGate_TestCheckTokenRefresh(&fix.conn), "a transient refresh failure keeps a usable token");
        CHECK(fix.conn.nTokenRefreshFailures == 1, "the failed attempt is counted");
        CHECK(fix.conn.nNextTokenRefreshMs > XTime_GetMonoMs(), "the next attempt is scheduled in the future");
        CHECK(fix.conn.nNextTokenRefreshMs < XTime_GetMonoMs() + DIRECTGATE_TEST_HOUR_MS,
            "the refresh back-off is on the monotonic clock");

        uint64_t nScheduled = fix.conn.nNextTokenRefreshMs;
        CHECK(DirectGate_TestCheckTokenRefresh(&fix.conn), "a pass inside the back-off keeps the session");
        CHECK(fix.conn.nTokenRefreshFailures == 1 && fix.conn.nNextTokenRefreshMs == nScheduled,
            "no refresh is attempted before the back-off expires");

        fix.cfg.enroll.nAccessTokenExp = (uint64_t)time(NULL) + 3600U;
        CHECK(DirectGate_TestCheckTokenRefresh(&fix.conn), "a fresh token needs no refresh");
        CHECK(fix.conn.nTokenRefreshFailures == 0 && fix.conn.nNextTokenRefreshMs == 0,
            "the back-off resets once no refresh is needed");
    }

    /* ---- a failed token save is retried -------------------------------------------------------------- */

    /* A rotated refresh token that only lives in memory is gone at the next restart, and presenting the old
       one gets the device revoked. So a save that failed is retried until it lands. */
    {
        char sCfgPath[600];
        snprintf(sCfgPath, sizeof(sCfgPath), "%s/agent.json", sRoot);

        xstrncpy(fix.cfg.sCfgPath, sizeof(fix.cfg.sCfgPath), "/proc/directgate-no-such-dir/agent.json");
        fix.cfg.bSavePending = XTRUE;
        fix.conn.nNextSaveRetryMs = 0;

        DirectGate_TestRetryPendingSave(&fix.conn);
        CHECK(fix.cfg.bSavePending, "a save that still cannot be written stays pending");
        CHECK(fix.conn.nNextSaveRetryMs > XTime_GetMonoMs(), "the next attempt is spaced out");
        CHECK(fix.conn.nNextSaveRetryMs < XTime_GetMonoMs() + DIRECTGATE_TEST_HOUR_MS, "the save retry is on the monotonic clock");

        uint64_t nScheduled = fix.conn.nNextSaveRetryMs;
        DirectGate_TestRetryPendingSave(&fix.conn);
        CHECK(fix.conn.nNextSaveRetryMs == nScheduled, "no attempt is made before the retry is due");

        xstrncpy(fix.cfg.sCfgPath, sizeof(fix.cfg.sCfgPath), sCfgPath);
        fix.conn.nNextSaveRetryMs = 0;
        DirectGate_TestRetryPendingSave(&fix.conn);
        CHECK(!fix.cfg.bSavePending, "a save that can be written clears the pending flag");
        CHECK(path_exists(sCfgPath), "the pending tokens reach the disk");
        unlink(sCfgPath);
    }

    /* ---- handshake refresh never disconnects its own socket ----------------------------------------- */

    /* The pre-role refresh runs inside the upgrade callback of the relay session. Disconnecting that session
       from there freed it under libxutils, which went on to queue the request into it. */
    {
        xapi_t api;
        XAPI_Init(&api, NULL, NULL);

        int nPair[2];
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, nPair) == 0, "a socket pair for the relay stand-in");

        xapi_endpoint_t endpt;
        XAPI_InitEndpoint(&endpt);
        endpt.eType = XAPI_EVENT;
        endpt.eRole = XAPI_CUSTOM;
        endpt.nEvents = XPOLLIN;
        endpt.bUnix = XTRUE;
        endpt.nFD = nPair[0];
        CHECK(XAPI_AddEndpoint(&api, &endpt) >= 0, "the relay stand-in registers");
        CHECK(XAPI_GetEventCount(&api) == 1, "one registered event");

        xevent_data_t *pEvData = XEvents_GetData(&api.events, nPair[0]);
        CHECK(pEvData != NULL && pEvData->pContext != NULL, "the registered session can be found");
        xapi_session_t *pRelay = (xapi_session_t*)pEvData->pContext;

        xhttp_t request;
        XHTTP_InitRequest(&request, XHTTP_GET, "/websock", NULL);

        pRelay->eRole = XAPI_CLIENT;
        pRelay->pSessionData = &fix.conn;
        pRelay->pPacket = &request;
        fix.conn.pWsSession = pRelay;

        xstrncpy(fix.cfg.sRoutingKey, sizeof(fix.cfg.sRoutingKey), "rk-life");
        fix.cfg.enroll.nAccessTokenExp = (uint64_t)time(NULL) - 10U;
        fix.conn.sDisconnectReason[0] = XSTR_NUL;

        xapi_ctx_t ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.eCbType = XAPI_CB_HANDSHAKE_REQUEST;
        ctx.pApi = &api;

        CHECK(DirectGate_ServiceCallback(&ctx, pRelay) == XAPI_DISCONNECT,
            "an expired token with the API unreachable refuses the handshake");
        CHECK(XAPI_GetEventCount(&api) == 1, "the refusal must leave the socket to the event loop");
        CHECK(xstrused(fix.conn.sDisconnectReason), "the refusal still records why the link is going down");

        pRelay->pPacket = NULL;
        XHTTP_Clear(&request);
        fix.conn.pWsSession = &fix.api;
        XAPI_Destroy(&api);
        close(nPair[1]);
    }

    /* ---- copy and delete run off the event loop ----------------------------------------------------- */

    /* A large tree used to be copied or deleted inside the handler, holding the event loop - and every other
       session on it - until the disk was done. The answer now arrives from the worker via the event loop. */
    {
        char sSrc[600], sDst[600], sNested[700], sFile[800];
        snprintf(sSrc, sizeof(sSrc), "%s/tree", sRoot);
        snprintf(sDst, sizeof(sDst), "%s/tree-copy", sRoot);
        snprintf(sNested, sizeof(sNested), "%s/nested", sSrc);
        CHECK(mkdir(sSrc, 0755) == 0 && mkdir(sNested, 0755) == 0, "a source tree for the copy");

        for (int i = 0; i < 20; i++)
        {
            snprintf(sFile, sizeof(sFile), "%s/file-%02d", sNested, i);
            FILE *pFile = fopen(sFile, "wb");
            CHECK(pFile != NULL, "a file in the source tree");
            fputs("payload", pFile);
            fclose(pFile);
        }

        xapi_t api;
        XAPI_Init(&api, DirectGate_ServiceCallback, &fix.conn);
        CHECK(XAPI_GetOrCreateEvents(&api) != NULL, "an event loop for the file operations");
        fix.api.pApi = &api;

        directgate_session_t *pSession = new_session(&fix, 61, XTRUE);
        CHECK(pSession != NULL, "a file manager session");
        CHECK(seal_session(&fix, pSession), "the file manager session gets its E2E keys");
        pSession->eActiveMode = DIRECTGATE_SESSION_MODE_FILE_MANAGER;

        xjson_obj_t *pCopy = manager_header("copy", sSrc, 61);
        CHECK(pCopy != NULL, "build a copy request");
        XJSON_AddString(pCopy, "targetPath", sDst);
        CHECK(deliver(&fix, pCopy, &fix.peer, NULL, 0) == XAPI_CONTINUE, "a copy request is accepted");
        CHECK(pSession->pFileOp != NULL, "the copy runs on its own worker");

        char sAction[256], sStatus[256], sPath[1024];
        CHECK(service_until_reply(&fix, &api), "the copy answers through the event loop");
        CHECK(take_manager_reply(&fix, sAction, sStatus, sPath, sizeof(sAction)), "the copy answer can be read");
        CHECK(!strcmp(sAction, "copy") && !strcmp(sStatus, "ok") && !strcmp(sPath, sDst),
            "the copy reports success with the path it created");

        snprintf(sFile, sizeof(sFile), "%s/nested/file-19", sDst);
        CHECK(path_exists(sFile), "the copied tree is complete");

        for (int i = 0; i < 50 && pSession->pFileOp != NULL; i++) XAPI_Service(&api, 10);
        CHECK(pSession->pFileOp == NULL && pSession->pFileOpSession == NULL, "a finished operation lets go of its endpoint");

        xjson_obj_t *pDelete = manager_header("delete", sDst, 61);
        CHECK(pDelete != NULL, "build a delete request");
        XJSON_AddBool(pDelete, "force", XTRUE);
        CHECK(deliver(&fix, pDelete, &fix.peer, NULL, 0) == XAPI_CONTINUE, "a delete request is accepted");
        CHECK(service_until_reply(&fix, &api), "the delete answers through the event loop");
        CHECK(take_manager_reply(&fix, sAction, sStatus, sPath, sizeof(sAction)), "the delete answer can be read");
        CHECK(!strcmp(sAction, "delete") && !strcmp(sStatus, "ok"), "the recursive delete reports success");
        CHECK(!path_exists(sDst), "the tree is gone");

        /* The session going away mid-copy neither waits for the copy nor frees what the worker still uses:
           the copy completes on its own and the worker releases the rest. */
        pCopy = manager_header("copy", sSrc, 61);
        CHECK(pCopy != NULL, "build a copy to abandon");
        XJSON_AddString(pCopy, "targetPath", sDst);
        CHECK(deliver(&fix, pCopy, &fix.peer, NULL, 0) == XAPI_CONTINUE, "the copy to abandon is accepted");
        DirectGate_SessionMgr_Remove(&fix.conn.mgr, pSession);

        snprintf(sFile, sizeof(sFile), "%s/nested/file-19", sDst);
        for (int i = 0; i < 500 && !path_exists(sFile); i++) usleep(10000);
        CHECK(path_exists(sFile), "an abandoned copy still completes");
        usleep(100000);

        XAPI_Destroy(&api);
        fix.api.pApi = NULL;
        drain(&fix);

        DirectGate_Files_Delete(sDst, XTRUE);
        DirectGate_Files_Delete(sSrc, XTRUE);
    }

    /* ---- stopping a running terminal ---------------------------------------------------------------- */

    /* cmd stop closes the PTY endpoint, whose close callback ends the whole session before the stop returns.
       The handler used to write the session's mode fields afterwards - into freed memory, at the offset
       where the allocator keeps its free-list pointer. */
    {
        struct passwd *pSelf = getpwuid(getuid());
        CHECK(pSelf != NULL && xstrused(pSelf->pw_name), "the current account can be resolved");

        xapi_t api;
        XAPI_Init(&api, DirectGate_ServiceCallback, &fix.conn);
        fix.api.pApi = &api;

        directgate_session_t *pSession = new_session(&fix, 51, XTRUE);
        CHECK(pSession != NULL, "a session for the terminal");
        CHECK(seal_session(&fix, pSession), "the terminal session gets its E2E keys");
        xstrncpy(pSession->term.sShellUser, sizeof(pSession->term.sShellUser), pSelf->pw_name);
        xstrncpy(pSession->term.sShellHome, sizeof(pSession->term.sShellHome), sRoot);

        CHECK(DirectGate_Session_StartMode(pSession, DIRECTGATE_SESSION_MODE_TERMINAL) == XAPI_CONTINUE,
            "a real shell starts behind a registered PTY endpoint");
        CHECK(pSession->eActiveMode == DIRECTGATE_SESSION_MODE_TERMINAL, "the session is in terminal mode");
        CHECK(pSession->term.pPTYSession != NULL, "the PTY endpoint is attached");
        drain(&fix);

        /* Shell output is not read while the link is this far behind; reading used to go on until the PTY ran
           dry, which a fast-printing command never lets happen, so the send queue grew until the agent died. */
        size_t nBacklog = 5U * 1024U * 1024U;
        uint8_t *pBacklog = (uint8_t*)calloc(1, nBacklog);
        CHECK(pBacklog != NULL, "allocate a stand-in transport backlog");
        CHECK(XByteBuffer_Add(&fix.api.txBuffer, pBacklog, nBacklog) > 0, "back the relay link up");
        free(pBacklog);

        CHECK(DirectGate_Term_OnRead(&pSession->term) == XAPI_CONTINUE, "a backed-up link is not an error");
        CHECK(fix.api.txBuffer.nUsed == nBacklog, "no shell output is queued behind a backed-up link");
        CHECK(DirectGate_Term_IsReadPaused(&pSession->term), "reading shell output pauses");
        CHECK(!(pSession->term.pPTYSession->nEvents & XPOLLIN), "the PTY stops being polled for output");

        DirectGate_Term_ResumeRead(&pSession->term);
        CHECK(DirectGate_Term_IsReadPaused(&pSession->term), "reading stays paused until the link drains");

        drain(&fix);
        DirectGate_Term_ResumeRead(&pSession->term);
        CHECK(!DirectGate_Term_IsReadPaused(&pSession->term), "a drained link resumes reading");
        CHECK(pSession->term.pPTYSession->nEvents & XPOLLIN, "the PTY is polled for output again");

        /* Input the shell never reads is capped instead of growing without bound. */
        size_t nFlood = 9U * 1024U * 1024U;
        uint8_t *pFlood = (uint8_t*)malloc(nFlood);
        CHECK(pFlood != NULL, "allocate an oversized paste");
        memset(pFlood, 'a', nFlood);
        CHECK(DirectGate_Term_Write(&pSession->term, pFlood, nFlood) == XSTDERR,
            "input beyond the backlog limit is refused");
        free(pFlood);
        CHECK(pSession->term.txBuffer.nUsed == 0, "a refused paste queues nothing");

        CHECK(deliver(&fix, DirectGate_Proto_BuildCmd("stop", NULL, NULL, NULL, 51), &fix.peer, NULL, 0)
            == XAPI_CONTINUE, "stopping a running terminal is not fatal");
        CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 51) == NULL, "stopping the terminal ends the session");

        XAPI_Destroy(&api);
        fix.api.pApi = NULL;
        drain(&fix);
    }

    DirectGate_SessionMgr_Destroy(&fix.conn.mgr);
    XByteBuffer_Clear(&fix.api.txBuffer);
    rmdir(sRoot);

    puts("session_lifetime_smoke: OK");
    return 0;
}
