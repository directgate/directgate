/*
 * Non-interactive commands ("exec" sessions) across the dispatch layer.
 *
 * A client asks for exec mode, then for one command; the agent runs it as the shell user, streams stdout and
 * stderr as separate encrypted messages, takes input when asked to, and reports the exit - code, signal,
 * timeout - before the session ends. Every message here goes through DirectGate_TestHandleTransportMessage
 * sealed with the browser half of the E2E context, and every answer is read back off the relay socket's send
 * buffer and opened with it, so the assertions are about what actually crossed the wire.
 *
 * The program runs behind real event-loop endpoints: each case turns a real xapi_t until the exit arrives.
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "src/agent/directgate.h"
#include "src/agent/command.h"
#include "webrtc_teardown.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "session_exec_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

int DirectGate_ServiceCallback(xapi_ctx_t *pCtx, xapi_session_t *pApiSession);
size_t DirectGate_Term_ReapPending(void);

/* Not in api.h: creates the event loop without registering anything on it. */
xevents_t* XAPI_GetOrCreateEvents(xapi_t *pApi);

typedef struct {
    directgate_cfg_t cfg;
    directgate_conn_t conn;
    xapi_session_t api;
    directgate_e2e_t peer;
} fixture_t;

/* What came back for one session, gathered across however many frames the agent queued. */
typedef struct {
    xbyte_buffer_t out;
    xbyte_buffer_t err;
    char sStarted[64];
    char sStartReason[256];
    char sSignal[16];
    char sError[256];
    int nPid;
    int nExitCode;
    xbool_t bExit;
    xbool_t bTimedOut;
    xbool_t bTruncated;
    xbool_t bClosed;
    xbool_t bPlainExec;
    xbool_t bCapability;
    xbool_t bRemoteMode;            /* auth/result offers "remote" sessions */
    xbool_t bListed;                /* a manager/list answer came */
    xbool_t bUnavailable;           /* webrtc/unavailable: the agent cannot set WebRTC up */
    int nRelayExec;                 /* exec messages that came on the relay */
    int nChannelExec;               /* ... and over the data channel */
} replies_t;

/* The client's half of a data channel, when a case has one: what the agent signals goes to it */
static directgate_webrtc_t *g_pPeer;

static void replies_init(replies_t *pReplies)
{
    memset(pReplies, 0, sizeof(*pReplies));
    XByteBuffer_Init(&pReplies->out, XSTDNON, XFALSE);
    XByteBuffer_Init(&pReplies->err, XSTDNON, XFALSE);
    pReplies->nExitCode = -1000;
}

static void replies_clear(replies_t *pReplies)
{
    XByteBuffer_Clear(&pReplies->out);
    XByteBuffer_Clear(&pReplies->err);
    replies_init(pReplies);
}

static void copy_str(char *pDst, size_t nSize, xjson_obj_t *pRoot, const char *pName)
{
    const char *pValue = XJSON_GetString(XJSON_GetObject(pRoot, pName));
    xstrncpy(pDst, nSize, pValue != NULL ? pValue : "");
}

/* Reads one inner package (already opened) into the replies. */
static void note_package(replies_t *pReplies, directgate_pkg_t *pPkg)
{
    xjson_obj_t *pRoot = pPkg->jsonHeader.pRootObj;
    const char *pType = pPkg->header.pType;

    if (xstrcmp(pType, "status"))
    {
        const char *pStatus = XJSON_GetString(XJSON_GetObject(pRoot, "status"));
        if (xstrcmp(pStatus, "closed")) pReplies->bClosed = XTRUE;
        return;
    }

    if (xstrcmp(pType, "error"))
    {
        copy_str(pReplies->sError, sizeof(pReplies->sError), pRoot, "reason");
        return;
    }

    if (xstrcmp(pType, "auth"))
    {
        pReplies->bCapability = XJSON_GetBool(XJSON_GetObject(pRoot, "exec"));
        pReplies->bRemoteMode = XJSON_GetBool(XJSON_GetObject(pRoot, "remote"));
        return;
    }

    if (xstrcmp(pType, "manager"))
    {
        if (xstrcmp(XJSON_GetString(XJSON_GetObject(pRoot, "action")), "list") &&
            xstrcmp(XJSON_GetString(XJSON_GetObject(pRoot, "status")), "ok")) pReplies->bListed = XTRUE;
        return;
    }

    if (xstrcmp(pType, "webrtc"))
    {
        const char *pAction = XJSON_GetString(XJSON_GetObject(pRoot, "action"));
        if (xstrcmp(pAction, "unavailable")) pReplies->bUnavailable = XTRUE;
        else if (g_pPeer != NULL && xstrcmp(pAction, "answer"))
            DirectGate_WebRTC_HandleAnswer(g_pPeer, XJSON_GetString(XJSON_GetObject(pRoot, "sdp")));
        else if (g_pPeer != NULL && xstrcmp(pAction, "ice"))
            DirectGate_WebRTC_HandleIceCandidate(g_pPeer, XJSON_GetString(XJSON_GetObject(pRoot, "candidate")),
                XJSON_GetString(XJSON_GetObject(pRoot, "sdpMid")), 0);
        return;
    }

    if (!xstrcmp(pType, "exec")) return;
    const directgate_pkg_exec_t *pExec = (const directgate_pkg_exec_t*)pPkg->pPackage;

    if (xstrcmp(pExec->pAction, "started"))
    {
        copy_str(pReplies->sStarted, sizeof(pReplies->sStarted), pRoot, "status");
        copy_str(pReplies->sStartReason, sizeof(pReplies->sStartReason), pRoot, "reason");
        pReplies->nPid = XJSON_GetInt(XJSON_GetObject(pRoot, "pid"));
    }
    else if (xstrcmp(pExec->pAction, "output"))
    {
        xbyte_buffer_t *pBuffer = xstrcmp(pExec->pStream, "stderr") ? &pReplies->err : &pReplies->out;
        if (pExec->data.nPayloadLength) XByteBuffer_Add(pBuffer, pExec->data.pPayload, pExec->data.nPayloadLength);
    }
    else if (xstrcmp(pExec->pAction, "exit"))
    {
        pReplies->bExit = XTRUE;
        pReplies->nExitCode = pExec->nExitCode;
        pReplies->bTimedOut = pExec->bTimedOut;
        pReplies->bTruncated = pExec->bTruncated;
        xstrncpy(pReplies->sSignal, sizeof(pReplies->sSignal), xstrused(pExec->pSignal) ? pExec->pSignal : "");
    }
}

/* Parses every frame the agent queued on the relay socket, opening the encrypted ones, and empties the queue. */
static void collect(fixture_t *pFix, replies_t *pReplies)
{
    size_t nOffset = 0;
    xbyte_buffer_t *pTx = &pFix->api.txBuffer;

    while (nOffset < pTx->nUsed)
    {
        xws_frame_t frame;
        if (XWebFrame_ParseData(&frame, pTx->pData + nOffset, pTx->nUsed - nOffset) != XWS_FRAME_COMPLETE)
        {
            XWebFrame_Clear(&frame);
            break;
        }

        size_t nFrame = XWebFrame_GetFrameLength(&frame);
        xbyte_buffer_t outer, inner;
        XByteBuffer_Init(&outer, XSTDNON, XFALSE);
        XByteBuffer_Init(&inner, XSTDNON, XFALSE);
        XByteBuffer_Add(&outer, XWebFrame_GetPayload(&frame), XWebFrame_GetPayloadLength(&frame));
        XWebFrame_Clear(&frame);

        directgate_pkg_t pkg;
        if (DirectGate_Package_Parse(&pkg, outer.pData, outer.nUsed))
        {
            if (pkg.header.eType == DIRECTGATE_PKG_ENCRYPTED)
            {
                directgate_pkg_t innerPkg;
                if (DirectGate_Proto_DecryptPackage(&inner, &pkg, &pFix->peer) &&
                    DirectGate_Package_Parse(&innerPkg, inner.pData, inner.nUsed))
                {
                    if (innerPkg.header.eType == DIRECTGATE_PKG_EXEC) pReplies->nRelayExec++;
                    note_package(pReplies, &innerPkg);
                    DirectGate_Package_Clear(&innerPkg);
                }
            }
            else
            {
                if (pkg.header.eType == DIRECTGATE_PKG_EXEC) pReplies->bPlainExec = XTRUE;
                note_package(pReplies, &pkg);
            }

            DirectGate_Package_Clear(&pkg);
        }

        XByteBuffer_Clear(&outer);
        XByteBuffer_Clear(&inner);
        if (!nFrame) break;
        nOffset += nFrame;
    }

    XByteBuffer_Clear(pTx);
    XByteBuffer_Init(pTx, XSTDNON, XFALSE);
}

/* What arrived over the client's data channel, read like relay traffic */
static fixture_t *g_pPeerFix;
static replies_t *g_pPeerReplies;

static void peer_data(const uint8_t *pData, size_t nLen, void *pCtx)
{
    (void)pCtx;
    directgate_pkg_t pkg;
    if (g_pPeerFix == NULL || g_pPeerReplies == NULL || !DirectGate_Package_Parse(&pkg, pData, nLen)) return;

    xbyte_buffer_t inner;
    XByteBuffer_Init(&inner, XSTDNON, XFALSE);
    directgate_pkg_t innerPkg;

    if (pkg.header.eType == DIRECTGATE_PKG_ENCRYPTED && DirectGate_Proto_DecryptPackage(&inner, &pkg, &g_pPeerFix->peer) &&
        DirectGate_Package_Parse(&innerPkg, inner.pData, inner.nUsed))
    {
        if (innerPkg.header.eType == DIRECTGATE_PKG_EXEC) g_pPeerReplies->nChannelExec++;
        note_package(g_pPeerReplies, &innerPkg);
        DirectGate_Package_Clear(&innerPkg);
    }

    XByteBuffer_Clear(&inner);
    DirectGate_Package_Clear(&pkg);
}

static int seal(fixture_t *pFix, xbyte_buffer_t *pPacket, xjson_obj_t *pHeader, const uint8_t *pPayload, size_t nPayload)
{
    uint32_t nSessionId = XJSON_GetU32(XJSON_GetObject(pHeader, "sessionId"));
    DirectGate_Proto_AddCC(pHeader, &pFix->peer, 0);
    return DirectGate_Proto_Build(pPacket, pHeader, pPayload, nPayload, XFALSE) &&
        DirectGate_Proto_EncryptPackage(pPacket, &pFix->peer, nSessionId);
}

/* The client's signalling, to the agent over the relay: what the WebRTC code produced, rebuilt as a sealed message */
static void peer_signal(const char *pJson, size_t nLen, void *pCtx);

static int deliver(fixture_t *pFix, xjson_obj_t *pHeader, xbool_t bSeal, const uint8_t *pPayload, size_t nPayload)
{
    xbyte_buffer_t packet;
    XByteBuffer_Init(&packet, XSTDNON, XFALSE);
    if (pHeader == NULL) return XSTDERR;

    uint32_t nSessionId = XJSON_GetU32(XJSON_GetObject(pHeader, "sessionId"));
    if (bSeal) DirectGate_Proto_AddCC(pHeader, &pFix->peer, 0);

    int nStatus = XSTDERR;
    if (DirectGate_Proto_Build(&packet, pHeader, pPayload, nPayload, XFALSE) &&
        (!bSeal || DirectGate_Proto_EncryptPackage(&packet, &pFix->peer, nSessionId)))
        nStatus = DirectGate_TestHandleTransportMessage(&pFix->api, packet.pData, packet.nUsed);

    XJSON_FreeObject(pHeader);
    XByteBuffer_Clear(&packet);
    return nStatus;
}

static int seal_session(fixture_t *pFix, directgate_session_t *pSession)
{
    uint8_t sKey[32], sAgentNonce[DIRECTGATE_SRP_NONCE_SIZE], sClientNonce[DIRECTGATE_SRP_NONCE_SIZE];
    for (size_t i = 0; i < sizeof(sKey); i++) sKey[i] = (uint8_t)(i + 11);
    for (size_t i = 0; i < sizeof(sAgentNonce); i++) sAgentNonce[i] = (uint8_t)(0x21 + i);
    for (size_t i = 0; i < sizeof(sClientNonce); i++) sClientNonce[i] = (uint8_t)(0x61 + i);

    DirectGate_E2E_Init(&pFix->peer);
    return DirectGate_E2E_DeriveFromSRP(&pSession->e2e, sKey, sizeof(sKey), sAgentNonce, sClientNonce,
               DIRECTGATE_SRP_NONCE_SIZE, "dev-exec", XTRUE) &&
           DirectGate_E2E_DeriveFromSRP(&pFix->peer, sKey, sizeof(sKey), sAgentNonce, sClientNonce,
               DIRECTGATE_SRP_NONCE_SIZE, "dev-exec", XFALSE);
}

/* An authenticated, sealed session already in exec mode. */
static directgate_session_t* exec_session(fixture_t *pFix, uint32_t nSessionId, const char *pHome)
{
    directgate_session_t *pSession = DirectGate_SessionMgr_Create(&pFix->conn.mgr, nSessionId);
    if (pSession == NULL) return NULL;

    pSession->pWsSession = &pFix->api;
    pSession->bAuthenticated = XTRUE;
    xstrncpy(pSession->term.sShellHome, sizeof(pSession->term.sShellHome), pHome);
    if (!seal_session(pFix, pSession)) return NULL;

    if (deliver(pFix, DirectGate_Proto_BuildCmd("start", NULL, NULL, "exec", nSessionId), XTRUE, NULL, 0) != XAPI_CONTINUE)
        return NULL;

    /* No data channel in this harness: as a client whose ICE failed, it says so, and the relay carries the output */
    if (deliver(pFix, DirectGate_Proto_BuildWebRTC("unavailable", nSessionId), XTRUE, NULL, 0) != XAPI_CONTINUE)
        return NULL;

    return pSession->eActiveMode == DIRECTGATE_SESSION_MODE_EXEC ? pSession : NULL;
}

static xjson_obj_t* exec_start(uint32_t nSessionId, const char *pCommand, const char *pCwd, uint32_t nTimeoutMs, xbool_t bStdin)
{
    xjson_obj_t *pHeader = DirectGate_Proto_BuildExec("start", NULL, NULL, nSessionId);
    if (pHeader == NULL) return NULL;

    XJSON_AddString(pHeader, "command", pCommand);
    if (pCwd != NULL) XJSON_AddString(pHeader, "cwd", pCwd);
    if (nTimeoutMs) XJSON_AddU32(pHeader, "timeoutMs", nTimeoutMs);
    if (bStdin) XJSON_AddBool(pHeader, "stdin", XTRUE);
    return pHeader;
}

/* Whether this system hands out pidfds at all: a kernel before 5.3, or a Valgrind before 3.21, answers ENOSYS. */
static int have_pidfd(void)
{
#if defined(__linux__) && defined(SYS_pidfd_open)
    long nFd = syscall(SYS_pidfd_open, getpid(), 0U);
    if (nFd < 0) return 0;
    close((int)nFd);
    return 1;
#else
    return 0;
#endif
}

static xjson_obj_t* exec_start_max(uint32_t nSessionId, const char *pCommand, uint32_t nOutputMax)
{
    xjson_obj_t *pHeader = exec_start(nSessionId, pCommand, NULL, 0, XFALSE);
    if (pHeader != NULL) XJSON_AddU32(pHeader, "outputMax", nOutputMax);
    return pHeader;
}

static void peer_signal(const char *pJson, size_t nLen, void *pCtx)
{
    uint32_t nSessionId = *(const uint32_t*)pCtx;
    xjson_t json;
    if (g_pPeerFix == NULL || !XJSON_Parse(&json, NULL, pJson, nLen)) return;

    xjson_obj_t *pRoot = json.pRootObj;
    xjson_obj_t *pHeader = DirectGate_Proto_BuildWebRTC(XJSON_GetString(XJSON_GetObject(pRoot, "action")), nSessionId);
    const char *aFields[] = { "sdp", "candidate", "sdpMid" };

    for (size_t i = 0; pHeader != NULL && i < sizeof(aFields) / sizeof(aFields[0]); i++)
    {
        xjson_obj_t *pField = XJSON_GetObject(pRoot, aFields[i]);
        if (pField != NULL) XJSON_AddString(pHeader, aFields[i], XJSON_GetString(pField));
    }

    if (pHeader != NULL) deliver(g_pPeerFix, pHeader, XTRUE, NULL, 0);
    XJSON_Destroy(&json);
}

/* Turns the event loop, gathering replies, until the exit arrives or nMs pass. */
static int run_until_exit(fixture_t *pFix, xapi_t *pApi, replies_t *pReplies, int nMs)
{
    uint64_t nDeadline = XTime_GetMonoMs() + (uint64_t)nMs;

    while (!pReplies->bExit && XTime_GetMonoMs() < nDeadline)
    {
        XAPI_Service(pApi, 10);
        collect(pFix, pReplies);
    }

    return pReplies->bExit;
}

static int output_is(const xbyte_buffer_t *pBuffer, const char *pExpected)
{
    size_t nLen = strlen(pExpected);
    return pBuffer->nUsed == nLen && (nLen == 0 || memcmp(pBuffer->pData, pExpected, nLen) == 0);
}

static int output_has(const xbyte_buffer_t *pBuffer, const char *pNeedle)
{
    size_t nLen = strlen(pNeedle);
    for (size_t i = 0; pBuffer->nUsed >= nLen && i + nLen <= pBuffer->nUsed; i++)
        if (!memcmp(pBuffer->pData + i, pNeedle, nLen)) return 1;
    return 0;
}

int main(void)
{
    /* The children's output goes through pipes, not through this process's stdio */
    signal(SIGPIPE, SIG_IGN);

    char sRoot[] = "/tmp/directgate_session_exec.XXXXXX";
    CHECK(mkdtemp(sRoot) != NULL, "a scratch directory can be created");

    char sReal[PATH_MAX];
    CHECK(realpath(sRoot, sReal) != NULL, "the scratch directory resolves");

    fixture_t fix;
    memset(&fix, 0, sizeof(fix));
    xstrncpy(fix.cfg.auth.sSaltHex, sizeof(fix.cfg.auth.sSaltHex),
        "0000000000000000000000000000000000000000000000000000000000000000");
    xstrncpy(fix.cfg.auth.sVerifierHex, sizeof(fix.cfg.auth.sVerifierHex), "configured");
    xstrncpy(fix.cfg.sDeviceId, sizeof(fix.cfg.sDeviceId), "dev-exec");
    fix.cfg.nKAInterval = 25;

    fix.conn.pCfg = &fix.cfg;
    DirectGate_SessionMgr_Init(&fix.conn.mgr, &fix.cfg);

    fix.api.pSessionData = &fix.conn;
    fix.api.sock.nFD = XSOCK_INVALID;
    fix.api.eRole = XAPI_CLIENT;
    fix.api.nEvents = XPOLLOUT;
    XByteBuffer_Init(&fix.api.txBuffer, XSTDNON, XFALSE);
    fix.conn.pWsSession = &fix.api;

    xapi_t api;
    XAPI_Init(&api, DirectGate_ServiceCallback, &fix.conn);
    CHECK(XAPI_GetOrCreateEvents(&api) != NULL, "an event loop for the commands");
    fix.api.pApi = &api;

    replies_t replies;
    replies_init(&replies);

    /* ---- the capability is advertised where commands can run, and only there ----------------------------- */
    {
        directgate_session_t *pSession = DirectGate_SessionMgr_Create(&fix.conn.mgr, 10);
        CHECK(pSession != NULL, "a session to answer authentication on");
        pSession->pWsSession = &fix.api;

        CHECK(DirectGate_Session_SendAuthResp(pSession, "ok", "00", NULL) >= 0, "an auth result is sent");
        collect(&fix, &replies);
        CHECK(replies.bCapability, "a successful auth result tells the client the agent runs commands");
        CHECK(replies.bRemoteMode, "and that it keeps remote sessions");
        replies_clear(&replies);

        CHECK(DirectGate_Session_SendAuthResp(pSession, "failed", NULL, "bad proof") >= 0, "a failed auth result is sent");
        collect(&fix, &replies);
        CHECK(!replies.bCapability, "a failed auth result offers nothing");
        replies_clear(&replies);

        pSession->bDesktopShare = XTRUE;
        CHECK(DirectGate_Session_SendAuthResp(pSession, "ok", "00", NULL) >= 0, "a share's auth result is sent");
        collect(&fix, &replies);
        CHECK(!replies.bCapability && !replies.bRemoteMode, "a temporary desktop share is never offered commands");
        replies_clear(&replies);

        pSession->bDesktopShare = XFALSE;
        DirectGate_Session_SetPreLogon(XTRUE);
        CHECK(DirectGate_Session_SendAuthResp(pSession, "ok", "00", NULL) >= 0, "a pre-logon auth result is sent");
        DirectGate_Session_SetPreLogon(XFALSE);
        collect(&fix, &replies);
        CHECK(!replies.bCapability && !replies.bRemoteMode, "an agent with nobody logged on offers no commands");
        replies_clear(&replies);

        DirectGate_SessionMgr_Remove(&fix.conn.mgr, pSession);
        collect(&fix, &replies);
        replies_clear(&replies);
    }

    /* ---- the gates in front of a command ------------------------------------------------------------------ */
    {
        directgate_session_t *pSession = DirectGate_SessionMgr_Create(&fix.conn.mgr, 11);
        CHECK(pSession != NULL, "a session for the gates");
        pSession->pWsSession = &fix.api;
        pSession->bAuthenticated = XTRUE;
        CHECK(seal_session(&fix, pSession), "the session gets its E2E keys");

        /* Not in exec mode yet: refused, nothing runs */
        CHECK(deliver(&fix, exec_start(11, "touch should-not-exist", sRoot, 0, XFALSE), XTRUE, NULL, 0) == XAPI_CONTINUE,
            "a command before exec mode is not fatal to the connection");
        collect(&fix, &replies);
        CHECK(!strcmp(replies.sError, "exec mode is not active"), "a command before exec mode is refused");
        CHECK(pSession->command.eState == DIRECTGATE_COMMAND_IDLE, "nothing ran outside exec mode");
        replies_clear(&replies);

        CHECK(deliver(&fix, DirectGate_Proto_BuildCmd("start", NULL, NULL, "exec", 11), XTRUE, NULL, 0) == XAPI_CONTINUE,
            "exec mode can be requested");
        CHECK(pSession->eActiveMode == DIRECTGATE_SESSION_MODE_EXEC, "the session is in exec mode");

        /* In the clear on an authenticated session: never dispatched */
        CHECK(deliver(&fix, exec_start(11, "touch should-not-exist", sRoot, 0, XFALSE), XFALSE, NULL, 0) >= XAPI_DISCONNECT,
            "a plaintext command is handled");
        collect(&fix, &replies);
        pSession = DirectGate_SessionMgr_Find(&fix.conn.mgr, 11);
        CHECK(pSession == NULL || pSession->command.eState == DIRECTGATE_COMMAND_IDLE,
            "a plaintext command after authentication never runs");

        char sPlanted[1200];
        snprintf(sPlanted, sizeof(sPlanted), "%s/should-not-exist", sRoot);
        struct stat st;
        CHECK(stat(sPlanted, &st) != 0, "neither refused command touched the disk");
        replies_clear(&replies);

        if (pSession != NULL)
        {
            /* Empty and oversized command lines are refused without ending the session */
            CHECK(deliver(&fix, exec_start(11, "", NULL, 0, XFALSE), XTRUE, NULL, 0) == XAPI_CONTINUE,
                "an empty command is handled");
            collect(&fix, &replies);
            CHECK(!strcmp(replies.sStarted, "failed") && !strcmp(replies.sStartReason, "command is required"),
                "an empty command is refused");
            replies_clear(&replies);

            size_t nLong = DIRECTGATE_COMMAND_MAX_BYTES + 1;
            char *pLong = (char*)malloc(nLong + 1);
            CHECK(pLong != NULL, "an oversized command line");
            memset(pLong, 'x', nLong);
            pLong[nLong] = '\0';
            CHECK(deliver(&fix, exec_start(11, pLong, NULL, 0, XFALSE), XTRUE, NULL, 0) == XAPI_CONTINUE,
                "an oversized command is handled");
            free(pLong);
            collect(&fix, &replies);
            CHECK(!strcmp(replies.sStarted, "failed") && !strcmp(replies.sStartReason, "command is too long"),
                "a command line over the limit is refused");
            CHECK(pSession->command.eState == DIRECTGATE_COMMAND_IDLE, "a refused command leaves the session ready");
            replies_clear(&replies);

            xjson_obj_t *pUnknown = DirectGate_Proto_BuildExec("rewind", NULL, NULL, 11);
            CHECK(deliver(&fix, pUnknown, XTRUE, NULL, 0) == XAPI_CONTINUE, "an unknown action is handled");
            collect(&fix, &replies);
            CHECK(!strcmp(replies.sError, "unknown exec action"), "an unknown action is refused");
            replies_clear(&replies);

            DirectGate_SessionMgr_Remove(&fix.conn.mgr, pSession);
            collect(&fix, &replies);
            replies_clear(&replies);
        }
    }

    /* ---- what may never run a command: a relative directory, a temporary share, a pre-logon agent ---------- */
    {
        directgate_session_t *pSession = exec_session(&fix, 12, sRoot);
        CHECK(pSession != NULL, "an exec session for a relative directory");

        char sPlanted[1200];
        snprintf(sPlanted, sizeof(sPlanted), "%s/relative-ran", sRoot);
        CHECK(deliver(&fix, exec_start(12, "touch relative-ran", "tmp", 0, XFALSE), XTRUE, NULL, 0) == XAPI_CONTINUE,
            "a command with a relative directory is handled");
        collect(&fix, &replies);
        CHECK(!strcmp(replies.sStarted, "failed") && !strcmp(replies.sStartReason, "working directory must be an absolute path"),
            "a relative working directory is refused");
        CHECK(pSession->command.eState == DIRECTGATE_COMMAND_IDLE, "nothing ran for a relative directory");
        DirectGate_SessionMgr_Remove(&fix.conn.mgr, pSession);
        collect(&fix, &replies);
        replies_clear(&replies);

        /* A temporary desktop share: exec mode and exec messages are both refused, and the guest is let go */
        pSession = DirectGate_SessionMgr_Create(&fix.conn.mgr, 13);
        CHECK(pSession != NULL, "a temporary share's session");
        pSession->pWsSession = &fix.api;
        pSession->bAuthenticated = XTRUE;
        pSession->bDesktopShare = XTRUE;
        CHECK(seal_session(&fix, pSession), "the share gets its E2E keys");

        CHECK(deliver(&fix, DirectGate_Proto_BuildCmd("start", NULL, NULL, "exec", 13), XTRUE, NULL, 0) == XAPI_CONTINUE,
            "a share asking for exec mode is handled");
        collect(&fix, &replies);
        CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 13) == NULL &&
            !strcmp(replies.sError, "temporary share allows desktop only"),
            "a temporary share asking for exec mode is refused and closed");
        replies_clear(&replies);

        pSession = DirectGate_SessionMgr_Create(&fix.conn.mgr, 15);
        CHECK(pSession != NULL, "a temporary share asking for a remote session");
        pSession->pWsSession = &fix.api;
        pSession->bAuthenticated = XTRUE;
        pSession->bDesktopShare = XTRUE;
        CHECK(seal_session(&fix, pSession), "the share gets its E2E keys");
        CHECK(deliver(&fix, DirectGate_Proto_BuildCmd("start", NULL, NULL, "remote", 15), XTRUE, NULL, 0) == XAPI_CONTINUE,
            "a share asking for a remote session is handled");
        collect(&fix, &replies);
        CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 15) == NULL &&
            !strcmp(replies.sError, "temporary share allows desktop only"),
            "a temporary share asking for a remote session is refused and closed");
        replies_clear(&replies);

        pSession = DirectGate_SessionMgr_Create(&fix.conn.mgr, 14);
        CHECK(pSession != NULL, "a second temporary share");
        pSession->pWsSession = &fix.api;
        pSession->bAuthenticated = XTRUE;
        pSession->bDesktopShare = XTRUE;
        CHECK(seal_session(&fix, pSession), "the second share gets its E2E keys");
        CHECK(deliver(&fix, exec_start(14, "touch share-ran", sRoot, 0, XFALSE), XTRUE, NULL, 0) == XAPI_CONTINUE,
            "a share sending a command is handled");
        collect(&fix, &replies);
        CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 14) == NULL, "a temporary share sending a command is closed");

        char sShareRan[1200];
        snprintf(sShareRan, sizeof(sShareRan), "%s/share-ran", sRoot);
        struct stat st;
        CHECK(stat(sShareRan, &st) != 0 && stat(sPlanted, &st) != 0, "no refused command touched the disk");
        replies_clear(&replies);

        /* Nobody logged on: only a desktop session exists */
        pSession = DirectGate_SessionMgr_Create(&fix.conn.mgr, 15);
        CHECK(pSession != NULL, "a session on a pre-logon agent");
        pSession->pWsSession = &fix.api;
        pSession->bAuthenticated = XTRUE;
        CHECK(seal_session(&fix, pSession), "the pre-logon session gets its E2E keys");

        DirectGate_Session_SetPreLogon(XTRUE);
        int nStatus = deliver(&fix, DirectGate_Proto_BuildCmd("start", NULL, NULL, "exec", 15), XTRUE, NULL, 0);
        DirectGate_Session_SetPreLogon(XFALSE);
        collect(&fix, &replies);
        CHECK(nStatus == XAPI_CONTINUE && pSession->eActiveMode == DIRECTGATE_SESSION_MODE_NONE &&
            strstr(replies.sError, "nobody is logged on") != NULL, "a pre-logon agent refuses exec mode");
        DirectGate_SessionMgr_Remove(&fix.conn.mgr, pSession);
        collect(&fix, &replies);
        replies_clear(&replies);
    }

    /* ---- output, separately per stream, then the exit ----------------------------------------------------- */
    {
        directgate_session_t *pSession = exec_session(&fix, 21, sRoot);
        CHECK(pSession != NULL, "an exec session");

        CHECK(deliver(&fix, exec_start(21, "printf out; printf err >&2; pwd -P >&2; exit 3", NULL, 0, XFALSE), XTRUE, NULL, 0)
            == XAPI_CONTINUE, "a command is accepted");
        collect(&fix, &replies);
        CHECK(!strcmp(replies.sStarted, "ok") && replies.nPid > 0, "the start is confirmed with the program's pid");

        CHECK(run_until_exit(&fix, &api, &replies, 5000), "the exit is reported");
        CHECK(!replies.bPlainExec, "nothing about the command crosses the relay in the clear");
        CHECK(output_is(&replies.out, "out"), "stdout arrives on its own stream");

        char sExpectedErr[PATH_MAX + 16];
        snprintf(sExpectedErr, sizeof(sExpectedErr), "err%s\n", sReal);
        CHECK(output_is(&replies.err, sExpectedErr), "stderr arrives on its own stream, and the default directory is shell.home");
        CHECK(replies.nExitCode == 3 && !replies.sSignal[0] && !replies.bTimedOut, "the exit code is the program's own");

        /* A second command on the same session is refused: one command per session */
        CHECK(deliver(&fix, exec_start(21, "true", NULL, 0, XFALSE), XTRUE, NULL, 0) == XAPI_CONTINUE,
            "a second start is handled");
        collect(&fix, &replies);
        CHECK(!strcmp(replies.sStarted, "failed"), "a second command on one session is refused");

        /* The client normally leaves once it has the exit; one that stays is closed after the linger */
        CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 21) == pSession, "the session waits for its client to leave");
        DirectGate_CMD_Check(pSession, XTime_GetMonoMs() + DIRECTGATE_COMMAND_LINGER_MS + 1);
        collect(&fix, &replies);
        CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 21) == NULL && replies.bClosed,
            "a client that stays is closed after the linger");
        replies_clear(&replies);
    }

    /* ---- input, end of file ------------------------------------------------------------------------------- */
    {
        directgate_session_t *pSession = exec_session(&fix, 22, sRoot);
        CHECK(pSession != NULL, "an exec session for input");

        CHECK(deliver(&fix, exec_start(22, "cat; echo done", NULL, 0, XTRUE), XTRUE, NULL, 0) == XAPI_CONTINUE,
            "a command reading stdin is accepted");

        const char *pText = "hello, program\n";
        CHECK(deliver(&fix, DirectGate_Proto_BuildExec("input", NULL, NULL, 22), XTRUE, (const uint8_t*)pText, strlen(pText))
            == XAPI_CONTINUE, "input is accepted");
        CHECK(deliver(&fix, DirectGate_Proto_BuildExec("eof", NULL, NULL, 22), XTRUE, NULL, 0) == XAPI_CONTINUE,
            "end of input is accepted");

        CHECK(run_until_exit(&fix, &api, &replies, 5000), "the command reading stdin finishes");
        CHECK(output_is(&replies.out, "hello, program\ndone\n"), "the program got the input and then end of file");
        CHECK(replies.nExitCode == 0, "the program exits normally");

        DirectGate_SessionMgr_Remove(&fix.conn.mgr, pSession);
        collect(&fix, &replies);
        replies_clear(&replies);

        /* Started without stdin: the program reads end of file at once and input has nowhere to go */
        pSession = exec_session(&fix, 23, sRoot);
        CHECK(pSession != NULL, "an exec session without stdin");
        CHECK(deliver(&fix, exec_start(23, "cat; echo rc=$?", NULL, 0, XFALSE), XTRUE, NULL, 0) == XAPI_CONTINUE,
            "a command without stdin is accepted");
        CHECK(deliver(&fix, DirectGate_Proto_BuildExec("input", NULL, NULL, 23), XTRUE, (const uint8_t*)"x", 1) == XAPI_CONTINUE,
            "input to a command without stdin is not fatal");
        CHECK(run_until_exit(&fix, &api, &replies, 5000), "the command without stdin finishes");
        CHECK(output_is(&replies.out, "rc=0\n"), "a command without stdin reads end of file, never the agent's stdin");

        DirectGate_SessionMgr_Remove(&fix.conn.mgr, pSession);
        collect(&fix, &replies);
        replies_clear(&replies);
    }

    /* ---- the working directory a client names is the one the command runs in, or none ------------------- */
    {
        char sMissing[1200];
        snprintf(sMissing, sizeof(sMissing), "%s/missing", sRoot);

        directgate_session_t *pSession = exec_session(&fix, 24, sRoot);
        CHECK(pSession != NULL, "an exec session for a missing directory");
        CHECK(deliver(&fix, exec_start(24, "echo ran", sMissing, 0, XFALSE), XTRUE, NULL, 0) == XAPI_CONTINUE,
            "a command in a missing directory is accepted");
        CHECK(run_until_exit(&fix, &api, &replies, 5000), "the command in a missing directory ends");
        CHECK(replies.nExitCode == 127 && output_has(&replies.err, "cannot change to the working directory"),
            "a directory that cannot be entered fails the command");
        CHECK(replies.out.nUsed == 0, "the command never runs somewhere else instead");
        DirectGate_SessionMgr_Remove(&fix.conn.mgr, pSession);
        collect(&fix, &replies);
        replies_clear(&replies);

        /* The default directory, when it cannot be entered, falls back to / as a login does */
        pSession = exec_session(&fix, 25, sMissing);
        CHECK(pSession != NULL, "an exec session whose home is missing");
        CHECK(deliver(&fix, exec_start(25, "pwd -P; echo \"$TERM\"", NULL, 0, XFALSE), XTRUE, NULL, 0) == XAPI_CONTINUE,
            "a command with a missing home is accepted");
        CHECK(run_until_exit(&fix, &api, &replies, 5000), "the command with a missing home ends");
        CHECK(output_has(&replies.out, "/\n") && replies.nExitCode == 0, "a missing default directory falls back to /");
        CHECK(output_is(&replies.out, "/\ndumb\n"), "a command without a terminal is told so by TERM");
        DirectGate_SessionMgr_Remove(&fix.conn.mgr, pSession);
        collect(&fix, &replies);
        replies_clear(&replies);
    }

    /* ---- timeout and signals reach the program's whole group ---------------------------------------------- */
    {
        char sPidFile[1200], sScript[1400];
        snprintf(sPidFile, sizeof(sPidFile), "%s/child.pid", sRoot);
        snprintf(sScript, sizeof(sScript), "sleep 30 & echo $! > %s; wait", sPidFile);

        directgate_session_t *pSession = exec_session(&fix, 31, sRoot);
        CHECK(pSession != NULL, "an exec session for the timeout");

        uint64_t nStart = XTime_GetMonoMs();
        CHECK(deliver(&fix, exec_start(31, sScript, NULL, 300, XFALSE), XTRUE, NULL, 0) == XAPI_CONTINUE,
            "a command with a timeout is accepted");
        CHECK(run_until_exit(&fix, &api, &replies, 5000), "a command that outlives its timeout is ended");
        CHECK(XTime_GetMonoMs() - nStart < 3000, "the timeout is honoured");
        CHECK(replies.bTimedOut && !strcmp(replies.sSignal, "KILL") && replies.nExitCode == 128 + SIGKILL,
            "the exit says the command was killed for its timeout");

        FILE *pFile = fopen(sPidFile, "r");
        CHECK(pFile != NULL, "the background child left its pid");
        int nChild = 0;
        int nRead = fscanf(pFile, "%d", &nChild);
        fclose(pFile);
        unlink(sPidFile);
        CHECK(nRead == 1 && nChild > 0, "the background pid can be read");

        int bGone = 0;
        for (int i = 0; i < 200 && !bGone; i++)
        {
            bGone = kill(nChild, 0) != 0 && errno == ESRCH;
            if (!bGone) usleep(10000);
        }

        CHECK(bGone, "the timeout also ended what the command started");
        DirectGate_SessionMgr_Remove(&fix.conn.mgr, pSession);
        collect(&fix, &replies);
        replies_clear(&replies);

        pSession = exec_session(&fix, 32, sRoot);
        CHECK(pSession != NULL, "an exec session for a signal");
        CHECK(deliver(&fix, exec_start(32, "exec sleep 30", NULL, 0, XFALSE), XTRUE, NULL, 0) == XAPI_CONTINUE,
            "a long command is accepted");

        xjson_obj_t *pBad = DirectGate_Proto_BuildExec("signal", NULL, NULL, 32);
        XJSON_AddString(pBad, "signal", "STOP");
        CHECK(deliver(&fix, pBad, XTRUE, NULL, 0) == XAPI_CONTINUE, "an unsupported signal is handled");
        collect(&fix, &replies);
        CHECK(!strcmp(replies.sError, "unknown signal") && !replies.bExit, "an unsupported signal is refused, not sent");

        xjson_obj_t *pSignal = DirectGate_Proto_BuildExec("signal", NULL, NULL, 32);
        XJSON_AddString(pSignal, "signal", "TERM");
        CHECK(deliver(&fix, pSignal, XTRUE, NULL, 0) == XAPI_CONTINUE, "a signal is accepted");
        CHECK(run_until_exit(&fix, &api, &replies, 5000), "the signalled command ends");
        CHECK(!strcmp(replies.sSignal, "TERM") && !replies.bTimedOut, "the exit names the signal that ended it");
        DirectGate_SessionMgr_Remove(&fix.conn.mgr, pSession);
        collect(&fix, &replies);
        replies_clear(&replies);
    }

    /* ---- output held open by something the command started does not hold up the exit ---------------------- */
    {
        directgate_session_t *pSession = exec_session(&fix, 33, sRoot);
        CHECK(pSession != NULL, "an exec session for a background child");

        uint64_t nStart = XTime_GetMonoMs();
        CHECK(deliver(&fix, exec_start(33, "sleep 3 & echo started", NULL, 0, XFALSE), XTRUE, NULL, 0) == XAPI_CONTINUE,
            "a command leaving a background child is accepted");
        CHECK(run_until_exit(&fix, &api, &replies, 5000), "its exit is reported");
        CHECK(XTime_GetMonoMs() - nStart < 2000, "the exit is not held up by the child keeping stdout open");
        CHECK(output_is(&replies.out, "started\n") && replies.nExitCode == 0, "the command's own output came first");
        DirectGate_SessionMgr_Remove(&fix.conn.mgr, pSession);
        collect(&fix, &replies);
        replies_clear(&replies);
    }

    /* ---- input a program does not read is capped --------------------------------------------------------- */
    {
        directgate_session_t *pSession = exec_session(&fix, 34, sRoot);
        CHECK(pSession != NULL, "an exec session for unread input");
        CHECK(deliver(&fix, exec_start(34, "exec sleep 30", NULL, 0, XTRUE), XTRUE, NULL, 0) == XAPI_CONTINUE,
            "a command that never reads stdin is accepted");
        collect(&fix, &replies);
        int nPid = replies.nPid;

        size_t nChunk = 1024U * 1024U;
        uint8_t *pChunk = (uint8_t*)calloc(1, nChunk);
        CHECK(pChunk != NULL, "a chunk of input");

        int nSent = 0;
        for (; nSent < 12 && DirectGate_SessionMgr_Find(&fix.conn.mgr, 34) != NULL; nSent++)
            deliver(&fix, DirectGate_Proto_BuildExec("input", NULL, NULL, 34), XTRUE, pChunk, nChunk);

        free(pChunk);
        collect(&fix, &replies);
        CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 34) == NULL && replies.bClosed,
            "input piling up past the limit ends the session instead of the agent's memory");
        CHECK(nSent > 7, "input up to the limit is queued, not refused early");

        int bGone = 0;
        for (int i = 0; i < 300 && !bGone; i++)
        {
            DirectGate_Term_ReapPending();
            bGone = kill(nPid, 0) != 0 && errno == ESRCH;
            if (!bGone) usleep(10000);
        }

        CHECK(bGone, "the command of a session ended for its input is stopped");
        replies_clear(&replies);
    }

    /* ---- a session that goes away takes its running command with it ---------------------------------------- */
    {
        directgate_session_t *pSession = exec_session(&fix, 41, sRoot);
        CHECK(pSession != NULL, "an exec session to abandon");
        CHECK(deliver(&fix, exec_start(41, "exec sleep 30", NULL, 0, XFALSE), XTRUE, NULL, 0) == XAPI_CONTINUE,
            "a long command to abandon is accepted");
        collect(&fix, &replies);
        int nPid = replies.nPid;
        CHECK(nPid > 0, "the abandoned command's pid is known");

        DirectGate_SessionMgr_Remove(&fix.conn.mgr, pSession);
        collect(&fix, &replies);

        int bGone = 0;
        for (int i = 0; i < 300 && !bGone; i++)
        {
            DirectGate_Term_ReapPending();
            bGone = kill(nPid, 0) != 0 && errno == ESRCH;
            if (!bGone) usleep(10000);
        }

        CHECK(bGone, "a command whose session is gone is stopped and collected");
        replies_clear(&replies);
    }

    /* ---- a program writing faster than the transport drains is paused, not buffered without bound ---------- */
    {
        directgate_session_t *pSession = exec_session(&fix, 51, sRoot);
        CHECK(pSession != NULL, "an exec session for a flood of output");

        /* Past the 4 MB high-water mark with room to spare: the program is still writing - blocked on a full pipe -
           when reading pauses, so its exit cannot come early. Not more, since every byte is sealed and opened again. */
        const size_t nTotal = 6U * 1024U * 1024U;
        char sScript[128];
        snprintf(sScript, sizeof(sScript), "head -c %zu /dev/zero", nTotal);
        CHECK(deliver(&fix, exec_start(51, sScript, NULL, 0, XFALSE), XTRUE, NULL, 0) == XAPI_CONTINUE,
            "a command flooding stdout is accepted");

        /* Not drained: the queue on the relay socket stops growing once reading pauses */
        /* Bounded by time, not by passes: a pass returns at once while the pipe is ready */
        uint64_t nPauseDeadline = XTime_GetMonoMs() + 30000;
        while (!pSession->command.bReadPaused && XTime_GetMonoMs() < nPauseDeadline) XAPI_Service(&api, 10);
        CHECK(pSession->command.bReadPaused, "reading output pauses behind a backed-up transport");

        size_t nQueued = fix.api.txBuffer.nUsed;
        for (int i = 0; i < 20; i++) XAPI_Service(&api, 10);
        CHECK(fix.api.txBuffer.nUsed == nQueued, "nothing more is queued while paused");
        CHECK(nQueued < 8U * 1024U * 1024U, "the queue stays near the high-water mark");
        CHECK(!replies.bExit, "a paused command's exit is not reported ahead of its output");

        /* Drained as a client would: everything arrives, then the exit */
        /* A second natively; half a minute under valgrind. The bound is for a hang, not for the speed. */
        CHECK(run_until_exit(&fix, &api, &replies, 120000), "the flooding command finishes once drained");
        CHECK(replies.out.nUsed == nTotal, "every byte of output arrives");
        CHECK(replies.nExitCode == 0, "the flooding command exits normally");
        DirectGate_SessionMgr_Remove(&fix.conn.mgr, pSession);
        collect(&fix, &replies);
        replies_clear(&replies);
    }

    /* ---- on the relay, output keeps below the relay's limit, and the loop sleeps until more may go ---------- */
    {
        directgate_session_t *pSession = exec_session(&fix, 57, sRoot);
        CHECK(pSession != NULL, "an exec session for paced output");

        /* 256 KB/s with no burst: kept to 240 KB/s, a 16 KB read every 67 ms. The program keeps its output open a while
           after writing it: what is left in the pipe of one that exits is read at once rather than lost (at most a pipe's
           worth, a debt what comes next waits for), and that is not what this measures. */
        DirectGate_SessionMgr_SetRelayLimit(&fix.conn.mgr, 262144, 0);
        uint64_t nStartMs = XTime_GetMonoMs(), nOutputMs = 0;
        xjson_obj_t *pPaced = exec_start(57, "head -c 131072 /dev/zero; sleep 1", NULL, 0, XFALSE);
        CHECK(deliver(&fix, pPaced, XTRUE, NULL, 0) == XAPI_CONTINUE, "a command writing 128 KB on the relay is accepted");

        xbool_t bPaced = XFALSE, bSlept = XFALSE;
        uint64_t nDeadline = XTime_GetMonoMs() + 60000;
        while (!replies.bExit && XTime_GetMonoMs() < nDeadline)
        {
            uint64_t nNowMs = XTime_GetMonoMs();
            uint32_t nServiceMs = DirectGate_TestGetServiceWaitMs(&fix.conn);

            if (pSession->command.bReadPaused && pSession->command.bPaced)
            {
                bPaced = XTRUE;
                CHECK(DirectGate_CMD_GetWaitMs(&pSession->command, nNowMs) == DIRECTGATE_COMMAND_WAIT_NONE,
                    "output held by the limit alone is not polled");
                if (DirectGate_Session_GetRelayWaitMs(pSession, nNowMs) > 20 && nServiceMs > DIRECTGATE_COMMAND_POLL_MIN_MS)
                    bSlept = XTRUE;
            }

            /* As the agent's loop does: no longer than it says, at most a moment past what this harness waits */
            XAPI_Service(&api, (int)(nServiceMs < 100 ? nServiceMs : 100));
            collect(&fix, &replies);
            if (!nOutputMs && replies.out.nUsed == 131072) nOutputMs = XTime_GetMonoMs();
        }

        CHECK(replies.bExit && replies.out.nUsed == 131072 && replies.nExitCode == 0, "every byte arrives, then the exit");
        CHECK(bPaced && bSlept, "held by the limit, the output waited, and the loop slept until it could go");
        CHECK(nOutputMs - nStartMs >= 400, "no faster than the limit allows: 128 KB at 240 KB/s");

        DirectGate_SessionMgr_SetRelayLimit(&fix.conn.mgr, 0, 0);
        DirectGate_SessionMgr_Remove(&fix.conn.mgr, pSession);
        collect(&fix, &replies);
        replies_clear(&replies);
    }

    /* ---- output held by the transport and the limit both: polled while the transport holds it, not once only the
            limit does, whose end the session knows ---------------------------------------------------------------- */
    {
        directgate_session_t *pSession = exec_session(&fix, 58, sRoot);
        CHECK(pSession != NULL, "an exec session held twice over");

        /* 15 bytes a millisecond: the first 16 KB read owes the limit a second */
        DirectGate_SessionMgr_SetRelayLimit(&fix.conn.mgr, 16384, 0);
        CHECK(deliver(&fix, exec_start(58, "head -c 65536 /dev/zero; sleep 5", NULL, 0, XFALSE), XTRUE, NULL, 0) == XAPI_CONTINUE,
            "a command for output held twice over is accepted");

        uint64_t nDeadline = XTime_GetMonoMs() + 30000;
        while (!(pSession->command.bReadPaused && pSession->command.bPaced) && XTime_GetMonoMs() < nDeadline)
        {
            XAPI_Service(&api, 10);
            collect(&fix, &replies);
        }
        CHECK(pSession->command.bReadPaused && pSession->command.bPaced, "the first read is held by the limit");

        const size_t nFill = 2U * 1024U * 1024U;
        size_t nUsed = fix.api.txBuffer.nUsed;
        uint8_t *pFill = (uint8_t*)calloc(1, nFill);
        CHECK(pFill != NULL && XByteBuffer_Add(&fix.api.txBuffer, pFill, nFill) > 0, "the relay link backs up meanwhile");
        free(pFill);

        DirectGate_CMD_Check(pSession, XTime_GetMonoMs());
        CHECK(pSession->command.bReadPaused && !pSession->command.bPaced &&
              DirectGate_CMD_GetWaitMs(&pSession->command, XTime_GetMonoMs()) == DIRECTGATE_COMMAND_POLL_MIN_MS,
            "held by the transport too, it is polled: the link drains without a word");

        fix.api.txBuffer.nUsed = nUsed;
        DirectGate_CMD_Check(pSession, XTime_GetMonoMs());
        CHECK(pSession->command.bReadPaused && pSession->command.bPaced &&
              DirectGate_CMD_GetWaitMs(&pSession->command, XTime_GetMonoMs()) == DIRECTGATE_COMMAND_WAIT_NONE,
            "drained, the limit alone holds it, and it is not polled");

        DirectGate_SessionMgr_SetRelayLimit(&fix.conn.mgr, 0, 0);
        DirectGate_CMD_Check(pSession, XTime_GetMonoMs());
        CHECK(!pSession->command.bReadPaused && !pSession->command.bPaced, "no limit, nothing holds it");

        DirectGate_SessionMgr_Remove(&fix.conn.mgr, pSession);
        collect(&fix, &replies);
        replies_clear(&replies);
    }

    /* ---- a program that exits while its last output waits behind the transport loses none of it ---------- */
    {
        /* The relay link backed up before the program even starts, so nothing of it is read yet; the program
           writes less than a pipe holds. Exiting, it hangs the pipe up - which the event loop answers by closing
           the descriptor, with that output still inside unless it is read out first. */
        const size_t nBacklog = 5U * 1024U * 1024U;
        const size_t nTotal = 32U * 1024U;
        const char *pScripts[2] = {
            "head -c 32768 /dev/zero",
            /* Something it started keeps the pipe open: no hangup, and the output waits behind the link */
            "head -c 32768 /dev/zero; sleep 2 &"
        };

        for (int nCase = 0; nCase < 2; nCase++)
        {
            directgate_session_t *pSession = exec_session(&fix, 52 + (uint32_t)nCase, sRoot);
            CHECK(pSession != NULL, "an exec session for output pending at exit");

            uint8_t *pBacklog = (uint8_t*)calloc(1, nBacklog);
            CHECK(pBacklog != NULL, "a stand-in transport backlog");
            CHECK(XByteBuffer_Add(&fix.api.txBuffer, pBacklog, nBacklog) > 0, "back the relay link up");
            free(pBacklog);

            CHECK(deliver(&fix, exec_start(52 + (uint32_t)nCase, pScripts[nCase], NULL, 0, XFALSE), XTRUE, NULL, 0)
                == XAPI_CONTINUE, "a command behind a backed-up link is accepted");

            /* Well past the exit grace, the link still backed up */
            uint64_t nUntil = XTime_GetMonoMs() + 3U * DIRECTGATE_COMMAND_GRACE_MS;
            while (XTime_GetMonoMs() < nUntil) XAPI_Service(&api, 10);
            CHECK(pSession->command.exec.bExited, "the program has exited meanwhile");
            CHECK(pSession->command.nExitFd == XSOCK_INVALID, "the exit endpoint goes once it fires, the link backed up or not");

            if (nCase == 1)
            {
                CHECK(pSession->command.bReadPaused, "reading is paused behind the backed-up link");
                CHECK(pSession->command.eState == DIRECTGATE_COMMAND_RUNNING, "the exit waits for the output still unread");
            }

            /* The link drains: the stand-in goes first, then whatever the agent queued behind it is read back */
            XByteBuffer_Advance(&fix.api.txBuffer, nBacklog);
            CHECK(run_until_exit(&fix, &api, &replies, 10000), "the exit follows once the link drains");
            CHECK(replies.out.nUsed == nTotal, "output still in the pipe at exit arrives in full");
            CHECK(replies.nExitCode == 0, "the program's exit is reported after its output");

            DirectGate_SessionMgr_Remove(&fix.conn.mgr, pSession);
            collect(&fix, &replies);
            replies_clear(&replies);
        }
    }

    /* ---- how long the event loop may sleep for a command --------------------------------------------------- */
    {
        /* Never spawned and never cleared: nothing here may reach a real process */
        directgate_command_t cmd;
        DirectGate_CMD_Init(&cmd);
        const uint64_t nT = 1000000;
        const uint32_t nNone = DIRECTGATE_COMMAND_WAIT_NONE;

        CHECK(DirectGate_CMD_GetWaitMs(NULL, nT) == nNone, "no command asks for nothing");
        CHECK(DirectGate_CMD_GetWaitMs(&cmd, nT) == nNone, "a command not started asks for nothing");

        cmd.eState = DIRECTGATE_COMMAND_RUNNING;
        cmd.nStartMs = nT;
        cmd.nOutFd = 5;
        CHECK(DirectGate_CMD_GetWaitMs(&cmd, nT) == nNone, "a running command with open output waits for its events");

        cmd.nTimeoutMs = 1000;
        CHECK(DirectGate_CMD_GetWaitMs(&cmd, nT + 400) == 600, "a timeout is a deadline the loop wakes for");
        CHECK(DirectGate_CMD_GetWaitMs(&cmd, nT + 1000) == 1 && DirectGate_CMD_GetWaitMs(&cmd, nT + 5000) == 1,
            "a deadline already due asks for the next pass, never for a spin");
        cmd.bTimedOut = XTRUE;
        CHECK(DirectGate_CMD_GetWaitMs(&cmd, nT + 5000) == nNone, "a timeout already enforced no longer counts");
        cmd.bTimedOut = XFALSE;
        cmd.nTimeoutMs = 0;

        cmd.nOutFd = XSOCK_INVALID;
        cmd.nExitFd = 7;
        CHECK(DirectGate_CMD_GetWaitMs(&cmd, nT) == nNone,
            "with an exit endpoint, a program that closed its output costs the loop nothing");

        cmd.nExitFd = XSOCK_INVALID;
        cmd.nErrFd = 6;
        CHECK(DirectGate_CMD_GetWaitMs(&cmd, nT) == nNone, "an open stderr announces the end as well");
        cmd.nErrFd = XSOCK_INVALID;

        cmd.nPollMs = nT;
        CHECK(DirectGate_CMD_GetWaitMs(&cmd, nT) == DIRECTGATE_COMMAND_POLL_MIN_MS, "an exit nothing announces is polled for");
        CHECK(DirectGate_CMD_GetWaitMs(&cmd, nT + 40) == 5, "at the shortest wait at first");
        CHECK(DirectGate_CMD_GetWaitMs(&cmd, nT + 80) == 10, "then an eighth of the time waited");
        CHECK(DirectGate_CMD_GetWaitMs(&cmd, nT + 400) == 50, "growing with the wait");
        CHECK(DirectGate_CMD_GetWaitMs(&cmd, nT + 800) == DIRECTGATE_COMMAND_POLL_MAX_MS &&
            DirectGate_CMD_GetWaitMs(&cmd, nT + 3600000) == DIRECTGATE_COMMAND_POLL_MAX_MS, "up to the longest and no further");
        CHECK(DirectGate_CMD_GetWaitMs(&cmd, nT - 10) == 5, "a clock reading before the poll began counts as no wait");
        cmd.nPollMs = 0;
        CHECK(DirectGate_CMD_GetWaitMs(&cmd, nT + 800) == 5, "polling the check has not started yet begins at the shortest");

        cmd.nPollMs = nT;
        cmd.nTimeoutMs = 1030;
        CHECK(DirectGate_CMD_GetWaitMs(&cmd, nT + 1000) == 30, "the nearer of the timeout and the next poll wins");
        cmd.nTimeoutMs = 0;

        cmd.bReadPaused = XTRUE;
        CHECK(DirectGate_CMD_GetWaitMs(&cmd, nT + 800) == DIRECTGATE_COMMAND_POLL_MIN_MS,
            "paused output is looked at again within the shortest wait");
        cmd.bReadPaused = XFALSE;

        cmd.exec.bExited = XTRUE;
        cmd.nExitMs = nT;
        cmd.nOutFd = 5;
        CHECK(DirectGate_CMD_GetWaitMs(&cmd, nT + 100) == DIRECTGATE_COMMAND_GRACE_MS - 100,
            "the end of the exit grace is a deadline");
        CHECK(DirectGate_CMD_GetWaitMs(&cmd, nT + DIRECTGATE_COMMAND_GRACE_MS + 10) == 1,
            "a grace already over asks for the next pass");

        cmd.eState = DIRECTGATE_COMMAND_DONE;
        CHECK(DirectGate_CMD_GetWaitMs(&cmd, nT) == nNone, "a reported exit asks for nothing");
    }

    /* ---- a program that closed its output ends as an event, not by being polled for ----------------------- */
    if (!have_pidfd()) fprintf(stderr, "session_exec_smoke: no pidfds on this system; exits are only polled for\n");
    else
    {
        directgate_session_t *pSession = exec_session(&fix, 61, sRoot);
        CHECK(pSession != NULL, "an exec session for a program without output");
        directgate_command_t *pCmd = &pSession->command;

        CHECK(deliver(&fix, exec_start(61, "exec >/dev/null 2>&1; sleep 0.3; exit 7", NULL, 0, XFALSE), XTRUE, NULL, 0)
            == XAPI_CONTINUE, "a command that closes its output is accepted");
        CHECK(pCmd->nExitFd != XSOCK_INVALID && pCmd->pExitSession != NULL, "the program's exit is an endpoint on the loop");

        uint64_t nDeadline = XTime_GetMonoMs() + 5000;
        while ((pCmd->nOutFd != XSOCK_INVALID || pCmd->nErrFd != XSOCK_INVALID) && XTime_GetMonoMs() < nDeadline)
            XAPI_Service(&api, 10);

        CHECK(pCmd->nOutFd == XSOCK_INVALID && pCmd->nErrFd == XSOCK_INVALID && !pCmd->exec.bExited,
            "the program runs on with its output closed");
        CHECK(DirectGate_CMD_GetWaitMs(pCmd, XTime_GetMonoMs()) == DIRECTGATE_COMMAND_WAIT_NONE,
            "nothing is polled for meanwhile: the loop may sleep");
        CHECK(DirectGate_TestGetServiceWaitMs(&fix.conn) >= DIRECTGATE_COMMAND_POLL_MAX_MS,
            "the agent's event loop sleeps its full wait");

        /* Each wait would last seconds: only the exit itself can end them early */
        uint64_t nStart = XTime_GetMonoMs();
        while (!replies.bExit && XTime_GetMonoMs() - nStart < 15000)
        {
            XAPI_Service(&api, 5000);
            collect(&fix, &replies);
        }

        CHECK(replies.bExit && replies.nExitCode == 7, "the exit is reported with the program's code");
        CHECK(XTime_GetMonoMs() - nStart < 2500, "the exit wakes the loop from a long wait");
        CHECK(pCmd->nExitFd == XSOCK_INVALID && pCmd->pExitSession == NULL, "the exit endpoint is gone once it has fired");
        DirectGate_SessionMgr_Remove(&fix.conn.mgr, pSession);
        collect(&fix, &replies);
        replies_clear(&replies);
    }

    /* ---- without an exit endpoint the exit is polled for, and still reported --------------------------------- */
    {
        directgate_session_t *pSession = exec_session(&fix, 62, sRoot);
        CHECK(pSession != NULL, "an exec session without an exit endpoint");
        directgate_command_t *pCmd = &pSession->command;

        CHECK(deliver(&fix, exec_start(62, "exec >/dev/null 2>&1; sleep 0.3; exit 9", NULL, 0, XFALSE), XTRUE, NULL, 0)
            == XAPI_CONTINUE, "a command for the polling path is accepted");

        /* As on a system that cannot announce an exit: the endpoint goes, and the command must not notice */
        CHECK(pCmd->pExitSession != NULL || !have_pidfd(), "an exit endpoint to take away");
        if (pCmd->pExitSession != NULL) XAPI_Disconnect(pCmd->pExitSession);
        pCmd->pExitSession = NULL;

        uint64_t nDeadline = XTime_GetMonoMs() + 5000;
        while ((pCmd->nOutFd != XSOCK_INVALID || pCmd->nErrFd != XSOCK_INVALID || pCmd->nExitFd != XSOCK_INVALID) &&
               XTime_GetMonoMs() < nDeadline)
            XAPI_Service(&api, 10);

        CHECK(pCmd->nExitFd == XSOCK_INVALID && !pCmd->exec.bExited, "the program runs with nothing to announce its exit");
        CHECK(pCmd->nPollMs != 0, "polling for the exit has begun");
        CHECK(DirectGate_CMD_GetWaitMs(pCmd, pCmd->nPollMs) == DIRECTGATE_COMMAND_POLL_MIN_MS, "from the shortest wait");

        /* Driven as the agent's own loop drives it: each pass waits as long as the loop would */
        uint32_t nShortest = DIRECTGATE_COMMAND_WAIT_NONE, nLongest = 0;
        uint64_t nStart = XTime_GetMonoMs();
        while (!replies.bExit && XTime_GetMonoMs() - nStart < 15000)
        {
            uint32_t nWaitMs = DirectGate_TestGetServiceWaitMs(&fix.conn);
            if (nWaitMs < nShortest) nShortest = nWaitMs;
            if (nWaitMs > nLongest) nLongest = nWaitMs;
            XAPI_Service(&api, (int)nWaitMs);
            collect(&fix, &replies);
        }

        CHECK(replies.bExit && replies.nExitCode == 9, "a polled-for exit is reported with the program's code");
        CHECK(nShortest < DIRECTGATE_COMMAND_POLL_MAX_MS, "the agent's loop wakes sooner than it would idle for an exit "
            "it has to poll for");
        CHECK(nLongest > DIRECTGATE_COMMAND_POLL_MIN_MS && nLongest <= DIRECTGATE_COMMAND_POLL_MAX_MS,
            "the polling backs off while the program runs, within its bounds");
        DirectGate_SessionMgr_Remove(&fix.conn.mgr, pSession);
        collect(&fix, &replies);
        replies_clear(&replies);
    }

    /* ---- a client's output limit: the rest is dropped on the device, and the program runs to its end ------- */
    {
        directgate_session_t *pSession = exec_session(&fix, 71, sRoot);
        CHECK(pSession != NULL, "an exec session with an output limit");
        CHECK(deliver(&fix, exec_start_max(71, "head -c 200000 /dev/zero; printf err >&2; exit 4", 1000), XTRUE, NULL, 0)
            == XAPI_CONTINUE, "a command with an output limit is accepted");
        CHECK(run_until_exit(&fix, &api, &replies, 10000), "the limited command finishes");
        CHECK(replies.out.nUsed == 1000, "no more of a stream is sent than the client asked for");
        CHECK(output_is(&replies.err, "err"), "each stream has a limit of its own");
        CHECK(replies.nExitCode == 4 && replies.bTruncated, "the exit is the program's own, and says output was dropped");
        DirectGate_SessionMgr_Remove(&fix.conn.mgr, pSession);
        collect(&fix, &replies);
        replies_clear(&replies);

        /* Exactly the limit on one stream, past it on the other */
        pSession = exec_session(&fix, 72, sRoot);
        CHECK(pSession != NULL, "an exec session for output at the limit");
        CHECK(deliver(&fix, exec_start_max(72, "printf abc; printf defg >&2", 3), XTRUE, NULL, 0) == XAPI_CONTINUE,
            "a command writing up to the limit is accepted");
        CHECK(run_until_exit(&fix, &api, &replies, 10000), "the command at the limit finishes");
        CHECK(output_is(&replies.out, "abc") && output_is(&replies.err, "def"), "output is cut at the byte");
        CHECK(replies.bTruncated, "a stream cut on one side is reported");
        DirectGate_SessionMgr_Remove(&fix.conn.mgr, pSession);
        collect(&fix, &replies);
        replies_clear(&replies);

        pSession = exec_session(&fix, 73, sRoot);
        CHECK(pSession != NULL, "an exec session for output that fits");
        CHECK(deliver(&fix, exec_start_max(73, "printf abc; printf def >&2", 3), XTRUE, NULL, 0) == XAPI_CONTINUE,
            "a command whose output fits is accepted");
        CHECK(run_until_exit(&fix, &api, &replies, 10000), "the command whose output fits finishes");
        CHECK(output_is(&replies.out, "abc") && output_is(&replies.err, "def") && !replies.bTruncated,
            "output that fits the limit is all sent, and nothing is reported dropped");
        DirectGate_SessionMgr_Remove(&fix.conn.mgr, pSession);
        collect(&fix, &replies);
        replies_clear(&replies);
    }

    /* ---- output past the limit is read on behind a backed-up link: the program is never blocked by it ------- */
    {
        const size_t nBacklog = 5U * 1024U * 1024U;
        directgate_session_t *pSession = exec_session(&fix, 74, sRoot);
        CHECK(pSession != NULL, "an exec session that wants no output");

        uint8_t *pBacklog = (uint8_t*)calloc(1, nBacklog);
        CHECK(pBacklog != NULL, "a stand-in transport backlog");
        CHECK(XByteBuffer_Add(&fix.api.txBuffer, pBacklog, nBacklog) > 0, "back the relay link up");
        free(pBacklog);

        /* Far more than a pipe holds: it can only finish if what it writes keeps being read */
        CHECK(deliver(&fix, exec_start_max(74, "head -c 8388608 /dev/zero; exit 5", 0), XTRUE, NULL, 0) == XAPI_CONTINUE,
            "a command that wants none of its output is accepted");

        uint64_t nDeadline = XTime_GetMonoMs() + 60000;
        while (pSession->command.eState == DIRECTGATE_COMMAND_RUNNING && XTime_GetMonoMs() < nDeadline)
            XAPI_Service(&api, 10);

        CHECK(pSession->command.eState == DIRECTGATE_COMMAND_DONE, "the program ran to its end with the link backed up");
        CHECK(fix.api.txBuffer.nUsed < nBacklog + 4096U, "none of the dropped output went onto the link");

        XByteBuffer_Advance(&fix.api.txBuffer, nBacklog);
        collect(&fix, &replies);
        CHECK(replies.bExit && replies.nExitCode == 5 && replies.bTruncated, "the exit says the output was dropped");
        CHECK(replies.out.nUsed == 0 && replies.err.nUsed == 0, "a limit of 0 sends no output at all");
        DirectGate_SessionMgr_Remove(&fix.conn.mgr, pSession);
        collect(&fix, &replies);
        replies_clear(&replies);
    }

    /* ---- output read out at the hangup, paused behind the link, still keeps to the limit ------------------- */
    {
        const size_t nBacklog = 5U * 1024U * 1024U;
        directgate_session_t *pSession = exec_session(&fix, 75, sRoot);
        CHECK(pSession != NULL, "an exec session for a limit at the hangup");

        uint8_t *pBacklog = (uint8_t*)calloc(1, nBacklog);
        CHECK(pBacklog != NULL, "a stand-in transport backlog");
        CHECK(XByteBuffer_Add(&fix.api.txBuffer, pBacklog, nBacklog) > 0, "back the relay link up");
        free(pBacklog);

        CHECK(deliver(&fix, exec_start_max(75, "head -c 32768 /dev/zero", 1000), XTRUE, NULL, 0) == XAPI_CONTINUE,
            "a limited command behind a backed-up link is accepted");

        uint64_t nUntil = XTime_GetMonoMs() + 3U * DIRECTGATE_COMMAND_GRACE_MS;
        while (XTime_GetMonoMs() < nUntil) XAPI_Service(&api, 10);
        CHECK(pSession->command.exec.bExited, "the program has exited meanwhile");

        XByteBuffer_Advance(&fix.api.txBuffer, nBacklog);
        CHECK(run_until_exit(&fix, &api, &replies, 10000), "the exit follows once the link drains");
        CHECK(replies.out.nUsed == 1000 && replies.bTruncated, "output read out at the hangup keeps to the limit");
        DirectGate_SessionMgr_Remove(&fix.conn.mgr, pSession);
        collect(&fix, &replies);
        replies_clear(&replies);
    }

    /* ---- a limit that is not a whole number of bytes is refused, never read as no limit --------------------- */
    {
        directgate_session_t *pSession = exec_session(&fix, 76, sRoot);
        CHECK(pSession != NULL, "an exec session for malformed limits");

        for (int nCase = 0; nCase < 5; nCase++)
        {
            xjson_obj_t *pStart = exec_start(76, "touch limit-ran", sRoot, 0, XFALSE);
            CHECK(pStart != NULL, "a start with a malformed limit");
            if (nCase == 0) XJSON_AddString(pStart, "outputMax", "1000");
            else if (nCase == 1) XJSON_AddInt(pStart, "outputMax", -1);
            else if (nCase == 2) XJSON_AddFloat(pStart, "outputMax", 1.5);
            else if (nCase == 3) XJSON_AddU64(pStart, "outputMax", 4294967296ULL);
            else XJSON_AddBool(pStart, "outputMax", XTRUE);

            CHECK(deliver(&fix, pStart, XTRUE, NULL, 0) == XAPI_CONTINUE, "a malformed limit is handled");
            collect(&fix, &replies);
            CHECK(!strcmp(replies.sStarted, "failed") &&
                !strcmp(replies.sStartReason, "outputMax must be a whole number of bytes"),
                "a malformed limit is refused with its reason");
            CHECK(pSession->command.eState == DIRECTGATE_COMMAND_IDLE, "nothing ran for a malformed limit");
            replies_clear(&replies);
        }

        char sLimitRan[PATH_MAX];
        snprintf(sLimitRan, sizeof(sLimitRan), "%s/limit-ran", sRoot);
        struct stat st;
        CHECK(stat(sLimitRan, &st) != 0, "no command with a malformed limit touched the disk");

        CHECK(deliver(&fix, exec_start_max(76, "printf x", 4294967295U), XTRUE, NULL, 0) == XAPI_CONTINUE,
            "the largest limit is accepted");
        CHECK(run_until_exit(&fix, &api, &replies, 10000) && output_is(&replies.out, "x") && !replies.bTruncated,
            "the largest limit runs the command");
        DirectGate_SessionMgr_Remove(&fix.conn.mgr, pSession);
        collect(&fix, &replies);
        replies_clear(&replies);
    }

    /* ---- a command's output is bulk data: no route, no command ----------------------------------------------- */
    {
        /* A session that has neither a data channel nor its client's word that WebRTC is impossible */
        directgate_session_t *pSession = DirectGate_SessionMgr_Create(&fix.conn.mgr, 81);
        CHECK(pSession != NULL, "a session with no route for output yet");
        pSession->pWsSession = &fix.api;
        pSession->bAuthenticated = XTRUE;
        xstrncpy(pSession->term.sShellHome, sizeof(pSession->term.sShellHome), sRoot);
        CHECK(seal_session(&fix, pSession), "the session gets its E2E keys");
        CHECK(deliver(&fix, DirectGate_Proto_BuildCmd("start", NULL, NULL, "exec", 81), XTRUE, NULL, 0) == XAPI_CONTINUE,
            "the session enters exec mode");
        collect(&fix, &replies);
        replies_clear(&replies);

        CHECK(deliver(&fix, exec_start(81, "touch no-route-ran", sRoot, 0, XFALSE), XTRUE, NULL, 0) == XAPI_CONTINUE,
            "a command before its route is known is handled");
        collect(&fix, &replies);
        CHECK(!strcmp(replies.sStarted, "failed") && !strcmp(replies.sStartReason, "the data channel is not ready"),
            "a command is refused while its output could only wait for a channel");
        CHECK(pSession->command.eState == DIRECTGATE_COMMAND_IDLE, "nothing ran without a route");

        char sNoRoute[PATH_MAX];
        snprintf(sNoRoute, sizeof(sNoRoute), "%s/no-route-ran", sRoot);
        struct stat st;
        CHECK(stat(sNoRoute, &st) != 0, "the refused command never touched the disk");
        replies_clear(&replies);

        /* Its output then goes over the data channel - here one that fails at once, as a channel lost midway does */
        pSession->webrtc.bConnected = XTRUE;
        pSession->webrtc.nDataChannelID = 1;
        CHECK(deliver(&fix, exec_start(81, "exec sleep 30", NULL, 0, XFALSE), XTRUE, NULL, 0) == XAPI_CONTINUE,
            "a command over the data channel is accepted");
        collect(&fix, &replies);
        int nPid = replies.nPid;
        CHECK(!strcmp(replies.sStarted, "ok") && nPid > 0, "the command starts on the channel's route");
        CHECK(pSession->eBulkPin == DIRECTGATE_BULK_CHANNEL, "its output is pinned to the channel");

        /* The channel is gone: what was in it cannot be known to have arrived, so the command ends with its session */
        for (int i = 0; i < 20 && DirectGate_SessionMgr_Find(&fix.conn.mgr, 81) != NULL; i++) XAPI_Service(&api, 10);
        collect(&fix, &replies);
        CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 81) == NULL && replies.bClosed,
            "a command whose data channel is lost ends with its session, never carried on over the relay");
        CHECK(!replies.bExit, "no exit is reported over another route");

        int bGone = 0;
        for (int i = 0; i < 300 && !bGone; i++)
        {
            DirectGate_Term_ReapPending();
            bGone = kill(nPid, 0) != 0 && errno == ESRCH;
            if (!bGone) usleep(10000);
        }

        CHECK(bGone, "the command of a session that lost its channel is stopped");
        replies_clear(&replies);
    }

    /* ---- a remote session: one command after another, and file operations, on one authenticated session --- */
    {
        directgate_session_t *pSession = DirectGate_SessionMgr_Create(&fix.conn.mgr, 85);
        CHECK(pSession != NULL, "a session for remote mode");
        pSession->pWsSession = &fix.api;
        pSession->bAuthenticated = XTRUE;
        xstrncpy(pSession->term.sShellHome, sizeof(pSession->term.sShellHome), sRoot);
        CHECK(seal_session(&fix, pSession), "the session gets its E2E keys");
        CHECK(deliver(&fix, DirectGate_Proto_BuildCmd("start", NULL, NULL, "remote", 85), XTRUE, NULL, 0) == XAPI_CONTINUE,
            "the session asks for remote mode");
        CHECK(pSession->eActiveMode == DIRECTGATE_SESSION_MODE_REMOTE, "the session is in remote mode");
        CHECK(deliver(&fix, DirectGate_Proto_BuildWebRTC("unavailable", 85), XTRUE, NULL, 0) == XAPI_CONTINUE,
            "no data channel in this harness: the relay carries it");
        collect(&fix, &replies);
        replies_clear(&replies);

        CHECK(deliver(&fix, exec_start(85, "sleep 0.3; printf first", NULL, 0, XFALSE), XTRUE, NULL, 0) == XAPI_CONTINUE,
            "a first command is accepted");
        collect(&fix, &replies);
        CHECK(!strcmp(replies.sStarted, "ok"), "the first command starts");
        replies_clear(&replies);

        CHECK(deliver(&fix, exec_start(85, "touch second-ran", sRoot, 0, XFALSE), XTRUE, NULL, 0) == XAPI_CONTINUE,
            "a command while one runs is handled");
        collect(&fix, &replies);
        CHECK(!strcmp(replies.sStarted, "failed") && !strcmp(replies.sStartReason, "a command is already running"),
            "a remote session runs one command at a time");
        replies_clear(&replies);

        CHECK(run_until_exit(&fix, &api, &replies, 10000) && output_is(&replies.out, "first") && replies.nExitCode == 0,
            "the first command finishes");
        CHECK(pSession->command.eState == DIRECTGATE_COMMAND_IDLE && pSession->command.nOutFd == XSOCK_INVALID &&
            pSession->command.nExitFd == XSOCK_INVALID && pSession->command.exec.nPid == XSTDERR,
            "its session is ready for the next command, with nothing of the last one left");
        replies_clear(&replies);

        CHECK(deliver(&fix, exec_start(85, "printf second; exit 4", NULL, 0, XFALSE), XTRUE, NULL, 0) == XAPI_CONTINUE,
            "a second command is accepted");
        CHECK(run_until_exit(&fix, &api, &replies, 10000) && output_is(&replies.out, "second") && replies.nExitCode == 4,
            "the second command runs on the same session");
        replies_clear(&replies);

        /* File operations on the same session */
        xjson_obj_t *pList = DirectGate_Proto_BuildManager("list", NULL, sRoot, NULL, 85);
        CHECK(pList != NULL && deliver(&fix, pList, XTRUE, NULL, 0) == XAPI_CONTINUE, "a listing on the remote session");
        collect(&fix, &replies);
        CHECK(replies.bListed, "a remote session lists directories too");
        replies_clear(&replies);

        /* Nothing ends it after a command: unlike an exec session it stays for as long as its client keeps it */
        uint64_t nUntil = XTime_GetMonoMs() + DIRECTGATE_COMMAND_LINGER_MS + 200;
        while (XTime_GetMonoMs() < nUntil) XAPI_Service(&api, 20);
        collect(&fix, &replies);
        CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 85) == pSession && !replies.bClosed,
            "a remote session outlives the linger of an exec session");

        /* A command that cannot start leaves it ready, too */
        char sMissingDir[PATH_MAX];
        snprintf(sMissingDir, sizeof(sMissingDir), "%s/no-such-dir", sRoot);
        CHECK(deliver(&fix, exec_start(85, "true", sMissingDir, 0, XFALSE), XTRUE, NULL, 0) == XAPI_CONTINUE,
            "a command in a missing directory is accepted");
        CHECK(run_until_exit(&fix, &api, &replies, 10000) && replies.nExitCode == 127, "and fails as such");
        CHECK(pSession->command.eState == DIRECTGATE_COMMAND_IDLE, "the session is ready again after a failed command");

        char sSecondRan[PATH_MAX];
        snprintf(sSecondRan, sizeof(sSecondRan), "%s/second-ran", sRoot);
        struct stat st;
        CHECK(stat(sSecondRan, &st) != 0, "the command refused while another ran never ran");

        DirectGate_SessionMgr_Remove(&fix.conn.mgr, pSession);
        collect(&fix, &replies);
        replies_clear(&replies);
    }

    /* ---- over a real data channel: the command, its output and its exit never touch the relay ------------- */
    {
        directgate_session_t *pSession = DirectGate_SessionMgr_Create(&fix.conn.mgr, 84);
        CHECK(pSession != NULL, "a session for a command over the data channel");
        pSession->pWsSession = &fix.api;
        pSession->bAuthenticated = XTRUE;
        xstrncpy(pSession->term.sShellHome, sizeof(pSession->term.sShellHome), sRoot);
        CHECK(seal_session(&fix, pSession), "the session gets its E2E keys");

        /* The mode first, as the client sends it: WebRTC is set up for a session whose mode is active */
        CHECK(deliver(&fix, DirectGate_Proto_BuildCmd("start", NULL, NULL, "exec", 84), XTRUE, NULL, 0) == XAPI_CONTINUE,
            "the session enters exec mode");
        collect(&fix, &replies);
        replies_clear(&replies);

        static directgate_webrtc_t peer;
        static uint32_t nPeerSession = 84;
        DirectGate_WebRTC_Init(&peer);
        peer.signalCb = peer_signal;
        peer.pSignalCtx = &nPeerSession;
        peer.dataCb = peer_data;
        g_pPeer = &peer;
        g_pPeerFix = &fix;
        g_pPeerReplies = &replies;
        CHECK(DirectGate_WebRTC_CreateOffer(&peer) == XSTDOK, "the client offers a data channel");

        uint64_t nDeadline = XTime_GetMonoMs() + 30000;
        while ((!DirectGate_WebRTC_IsConnected(&peer) || !DirectGate_WebRTC_IsConnected(&pSession->webrtc)) &&
               XTime_GetMonoMs() < nDeadline)
        {
            DirectGate_WebRTC_ProcessQueue(&peer);
            XAPI_Service(&api, 10);
            collect(&fix, &replies);
        }

        CHECK(DirectGate_WebRTC_IsConnected(&peer) && DirectGate_WebRTC_IsConnected(&pSession->webrtc),
            "the data channel opens between the client and the agent");
        CHECK(DirectGate_Session_GetBulkRoute(pSession, XTime_GetMonoMs()) == DIRECTGATE_BULK_CHANNEL,
            "the channel is the route for bulk data");

        /* A relay limit, and a session deep in debt with it: none of that holds back what goes over the channel */
        DirectGate_SessionMgr_SetRelayLimit(&fix.conn.mgr, 16384, 0);
        pSession->nRelayTokens = -2000000000LL;
        pSession->nRelayTokensMs = XTime_GetMonoMs();

        /* The command goes over the channel, as dgcli sends it once the channel is open */
        xbyte_buffer_t packet;
        XByteBuffer_Init(&packet, XSTDNON, XFALSE);
        /* The program writes, then keeps running: its output has to arrive while it runs, not with its exit */
        xjson_obj_t *pStart = exec_start(84, "printf over-the-channel; printf warn >&2; sleep 3; exit 6", NULL, 0, XFALSE);
        CHECK(pStart != NULL && seal(&fix, &packet, pStart, NULL, 0), "seal a command for the channel");
        XJSON_FreeObject(pStart);
        CHECK(DirectGate_WebRTC_Send(&peer, packet.pData, packet.nUsed) == XSTDOK, "the command goes over the channel");
        XByteBuffer_Clear(&packet);

        nDeadline = XTime_GetMonoMs() + 30000;
        uint64_t nOutputMs = 0, nExitMs = 0;
        while (!replies.bExit && XTime_GetMonoMs() < nDeadline)
        {
            DirectGate_WebRTC_ProcessQueue(&peer);
            XAPI_Service(&api, 10);
            collect(&fix, &replies);
            if (!nOutputMs && output_is(&replies.out, "over-the-channel") && output_is(&replies.err, "warn"))
                nOutputMs = XTime_GetMonoMs();
        }
        nExitMs = XTime_GetMonoMs();

        CHECK(replies.bExit && replies.nExitCode == 6, "the exit arrives with the program's code");
        CHECK(nOutputMs && nExitMs - nOutputMs >= 1000,
            "the output arrives as it is written: a relay limit and a debt with it hold nothing back on the channel");
        CHECK(output_is(&replies.out, "over-the-channel") && output_is(&replies.err, "warn"), "the output arrives whole");
        CHECK(replies.nChannelExec >= 3 && replies.nRelayExec == 0,
            "the start, the output and the exit all came over the channel, and nothing of the command on the relay");
        DirectGate_SessionMgr_SetRelayLimit(&fix.conn.mgr, 0, 0);

        g_pPeer = NULL;
        g_pPeerReplies = NULL;
        DirectGate_WebRTC_Clear(&peer);
        DirectGate_SessionMgr_Remove(&fix.conn.mgr, pSession);
        collect(&fix, &replies);
        replies_clear(&replies);
    }

    /* ---- an offer the agent cannot answer: its client is told at once, instead of waiting the channel out ---- */
    {
        directgate_session_t *pSession = DirectGate_SessionMgr_Create(&fix.conn.mgr, 83);
        CHECK(pSession != NULL, "a session for an offer that cannot be answered");
        pSession->pWsSession = &fix.api;
        pSession->bAuthenticated = XTRUE;
        CHECK(seal_session(&fix, pSession), "the session gets its E2E keys");

        /* Replacing a working peer in the background: that peer and its route stay as they are */
        pSession->webrtc.bConnected = XTRUE;
        pSession->webrtc.nDataChannelID = 1;
        xjson_obj_t *pBackground = DirectGate_Proto_BuildWebRTC("offer", 83);
        CHECK(pBackground != NULL, "a background offer");
        XJSON_AddString(pBackground, "sdp", "not an sdp");
        XJSON_AddString(pBackground, "migration", "p2p");
        CHECK(deliver(&fix, pBackground, XTRUE, NULL, 0) == XAPI_CONTINUE, "a background offer that fails is handled");
        collect(&fix, &replies);
        CHECK(!replies.bUnavailable && !pSession->bBulkRelay, "a background offer that fails leaves the working route alone");
        pSession->webrtc.bConnected = XFALSE;
        pSession->webrtc.nDataChannelID = -1;
        replies_clear(&replies);

        /* The first offer of a session: no channel is coming */
        xjson_obj_t *pOffer = DirectGate_Proto_BuildWebRTC("offer", 83);
        CHECK(pOffer != NULL, "an offer");
        XJSON_AddString(pOffer, "sdp", "not an sdp");
        CHECK(deliver(&fix, pOffer, XTRUE, NULL, 0) == XAPI_CONTINUE, "an offer that cannot be answered is handled");
        collect(&fix, &replies);
        CHECK(replies.bUnavailable, "the client is told WebRTC cannot be set up");
        CHECK(pSession->bBulkRelay && DirectGate_Session_GetBulkRoute(pSession, XTime_GetMonoMs()) == DIRECTGATE_BULK_RELAY,
            "and the relay is the session's route at once");
        CHECK(!replies.bPlainExec, "the answer is sealed like every message after authentication");

        DirectGate_SessionMgr_Remove(&fix.conn.mgr, pSession);
        collect(&fix, &replies);
        replies_clear(&replies);
    }

    XAPI_Destroy(&api);
    fix.api.pApi = NULL;

    DirectGate_SessionMgr_Destroy(&fix.conn.mgr);
    webrtc_cleanup_settled();
    XByteBuffer_Clear(&fix.api.txBuffer);
    replies_clear(&replies);
    XByteBuffer_Clear(&replies.out);
    XByteBuffer_Clear(&replies.err);
    rmdir(sRoot);

    puts("session_exec_smoke: OK");
    return 0;
}
