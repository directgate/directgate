/*
 * The in-session token refresh, with its request off the event loop.
 *
 * The refresh used to make its HTTPS round trip on the relay event loop, and
 * every live session stood still until the API answered: video, input, audio
 * and the relay. That was about 1.3 s once an hour, and 15 s the day the API
 * timed out, long enough for the viewer to give up on the session. Now the
 * request runs on a worker and a later loop pass takes the answer, so a pass
 * returns at once however long the API takes.
 *
 * Running on its own also means it can still be out when something else wants
 * to refresh. Two requests with one refresh token read as reuse to the API the
 * moment it rotates that token, and the device is revoked, so nothing else
 * refreshes while one is out. And its answer is never lost: it is applied
 * after the relay went away, waited for at shutdown, and only dropped when the
 * enrollment it belongs to was cleared in the meantime.
 *
 * The reconnect asks the API too, before the relay is back, and so does the
 * relay re-probe when reconnects keep failing. Both ran on the loop while the
 * sessions the relay left on their data channels needed it: a relay restart
 * froze them for the second the API took. Now they use the same worker, and so
 * does the relay host's name lookup; the connect itself returns before TCP and
 * TLS are done where the platform allows it.
 *
 * The API is a real HTTPS endpoint in this process that can hold its answer,
 * next to a WSS relay the reconnects reach.
 */

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <time.h>
#include <unistd.h>

#include "src/agent/directgate.h"
#include "src/common/common.h"

#include "tls_fixture.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "token_refresh_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

#define RELAY_URL       "wss://relay1.example.test/websock"
#define ANSWER_OK       1   /* a new access token, the refresh token kept */
#define ANSWER_ROTATED  2   /* a new access token and a rotated refresh token */
#define ANSWER_DOWN     3   /* the API cannot answer for now */
#define ANSWER_REVOKED  4   /* the enrollment is gone for good */
#define WAIT_MS         20000U
#define QUICK_MS        1000U   /* a loop pass that waits for nothing returns well inside this */

int DirectGate_ServiceCallback(xapi_ctx_t *pCtx, xapi_session_t *pApiSession);

typedef struct {
    xapi_t api;
    xatomic_t bStop;
    xatomic_t nRequests;
    xatomic_t nAnswer;
    xatomic_t bHold;        /* keep the answer back until released */
    xatomic_t bRelease;
    xatomic_t nReleaseAtMs; /* since nBaseMs: released by the API then, so code that waits in-line fails, not hangs */
    uint64_t nBaseMs;
    xapi_session_t *pHeld;  /* API thread only */

    /* The WSS relay, and the relay the answers name: this one when bLocalRelay is set */
    uint16_t nRelayPort;
    char sLocalRelayUrl[128];
    xatomic_t bLocalRelay;
    xatomic_t nRelayAccepts;
    xatomic_t nRelayUpgrades;
    char sRelayHost[128];   /* the Host header of the last upgrade, written before nRelayUpgrades counts it */
} api_t;

static api_t g_api;

static int api_answer(xapi_session_t *pSession)
{
    char sBody[1024];
    const char *pRelayUrl = XSYNC_ATOMIC_GET(&g_api.bLocalRelay) ? g_api.sLocalRelayUrl : RELAY_URL;
    uint16_t nCode = 200;

    if (XSYNC_ATOMIC_GET(&g_api.nAnswer) == ANSWER_DOWN)
    {
        nCode = 503;
        snprintf(sBody, sizeof(sBody), "{\"message\":\"unavailable\"}");
    }
    else if (XSYNC_ATOMIC_GET(&g_api.nAnswer) == ANSWER_REVOKED)
    {
        nCode = 403;
        snprintf(sBody, sizeof(sBody), "{\"message\":\"Device enrollment revoked\",\"code\":\"DEVICE_ENROLLMENT_REVOKED\"}");
    }
    else if (XSYNC_ATOMIC_GET(&g_api.nAnswer) == ANSWER_ROTATED)
        snprintf(sBody, sizeof(sBody),
            "{\"accessToken\":\"access-new\",\"refreshTokenRotated\":true,\"refreshToken\":\"refresh-rotated\","
            "\"refreshTokenExpiresAt\":\"2099-01-01T00:00:00Z\",\"accessTokenExpiresIn\":3600,"
            "\"enrollmentExpiresAt\":\"2099-01-01T00:00:00Z\",\"relayUrl\":\"%s\",\"routingKey\":\"rk-refresh\","
            "\"deviceId\":\"dev-refresh\"}", pRelayUrl);
    else
        snprintf(sBody, sizeof(sBody),
            "{\"accessToken\":\"access-new\",\"refreshTokenRotated\":false,\"accessTokenExpiresIn\":3600,"
            "\"enrollmentExpiresAt\":\"2099-01-01T00:00:00Z\",\"relayUrl\":\"%s\",\"routingKey\":\"rk-refresh\","
            "\"deviceId\":\"dev-refresh\"}", pRelayUrl);

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
    XSYNC_ATOMIC_ADD(&g_api.nRequests, 1);

    if (!XSYNC_ATOMIC_GET(&g_api.bHold)) return api_answer(pSession);
    g_api.pHeld = pSession;
    return XAPI_CONTINUE;
}

/* The relay only takes the upgrade and keeps the link: what is checked is that the reconnect got there, and as whom */
static int relay_upgrade(xapi_session_t *pSession)
{
    xhttp_t *pHandle = (xhttp_t*)pSession->pPacket;
    const char *pHost = pHandle != NULL ? XHTTP_GetHeader(pHandle, "Host") : NULL;
    xstrncpy(g_api.sRelayHost, sizeof(g_api.sRelayHost), pHost != NULL ? pHost : "");
    XSYNC_ATOMIC_ADD(&g_api.nRelayUpgrades, 1);
    return XAPI_CONTINUE;
}

static int api_callback(xapi_ctx_t *pCtx, xapi_session_t *pSession)
{
    if (pSession != NULL && pSession->eType == XAPI_WS)
    {
        if (pCtx->eCbType == XAPI_CB_ACCEPTED)
        {
            XSYNC_ATOMIC_ADD(&g_api.nRelayAccepts, 1);
            return XAPI_SetEvents(pSession, XPOLLIN);
        }

        return pCtx->eCbType == XAPI_CB_HANDSHAKE_REQUEST ? relay_upgrade(pSession) : XAPI_CONTINUE;
    }

    switch (pCtx->eCbType)
    {
        case XAPI_CB_ACCEPTED: return XAPI_SetEvents(pSession, XPOLLIN);
        case XAPI_CB_READ: return api_request(pSession);
        case XAPI_CB_COMPLETE: return XAPI_DISCONNECT;
        case XAPI_CB_CLOSED:
            if (pSession == g_api.pHeld) g_api.pHeld = NULL;
            break;
        default: break;
    }

    return XAPI_CONTINUE;
}

static void* api_thread(void *pArg)
{
    (void)pArg;
    while (!XSYNC_ATOMIC_GET(&g_api.bStop))
    {
        XAPI_Service(&g_api.api, 20);

        uint64_t nReleaseAtMs = (uint64_t)XSYNC_ATOMIC_GET(&g_api.nReleaseAtMs);
        if (g_api.pHeld != NULL && nReleaseAtMs && XTime_GetMonoMs() - g_api.nBaseMs >= nReleaseAtMs)
        {
            XSYNC_ATOMIC_SET(&g_api.nReleaseAtMs, 0);
            XSYNC_ATOMIC_SET(&g_api.bHold, 0);
            XSYNC_ATOMIC_SET(&g_api.bRelease, 1);
        }

        if (g_api.pHeld == NULL || !XSYNC_ATOMIC_GET(&g_api.bRelease)) continue;

        xapi_session_t *pHeld = g_api.pHeld;
        g_api.pHeld = NULL;
        XSYNC_ATOMIC_SET(&g_api.bRelease, 0);
        if (api_answer(pHeld) == XAPI_DISCONNECT) XAPI_Disconnect(pHeld);
    }

    return NULL;
}

/* Hold the next answer, and say what it will be. */
static void api_hold(int nAnswer)
{
    XSYNC_ATOMIC_SET(&g_api.nAnswer, nAnswer);
    XSYNC_ATOMIC_SET(&g_api.bRelease, 0);
    XSYNC_ATOMIC_SET(&g_api.bHold, 1);
}

static void api_release(void)
{
    XSYNC_ATOMIC_SET(&g_api.nReleaseAtMs, 0);
    XSYNC_ATOMIC_SET(&g_api.bHold, 0);
    XSYNC_ATOMIC_SET(&g_api.bRelease, 1);
}

/* Hold the next answer, but let it go by itself after nMs: code that waited for it in-line returns that late */
static void api_hold_for(int nAnswer, uint32_t nMs)
{
    api_hold(nAnswer);
    XSYNC_ATOMIC_SET(&g_api.nReleaseAtMs, (xatomic_t)(XTime_GetMonoMs() - g_api.nBaseMs + nMs));
}

/* Wait until the request is with the API, by time: an iteration count over a call that returns at once is no bound. */
static int api_wait_requests(uint32_t nRequests)
{
    uint64_t nDeadlineMs = XTime_GetMonoMs() + WAIT_MS;
    while ((uint32_t)XSYNC_ATOMIC_GET(&g_api.nRequests) < nRequests && XTime_GetMonoMs() < nDeadlineMs) xusleep(5000);
    return (uint32_t)XSYNC_ATOMIC_GET(&g_api.nRequests) >= nRequests;
}

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
    if (bind(nFd, (struct sockaddr*)&addr, sizeof(addr)) == 0 && getsockname(nFd, (struct sockaddr*)&addr, &nLen) == 0)
        nPort = ntohs(addr.sin_port);

    close(nFd);
    return nPort;
}

typedef struct {
    directgate_cfg_t cfg;
    directgate_conn_t conn;
    xapi_session_t relay;
} fixture_t;

/* An enrolled agent on a live relay whose access token is due for a refresh. */
static void fixture_open(fixture_t *pFix, const char *pRoot, uint16_t nPort)
{
    memset(pFix, 0, sizeof(*pFix));
    directgate_cfg_t *pCfg = &pFix->cfg;
    snprintf(pCfg->sCfgPath, sizeof(pCfg->sCfgPath), "%s/agent.json", pRoot);
    xstrncpy(pCfg->sDeviceId, sizeof(pCfg->sDeviceId), "dev-refresh");
    xstrncpy(pCfg->sRelayUrl, sizeof(pCfg->sRelayUrl), RELAY_URL);
    xstrncpy(pCfg->sRoutingKey, sizeof(pCfg->sRoutingKey), "rk-refresh");
    snprintf(pCfg->enroll.sApiUrl, sizeof(pCfg->enroll.sApiUrl), "https://127.0.0.1:%u", (unsigned)nPort);
    xstrncpy(pCfg->enroll.sAccessToken, sizeof(pCfg->enroll.sAccessToken), "access-old");
    xstrncpy(pCfg->enroll.sRefreshToken, sizeof(pCfg->enroll.sRefreshToken), "refresh-old");
    xstrncpy(pCfg->enroll.sEnrollExpiresAt, sizeof(pCfg->enroll.sEnrollExpiresAt), "2099-01-01T00:00:00Z");
    pCfg->enroll.nAccessTokenExp = (uint64_t)time(NULL) + 30U;
    pCfg->enroll.nRefreshSkewSec = 120;
    pCfg->enroll.bEnrolled = XTRUE;

    directgate_conn_t *pConn = &pFix->conn;
    pConn->pCfg = pCfg;
    DirectGate_SessionMgr_Init(&pConn->mgr, pCfg);

    /* Already watching for writes, so queueing a frame needs no event loop behind it */
    pFix->relay.eRole = XAPI_CLIENT;
    pFix->relay.sock.nFD = XSOCK_INVALID;
    pFix->relay.nEvents = XPOLLIO;
    pFix->relay.pSessionData = pConn;
    XByteBuffer_Init(&pFix->relay.txBuffer, XSTDNON, XFALSE);
    pConn->pWsSession = &pFix->relay;
    pConn->bRoleSent = XTRUE;
}

static void fixture_close(fixture_t *pFix)
{
    XByteBuffer_Clear(&pFix->relay.txBuffer);
    DirectGate_SessionMgr_Destroy(&pFix->conn.mgr);
}

/* The relay socket reports that the far end went away. */
static void relay_closed(fixture_t *pFix)
{
    xapi_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.eCbType = XAPI_CB_STATUS;
    ctx.eStatType = XAPI_SOCK;
    ctx.nStatus = XSOCK_EOF;
    DirectGate_ServiceCallback(&ctx, &pFix->relay);
}

static int file_has(const char *pPath, const char *pNeedle)
{
    char sBuffer[8192];
    FILE *pFile = fopen(pPath, "rb");
    if (pFile == NULL) return 0;

    size_t nRead = fread(sBuffer, 1, sizeof(sBuffer) - 1, pFile);
    fclose(pFile);
    sBuffer[nRead] = '\0';
    return strstr(sBuffer, pNeedle) != NULL;
}

/* Threads of this process, where the platform can say; -1 where it cannot. */
static int thread_count(void)
{
#ifdef __linux__
    DIR *pDir = opendir("/proc/self/task");
    if (pDir == NULL) return -1;

    int nCount = 0;
    struct dirent *pEntry;
    while ((pEntry = readdir(pDir)) != NULL) if (pEntry->d_name[0] != '.') nCount++;
    closedir(pDir);
    return nCount;
#else
    return -1;
#endif
}

/* The loop pass that starts a refresh returns while the API still holds its answer, and the passes after it take
   nothing until the answer is in. Then one of them applies it and tells the relay. */
static int test_off_the_loop(const char *pRoot, uint16_t nPort)
{
    fixture_t fix;
    fixture_open(&fix, pRoot, nPort);
    uint32_t nRequests = (uint32_t)XSYNC_ATOMIC_GET(&g_api.nRequests);
    api_hold(ANSWER_OK);

    uint64_t nStartMs = XTime_GetMonoMs();
    CHECK(DirectGate_TestCheckTokenRefresh(&fix.conn), "a refresh that is due starts");
    CHECK(XTime_GetMonoMs() - nStartMs < 1000, "the loop pass that starts it does not wait for the API");
    CHECK(fix.conn.pRefreshJob != NULL, "the request is out on the worker");
    CHECK(api_wait_requests(nRequests + 1U), "the request reaches the API");

    for (int i = 0; i < 5; i++)
    {
        nStartMs = XTime_GetMonoMs();
        CHECK(DirectGate_TestCheckTokenRefresh(&fix.conn), "a pass while the request is out keeps the session");
        CHECK(XTime_GetMonoMs() - nStartMs < 1000, "and returns at once");
    }

    CHECK(XSYNC_ATOMIC_GET(&g_api.nRequests) == nRequests + 1, "no second request goes out while one is in flight");
    CHECK(!strcmp(fix.cfg.enroll.sAccessToken, "access-old"), "nothing is applied before the answer is in");
    CHECK(fix.relay.txBuffer.nUsed == 0, "and the relay is told nothing yet");

    api_release();
    CHECK(DirectGate_TestFinishTokenRefresh(&fix.conn, WAIT_MS), "the answer is taken");
    CHECK(fix.conn.pRefreshJob == NULL, "and the refresh is over");
    CHECK(!strcmp(fix.cfg.enroll.sAccessToken, "access-new"), "the new access token is applied");
    CHECK(!strcmp(fix.cfg.enroll.sRefreshToken, "refresh-old"), "an unrotated refresh token is kept");
    CHECK(fix.cfg.enroll.nAccessTokenExp > (uint64_t)time(NULL) + 3000U, "with its new expiry");
    CHECK(fix.conn.nTokenRefreshFailures == 0 && fix.conn.nNextTokenRefreshMs == 0, "the back-off is reset");
    CHECK(fix.relay.txBuffer.nUsed > 0, "the relay gets the new token in a verify update");
    CHECK(file_has(fix.cfg.sCfgPath, "access-new"), "the new token is saved");

    size_t nSent = fix.relay.txBuffer.nUsed;
    CHECK(DirectGate_TestCheckTokenRefresh(&fix.conn), "a pass after it keeps the session");
    CHECK((uint32_t)XSYNC_ATOMIC_GET(&g_api.nRequests) == nRequests + 1U && fix.relay.txBuffer.nUsed == nSent,
        "a fresh token is not refreshed again");

    fixture_close(&fix);
    return 0;
}

/* The relay goes away while the request is out. Nothing else may refresh with the same token meanwhile, the relay
   re-probe included, and the answer still lands: it is the one that carries a rotated refresh token. */
static int test_relay_lost(const char *pRoot, uint16_t nPort)
{
    fixture_t fix;
    fixture_open(&fix, pRoot, nPort);
    uint32_t nRequests = (uint32_t)XSYNC_ATOMIC_GET(&g_api.nRequests);
    api_hold(ANSWER_ROTATED);

    CHECK(DirectGate_TestCheckTokenRefresh(&fix.conn) && fix.conn.pRefreshJob != NULL, "the refresh goes out");
    CHECK(api_wait_requests(nRequests + 1U), "the request reaches the API");

    /* Enough failures that a reconnect would ask the API for another relay - with the same refresh token */
    fix.conn.nReconnectAttempt = 5;
    relay_closed(&fix);
    CHECK(fix.conn.pWsSession == NULL && fix.conn.nNextReconnectMs > 0, "the relay is gone and a reconnect is due");
    CHECK(fix.conn.nNextRefreshProbeMs == 0, "the relay re-probe does not run while a refresh is out");
    CHECK(XSYNC_ATOMIC_GET(&g_api.nRequests) == nRequests + 1, "so no second request carries the same refresh token");

    api_release();
    CHECK(DirectGate_TestFinishTokenRefresh(&fix.conn, WAIT_MS), "the answer is taken with the relay gone");
    CHECK(fix.conn.pRefreshJob == NULL, "and the refresh is over");
    CHECK(!strcmp(fix.cfg.enroll.sRefreshToken, "refresh-rotated"), "the rotated refresh token is applied");
    CHECK(!strcmp(fix.cfg.enroll.sAccessToken, "access-new"), "so is the access token the reconnect will present");
    CHECK(file_has(fix.cfg.sCfgPath, "refresh-rotated"), "and the rotated refresh token reaches the disk");

    fixture_close(&fix);
    return 0;
}

/* An answer to an enrollment that was cleared while the request was out does not bring it back. */
static int test_enrollment_cleared(const char *pRoot, uint16_t nPort)
{
    fixture_t fix;
    fixture_open(&fix, pRoot, nPort);
    uint32_t nRequests = (uint32_t)XSYNC_ATOMIC_GET(&g_api.nRequests);
    api_hold(ANSWER_OK);

    CHECK(DirectGate_TestCheckTokenRefresh(&fix.conn) && fix.conn.pRefreshJob != NULL, "the refresh goes out");
    CHECK(api_wait_requests(nRequests + 1U), "the request reaches the API");

    /* What a terminal disconnect leaves behind */
    fix.cfg.enroll.sAccessToken[0] = '\0';
    fix.cfg.enroll.sRefreshToken[0] = '\0';
    fix.cfg.enroll.nAccessTokenExp = 0;
    fix.cfg.enroll.bEnrolled = XFALSE;
    fix.conn.pWsSession = NULL;
    fix.conn.bReconnectSuppressed = XTRUE;

    api_release();
    CHECK(!DirectGate_TestFinishTokenRefresh(&fix.conn, WAIT_MS), "the answer is not taken as a success");
    CHECK(fix.conn.pRefreshJob == NULL, "the refresh is over");
    CHECK(!fix.cfg.enroll.bEnrolled && fix.cfg.enroll.sAccessToken[0] == '\0' && fix.cfg.enroll.sRefreshToken[0] == '\0',
        "the cleared enrollment stays cleared");

    fixture_close(&fix);
    return 0;
}

/* A refresh out when the agent stops: its answer is waited for and saved, or, past the wait, left behind. */
static int test_shutdown(const char *pRoot, uint16_t nPort)
{
    fixture_t fix;
    fixture_open(&fix, pRoot, nPort);
    uint32_t nRequests = (uint32_t)XSYNC_ATOMIC_GET(&g_api.nRequests);
    api_hold(ANSWER_ROTATED);

    CHECK(DirectGate_TestCheckTokenRefresh(&fix.conn) && fix.conn.pRefreshJob != NULL, "the refresh goes out");
    CHECK(api_wait_requests(nRequests + 1U), "the request reaches the API");

    api_release();
    DirectGate_TestSettleTokenRefresh(&fix.conn, WAIT_MS);
    CHECK(fix.conn.pRefreshJob == NULL, "the stop takes the refresh");
    CHECK(!strcmp(fix.cfg.enroll.sRefreshToken, "refresh-rotated"), "the answer that came in time is applied");
    CHECK(file_has(fix.cfg.sCfgPath, "refresh-rotated"), "and the rotated refresh token is saved for the next start");
    fixture_close(&fix);

    /* An answer that does not come in time is not waited for */
    fixture_open(&fix, pRoot, nPort);
    int nThreads = thread_count();
    nRequests = (uint32_t)XSYNC_ATOMIC_GET(&g_api.nRequests);
    api_hold(ANSWER_OK);

    CHECK(DirectGate_TestCheckTokenRefresh(&fix.conn) && fix.conn.pRefreshJob != NULL, "another refresh goes out");
    CHECK(api_wait_requests(nRequests + 1U), "the request reaches the API");

    uint64_t nStartMs = XTime_GetMonoMs();
    DirectGate_TestSettleTokenRefresh(&fix.conn, 200);
    CHECK(XTime_GetMonoMs() - nStartMs < 5000, "the stop waits only as long as it was given");
    CHECK(fix.conn.pRefreshJob == NULL, "and leaves the request behind");
    CHECK(!strcmp(fix.cfg.enroll.sAccessToken, "access-old"), "nothing is applied without an answer");

    /* The worker frees what it was left with once its request ends */
    api_release();
    uint64_t nDeadlineMs = XTime_GetMonoMs() + WAIT_MS;
    if (nThreads > 0)
    {
        while (thread_count() > nThreads && XTime_GetMonoMs() < nDeadlineMs) xusleep(10000);
        CHECK(thread_count() <= nThreads, "the left-behind worker ends once its answer is in");
    }
    else xusleep(1000000);

    fixture_close(&fix);
    return 0;
}

/* ---- the reconnect ------------------------------------------------------------------------------------ */

/* An enrolled agent whose relay link is gone and whose reconnect is due, with an event loop of its own */
typedef struct {
    directgate_cfg_t cfg;
    directgate_conn_t conn;
    xapi_t api;
    xapi_endpoint_t endpt;
} reconnect_t;

static void reconnect_open(reconnect_t *pRec, const char *pRoot, uint16_t nPort, const char *pRelayUrl)
{
    memset(pRec, 0, sizeof(*pRec));
    directgate_cfg_t *pCfg = &pRec->cfg;
    snprintf(pCfg->sCfgPath, sizeof(pCfg->sCfgPath), "%s/agent.json", pRoot);
    xstrncpy(pCfg->sDeviceId, sizeof(pCfg->sDeviceId), "dev-refresh");
    xstrncpy(pCfg->sRelayUrl, sizeof(pCfg->sRelayUrl), pRelayUrl);
    xstrncpy(pCfg->sRoutingKey, sizeof(pCfg->sRoutingKey), "rk-refresh");
    snprintf(pCfg->enroll.sApiUrl, sizeof(pCfg->enroll.sApiUrl), "https://127.0.0.1:%u", (unsigned)nPort);
    xstrncpy(pCfg->enroll.sAccessToken, sizeof(pCfg->enroll.sAccessToken), "access-old");
    xstrncpy(pCfg->enroll.sRefreshToken, sizeof(pCfg->enroll.sRefreshToken), "refresh-old");
    xstrncpy(pCfg->enroll.sEnrollExpiresAt, sizeof(pCfg->enroll.sEnrollExpiresAt), "2099-01-01T00:00:00Z");
    pCfg->enroll.nAccessTokenExp = (uint64_t)time(NULL) + 3600U;
    pCfg->enroll.nRefreshSkewSec = 120;
    pCfg->enroll.bEnrolled = XTRUE;

    /* A link the agent could not authenticate on is dropped as soon as it is handed over */
    xstrncpy(pCfg->auth.sSaltHex, sizeof(pCfg->auth.sSaltHex),
        "00000000000000000000000000000000"
        "00000000000000000000000000000000");
    xstrncpy(pCfg->auth.sVerifierHex, sizeof(pCfg->auth.sVerifierHex), "configured");

    directgate_conn_t *pConn = &pRec->conn;
    pConn->pCfg = pCfg;
    DirectGate_SessionMgr_Init(&pConn->mgr, pCfg);
    pConn->bStartupRelayRefreshDone = XTRUE;
    pConn->nNextReconnectMs = 1;

    XAPI_Init(&pRec->api, DirectGate_ServiceCallback, pConn);
    XAPI_InitEndpoint(&pRec->endpt);
    pRec->endpt.eType = XAPI_WS;
    pRec->endpt.eRole = XAPI_CLIENT;
    pRec->endpt.pSessionData = pConn;
}

static void reconnect_close(reconnect_t *pRec)
{
    DirectGate_TestDropRelayResolve(&pRec->conn);
    if (pRec->conn.pRefreshJob != NULL) DirectGate_TestSettleTokenRefresh(&pRec->conn, WAIT_MS);
    XAPI_Destroy(&pRec->api);
    DirectGate_SessionMgr_Destroy(&pRec->conn.mgr);
}

/* The relay link reports its far end gone, the way the socket layer does */
static void reconnect_link_lost(reconnect_t *pRec)
{
    static xapi_session_t link;
    memset(&link, 0, sizeof(link));
    link.eRole = XAPI_CLIENT;
    link.pSessionData = &pRec->conn;
    link.sock.nFD = XSOCK_INVALID;
    pRec->conn.pWsSession = &link;
    pRec->conn.nNextReconnectMs = 0;

    xapi_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.eCbType = XAPI_CB_STATUS;
    ctx.eStatType = XAPI_SOCK;
    ctx.nStatus = XSOCK_EOF;
    DirectGate_ServiceCallback(&ctx, &link);
}

/* One reconnect pass, and how long it held the loop */
static uint64_t reconnect_pass(reconnect_t *pRec)
{
    uint64_t nStartMs = XTime_GetMonoMs();
    DirectGate_TestCheckReconnect(&pRec->api, &pRec->endpt, &pRec->conn);
    return XTime_GetMonoMs() - nStartMs;
}

/* Runs the agent's loop until its link is up and its role went out to the relay */
static int reconnect_until_role(reconnect_t *pRec)
{
    uint64_t nDeadlineMs = XTime_GetMonoMs() + WAIT_MS;
    while (!pRec->conn.bRoleSent && pRec->conn.pWsSession != NULL && XTime_GetMonoMs() < nDeadlineMs)
        XAPI_Service(&pRec->api, 20);

    return pRec->conn.bRoleSent;
}

/* The reconnect's refresh goes out on the worker: passes return while the API holds its answer, nothing else asks
   meanwhile, and nothing is dialed until it is in. Then the connect goes with the token it brought, and returns
   before its link is up where the platform allows it. */
static int test_reconnect_refresh(const char *pRoot, uint16_t nPort)
{
    reconnect_t rec;
    reconnect_open(&rec, pRoot, nPort, g_api.sLocalRelayUrl);
    rec.cfg.enroll.nAccessTokenExp = (uint64_t)time(NULL) + 30U;

    uint32_t nRequests = (uint32_t)XSYNC_ATOMIC_GET(&g_api.nRequests);
    uint32_t nAccepts = (uint32_t)XSYNC_ATOMIC_GET(&g_api.nRelayAccepts);
    XSYNC_ATOMIC_SET(&g_api.bLocalRelay, 1);
    api_hold_for(ANSWER_OK, 5000);

    CHECK(reconnect_pass(&rec) < QUICK_MS, "the pass that starts the reconnect does not wait for the API");
    CHECK(rec.conn.pRefreshJob != NULL && rec.conn.eRefreshKind == DIRECTGATE_REFRESH_CONNECT,
        "its refresh is out on the worker");
    CHECK(rec.conn.pWsSession == NULL, "and nothing is dialed before its answer");
    CHECK(api_wait_requests(nRequests + 1U), "the request reaches the API");

    for (int i = 0; i < 3; i++) CHECK(reconnect_pass(&rec) < QUICK_MS, "a pass while it is out returns at once");
    CHECK((uint32_t)XSYNC_ATOMIC_GET(&g_api.nRequests) == nRequests + 1U, "no second request goes out meanwhile");
    CHECK(rec.conn.pWsSession == NULL && (uint32_t)XSYNC_ATOMIC_GET(&g_api.nRelayAccepts) == nAccepts,
        "the relay is not dialed before the answer is in");

    api_release();
    CHECK(DirectGate_TestCollectReconnect(&rec.conn, WAIT_MS), "a later pass takes the answer");
    CHECK(rec.conn.pRefreshJob == NULL && rec.conn.bConnectRefreshed, "and lets the connect go on");
    CHECK(!strcmp(rec.cfg.enroll.sAccessToken, "access-new"), "with the token the answer brought");

    CHECK(reconnect_pass(&rec) < QUICK_MS, "the connect returns before the link is up");
    CHECK(rec.conn.pResolveJob == NULL, "a numeric relay host is not looked up");
    CHECK(rec.conn.pWsSession != NULL && !rec.conn.bConnectRefreshed, "the link is under way, its refresh used up");
#ifdef __linux__
    CHECK(XFLAGS_CHECK(rec.conn.pWsSession->sock.nFlags, XSOCK_ASYNC), "TCP and TLS finish on the loop");
#endif
    CHECK((uint32_t)XSYNC_ATOMIC_GET(&g_api.nRequests) == nRequests + 1U, "the connect asks the API nothing more");

    CHECK(reconnect_until_role(&rec), "the link comes up and the agent announces itself");
    char sHost[64];
    snprintf(sHost, sizeof(sHost), "127.0.0.1:%u", (unsigned)g_api.nRelayPort);
    CHECK(!strcmp(g_api.sRelayHost, sHost), "to the relay it was told to use");

    XSYNC_ATOMIC_SET(&g_api.bLocalRelay, 0);
    reconnect_close(&rec);
    return 0;
}

/* How the reconnect's refresh ends: a failure that leaves a good token connects with it, one that leaves none waits
   for the next attempt, and a revocation stops the reconnects. None of them dials before the answer. */
static int test_reconnect_answers(const char *pRoot, uint16_t nPort)
{
    reconnect_t rec;
    reconnect_open(&rec, pRoot, nPort, g_api.sLocalRelayUrl);
    rec.cfg.enroll.nAccessTokenExp = (uint64_t)time(NULL) + 30U;
    api_hold_for(ANSWER_DOWN, 0);
    api_release();

    reconnect_pass(&rec);
    CHECK(rec.conn.pRefreshJob != NULL, "the refresh goes out");
    CHECK(DirectGate_TestCollectReconnect(&rec.conn, WAIT_MS), "the API's failure is taken");
    CHECK(rec.conn.bConnectRefreshed && !strcmp(rec.cfg.enroll.sAccessToken, "access-old"),
        "a token still good is kept and the connect goes on with it");
    CHECK(rec.conn.nReconnectAttempt == 0 && !rec.conn.bReconnectSuppressed, "nothing is rescheduled");
    reconnect_close(&rec);

    reconnect_open(&rec, pRoot, nPort, g_api.sLocalRelayUrl);
    rec.cfg.enroll.nAccessTokenExp = (uint64_t)time(NULL) - 10U;
    reconnect_pass(&rec);
    CHECK(rec.conn.pRefreshJob != NULL, "an expired token is refreshed first");
    CHECK(DirectGate_TestCollectReconnect(&rec.conn, WAIT_MS), "the failure is taken");
    CHECK(!rec.conn.bConnectRefreshed && rec.conn.nReconnectAttempt == 1, "with no good token left the attempt fails");
    CHECK(rec.conn.nNextReconnectMs > XTime_GetMonoMs() && !rec.conn.bReconnectSuppressed, "and the next one is scheduled");
    reconnect_pass(&rec);
    CHECK(rec.conn.pRefreshJob == NULL && rec.conn.pWsSession == NULL, "nothing happens before it is due");
    reconnect_close(&rec);

    reconnect_open(&rec, pRoot, nPort, g_api.sLocalRelayUrl);
    rec.conn.bStartupRelayRefreshDone = XFALSE;
    api_hold_for(ANSWER_REVOKED, 0);
    api_release();
    reconnect_pass(&rec);
    CHECK(rec.conn.pRefreshJob != NULL && rec.conn.bStartupRelayRefreshDone, "a link that existed has the API asked first");
    CHECK(DirectGate_TestCollectReconnect(&rec.conn, WAIT_MS), "the revocation is taken");
    CHECK(rec.conn.bReconnectSuppressed && !rec.cfg.enroll.bEnrolled, "a revocation stops the reconnects");
    reconnect_pass(&rec);
    CHECK(rec.conn.pRefreshJob == NULL && rec.conn.pWsSession == NULL, "and nothing is dialed after it");
    reconnect_close(&rec);

    api_hold_for(ANSWER_OK, 0);
    api_release();
    return 0;
}

/* The relay host's name is looked up on a worker. The connect dials the address it found while the name still goes
   into TLS and the upgrade, and a name that does not resolve fails the attempt without dialing anything. */
static int test_reconnect_lookup(const char *pRoot, uint16_t nPort)
{
    char sUrl[128];
    snprintf(sUrl, sizeof(sUrl), "wss://localhost:%u/websock", (unsigned)g_api.nRelayPort);

    reconnect_t rec;
    reconnect_open(&rec, pRoot, nPort, sUrl);
    uint32_t nRequests = (uint32_t)XSYNC_ATOMIC_GET(&g_api.nRequests);

    CHECK(reconnect_pass(&rec) < QUICK_MS, "the pass that starts the lookup returns at once");
    CHECK(rec.conn.pRefreshJob == NULL && rec.conn.pResolveJob != NULL, "a fresh token needs no refresh, the host a lookup");
    CHECK(rec.conn.pWsSession == NULL, "nothing is dialed before the address is in");
    directgate_resolve_job_t *pLookup = rec.conn.pResolveJob;
    reconnect_pass(&rec);
    CHECK(rec.conn.pResolveJob == pLookup && rec.conn.pWsSession == NULL, "a pass while it is out starts nothing more");
    CHECK(DirectGate_TestCollectReconnect(&rec.conn, WAIT_MS), "a later pass takes the address");
    CHECK(!strcmp(rec.conn.sRelayHost, "localhost") && !strcmp(rec.conn.sRelayIPAddr, "127.0.0.1"),
        "the address the connect would have looked up itself");

    CHECK(reconnect_pass(&rec) < QUICK_MS && rec.conn.pWsSession != NULL, "the connect goes to it");
    CHECK(rec.conn.pResolveJob == NULL && rec.conn.sRelayIPAddr[0] == '\0', "the address serves this one attempt");
    CHECK(!strcmp(rec.conn.pWsSession->sAddr, "localhost"), "the link keeps the name");
    CHECK(reconnect_until_role(&rec), "TLS verified for the name lets the link come up");

    char sHost[64];
    snprintf(sHost, sizeof(sHost), "localhost:%u", (unsigned)g_api.nRelayPort);
    CHECK(!strcmp(g_api.sRelayHost, sHost), "the upgrade names the host, not the address");
    CHECK((uint32_t)XSYNC_ATOMIC_GET(&g_api.nRequests) == nRequests, "and the API was not asked");
    reconnect_close(&rec);

    snprintf(sUrl, sizeof(sUrl), "wss://dg-relay..invalid:%u/websock", (unsigned)g_api.nRelayPort);
    reconnect_open(&rec, pRoot, nPort, sUrl);
    uint32_t nAccepts = (uint32_t)XSYNC_ATOMIC_GET(&g_api.nRelayAccepts);

    reconnect_pass(&rec);
    CHECK(rec.conn.pResolveJob != NULL, "a host that will not resolve is looked up on the worker too");
    CHECK(DirectGate_TestCollectReconnect(&rec.conn, WAIT_MS), "its failure is taken");
    CHECK(rec.conn.pWsSession == NULL && rec.conn.sRelayIPAddr[0] == '\0', "nothing is dialed");
    CHECK(!rec.conn.bConnectRefreshed, "and the next attempt starts over with its own refresh check");
    CHECK(rec.conn.nReconnectAttempt == 1 && rec.conn.nNextReconnectMs > XTime_GetMonoMs(),
        "the attempt fails and another is due");
    CHECK((uint32_t)XSYNC_ATOMIC_GET(&g_api.nRelayAccepts) == nAccepts, "and the relay never heard of it");

    /* An address in hand for the host is dialed as it is: this name would not resolve, so only it reaches the relay */
    rec.conn.nNextReconnectMs = 1;
    xstrncpy(rec.conn.sRelayHost, sizeof(rec.conn.sRelayHost), "dg-relay..invalid");
    xstrncpy(rec.conn.sRelayIPAddr, sizeof(rec.conn.sRelayIPAddr), "127.0.0.1");
    reconnect_pass(&rec);
    CHECK(rec.conn.pResolveJob == NULL && rec.conn.pWsSession != NULL, "the address found is the one dialed");

    uint64_t nDeadlineMs = XTime_GetMonoMs() + WAIT_MS;
    while ((uint32_t)XSYNC_ATOMIC_GET(&g_api.nRelayAccepts) == nAccepts && rec.conn.pWsSession != NULL &&
        XTime_GetMonoMs() < nDeadlineMs) XAPI_Service(&rec.api, 20);
    CHECK((uint32_t)XSYNC_ATOMIC_GET(&g_api.nRelayAccepts) > nAccepts, "and it reaches the relay");
    while (rec.conn.pWsSession != NULL && XTime_GetMonoMs() < nDeadlineMs) XAPI_Service(&rec.api, 20);
    CHECK(rec.conn.pWsSession == NULL && !rec.conn.bRoleSent, "where TLS still holds it to the name it lacks");
    reconnect_close(&rec);
    return 0;
}

/* A relay that refuses the connect is not a link that existed: the next attempt does not ask the API first, as
   when a connect in-line failed before ever handing a link over. */
static int test_reconnect_refused(const char *pRoot, uint16_t nPort)
{
    char sUrl[128];
    uint16_t nClosed = reserve_port();
    CHECK(nClosed != 0, "reserve a port nothing listens on");
    snprintf(sUrl, sizeof(sUrl), "wss://127.0.0.1:%u/websock", (unsigned)nClosed);

    reconnect_t rec;
    reconnect_open(&rec, pRoot, nPort, sUrl);
    uint32_t nRequests = (uint32_t)XSYNC_ATOMIC_GET(&g_api.nRequests);

    reconnect_pass(&rec);
    uint64_t nDeadlineMs = XTime_GetMonoMs() + WAIT_MS;
    while (rec.conn.pWsSession != NULL && XTime_GetMonoMs() < nDeadlineMs) XAPI_Service(&rec.api, 20);

    CHECK(rec.conn.pWsSession == NULL && rec.conn.nReconnectAttempt == 1, "the refused attempt fails");
    CHECK(rec.conn.nNextReconnectMs > XTime_GetMonoMs(), "and another is scheduled");
    CHECK(rec.conn.bStartupRelayRefreshDone, "without the next one asking the API first");
    CHECK((uint32_t)XSYNC_ATOMIC_GET(&g_api.nRequests) == nRequests, "nor was the API asked");

    /* Loopback refuses at once, inside the connect. A remote relay refuses later, after the async link was handed
       over and before it ever connected: that link did not exist either. */
    xapi_session_t link;
    memset(&link, 0, sizeof(link));
    link.eRole = XAPI_CLIENT;
    link.pSessionData = &rec.conn;
    link.sock.nFD = XSOCK_INVALID;
    link.sock.nFlags = XSOCK_ASYNC;

    xapi_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.eCbType = XAPI_CB_CONNECTED;
    CHECK(DirectGate_ServiceCallback(&ctx, &link) == XAPI_CONTINUE && rec.conn.pWsSession == &link,
        "an async link is handed over while it connects");
    CHECK(rec.conn.bStartupRelayRefreshDone, "and is not yet a link that existed");

    ctx.eCbType = XAPI_CB_CLOSED;
    DirectGate_ServiceCallback(&ctx, &link);
    CHECK(rec.conn.pWsSession == NULL && rec.conn.bStartupRelayRefreshDone, "so losing it has the next attempt not ask the API");
    reconnect_close(&rec);
    return 0;
}

/* The relay re-probe goes out on the worker too, and the reconnect waits for it: two requests with one refresh
   token read as reuse. A relay it names that is not the one asked about is taken, and tried at the base delay. */
static int test_reconnect_reprobe(const char *pRoot, uint16_t nPort)
{
    reconnect_t rec;
    reconnect_open(&rec, pRoot, nPort, RELAY_URL);
    rec.conn.nReconnectAttempt = 5;

    uint32_t nRequests = (uint32_t)XSYNC_ATOMIC_GET(&g_api.nRequests);
    XSYNC_ATOMIC_SET(&g_api.bLocalRelay, 1);
    api_hold_for(ANSWER_OK, 5000);

    uint64_t nStartMs = XTime_GetMonoMs();
    reconnect_link_lost(&rec);
    CHECK(XTime_GetMonoMs() - nStartMs < QUICK_MS, "losing the relay does not wait for the API");
    CHECK(rec.conn.pRefreshJob != NULL && rec.conn.eRefreshKind == DIRECTGATE_REFRESH_REPROBE, "the re-probe is out");
    CHECK(api_wait_requests(nRequests + 1U), "the re-probe reaches the API");

    rec.conn.nNextReconnectMs = 1;
    CHECK(reconnect_pass(&rec) < QUICK_MS, "a reconnect that is due returns at once");
    CHECK(rec.conn.eRefreshKind == DIRECTGATE_REFRESH_REPROBE && rec.conn.pWsSession == NULL, "and waits for the re-probe");
    CHECK((uint32_t)XSYNC_ATOMIC_GET(&g_api.nRequests) == nRequests + 1U, "without a refresh of its own");

    api_release();
    CHECK(DirectGate_TestCollectReconnect(&rec.conn, WAIT_MS), "the re-probe's answer is taken");
    nStartMs = XTime_GetMonoMs();
    CHECK(!strcmp(rec.cfg.sRelayUrl, g_api.sLocalRelayUrl), "the relay it names is taken");
    CHECK(rec.conn.nReconnectAttempt == 1 && rec.conn.nNextReconnectMs <= nStartMs + 3000U,
        "and tried at the base delay from the answer");

    XSYNC_ATOMIC_SET(&g_api.bLocalRelay, 0);
    reconnect_close(&rec);
    return 0;
}

/* The pre-role refresh never runs in-line: a token that is only due goes with the upgrade and the API is not asked
   on the loop, and one that has run out ends the attempt so the reconnect refreshes first. */
static int test_pre_role(const char *pRoot, uint16_t nPort)
{
    reconnect_t rec;
    reconnect_open(&rec, pRoot, nPort, RELAY_URL);
    rec.cfg.enroll.nAccessTokenExp = (uint64_t)time(NULL) + 30U;
    uint32_t nRequests = (uint32_t)XSYNC_ATOMIC_GET(&g_api.nRequests);
    api_hold_for(ANSWER_OK, 3000);

    xapi_session_t link;
    memset(&link, 0, sizeof(link));
    link.eRole = XAPI_CLIENT;
    link.pSessionData = &rec.conn;
    link.sock.nFD = XSOCK_INVALID;

    xhttp_t request;
    XHTTP_InitRequest(&request, XHTTP_GET, "/websock", NULL);
    link.pPacket = &request;

    xapi_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.eCbType = XAPI_CB_HANDSHAKE_REQUEST;

    uint64_t nStartMs = XTime_GetMonoMs();
    int nStatus = DirectGate_ServiceCallback(&ctx, &link);
    CHECK(XTime_GetMonoMs() - nStartMs < QUICK_MS, "the upgrade does not wait for the API");
    CHECK(nStatus == XAPI_CONTINUE && strstr(request.sUri, "rk=rk-refresh") != NULL, "a token that is only due goes with it");
    CHECK(!rec.conn.bStartupRelayRefreshDone, "a link that got this far has the next connect ask the API first");
    XHTTP_Clear(&request);

    rec.cfg.enroll.nAccessTokenExp = 0;
    XHTTP_InitRequest(&request, XHTTP_GET, "/websock", NULL);
    link.pPacket = &request;
    CHECK(DirectGate_ServiceCallback(&ctx, &link) == XAPI_CONTINUE, "a token with no known expiry goes as it did");
    XHTTP_Clear(&request);

    rec.cfg.enroll.nAccessTokenExp = (uint64_t)time(NULL) - 10U;
    XHTTP_InitRequest(&request, XHTTP_GET, "/websock", NULL);
    link.pPacket = &request;
    CHECK(DirectGate_ServiceCallback(&ctx, &link) == XAPI_DISCONNECT, "an expired token ends the attempt");
    CHECK(!strcmp(rec.conn.sDisconnectReason, "access token expired"), "and says why");
    CHECK((uint32_t)XSYNC_ATOMIC_GET(&g_api.nRequests) == nRequests, "neither asked the API");
    XHTTP_Clear(&request);

    api_release();
    reconnect_close(&rec);
    return 0;
}

/* The first connect runs before the loop, where nothing is waiting on it, and stays in-line. A re-probe its failures
   sent out on the worker is waited for there, and its answer is what the next attempt connects to. */
static int test_initial_connect(const char *pRoot, uint16_t nPort)
{
    reconnect_t rec;
    reconnect_open(&rec, pRoot, nPort, RELAY_URL);
    rec.conn.nReconnectAttempt = 5;

    uint32_t nRequests = (uint32_t)XSYNC_ATOMIC_GET(&g_api.nRequests);
    XSYNC_ATOMIC_SET(&g_api.bLocalRelay, 1);
    api_hold_for(ANSWER_OK, 300);

    reconnect_link_lost(&rec);
    CHECK(rec.conn.pRefreshJob != NULL && rec.conn.eRefreshKind == DIRECTGATE_REFRESH_REPROBE, "a re-probe is out");

    DirectGate_TestInitialConnect(&rec.api, &rec.endpt, &rec.conn);
    CHECK(rec.conn.pRefreshJob == NULL, "the startup loop takes the re-probe's answer");
    CHECK(!strcmp(rec.cfg.sRelayUrl, g_api.sLocalRelayUrl), "and connects to the relay it named");
    CHECK(rec.conn.pWsSession != NULL && !XFLAGS_CHECK(rec.conn.pWsSession->sock.nFlags, XSOCK_ASYNC),
        "the first connect is still made in-line");
    CHECK(!rec.conn.bStartupRelayRefreshDone, "and a link handed over connected has the next connect ask the API first");
    CHECK((uint32_t)XSYNC_ATOMIC_GET(&g_api.nRequests) == nRequests + 1U, "with the API asked once");
    CHECK(reconnect_until_role(&rec), "and the link comes up");

    XSYNC_ATOMIC_SET(&g_api.bLocalRelay, 0);
    reconnect_close(&rec);
    return 0;
}

/* A lookup still out when the agent stops is left to its worker, which frees it; one that is over is freed at once */
static int test_lookup_dropped(const char *pRoot, uint16_t nPort)
{
    char sUrl[128];
    snprintf(sUrl, sizeof(sUrl), "wss://localhost:%u/websock", (unsigned)g_api.nRelayPort);
    int nThreads = thread_count();

    reconnect_t rec;
    reconnect_open(&rec, pRoot, nPort, sUrl);
    reconnect_pass(&rec);
    CHECK(rec.conn.pResolveJob != NULL, "a lookup is out");
    DirectGate_TestDropRelayResolve(&rec.conn);
    CHECK(rec.conn.pResolveJob == NULL, "the stop lets go of it");

    uint64_t nDeadlineMs = XTime_GetMonoMs() + WAIT_MS;
    if (nThreads > 0)
    {
        while (thread_count() > nThreads && XTime_GetMonoMs() < nDeadlineMs) xusleep(10000);
        CHECK(thread_count() <= nThreads, "the worker ends on its own");
    }
    else xusleep(500000);

    rec.conn.sRelayIPAddr[0] = '\0';
    reconnect_pass(&rec);
    CHECK(rec.conn.pResolveJob != NULL, "another lookup is out");
    if (nThreads > 0)
    {
        while (thread_count() > nThreads && XTime_GetMonoMs() < nDeadlineMs) xusleep(10000);
        CHECK(thread_count() <= nThreads, "and over");
    }
    else xusleep(500000);

    DirectGate_TestDropRelayResolve(&rec.conn);
    CHECK(rec.conn.pResolveJob == NULL, "one that is over is let go of as well");
    reconnect_close(&rec);
    return 0;
}

/* What a refresh refuses before anything is sent, the same as the in-line one does. */
static int test_refusals(const char *pRoot, uint16_t nPort)
{
    fixture_t fix;
    fixture_open(&fix, pRoot, nPort);
    uint32_t nRequests = (uint32_t)XSYNC_ATOMIC_GET(&g_api.nRequests);
    char sReason[XSTR_TINY];
    directgate_enroll_status_t eStatus = DIRECTGATE_ENROLL_REFRESH_OK;

    xstrncpy(fix.cfg.enroll.sApiUrl, sizeof(fix.cfg.enroll.sApiUrl), "http://127.0.0.1:1");
    CHECK(DirectGate_Enroll_StartRefresh(&fix.cfg, &eStatus, sReason, sizeof(sReason)) == NULL &&
        eStatus == DirectGate_Enroll_Refresh(&fix.cfg, sReason, sizeof(sReason)),
        "an API endpoint the build does not allow is refused up front, as the in-line refresh refuses it");

    fix.cfg.enroll.sRefreshToken[0] = '\0';
    CHECK(DirectGate_Enroll_StartRefresh(&fix.cfg, &eStatus, sReason, sizeof(sReason)) == NULL &&
        eStatus == DIRECTGATE_ENROLL_REFRESH_TERMINAL, "no refresh token is final");

    fix.cfg.enroll.bEnrolled = XFALSE;
    CHECK(DirectGate_Enroll_StartRefresh(&fix.cfg, &eStatus, sReason, sizeof(sReason)) == NULL &&
        eStatus == DIRECTGATE_ENROLL_REFRESH_TERMINAL, "so is no enrollment");

    CHECK((uint32_t)XSYNC_ATOMIC_GET(&g_api.nRequests) == nRequests, "none of them reached the API");
    fixture_close(&fix);
    return 0;
}

int main(void)
{
    memset(&g_api, 0, sizeof(g_api));

    tls_fixture_t tls;
    CHECK(tls_fixture_begin(&tls), "create a TLS identity for the API");
    setenv("SSL_CERT_FILE", tls.sCert, 1);
    unsetenv("SSL_CERT_DIR");

    char sRoot[] = "/tmp/directgate_refresh.XXXXXX";
    CHECK(mkdtemp(sRoot) != NULL, "create a working directory");

    uint16_t nPort = reserve_port();
    CHECK(nPort != 0, "reserve a local port");
    g_api.nRelayPort = reserve_port();
    CHECK(g_api.nRelayPort != 0 && g_api.nRelayPort != nPort, "reserve a port for the relay");
    snprintf(g_api.sLocalRelayUrl, sizeof(g_api.sLocalRelayUrl), "wss://127.0.0.1:%u/websock", (unsigned)g_api.nRelayPort);
    g_api.nBaseMs = XTime_GetMonoMs();

    XAPI_Init(&g_api.api, api_callback, &g_api);
    xapi_endpoint_t endpt;
    XAPI_InitEndpoint(&endpt);
    endpt.eType = XAPI_HTTP;
    endpt.eRole = XAPI_SERVER;
    endpt.pAddr = "127.0.0.1";
    endpt.nPort = nPort;
    endpt.bTLS = XTRUE;
    endpt.bForce = XTRUE;
    endpt.certs.pCertPath = tls.sCert;
    endpt.certs.pKeyPath = tls.sKey;
    CHECK(XAPI_AddEndpoint(&g_api.api, &endpt) >= 0, "start the API");

    XAPI_InitEndpoint(&endpt);
    endpt.eType = XAPI_WS;
    endpt.eRole = XAPI_SERVER;
    endpt.pAddr = "127.0.0.1";
    endpt.nPort = g_api.nRelayPort;
    endpt.pUri = "/websock";
    endpt.bTLS = XTRUE;
    endpt.bForce = XTRUE;
    endpt.certs.pCertPath = tls.sCert;
    endpt.certs.pKeyPath = tls.sKey;
    CHECK(XAPI_AddEndpoint(&g_api.api, &endpt) >= 0, "start the relay");

    xthread_t thread;
    CHECK(XThread_Create(&thread, api_thread, NULL, XFALSE) == XSTDOK, "start the API thread");

    int nResult = test_off_the_loop(sRoot, nPort);
    if (!nResult) nResult = test_relay_lost(sRoot, nPort);
    if (!nResult) nResult = test_enrollment_cleared(sRoot, nPort);
    if (!nResult) nResult = test_shutdown(sRoot, nPort);
    if (!nResult) nResult = test_refusals(sRoot, nPort);
    if (!nResult) nResult = test_reconnect_refresh(sRoot, nPort);
    if (!nResult) nResult = test_reconnect_answers(sRoot, nPort);
    if (!nResult) nResult = test_reconnect_lookup(sRoot, nPort);
    if (!nResult) nResult = test_reconnect_refused(sRoot, nPort);
    if (!nResult) nResult = test_reconnect_reprobe(sRoot, nPort);
    if (!nResult) nResult = test_pre_role(sRoot, nPort);
    if (!nResult) nResult = test_initial_connect(sRoot, nPort);
    if (!nResult) nResult = test_lookup_dropped(sRoot, nPort);

    XSYNC_ATOMIC_SET(&g_api.bStop, 1);
    XThread_Join(&thread);
    XAPI_Destroy(&g_api.api);

    char sPath[128];
    snprintf(sPath, sizeof(sPath), "%s/agent.json", sRoot);
    unlink(sPath);
    snprintf(sPath, sizeof(sPath), "%s/agent.json.tmp", sRoot);
    unlink(sPath);
    rmdir(sRoot);
    tls_fixture_end(&tls);

    if (!nResult) puts("token_refresh_smoke: OK");
    return nResult;
}
