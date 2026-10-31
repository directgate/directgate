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
 * The API is a real HTTPS endpoint in this process that can hold its answer.
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
#define WAIT_MS         20000U

int DirectGate_ServiceCallback(xapi_ctx_t *pCtx, xapi_session_t *pApiSession);

typedef struct {
    xapi_t api;
    xatomic_t bStop;
    xatomic_t nRequests;
    xatomic_t nAnswer;
    xatomic_t bHold;        /* keep the answer back until released */
    xatomic_t bRelease;
    xapi_session_t *pHeld;  /* API thread only */
} api_t;

static api_t g_api;

static int api_answer(xapi_session_t *pSession)
{
    char sBody[1024];
    if (XSYNC_ATOMIC_GET(&g_api.nAnswer) == ANSWER_ROTATED)
        snprintf(sBody, sizeof(sBody),
            "{\"accessToken\":\"access-new\",\"refreshTokenRotated\":true,\"refreshToken\":\"refresh-rotated\","
            "\"refreshTokenExpiresAt\":\"2099-01-01T00:00:00Z\",\"accessTokenExpiresIn\":3600,"
            "\"enrollmentExpiresAt\":\"2099-01-01T00:00:00Z\",\"relayUrl\":\"%s\",\"routingKey\":\"rk-refresh\","
            "\"deviceId\":\"dev-refresh\"}", RELAY_URL);
    else
        snprintf(sBody, sizeof(sBody),
            "{\"accessToken\":\"access-new\",\"refreshTokenRotated\":false,\"accessTokenExpiresIn\":3600,"
            "\"enrollmentExpiresAt\":\"2099-01-01T00:00:00Z\",\"relayUrl\":\"%s\",\"routingKey\":\"rk-refresh\","
            "\"deviceId\":\"dev-refresh\"}", RELAY_URL);

    xhttp_t handle;
    if (XHTTP_InitResponse(&handle, 200, NULL) <= 0) return XAPI_DISCONNECT;
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

static int api_callback(xapi_ctx_t *pCtx, xapi_session_t *pSession)
{
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
    XSYNC_ATOMIC_SET(&g_api.bHold, 0);
    XSYNC_ATOMIC_SET(&g_api.bRelease, 1);
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

    xthread_t thread;
    CHECK(XThread_Create(&thread, api_thread, NULL, XFALSE) == XSTDOK, "start the API thread");

    int nResult = test_off_the_loop(sRoot, nPort);
    if (!nResult) nResult = test_relay_lost(sRoot, nPort);
    if (!nResult) nResult = test_enrollment_cleared(sRoot, nPort);
    if (!nResult) nResult = test_shutdown(sRoot, nPort);
    if (!nResult) nResult = test_refusals(sRoot, nPort);

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
