/*
 * The agent asking the API for another relay when the one it has keeps failing.
 *
 * After enough failed reconnects the relay the agent knows may simply be gone,
 * and the API, asked again, can hand out a different one. The agent then has
 * to take it and start its backoff over, so the new relay is tried at once. It
 * must not ask more often than the probe gap allows, a failed ask must not stop
 * the reconnects, and the same relay handed back again is not a migration.
 *
 * The API is a real HTTPS endpoint in this process; the reconnects are driven
 * through the agent's own service callback, the way the socket layer reports a
 * relay that closed. The same callback's tick pumps downloads, checked here as
 * well: chunks go while the relay socket takes them and wait while it is full.
 */

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "src/agent/directgate.h"
#include "src/agent/files.h"
#include "src/common/common.h"

#include "tls_fixture.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "relay_reprobe_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

#define FIRST_RELAY  "wss://relay1.example.test/websock"
#define SECOND_RELAY "wss://relay2.example.test/websock"

int DirectGate_ServiceCallback(xapi_ctx_t *pCtx, xapi_session_t *pApiSession);

typedef struct {
    xapi_t api;
    xatomic_t bStop;
    xatomic_t nRefreshes;
    xatomic_t nCode;          /* what the refresh answers with */
    char sRelayUrl[128];      /* the relay it names */
} api_t;

static api_t g_api;

static int api_request(xapi_session_t *pSession)
{
    xhttp_t *pHandle = (xhttp_t*)pSession->pPacket;
    if (pHandle == NULL || strcmp(pHandle->sUri, "/api/v1/devices/refresh") != 0) return XAPI_DISCONNECT;
    XSYNC_ATOMIC_ADD(&g_api.nRefreshes, 1);

    char sBody[1024];
    uint16_t nCode = (uint16_t)XSYNC_ATOMIC_GET(&g_api.nCode);
    if (nCode == 200)
        snprintf(sBody, sizeof(sBody),
            "{\"accessToken\":\"access-new\",\"refreshTokenRotated\":false,\"accessTokenExpiresIn\":3600,"
            "\"enrollmentExpiresAt\":\"2099-01-01T00:00:00Z\",\"relayUrl\":\"%s\",\"routingKey\":\"rk-reprobe\","
            "\"deviceId\":\"dev-reprobe\"}", g_api.sRelayUrl);
    else
        snprintf(sBody, sizeof(sBody), "{\"message\":\"the registry is having a moment\"}");

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

static int api_callback(xapi_ctx_t *pCtx, xapi_session_t *pSession)
{
    switch (pCtx->eCbType)
    {
        case XAPI_CB_ACCEPTED: return XAPI_SetEvents(pSession, XPOLLIN);
        case XAPI_CB_READ: return api_request(pSession);
        case XAPI_CB_COMPLETE: return XAPI_DISCONNECT;
        default: break;
    }

    return XAPI_CONTINUE;
}

static void* api_thread(void *pArg)
{
    (void)pArg;
    while (!XSYNC_ATOMIC_GET(&g_api.bStop)) XAPI_Service(&g_api.api, 20);
    return NULL;
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

/* The relay socket reports that the far end went away. */
static void relay_closed(directgate_conn_t *pConn, xapi_session_t *pRelay)
{
    memset(pRelay, 0, sizeof(*pRelay));
    pRelay->eRole = XAPI_CLIENT;
    pRelay->pSessionData = pConn;
    pRelay->sock.nFD = XSOCK_INVALID;
    pConn->pWsSession = pRelay;
    pConn->nNextReconnectMs = 0;

    xapi_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.eCbType = XAPI_CB_STATUS;
    ctx.eStatType = XAPI_SOCK;
    ctx.nStatus = XSOCK_EOF;
    DirectGate_ServiceCallback(&ctx, pRelay);
}

static int run(const char *pRoot, uint16_t nPort)
{
    directgate_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.sCfgPath, sizeof(cfg.sCfgPath), "%s/agent.json", pRoot);
    xstrncpy(cfg.sDeviceId, sizeof(cfg.sDeviceId), "dev-reprobe");
    xstrncpy(cfg.sRelayUrl, sizeof(cfg.sRelayUrl), FIRST_RELAY);
    xstrncpy(cfg.sRoutingKey, sizeof(cfg.sRoutingKey), "rk-reprobe");
    snprintf(cfg.enroll.sApiUrl, sizeof(cfg.enroll.sApiUrl), "https://127.0.0.1:%u", (unsigned)nPort);
    xstrncpy(cfg.enroll.sAccessToken, sizeof(cfg.enroll.sAccessToken), "access-old");
    xstrncpy(cfg.enroll.sRefreshToken, sizeof(cfg.enroll.sRefreshToken), "refresh-reprobe");
    xstrncpy(cfg.enroll.sEnrollExpiresAt, sizeof(cfg.enroll.sEnrollExpiresAt), "2099-01-01T00:00:00Z");
    cfg.enroll.bEnrolled = XTRUE;
    cfg.enroll.nRefreshSkewSec = 60;

    directgate_conn_t conn;
    memset(&conn, 0, sizeof(conn));
    conn.pCfg = &cfg;
    DirectGate_SessionMgr_Init(&conn.mgr, &cfg);
    xapi_session_t relay;

    /* A few failures are just reconnects: the API is not asked. */
    relay_closed(&conn, &relay);
    CHECK(conn.nReconnectAttempt == 1 && XSYNC_ATOMIC_GET(&g_api.nRefreshes) == 0,
        "the first failures only schedule reconnects");

    /* Enough of them, and the API is asked for a relay; a different one is taken at once. */
    XSYNC_ATOMIC_SET(&g_api.nCode, 200);
    xstrncpy(g_api.sRelayUrl, sizeof(g_api.sRelayUrl), SECOND_RELAY);
    conn.nReconnectAttempt = 5;
    relay_closed(&conn, &relay);
    CHECK(XSYNC_ATOMIC_GET(&g_api.nRefreshes) == 1, "after enough failed reconnects the API is asked again");
    CHECK(strcmp(cfg.sRelayUrl, SECOND_RELAY) == 0, "the relay the API hands out is the one used next");
    CHECK(conn.nReconnectAttempt == 1, "a new relay starts the backoff over, so it is tried at once");

    /* Not again inside the probe gap, however many failures pile up. */
    conn.nReconnectAttempt = 9;
    relay_closed(&conn, &relay);
    CHECK(XSYNC_ATOMIC_GET(&g_api.nRefreshes) == 1, "the API is not asked again inside the probe gap");
    CHECK(conn.nReconnectAttempt == 10, "inside the gap the reconnects simply go on");

    /* A failed ask changes nothing: the reconnects go on with the relay there is. */
    XSYNC_ATOMIC_SET(&g_api.nCode, 503);
    conn.nNextRefreshProbeMs = 0;
    relay_closed(&conn, &relay);
    CHECK(XSYNC_ATOMIC_GET(&g_api.nRefreshes) == 2, "after the gap the API is asked again");
    CHECK(strcmp(cfg.sRelayUrl, SECOND_RELAY) == 0 && conn.nReconnectAttempt == 11,
        "a failed ask keeps the relay and the backoff");

    /* The same relay handed back is not a migration. */
    XSYNC_ATOMIC_SET(&g_api.nCode, 200);
    conn.nNextRefreshProbeMs = 0;
    relay_closed(&conn, &relay);
    CHECK(XSYNC_ATOMIC_GET(&g_api.nRefreshes) == 3, "the API is asked once more after the gap");
    CHECK(conn.nReconnectAttempt == 12, "the same relay handed back does not restart the backoff");

    /* A connection that is not the relay's own is never taken for it. */
    xapi_session_t other;
    memset(&other, 0, sizeof(other));
    other.eRole = XAPI_CUSTOM;
    other.sock.nFD = XSOCK_INVALID;
    xapi_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.eCbType = XAPI_CB_ERROR;
    ctx.eStatType = XAPI_SOCK;
    ctx.nStatus = XSOCK_ERR_READ;
    CHECK(DirectGate_ServiceCallback(&ctx, &other) == XAPI_CONTINUE, "an error on another endpoint is only logged");
    ctx.eCbType = XAPI_CB_WRITE;
    CHECK(DirectGate_ServiceCallback(&ctx, &relay) == XAPI_NO_ACTION, "a relay ready to write needs nothing from the agent");

    DirectGate_SessionMgr_Destroy(&conn.mgr);
    return 0;
}

/* The relay URL the API handed out is checked before anything connects to it. */
static int test_relay_targets(void)
{
    directgate_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    xstrncpy(cfg.sRoutingKey, sizeof(cfg.sRoutingKey), "rk-target");
    xstrncpy(cfg.enroll.sAccessToken, sizeof(cfg.enroll.sAccessToken), "access-target");

    directgate_conn_t conn;
    memset(&conn, 0, sizeof(conn));
    conn.pCfg = &cfg;

    xstrncpy(cfg.sRelayUrl, sizeof(cfg.sRelayUrl), "wss://relay.example.test:8443/websock");
    CHECK(DirectGate_TestPrepareEndpoint(&conn), "a wss relay is taken");
    CHECK(conn.relayLink.nPort == 8443 && strcmp(conn.relayLink.sAddr, "relay.example.test") == 0, "its host and port are used");

    static const char *pRefused[] = { "wss://", "https://relay.example.test/websock", "relay.example.test:0" };
    for (size_t i = 0; i < sizeof(pRefused) / sizeof(pRefused[0]); i++)
    {
        xstrncpy(cfg.sRelayUrl, sizeof(cfg.sRelayUrl), pRefused[i]);
        CHECK(!DirectGate_TestPrepareEndpoint(&conn), "a relay URL that is not a wss endpoint is refused");
    }

    /* Plain ws only where the build allows it, and exactly where it does. */
    xstrncpy(cfg.sRelayUrl, sizeof(cfg.sRelayUrl), "ws://relay.example.test/websock");
    CHECK(DirectGate_TestPrepareEndpoint(&conn) == DirectGate_IsRelayEndpointAllowed(cfg.sRelayUrl),
        "unencrypted relays follow the build's policy");

    cfg.sRoutingKey[0] = '\0';
    xstrncpy(cfg.sRelayUrl, sizeof(cfg.sRelayUrl), "wss://relay.example.test/websock");
    CHECK(!DirectGate_TestPrepareEndpoint(&conn), "a relay without a routing key is not connected to");
    return 0;
}

/* One service tick, the way the event loop delivers it. */
static void tick(xapi_t *pApi)
{
    xapi_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.eCbType = XAPI_CB_TICK;
    ctx.pApi = pApi;
    DirectGate_ServiceCallback(&ctx, NULL);
}

/* A download over the relay: each tick sends a few chunks while the socket
   takes them, stops once its buffer is full, and carries on as it drains. */
static int test_transfer_pump(const char *pRoot)
{
    char sPath[256];
    snprintf(sPath, sizeof(sPath), "%s/download.bin", pRoot);
    FILE *pFile = fopen(sPath, "wb");
    CHECK(pFile != NULL, "create the file to download");
    static uint8_t block[64 * 1024];
    memset(block, 'd', sizeof(block));
    for (int i = 0; i < 48; i++) CHECK(fwrite(block, 1, sizeof(block), pFile) == sizeof(block), "write the file");
    CHECK(fclose(pFile) == 0, "close the file");

    directgate_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    directgate_conn_t conn;
    memset(&conn, 0, sizeof(conn));
    conn.pCfg = &cfg;
    DirectGate_SessionMgr_Init(&conn.mgr, &cfg);

    /* Already waiting for write, so queuing more asks nothing of an event loop. */
    static xapi_session_t relay;
    memset(&relay, 0, sizeof(relay));
    relay.eRole = XAPI_CLIENT;
    relay.sock.nFD = XSOCK_INVALID;
    relay.nEvents = XPOLLOUT;
    relay.pSessionData = &conn;
    XByteBuffer_Init(&relay.txBuffer, XSTDNON, XFALSE);
    conn.pWsSession = &relay;

    directgate_session_t *pSession = DirectGate_SessionMgr_Create(&conn.mgr, 33);
    CHECK(pSession != NULL, "create the session");
    pSession->pWsSession = &relay;
    pSession->bAuthenticated = XTRUE;
    CHECK(DirectGate_Transfer_Send(&pSession->transfer, sPath, DirectGate_Files_TransferSendCb, pSession) == XSTDOK,
        "the download starts");

    xapi_t api;
    memset(&api, 0, sizeof(api));
    api.pUserCtx = &conn;

    for (int i = 0; i < 8; i++) tick(&api);
    size_t nFull = relay.txBuffer.nUsed;
    CHECK(nFull >= 1024U * 1024U && pSession->transfer.eState == XTRANSFER_STATE_SENDING,
        "the ticks fill the relay socket and the download waits");
    tick(&api);
    CHECK(relay.txBuffer.nUsed == nFull, "nothing more is queued behind a full socket");

    for (int i = 0; i < 100 && pSession->transfer.eState == XTRANSFER_STATE_SENDING; i++)
    {
        XByteBuffer_Reset(&relay.txBuffer);
        tick(&api);
    }

    CHECK(pSession->transfer.eState != XTRANSFER_STATE_SENDING, "a draining socket lets the download finish");

    XByteBuffer_Clear(&relay.txBuffer);
    DirectGate_SessionMgr_Destroy(&conn.mgr);
    unlink(sPath);
    return 0;
}

int main(void)
{
    memset(&g_api, 0, sizeof(g_api));

    tls_fixture_t tls;
    CHECK(tls_fixture_begin(&tls), "create a TLS identity for the API");
    setenv("SSL_CERT_FILE", tls.sCert, 1);
    unsetenv("SSL_CERT_DIR");

    char sRoot[] = "/tmp/directgate_reprobe.XXXXXX";
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

    int nResult = run(sRoot, nPort);
    if (!nResult) nResult = test_transfer_pump(sRoot);
    if (!nResult) nResult = test_relay_targets();

    XSYNC_ATOMIC_SET(&g_api.bStop, 1);
    XThread_Join(&thread);
    XAPI_Destroy(&g_api.api);

    char sCmd[256];
    snprintf(sCmd, sizeof(sCmd), "rm -rf '%s'", sRoot);
    if (system(sCmd) != 0) fprintf(stderr, "relay_reprobe_smoke: could not remove %s\n", sRoot);
    tls_fixture_end(&tls);

    if (nResult) return 1;
    puts("relay_reprobe_smoke: OK");
    return 0;
}
