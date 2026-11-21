#include <stdio.h>
#include <string.h>

#include "src/agent/directgate.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "connection_lifecycle_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

int DirectGate_ServiceCallback(xapi_ctx_t *pCtx, xapi_session_t *pApiSession);

static int dispatch(directgate_conn_t *pConn, xapi_session_t *pSession, xapi_cb_type_t eType)
{
    xapi_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.eCbType = eType;

    memset(pSession, 0, sizeof(*pSession));
    pSession->pSessionData = pConn;
    pSession->sock.nFD = XSOCK_INVALID;

    return DirectGate_ServiceCallback(&ctx, pSession);
}

static int send_header(directgate_conn_t *pConn, xapi_session_t *pSession, xjson_obj_t *pHeader)
{
    xbyte_buffer_t packet;
    XByteBuffer_Init(&packet, XSTDNON, XFALSE);

    if (pHeader == NULL || !DirectGate_Proto_Build(&packet, pHeader, NULL, 0, XFALSE))
    {
        XJSON_FreeObject(pHeader);
        XByteBuffer_Clear(&packet);
        return XSTDERR;
    }

    pSession->pSessionData = pConn;
    int nStatus = DirectGate_TestHandleTransportMessage(pSession, packet.pData, packet.nUsed);
    XJSON_FreeObject(pHeader);
    XByteBuffer_Clear(&packet);
    return nStatus;
}

static char g_sLogged[16384];

static int collect_log(const char *pLog, size_t nLength, xlog_flag_t eFlag, void *pCtx)
{
    (void)eFlag;
    (void)pCtx;
    size_t nUsed = strlen(g_sLogged);
    if (nUsed + nLength >= sizeof(g_sLogged)) return 0;

    memcpy(g_sLogged + nUsed, pLog, nLength);
    g_sLogged[nUsed + nLength] = '\0';
    return 0;
}

/* A blocked event loop reads nothing, so what the relay and the peers sent meanwhile waits unread, and no pong can
   even be on its way: the pings it would answer are not sent. That wait is not silence. The checks used to run right
   after the block and close live links over it; the time the loop was blocked now comes off every liveness clock. */
static int test_loop_stall(void)
{
    xlog_init("connection_lifecycle_smoke", XLOG_ALL, XFALSE);
    xlog_screen(XFALSE);
    xlog_callback(collect_log, NULL);

    directgate_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    xstrncpy(cfg.auth.sSaltHex, sizeof(cfg.auth.sSaltHex),
        "00000000000000000000000000000000"
        "00000000000000000000000000000000");
    xstrncpy(cfg.auth.sVerifierHex, sizeof(cfg.auth.sVerifierHex), "configured");
    cfg.nKAInterval = 25;

    directgate_conn_t conn;
    memset(&conn, 0, sizeof(conn));
    conn.pCfg = &cfg;
    DirectGate_SessionMgr_Init(&conn.mgr, &cfg);

    xapi_session_t relay;
    CHECK(dispatch(&conn, &relay, XAPI_CB_CONNECTED) == XAPI_CONTINUE, "the stall test relay connects");
    relay.nEvents = XPOLLIO;
    conn.bRoleSent = XTRUE;

    directgate_session_t *pPeer = DirectGate_SessionMgr_Create(&conn.mgr, 91);
    directgate_session_t *pIdle = DirectGate_SessionMgr_Create(&conn.mgr, 92);
    directgate_session_t *pRecent = DirectGate_SessionMgr_Create(&conn.mgr, 93);
    CHECK(pPeer != NULL && pIdle != NULL && pRecent != NULL, "the stall test sessions are created");
    pPeer->pWsSession = &relay;
    pPeer->bAuthenticated = XTRUE;
    pPeer->webrtc.bConnected = XTRUE;
    pPeer->webrtc.nDataChannelID = 0;
    pIdle->pWsSession = &relay;
    pRecent->pWsSession = &relay;

    /* The first pass has nothing to measure from */
    conn.nLoopPassMs = 0;
    conn.nLastRelayRecvMs = XTime_GetMonoMs() - 30000ULL;
    uint64_t nRecvMs = conn.nLastRelayRecvMs;
    DirectGate_TestCheckLoopStall(&conn, 100);
    CHECK(conn.nLoopPassMs > 0 && conn.nLastRelayRecvMs == nRecvMs, "the first pass only stamps the loop");

    /* Gaps the loop spends waiting for input, or not much more, move no clock */
    conn.nLoopPassMs = XTime_GetMonoMs() - 600ULL;
    g_sLogged[0] = '\0';
    DirectGate_TestCheckLoopStall(&conn, 100);
    CHECK(conn.nLastRelayRecvMs == nRecvMs && g_sLogged[0] == '\0', "a loop that kept listening moves no clock");

    /* 80 s blocked: the relay was last heard, and the last pong came, just before the block */
    uint64_t nNowMs = XTime_GetMonoMs();
    conn.nLoopPassMs = nNowMs - 80000ULL;
    conn.nLastRelayRecvMs = nNowMs - 80500ULL;
    conn.nLastRelayProbeMs = 0;
    pPeer->nLastKAPingMs = nNowMs - 80600ULL;
    pPeer->nLastKAPongMs = nNowMs - 80500ULL;
    pIdle->nLastKAPongMs = 0;
    pRecent->nLastKAPongMs = nNowMs - 100ULL;

    g_sLogged[0] = '\0';
    DirectGate_TestCheckLoopStall(&conn, 100);
    uint64_t nAfterMs = XTime_GetMonoMs();
    CHECK(nAfterMs - conn.nLastRelayRecvMs < 5000ULL && conn.nLastRelayRecvMs <= nAfterMs,
        "the blocked time comes off the relay clock, never past now");
    CHECK(nAfterMs - pPeer->nLastKAPongMs < 5000ULL && pPeer->nLastKAPongMs <= nAfterMs,
        "and off the peer's pong clock");
    CHECK(pIdle->nLastKAPongMs == 0, "a pong clock that was never armed stays unarmed");
    CHECK(pRecent->nLastKAPongMs <= nAfterMs && nAfterMs - pRecent->nLastKAPongMs < 5000ULL,
        "a pong read just before the block is moved up to now, not into the future");
    CHECK(strstr(g_sLogged, "Event loop was blocked") != NULL, "the block is reported");

    g_sLogged[0] = '\0';
    DirectGate_TestCheckRelayKeepalive(&conn);
    CHECK(strstr(g_sLogged, "Relay keepalive timeout") == NULL, "so the relay is not taken for dead");
    DirectGate_TestCheckWebRTCKeepalive(&conn);
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 91) == pPeer, "nor is the peer");
    CHECK(pPeer->nLastKAPingMs >= nNowMs, "and the peer is pinged at once, there being no ping out since the block");

    /* Only the time beyond the wait for input counts as blocked: 10 s between passes that each wait up to 5 s is 5 s
       blocked. And a relay frame read just before the block moves the clock up to now, not into the future. */
    nNowMs = XTime_GetMonoMs();
    conn.nLoopPassMs = nNowMs - 10000ULL;
    conn.nLastRelayRecvMs = nNowMs - 10000ULL;
    DirectGate_TestCheckLoopStall(&conn, 5000);
    nAfterMs = XTime_GetMonoMs();
    CHECK(nAfterMs - conn.nLastRelayRecvMs >= 4000ULL && nAfterMs - conn.nLastRelayRecvMs < 6000ULL,
        "the time the loop spent waiting for input is not taken off the clocks");

    nNowMs = XTime_GetMonoMs();
    conn.nLoopPassMs = nNowMs - 80000ULL;
    conn.nLastRelayRecvMs = nNowMs - 100ULL;
    DirectGate_TestCheckLoopStall(&conn, 100);
    nAfterMs = XTime_GetMonoMs();
    CHECK(conn.nLastRelayRecvMs <= nAfterMs && nAfterMs - conn.nLastRelayRecvMs < 5000ULL,
        "a relay frame read just before the block is moved up to now, not into the future");

    /* The same silence while the loop was listening all along is a dead link, as it always was. The ping above went
       to a data channel that is not really there, which marked it down. */
    pPeer->webrtc.bConnected = XTRUE;
    nNowMs = XTime_GetMonoMs();
    conn.nLoopPassMs = nNowMs - 100ULL;
    conn.nLastRelayRecvMs = nNowMs - 80000ULL;
    pPeer->nLastKAPingMs = nNowMs - 1000ULL;
    pPeer->nLastKAPongMs = nNowMs - 80000ULL;

    g_sLogged[0] = '\0';
    DirectGate_TestCheckLoopStall(&conn, 100);
    CHECK(conn.nLastRelayRecvMs == nNowMs - 80000ULL && pPeer->nLastKAPongMs == nNowMs - 80000ULL,
        "a loop that was listening moves no clock");
    DirectGate_TestCheckRelayKeepalive(&conn);
    CHECK(strstr(g_sLogged, "Relay keepalive timeout") != NULL, "a relay silent while the loop listened is taken for dead");
    DirectGate_TestCheckWebRTCKeepalive(&conn);
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 91) == NULL, "and so is a peer that stopped answering");

    XByteBuffer_Clear(&relay.txBuffer);
    DirectGate_SessionMgr_Destroy(&conn.mgr);
    xlog_destroy();
    return 0;
}

static int count_pings(const xbyte_buffer_t *pBuffer)
{
    /* Unmasked control frames from the agent: 0x89 is a final PING */
    int nPings = 0;
    for (size_t i = 0; i + 1 < pBuffer->nUsed; i++)
        if (pBuffer->pData[i] == 0x89 && (pBuffer->pData[i + 1] & 0x7F) == 0) nPings++;
    return nPings;
}

/* A relay link can die without a word: the agent then went on sending into it, and only noticed when a minute passed
   with nothing read. A probe that has nothing queued ahead of it is now owed an answer within seconds, and a data
   channel going down sends one at once, since the same network change usually takes the relay link with it. */
static int test_relay_probe(void)
{
    xlog_init("connection_lifecycle_smoke", XLOG_ALL, XFALSE);
    xlog_screen(XFALSE);
    xlog_callback(collect_log, NULL);

    directgate_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    xstrncpy(cfg.auth.sSaltHex, sizeof(cfg.auth.sSaltHex),
        "00000000000000000000000000000000"
        "00000000000000000000000000000000");
    xstrncpy(cfg.auth.sVerifierHex, sizeof(cfg.auth.sVerifierHex), "configured");

    directgate_conn_t conn;
    memset(&conn, 0, sizeof(conn));
    conn.pCfg = &cfg;
    DirectGate_SessionMgr_Init(&conn.mgr, &cfg);

    /* A real socket under the relay session, so the kernel queue behind it can be read */
    XSOCKET pair[2] = {XSOCK_INVALID, XSOCK_INVALID};
    CHECK(XSock_CreatePair(pair) == XSTDOK, "the probe test socket pair is created");

    xapi_session_t relay;
    CHECK(dispatch(&conn, &relay, XAPI_CB_CONNECTED) == XAPI_CONTINUE, "the probe test relay connects");
    CHECK(conn.nRelayProbeDeadlineMs == 0, "a fresh link owes no answer");
    relay.sock.nFD = pair[0];
    relay.nEvents = XPOLLIO;

    /* A link still connecting gets no frame: one queued ahead of the upgrade request of an async connect would go out
       first and break it. Its upgrade is owed all the same, so a link that never gets one is given up as before. */
    uint64_t nNowMs = XTime_GetMonoMs();
    conn.nLastRelayRecvMs = nNowMs - 21000ULL;
    DirectGate_TestCheckRelayKeepalive(&conn);
    CHECK(relay.txBuffer.nUsed == 0, "a link still connecting is not pinged");
    CHECK(conn.nRelayProbeDeadlineMs >= nNowMs + 7000ULL && conn.nRelayProbeDeadlineMs <= nNowMs + 9000ULL,
        "its upgrade is owed within the answer time a ping would have");

    conn.nRelayProbeDeadlineMs = XTime_GetMonoMs() - 1ULL;
    g_sLogged[0] = '\0';
    DirectGate_TestCheckRelayKeepalive(&conn);
    CHECK(strstr(g_sLogged, "Relay probe went unanswered") != NULL, "a link whose upgrade never comes is given up");

    /* From here an established link: upgraded, its role sent */
    conn.nLastRelayProbeMs = 0;
    conn.nRelayProbeDeadlineMs = 0;
    relay.bHandshakeDone = XTRUE;
    conn.bRoleSent = XTRUE;

    /* Silent for the probe interval with nothing queued: the probe is owed an answer within seconds */
    nNowMs = XTime_GetMonoMs();
    conn.nLastRelayRecvMs = nNowMs - 21000ULL;
    DirectGate_TestCheckRelayKeepalive(&conn);
    CHECK(count_pings(&relay.txBuffer) == 1, "an idle link is probed");
    CHECK(conn.nRelayProbeDeadlineMs >= nNowMs + 7000ULL && conn.nRelayProbeDeadlineMs <= nNowMs + 9000ULL,
        "a probe with nothing ahead of it is owed an answer within seconds");

    g_sLogged[0] = '\0';
    DirectGate_TestCheckRelayKeepalive(&conn);
    CHECK(count_pings(&relay.txBuffer) == 1, "no second probe goes out while the first is unanswered");
    CHECK(strstr(g_sLogged, "unanswered") == NULL, "nor is the link given up before the answer is due");

    /* Answered in time: a frame read since the probe ends the wait, even with a deadline left behind */
    nNowMs = XTime_GetMonoMs();
    conn.nLastRelayProbeMs = nNowMs - 2000ULL;
    conn.nLastRelayRecvMs = nNowMs - 1000ULL;
    conn.nRelayProbeDeadlineMs = nNowMs - 1ULL;
    g_sLogged[0] = '\0';
    DirectGate_TestCheckRelayKeepalive(&conn);
    CHECK(strstr(g_sLogged, "unanswered") == NULL && strstr(g_sLogged, "keepalive timeout") == NULL,
        "a link that answered after the probe is kept, whatever the deadline says");

    /* Not answered: the link is given up long before the idle timeout */
    XByteBuffer_Clear(&relay.txBuffer);
    nNowMs = XTime_GetMonoMs();
    conn.nLastRelayRecvMs = nNowMs - 30000ULL;
    conn.nLastRelayProbeMs = nNowMs - 9000ULL;
    conn.nRelayProbeDeadlineMs = nNowMs - 1000ULL;
    g_sLogged[0] = '\0';
    DirectGate_TestCheckRelayKeepalive(&conn);
    CHECK(strstr(g_sLogged, "Relay probe went unanswered") != NULL, "an unanswered probe gives the link up");

    /* The same probe behind queued data is held to the idle timeout only: a slow link that drains is not dead */
    conn.nLastRelayProbeMs = 0;
    conn.nRelayProbeDeadlineMs = 0;
    conn.nLastRelayRecvMs = XTime_GetMonoMs() - 21000ULL;
    CHECK(XByteBuffer_Add(&relay.txBuffer, (const uint8_t*)"queued", 6) > 0, "data is queued for the relay");
    DirectGate_TestCheckRelayKeepalive(&conn);
    CHECK(conn.nLastRelayProbeMs > 0 && conn.nRelayProbeDeadlineMs == 0, "a probe behind queued data owes no prompt answer");
    XByteBuffer_Clear(&relay.txBuffer);

    /* Data the kernel still holds counts as queued too */
    char sUnread[256];
    memset(sUnread, 'k', sizeof(sUnread));
    CHECK(send(pair[0], sUnread, sizeof(sUnread), 0) == (ssize_t)sizeof(sUnread), "data waits unread in the kernel");
    conn.nLastRelayProbeMs = 0;
    conn.nLastRelayRecvMs = XTime_GetMonoMs() - 21000ULL;
    DirectGate_TestCheckRelayKeepalive(&conn);
    CHECK(conn.nLastRelayProbeMs > 0 && conn.nRelayProbeDeadlineMs == 0, "a probe behind kernel data owes no prompt answer");
    CHECK(recv(pair[1], sUnread, sizeof(sUnread), 0) > 0, "the kernel queue drains");

    /* A blocked loop moves the deadline on by the block: an answer may be sitting unread */
    conn.nRelayProbeDeadlineMs = 5000ULL;
    nNowMs = XTime_GetMonoMs();
    conn.nLoopPassMs = nNowMs - 3100ULL;
    DirectGate_TestCheckLoopStall(&conn, 100);
    CHECK(conn.nRelayProbeDeadlineMs >= 7900ULL && conn.nRelayProbeDeadlineMs <= 8100ULL,
        "a blocked loop moves the answer deadline by the time it was blocked");
    conn.nRelayProbeDeadlineMs = 0;
    nNowMs = XTime_GetMonoMs();
    conn.nLoopPassMs = nNowMs - 3100ULL;
    DirectGate_TestCheckLoopStall(&conn, 100);
    CHECK(conn.nRelayProbeDeadlineMs == 0, "and arms none that was not set");

    /* A data channel going down probes the relay at once, recently heard from or not */
    XByteBuffer_Clear(&relay.txBuffer);
    directgate_session_t *pPeer = DirectGate_SessionMgr_Create(&conn.mgr, 81);
    CHECK(pPeer != NULL, "the drop test session is created");
    pPeer->webrtc.bConnected = XTRUE;
    pPeer->webrtc.nDataChannelID = 0;
    conn.nLastRelayRecvMs = XTime_GetMonoMs();
    conn.nLastRelayProbeMs = 0;
    DirectGate_TestCheckWebRTCDrops(&conn);
    CHECK(count_pings(&relay.txBuffer) == 0 && pPeer->bWebRTCWasUp, "a channel that is up probes nothing");
    DirectGate_TestCheckWebRTCDrops(&conn);
    CHECK(count_pings(&relay.txBuffer) == 0, "nor does one that stays up");

    pPeer->webrtc.bConnected = XFALSE;
    DirectGate_TestCheckWebRTCDrops(&conn);
    CHECK(count_pings(&relay.txBuffer) == 1, "a channel that went down probes the relay");
    CHECK(conn.nRelayProbeDeadlineMs > 0, "and the probe is owed a prompt answer");
    DirectGate_TestCheckWebRTCDrops(&conn);
    CHECK(count_pings(&relay.txBuffer) == 1 && !pPeer->bWebRTCWasUp, "the drop is seen once");

    /* A second drop while the first probe is out sends nothing more */
    pPeer->webrtc.bConnected = XTRUE;
    DirectGate_TestCheckWebRTCDrops(&conn);
    pPeer->webrtc.bConnected = XFALSE;
    DirectGate_TestCheckWebRTCDrops(&conn);
    CHECK(count_pings(&relay.txBuffer) == 1, "no second probe while the first is unanswered");

    /* Once answered, a channel that stays down sends no further probe */
    conn.nLastRelayRecvMs = XTime_GetMonoMs();
    conn.nLastRelayProbeMs = conn.nLastRelayRecvMs - 1ULL;
    DirectGate_TestCheckWebRTCDrops(&conn);
    CHECK(count_pings(&relay.txBuffer) == 1, "a channel that stays down probes nothing more once answered");

    /* The relay liveness check that runs every pass looks for drops itself */
    XByteBuffer_Clear(&relay.txBuffer);
    conn.nLastRelayRecvMs = XTime_GetMonoMs();
    conn.nLastRelayProbeMs = 0;
    pPeer->webrtc.bConnected = XTRUE;
    DirectGate_TestCheckRelayKeepalive(&conn);
    pPeer->webrtc.bConnected = XFALSE;
    DirectGate_TestCheckRelayKeepalive(&conn);
    CHECK(count_pings(&relay.txBuffer) == 1, "the per-pass relay check probes on a drop");

    /* Without a relay link there is nothing to probe */
    xapi_session_t *pSaved = conn.pWsSession;
    conn.pWsSession = NULL;
    conn.nLastRelayProbeMs = 0;
    pPeer->webrtc.bConnected = XTRUE;
    DirectGate_TestCheckWebRTCDrops(&conn);
    pPeer->webrtc.bConnected = XFALSE;
    DirectGate_TestCheckWebRTCDrops(&conn);
    CHECK(conn.nLastRelayProbeMs == 0, "a drop with no relay link probes nothing");
    conn.pWsSession = pSaved;

    XByteBuffer_Clear(&relay.txBuffer);
    DirectGate_SessionMgr_Destroy(&conn.mgr);
    xclosesock(pair[0]);
    xclosesock(pair[1]);

#if defined(__linux__)
    /* On a real TCP link the kernel is told to give up on data that stays unacknowledged */
    xsock_t server, client;
    uint16_t nPort = 0;
    for (uint16_t nTry = 39700; nTry < 39800 && !nPort; nTry++)
    {
        if (XSock_Create(&server, XSOCK_TCP_SERVER | XSOCK_REUSEADDR, "127.0.0.1", nTry) != XSOCK_INVALID &&
            XSock_Status(&server) == XSOCK_ERR_NONE) nPort = nTry;
        else XSock_Close(&server);
    }

    if (nPort)
    {
        CHECK(XSock_Create(&client, XSOCK_TCP_CLIENT, "127.0.0.1", nPort) != XSOCK_INVALID, "the TCP client connects");

        xapi_ctx_t ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.eCbType = XAPI_CB_CONNECTED;
        memset(&relay, 0, sizeof(relay));
        relay.pSessionData = &conn;
        relay.sock = client;
        CHECK(DirectGate_ServiceCallback(&ctx, &relay) == XAPI_CONTINUE, "a TCP relay link connects");

        unsigned int nValue = 0;
        socklen_t nLen = sizeof(nValue);
        CHECK(getsockopt(client.nFD, IPPROTO_TCP, TCP_USER_TIMEOUT, &nValue, &nLen) == 0 && nValue == 20000U,
            "the relay link gives up on data unacknowledged for 20 s");

        XByteBuffer_Clear(&relay.txBuffer);
        XSock_Close(&client);
        XSock_Close(&server);
    }
#endif

    xlog_destroy();
    return 0;
}

#define DETACH_DEVICE_ID "device-detach"

/* An authenticated desktop with its data channel up, keys on both halves, as a finished handshake leaves it */
static directgate_session_t* detach_session(directgate_conn_t *pConn, xapi_session_t *pRelay, uint32_t nSessionId,
                                            directgate_e2e_t *pPeer)
{
    directgate_session_t *pSession = DirectGate_SessionMgr_Create(&pConn->mgr, nSessionId);
    if (pSession == NULL) return NULL;

    uint8_t sKey[32], agentNonce[DIRECTGATE_SRP_NONCE_SIZE], clientNonce[DIRECTGATE_SRP_NONCE_SIZE];
    memset(sKey, 0x5c, sizeof(sKey));
    memset(agentNonce, 0x11, sizeof(agentNonce));
    memset(clientNonce, 0x22, sizeof(clientNonce));

    DirectGate_E2E_Init(&pSession->e2e);
    if (pPeer != NULL) DirectGate_E2E_Init(pPeer);
    if (!DirectGate_E2E_DeriveFromSRP(&pSession->e2e, sKey, sizeof(sKey), agentNonce, clientNonce,
            sizeof(agentNonce), DETACH_DEVICE_ID, XTRUE) ||
        (pPeer != NULL && !DirectGate_E2E_DeriveFromSRP(pPeer, sKey, sizeof(sKey), agentNonce, clientNonce,
            sizeof(agentNonce), DETACH_DEVICE_ID, XFALSE))) return NULL;

    pSession->pWsSession = pRelay;
    pSession->bAuthenticated = XTRUE;
    pSession->eActiveMode = DIRECTGATE_SESSION_MODE_DESKTOP;
    pSession->webrtc.bConnected = XTRUE;
    pSession->webrtc.nDataChannelID = 0;
    return pSession;
}

static int relay_status(directgate_conn_t *pConn, xapi_session_t *pRelay, uint32_t nSessionId, const char *pReason)
{
    xjson_obj_t *pHeader = DirectGate_Proto_BuildStatus("closed", nSessionId);
    if (pHeader != NULL && pReason != NULL) XJSON_AddString(pHeader, "reason", pReason);
    return send_header(pConn, pRelay, pHeader);
}

/* What the browser puts on the data channel: sealed with the session keys */
static void data_channel(directgate_session_t *pSession, directgate_e2e_t *pPeer, xjson_obj_t *pHeader,
                         const char *pPayload)
{
    xbyte_buffer_t packet;
    XByteBuffer_Init(&packet, XSTDNON, XFALSE);
    size_t nPayload = pPayload != NULL ? strlen(pPayload) : 0;

    DirectGate_Proto_AddCC(pHeader, pPeer, 0);
    if (DirectGate_Proto_Build(&packet, pHeader, (const uint8_t*)pPayload, nPayload, XFALSE) &&
        DirectGate_Proto_EncryptPackage(&packet, pPeer, pSession->nSessionId))
        DirectGate_TestHandleDataChannelMessage(pSession, packet.pData, packet.nUsed);

    XJSON_FreeObject(pHeader);
    XByteBuffer_Clear(&packet);
}

static int relay_closes(xapi_session_t *pRelay)
{
    xapi_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.eCbType = XAPI_CB_CLOSED;
    return DirectGate_ServiceCallback(&ctx, pRelay);
}

/* A desktop watched over a working data channel used to end with its relay route: the relay told the agent the
   browser's socket was gone, or the agent's own link dropped, and the picture froze until a new session came up. It
   now carries on over the data channel alone, for a bounded time, never touching the relay. A client the relay ends
   on purpose - a sign-out above all - still ends at once. */
static int test_detach(void)
{
    xlog_init("connection_lifecycle_smoke", XLOG_ALL, XFALSE);
    xlog_screen(XFALSE);
    xlog_callback(collect_log, NULL);

    directgate_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    xstrncpy(cfg.auth.sSaltHex, sizeof(cfg.auth.sSaltHex),
        "00000000000000000000000000000000"
        "00000000000000000000000000000000");
    xstrncpy(cfg.auth.sVerifierHex, sizeof(cfg.auth.sVerifierHex), "configured");

    directgate_conn_t conn;
    memset(&conn, 0, sizeof(conn));
    conn.pCfg = &cfg;
    DirectGate_SessionMgr_Init(&conn.mgr, &cfg);

    xapi_session_t relay;
    CHECK(dispatch(&conn, &relay, XAPI_CB_CONNECTED) == XAPI_CONTINUE, "the detach test relay connects");
    relay.nEvents = XPOLLIO;
    conn.bRoleSent = XTRUE;

    /* The browser's socket went away: a watched desktop stays, on its data channel */
    directgate_e2e_t peer;
    directgate_session_t *pDesk = detach_session(&conn, &relay, 61, &peer);
    CHECK(pDesk != NULL, "the detach test desktop is up");
    relay_status(&conn, &relay, 61, "lost");
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 61) == pDesk && pDesk->bDetached, "a lost browser socket detaches it");
    CHECK(pDesk->pWsSession == &conn.detachLink, "and it lets go of the relay link");
    CHECK(conn.detachLink.pSessionData == &conn && conn.detachLink.eRole == XAPI_CLIENT &&
        conn.detachLink.sock.nFD == XSOCK_INVALID, "for a stand-in that dispatch reads as this connection, without a socket");

    /* The relay ending the browser itself ends the session as before */
    directgate_session_t *pKicked = detach_session(&conn, &relay, 62, NULL);
    CHECK(pKicked != NULL, "the kick test desktop is up");
    relay_status(&conn, &relay, 62, NULL);
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 62) == NULL, "a closed status without lost ends the session");

    /* Only a watched desktop on a working data channel detaches */
    directgate_session_t *pTerm = detach_session(&conn, &relay, 63, NULL);
    directgate_session_t *pDown = detach_session(&conn, &relay, 64, NULL);
    directgate_session_t *pGuest = detach_session(&conn, &relay, 65, NULL);
    CHECK(pTerm != NULL && pDown != NULL && pGuest != NULL, "the excluded sessions are up");
    pTerm->eActiveMode = DIRECTGATE_SESSION_MODE_TERMINAL;
    pDown->webrtc.bConnected = XFALSE;
    pGuest->bDesktopShare = XTRUE;
    relay_status(&conn, &relay, 63, "lost");
    relay_status(&conn, &relay, 64, "lost");
    relay_status(&conn, &relay, 65, "lost");
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 63) == NULL, "a terminal ends with its browser's socket");
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 64) == NULL, "a desktop without a data channel ends");
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 65) == NULL, "a temporary share's guest ends");

    /* What the viewer sends while it watches reaches the detached desktop; nothing that would need the relay does */
    g_sLogged[0] = '\0';
    data_channel(pDesk, &peer, DirectGate_Proto_BuildKeepalive("pong", 61), NULL);
    CHECK(strstr(g_sLogged, "not taken by a detached session") == NULL, "a keepalive answer is taken");
    CHECK(pDesk->nLastKAPongMs > 0, "and counts as one");
    xjson_obj_t *pInput = DirectGate_Proto_BuildData(61);
    XJSON_AddString(pInput, "payloadType", "desktop-input/json");
    data_channel(pDesk, &peer, pInput, "{}");
    CHECK(strstr(g_sLogged, "not taken by a detached session") == NULL, "desktop input is taken");
    data_channel(pDesk, &peer, DirectGate_Proto_BuildCmd("start", NULL, NULL, "terminal", 61), NULL);
    CHECK(strstr(g_sLogged, "not taken by a detached session") != NULL, "a start command is not");
    g_sLogged[0] = '\0';
    xjson_obj_t *pFile = DirectGate_Proto_BuildData(61);
    XJSON_AddString(pFile, "payloadType", "terminal/raw");
    data_channel(pDesk, &peer, pFile, "ls\n");
    CHECK(strstr(g_sLogged, "not taken by a detached session") != NULL, "nor is anything that is not the desktop's");

    /* An answer it cannot put on the data channel goes nowhere else: never to the relay */
    XByteBuffer_Clear(&relay.txBuffer);
    data_channel(pDesk, &peer, DirectGate_Proto_BuildKeepalive("ping", 61), NULL);
    CHECK(relay.txBuffer.nUsed == 0 && conn.detachLink.txBuffer.nUsed == 0, "a detached session never writes to a relay");
    pDesk->webrtc.bConnected = XTRUE;

    /* The relay repeating that the socket is lost changes nothing; anything else for the id ends the session */
    relay_status(&conn, &relay, 61, "lost");
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 61) == pDesk, "a repeated lost notice leaves it detached");
    relay_status(&conn, &relay, 61, NULL);
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 61) == NULL, "the relay ending that client ends the detached session");
    CHECK(relay.txBuffer.nUsed == 0, "and nothing is announced on the relay for an id that is no longer its own");

    pDesk = detach_session(&conn, &relay, 66, &peer);
    CHECK(pDesk != NULL, "a second desktop is up");
    relay_status(&conn, &relay, 66, "lost");
    CHECK(pDesk->bDetached, "and detached");
    send_header(&conn, &relay, DirectGate_Proto_BuildData(66));
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 66) == NULL, "a relay message for its id, now another client's, ends it");

    /* It ends with its data channel, after its time, or with the enrollment */
    pDesk = detach_session(&conn, &relay, 67, NULL);
    relay_status(&conn, &relay, 67, "lost");
    DirectGate_TestCheckDetachedSessions(&conn);
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 67) == pDesk, "a detached session with its channel up stays");
    pDesk->webrtc.bConnected = XFALSE;
    DirectGate_TestCheckDetachedSessions(&conn);
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 67) == NULL, "it ends with its data channel");

    pDesk = detach_session(&conn, &relay, 68, NULL);
    relay_status(&conn, &relay, 68, "lost");
    pDesk->nDetachedMs = XTime_GetMonoMs() - 59000ULL;
    DirectGate_TestCheckDetachedSessions(&conn);
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 68) == pDesk, "a session detached under a minute ago stays");
    pDesk->nDetachedMs = XTime_GetMonoMs() - 60000ULL;
    DirectGate_TestCheckAuthTimeouts(&conn);
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 68) == NULL, "it ends a minute after it was detached, with the other deadlines");

    pDesk = detach_session(&conn, &relay, 69, NULL);
    relay_status(&conn, &relay, 69, "lost");
    conn.bReconnectSuppressed = XTRUE;
    DirectGate_TestCheckDetachedSessions(&conn);
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 69) == NULL, "an ended enrollment keeps nothing");
    conn.bReconnectSuppressed = XFALSE;
    CHECK(relay.txBuffer.nUsed == 0 && conn.detachLink.txBuffer.nUsed == 0,
        "none of those endings were announced on the relay, nor written to its stand-in");

    /* The agent's own relay link drops: watched desktops detach, the rest ends, the detached stay detached */
    directgate_session_t *pKept = detach_session(&conn, &relay, 71, NULL);
    directgate_session_t *pEnded = detach_session(&conn, &relay, 72, NULL);
    directgate_session_t *pEarlier = detach_session(&conn, &relay, 73, NULL);
    CHECK(pKept != NULL && pEnded != NULL && pEarlier != NULL, "the relay loss sessions are up");
    pEnded->eActiveMode = DIRECTGATE_SESSION_MODE_FILE_MANAGER;
    relay_status(&conn, &relay, 73, "lost");
    pEarlier->nDetachedMs = XTime_GetMonoMs() - 30000ULL;
    uint64_t nEarlierMs = pEarlier->nDetachedMs;
    xapi_t api;
    memset(&api, 0, sizeof(api));
    relay.pApi = &api;
    relay_closes(&relay);
    CHECK(conn.pWsSession == NULL, "the relay link is gone");
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 71) == pKept && pKept->bDetached, "a watched desktop outlives the link");
    CHECK(pKept->pWsSession == &conn.detachLink && conn.detachLink.pApi == &api, "and keeps nothing of it but the loop");
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 72) == NULL, "a file manager ends with the link");
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 73) == pEarlier && pEarlier->nDetachedMs == nEarlierMs,
        "a session detached before stays as it is, its time still running from then");

    /* The next link keeps them; anything attached that was left behind is cleaned */
    xapi_session_t next;
    directgate_session_t *pStale = DirectGate_SessionMgr_Create(&conn.mgr, 74);
    CHECK(pStale != NULL, "a stale session is left behind");
    CHECK(dispatch(&conn, &next, XAPI_CB_CONNECTED) == XAPI_CONTINUE, "the next relay link connects");
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 74) == NULL, "a stale attached session is cleaned");
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 71) == pKept && pKept->pWsSession == &conn.detachLink,
        "the detached ones carry on, still off the relay");

    /* A link the relay ended on purpose, or one under an enrollment in doubt, detaches nothing */
    next.nEvents = XPOLLIO;
    conn.bRoleSent = XTRUE;
    directgate_session_t *pReasoned = detach_session(&conn, &next, 75, NULL);
    CHECK(pReasoned != NULL, "a desktop on the next link is up");
    xstrncpy(conn.sDisconnectReason, sizeof(conn.sDisconnectReason), "turn-quota-reached");
    relay_closes(&next);
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 75) == NULL, "a link ended with a reason takes its sessions along");

    xapi_session_t fourth;
    CHECK(dispatch(&conn, &fourth, XAPI_CB_CONNECTED) == XAPI_CONTINUE, "a fourth relay link connects");
    fourth.nEvents = XPOLLIO;
    directgate_session_t *pRevoked = detach_session(&conn, &fourth, 77, NULL);
    CHECK(pRevoked != NULL, "a desktop on the fourth link is up");
    conn.bReconnectSuppressed = XTRUE;
    relay_closes(&fourth);
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 77) == NULL, "a link lost after the enrollment ended detaches nothing");
    conn.bReconnectSuppressed = XFALSE;
    conn.nNextReconnectMs = 0;

    xapi_session_t third;
    CHECK(dispatch(&conn, &third, XAPI_CB_CONNECTED) == XAPI_CONTINUE, "a third relay link connects");
    third.nEvents = XPOLLIO;
    directgate_session_t *pDoubt = detach_session(&conn, &third, 76, NULL);
    CHECK(pDoubt != NULL, "a desktop on the third link is up");
    conn.bEnrollmentDoubt = XTRUE;
    relay_closes(&third);
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 76) == NULL, "a link lost with the enrollment in doubt detaches nothing");
    conn.bEnrollmentDoubt = XFALSE;

    XByteBuffer_Clear(&relay.txBuffer);
    XByteBuffer_Clear(&next.txBuffer);
    XByteBuffer_Clear(&third.txBuffer);
    XByteBuffer_Clear(&fourth.txBuffer);
    DirectGate_E2E_Clear(&peer);
    DirectGate_SessionMgr_Destroy(&conn.mgr);
    xlog_destroy();
    return 0;
}

typedef struct {
    int bFound;
    char sStatus[16];
    char sReason[64];
    int bResume;
    int bResumed;
    char sProof[2048];
} auth_result_t;

/* The last auth result the agent wrote to a relay link for an id: read back out of its (masked) binary frames */
static int read_auth_result(const xbyte_buffer_t *pBuffer, uint32_t nSessionId, auth_result_t *pResult)
{
    memset(pResult, 0, sizeof(*pResult));

    for (size_t nPos = 0; nPos + 2 <= pBuffer->nUsed;)
    {
        const uint8_t *pFrame = pBuffer->pData + nPos;
        size_t nLength = pFrame[1] & 0x7F, nHeader = 2;

        if (nLength == 126)
        {
            if (nPos + 4 > pBuffer->nUsed) break;
            nLength = ((size_t)pFrame[2] << 8) | pFrame[3];
            nHeader = 4;
        }
        else if (nLength == 127)
        {
            if (nPos + 10 > pBuffer->nUsed) break;
            nLength = 0;
            for (int i = 0; i < 8; i++) nLength = (nLength << 8) | pFrame[2 + i];
            nHeader = 10;
        }

        size_t nMaskAt = nHeader;
        if (pFrame[1] & 0x80) nHeader += 4;
        if (nPos + nHeader + nLength > pBuffer->nUsed) break;

        if ((pFrame[0] & 0x0F) == 0x02 && nLength > 0)
        {
            uint8_t *pPayload = (uint8_t*)malloc(nLength);
            if (pPayload == NULL) return 0;

            for (size_t i = 0; i < nLength; i++)
                pPayload[i] = pFrame[nHeader + i] ^ ((pFrame[1] & 0x80) ? pFrame[nMaskAt + (i % 4)] : 0);

            directgate_pkg_t pkg;
            if (DirectGate_Package_Parse(&pkg, pPayload, nLength))
            {
                const directgate_pkg_auth_t *pAuth = (const directgate_pkg_auth_t*)pkg.pPackage;
                xjson_obj_t *pRoot = pkg.jsonHeader.pRootObj;

                if (pkg.header.eType == DIRECTGATE_PKG_AUTH && pkg.header.nSessionId == nSessionId && pAuth != NULL)
                {
                    pResult->bFound = 1;
                    xstrncpy(pResult->sStatus, sizeof(pResult->sStatus), pAuth->pStatus);
                    xstrncpy(pResult->sReason, sizeof(pResult->sReason), XJSON_GetString(XJSON_GetObject(pRoot, "reason")));
                    xstrncpy(pResult->sProof, sizeof(pResult->sProof), XJSON_GetString(XJSON_GetObject(pRoot, "proof")));
                    pResult->bResume = XJSON_GetBool(XJSON_GetObject(pRoot, "resume"));
                    pResult->bResumed = XJSON_GetBool(XJSON_GetObject(pRoot, "resumed"));
                }

                DirectGate_Package_Clear(&pkg);
            }

            free(pPayload);
        }

        nPos += nHeader + nLength;
    }

    return pResult->bFound;
}

/* What a client that lost its relay socket seals with the session's keys to take it back: an auth "resume" under the
   old id, bound to the new one and the device. Returned as the base64 the request carries, so a test can resend it. */
static int seal_resume_proof(directgate_e2e_t *pPeer, uint32_t nPrevId, uint32_t nBoundId, const char *pDeviceId,
                             char *pProof, size_t nProofSize)
{
    xjson_obj_t *pInner = DirectGate_Proto_NewHeader("auth", nPrevId);
    if (pInner == NULL) return 0;

    XJSON_AddString(pInner, "action", "resume");
    XJSON_AddU32(pInner, "newSessionId", nBoundId);
    XJSON_AddString(pInner, "deviceId", pDeviceId);
    DirectGate_Proto_AddCC(pInner, pPeer, 0);

    xbyte_buffer_t packet;
    XByteBuffer_Init(&packet, XSTDNON, XFALSE);
    int bOk = DirectGate_Proto_Build(&packet, pInner, NULL, 0, XFALSE) &&
        DirectGate_Proto_EncryptPackage(&packet, pPeer, nPrevId) &&
        DirectGate_KeyAuth_Base64Encode(packet.pData, packet.nUsed, pProof, nProofSize);

    XJSON_FreeObject(pInner);
    XByteBuffer_Clear(&packet);
    return bOk;
}

/* A proof that is wrong in one way: its envelope's id, what it seals, or not sealed at all */
static int seal_odd_proof(directgate_e2e_t *pPeer, const char *pType, const char *pAction, uint32_t nInnerId,
                          uint32_t nEnvelopeId, int bSeal, char *pProof, size_t nProofSize)
{
    xjson_obj_t *pInner = DirectGate_Proto_NewHeader(pType, nInnerId);
    if (pInner == NULL) return 0;

    XJSON_AddString(pInner, "action", pAction);
    XJSON_AddU32(pInner, "newSessionId", 97);
    XJSON_AddString(pInner, "deviceId", DETACH_DEVICE_ID);
    if (bSeal) DirectGate_Proto_AddCC(pInner, pPeer, 0);

    xbyte_buffer_t packet;
    XByteBuffer_Init(&packet, XSTDNON, XFALSE);
    int bOk = DirectGate_Proto_Build(&packet, pInner, NULL, 0, XFALSE) &&
        (!bSeal || DirectGate_Proto_EncryptPackage(&packet, pPeer, nEnvelopeId)) &&
        DirectGate_KeyAuth_Base64Encode(packet.pData, packet.nUsed, pProof, nProofSize);

    XJSON_FreeObject(pInner);
    XByteBuffer_Clear(&packet);
    return bOk;
}

/* The request itself, plaintext on the new socket's id, as the relay has to see an auth message before any other */
static int send_resume(directgate_conn_t *pConn, xapi_session_t *pRelay, uint32_t nNewId, uint32_t nPrevId, const char *pProof)
{
    xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("auth", nNewId);
    if (pHeader == NULL) return XSTDERR;

    g_sLogged[0] = '\0';
    XJSON_AddString(pHeader, "action", "resume");
    if (nPrevId) XJSON_AddU32(pHeader, "resumeSid", nPrevId);
    if (pProof != NULL) XJSON_AddString(pHeader, "proof", pProof);
    return send_header(pConn, pRelay, pHeader);
}

/* The agent's answer, opened with the client's half of the keys: it has to be the agent's own, for the new id */
static int open_resume_answer(directgate_e2e_t *pPeer, const char *pProof, uint32_t nNewId, uint32_t nPrevId,
                              const char *pDeviceId)
{
    uint8_t sDecoded[DIRECTGATE_SESSION_RESUME_PROOF_MAX];
    size_t nDecoded = 0;
    if (!DirectGate_KeyAuth_Base64Decode(pProof, sDecoded, sizeof(sDecoded), &nDecoded)) return 0;

    directgate_pkg_t sealed;
    if (!DirectGate_Package_Parse(&sealed, sDecoded, nDecoded)) return 0;

    xbyte_buffer_t inner;
    XByteBuffer_Init(&inner, XSTDNON, XFALSE);
    int bOk = sealed.header.eType == DIRECTGATE_PKG_ENCRYPTED && sealed.header.nSessionId == nNewId &&
        DirectGate_Proto_DecryptPackage(&inner, &sealed, pPeer);

    if (bOk)
    {
        directgate_pkg_t answer;
        bOk = DirectGate_Package_Parse(&answer, inner.pData, inner.nUsed);

        if (bOk)
        {
            const directgate_pkg_auth_t *pAuth = (const directgate_pkg_auth_t*)answer.pPackage;
            xjson_obj_t *pRoot = answer.jsonHeader.pRootObj;

            bOk = answer.header.eType == DIRECTGATE_PKG_AUTH && pAuth != NULL && xstrcmp(pAuth->pAction, "resumed") &&
                answer.header.nSessionId == nNewId && XJSON_GetU32(XJSON_GetObject(pRoot, "prevSessionId")) == nPrevId &&
                xstrcmp(XJSON_GetString(XJSON_GetObject(pRoot, "deviceId")), pDeviceId);

            DirectGate_Package_Clear(&answer);
        }
    }

    XByteBuffer_Clear(&inner);
    DirectGate_Package_Clear(&sealed);
    return bOk;
}

/* data_channel, sealed under an id of the caller's choosing: the one a resumed session had before */
static void data_channel_as(directgate_session_t *pSession, directgate_e2e_t *pPeer, xjson_obj_t *pHeader, uint32_t nSealedId)
{
    xbyte_buffer_t packet;
    XByteBuffer_Init(&packet, XSTDNON, XFALSE);

    DirectGate_Proto_AddCC(pHeader, pPeer, 0);
    if (DirectGate_Proto_Build(&packet, pHeader, NULL, 0, XFALSE) && DirectGate_Proto_EncryptPackage(&packet, pPeer, nSealedId))
        DirectGate_TestHandleDataChannelMessage(pSession, packet.pData, packet.nUsed);

    XJSON_FreeObject(pHeader);
    XByteBuffer_Clear(&packet);
}

/* A refused resume answers "failed" on the new id and leaves every session exactly as it was */
static int expect_refused(directgate_conn_t *pConn, xapi_session_t *pRelay, uint32_t nNewId,
                          directgate_session_t *pSession, uint32_t nPrevId, const char *pWhy, const char *pReason)
{
    auth_result_t result;
    char sLogged[96];
    snprintf(sLogged, sizeof(sLogged), "reason(%s)", pReason);

    if (strstr(g_sLogged, sLogged) == NULL)
    {
        fprintf(stderr, "connection_lifecycle_smoke: %s: not refused for %s\n", pWhy, pReason);
        return 1;
    }
    xbool_t bDetached = pSession != NULL ? pSession->bDetached : XFALSE;

    if (!read_auth_result(&pRelay->txBuffer, nNewId, &result) || strcmp(result.sStatus, "failed") ||
        strcmp(result.sReason, "resume refused") || result.bResumed || result.sProof[0])
    {
        fprintf(stderr, "connection_lifecycle_smoke: %s: no plain refusal on the new id\n", pWhy);
        return 1;
    }

    if ((nNewId != nPrevId && DirectGate_SessionMgr_Find(&pConn->mgr, nNewId) != NULL) ||
        (pSession != NULL && (DirectGate_SessionMgr_Find(&pConn->mgr, nPrevId) != pSession || pSession->bDetached != bDetached)))
    {
        fprintf(stderr, "connection_lifecycle_smoke: %s: a refused resume changed a session\n", pWhy);
        return 1;
    }

    XByteBuffer_Clear(&pRelay->txBuffer);
    return 0;
}

/* A desktop whose client lost its relay socket used to end there, or live on its data channel only until the client
   authenticated a brand-new session and the picture started over. The client now proves on its new socket that it
   holds the session's keys, and the session carries on under the new id: same keys, counters and data channel. A
   proof for another id, another device, another key, a second time, or for a session that cannot outlive its route
   is refused, and changes nothing. */
static int test_resume(void)
{
    xlog_init("connection_lifecycle_smoke", XLOG_ALL, XFALSE);
    xlog_screen(XFALSE);
    xlog_callback(collect_log, NULL);

    directgate_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    xstrncpy(cfg.sDeviceId, sizeof(cfg.sDeviceId), DETACH_DEVICE_ID);
    xstrncpy(cfg.auth.sSaltHex, sizeof(cfg.auth.sSaltHex), "0000000000000000000000000000000000000000000000000000000000000000");
    xstrncpy(cfg.auth.sVerifierHex, sizeof(cfg.auth.sVerifierHex), "configured");

    directgate_conn_t conn;
    memset(&conn, 0, sizeof(conn));
    conn.pCfg = &cfg;
    DirectGate_SessionMgr_Init(&conn.mgr, &cfg);

    xapi_session_t relay;
    CHECK(dispatch(&conn, &relay, XAPI_CB_CONNECTED) == XAPI_CONTINUE, "the resume test relay connects");
    relay.nEvents = XPOLLIO;
    conn.bRoleSent = XTRUE;

    /* A client is told it may resume; a temporary share's guest, and a refusal, are not */
    auth_result_t result;
    directgate_session_t *pFresh = DirectGate_SessionMgr_Create(&conn.mgr, 79);
    CHECK(pFresh != NULL, "a session to answer is up");
    pFresh->pWsSession = &relay;
    DirectGate_Session_SendAuthResp(pFresh, "ok", "00", NULL);
    CHECK(read_auth_result(&relay.txBuffer, 79, &result) && result.bResume, "an accepted client may resume");
    XByteBuffer_Clear(&relay.txBuffer);
    DirectGate_Session_SendAuthResp(pFresh, "failed", NULL, "no");
    CHECK(read_auth_result(&relay.txBuffer, 79, &result) && !result.bResume, "a refused one is not told so");
    XByteBuffer_Clear(&relay.txBuffer);
    pFresh->bDesktopShare = XTRUE;
    DirectGate_Session_SendAuthResp(pFresh, "ok", "00", NULL);
    CHECK(read_auth_result(&relay.txBuffer, 79, &result) && !result.bResume, "nor is a temporary share's guest");
    XByteBuffer_Clear(&relay.txBuffer);
    DirectGate_SessionMgr_Remove(&conn.mgr, pFresh);

    /* The browser's socket went away and the desktop lives on its data channel; the client comes back on a new one */
    directgate_e2e_t peer;
    directgate_session_t *pDesk = detach_session(&conn, &relay, 81, &peer);
    CHECK(pDesk != NULL, "the resume test desktop is up");
    relay_status(&conn, &relay, 81, "lost");
    CHECK(pDesk->bDetached, "and detached");

    char sProof[2048];
    CHECK(seal_resume_proof(&peer, 81, 91, DETACH_DEVICE_ID, sProof, sizeof(sProof)), "a resume proof is sealed");
    XByteBuffer_Clear(&relay.txBuffer);
    CHECK(send_resume(&conn, &relay, 91, 81, sProof) == XAPI_CONTINUE, "a resume never takes the relay link down");
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 91) == pDesk, "the session goes by the new socket's id");
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 81) == NULL, "and no longer by its old one");
    CHECK(!pDesk->bDetached && pDesk->nDetachedMs == 0 && pDesk->pWsSession == &relay, "it is back on the relay link");
    CHECK(pDesk->nPrevSessionId == 81, "it remembers the id it had");
    CHECK(DirectGate_E2E_IsInitialized(&pDesk->e2e) && pDesk->bAuthenticated, "with the keys it authenticated with");
    CHECK(read_auth_result(&relay.txBuffer, 91, &result), "the resume is answered on the new id");
    CHECK(!strcmp(result.sStatus, "ok") && result.bResumed && result.bResume, "with a plaintext ok the relay can read");
    CHECK(open_resume_answer(&peer, result.sProof, 91, 81, DETACH_DEVICE_ID), "and the agent's own sealed answer");
    CHECK(!open_resume_answer(&peer, result.sProof, 91, 81, DETACH_DEVICE_ID), "which opens once, like any message");
    XByteBuffer_Clear(&relay.txBuffer);

    /* What the client put on the data channel under the old id before the new one reached it still lands */
    g_sLogged[0] = '\0';
    pDesk->nLastKAPongMs = 0;
    data_channel_as(pDesk, &peer, DirectGate_Proto_BuildKeepalive("pong", 81), 81);
    CHECK(pDesk->nLastKAPongMs > 0, "a message sealed under the old id is taken in the moments after a resume");
    CHECK(strstr(g_sLogged, "without session E2E context") == NULL, "and handled as the session's own");
    pDesk->nLastKAPongMs = 0;
    data_channel_as(pDesk, &peer, DirectGate_Proto_BuildKeepalive("pong", 91), 91);
    CHECK(pDesk->nLastKAPongMs > 0, "as is one under the new id");

    /* Never over the relay, which hands out new ids to new sockets, and not for long */
    pDesk->nLastKAPongMs = 0;
    xbyte_buffer_t sealed;
    XByteBuffer_Init(&sealed, XSTDNON, XFALSE);
    xjson_obj_t *pPong = DirectGate_Proto_BuildKeepalive("pong", 81);
    DirectGate_Proto_AddCC(pPong, &peer, 0);
    CHECK(DirectGate_Proto_Build(&sealed, pPong, NULL, 0, XFALSE) &&
        DirectGate_Proto_EncryptPackage(&sealed, &peer, 81), "an old-id message for the relay is sealed");
    XJSON_FreeObject(pPong);
    DirectGate_TestHandleTransportMessage(&relay, sealed.pData, sealed.nUsed);
    XByteBuffer_Clear(&sealed);
    CHECK(pDesk->nLastKAPongMs == 0, "the old id means nothing on the relay link");
    pDesk->nPrevSessionUntilMs = XTime_GetMonoMs();
    g_sLogged[0] = '\0';
    data_channel_as(pDesk, &peer, DirectGate_Proto_BuildKeepalive("pong", 81), 81);
    CHECK(pDesk->nLastKAPongMs == 0, "nor on the data channel once the switch is long over");
    CHECK(strstr(g_sLogged, "without session E2E context") != NULL, "it reads as any unknown id");

    /* The relay speaking of the old id now - its socket timing out at last - is not about this session */
    relay_status(&conn, &relay, 81, NULL);
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 91) == pDesk, "a late notice for the old id leaves the session alone");

    /* It can be resumed again: the next socket lost, the next one taken */
    relay_status(&conn, &relay, 91, "lost");
    CHECK(pDesk->bDetached, "the resumed session detaches like any other");
    CHECK(seal_resume_proof(&peer, 91, 101, DETACH_DEVICE_ID, sProof, sizeof(sProof)), "a second proof is sealed");
    send_resume(&conn, &relay, 101, 91, sProof);
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 101) == pDesk && !pDesk->bDetached, "and it is resumed again");
    CHECK(pDesk->nPrevSessionId == 91, "the newest old id is the one remembered");
    XByteBuffer_Clear(&relay.txBuffer);

    /* An attached desktop whose relay socket the relay has not noticed is gone yet resumes the same way */
    directgate_e2e_t attachedPeer;
    directgate_session_t *pAttached = detach_session(&conn, &relay, 82, &attachedPeer);
    CHECK(pAttached != NULL && !pAttached->bDetached, "an attached desktop is up");
    CHECK(seal_resume_proof(&attachedPeer, 82, 92, DETACH_DEVICE_ID, sProof, sizeof(sProof)), "its proof is sealed");
    send_resume(&conn, &relay, 92, 82, sProof);
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 92) == pAttached && pAttached->pWsSession == &relay,
        "a session on a socket the relay still thinks alive moves to the new one");
    XByteBuffer_Clear(&relay.txBuffer);

    /* Refusals: each leaves the session as it was and answers "failed", so the client authenticates afresh */
    directgate_e2e_t detPeer;
    directgate_session_t *pDet = detach_session(&conn, &relay, 83, &detPeer);
    CHECK(pDet != NULL, "a desktop to refuse resumes for is up");
    relay_status(&conn, &relay, 83, "lost");
    XByteBuffer_Clear(&relay.txBuffer);

    CHECK(seal_resume_proof(&detPeer, 83, 93, DETACH_DEVICE_ID, sProof, sizeof(sProof)), "a proof for 93 is sealed");
    send_resume(&conn, &relay, 94, 83, sProof);
    if (expect_refused(&conn, &relay, 94, pDet, 83, "a proof bound to another id", "invalid proof") != 0) return 1;
    send_resume(&conn, &relay, 93, 83, sProof);
    if (expect_refused(&conn, &relay, 93, pDet, 83, "a proof already opened, even if refused", "invalid proof") != 0) return 1;

    CHECK(seal_resume_proof(&detPeer, 83, 95, "another-device", sProof, sizeof(sProof)), "a foreign proof is sealed");
    send_resume(&conn, &relay, 95, 83, sProof);
    if (expect_refused(&conn, &relay, 95, pDet, 83, "a proof for another device", "invalid proof") != 0) return 1;

    directgate_e2e_t strangerPeer;
    DirectGate_E2E_Init(&strangerPeer);
    uint8_t sKey[32], agentNonce[DIRECTGATE_SRP_NONCE_SIZE], clientNonce[DIRECTGATE_SRP_NONCE_SIZE];
    memset(sKey, 0x7a, sizeof(sKey));
    memset(agentNonce, 0x11, sizeof(agentNonce));
    memset(clientNonce, 0x22, sizeof(clientNonce));
    CHECK(DirectGate_E2E_DeriveFromSRP(&strangerPeer, sKey, sizeof(sKey), agentNonce, clientNonce,
        sizeof(agentNonce), DETACH_DEVICE_ID, XFALSE), "a stranger's keys are derived");
    CHECK(seal_resume_proof(&strangerPeer, 83, 96, DETACH_DEVICE_ID, sProof, sizeof(sProof)), "a stranger's proof");
    send_resume(&conn, &relay, 96, 83, sProof);
    if (expect_refused(&conn, &relay, 96, pDet, 83, "a proof under other keys", "invalid proof") != 0) return 1;
    DirectGate_E2E_Clear(&strangerPeer);

    CHECK(seal_resume_proof(&detPeer, 83, 97, DETACH_DEVICE_ID, sProof, sizeof(sProof)), "a proof for 97 is sealed");
    send_resume(&conn, &relay, 97, 83, NULL);
    if (expect_refused(&conn, &relay, 97, pDet, 83, "a request without a proof", "malformed request") != 0) return 1;
    send_resume(&conn, &relay, 97, 0, sProof);
    if (expect_refused(&conn, &relay, 97, pDet, 83, "a request without the old id", "malformed request") != 0) return 1;
    send_resume(&conn, &relay, 97, 84, sProof);
    if (expect_refused(&conn, &relay, 97, NULL, 84, "a request for no such session", "no such session") != 0) return 1;
    send_resume(&conn, &relay, 101, 83, sProof);
    CHECK(relay.txBuffer.nUsed == 0, "a resume on another live session's id is plaintext where it must not be: dropped");
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 101) == pDesk && DirectGate_SessionMgr_Find(&conn.mgr, 83) == pDet &&
        pDet->bDetached && !pDesk->bDetached, "without touching either session");

    /* A proof has to be the session's own sealed resume, for the session it names */
    char sOdd[2048];
    CHECK(seal_odd_proof(&detPeer, "auth", "resume", 83, 83, 0, sOdd, sizeof(sOdd)), "an unsealed proof is built");
    send_resume(&conn, &relay, 97, 83, sOdd);
    if (expect_refused(&conn, &relay, 97, pDet, 83, "a proof that is not sealed", "malformed proof") != 0) return 1;
    CHECK(seal_odd_proof(&detPeer, "auth", "resume", 83, 84, 1, sOdd, sizeof(sOdd)), "a misaddressed proof is sealed");
    send_resume(&conn, &relay, 97, 83, sOdd);
    if (expect_refused(&conn, &relay, 97, pDet, 83, "a proof sealed for another id", "malformed proof") != 0) return 1;
    CHECK(seal_odd_proof(&detPeer, "auth", "resume", 84, 83, 1, sOdd, sizeof(sOdd)), "a proof naming another session");
    send_resume(&conn, &relay, 97, 83, sOdd);
    if (expect_refused(&conn, &relay, 97, pDet, 83, "a proof that names another session", "invalid proof") != 0) return 1;
    CHECK(seal_odd_proof(&detPeer, "auth", "hello", 83, 83, 1, sOdd, sizeof(sOdd)), "a proof of another action");
    send_resume(&conn, &relay, 97, 83, sOdd);
    if (expect_refused(&conn, &relay, 97, pDet, 83, "a sealed message that is not a resume", "invalid proof") != 0) return 1;
    CHECK(seal_odd_proof(&detPeer, "keepalive", "resume", 83, 83, 1, sOdd, sizeof(sOdd)), "a proof of another type");
    send_resume(&conn, &relay, 97, 83, sOdd);
    if (expect_refused(&conn, &relay, 97, pDet, 83, "a sealed message that is not auth", "invalid proof") != 0) return 1;

    /* A client that began authenticating on the new id already has a session there */
    directgate_session_t *pPending = DirectGate_SessionMgr_Create(&conn.mgr, 98);
    CHECK(pPending != NULL, "a session still authenticating is up");
    CHECK(seal_resume_proof(&detPeer, 83, 98, DETACH_DEVICE_ID, sOdd, sizeof(sOdd)), "a proof for its id is sealed");
    send_resume(&conn, &relay, 98, 83, sOdd);
    CHECK(read_auth_result(&relay.txBuffer, 98, &result) && !strcmp(result.sStatus, "failed"), "a new id in use");
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 98) == pPending && DirectGate_SessionMgr_Find(&conn.mgr, 83) == pDet &&
        pDet->bDetached, "is refused, leaving both sessions as they were");
    DirectGate_SessionMgr_Remove(&conn.mgr, pPending);
    XByteBuffer_Clear(&relay.txBuffer);

    char sHuge[4096];
    memset(sHuge, 'A', sizeof(sHuge) - 1);
    sHuge[sizeof(sHuge) - 1] = '\0';
    send_resume(&conn, &relay, 97, 83, sHuge);
    if (expect_refused(&conn, &relay, 97, pDet, 83, "a proof larger than any could be", "malformed proof") != 0) return 1;
    send_resume(&conn, &relay, 97, 83, "!!!not-base64!!!");
    if (expect_refused(&conn, &relay, 97, pDet, 83, "a proof that is not base64", "malformed proof") != 0) return 1;

    /* Only a session that could outlive its route, inside its minute: then the same proof still works */
    pDet->nDetachedMs = XTime_GetMonoMs() - DIRECTGATE_SESSION_DETACHED_MAX_MS;
    send_resume(&conn, &relay, 97, 83, sProof);
    if (expect_refused(&conn, &relay, 97, pDet, 83, "a session detached a minute ago", "session expired") != 0) return 1;
    pDet->nDetachedMs = XTime_GetMonoMs();
    pDet->webrtc.bConnected = XFALSE;
    send_resume(&conn, &relay, 97, 83, sProof);
    if (expect_refused(&conn, &relay, 97, pDet, 83, "a session whose data channel is gone", "session cannot be resumed") != 0)
        return 1;
    pDet->webrtc.bConnected = XTRUE;
    pDet->bDesktopShare = XTRUE;
    send_resume(&conn, &relay, 97, 83, sProof);
    if (expect_refused(&conn, &relay, 97, pDet, 83, "a temporary share's guest", "session cannot be resumed") != 0) return 1;
    pDet->bDesktopShare = XFALSE;
    pDet->eActiveMode = DIRECTGATE_SESSION_MODE_TERMINAL;
    send_resume(&conn, &relay, 97, 83, sProof);
    if (expect_refused(&conn, &relay, 97, pDet, 83, "a session that is not a desktop", "session cannot be resumed") != 0)
        return 1;
    pDet->eActiveMode = DIRECTGATE_SESSION_MODE_DESKTOP;

    /* Nor off the relay link: a resume put on a data channel, plaintext or not, is not heard */
    xbyte_buffer_t plain;
    XByteBuffer_Init(&plain, XSTDNON, XFALSE);
    xjson_obj_t *pOff = DirectGate_Proto_NewHeader("auth", 97);
    XJSON_AddString(pOff, "action", "resume");
    XJSON_AddU32(pOff, "resumeSid", 83);
    XJSON_AddString(pOff, "proof", sProof);
    CHECK(DirectGate_Proto_Build(&plain, pOff, NULL, 0, XFALSE), "an off-link resume is built");
    XJSON_FreeObject(pOff);
    DirectGate_TestHandleDataChannelMessage(pDet, plain.pData, plain.nUsed);
    XByteBuffer_Clear(&plain);
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 97) == NULL && pDet->bDetached && relay.txBuffer.nUsed == 0,
        "a resume off a data channel moves nothing and is not answered");

    /* Under the session's own id, the data channel is still no place for plaintext: a protocol violation, as ever */
    xjson_obj_t *pOwnOff = DirectGate_Proto_NewHeader("auth", 83);
    XJSON_AddString(pOwnOff, "action", "resume");
    XJSON_AddU32(pOwnOff, "resumeSid", 83);
    XJSON_AddString(pOwnOff, "proof", sProof);
    CHECK(DirectGate_Proto_Build(&plain, pOwnOff, NULL, 0, XFALSE), "an own-id resume for the data channel is built");
    XJSON_FreeObject(pOwnOff);
    g_sLogged[0] = '\0';
    DirectGate_TestHandleDataChannelMessage(pDet, plain.pData, plain.nUsed);
    XByteBuffer_Clear(&plain);
    CHECK(strstr(g_sLogged, "Protocol violation") != NULL && pDet->bDetached && relay.txBuffer.nUsed == 0,
        "an own-id resume off a data channel is plaintext where it may not be");

    /* After all of those, the proof that was never opened still resumes the session */
    send_resume(&conn, &relay, 97, 83, sProof);
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 97) == pDet && !pDet->bDetached, "the untouched proof still works");
    CHECK(read_auth_result(&relay.txBuffer, 97, &result) && open_resume_answer(&detPeer, result.sProof, 97, 83,
        DETACH_DEVICE_ID), "and is answered by the agent");

    /* A relay that restarted hands its ids out from 1 again: the new socket may get the very id the lost one had. The
       session's own resume under that id is the one relay message that does not end it; its proof decides. */
    directgate_e2e_t samePeer;
    directgate_session_t *pSame = detach_session(&conn, &relay, 88, &samePeer);
    CHECK(pSame != NULL, "a desktop whose id comes back is up");
    relay_status(&conn, &relay, 88, "lost");
    CHECK(pSame->bDetached, "and detached");
    CHECK(seal_resume_proof(&samePeer, 88, 88, DETACH_DEVICE_ID, sProof, sizeof(sProof)), "a same-id proof is sealed");
    XByteBuffer_Clear(&relay.txBuffer);
    send_resume(&conn, &relay, 88, 88, sProof);
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 88) == pSame && !pSame->bDetached && pSame->pWsSession == &relay,
        "a resume under the same id takes the session back");
    CHECK(pSame->nPrevSessionId == 0, "with no old id to keep taking");
    CHECK(read_auth_result(&relay.txBuffer, 88, &result) && result.bResumed &&
        open_resume_answer(&samePeer, result.sProof, 88, 88, DETACH_DEVICE_ID), "and the agent answers it as its own");
    XByteBuffer_Clear(&relay.txBuffer);

    /* Under the same id, a proof the session's keys do not open is refused, and the session stays as it was: the
       first message of a new session on that id ends it, as before */
    relay_status(&conn, &relay, 88, "lost");
    CHECK(pSame->bDetached, "the same-id session detaches again");
    directgate_e2e_t samePeerStranger;
    DirectGate_E2E_Init(&samePeerStranger);
    memset(sKey, 0x6b, sizeof(sKey));
    CHECK(DirectGate_E2E_DeriveFromSRP(&samePeerStranger, sKey, sizeof(sKey), agentNonce, clientNonce,
        sizeof(agentNonce), DETACH_DEVICE_ID, XFALSE), "a stranger's keys for the same id");
    CHECK(seal_resume_proof(&samePeerStranger, 88, 88, DETACH_DEVICE_ID, sProof, sizeof(sProof)), "a stranger's proof");
    send_resume(&conn, &relay, 88, 88, sProof);
    if (expect_refused(&conn, &relay, 88, pSame, 88, "a same-id proof under other keys", "invalid proof") != 0) return 1;
    DirectGate_E2E_Clear(&samePeerStranger);
    xjson_obj_t *pHello = DirectGate_Proto_NewHeader("auth", 88);
    XJSON_AddString(pHello, "action", "hello");
    XJSON_AddU32(pHello, "resumeSid", 88);
    send_header(&conn, &relay, pHello);
    directgate_session_t *pAfter = DirectGate_SessionMgr_Find(&conn.mgr, 88);
    CHECK(pAfter == NULL || (!pAfter->bAuthenticated && !pAfter->bDetached), "a new session's hello on that id ends it");
    DirectGate_E2E_Clear(&samePeer);
    XByteBuffer_Clear(&relay.txBuffer);

    /* A resume for another session, on an id a stale detached session still holds: the stale one goes, as any relay
       message for its id ends it, and the session asked for takes the id */
    directgate_e2e_t stalePeer, targetPeer;
    directgate_session_t *pStale = detach_session(&conn, &relay, 111, &stalePeer);
    directgate_session_t *pTarget = detach_session(&conn, &relay, 112, &targetPeer);
    CHECK(pStale != NULL && pTarget != NULL, "a stale and a wanted detached session are up");
    relay_status(&conn, &relay, 111, "lost");
    relay_status(&conn, &relay, 112, "lost");
    CHECK(seal_resume_proof(&targetPeer, 112, 111, DETACH_DEVICE_ID, sProof, sizeof(sProof)), "a proof onto 111");
    send_resume(&conn, &relay, 111, 112, sProof);
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 111) == pTarget && !pTarget->bDetached && pTarget->nPrevSessionId == 112,
        "the wanted session takes over the id the stale one held");
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 112) == NULL, "and no longer goes by its old one");
    DirectGate_E2E_Clear(&stalePeer);
    DirectGate_E2E_Clear(&targetPeer);

    XByteBuffer_Clear(&relay.txBuffer);
    DirectGate_E2E_Clear(&peer);
    DirectGate_E2E_Clear(&attachedPeer);
    DirectGate_E2E_Clear(&detPeer);
    DirectGate_SessionMgr_Destroy(&conn.mgr);
    xlog_destroy();
    return 0;
}

int main(void)
{
    directgate_desktop_t desktop;
    DirectGate_Desktop_Init(&desktop);
    directgate_desktop_monitor_t monitor;
    memset(&monitor, 0, sizeof(monitor));
    DirectGate_Desktop_AddMonitorMode(&monitor, 1920, 1080);
    DirectGate_Desktop_AddMonitorMode(&monitor, 1920, 1080);
    DirectGate_Desktop_AddMonitorMode(&monitor, 1600, 900);
    CHECK(monitor.nModeCount == 2U,
        "desktop monitor modes should be advertised once per resolution");

    desktop.nTargetWidth = 1280;
    desktop.nTargetHeight = 800;
    uint32_t nWidth = 0;
    uint32_t nHeight = 0;
    DirectGate_Desktop_ComputeOutputSize(&desktop, 2560, 1440, &nWidth, &nHeight);
    CHECK(nWidth == 1280 && nHeight == 720,
        "desktop output should aspect-fit the browser viewport");

    desktop.nTargetWidth = 2560;
    desktop.nTargetHeight = 1440;
    DirectGate_Desktop_ComputeOutputSize(&desktop, 1280, 720, &nWidth, &nHeight);
    CHECK(nWidth == 1280 && nHeight == 720,
        "desktop output must never upscale above the capture size");

    desktop.eResizeMode = DIRECTGATE_DESKTOP_RESIZE_DISPLAY;
    desktop.nTargetWidth = 800;
    desktop.nTargetHeight = 600;
    DirectGate_Desktop_ComputeOutputSize(&desktop, 1024, 768, &nWidth, &nHeight);
    CHECK(nWidth == 1024 && nHeight == 768,
        "display mode must encode the resized display without a second scale");
    DirectGate_Desktop_Clear(&desktop);

    directgate_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    xstrncpy(cfg.auth.sSaltHex, sizeof(cfg.auth.sSaltHex),
        "00000000000000000000000000000000"
        "00000000000000000000000000000000");
    xstrncpy(cfg.auth.sVerifierHex, sizeof(cfg.auth.sVerifierHex), "configured");

    directgate_conn_t conn;
    memset(&conn, 0, sizeof(conn));
    conn.pCfg = &cfg;
    DirectGate_SessionMgr_Init(&conn.mgr, &cfg);

    xapi_session_t firstRelay;
    CHECK(dispatch(&conn, &firstRelay, XAPI_CB_CONNECTED) == XAPI_CONTINUE,
        "initial relay connection should be accepted");

    /* Liveness is measured on the monotonic clock, so a change of the system
       time can neither fake a dead relay nor hide one. A wall clock stamp is
       some fifty years of milliseconds past it. */
    uint64_t nMonoMs = XTime_GetMonoMs();
    CHECK(conn.nLastRelayRecvMs <= nMonoMs && nMonoMs - conn.nLastRelayRecvMs < 60000ULL,
        "relay liveness should be stamped on the monotonic clock");
    CHECK(conn.pWsSession == &firstRelay,
        "initial relay connection should be attached");
    CHECK(DirectGate_SessionMgr_IsEmpty(&conn.mgr),
        "new connection manager should be empty");

    CHECK(send_header(&conn, &firstRelay,
        DirectGate_Proto_BuildCmd("start", NULL, NULL, "terminal", 50)) == XAPI_CONTINUE,
        "pre-auth start without a session should be ignored");
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 50) == NULL,
        "pre-auth start must not create a session");

    directgate_session_t *pUnauth = DirectGate_SessionMgr_Create(&conn.mgr, 51);
    CHECK(pUnauth != NULL, "unauthenticated test session should be created");
    pUnauth->pWsSession = &firstRelay;

    CHECK(send_header(&conn, &firstRelay,
        DirectGate_Proto_BuildCmd("start", NULL, NULL, "terminal", 51)) == XAPI_CONTINUE,
        "pre-auth start for an existing session should be ignored");
    CHECK(pUnauth->eRequestedMode == DIRECTGATE_SESSION_MODE_NONE,
        "pre-auth start must not prime a requested mode");

    xjson_obj_t *pOffer = DirectGate_Proto_NewHeader("webrtc", 51);
    CHECK(pOffer != NULL, "build pre-auth WebRTC offer");
    XJSON_AddString(pOffer, "action", "offer");
    XJSON_AddString(pOffer, "sdp", "malicious pre-auth offer");
    CHECK(send_header(&conn, &firstRelay, pOffer) == XAPI_CONTINUE,
        "pre-auth WebRTC offer should be ignored");
    CHECK(pUnauth->webrtc.signalCb == NULL && pUnauth->webrtc.nPeerConnectionID < 0,
        "pre-auth WebRTC offer must not initialize libdatachannel");

    CHECK(send_header(&conn, &firstRelay,
        DirectGate_Proto_BuildStatus("closed", 51)) == XAPI_CONTINUE,
        "pre-auth closed status should be ignored");

    /* A message of a type this agent does not know, or of no type at all, is dropped and the link stays up */
    CHECK(send_header(&conn, &firstRelay, DirectGate_Proto_NewHeader("from-the-future", 0)) == XAPI_CONTINUE,
        "a message of an unknown type should be ignored");
    xjson_obj_t *pUntyped = XJSON_NewObject(NULL, NULL, XFALSE);
    CHECK(pUntyped != NULL && XJSON_AddInt(pUntyped, "version", 1) == XJSON_ERR_NONE, "build an untyped header");
    CHECK(send_header(&conn, &firstRelay, pUntyped) == XAPI_CONTINUE, "a message without a type should be ignored");
    CHECK(conn.pWsSession == &firstRelay, "dropped messages should leave the relay attached");
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 51) == pUnauth,
        "pre-auth closed status must not remove a session");

    pUnauth->bAuthenticated = XTRUE;
    CHECK(send_header(&conn, &firstRelay,
        DirectGate_Proto_BuildStatus("closed", 0)) == XAPI_CONTINUE,
        "session-zero closed status should be ignored");
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 51) == pUnauth,
        "session-zero closed status must not perform global cleanup");

    CHECK(send_header(&conn, &firstRelay,
        DirectGate_Proto_BuildStatus("closed", 51)) == XAPI_CONTINUE,
        "authenticated closed status should be accepted");
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 51) == NULL,
        "authenticated closed status should remove its session");

    /* The relay turns a departed client into a closed status, which always
       arrives after an agent-initiated close has already dropped the
       session. Re-delivering it must stay a quiet no-op. */
    CHECK(send_header(&conn, &firstRelay,
        DirectGate_Proto_BuildStatus("closed", 51)) == XAPI_CONTINUE,
        "closed status for an already removed session should be ignored");

    directgate_session_t *pSession = DirectGate_SessionMgr_Create(&conn.mgr, 1);
    CHECK(pSession != NULL, "logical session should be created");
    pSession->pWsSession = &firstRelay;
    conn.mgr.nAuthWindowStartMs = XTime_GetMonoMs();
    conn.mgr.nAuthAttempts = 7;

    CHECK(dispatch(&conn, &firstRelay, XAPI_CB_CLOSED) == XAPI_CONTINUE,
        "relay disconnect should be handled");
    CHECK(conn.pWsSession == NULL,
        "relay disconnect should detach the websocket");
    CHECK(DirectGate_SessionMgr_IsEmpty(&conn.mgr),
        "relay disconnect should remove every logical session");
    CHECK(conn.mgr.nAuthAttempts == 7,
        "relay disconnect should preserve auth-rate state");

    xapi_session_t secondRelay;
    CHECK(dispatch(&conn, &secondRelay, XAPI_CB_CONNECTED) == XAPI_CONTINUE,
        "clean relay reconnect should be accepted");
    CHECK(conn.pWsSession == &secondRelay,
        "clean relay reconnect should attach the new websocket");
    CHECK(conn.mgr.nAuthAttempts == 7,
        "relay reconnect should preserve auth-rate state");

    CHECK(dispatch(&conn, &secondRelay, XAPI_CB_CLOSED) == XAPI_CONTINUE,
        "second relay disconnect should be handled");
    CHECK(DirectGate_SessionMgr_Create(&conn.mgr, 2) != NULL,
        "test should create a stale logical session");

    xapi_session_t staleReconnect;
    CHECK(dispatch(&conn, &staleReconnect, XAPI_CB_CONNECTED) == XAPI_CONTINUE,
        "relay reconnect with stale logical sessions should recover");
    CHECK(conn.pWsSession == &staleReconnect,
        "recovered relay reconnect should attach its websocket");
    CHECK(DirectGate_SessionMgr_IsEmpty(&conn.mgr),
        "relay reconnect recovery should remove stale sessions");
    CHECK(conn.mgr.nAuthAttempts == 7,
        "stale reconnect recovery should preserve auth-rate state");

    CHECK(dispatch(&conn, &staleReconnect, XAPI_CB_CLOSED) == XAPI_CONTINUE,
        "recovered relay disconnect should be handled");

    /* Keepalive travels on the data channel, so its schedule must not survive
       a stretch where that channel is down. A frozen pong timestamp used to
       expire a session the instant a renegotiated channel opened, which took
       a device offline in the middle of a long file transfer. */
    xapi_session_t kaRelay;
    CHECK(dispatch(&conn, &kaRelay, XAPI_CB_CONNECTED) == XAPI_CONTINUE,
        "keepalive test relay connection should be accepted");

    cfg.nKAInterval = 25;
    directgate_session_t *pKeepalive = DirectGate_SessionMgr_Create(&conn.mgr, 90);
    CHECK(pKeepalive != NULL, "keepalive test session should be created");
    pKeepalive->pWsSession = &kaRelay;
    pKeepalive->bAuthenticated = XTRUE;

    uint64_t nStaleMs = XTime_GetMonoMs() - (uint64_t)cfg.nKAInterval * 3000ULL * 2ULL;
    pKeepalive->nLastKAPingMs = nStaleMs;
    pKeepalive->nLastKAPongMs = nStaleMs;
    pKeepalive->webrtc.bConnected = XFALSE;

    DirectGate_TestCheckWebRTCKeepalive(&conn);
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 90) == pKeepalive,
        "a session without a data channel must not be expired by keepalive");
    CHECK(pKeepalive->nLastKAPingMs == 0 && pKeepalive->nLastKAPongMs == 0,
        "keepalive schedule must be cleared while the data channel is down");

    /* Channel back up: the next pass re-arms the schedule from now instead of
       measuring the pong age against the gap that just ended. */
    pKeepalive->webrtc.bConnected = XTRUE;
    pKeepalive->webrtc.nDataChannelID = 0;

    DirectGate_TestCheckWebRTCKeepalive(&conn);
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 90) == pKeepalive,
        "a session must survive the first keepalive pass after the channel returns");
    CHECK(pKeepalive->nLastKAPongMs != 0,
        "keepalive schedule should re-arm once the data channel is back");
    CHECK(pKeepalive->nLastKAPongMs <= XTime_GetMonoMs() + (uint64_t)cfg.nKAInterval * 1000ULL,
        "keepalive schedule should be armed on the monotonic clock");

    /* With the channel up: a ping goes out once an interval has passed, a pass after a stalled loop restarts
       the schedule instead of pinging into it, and a pong older than three intervals ends the session. */
    cfg.nKAInterval = 1;
    uint64_t nBeforeMs = XTime_GetMonoMs();
    pKeepalive->nLastKAPingMs = nBeforeMs - 1500ULL;
    pKeepalive->nLastKAPongMs = nBeforeMs;

    DirectGate_TestCheckWebRTCKeepalive(&conn);
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 90) == pKeepalive && pKeepalive->nLastKAPingMs >= nBeforeMs,
        "a ping should go out once the interval has passed");
    CHECK(!pKeepalive->webrtc.bConnected, "a ping the data channel refused should mark the channel down");

    pKeepalive->webrtc.bConnected = XTRUE;
    nBeforeMs = XTime_GetMonoMs();
    pKeepalive->nLastKAPingMs = nBeforeMs - 7000ULL;
    pKeepalive->nLastKAPongMs = nBeforeMs;

    DirectGate_TestCheckWebRTCKeepalive(&conn);
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 90) == pKeepalive && pKeepalive->nLastKAPingMs >= nBeforeMs,
        "a stalled loop should restart the ping schedule from now");

    pKeepalive->webrtc.bConnected = XTRUE;
    nBeforeMs = XTime_GetMonoMs();
    pKeepalive->nLastKAPingMs = nBeforeMs;
    pKeepalive->nLastKAPongMs = nBeforeMs - 3000ULL;

    DirectGate_TestCheckWebRTCKeepalive(&conn);
    CHECK(DirectGate_SessionMgr_Find(&conn.mgr, 90) == NULL,
        "a session whose last pong is three intervals old should be closed");
    CHECK(kaRelay.txBuffer.nUsed > 0, "the ping and the close went out over the relay");
    XByteBuffer_Clear(&kaRelay.txBuffer);

    CHECK(dispatch(&conn, &kaRelay, XAPI_CB_CLOSED) == XAPI_CONTINUE,
        "keepalive test relay disconnect should be handled");
    DirectGate_SessionMgr_Destroy(&conn.mgr);

    /*
       A PTY reaching EOF raises a status event on its own XAPI_CUSTOM
       endpoint, whose pSessionData is a terminal - not a connection. Treating
       it as one used to schedule a relay reconnect and write the attempt
       counter far past the end of the terminal object, which wedged the agent
       and dropped the device offline every time a remote shell exited.

       The buffer is connection-sized so a regression lands inside it rather
       than corrupting unrelated memory, and zeroed because that is what a
       real terminal object looks like: a non-zero nNextReconnectMs would
       make the buggy path skip the reconnect and hide the write.
    */
    unsigned char sForeign[sizeof(directgate_conn_t)];
    memset(sForeign, 0, sizeof(sForeign));

    xapi_session_t custom;
    memset(&custom, 0, sizeof(custom));
    custom.eRole = XAPI_CUSTOM;
    custom.pSessionData = sForeign;
    custom.sock.nFD = XSOCK_INVALID;

    xapi_ctx_t statusCtx;
    memset(&statusCtx, 0, sizeof(statusCtx));
    statusCtx.eCbType = XAPI_CB_STATUS;
    statusCtx.eStatType = XAPI_SELF;
    statusCtx.nStatus = XAPI_HUNGED;

    CHECK(DirectGate_ServiceCallback(&statusCtx, &custom) == XAPI_CONTINUE,
        "a hung custom endpoint should be reported without further action");

    for (size_t i = 0; i < sizeof(sForeign); i++)
    {
        CHECK(sForeign[i] == 0,
            "custom endpoint data must never be written through as a connection");
    }

    /* A relay error frame is unauthenticated and unencrypted, so a claim that this device is no longer enrolled
       must not be acted on locally. It only marks the enrollment for a check against the API on the next connect;
       clearing the tokens here would let one injected frame take the device offline until somebody re-pairs it. */
    directgate_cfg_t revokeCfg;
    memset(&revokeCfg, 0, sizeof(revokeCfg));
    xstrncpy(revokeCfg.auth.sSaltHex, sizeof(revokeCfg.auth.sSaltHex),
        "00000000000000000000000000000000"
        "00000000000000000000000000000000");
    xstrncpy(revokeCfg.auth.sVerifierHex, sizeof(revokeCfg.auth.sVerifierHex), "configured");
    xstrncpy(revokeCfg.enroll.sAccessToken, sizeof(revokeCfg.enroll.sAccessToken), "access-token");
    xstrncpy(revokeCfg.enroll.sRefreshToken, sizeof(revokeCfg.enroll.sRefreshToken), "refresh-token");
    xstrncpy(revokeCfg.sRelayUrl, sizeof(revokeCfg.sRelayUrl), "wss://relay1.directgate.io/websock");
    xstrncpy(revokeCfg.sRoutingKey, sizeof(revokeCfg.sRoutingKey), "routing-key");
    revokeCfg.enroll.bEnrolled = XTRUE;

    directgate_conn_t revokeConn;
    memset(&revokeConn, 0, sizeof(revokeConn));
    revokeConn.pCfg = &revokeCfg;
    DirectGate_SessionMgr_Init(&revokeConn.mgr, &revokeCfg);

    xapi_session_t revokeRelay;
    CHECK(dispatch(&revokeConn, &revokeRelay, XAPI_CB_CONNECTED) == XAPI_CONTINUE,
        "relay connection for the revocation test should be accepted");

    CHECK(send_header(&revokeConn, &revokeRelay,
        DirectGate_Proto_BuildError("device-revoked", 0)) == XAPI_CONTINUE,
        "a relay revocation claim should be accepted as a message");

    CHECK(!revokeConn.bReconnectSuppressed,
        "a relay revocation claim must not suppress reconnects on its own");
    CHECK(revokeConn.bEnrollmentDoubt,
        "a relay revocation claim should mark the enrollment for an API check");
    CHECK(revokeCfg.enroll.bEnrolled,
        "a relay revocation claim must not clear the enrollment");
    CHECK(strcmp(revokeCfg.enroll.sRefreshToken, "refresh-token") == 0,
        "a relay revocation claim must not wipe the refresh token");
    CHECK(strcmp(revokeCfg.sRoutingKey, "routing-key") == 0,
        "a relay revocation claim must not wipe the routing key");

    /* Every reason that casts doubt on the enrollment is treated the same way; any other is not. */
    static const char *pDoubts[] = {
        "device-enrollment-expired", "device-reenroll", "refresh-token-reuse", "invalid-refresh-token"
    };

    for (size_t i = 0; i < sizeof(pDoubts) / sizeof(pDoubts[0]); i++)
    {
        revokeConn.bEnrollmentDoubt = XFALSE;
        CHECK(send_header(&revokeConn, &revokeRelay, DirectGate_Proto_BuildError(pDoubts[i], 0)) == XAPI_CONTINUE,
            "a relay enrollment claim is accepted as a message");
        CHECK(revokeConn.bEnrollmentDoubt && revokeCfg.enroll.bEnrolled && !revokeConn.bReconnectSuppressed,
            "each enrollment claim only marks the enrollment for an API check");
    }

    revokeConn.bEnrollmentDoubt = XFALSE;
    CHECK(send_header(&revokeConn, &revokeRelay, DirectGate_Proto_BuildError("rate-limited", 0)) == XAPI_CONTINUE,
        "another relay error is accepted as a message");
    CHECK(!revokeConn.bEnrollmentDoubt, "an error about something else casts no doubt on the enrollment");

    DirectGate_SessionMgr_Destroy(&revokeConn.mgr);
    if (test_loop_stall() != 0) return 1;
    if (test_relay_probe() != 0) return 1;
    if (test_detach() != 0) return 1;
    if (test_resume() != 0) return 1;

    puts("connection_lifecycle_smoke: OK");
    return 0;
}
