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
    conn.bRoleSent = XTRUE;

    /* Silent for the probe interval with nothing queued: the probe is owed an answer within seconds */
    uint64_t nNowMs = XTime_GetMonoMs();
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

    puts("connection_lifecycle_smoke: OK");
    return 0;
}
