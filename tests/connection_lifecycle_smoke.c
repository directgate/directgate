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
    conn.mgr.nAuthWindowStartMs = XTime_GetMs();
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

    uint64_t nStaleMs = XTime_GetMs() - (uint64_t)cfg.nKAInterval * 3000ULL * 2ULL;
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

    pKeepalive->webrtc.bConnected = XFALSE;
    pKeepalive->webrtc.nDataChannelID = -1;

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

    puts("connection_lifecycle_smoke: OK");
    return 0;
}
