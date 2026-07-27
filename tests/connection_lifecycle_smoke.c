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
    DirectGate_SessionMgr_Destroy(&conn.mgr);
    puts("connection_lifecycle_smoke: OK");
    return 0;
}
