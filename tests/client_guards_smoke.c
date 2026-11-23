/*
 * What dgcli refuses or ignores: every send and handler without its context, configuration or socket, messages
 * with nothing parsed in them or no action, anything but role and auth before the login, the terminal and pipe
 * endpoints without their client, and the event loop callbacks once the client is finishing. Compiled straight
 * from client.c, its main renamed away, as client_io_smoke is.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define main dgcli_main
#include "src/client/client.c"
#undef main

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "client_guards_smoke: %s (line %d)\n", msg, __LINE__); \
            return 1; \
        } \
    } while (0)

static directgate_cfg_t g_cfg;
static directgate_ctx_t g_cli;

static void pkg_with(directgate_pkg_t *pPkg, void *pPackage)
{
    memset(pPkg, 0, sizeof(*pPkg));
    pPkg->pPackage = pPackage;
}

static int check_sending(void)
{
    DirectGate_Client_CleanseSecret(NULL);
    DirectGate_Client_Release(NULL);
    DirectGate_Client_CleanseSecretCtx(NULL);

    directgate_ctx_t bare;
    memset(&bare, 0, sizeof(bare));
    DirectGate_Client_CleanseSecretCtx(&bare);

    CHECK(DirectGate_Client_SetNonBlock(-1, XTRUE) < 0, "a descriptor that is not open cannot be made non-blocking");
    CHECK(DirectGate_Client_EnableRawIO(NULL) == XSTDINV, "no terminal state, no raw mode");
    DirectGate_Client_RestoreIO(NULL);
    CHECK(DirectGate_Client_WriteAll(STDOUT_FILENO, NULL, 1) == XSTDERR &&
          DirectGate_Client_WriteAll(STDOUT_FILENO, "x", 0) == XSTDNON, "writing needs bytes, and none is nothing");

    xjson_obj_t *pData = DirectGate_Proto_BuildData(1);
    xjson_obj_t *pRole = DirectGate_Proto_BuildRole("client", "device");
    CHECK(pData != NULL && pRole != NULL, "build headers");

    CHECK(DirectGate_Client_SendMsg(NULL, pData, NULL, 0) == XAPI_DISCONNECT &&
          DirectGate_Client_SendMsg(&g_cli, NULL, NULL, 0) == XAPI_DISCONNECT, "a message needs a client and a header");
    CHECK(DirectGate_Client_SendMsg(&g_cli, pData, NULL, 0) == XAPI_CONTINUE, "data before the login is held back");
    CHECK(DirectGate_Client_SendMsg(&g_cli, pRole, NULL, 0) == XAPI_DISCONNECT, "and a role with nowhere to go fails");
    CHECK(DirectGate_Client_Transfer_SendCb(pData, NULL, 0, NULL) == XSTDERR &&
          DirectGate_Client_Transfer_SendCb(NULL, NULL, 0, &g_cli) == XSTDERR, "a file chunk needs a client and a header");
    XJSON_FreeObject(pData);
    XJSON_FreeObject(pRole);

    DirectGate_Client_WebRTC_SignalCb("{}", 2, NULL);
    DirectGate_Client_WebRTC_SignalCb(NULL, 2, &g_cli);
    DirectGate_Client_WebRTC_SignalCb("{}", 0, &g_cli);
    DirectGate_Client_WebRTC_SignalCb("{", 1, &g_cli);
    DirectGate_Client_WebRTC_DataCb((const uint8_t*)"x", 1, NULL);
    DirectGate_Client_WebRTC_DataCb(NULL, 1, &g_cli);
    DirectGate_Client_WebRTC_DataCb((const uint8_t*)"x", 0, &g_cli);

    /* Without a socket nothing goes anywhere */
    CHECK(DirectGate_Client_SendRole(&g_cli, "client", "device") == XAPI_DISCONNECT, "a role needs a socket");
    CHECK(DirectGate_Client_SendAuthHello(NULL) == XAPI_DISCONNECT && DirectGate_Client_SendAuthHello(&g_cli) == XAPI_DISCONNECT,
        "so does the password hello");
    CHECK(DirectGate_Client_SendData(NULL, (const uint8_t*)"x", 1) == XAPI_DISCONNECT &&
          DirectGate_Client_SendData(&g_cli, (const uint8_t*)"x", 1) == XAPI_DISCONNECT, "and data");
    CHECK(DirectGate_Client_SendResize(NULL) == XAPI_DISCONNECT && DirectGate_Client_SendResize(&g_cli) == XAPI_DISCONNECT,
        "and a window size");
    CHECK(DirectGate_Client_SendCmdStart(NULL, "shell") == XAPI_DISCONNECT &&
          DirectGate_Client_SendCmdStart(&g_cli, "shell") == XAPI_DISCONNECT, "and a start");

    xapi_session_t sock;
    memset(&sock, 0, sizeof(sock));
    sock.sock.nFD = XSOCK_INVALID;
    g_cli.pWsSession = &sock;
    g_cli.pCfg = NULL;
    CHECK(DirectGate_Client_SendAuthHello(&g_cli) == XAPI_DISCONNECT, "no configuration, no hello");
    CHECK(DirectGate_Client_SendData(&g_cli, NULL, 1) == XAPI_DISCONNECT, "data that is not there is not sent");
    g_cli.pCfg = &g_cfg;
    g_cli.pWsSession = NULL;

    char sRk[64];
    CHECK(!DirectGate_Client_ExtractRoutingKey("not-a-token", sRk, sizeof(sRk)), "a token with no payload has no routing key");
    return 0;
}

static int check_handlers(void)
{
    directgate_pkg_t pkg;
    pkg_with(&pkg, NULL);

    CHECK(DirectGate_Client_HandleAdminMsg(&g_cli, &pkg) == XAPI_DISCONNECT, "an admin answer with nothing in it ends it");
    CHECK(DirectGate_Client_HandleAuthMsg(NULL, &pkg) == XAPI_DISCONNECT &&
          DirectGate_Client_HandleAuthMsg(&g_cli, &pkg) == XAPI_DISCONNECT,
        "so does an auth message");
    directgate_pkg_auth_t auth = { 0 };
    pkg_with(&pkg, &auth);
    g_cli.pCfg = NULL;
    CHECK(DirectGate_Client_HandleAuthMsg(&g_cli, &pkg) == XAPI_DISCONNECT, "and one for a client with no configuration");
    g_cli.pCfg = &g_cfg;

    directgate_pkg_cmd_t cmd = { 0 };
    directgate_pkg_webrtc_t rtc = { 0 };
    directgate_pkg_file_t file = { 0 };

    pkg_with(&pkg, NULL);
    CHECK(DirectGate_Client_HandleCmdMsg(NULL, &pkg) == XAPI_DISCONNECT &&
          DirectGate_Client_HandleCmdMsg(&g_cli, &pkg) == XAPI_DISCONNECT,
        "a command needs a client and a command");
    pkg_with(&pkg, &cmd);
    CHECK(DirectGate_Client_HandleCmdMsg(&g_cli, &pkg) == XAPI_DISCONNECT, "and an action");

    pkg_with(&pkg, NULL);
    CHECK(DirectGate_Client_HandleWebRTCMsg(NULL, &pkg) == XAPI_DISCONNECT &&
          DirectGate_Client_HandleWebRTCMsg(&g_cli, &pkg) == XAPI_DISCONNECT, "so does a WebRTC message");
    pkg_with(&pkg, &rtc);
    CHECK(DirectGate_Client_HandleWebRTCMsg(&g_cli, &pkg) == XAPI_DISCONNECT, "with an action");

    pkg_with(&pkg, NULL);
    CHECK(DirectGate_Client_HandleFileMsg(NULL, &pkg, "relay") == XAPI_DISCONNECT &&
          DirectGate_Client_HandleFileMsg(&g_cli, &pkg, "relay") == XAPI_DISCONNECT, "and a file message");
    pkg_with(&pkg, &file);
    CHECK(DirectGate_Client_HandleFileMsg(&g_cli, &pkg, "relay") == XAPI_DISCONNECT, "with an action");

    /* Status, data, keepalive and errors with nothing in them are only looked at */
    pkg_with(&pkg, NULL);
    CHECK(DirectGate_Client_HandleStatusMsg(&pkg, "relay") == XAPI_CONTINUE, "a status with nothing in it is nothing");
    CHECK(DirectGate_Client_HandleDataMsg(NULL, &pkg) == XAPI_CONTINUE, "and data for nobody");
    CHECK(DirectGate_Client_HandleKeepaliveMsg(NULL, &pkg) == XAPI_CONTINUE, "a keepalive for nobody is not answered");
    directgate_pkg_keepalive_t pong = { .pAction = "pong" };
    pkg_with(&pkg, &pong);
    CHECK(DirectGate_Client_HandleKeepaliveMsg(&g_cli, &pkg) == XAPI_CONTINUE, "nor is a pong");
    pkg_with(&pkg, NULL);
    (void)DirectGate_Client_HandleErrorMsg(&g_cli, &pkg);

    CHECK(DirectGate_Client_DispatchMessage(NULL, &pkg, "relay") == XAPI_DISCONNECT &&
          DirectGate_Client_DispatchMessage(&g_cli, NULL, "relay") == XAPI_DISCONNECT &&
          DirectGate_Client_DispatchMessage(&g_cli, &pkg, "relay") == XAPI_DISCONNECT, "nothing parsed is nothing to dispatch");
    CHECK(DirectGate_Client_HandleMessage(NULL, (const uint8_t*)"x", 1, "relay") == XAPI_DISCONNECT &&
          DirectGate_Client_HandleMessage(&g_cli, NULL, 1, "relay") == XAPI_CONTINUE &&
          DirectGate_Client_HandleMessage(&g_cli, (const uint8_t*)"x", 0, "relay") == XAPI_CONTINUE,
        "an empty message is nothing, one for no client ends it");
    return 0;
}

static int check_loop(void)
{
    xapi_t api;
    memset(&api, 0, sizeof(api));
    xapi_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.pApi = &api;

    xapi_session_t sess;
    memset(&sess, 0, sizeof(sess));
    sess.sock.nFD = XSOCK_INVALID;
    sess.eRole = XAPI_CLIENT;

    CHECK(DirectGate_Client_HandshakeRequest(NULL, &sess) == XAPI_DISCONNECT &&
          DirectGate_Client_HandshakeRequest(&ctx, NULL) == XAPI_DISCONNECT, "a handshake needs a session and a loop");
    CHECK(DirectGate_Client_HandshakeResponse(NULL, &sess) == XAPI_DISCONNECT &&
          DirectGate_Client_HandshakeResponse(&ctx, NULL) == XAPI_DISCONNECT, "and so does its answer");
    CHECK(DirectGate_Client_HandleFrame(NULL, &sess) == XAPI_DISCONNECT &&
          DirectGate_Client_HandleFrame(&ctx, NULL) == XAPI_DISCONNECT &&
          DirectGate_Client_HandleFrame(&ctx, &sess) == XAPI_DISCONNECT, "a frame needs a session, a loop and a frame");
    CHECK(DirectGate_Client_InitSession(NULL, &sess) == XAPI_DISCONNECT &&
          DirectGate_Client_InitSession(&ctx, NULL) == XAPI_DISCONNECT,
        "a connection needs a session and a loop");
    CHECK(DirectGate_Client_DestroySession(NULL, &sess) == XAPI_DISCONNECT &&
          DirectGate_Client_DestroySession(&ctx, NULL) == XAPI_DISCONNECT,
        "and so does its end");

    /* Stdin and the WebRTC pipe are custom endpoints that carry the client */
    xapi_session_t term;
    memset(&term, 0, sizeof(term));
    term.eRole = XAPI_CUSTOM;
    term.sock.nFD = 1234;
    CHECK(DirectGate_Client_HandleStdin(NULL) == XAPI_DISCONNECT && DirectGate_Client_HandleStdin(&term) == XAPI_DISCONNECT,
        "stdin without its client is closed");
    term.pSessionData = &g_cli;
    CHECK(DirectGate_Client_HandleStdin(&term) == XAPI_DISCONNECT, "and with a client that has no socket");
    term.pSessionData = NULL;
    CHECK(DirectGate_Client_HandleFrame(&ctx, &term) == XAPI_DISCONNECT, "a custom endpoint without a client is closed");
    CHECK(DirectGate_Client_DestroySession(&ctx, &term) == XAPI_NO_ACTION, "and its end is nothing to do");
    term.pSessionData = &g_cli;
    CHECK(DirectGate_Client_DestroySession(&ctx, &term) == XAPI_NO_ACTION && g_cli.pPipeSession == NULL,
        "an endpoint that is not the pipe leaves the pipe alone");
    term.pSessionData = NULL;

    CHECK(DirectGate_Client_HandleRegistered(NULL) == XAPI_DISCONNECT &&
          DirectGate_Client_HandleRegistered(&sess) == XAPI_CONTINUE &&
          DirectGate_Client_HandleRegistered(&term) == XAPI_DISCONNECT, "a custom endpoint registers only with its client");

    CHECK(DirectGate_Client_Interrupt(&ctx) == XAPI_CONTINUE && DirectGate_Client_Tick(&ctx) == XAPI_CONTINUE,
        "a loop with no client keeps going");
    g_bFinish = XTRUE;
    CHECK(DirectGate_Client_Interrupt(&ctx) == XAPI_DISCONNECT && DirectGate_Client_Tick(&ctx) == XAPI_DISCONNECT,
        "until the client is finishing");
    g_bFinish = XFALSE;

    ctx.eCbType = XAPI_CB_COMPLETE;
    CHECK(DirectGate_Client_ServiceCallback(&ctx, NULL) == XAPI_DISCONNECT, "a finished send needs its session");
    return 0;
}

/* What the session wrote on stdout while pFn ran: its answers */
static size_t capture_stdout(void (*pFn)(directgate_ctx_t*), directgate_ctx_t *pCli, char *pOut, size_t nSize)
{
    int nPipe[2];
    if (pipe(nPipe) != 0) return 0;

    fflush(stdout);
    int nSaved = dup(STDOUT_FILENO);
    dup2(nPipe[1], STDOUT_FILENO);
    close(nPipe[1]);
    pFn(pCli);
    dup2(nSaved, STDOUT_FILENO);
    close(nSaved);

    ssize_t nRead = read(nPipe[0], pOut, nSize - 1);
    close(nPipe[0]);
    pOut[nRead > 0 ? nRead : 0] = '\0';
    return nRead > 0 ? (size_t)nRead : 0;
}

static void serve_next(directgate_ctx_t *pCli) { DirectGate_Client_ServeNext(pCli); }

/* dgcli session between its requests: what ends it, and what does not */
static int check_session(void)
{
    directgate_ctx_t sess;
    memset(&sess, 0, sizeof(sess));
    directgate_remote_req_t req;
    memset(&req, 0, sizeof(req));
    req.eOp = DIRECTGATE_REMOTE_SESSION;
    directgate_remote_t op;
    DirectGate_Remote_Init(&op, &req, NULL, NULL);
    sess.pRemote = &op;
    sess.bServe = XTRUE;
    g_bFinish = XFALSE;

    CHECK(DirectGate_Client_ServiceSession(&sess) == XAPI_CONTINUE && !g_bFinish, "a session not open yet waits for its route");

    uint64_t nNowMs = XTime_GetMonoMs();
    sess.bServeReady = XTRUE;
    sess.nServeStartMs = nNowMs;
    sess.nServeIdleMs = nNowMs;
    sess.nServeIdleLimitMs = DIRECTGATE_REMOTE_IDLE_MS;
    CHECK(DirectGate_Client_ServiceSession(&sess) == XAPI_CONTINUE && !g_bFinish, "a fresh session waits for requests");

    sess.bServeBusy = XTRUE;
    sess.nServeIdleMs = nNowMs - 2 * DIRECTGATE_REMOTE_IDLE_MS;
    sess.nServeStartMs = nNowMs - 2 * DIRECTGATE_REMOTE_LIFETIME_MS;
    CHECK(DirectGate_Client_ServiceSession(&sess) == XAPI_CONTINUE && !g_bFinish,
        "a session running an operation is never ended under it");

    sess.bServeBusy = XFALSE;
    sess.nServeStartMs = nNowMs;
    CHECK(DirectGate_Client_ServiceSession(&sess) == XAPI_DISCONNECT && g_bFinish && sess.bServeDone,
        "a session idle for too long ends by its own rule");

    g_bFinish = XFALSE;
    sess.bServeDone = XFALSE;
    sess.nServeIdleMs = nNowMs;
    sess.nServeStartMs = nNowMs - DIRECTGATE_REMOTE_LIFETIME_MS;
    CHECK(DirectGate_Client_ServiceSession(&sess) == XAPI_DISCONNECT && g_bFinish && sess.bServeDone,
        "a session that has lived its lifetime ends, between operations");

    g_bFinish = XFALSE;
    sess.bServeDone = XFALSE;
    sess.nServeStartMs = nNowMs;
    /* Against the clock the session reads itself: half a second short of a one-second limit is no end yet, even
       under valgrind, and a whole second is - where the default would wait ten minutes */
    sess.nServeIdleLimitMs = 1000;
    sess.nServeIdleMs = XTime_GetMonoMs() - 500;
    CHECK(DirectGate_Client_ServiceSession(&sess) == XAPI_CONTINUE && !g_bFinish, "-t sets the idle time");
    sess.nServeIdleMs = XTime_GetMonoMs() - 1000;
    CHECK(DirectGate_Client_ServiceSession(&sess) == XAPI_DISCONNECT && g_bFinish, "and ends it once the time is up");

    /* Blank lines ask for nothing; the last line need not end in a newline once stdin has ended */
    g_bFinish = XFALSE;
    sess.bServeDone = XFALSE;
    sess.nServeIdleMs = nNowMs;
    sess.nServeIdleLimitMs = DIRECTGATE_REMOTE_IDLE_MS;
    xstrncpy(sess.sServeDevice, sizeof(sess.sServeDevice), "box");
    XByteBuffer_Add(&sess.serveIn, (const uint8_t*)"\n\r\n{\"argv\":[\"exec\",\"elsewhere\",\"ls\"]}", 37);

    char sOut[1024];
    size_t nOut = capture_stdout(serve_next, &sess, sOut, sizeof(sOut));
    CHECK(nOut == 0 && sess.serveIn.nUsed == 36, "a blank line is passed over without an answer");
    capture_stdout(serve_next, &sess, sOut, sizeof(sOut));
    CHECK(sess.serveIn.nUsed == 34, "and so is one that is only a carriage return");
    nOut = capture_stdout(serve_next, &sess, sOut, sizeof(sOut));
    CHECK(nOut == 0 && sess.serveIn.nUsed == 34, "a line still being written is not taken");

    sess.bServeEof = XTRUE;
    nOut = capture_stdout(serve_next, &sess, sOut, sizeof(sOut));
    CHECK(nOut > 0 && strstr(sOut, "{\"exitCode\":255,") == sOut && strstr(sOut, "a session reaches its own device only") != NULL,
        "with stdin over, the last line is taken without its newline, and answered");
    CHECK(!sess.serveIn.nUsed && !sess.bServeBusy, "nothing is left waiting");
    CHECK(DirectGate_Client_ServiceSession(&sess) == XAPI_DISCONNECT && g_bFinish && sess.bServeDone,
        "with its requests over and answered, the session ends");

    sess.bServeReady = XFALSE;
    g_bFinish = XFALSE;
    capture_stdout(serve_next, &sess, sOut, sizeof(sOut));
    CHECK(!sess.bServeBusy, "nothing is taken before the session is open");

    /* The agent closing the session while nothing runs: a failure, not an end of its own */
    sess.bServeReady = XTRUE;
    xbyte_buffer_t packet;
    XByteBuffer_Init(&packet, XSTDNON, XFALSE);
    xjson_obj_t *pStatus = DirectGate_Proto_BuildStatus("closed", 1);
    directgate_pkg_t pkg;
    CHECK(pStatus != NULL && DirectGate_Proto_Build(&packet, pStatus, NULL, 0, XFALSE) &&
          DirectGate_Package_Parse(&pkg, packet.pData, packet.nUsed), "a closed status");
    XJSON_FreeObject(pStatus);
    sess.nServeExit = 0;
    CHECK(DirectGate_Client_ServeMessage(&sess, &pkg) == XAPI_DISCONNECT && g_bFinish &&
          sess.nServeExit == DIRECTGATE_REMOTE_EXIT_FAILED, "a session the agent closes ends as broken");
    DirectGate_Package_Clear(&pkg);
    XByteBuffer_Reset(&packet);

    g_bFinish = XFALSE;
    xjson_obj_t *pError = DirectGate_Proto_BuildError("between operations", 1);
    CHECK(pError != NULL && DirectGate_Proto_Build(&packet, pError, NULL, 0, XFALSE) &&
          DirectGate_Package_Parse(&pkg, packet.pData, packet.nUsed), "an error");
    XJSON_FreeObject(pError);
    CHECK(DirectGate_Client_ServeMessage(&sess, &pkg) == XAPI_CONTINUE && !g_bFinish,
        "an error between operations is noted, and the session goes on");
    DirectGate_Package_Clear(&pkg);
    XByteBuffer_Clear(&packet);

    /* An upload over the data channel paces the loop; nothing else does */
    CHECK(DirectGate_Client_GetWaitMs(&sess) == DIRECTGATE_CLIENT_LOOP_WAIT_MS, "an idle session sleeps the whole wait");
    sess.bChannelUsed = XTRUE;
    op.transfer.eState = XTRANSFER_STATE_SENDING;
    CHECK(DirectGate_Client_GetWaitMs(&sess) == DIRECTGATE_CLIENT_TRANSFER_WAIT_MS, "an upload on the channel paces the loop");
    sess.bChannelUsed = XFALSE;
    CHECK(DirectGate_Client_GetWaitMs(&sess) == DIRECTGATE_CLIENT_LOOP_WAIT_MS, "one on the relay waits for its socket");
    op.transfer.eState = XTRANSFER_STATE_IDLE;
    CHECK(DirectGate_Client_GetWaitMs(NULL) == DIRECTGATE_CLIENT_LOOP_WAIT_MS, "no client sleeps the whole wait");

    g_bFinish = XFALSE;
    DirectGate_Client_Release(&sess);
    DirectGate_Remote_Clear(&op);
    return 0;
}

int main(void)
{
    memset(&g_cfg, 0, sizeof(g_cfg));
    memset(&g_cli, 0, sizeof(g_cli));
    g_cli.pCfg = &g_cfg;
    DirectGate_WebRTC_Init(&g_cli.webrtc);

    int nFailed = check_sending() || check_handlers() || check_loop() || check_session();

    DirectGate_WebRTC_Clear(&g_cli.webrtc);
    if (nFailed) return 1;

    puts("client_guards_smoke: OK");
    return 0;
}
