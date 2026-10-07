/* What the agent's connection layer refuses or ignores: every relay handler reached without its connection,
 * session-level messages for a session that does not exist, the reconnect, refresh, keepalive and token paths with
 * the piece each one needs missing, the temporary desktop shares with bad identifiers, and the start-up privilege
 * and config-path checks as an unprivileged user can reach them. Includes directgate.c, under DIRECTGATE_TESTING,
 * for the static handlers. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <pwd.h>
#include <sched.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

#include "src/agent/directgate.c"

#define CHECK(c, msg) \
    do { if (!(c)) { fprintf(stderr, "directgate_guards_smoke: %s (line %d)\n", msg, __LINE__); return 1; } } while (0)

static directgate_cfg_t g_cfg;
static directgate_conn_t g_conn;

/* A relay session whose connection is missing, as a stale or foreign endpoint would be */
static void orphan(xapi_session_t *pSession)
{
    memset(pSession, 0, sizeof(*pSession));
    pSession->eRole = XAPI_CLIENT;
    pSession->sock.nFD = XSOCK_INVALID;
}

static int check_handlers(void)
{
    xapi_session_t sess;
    orphan(&sess);
    directgate_pkg_t pkg;
    memset(&pkg, 0, sizeof(pkg));
    directgate_pkg_cmd_t cmd = { 0 };
    pkg.pPackage = &cmd;

    int (*handlers[])(xapi_session_t*, directgate_pkg_t*) = {
        DirectGate_HandleResize, DirectGate_HandleCmd, DirectGate_HandleAdmin, DirectGate_HandleData,
        DirectGate_HandleStatus, DirectGate_HandleWebRTC, DirectGate_HandleAuth, DirectGate_HandleKeepalive
    };

    for (size_t i = 0; i < sizeof(handlers) / sizeof(handlers[0]); i++)
        CHECK(handlers[i](&sess, &pkg) == XAPI_DISCONNECT, "a message on a session without its connection is refused");

    CHECK(DirectGate_HandleEncryptedMsg(&sess, &pkg, "relay") == XAPI_DISCONNECT, "so is an encrypted one");
    CHECK(DirectGate_DispatchMessage(NULL, &pkg) == XAPI_DISCONNECT && DirectGate_DispatchMessage(&sess, NULL) == XAPI_DISCONNECT,
        "nothing is dispatched without a session and a message");
    pkg.pPackage = NULL;
    CHECK(DirectGate_DispatchMessage(&sess, &pkg) == XAPI_DISCONNECT, "nor a message with nothing parsed in it");
    pkg.pPackage = &cmd;

    const uint8_t byte = 0;
    CHECK(DirectGate_HandleTransportMessage(NULL, &byte, 1, "relay") == XAPI_DISCONNECT, "no session, no message");
    CHECK(DirectGate_HandleTransportMessage(&sess, NULL, 1, "relay") == XAPI_CONTINUE &&
          DirectGate_HandleTransportMessage(&sess, &byte, 0, "relay") == XAPI_CONTINUE, "and an empty one is nothing");
    CHECK(DirectGate_HandleTransportMessage(&sess, &byte, 1, "relay") == XAPI_DISCONNECT, "and one without a connection");
    CHECK(DirectGate_RequiresEncryption(NULL, &pkg) != XFALSE && DirectGate_RequiresEncryption(&g_conn, NULL) != XFALSE,
        "a message nothing is known about has to be encrypted");

    CHECK(DirectGate_HandleError(NULL, NULL) == XAPI_CONTINUE, "an error with nothing attached is only logged");
    CHECK(DirectGate_HandleError(&sess, &pkg) == XAPI_CONTINUE, "and so is one without a connection");

    xapi_t api;
    memset(&api, 0, sizeof(api));
    xapi_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.pApi = &api;

    CHECK(DirectGate_HandleFrame(&ctx, NULL) == XAPI_DISCONNECT && DirectGate_HandleFrame(&ctx, &sess) == XAPI_DISCONNECT,
        "a frame needs a session with a connection");
    sess.pSessionData = &g_conn;
    CHECK(DirectGate_HandleFrame(&ctx, &sess) == XAPI_DISCONNECT, "and a frame");
    sess.pSessionData = NULL;

    CHECK(DirectGate_SendFrame(NULL, &sess) == XAPI_DISCONNECT && DirectGate_SendFrame(&ctx, NULL) == XAPI_DISCONNECT &&
          DirectGate_SendFrame(&ctx, &sess) == XAPI_NO_ACTION, "only a terminal endpoint writes on its own");
    CHECK(DirectGate_HandleTick(NULL, &sess) == XAPI_DISCONNECT && DirectGate_HandleTick(&ctx, &sess) == XAPI_CONTINUE,
        "a tick with no connection does nothing");
    CHECK(DirectGate_HandleComplete(NULL, &sess) == XAPI_DISCONNECT && DirectGate_HandleComplete(&ctx, NULL) == XAPI_DISCONNECT &&
          DirectGate_HandleComplete(&ctx, &sess) == XAPI_CONTINUE, "nor does a finished send");
    CHECK(DirectGate_HandshakeRequest(NULL, &sess) == XAPI_DISCONNECT &&
          DirectGate_HandshakeRequest(&ctx, NULL) == XAPI_DISCONNECT,
        "no handshake without a session");
    CHECK(DirectGate_HandshakeResponse(NULL, &sess) == XAPI_DISCONNECT &&
          DirectGate_HandshakeResponse(&ctx, NULL) == XAPI_DISCONNECT,
        "or an answer to one");
    CHECK(DirectGate_InitConnection(NULL, &sess) == XAPI_DISCONNECT && DirectGate_InitConnection(&ctx, NULL) == XAPI_DISCONNECT &&
          DirectGate_InitConnection(&ctx, &sess) == XAPI_DISCONNECT, "a connection is not started without one");
    CHECK(DirectGate_DestroyConnection(NULL, &sess) == XAPI_DISCONNECT &&
          DirectGate_DestroyConnection(&ctx, NULL) == XAPI_DISCONNECT,
        "or torn down");
    CHECK(DirectGate_DestroyConnection(&ctx, &sess) == XAPI_CONTINUE, "and a socket closing without one is let go");
    CHECK(DirectGate_HandshakeRequest(&ctx, &sess) == XAPI_DISCONNECT, "a handshake on a socket without one is refused");
    CHECK(DirectGate_SendControlFrame(NULL, XWS_PING) == XAPI_DISCONNECT, "a control frame needs a session");
    CHECK(DirectGate_LogStatus(NULL, &sess) == XAPI_CONTINUE, "a status for nothing is not logged");

    /* Terminal endpoints carry a session, not a connection */
    xapi_session_t term;
    memset(&term, 0, sizeof(term));
    term.eRole = XAPI_CUSTOM;
    CHECK(DirectGate_HandleCustomRead(NULL) == XAPI_DISCONNECT && DirectGate_HandleCustomRead(&term) == XAPI_DISCONNECT &&
          DirectGate_HandleCustomWrite(NULL) == XAPI_DISCONNECT && DirectGate_HandleCustomWrite(&term) == XAPI_DISCONNECT,
        "a terminal endpoint without its session is closed");
    CHECK(DirectGate_HandleRegistered(NULL) == XAPI_DISCONNECT && DirectGate_HandleRegistered(&term) == XAPI_DISCONNECT &&
          DirectGate_HandleRegistered(&sess) == XAPI_CONTINUE, "registering one needs its session, and others pass");
    CHECK(DirectGate_HandleClosed(NULL) == XAPI_DISCONNECT && DirectGate_HandleClosed(&term) == XAPI_NO_ACTION &&
          DirectGate_HandleClosed(&sess) == XAPI_CONTINUE, "closing one without its session is nothing to do");
    return 0;
}

static int check_sessions(void)
{
    /* A connection that knows no session: everything addressed to one is ignored */
    xapi_session_t sess;
    orphan(&sess);
    sess.pSessionData = &g_conn;

    directgate_pkg_t pkg;
    memset(&pkg, 0, sizeof(pkg));
    pkg.header.nSessionId = 4242;
    directgate_pkg_data_t data = { 0 };
    pkg.pPackage = &data;

    CHECK(DirectGate_HandleResize(&sess, &pkg) == XAPI_CONTINUE && DirectGate_HandleData(&sess, &pkg) == XAPI_CONTINUE &&
          DirectGate_HandleKeepalive(&sess, &pkg) == XAPI_CONTINUE, "a message for an unknown session is dropped");

    CHECK(DirectGate_Admin_SendActionResp(NULL, "admin", "error", "x") == XAPI_CONTINUE, "no session gets no answer");
    directgate_session_t idle;
    memset(&idle, 0, sizeof(idle));
    DirectGate_WebRTC_SignalCb("{}", 2, NULL);
    DirectGate_WebRTC_SignalCb(NULL, 2, &idle);
    DirectGate_WebRTC_SignalCb("{}", 0, &idle);
    DirectGate_WebRTC_DataCb((const uint8_t*)"x", 1, NULL);
    DirectGate_WebRTC_DataCb(NULL, 1, &idle);
    DirectGate_WebRTC_DataCb((const uint8_t*)"x", 0, &idle);

    CHECK(DirectGate_Session_GetWsFd(NULL) == (int)XSOCK_INVALID, "no session has no socket");
    CHECK(!DirectGate_Session_IsTransferWritable(NULL), "nor a transfer");
    CHECK(!DirectGate_Conn_HasOutboundTransfers(NULL) && !DirectGate_Conn_HasPausedTerminals(NULL), "nor a connection");
    DirectGate_PumpOutboundTransfers(NULL);

    CHECK(DirectGate_Conn_GetFD(NULL, NULL) == (int)XSOCK_INVALID && DirectGate_Conn_GetID(NULL, NULL) == 0 &&
          DirectGate_Conn_GetPort(NULL, NULL) == 0, "a connection that is not there has no socket");
    g_conn.relayLink.nPort = 443;
    xstrncpy(g_conn.relayLink.sAddr, sizeof(g_conn.relayLink.sAddr), "relay.example.test");
    CHECK(DirectGate_Conn_GetPort(&g_conn, NULL) == 443 &&
          strcmp(DirectGate_Conn_GetAddr(&g_conn, NULL), "relay.example.test") == 0,
        "one between sockets reports the relay it is going to");
    g_conn.relayLink.nPort = 0;
    g_conn.relayLink.sAddr[0] = '\0';

    /* Directed at a temporary share, the only packages it allows are its own kind */
    directgate_session_t share;
    memset(&share, 0, sizeof(share));
    share.bDesktopShare = XTRUE;
    directgate_pkg_t other;
    memset(&other, 0, sizeof(other));
    other.header.pType = "cmd";
    other.pPackage = NULL;
    CHECK(!DirectGate_TemporaryDesktopShare_AllowsPackage(&share, &other), "a command with nothing in it is not allowed");
    directgate_pkg_cmd_t empty = { 0 };
    other.pPackage = &empty;
    CHECK(!DirectGate_TemporaryDesktopShare_AllowsPackage(&share, &other), "nor one with no action");
    other.header.pType = "data";
    other.pPackage = &data;
    CHECK(!DirectGate_TemporaryDesktopShare_AllowsPackage(&share, &other), "nor data of no kind");
    return 0;
}

static int check_shares(void)
{
    DirectGate_TemporaryDesktopShare_Clear(NULL);
    DirectGate_TemporaryDesktopShares_Cleanup(NULL, 0);
    CHECK(DirectGate_TemporaryDesktopShare_Find(NULL, "share", 0) == NULL &&
          DirectGate_TemporaryDesktopShare_Find(&g_conn, "", 0) == NULL, "no share is found without an id");

    directgate_pkg_admin_t admin = { 0 };
    CHECK(!DirectGate_TemporaryDesktopShare_Provision(NULL, &admin) && !DirectGate_TemporaryDesktopShare_Provision(&g_conn, NULL),
        "nor provisioned without a connection and a request");

    char sLong[XSTR_MID + 8];
    memset(sLong, 's', sizeof(sLong) - 1);
    sLong[sizeof(sLong) - 1] = '\0';
    CHECK(!DirectGate_TemporaryDesktopShare_Revoke(NULL, "share") && !DirectGate_TemporaryDesktopShare_Revoke(&g_conn, "") &&
          !DirectGate_TemporaryDesktopShare_Revoke(&g_conn, sLong), "nor revoked by an id it cannot have");
    return 0;
}

static int check_connection(void)
{
    directgate_conn_t conn;
    memset(&conn, 0, sizeof(conn));
    xapi_endpoint_t endpt;
    XAPI_InitEndpoint(&endpt);

    DirectGate_Connection_Init(NULL, &g_cfg);
    DirectGate_Connection_Init(&conn, NULL);
    CHECK(DirectGate_GetRelayUrl(NULL) == NULL, "no configuration, no relay");
    CHECK(!DirectGate_IsEnrollmentDoubtReason(NULL) && !DirectGate_IsEnrollmentDoubtReason(""), "no reason is no doubt");
    DirectGate_ClearEnrollmentState(NULL);

    /* Every connection step refuses a connection without a configuration */
    DirectGate_SuppressReconnect(NULL, "x");
    DirectGate_SuppressReconnect(&conn, "x");
    CHECK(!conn.bReconnectSuppressed, "a connection without a configuration is not suppressed");
    CHECK(!DirectGate_HandleRefreshStatus(NULL, DIRECTGATE_ENROLL_REFRESH_OK, "x", "x", XFALSE) &&
          !DirectGate_HandleRefreshStatus(&conn, DIRECTGATE_ENROLL_REFRESH_OK, "x", "x", XFALSE), "nor refreshed");
    CHECK(!DirectGate_PrepareEndpoint(NULL, &endpt) && !DirectGate_PrepareEndpoint(&g_conn, NULL) &&
          !DirectGate_PrepareEndpoint(&conn, &endpt), "nor prepared");
    CHECK(!DirectGate_PreConnectRefresh(NULL) && !DirectGate_PreConnectRefresh(&conn), "nor refreshed before connecting");
    CHECK(!DirectGate_TryRelayReprobe(NULL, 0) && !DirectGate_TryRelayReprobe(&conn, 0), "nor re-probed");
    CHECK(DirectGate_SendVerifyUpdate(NULL) == XSTDERR && DirectGate_SendVerifyUpdate(&conn) == XSTDERR,
        "nor does it send a verify update");
    CHECK(!DirectGate_CheckTokenRefresh(NULL) && !DirectGate_CheckTokenRefresh(&conn), "nor check its token");
    DirectGate_RetryPendingSave(NULL);
    DirectGate_RetryPendingSave(&conn);
    DirectGate_CheckRelayKeepalive(NULL);
    DirectGate_CheckRelayKeepalive(&conn);
    DirectGate_CheckAuthTimeouts(NULL);
    DirectGate_CheckWebRTCKeepalive(NULL);
    DirectGate_CheckWebRTCKeepalive(&conn);
    DirectGate_ScheduleReconnect(NULL, "x");

    /* A configuration missing the relay, then the token: nothing to connect to */
    directgate_cfg_t cfg;
    DirectGate_InitConfig(&cfg);
    conn.pCfg = &cfg;
    CHECK(!DirectGate_PrepareEndpoint(&conn, &endpt), "no relay URL, no endpoint");
    xstrncpy(cfg.sRelayUrl, sizeof(cfg.sRelayUrl), "wss://relay.example.test/websock");
    CHECK(!DirectGate_PrepareEndpoint(&conn, &endpt), "nor without an access token");
    CHECK(!DirectGate_PreConnectRefresh(&conn) && !DirectGate_CheckTokenRefresh(&conn), "nothing to refresh unenrolled");
    CHECK(DirectGate_SendVerifyUpdate(&conn) == XSTDERR, "no verify update without a socket");

    xapi_session_t sock;
    orphan(&sock);
    conn.pWsSession = &sock;
    CHECK(DirectGate_SendVerifyUpdate(&conn) == XSTDERR, "nor without a token");
    conn.pWsSession = NULL;

    cfg.nKAInterval = 0;
    DirectGate_CheckWebRTCKeepalive(&conn);

    /* Reconnects stop once finishing, and once suppressed */
    g_bFinish = XTRUE;
    DirectGate_ScheduleReconnect(&conn, "x");
    g_bFinish = XFALSE;
    conn.bReconnectSuppressed = XTRUE;
    DirectGate_ScheduleReconnect(&conn, "x");
    CHECK(conn.nNextReconnectMs == 0, "no reconnect is scheduled while finishing or suppressed");
    return 0;
}

static int check_startup(void)
{
    /* The privilege drop refuses a missing or unknown user, and goes on as the user it already is */
    directgate_cfg_t cfg;
    DirectGate_InitConfig(&cfg);
    cfg.sShellUser[0] = '\0';
    CHECK(!DirectGate_DropPrivileges(NULL) && !DirectGate_DropPrivileges(&cfg), "no shell user is no start");
    xstrncpy(cfg.sShellUser, sizeof(cfg.sShellUser), "directgate-no-such-user");
    CHECK(!DirectGate_DropPrivileges(&cfg), "nor is one that does not exist");

    struct passwd *pSelf = getpwuid(getuid());
    if (pSelf != NULL && getuid() != 0)
    {
        xstrncpy(cfg.sShellUser, sizeof(cfg.sShellUser), pSelf->pw_name);
        CHECK(DirectGate_DropPrivileges(&cfg), "the user it runs as needs no drop");

        struct passwd *pRoot = getpwuid(0);
        if (pRoot != NULL)
        {
            xstrncpy(cfg.sShellUser, sizeof(cfg.sShellUser), pRoot->pw_name);
            CHECK(DirectGate_DropPrivileges(&cfg), "without root it goes on as itself");
        }
    }

    /* An unprivileged agent has nothing anyone could escalate through its configuration */
    CHECK(!DirectGate_ConfigIsPrivilegedSafe(NULL), "no configuration is not safe");
    CHECK(geteuid() == 0 || DirectGate_ConfigIsPrivilegedSafe(&cfg), "without root every configuration is");
    return 0;
}

static int write_text(const char *pPath, const char *pText)
{
    FILE *pFile = fopen(pPath, "w");
    if (pFile == NULL) return 0;

    size_t nLen = strlen(pText);
    int nOk = fwrite(pText, 1, nLen, pFile) == nLen;
    return (fclose(pFile) == 0) && nOk;
}

/* As root of a private user namespace, where what this test owns is root's and what root owns is nobody's */
static int root_child(void)
{
    uid_t nOuterUid = getuid();
    gid_t nOuterGid = getgid();
    if (unshare(CLONE_NEWUSER) != 0) return 77;

    char sMap[64];
    snprintf(sMap, sizeof(sMap), "0 %u 1\n", (unsigned)nOuterUid);
    if (!write_text("/proc/self/uid_map", sMap)) return 77;
    snprintf(sMap, sizeof(sMap), "0 %u 1\n", (unsigned)nOuterGid);
    if (!write_text("/proc/self/setgroups", "deny") || !write_text("/proc/self/gid_map", sMap)) return 77;
    if (geteuid() != 0) return 77;

    char sDir[] = "/tmp/directgate_guards.XXXXXX";
    CHECK(mkdtemp(sDir) != NULL, "make a directory root owns");
    char sFile[96];
    snprintf(sFile, sizeof(sFile), "%s/agent.json", sDir);
    CHECK(write_text(sFile, "{}") && chmod(sFile, 0600) == 0, "and a configuration in it");

    /* Only a file root owns, closed to others, in a directory the same, is trusted */
    directgate_cfg_t cfg;
    DirectGate_InitConfig(&cfg);
    cfg.sCfgPath[0] = '\0';
    CHECK(!DirectGate_ConfigIsPrivilegedSafe(&cfg), "no path is not safe");
    xstrncpy(cfg.sCfgPath, sizeof(cfg.sCfgPath), "/nonexistent/agent.json");
    CHECK(!DirectGate_ConfigIsPrivilegedSafe(&cfg), "nor one that is not there");
    xstrncpy(cfg.sCfgPath, sizeof(cfg.sCfgPath), sDir);
    CHECK(!DirectGate_ConfigIsPrivilegedSafe(&cfg), "nor a directory");
    xstrncpy(cfg.sCfgPath, sizeof(cfg.sCfgPath), "/etc/passwd");
    CHECK(!DirectGate_ConfigIsPrivilegedSafe(&cfg), "nor a file somebody else owns");
    xstrncpy(cfg.sCfgPath, sizeof(cfg.sCfgPath), sFile);
    CHECK(DirectGate_ConfigIsPrivilegedSafe(&cfg), "a closed file in a closed directory root owns is safe");

    CHECK(chdir(sDir) == 0, "work in that directory");
    xstrncpy(cfg.sCfgPath, sizeof(cfg.sCfgPath), "agent.json");
    CHECK(DirectGate_ConfigIsPrivilegedSafe(&cfg), "a bare name is checked against where it is");
    CHECK(chmod(sDir, 0770) == 0 && !DirectGate_ConfigIsPrivilegedSafe(&cfg), "a directory others can write is not");
    CHECK(chmod(sDir, 0700) == 0 && chmod(sFile, 0660) == 0, "open the file to the group");
    xstrncpy(cfg.sCfgPath, sizeof(cfg.sCfgPath), sFile);
    CHECK(!DirectGate_ConfigIsPrivilegedSafe(&cfg), "nor is a file others can write");

    /* Dropping to an account this namespace cannot become: the hand-over of the files fails quietly, then the
       group change fails the start */
    struct passwd *pNobody = getpwnam("nobody");
    if (pNobody != NULL && pNobody->pw_uid != 0)
    {
        xstrncpy(cfg.sShellUser, sizeof(cfg.sShellUser), "nobody");
        CHECK(!DirectGate_DropPrivileges(&cfg), "a drop that cannot change groups refuses to start");
    }

    CHECK(chdir("/") == 0 && unlink(sFile) == 0 && rmdir(sDir) == 0, "clean up");
    return 0;
}

static int check_as_root(void)
{
    pid_t nPid = fork();
    CHECK(nPid >= 0, "fork the namespace child");
    /* exit, not _exit: the child's coverage is written by its exit handlers */
    if (nPid == 0) exit(root_child());

    int nStatus = 0;
    CHECK(waitpid(nPid, &nStatus, 0) == nPid && WIFEXITED(nStatus), "the namespace child exits");
    if (WEXITSTATUS(nStatus) == 77) puts("directgate_guards_smoke: no user namespaces here, root paths not checked");
    else CHECK(WEXITSTATUS(nStatus) == 0, "the root paths behave");
    return 0;
}

int main(void)
{
    DirectGate_InitConfig(&g_cfg);
    DirectGate_Connection_Init(&g_conn, &g_cfg);

    int nFailed = check_handlers() || check_sessions() || check_shares() || check_connection() || check_startup() ||
        check_as_root();

    DirectGate_SessionMgr_Destroy(&g_conn.mgr);
    if (nFailed) return 1;

    puts("directgate_guards_smoke: OK");
    return 0;
}
