/*
 * The session send path and the file-manager message handlers on top of it.
 *
 * Everything a browser asks of a file-manager session lands in
 * DirectGate_Files_HandleManager / HandleFile, and every answer leaves through
 * DirectGate_Session_Send. Neither had coverage: the existing files tests stub
 * the send layer out, so the framing, the mode gate and the transfer bookkeeping
 * between them were never exercised together.
 *
 * The session here is wired to a real xapi_session_t with XPOLLOUT already
 * enabled, which is what lets DirectGate_Session_Send run to completion without
 * an event loop behind it: the frame is appended to txBuffer and the readiness
 * update short-circuits. Every answer is then parsed back off that buffer, so
 * the assertions are about what actually went on the wire.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "src/agent/directgate.h"
#include "src/agent/files.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "session_files_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

typedef struct {
    directgate_cfg_t cfg;
    directgate_conn_t conn;
    xapi_session_t api;
    directgate_session_t *pSession;
    /* The browser half of the session's E2E context: same inputs, opposite
       role, so its TX keys are the agent's RX keys. Once the session is
       authenticated the agent refuses plaintext for every type the file
       manager uses, so the test has to speak the real encrypted protocol. */
    directgate_e2e_t peer;
    /* Package_Parse keeps pointers into the bytes it was handed, so the
       fixture owns them for as long as a parsed package is in use. */
    xbyte_buffer_t pktBuf;
} fixture_t;

/* Drops whatever the session has queued so the next assertion sees only the
   answer it triggered. */
static void drain(fixture_t *pFix)
{
    XByteBuffer_Clear(&pFix->api.txBuffer);
    XByteBuffer_Init(&pFix->api.txBuffer, XSTDNON, XFALSE);
    XByteBuffer_Clear(&pFix->pktBuf);
    XByteBuffer_Init(&pFix->pktBuf, XSTDNON, XFALSE);
}

/* Parses the single WebSocket frame the session just queued and hands back the
   protocol package inside it. Returns 0 when nothing was queued. */
static int take_packet(fixture_t *pFix, directgate_pkg_t *pPkg)
{
    if (pFix->api.txBuffer.nUsed == 0) return 0;

    xws_frame_t frame;
    xws_status_t eStatus = XWebFrame_ParseData(&frame,
        pFix->api.txBuffer.pData, pFix->api.txBuffer.nUsed);

    if (eStatus != XWS_FRAME_COMPLETE || !frame.bComplete)
    {
        XWebFrame_Clear(&frame);
        return 0;
    }

    const uint8_t *pPayload = XWebFrame_GetPayload(&frame);
    size_t nPayload = XWebFrame_GetPayloadLength(&frame);

    /* Copied out of the frame before it is released: the parsed package points
       straight into these bytes and outlives this call. */
    XByteBuffer_Clear(&pFix->pktBuf);
    XByteBuffer_Init(&pFix->pktBuf, XSTDNON, XFALSE);

    int nCopied = (pPayload != NULL && nPayload > 0 &&
        XByteBuffer_Add(&pFix->pktBuf, pPayload, nPayload) > 0);
    XWebFrame_Clear(&frame);
    if (!nCopied) return 0;

    if (!DirectGate_Package_Parse(pPkg, pFix->pktBuf.pData, pFix->pktBuf.nUsed))
        return 0;

    /* Answers from an authenticated session arrive inside an encrypted
       envelope; unwrap it so assertions can read the inner header. */
    if (pPkg->header.pType != NULL && strcmp(pPkg->header.pType, "encrypted") == 0)
    {
        xbyte_buffer_t inner;
        XByteBuffer_Init(&inner, XSTDNON, XFALSE);

        int nInner = DirectGate_Proto_DecryptPackage(&inner, pPkg, &pFix->peer);
        DirectGate_Package_Clear(pPkg);

        /* The plaintext replaces the envelope as the fixture-owned backing
           store, again because the package will point into it. */
        XByteBuffer_Clear(&pFix->pktBuf);
        XByteBuffer_Init(&pFix->pktBuf, XSTDNON, XFALSE);

        if (!nInner || XByteBuffer_Add(&pFix->pktBuf, inner.pData, inner.nUsed) <= 0)
        {
            XByteBuffer_Clear(&inner);
            return 0;
        }

        XByteBuffer_Clear(&inner);

        if (!DirectGate_Package_Parse(pPkg, pFix->pktBuf.pData, pFix->pktBuf.nUsed))
            return 0;
    }

    return 1;
}

/* Convenience: the "action" and "status" of a queued manager answer. */
static int expect_manager(fixture_t *pFix, const char *pAction, const char *pStatus)
{
    directgate_pkg_t pkg;
    if (!take_packet(pFix, &pkg)) return 0;

    xjson_obj_t *pRoot = pkg.jsonHeader.pRootObj;
    const char *pGotType = XJSON_GetString(XJSON_GetObject(pRoot, "type"));
    const char *pGotAction = XJSON_GetString(XJSON_GetObject(pRoot, "action"));
    const char *pGotStatus = XJSON_GetString(XJSON_GetObject(pRoot, "status"));

    int nOk = (pGotType != NULL && strcmp(pGotType, "manager") == 0 &&
        pGotAction != NULL && strcmp(pGotAction, pAction) == 0 &&
        pGotStatus != NULL && strcmp(pGotStatus, pStatus) == 0);

    DirectGate_Package_Clear(&pkg);
    drain(pFix);
    return nOk;
}

/* Sends an already-built header into the agent as if it arrived from the relay. */
static int deliver_payload(fixture_t *pFix, xjson_obj_t *pHeader,
                           const uint8_t *pPayload, size_t nPayload)
{
    xbyte_buffer_t packet;
    XByteBuffer_Init(&packet, XSTDNON, XFALSE);

    if (pHeader == NULL)
    {
        XByteBuffer_Clear(&packet);
        return XSTDERR;
    }

    /* Same order the browser uses: counter first, then frame, then seal. */
    if (DirectGate_E2E_IsInitialized(&pFix->peer))
        DirectGate_Proto_AddCC(pHeader, &pFix->peer, 0);

    if (!DirectGate_Proto_Build(&packet, pHeader, pPayload, nPayload, XFALSE))
    {
        XJSON_FreeObject(pHeader);
        XByteBuffer_Clear(&packet);
        return XSTDERR;
    }

    if (DirectGate_E2E_IsInitialized(&pFix->peer) &&
        !DirectGate_Proto_EncryptPackage(&packet, &pFix->peer,
            pFix->pSession != NULL ? pFix->pSession->nSessionId : 0))
    {
        XJSON_FreeObject(pHeader);
        XByteBuffer_Clear(&packet);
        return XSTDERR;
    }

    int nStatus = DirectGate_TestHandleTransportMessage(&pFix->api,
        packet.pData, packet.nUsed);

    XJSON_FreeObject(pHeader);
    XByteBuffer_Clear(&packet);
    return nStatus;
}

static int deliver(fixture_t *pFix, xjson_obj_t *pHeader)
{
    return deliver_payload(pFix, pHeader, NULL, 0);
}

/* A manager request with the fields the handler reads. */
static xjson_obj_t* manager_header(const char *pAction, const char *pPath,
                                   const char *pTargetPath, uint32_t nSessionId,
                                   xbool_t bForce)
{
    xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("manager", nSessionId);
    if (pHeader == NULL) return NULL;

    XJSON_AddString(pHeader, "action", pAction);
    if (pPath != NULL) XJSON_AddString(pHeader, "path", pPath);
    if (pTargetPath != NULL) XJSON_AddString(pHeader, "targetPath", pTargetPath);
    if (bForce) XJSON_AddBool(pHeader, "force", XTRUE);

    return pHeader;
}

static int write_file(const char *pPath, const char *pData)
{
    FILE *pFile = fopen(pPath, "wb");
    if (pFile == NULL) return 0;

    size_t nLen = strlen(pData);
    int nOk = fwrite(pData, 1, nLen, pFile) == nLen;
    fclose(pFile);
    return nOk;
}

int main(void)
{
    char sRoot[] = "/tmp/directgate_session_files_smoke.XXXXXX";
    CHECK(mkdtemp(sRoot) != NULL, "mkdtemp root");

    char sFile[512], sDir[512], sNested[512], sRenamed[512], sCopy[512], sMissing[512];
    snprintf(sFile, sizeof(sFile), "%s/alpha.txt", sRoot);
    snprintf(sDir, sizeof(sDir), "%s/tree", sRoot);
    snprintf(sNested, sizeof(sNested), "%s/tree/nested", sRoot);
    snprintf(sRenamed, sizeof(sRenamed), "%s/beta.txt", sRoot);
    snprintf(sCopy, sizeof(sCopy), "%s/gamma.txt", sRoot);
    snprintf(sMissing, sizeof(sMissing), "%s/absent.txt", sRoot);

    CHECK(write_file(sFile, "hello transfer"), "seed a file");

    fixture_t fix;
    memset(&fix, 0, sizeof(fix));
    xstrncpy(fix.cfg.auth.sSaltHex, sizeof(fix.cfg.auth.sSaltHex),
        "00000000000000000000000000000000"
        "00000000000000000000000000000000");
    xstrncpy(fix.cfg.auth.sVerifierHex, sizeof(fix.cfg.auth.sVerifierHex), "configured");
    fix.cfg.nKAInterval = 25;

    fix.conn.pCfg = &fix.cfg;
    DirectGate_SessionMgr_Init(&fix.conn.mgr, &fix.cfg);

    fix.api.pSessionData = &fix.conn;
    fix.api.sock.nFD = XSOCK_INVALID;
    fix.api.eRole = XAPI_CLIENT;
    /* Already writable, so XAPI_EnableEvent inside the send path returns
       without needing a registered event loop. */
    fix.api.nEvents = XPOLLOUT;
    XByteBuffer_Init(&fix.api.txBuffer, XSTDNON, XFALSE);
    XByteBuffer_Init(&fix.pktBuf, XSTDNON, XFALSE);

    fix.pSession = DirectGate_SessionMgr_Create(&fix.conn.mgr, 11);
    CHECK(fix.pSession != NULL, "create the session");
    fix.pSession->pWsSession = &fix.api;

    CHECK(!DirectGate_SessionMgr_IsEmpty(&fix.conn.mgr),
        "the manager reports the session it holds");

    /* ---- session send layer -------------------------------------------- */

    /* An unauthenticated session must not be answered; it is closed instead. */
    {
        directgate_session_t *pStranger = DirectGate_SessionMgr_Create(&fix.conn.mgr, 12);
        CHECK(pStranger != NULL, "create an unauthenticated session");
        pStranger->pWsSession = &fix.api;

        DirectGate_Session_SendManagerResp(pStranger, "list", "ok", NULL, "/");
        CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 12) == NULL,
            "answering an unauthenticated session closes it");
        drain(&fix);
    }

    fix.pSession->bAuthenticated = XTRUE;

    /* Before E2E is derived the session sends in the clear; that is the state
       the auth handshake itself runs in. */
    {
        CHECK(DirectGate_Session_SendKeepalive(fix.pSession, "ping") >= 0,
            "send a keepalive ping");

        directgate_pkg_t pkg;
        CHECK(take_packet(&fix, &pkg), "keepalive reaches the wire");
        const char *pType = XJSON_GetString(
            XJSON_GetObject(pkg.jsonHeader.pRootObj, "type"));
        const char *pAction = XJSON_GetString(
            XJSON_GetObject(pkg.jsonHeader.pRootObj, "action"));
        CHECK(pType != NULL && strcmp(pType, "keepalive") == 0, "keepalive type");
        CHECK(pAction != NULL && strcmp(pAction, "ping") == 0, "keepalive action");
        DirectGate_Package_Clear(&pkg);
        drain(&fix);
    }

    {
        CHECK(DirectGate_Session_SendErrorMsg(fix.pSession, "because") >= 0,
            "send an error message");

        directgate_pkg_t pkg;
        CHECK(take_packet(&fix, &pkg), "error reaches the wire");
        const char *pReason = XJSON_GetString(
            XJSON_GetObject(pkg.jsonHeader.pRootObj, "reason"));
        CHECK(pReason != NULL && strcmp(pReason, "because") == 0, "error carries a reason");
        DirectGate_Package_Clear(&pkg);
        drain(&fix);
    }

    {
        CHECK(DirectGate_Session_SendAuthResp(fix.pSession, "ok", "M2HEX", NULL) >= 0,
            "send an auth result");

        directgate_pkg_t pkg;
        CHECK(take_packet(&fix, &pkg), "auth result reaches the wire");
        const char *pM2 = XJSON_GetString(XJSON_GetObject(pkg.jsonHeader.pRootObj, "M2"));
        CHECK(pM2 != NULL && strcmp(pM2, "M2HEX") == 0, "auth result carries M2");
        DirectGate_Package_Clear(&pkg);
        drain(&fix);
    }

    /* A payload-carrying manager answer keeps its bytes and is marked json. */
    {
        const char *pJson = "{\"path\":\"/\",\"entries\":[]}";
        CHECK(DirectGate_Session_SendManagerData(fix.pSession, "list", "ok", "/",
            (const uint8_t*)pJson, strlen(pJson)) == XAPI_CONTINUE,
            "send a manager payload");

        directgate_pkg_t pkg;
        CHECK(take_packet(&fix, &pkg), "manager payload reaches the wire");
        const char *pPayloadType = XJSON_GetString(
            XJSON_GetObject(pkg.jsonHeader.pRootObj, "payloadType"));
        CHECK(pPayloadType != NULL && strcmp(pPayloadType, "json") == 0,
            "payload is tagged as json");
        DirectGate_Package_Clear(&pkg);
        drain(&fix);
    }

    /* Bring up E2E on both halves from the same SRP inputs. The agent takes
       the host role and the fixture the client role, so each encrypts under
       the other's decrypt keys - the property that makes a reflected packet
       fail its tag. */
    {
        uint8_t sKey[32];
        uint8_t sAgentNonce[DIRECTGATE_SRP_NONCE_SIZE];
        uint8_t sClientNonce[DIRECTGATE_SRP_NONCE_SIZE];

        for (size_t i = 0; i < sizeof(sKey); i++) sKey[i] = (uint8_t)(i + 1);
        for (size_t i = 0; i < sizeof(sAgentNonce); i++) sAgentNonce[i] = (uint8_t)(0xA0 + i);
        for (size_t i = 0; i < sizeof(sClientNonce); i++) sClientNonce[i] = (uint8_t)(0xC0 + i);

        DirectGate_E2E_Init(&fix.peer);
        CHECK(DirectGate_E2E_DeriveFromSRP(&fix.pSession->e2e, sKey, sizeof(sKey),
            sAgentNonce, sClientNonce, DIRECTGATE_SRP_NONCE_SIZE, "dev-1", XTRUE),
            "derive the agent side of the E2E context");
        CHECK(DirectGate_E2E_DeriveFromSRP(&fix.peer, sKey, sizeof(sKey),
            sAgentNonce, sClientNonce, DIRECTGATE_SRP_NONCE_SIZE, "dev-1", XFALSE),
            "derive the browser side of the E2E context");

        CHECK(DirectGate_E2E_IsInitialized(&fix.pSession->e2e), "agent E2E is up");
        CHECK(DirectGate_E2E_IsInitialized(&fix.peer), "browser E2E is up");
    }

    /* A sealed answer round-trips through the peer context. */
    {
        CHECK(DirectGate_Session_SendKeepalive(fix.pSession, "ping") >= 0,
            "send an encrypted keepalive");

        directgate_pkg_t pkg;
        CHECK(take_packet(&fix, &pkg), "the encrypted keepalive decrypts");
        const char *pAction = XJSON_GetString(
            XJSON_GetObject(pkg.jsonHeader.pRootObj, "action"));
        CHECK(pAction != NULL && strcmp(pAction, "ping") == 0,
            "the decrypted packet is the keepalive");
        DirectGate_Package_Clear(&pkg);
        drain(&fix);
    }

    /* Plaintext is refused once the session is authenticated, which is the
       policy that keeps a downgraded transport from being accepted. */
    {
        xjson_obj_t *pHeader = manager_header("list", sRoot, NULL, 11, XFALSE);
        CHECK(pHeader != NULL, "build a plaintext manager header");

        xbyte_buffer_t packet;
        XByteBuffer_Init(&packet, XSTDNON, XFALSE);
        CHECK(DirectGate_Proto_Build(&packet, pHeader, NULL, 0, XFALSE),
            "frame the plaintext request");
        CHECK(DirectGate_TestHandleTransportMessage(&fix.api,
            packet.pData, packet.nUsed) == XAPI_CONTINUE,
            "a plaintext request is dropped, not fatal");
        CHECK(fix.api.txBuffer.nUsed == 0, "a plaintext request is not answered");

        XJSON_FreeObject(pHeader);
        XByteBuffer_Clear(&packet);
    }

    /* ---- session mode gate --------------------------------------------- */

    /* Before a mode is started every file-manager message is refused with an
       error rather than acted on. */
    {
        CHECK(DirectGate_Session_EnsureMode(fix.pSession,
            DIRECTGATE_SESSION_MODE_FILE_MANAGER, "not started") == XAPI_CONTINUE,
            "an unstarted mode is refused");

        directgate_pkg_t pkg;
        CHECK(take_packet(&fix, &pkg), "the refusal reaches the wire");
        const char *pType = XJSON_GetString(
            XJSON_GetObject(pkg.jsonHeader.pRootObj, "type"));
        CHECK(pType != NULL && strcmp(pType, "error") == 0,
            "an unstarted mode is refused with an error");
        DirectGate_Package_Clear(&pkg);
        drain(&fix);
    }

    /* Starting a mode registers pipe endpoints on the connection's event loop.
       This fixture has none, so registration fails - which is the interesting
       case: the helper closes and frees the session, and StartMode chains
       several of those behind a "< 0" guard. Returning Close's XAPI_CONTINUE
       there let StartMode carry on through a freed session, so this asserts
       the failure is reported and the session really is gone. */
    {
        directgate_session_t *pDoomed = DirectGate_SessionMgr_Create(&fix.conn.mgr, 13);
        CHECK(pDoomed != NULL, "create a session for the endpoint failure");
        pDoomed->pWsSession = &fix.api;
        pDoomed->bAuthenticated = XTRUE;

        CHECK(DirectGate_Session_StartMode(pDoomed,
            DIRECTGATE_SESSION_MODE_FILE_MANAGER) < 0,
            "a failed endpoint registration is reported as a failure");
        CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 13) == NULL,
            "the session is closed when its endpoint cannot be registered");
        drain(&fix);
    }

    /* The handler tests below need an active mode without an event loop, so
       the mode is set the way a successful StartMode would leave it. */
    fix.pSession->eActiveMode = DIRECTGATE_SESSION_MODE_FILE_MANAGER;
    CHECK(DirectGate_Session_EnsureMode(fix.pSession,
        DIRECTGATE_SESSION_MODE_FILE_MANAGER, "not started") == XSTDOK,
        "the active mode passes the gate");

    /* A session already in one mode is not switched into another. */
    CHECK(DirectGate_Session_StartMode(fix.pSession,
        DIRECTGATE_SESSION_MODE_FILE_MANAGER) == XAPI_CONTINUE,
        "re-starting the active mode is accepted");
    CHECK(DirectGate_Session_StartMode(fix.pSession,
        DIRECTGATE_SESSION_MODE_NONE) == XAPI_CONTINUE,
        "starting no mode is a no-op");
    DirectGate_Session_StartMode(fix.pSession, DIRECTGATE_SESSION_MODE_TERMINAL);
    CHECK(fix.pSession->eActiveMode == DIRECTGATE_SESSION_MODE_FILE_MANAGER,
        "a session does not switch modes underneath itself");
    CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 11) == fix.pSession,
        "a refused mode switch leaves the session alive");
    drain(&fix);

    /* ---- manager actions ------------------------------------------------ */

    CHECK(deliver(&fix, manager_header("list", sRoot, NULL, 11, XFALSE)) == XAPI_CONTINUE,
        "deliver a list request");
    CHECK(expect_manager(&fix, "list", "ok"), "list succeeds");

    CHECK(deliver(&fix, manager_header("list", sMissing, NULL, 11, XFALSE)) == XAPI_CONTINUE,
        "deliver a list of a missing directory");
    CHECK(expect_manager(&fix, "list", "failed"), "listing a missing path fails");

    CHECK(deliver(&fix, manager_header("mkdir", sDir, NULL, 11, XFALSE)) == XAPI_CONTINUE,
        "deliver a mkdir");
    CHECK(expect_manager(&fix, "mkdir", "ok"), "mkdir succeeds");
    CHECK(deliver(&fix, manager_header("mkdir", sDir, NULL, 11, XFALSE)) == XAPI_CONTINUE,
        "deliver a duplicate mkdir");
    CHECK(expect_manager(&fix, "mkdir", "failed"), "mkdir on an existing path fails");

    CHECK(deliver(&fix, manager_header("mkdir", sNested, NULL, 11, XFALSE)) == XAPI_CONTINUE,
        "deliver a nested mkdir");
    CHECK(expect_manager(&fix, "mkdir", "ok"), "nested mkdir succeeds");

    CHECK(deliver(&fix, manager_header("rename", sFile, sRenamed, 11, XFALSE)) == XAPI_CONTINUE,
        "deliver a rename");
    CHECK(expect_manager(&fix, "rename", "ok"), "rename succeeds");
    CHECK(deliver(&fix, manager_header("rename", sRenamed, NULL, 11, XFALSE)) == XAPI_CONTINUE,
        "deliver a rename with no target");
    CHECK(expect_manager(&fix, "rename", "failed"), "rename without a target fails");

    CHECK(deliver(&fix, manager_header("copy", sRenamed, sCopy, 11, XFALSE)) == XAPI_CONTINUE,
        "deliver a copy");
    CHECK(expect_manager(&fix, "copy", "ok"), "copy succeeds");
    CHECK(deliver(&fix, manager_header("copy", sRenamed, NULL, 11, XFALSE)) == XAPI_CONTINUE,
        "deliver a copy with no target");
    CHECK(expect_manager(&fix, "copy", "failed"), "copy without a target fails");

    CHECK(deliver(&fix, manager_header("move", sCopy, sFile, 11, XFALSE)) == XAPI_CONTINUE,
        "deliver a move");
    CHECK(expect_manager(&fix, "move", "ok"), "move succeeds");
    CHECK(deliver(&fix, manager_header("move", sFile, sFile, 11, XFALSE)) == XAPI_CONTINUE,
        "deliver a move onto itself");
    CHECK(expect_manager(&fix, "move", "ok"), "moving onto itself is a no-op");

    /* A non-empty directory needs the recursive flag; that is the branch
       DirectoryHasEntries exists to report. */
    CHECK(deliver(&fix, manager_header("delete", sDir, NULL, 11, XFALSE)) == XAPI_CONTINUE,
        "deliver a non-recursive delete of a populated directory");
    CHECK(expect_manager(&fix, "delete", "failed"), "a populated directory is not deleted");
    CHECK(deliver(&fix, manager_header("delete", sDir, NULL, 11, XTRUE)) == XAPI_CONTINUE,
        "deliver a recursive delete");
    CHECK(expect_manager(&fix, "delete", "ok"), "a recursive delete succeeds");

    CHECK(deliver(&fix, manager_header("wobble", sRoot, NULL, 11, XFALSE)) == XAPI_CONTINUE,
        "deliver an unknown action");
    CHECK(expect_manager(&fix, "wobble", "failed"), "an unknown action is refused");

    /* A request without a path is refused before it touches the filesystem. */
    CHECK(deliver(&fix, manager_header("list", NULL, NULL, 11, XFALSE)) == XAPI_CONTINUE,
        "deliver a pathless request");
    CHECK(expect_manager(&fix, "list", "failed"), "a pathless request is refused");

    /* An action-less manager message is dropped without an answer. */
    {
        xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("manager", 11);
        CHECK(pHeader != NULL, "build an action-less manager header");
        XJSON_AddString(pHeader, "path", sRoot);
        CHECK(deliver(&fix, pHeader) == XAPI_CONTINUE, "deliver an action-less request");
        CHECK(fix.api.txBuffer.nUsed == 0, "an action-less request is not answered");
    }

    /* ---- outbound transfer --------------------------------------------- */

    CHECK(deliver(&fix, manager_header("open", sMissing, NULL, 11, XFALSE)) == XAPI_CONTINUE,
        "deliver an open of a missing file");
    CHECK(expect_manager(&fix, "open", "failed"), "opening a missing file fails");

    CHECK(deliver(&fix, manager_header("open", sRoot, NULL, 11, XFALSE)) == XAPI_CONTINUE,
        "deliver an open of a directory");
    CHECK(expect_manager(&fix, "open", "failed"), "opening a directory fails");

    {
        CHECK(deliver(&fix, manager_header("open", sFile, NULL, 11, XFALSE)) == XAPI_CONTINUE,
            "deliver an open");
        CHECK(fix.pSession->transfer.eState == XTRANSFER_STATE_SENDING,
            "an accepted open starts sending");

        /* file/start goes out before the manager answer, so drain both. */
        drain(&fix);

        /* A second open while one is in flight is refused rather than
           clobbering the session's single transfer slot. */
        CHECK(deliver(&fix, manager_header("open", sFile, NULL, 11, XFALSE)) == XAPI_CONTINUE,
            "deliver a second open");
        CHECK(expect_manager(&fix, "open", "failed"),
            "a second open is refused while a transfer is active");

        /* Pump until the transfer finishes; the file is one chunk. */
        for (int i = 0; i < 8 && fix.pSession->transfer.eState == XTRANSFER_STATE_SENDING; i++)
        {
            DirectGate_Files_ProcessTransfer(fix.pSession);
            drain(&fix);
        }

        CHECK(fix.pSession->transfer.eState == XTRANSFER_STATE_DONE,
            "the outbound transfer completes");
        CHECK(fix.pSession->transfer.nBytesXferred == strlen("hello transfer"),
            "every byte of the file was sent");

        /* Pumping a finished transfer must be a no-op, not a re-send. */
        DirectGate_Files_ProcessTransfer(fix.pSession);
        CHECK(fix.api.txBuffer.nUsed == 0, "a finished transfer sends nothing further");
    }

    /* A link the user picked opens what it points at. The transfer itself
       refuses to follow a link, so the handler has to resolve it first - the
       download used to be refused as "not a regular file". */
    {
        char sLinkTarget[512], sLink[512];
        snprintf(sLinkTarget, sizeof(sLinkTarget), "%s/link-target.txt", sRoot);
        snprintf(sLink, sizeof(sLink), "%s/link.txt", sRoot);

        CHECK(write_file(sLinkTarget, "behind the link"), "seed a link target");
        CHECK(symlink(sLinkTarget, sLink) == 0, "create the link");

        CHECK(deliver(&fix, manager_header("open", sLink, NULL, 11, XFALSE)) == XAPI_CONTINUE,
            "deliver an open of a symlink");
        CHECK(fix.pSession->transfer.eState == XTRANSFER_STATE_SENDING,
            "opening a symlink starts a transfer");
        drain(&fix);

        for (int i = 0; i < 8 && fix.pSession->transfer.eState == XTRANSFER_STATE_SENDING; i++)
        {
            DirectGate_Files_ProcessTransfer(fix.pSession);
            drain(&fix);
        }

        CHECK(fix.pSession->transfer.eState == XTRANSFER_STATE_DONE,
            "the symlinked download completes");
        CHECK(fix.pSession->transfer.nBytesXferred == strlen("behind the link"),
            "the bytes come from the link target");

        /* A link to a directory is still not a download. */
        char sDirLink[512];
        snprintf(sDirLink, sizeof(sDirLink), "%s/dir-link", sRoot);
        CHECK(symlink(sRoot, sDirLink) == 0, "create a link to a directory");
        CHECK(deliver(&fix, manager_header("open", sDirLink, NULL, 11, XFALSE)) == XAPI_CONTINUE,
            "deliver an open of a directory link");
        CHECK(expect_manager(&fix, "open", "failed"),
            "opening a link to a directory is refused");
    }

    /* ---- inbound transfer ----------------------------------------------- */

    {
        char sUpload[512];
        snprintf(sUpload, sizeof(sUpload), "%s/uploaded.txt", sRoot);

        CHECK(deliver(&fix, manager_header("save", sUpload, NULL, 11, XFALSE)) == XAPI_CONTINUE,
            "deliver a save");
        CHECK(expect_manager(&fix, "save", "ok"), "save is accepted");
        CHECK(xstrused(fix.pSession->sSaveTempPath), "save reserved a temp path");

        const char *pBody = "uploaded body";
        size_t nBody = strlen(pBody);

        char sSha[XSHA256_DIGEST_SIZE * 2 + 1];
        uint8_t digest[XSHA256_DIGEST_SIZE];
        XSHA256_Compute(digest, sizeof(digest), (const uint8_t*)pBody, nBody);
        for (size_t i = 0; i < sizeof(digest); i++)
            snprintf(sSha + (i * 2), sizeof(sSha) - (i * 2), "%02x", digest[i]);

        xjson_obj_t *pStart = DirectGate_Proto_BuildFileStart("up-1", "uploaded.txt",
            nBody, 1, 65536);
        CHECK(pStart != NULL, "build file/start");
        XJSON_AddU32(pStart, "sessionId", 11);
        CHECK(deliver(&fix, pStart) == XAPI_CONTINUE, "deliver file/start");
        CHECK(fix.pSession->transfer.eState == XTRANSFER_STATE_RECEIVING,
            "file/start opens the destination");
        drain(&fix);

        /* The chunk carries a payload, so it is built by hand rather than
           through the header-only deliver() helper. */
        {
            xjson_obj_t *pChunk = DirectGate_Proto_BuildFileChunk("up-1", 0);
            CHECK(pChunk != NULL, "build file/chunk");
            XJSON_AddU32(pChunk, "sessionId", 11);
            CHECK(deliver_payload(&fix, pChunk, (const uint8_t*)pBody, nBody) ==
                XAPI_CONTINUE, "deliver file/chunk");
        }

        CHECK(fix.pSession->transfer.nBytesXferred == nBody, "the chunk was written");
        drain(&fix);

        xjson_obj_t *pEnd = DirectGate_Proto_BuildFileEnd("up-1", sSha);
        CHECK(pEnd != NULL, "build file/end");
        XJSON_AddU32(pEnd, "sessionId", 11);
        CHECK(deliver(&fix, pEnd) == XAPI_CONTINUE, "deliver file/end");

        CHECK(XPath_Exists(sUpload), "the upload was committed to its final path");
        CHECK(!xstrused(fix.pSession->sSaveTempPath), "the pending save was cleared");

        /* The commit is acknowledged, which is what releases the uploader. */
        {
            directgate_pkg_t pkg;
            CHECK(take_packet(&fix, &pkg), "an ack reaches the wire");
            const char *pAction = XJSON_GetString(
                XJSON_GetObject(pkg.jsonHeader.pRootObj, "action"));
            CHECK(pAction != NULL && strcmp(pAction, "ack") == 0, "the answer is an ack");
            DirectGate_Package_Clear(&pkg);
            drain(&fix);
        }

        /* A second file/end for the same transfer - a retry, or one replayed
           inside the counter window - must not take the committed file with
           it. The transfer is finished by then, and its path is the file that
           was just saved rather than a partial upload to clean up. */
        {
            xjson_obj_t *pRepeat = DirectGate_Proto_BuildFileEnd("up-1", sSha);
            CHECK(pRepeat != NULL, "build a duplicate file/end");
            XJSON_AddU32(pRepeat, "sessionId", 11);
            CHECK(deliver(&fix, pRepeat) == XAPI_CONTINUE, "deliver the duplicate file/end");

            CHECK(XPath_Exists(sUpload),
                "a duplicate file/end leaves the committed upload alone");

            char sBody[64] = {0};
            FILE *pFile = fopen(sUpload, "rb");
            CHECK(pFile != NULL, "reopen the committed upload");
            size_t nRead = fread(sBody, 1, sizeof(sBody) - 1, pFile);
            fclose(pFile);
            CHECK(nRead == nBody && strcmp(sBody, pBody) == 0,
                "the committed upload still holds its bytes");
            drain(&fix);
        }
    }

    /* A bad hash must be refused and the partial file must not survive. */
    {
        char sBad[512];
        snprintf(sBad, sizeof(sBad), "%s/bad-hash.txt", sRoot);

        CHECK(deliver(&fix, manager_header("save", sBad, NULL, 11, XFALSE)) == XAPI_CONTINUE,
            "deliver a save for the bad-hash upload");
        CHECK(expect_manager(&fix, "save", "ok"), "save is accepted");

        xjson_obj_t *pStart = DirectGate_Proto_BuildFileStart("up-2", "bad-hash.txt",
            4, 1, 65536);
        CHECK(pStart != NULL, "build file/start");
        XJSON_AddU32(pStart, "sessionId", 11);
        CHECK(deliver(&fix, pStart) == XAPI_CONTINUE, "deliver file/start");
        drain(&fix);

        {
            xjson_obj_t *pChunk = DirectGate_Proto_BuildFileChunk("up-2", 0);
            CHECK(pChunk != NULL, "build file/chunk");
            XJSON_AddU32(pChunk, "sessionId", 11);
            CHECK(deliver_payload(&fix, pChunk, (const uint8_t*)"beef", 4) ==
                XAPI_CONTINUE, "deliver file/chunk");
        }
        drain(&fix);

        xjson_obj_t *pEnd = DirectGate_Proto_BuildFileEnd("up-2",
            "0000000000000000000000000000000000000000000000000000000000000000");
        CHECK(pEnd != NULL, "build file/end with a wrong hash");
        XJSON_AddU32(pEnd, "sessionId", 11);
        CHECK(deliver(&fix, pEnd) == XAPI_CONTINUE, "deliver the bad file/end");

        CHECK(!XPath_Exists(sBad), "a hash mismatch does not produce a file");

        directgate_pkg_t pkg;
        CHECK(take_packet(&fix, &pkg), "a cancel reaches the wire");
        const char *pAction = XJSON_GetString(
            XJSON_GetObject(pkg.jsonHeader.pRootObj, "action"));
        CHECK(pAction != NULL && strcmp(pAction, "cancel") == 0,
            "a hash mismatch is answered with a cancel");
        DirectGate_Package_Clear(&pkg);
        drain(&fix);
    }

    /* An out-of-order chunk is refused and the transfer is torn down. */
    {
        char sSkew[512];
        snprintf(sSkew, sizeof(sSkew), "%s/skewed.txt", sRoot);

        CHECK(deliver(&fix, manager_header("save", sSkew, NULL, 11, XFALSE)) == XAPI_CONTINUE,
            "deliver a save for the skewed upload");
        CHECK(expect_manager(&fix, "save", "ok"), "save is accepted");

        xjson_obj_t *pStart = DirectGate_Proto_BuildFileStart("up-3", "skewed.txt",
            8, 2, 4);
        CHECK(pStart != NULL, "build file/start");
        XJSON_AddU32(pStart, "sessionId", 11);
        CHECK(deliver(&fix, pStart) == XAPI_CONTINUE, "deliver file/start");
        drain(&fix);

        /* Index 1 while index 0 is expected. */
        xjson_obj_t *pChunk = DirectGate_Proto_BuildFileChunk("up-3", 1);
        CHECK(pChunk != NULL, "build the out-of-order chunk");
        XJSON_AddU32(pChunk, "sessionId", 11);
        CHECK(deliver_payload(&fix, pChunk, (const uint8_t*)"beef", 4) ==
            XAPI_CONTINUE, "deliver the out-of-order chunk");

        CHECK(!XPath_Exists(sSkew), "an out-of-order chunk produces no file");
        CHECK(!DirectGate_Transfer_IsActive(&fix.pSession->transfer),
            "an out-of-order chunk ends the transfer");
        drain(&fix);
    }

    /* A save while a transfer is active is refused, and an explicit cancel
       clears the slot again. */
    {
        char sBlocked[512];
        snprintf(sBlocked, sizeof(sBlocked), "%s/blocked.txt", sRoot);

        CHECK(deliver(&fix, manager_header("save", sBlocked, NULL, 11, XFALSE)) == XAPI_CONTINUE,
            "deliver a save");
        CHECK(expect_manager(&fix, "save", "ok"), "save is accepted");

        xjson_obj_t *pStart = DirectGate_Proto_BuildFileStart("up-4", "blocked.txt",
            4, 1, 65536);
        CHECK(pStart != NULL, "build file/start");
        XJSON_AddU32(pStart, "sessionId", 11);
        CHECK(deliver(&fix, pStart) == XAPI_CONTINUE, "deliver file/start");
        drain(&fix);

        CHECK(deliver(&fix, manager_header("save", sBlocked, NULL, 11, XFALSE)) == XAPI_CONTINUE,
            "deliver a second save");
        CHECK(expect_manager(&fix, "save", "failed"),
            "a save is refused while a transfer is active");

        xjson_obj_t *pCancel = DirectGate_Proto_BuildFileCancel("up-4", "user aborted");
        CHECK(pCancel != NULL, "build file/cancel");
        XJSON_AddU32(pCancel, "sessionId", 11);
        CHECK(deliver(&fix, pCancel) == XAPI_CONTINUE, "deliver file/cancel");

        CHECK(!DirectGate_Transfer_IsActive(&fix.pSession->transfer),
            "a cancel releases the transfer slot");
        CHECK(!XPath_Exists(sBlocked), "a cancelled upload leaves no file behind");
        drain(&fix);
    }

    /* An ack from the peer is accepted and ignored; it must not disturb state. */
    {
        xjson_obj_t *pAck = DirectGate_Proto_BuildFileAck("up-4", 0);
        CHECK(pAck != NULL, "build file/ack");
        XJSON_AddU32(pAck, "sessionId", 11);
        CHECK(deliver(&fix, pAck) == XAPI_CONTINUE, "deliver file/ack");
        CHECK(fix.api.txBuffer.nUsed == 0, "an ack is not answered");
    }

    /* An action-less file message is dropped. */
    {
        xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("file", 11);
        CHECK(pHeader != NULL, "build an action-less file header");
        CHECK(deliver(&fix, pHeader) == XAPI_CONTINUE, "deliver an action-less file message");
        CHECK(fix.api.txBuffer.nUsed == 0, "an action-less file message is not answered");
    }

    /* Saving onto a link writes through it: the link stays, its target gets the
       bytes, and the target's permissions survive - not the 0777 the link
       reports for itself. */
    {
        char sSaveTarget[512], sSaveLink[512];
        snprintf(sSaveTarget, sizeof(sSaveTarget), "%s/save-target.txt", sRoot);
        snprintf(sSaveLink, sizeof(sSaveLink), "%s/save-link.txt", sRoot);

        CHECK(write_file(sSaveTarget, "old"), "seed the save target");
        CHECK(chmod(sSaveTarget, 0640) == 0, "give the target a distinct mode");
        CHECK(symlink(sSaveTarget, sSaveLink) == 0, "link to it");

        const char *pBody = "written through";
        size_t nBody = strlen(pBody);

        char sSha[XSHA256_DIGEST_SIZE * 2 + 1];
        uint8_t digest[XSHA256_DIGEST_SIZE];
        XSHA256_Compute(digest, sizeof(digest), (const uint8_t*)pBody, nBody);
        for (size_t i = 0; i < sizeof(digest); i++)
            snprintf(sSha + (i * 2), sizeof(sSha) - (i * 2), "%02x", digest[i]);

        CHECK(deliver(&fix, manager_header("save", sSaveLink, NULL, 11, XTRUE)) == XAPI_CONTINUE,
            "deliver a forced save onto the link");
        CHECK(expect_manager(&fix, "save", "ok"), "the save is accepted");

        xjson_obj_t *pStart = DirectGate_Proto_BuildFileStart("link-1", "save-link.txt",
            nBody, 1, 65536);
        CHECK(pStart != NULL, "build file/start");
        XJSON_AddU32(pStart, "sessionId", 11);
        CHECK(deliver(&fix, pStart) == XAPI_CONTINUE, "deliver file/start");
        drain(&fix);

        {
            xjson_obj_t *pChunk = DirectGate_Proto_BuildFileChunk("link-1", 0);
            CHECK(pChunk != NULL, "build file/chunk");
            XJSON_AddU32(pChunk, "sessionId", 11);
            CHECK(deliver_payload(&fix, pChunk, (const uint8_t*)pBody, nBody) ==
                XAPI_CONTINUE, "deliver file/chunk");
        }
        drain(&fix);

        xjson_obj_t *pEnd = DirectGate_Proto_BuildFileEnd("link-1", sSha);
        CHECK(pEnd != NULL, "build file/end");
        XJSON_AddU32(pEnd, "sessionId", 11);
        CHECK(deliver(&fix, pEnd) == XAPI_CONTINUE, "deliver file/end");
        drain(&fix);

        xstat_t linkSt;
        CHECK(xstat(sSaveLink, &linkSt) == XSTDOK, "lstat the save path");
        CHECK(S_ISLNK(linkSt.st_mode), "the link survived the save");

        char sBody[64] = {0};
        FILE *pFile = fopen(sSaveTarget, "rb");
        CHECK(pFile != NULL, "reopen the link target");
        size_t nRead = fread(sBody, 1, sizeof(sBody) - 1, pFile);
        fclose(pFile);
        CHECK(nRead == nBody && strcmp(sBody, pBody) == 0,
            "the bytes landed in the file the link points at");

        xstat_t targetSt;
        CHECK(xstat(sSaveTarget, &targetSt) == XSTDOK, "stat the link target");
        CHECK((targetSt.st_mode & 0777) == 0640,
            "the target keeps its own permissions, not the link's 0777");
    }

    /* A cross-device copy reproduces a link by asking for one, since it has no
       bytes to stream. */
    {
        char sMadeLink[512];
        snprintf(sMadeLink, sizeof(sMadeLink), "%s/made-link", sRoot);

        xjson_obj_t *pHeader = manager_header("symlink", sMadeLink, "/elsewhere/file.txt",
            11, XFALSE);
        CHECK(pHeader != NULL, "build a symlink request");
        CHECK(deliver(&fix, pHeader) == XAPI_CONTINUE, "deliver the symlink request");
        CHECK(expect_manager(&fix, "symlink", "ok"), "the link is created");

        xstat_t linkSt;
        CHECK(xstat(sMadeLink, &linkSt) == XSTDOK, "lstat the created link");
        CHECK(S_ISLNK(linkSt.st_mode), "the created entry is a link");

        /* A second one over the same path is refused rather than replacing it. */
        pHeader = manager_header("symlink", sMadeLink, "/other", 11, XFALSE);
        CHECK(pHeader != NULL, "build a duplicate symlink request");
        CHECK(deliver(&fix, pHeader) == XAPI_CONTINUE, "deliver the duplicate");
        CHECK(expect_manager(&fix, "symlink", "failed"), "an existing entry is kept");

        /* Without a target there is nothing to point at. */
        pHeader = manager_header("symlink", sMadeLink, NULL, 11, XFALSE);
        CHECK(pHeader != NULL, "build a targetless symlink request");
        CHECK(deliver(&fix, pHeader) == XAPI_CONTINUE, "deliver the targetless request");
        CHECK(expect_manager(&fix, "symlink", "failed"), "a targetless request is refused");
    }

    /* A message for a session that does not exist is dropped, not fatal. */
    CHECK(deliver(&fix, manager_header("list", sRoot, NULL, 999, XFALSE)) == XAPI_CONTINUE,
        "a message for an unknown session is ignored");

    /* ---- teardown ------------------------------------------------------- */

    CHECK(DirectGate_SessionMgr_Close(&fix.conn.mgr, 11, "done") == XAPI_CONTINUE,
        "close the session by id");
    CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 11) == NULL,
        "the closed session is gone");
    CHECK(DirectGate_SessionMgr_IsEmpty(&fix.conn.mgr),
        "the manager is empty again");
    CHECK(DirectGate_SessionMgr_Close(&fix.conn.mgr, 11, "again") == XAPI_CONTINUE,
        "closing an already closed session is harmless");

    DirectGate_SessionMgr_Destroy(&fix.conn.mgr);
    DirectGate_E2E_Clear(&fix.peer);
    XByteBuffer_Clear(&fix.api.txBuffer);
    XByteBuffer_Clear(&fix.pktBuf);

    puts("session_files_smoke: OK");
    return 0;
}
