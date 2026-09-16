/*
 * The agent's authentication message handler, driven over the real transport.
 *
 * DirectGate_HandleAuth is the only thing standing between the relay and a
 * live session, and it is the one place where a wrong answer costs everything:
 * a refusal that forgets to close, a key-auth path that stays open when no key
 * is configured, a device id that is not the agent's, a pre-auth flood that is
 * never capped. None of those show up as a crash, so each is asserted here by
 * the exact answer that goes on the wire.
 *
 * Messages arrive through DirectGate_TestHandleTransportMessage, the same entry
 * the relay socket feeds, and every answer is read back off the session's
 * transmit buffer rather than from a mock.
 */

#include <stdio.h>
#include <string.h>

#include "src/agent/directgate.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "auth_flow_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

#define AGENT_DEVICE_ID "device-under-test"

typedef struct {
    directgate_cfg_t cfg;
    directgate_conn_t conn;
    xapi_session_t api;
    /* The browser half of an established session's E2E context: same inputs,
       opposite role, so its TX keys are the agent's RX keys. */
    directgate_e2e_t peer;
    xbyte_buffer_t pktBuf;
} fixture_t;

static void drain(fixture_t *pFix)
{
    XByteBuffer_Clear(&pFix->api.txBuffer);
    XByteBuffer_Init(&pFix->api.txBuffer, XSTDNON, XFALSE);
}

/* Parses the one frame the session queued and hands back the package in it. */
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

    XByteBuffer_Clear(&pFix->pktBuf);
    XByteBuffer_Init(&pFix->pktBuf, XSTDNON, XFALSE);

    int nCopied = (pPayload != NULL && nPayload > 0 &&
        XByteBuffer_Add(&pFix->pktBuf, pPayload, nPayload) > 0);
    XWebFrame_Clear(&frame);
    if (!nCopied) return 0;

    if (!DirectGate_Package_Parse(pPkg, pFix->pktBuf.pData, pFix->pktBuf.nUsed)) return 0;

    /* Answers to an established session arrive sealed; unwrap so the assertion
       reads the same header the browser would. */
    if (pPkg->header.pType != NULL && strcmp(pPkg->header.pType, "encrypted") == 0)
    {
        xbyte_buffer_t inner;
        XByteBuffer_Init(&inner, XSTDNON, XFALSE);

        int nInner = DirectGate_Proto_DecryptPackage(&inner, pPkg, &pFix->peer);
        DirectGate_Package_Clear(pPkg);

        XByteBuffer_Clear(&pFix->pktBuf);
        XByteBuffer_Init(&pFix->pktBuf, XSTDNON, XFALSE);

        if (!nInner || XByteBuffer_Add(&pFix->pktBuf, inner.pData, inner.nUsed) <= 0)
        {
            XByteBuffer_Clear(&inner);
            return 0;
        }

        XByteBuffer_Clear(&inner);
        if (!DirectGate_Package_Parse(pPkg, pFix->pktBuf.pData, pFix->pktBuf.nUsed)) return 0;
    }

    return 1;
}

/* Asserts the queued answer is an auth result with this status and reason.
 * A NULL reason means "do not care"; an empty one means "must not carry one". */
static int expect_auth(fixture_t *pFix, const char *pStatus, const char *pReason)
{
    directgate_pkg_t pkg;
    if (!take_packet(pFix, &pkg)) return 0;

    xjson_obj_t *pRoot = pkg.jsonHeader.pRootObj;
    const char *pGotType = XJSON_GetString(XJSON_GetObject(pRoot, "type"));
    const char *pGotStatus = XJSON_GetString(XJSON_GetObject(pRoot, "status"));
    const char *pGotReason = XJSON_GetString(XJSON_GetObject(pRoot, "reason"));

    int nOk = (pGotType != NULL && strcmp(pGotType, "auth") == 0 &&
               pGotStatus != NULL && strcmp(pGotStatus, pStatus) == 0);

    if (nOk && pReason != NULL)
        nOk = (pGotReason != NULL && strcmp(pGotReason, pReason) == 0);

    DirectGate_Package_Clear(&pkg);
    return nOk;
}

static int no_answer(fixture_t *pFix)
{
    return pFix->api.txBuffer.nUsed == 0;
}

static int deliver(fixture_t *pFix, xjson_obj_t *pHeader)
{
    xbyte_buffer_t packet;
    XByteBuffer_Init(&packet, XSTDNON, XFALSE);

    if (pHeader == NULL || !DirectGate_Proto_Build(&packet, pHeader, NULL, 0, XFALSE))
    {
        XJSON_FreeObject(pHeader);
        XByteBuffer_Clear(&packet);
        return XSTDERR;
    }

    int nStatus = DirectGate_TestHandleTransportMessage(&pFix->api, packet.pData, packet.nUsed);
    XJSON_FreeObject(pHeader);
    XByteBuffer_Clear(&packet);
    return nStatus;
}

/* Delivers a header the way an established peer does: sealed under the
 * session's E2E keys, which is the only shape an authenticated session reads. */
static int deliver_encrypted(fixture_t *pFix, xjson_obj_t *pHeader, uint32_t nSessionId)
{
    xbyte_buffer_t packet;
    XByteBuffer_Init(&packet, XSTDNON, XFALSE);

    if (pHeader == NULL)
    {
        XByteBuffer_Clear(&packet);
        return XSTDERR;
    }

    DirectGate_Proto_AddCC(pHeader, &pFix->peer, 0);

    if (!DirectGate_Proto_Build(&packet, pHeader, NULL, 0, XFALSE) ||
        !DirectGate_Proto_EncryptPackage(&packet, &pFix->peer, nSessionId))
    {
        XJSON_FreeObject(pHeader);
        XByteBuffer_Clear(&packet);
        return XSTDERR;
    }

    int nStatus = DirectGate_TestHandleTransportMessage(&pFix->api, packet.pData, packet.nUsed);
    XJSON_FreeObject(pHeader);
    XByteBuffer_Clear(&packet);
    return nStatus;
}

/* An auth header with only the fields a case needs; anything NULL is left off,
 * which is exactly how a malformed client message arrives. */
static xjson_obj_t* auth_header(const char *pAction, const char *pMethod, uint32_t nSessionId)
{
    xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("auth", nSessionId);
    if (pHeader == NULL) return NULL;

    if (pAction != NULL) XJSON_AddString(pHeader, "action", pAction);
    if (pMethod != NULL) XJSON_AddString(pHeader, "method", pMethod);

    return pHeader;
}

static void setup(fixture_t *pFix)
{
    memset(pFix, 0, sizeof(*pFix));

    xstrncpy(pFix->cfg.sDeviceId, sizeof(pFix->cfg.sDeviceId), AGENT_DEVICE_ID);
    xstrncpy(pFix->cfg.auth.sSaltHex, sizeof(pFix->cfg.auth.sSaltHex),
        "00000000000000000000000000000000"
        "00000000000000000000000000000000");
    xstrncpy(pFix->cfg.auth.sVerifierHex, sizeof(pFix->cfg.auth.sVerifierHex), "configured");
    pFix->cfg.auth.nSuite = DIRECTGATE_SRP_SUITE;

    pFix->conn.pCfg = &pFix->cfg;
    DirectGate_SessionMgr_Init(&pFix->conn.mgr, &pFix->cfg);

    pFix->api.pSessionData = &pFix->conn;
    pFix->api.sock.nFD = XSOCK_INVALID;
    pFix->api.eRole = XAPI_CLIENT;
    pFix->api.nEvents = XPOLLOUT;

    XByteBuffer_Init(&pFix->api.txBuffer, XSTDNON, XFALSE);
    XByteBuffer_Init(&pFix->pktBuf, XSTDNON, XFALSE);
}

static void teardown(fixture_t *pFix)
{
    DirectGate_SessionMgr_Destroy(&pFix->conn.mgr);
    XByteBuffer_Clear(&pFix->api.txBuffer);
    XByteBuffer_Clear(&pFix->pktBuf);
}

static int test_malformed(void)
{
    fixture_t fix;
    setup(&fix);

    /* Without an action there is nothing to answer, and answering anyway would
     * hand an unauthenticated peer a free round trip. */
    drain(&fix);
    CHECK(deliver(&fix, auth_header(NULL, NULL, 20)) == XAPI_CONTINUE,
        "an auth message with no action is handled");
    CHECK(no_answer(&fix), "an auth message with no action is not answered");
    CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 20) == NULL,
        "an auth message with no action does not create a session");

    /* An action nobody implements is a client that does not speak this
     * protocol; it is told so and the session goes rather than lingering as a
     * half-open pre-auth slot. */
    drain(&fix);
    CHECK(deliver(&fix, auth_header("wobble", NULL, 21)) == XAPI_CONTINUE,
        "an auth message with an unknown action is handled");
    CHECK(expect_auth(&fix, "failed", "unexpected action"),
        "an unknown auth action is refused by name");
    CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 21) == NULL,
        "an unknown auth action closes the session");

    teardown(&fix);
    return 0;
}

static int test_srp_hello_refusals(void)
{
    fixture_t fix;
    setup(&fix);

    /* Each of these is a hello the agent must refuse by name, so a client
     * learns what it got wrong without the agent starting a handshake. */
    struct {
        xbool_t bDeviceId;
        xbool_t bA;
        xbool_t bNonce;
        const char *pDeviceIdValue;
        const char *pReason;
        const char *pMsg;
    } cases[] = {
        { XFALSE, XTRUE,  XTRUE,  NULL, "missing device ID",
          "an SRP hello with no device id is refused by name" },
        { XTRUE,  XFALSE, XTRUE,  AGENT_DEVICE_ID, "missing A",
          "an SRP hello with no client public value is refused by name" },
        { XTRUE,  XTRUE,  XFALSE, AGENT_DEVICE_ID, "missing nonce",
          "an SRP hello with no nonce is refused by name" },
        { XTRUE,  XTRUE,  XTRUE,  "some-other-device", "invalid device ID",
          "an SRP hello for another agent's device id is refused" },
        { XTRUE,  XTRUE,  XTRUE,  AGENT_DEVICE_ID, "invalid nonce",
          "an SRP hello whose nonce is not a 32-byte hex value is refused" }
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    {
        uint32_t nSid = (uint32_t)(100 + i);
        xjson_obj_t *pHeader = auth_header("hello", NULL, nSid);
        CHECK(pHeader != NULL, "build an SRP hello");

        if (cases[i].bDeviceId) XJSON_AddString(pHeader, "deviceId", cases[i].pDeviceIdValue);
        if (cases[i].bA) XJSON_AddString(pHeader, "A", "0123456789abcdef");
        if (cases[i].bNonce) XJSON_AddString(pHeader, "nonce", "not-a-nonce");

        drain(&fix);
        CHECK(deliver(&fix, pHeader) == XAPI_CONTINUE, "an SRP hello is handled");
        CHECK(expect_auth(&fix, "failed", cases[i].pReason), cases[i].pMsg);

        /* A refused hello leaves the session unauthenticated and open, so the
         * client can correct itself within its remaining attempts. */
        directgate_session_t *pSession = DirectGate_SessionMgr_Find(&fix.conn.mgr, nSid);
        CHECK(pSession != NULL && !pSession->bAuthenticated,
            "a refused SRP hello leaves the session unauthenticated");
    }

    teardown(&fix);
    return 0;
}

/* Two different "not configured" shapes, which answer differently on purpose. */
static int test_srp_not_configured(void)
{
    fixture_t fix;
    setup(&fix);

    /* Nothing configured at all: there is no method that could ever succeed,
     * so no pre-auth session slot is handed out and nothing is answered. A
     * slot here would be a free resource for anyone who can reach the relay. */
    fix.cfg.auth.sVerifierHex[0] = '\0';

    xjson_obj_t *pHeader = auth_header("hello", NULL, 30);
    CHECK(pHeader != NULL, "build an SRP hello for an unconfigured agent");
    XJSON_AddString(pHeader, "deviceId", AGENT_DEVICE_ID);
    XJSON_AddString(pHeader, "A", "0123456789abcdef");
    XJSON_AddString(pHeader, "nonce", "00");

    drain(&fix);
    CHECK(deliver(&fix, pHeader) == XAPI_CONTINUE, "an SRP hello is handled");
    CHECK(no_answer(&fix),
        "an agent with no auth method at all answers nothing");
    CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 30) == NULL,
        "an agent with no auth method at all hands out no pre-auth session");

    teardown(&fix);

    /* Key auth configured but SRP not: the agent can authenticate someone, so
     * the session exists and the client is told which method it has to use. */
    setup(&fix);
    fix.cfg.auth.sVerifierHex[0] = '\0';
    fix.cfg.keyauth.nAuthorizedKeyCount = 1;
    xstrncpy(fix.cfg.keyauth.sAuthorizedKeys[0], sizeof(fix.cfg.keyauth.sAuthorizedKeys[0]),
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    xstrncpy(fix.cfg.keyauth.sIdentitySeedB64, sizeof(fix.cfg.keyauth.sIdentitySeedB64),
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    xstrncpy(fix.cfg.keyauth.sIdentityPubB64, sizeof(fix.cfg.keyauth.sIdentityPubB64),
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");

    pHeader = auth_header("hello", NULL, 31);
    CHECK(pHeader != NULL, "build an SRP hello for a key-only agent");
    XJSON_AddString(pHeader, "deviceId", AGENT_DEVICE_ID);
    XJSON_AddString(pHeader, "A", "0123456789abcdef");
    XJSON_AddString(pHeader, "nonce", "00");

    drain(&fix);
    CHECK(deliver(&fix, pHeader) == XAPI_CONTINUE, "an SRP hello to a key-only agent is handled");
    CHECK(expect_auth(&fix, "failed", "srp not configured"),
        "a key-only agent refuses SRP by name so the client can switch method");

    teardown(&fix);
    return 0;
}

static int test_srp_challenge_and_proof(void)
{
    fixture_t fix;
    setup(&fix);

    /* A verifier the agent can actually load, so the handshake reaches the
     * challenge and the proof check rather than stopping at configuration. */
    const char *pSecret = "correct horse battery staple";
    uint8_t salt[DIRECTGATE_SRP_SALT_SIZE];
    memset(salt, 0x2b, sizeof(salt));

    char sVerifier[2048];
    CHECK(DirectGate_SRP_CreateVerifier(pSecret, salt, sizeof(salt), sVerifier, sizeof(sVerifier)),
        "build a verifier for the test secret");

    for (size_t i = 0; i < sizeof(salt); i++)
        snprintf(fix.cfg.auth.sSaltHex + (i * 2), 3, "%02x", salt[i]);

    xstrncpy(fix.cfg.auth.sVerifierHex, sizeof(fix.cfg.auth.sVerifierHex), sVerifier);

    /* A proof with no hello behind it must not be treated as a live handshake. */
    drain(&fix);
    CHECK(deliver(&fix, DirectGate_Proto_BuildAuthProof("aabb", 40)) == XAPI_CONTINUE,
        "an SRP proof with no handshake behind it is handled");
    CHECK(expect_auth(&fix, "failed", NULL),
        "an SRP proof with no handshake behind it is refused");

    /* The real client half, so the challenge the agent sends is one a client
     * can answer - and the proof it answers with is one the agent accepts. */
    directgate_srp_client_t client;
    CHECK(DirectGate_SRP_ClientInit(&client), "init the client SRP context");

    char sAHex[2048];
    char sClientNonceHex[(DIRECTGATE_SRP_NONCE_SIZE * 2) + 1];
    CHECK(DirectGate_SRP_ClientGenerateA(&client, sAHex, sizeof(sAHex),
        sClientNonceHex, sizeof(sClientNonceHex)), "start the client handshake");

    xjson_obj_t *pHello = DirectGate_Proto_BuildAuthHello(AGENT_DEVICE_ID, sAHex, sClientNonceHex, 41);
    CHECK(pHello != NULL, "build a well-formed SRP hello");

    drain(&fix);
    CHECK(deliver(&fix, pHello) == XAPI_CONTINUE, "a well-formed SRP hello is handled");

    directgate_pkg_t chal;
    CHECK(take_packet(&fix, &chal), "the agent answers a well-formed hello");

    xjson_obj_t *pChalRoot = chal.jsonHeader.pRootObj;
    const char *pType = XJSON_GetString(XJSON_GetObject(pChalRoot, "type"));
    const char *pSaltHex = XJSON_GetString(XJSON_GetObject(pChalRoot, "salt"));
    const char *pBHex = XJSON_GetString(XJSON_GetObject(pChalRoot, "B"));
    const char *pAgentNonce = XJSON_GetString(XJSON_GetObject(pChalRoot, "nonce"));
    uint32_t nSuite = XJSON_GetU32(XJSON_GetObject(pChalRoot, "suite"));

    CHECK(pType != NULL && strcmp(pType, "auth") == 0,
        "the answer to a hello is an auth message");
    CHECK(pSaltHex != NULL && strcmp(pSaltHex, fix.cfg.auth.sSaltHex) == 0,
        "the challenge carries the agent's configured salt");
    CHECK(pBHex != NULL && *pBHex != '\0', "the challenge carries a server public value");
    CHECK(pAgentNonce != NULL && strlen(pAgentNonce) == DIRECTGATE_SRP_NONCE_SIZE * 2,
        "the challenge carries a full-length agent nonce");
    CHECK(nSuite == DIRECTGATE_SRP_SUITE,
        "the challenge advertises the suite the client has to bind its proof to");

    size_t nNonceBytes = 0;
    CHECK(DirectGate_SRP_HexToBytes(pAgentNonce, client.agentNonce,
        sizeof(client.agentNonce), &nNonceBytes) &&
        nNonceBytes == sizeof(client.agentNonce), "parse the agent nonce off the challenge");

    char sM1[256];
    CHECK(DirectGate_SRP_ClientComputeKey(&client, AGENT_DEVICE_ID, pSecret, pSaltHex,
        pBHex, nSuite, sM1, sizeof(sM1)),
        "the client can answer the agent's challenge");
    DirectGate_Package_Clear(&chal);

    /* A proof that is not the client's must never authenticate the session. */
    char sWrongM1[256];
    xstrncpy(sWrongM1, sizeof(sWrongM1), sM1);
    sWrongM1[0] = (sWrongM1[0] == 'a') ? 'b' : 'a';

    drain(&fix);
    CHECK(deliver(&fix, DirectGate_Proto_BuildAuthProof(sWrongM1, 41)) == XAPI_CONTINUE,
        "a wrong SRP proof is handled");
    CHECK(expect_auth(&fix, "failed", NULL), "a wrong SRP proof is refused");
    CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 41) == NULL,
        "a wrong SRP proof closes the session rather than allowing another guess on it");

    DirectGate_SRP_ClientCleanse(&client);
    teardown(&fix);
    return 0;
}

static int test_key_auth_refusals(void)
{
    fixture_t fix;
    setup(&fix);

    /* Key auth is only offered when the agent actually has keys. Answering
     * anything else would let a client believe a key was accepted. */
    xjson_obj_t *pHeader = auth_header("hello", "key", 50);
    CHECK(pHeader != NULL, "build a key-auth hello");
    XJSON_AddString(pHeader, "deviceId", AGENT_DEVICE_ID);
    XJSON_AddString(pHeader, "clientPubKey", "AAAA");
    XJSON_AddString(pHeader, "clientEph", "AAAA");
    XJSON_AddString(pHeader, "nonce", "00");

    drain(&fix);
    CHECK(deliver(&fix, pHeader) == XAPI_CONTINUE, "a key-auth hello is handled");
    CHECK(expect_auth(&fix, "failed", "key auth not configured"),
        "an agent with no authorized keys refuses key auth by name so the client can fall back");

    /* Missing fields are refused before anything is decoded. */
    pHeader = auth_header("hello", "key", 51);
    CHECK(pHeader != NULL, "build an incomplete key-auth hello");
    XJSON_AddString(pHeader, "deviceId", AGENT_DEVICE_ID);
    XJSON_AddString(pHeader, "clientPubKey", "AAAA");

    drain(&fix);
    CHECK(deliver(&fix, pHeader) == XAPI_CONTINUE, "an incomplete key-auth hello is handled");
    CHECK(expect_auth(&fix, "failed", "missing key hello fields"),
        "a key-auth hello missing its ephemeral or nonce is refused by name");

    /* Another agent's device id must not start a handshake here. */
    pHeader = auth_header("hello", "key", 52);
    CHECK(pHeader != NULL, "build a key-auth hello for another device");
    XJSON_AddString(pHeader, "deviceId", "some-other-device");
    XJSON_AddString(pHeader, "clientPubKey", "AAAA");
    XJSON_AddString(pHeader, "clientEph", "AAAA");
    XJSON_AddString(pHeader, "nonce", "00");

    drain(&fix);
    CHECK(deliver(&fix, pHeader) == XAPI_CONTINUE, "a mismatched key-auth hello is handled");
    CHECK(expect_auth(&fix, "failed", "invalid device ID"),
        "a key-auth hello for another agent's device id is refused");

    /* A key-auth client must not be able to claim a temporary desktop share:
     * shares are bound to a one-time SRP secret, not to an authorized key. */
    pHeader = auth_header("hello", "key", 53);
    CHECK(pHeader != NULL, "build a key-auth hello claiming a share");
    XJSON_AddString(pHeader, "deviceId", AGENT_DEVICE_ID);
    XJSON_AddString(pHeader, "clientPubKey", "AAAA");
    XJSON_AddString(pHeader, "clientEph", "AAAA");
    XJSON_AddString(pHeader, "nonce", "00");
    XJSON_AddString(pHeader, "desktopShareId", "share-1");

    drain(&fix);
    CHECK(deliver(&fix, pHeader) == XAPI_CONTINUE, "a share-claiming key-auth hello is handled");
    CHECK(expect_auth(&fix, "failed", "temporary desktop shares require SRP"),
        "a key-auth client cannot claim a temporary desktop share");
    CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 53) == NULL,
        "claiming a share with the wrong method closes the session");

    /* An SRP hello quoting a share that was never issued is refused too. */
    pHeader = auth_header("hello", NULL, 54);
    CHECK(pHeader != NULL, "build an SRP hello quoting an unknown share");
    XJSON_AddString(pHeader, "deviceId", AGENT_DEVICE_ID);
    XJSON_AddString(pHeader, "A", "0123456789abcdef");
    XJSON_AddString(pHeader, "nonce", "00");
    XJSON_AddString(pHeader, "desktopShareId", "never-issued");

    drain(&fix);
    CHECK(deliver(&fix, pHeader) == XAPI_CONTINUE, "a hello quoting an unknown share is handled");
    CHECK(expect_auth(&fix, "failed", "temporary desktop share is invalid or expired"),
        "a hello quoting a share that was never issued is refused");
    CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 54) == NULL,
        "a hello quoting an unknown share closes the session");

    teardown(&fix);
    return 0;
}

/* An unauthenticated peer gets a fixed number of auth messages per session.
 * Without that cap one session is an unlimited guessing channel. */
static int test_pre_auth_message_cap(void)
{
    fixture_t fix;
    setup(&fix);

    for (uint32_t i = 0; i < DIRECTGATE_AUTH_MAX_MESSAGES; i++)
    {
        xjson_obj_t *pHeader = auth_header("hello", NULL, 60);
        CHECK(pHeader != NULL, "build a hello inside the attempt budget");
        XJSON_AddString(pHeader, "deviceId", AGENT_DEVICE_ID);

        drain(&fix);
        CHECK(deliver(&fix, pHeader) == XAPI_CONTINUE, "a hello inside the budget is handled");
        CHECK(expect_auth(&fix, "failed", "missing A"),
            "a hello inside the budget is answered on its own merits");
    }

    xjson_obj_t *pHeader = auth_header("hello", NULL, 60);
    CHECK(pHeader != NULL, "build the hello that exceeds the budget");
    XJSON_AddString(pHeader, "deviceId", AGENT_DEVICE_ID);

    drain(&fix);
    CHECK(deliver(&fix, pHeader) == XAPI_CONTINUE, "the hello past the budget is handled");
    CHECK(expect_auth(&fix, "failed", "authentication attempt limit reached"),
        "a session past its pre-auth message budget is refused by name");
    CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 60) == NULL,
        "a session past its pre-auth message budget is closed, not left to keep guessing");

    teardown(&fix);
    return 0;
}

/* An authenticated session must not be re-negotiable: accepting a second
 * handshake on it would let a later peer take over an established session. */
static int test_duplicate_after_auth(void)
{
    fixture_t fix;
    setup(&fix);

    directgate_session_t *pSession = DirectGate_SessionMgr_Create(&fix.conn.mgr, 70);
    CHECK(pSession != NULL, "create a session to authenticate");
    pSession->pWsSession = &fix.api;

    /* Bring the session up the way a finished handshake leaves it: keys on
       both halves, agent role on one side and browser role on the other. */
    uint8_t sKey[32];
    uint8_t agentNonce[DIRECTGATE_SRP_NONCE_SIZE];
    uint8_t clientNonce[DIRECTGATE_SRP_NONCE_SIZE];

    memset(sKey, 0x5c, sizeof(sKey));
    memset(agentNonce, 0x11, sizeof(agentNonce));
    memset(clientNonce, 0x22, sizeof(clientNonce));

    DirectGate_E2E_Init(&pSession->e2e);
    DirectGate_E2E_Init(&fix.peer);

    CHECK(DirectGate_E2E_DeriveFromSRP(&pSession->e2e, sKey, sizeof(sKey), agentNonce,
        clientNonce, sizeof(agentNonce), AGENT_DEVICE_ID, XTRUE), "derive the agent's E2E keys");
    CHECK(DirectGate_E2E_DeriveFromSRP(&fix.peer, sKey, sizeof(sKey), agentNonce,
        clientNonce, sizeof(agentNonce), AGENT_DEVICE_ID, XFALSE), "derive the browser's E2E keys");

    pSession->bAuthenticated = XTRUE;
    pSession->term.bEncrypt = XTRUE;

    /* Anyone who can reach the relay can put plaintext on it. An established
       session must not read a word of it, least of all a new handshake. */
    xjson_obj_t *pHeader = auth_header("hello", NULL, 70);
    CHECK(pHeader != NULL, "build a plaintext hello for an authenticated session");
    XJSON_AddString(pHeader, "deviceId", AGENT_DEVICE_ID);
    XJSON_AddString(pHeader, "A", "0123456789abcdef");
    XJSON_AddString(pHeader, "nonce", "00");

    drain(&fix);
    CHECK(deliver(&fix, pHeader) == XAPI_CONTINUE, "a plaintext hello is handled");
    CHECK(no_answer(&fix),
        "an authenticated session does not answer a plaintext handshake at all");
    CHECK(pSession->bAuthenticated,
        "a plaintext handshake leaves the established session authenticated");

    /* The established peer's own second handshake is refused by name rather
       than re-running the key exchange on a live session. */
    pHeader = auth_header("hello", NULL, 70);
    CHECK(pHeader != NULL, "build an encrypted hello for an authenticated session");
    XJSON_AddString(pHeader, "deviceId", AGENT_DEVICE_ID);
    XJSON_AddString(pHeader, "A", "0123456789abcdef");
    XJSON_AddString(pHeader, "nonce", "00");

    drain(&fix);
    CHECK(deliver_encrypted(&fix, pHeader, 70) == XAPI_CONTINUE,
        "an encrypted second hello is handled");
    CHECK(expect_auth(&fix, "failed", "already authenticated"),
        "a second handshake on an authenticated session is refused by name");
    CHECK(pSession->bAuthenticated,
        "a refused second handshake leaves the established session authenticated");

    DirectGate_E2E_Clear(&fix.peer);
    teardown(&fix);
    return 0;
}

int main(void)
{
    if (test_malformed()) return 1;
    if (test_srp_hello_refusals()) return 1;
    if (test_srp_not_configured()) return 1;
    if (test_srp_challenge_and_proof()) return 1;
    if (test_key_auth_refusals()) return 1;
    if (test_pre_auth_message_cap()) return 1;
    if (test_duplicate_after_auth()) return 1;

    puts("auth_flow_smoke: OK");
    return 0;
}
