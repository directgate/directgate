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
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/crypto.h>

#include "src/agent/directgate.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "auth_flow_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

#define AGENT_DEVICE_ID "device-under-test"

int DirectGate_ServiceCallback(xapi_ctx_t *pCtx, xapi_session_t *pApiSession);

/* Not in api.h: creates the event loop without registering anything on it. */
xevents_t* XAPI_GetOrCreateEvents(xapi_t *pApi);

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

/* ---- completed handshakes ------------------------------------------------- */

/* A salt and the matching verifier for pSecret, in the hex form the config and
 * the admin share message carry. */
static int make_srp_record(const char *pSecret, uint8_t nSaltByte,
                           char *pSaltHex, size_t nSaltHexSize,
                           char *pVerifierHex, size_t nVerifierHexSize)
{
    uint8_t salt[DIRECTGATE_SRP_SALT_SIZE];
    memset(salt, nSaltByte, sizeof(salt));

    if (nSaltHexSize < sizeof(salt) * 2 + 1) return 0;
    if (!DirectGate_SRP_CreateVerifier(pSecret, salt, sizeof(salt), pVerifierHex, nVerifierHexSize)) return 0;

    for (size_t i = 0; i < sizeof(salt); i++) snprintf(pSaltHex + (i * 2), 3, "%02x", salt[i]);
    return 1;
}

static int configure_srp(fixture_t *pFix, const char *pSecret)
{
    return make_srp_record(pSecret, 0x2b, pFix->cfg.auth.sSaltHex, sizeof(pFix->cfg.auth.sSaltHex),
        pFix->cfg.auth.sVerifierHex, sizeof(pFix->cfg.auth.sVerifierHex));
}

/* Runs an SRP handshake for nSessionId the way a browser does. Returns 1 when the
 * agent accepted the proof (and verified itself with M2), in which case pPeer holds
 * the browser's E2E keys; 0 when the agent refused, with the refusal left unread
 * on the wire; -1 when the exchange itself broke. */
static int srp_login(fixture_t *pFix, uint32_t nSessionId, const char *pSecret,
                     const char *pShareId, xbool_t bWrongProof, directgate_e2e_t *pPeer)
{
    directgate_srp_client_t client;
    if (!DirectGate_SRP_ClientInit(&client)) return -1;

    char sAHex[2048];
    char sNonceHex[(DIRECTGATE_SRP_NONCE_SIZE * 2) + 1];
    char sBHex[2048];
    char sSaltHex[DIRECTGATE_AUTH_SALT_HEX_SIZE];
    char sM1[256];
    int nResult = -1;

    do
    {
        if (!DirectGate_SRP_ClientGenerateA(&client, sAHex, sizeof(sAHex), sNonceHex, sizeof(sNonceHex))) break;

        xjson_obj_t *pHello = DirectGate_Proto_BuildAuthHello(AGENT_DEVICE_ID, sAHex, sNonceHex, nSessionId);
        if (pHello == NULL) break;
        if (pShareId != NULL) XJSON_AddString(pHello, "desktopShareId", pShareId);

        drain(pFix);
        if (deliver(pFix, pHello) != XAPI_CONTINUE && pShareId == NULL) break;

        directgate_pkg_t chal;
        if (!take_packet(pFix, &chal)) break;

        xjson_obj_t *pRoot = chal.jsonHeader.pRootObj;
        const char *pAction = XJSON_GetString(XJSON_GetObject(pRoot, "action"));

        if (pAction == NULL || strcmp(pAction, "challenge") != 0)
        {
            /* The refusal stays queued for the caller to read. */
            DirectGate_Package_Clear(&chal);
            nResult = 0;
            break;
        }

        xstrncpy(sBHex, sizeof(sBHex), XJSON_GetString(XJSON_GetObject(pRoot, "B")));
        xstrncpy(sSaltHex, sizeof(sSaltHex), XJSON_GetString(XJSON_GetObject(pRoot, "salt")));
        const char *pAgentNonce = XJSON_GetString(XJSON_GetObject(pRoot, "nonce"));
        uint32_t nSuite = XJSON_GetU32(XJSON_GetObject(pRoot, "suite"));

        size_t nNonceBytes = 0;
        xbool_t bParsed = DirectGate_SRP_HexToBytes(pAgentNonce, client.agentNonce,
            sizeof(client.agentNonce), &nNonceBytes) && nNonceBytes == sizeof(client.agentNonce);
        DirectGate_Package_Clear(&chal);

        if (!bParsed || !DirectGate_SRP_ClientComputeKey(&client, AGENT_DEVICE_ID, pSecret, sSaltHex,
                sBHex, nSuite, sM1, sizeof(sM1))) break;

        if (bWrongProof) sM1[0] = (sM1[0] == 'a') ? 'b' : 'a';

        drain(pFix);
        if (deliver(pFix, DirectGate_Proto_BuildAuthProof(sM1, nSessionId)) != XAPI_CONTINUE && !bWrongProof) break;

        directgate_pkg_t result;
        if (!take_packet(pFix, &result)) break;

        const char *pStatus = XJSON_GetString(XJSON_GetObject(result.jsonHeader.pRootObj, "status"));
        const char *pM2 = XJSON_GetString(XJSON_GetObject(result.jsonHeader.pRootObj, "M2"));

        if (pStatus == NULL || strcmp(pStatus, "ok") != 0)
        {
            DirectGate_Package_Clear(&result);
            nResult = 0;
            break;
        }

        /* The agent has to prove itself too: a browser that accepted any "ok"
           could be answered by the relay instead of the agent. */
        xbool_t bAgentProved = pM2 != NULL && DirectGate_SRP_ClientVerifyM2(&client, sBHex, pM2);
        DirectGate_Package_Clear(&result);
        if (!bAgentProved) break;

        DirectGate_E2E_Init(pPeer);
        if (!DirectGate_E2E_DeriveFromSRP(pPeer, client.K, sizeof(client.K), client.agentNonce,
                client.nonce, DIRECTGATE_SRP_NONCE_SIZE, AGENT_DEVICE_ID, XFALSE)) break;

        nResult = 1;
    }
    while (0);

    DirectGate_SRP_ClientCleanse(&client);
    return nResult;
}

/* Sends header and payload sealed under pPeer, as that browser would. Whatever
 * was still queued is dropped first, so the next read is the answer to this message. */
static int deliver_payload_as(fixture_t *pFix, directgate_e2e_t *pPeer, xjson_obj_t *pHeader,
                              const char *pPayload, uint32_t nSessionId)
{
    drain(pFix);
    xbyte_buffer_t packet;
    XByteBuffer_Init(&packet, XSTDNON, XFALSE);
    if (pHeader == NULL) return XSTDERR;

    DirectGate_Proto_AddCC(pHeader, pPeer, 0);
    size_t nPayload = pPayload != NULL ? strlen(pPayload) : 0;

    if (!DirectGate_Proto_Build(&packet, pHeader, (const uint8_t*)pPayload, nPayload, XFALSE) ||
        !DirectGate_Proto_EncryptPackage(&packet, pPeer, nSessionId))
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

static int deliver_as(fixture_t *pFix, directgate_e2e_t *pPeer, xjson_obj_t *pHeader, uint32_t nSessionId)
{
    return deliver_payload_as(pFix, pPeer, pHeader, NULL, nSessionId);
}

/* Reads the next answer sealed for pPeer; the fixture's own peer is swapped in
 * only for the duration of the read. */
static int take_packet_as(fixture_t *pFix, directgate_e2e_t *pPeer, directgate_pkg_t *pPkg)
{
    directgate_e2e_t saved = pFix->peer;
    pFix->peer = *pPeer;
    int nTaken = take_packet(pFix, pPkg);
    *pPeer = pFix->peer;
    pFix->peer = saved;
    return nTaken;
}

/* A keepalive ping answered with a pong proves both halves hold matching keys. */
static int keepalive_round_trip(fixture_t *pFix, directgate_e2e_t *pPeer, uint32_t nSessionId)
{
    drain(pFix);
    if (deliver_as(pFix, pPeer, DirectGate_Proto_BuildKeepalive("ping", nSessionId), nSessionId) != XAPI_CONTINUE)
        return 0;

    directgate_pkg_t pkg;
    if (!take_packet_as(pFix, pPeer, &pkg)) return 0;

    const char *pAction = XJSON_GetString(XJSON_GetObject(pkg.jsonHeader.pRootObj, "action"));
    int nOk = pAction != NULL && strcmp(pAction, "pong") == 0;

    DirectGate_Package_Clear(&pkg);
    drain(pFix);
    return nOk;
}

static const char* take_field(fixture_t *pFix, directgate_e2e_t *pPeer, const char *pField,
                              char *pOut, size_t nOutSize)
{
    directgate_pkg_t pkg;
    pOut[0] = '\0';
    if (!take_packet_as(pFix, pPeer, &pkg)) return pOut;

    const char *pValue = XJSON_GetString(XJSON_GetObject(pkg.jsonHeader.pRootObj, pField));
    if (pValue != NULL) xstrncpy(pOut, nOutSize, pValue);

    DirectGate_Package_Clear(&pkg);
    drain(pFix);
    return pOut;
}

static int test_srp_login(void)
{
    fixture_t fix;
    setup(&fix);

    const char *pSecret = "correct horse battery staple";
    CHECK(configure_srp(&fix, pSecret), "configure a loadable SRP record");

    /* Failures before a success are counted, and a success clears them: the
       throttle must never keep punishing the owner after they got in. */
    directgate_e2e_t peer;
    CHECK(srp_login(&fix, 80, pSecret, NULL, XTRUE, &peer) == 0, "a wrong proof does not authenticate");
    CHECK(expect_auth(&fix, "failed", "invalid proof"), "a wrong proof is refused by name");
    CHECK(fix.conn.mgr.nAuthFailures == 1, "a wrong proof is counted against the throttle");

    CHECK(srp_login(&fix, 81, pSecret, NULL, XFALSE, &peer) == 1,
        "the right password authenticates and the agent proves itself with M2");
    CHECK(fix.conn.mgr.nAuthFailures == 0, "a successful login clears the failure count");

    directgate_session_t *pSession = DirectGate_SessionMgr_Find(&fix.conn.mgr, 81);
    CHECK(pSession != NULL && pSession->bAuthenticated && pSession->term.bEncrypt,
        "a successful login leaves an authenticated, encrypting session");
    CHECK(!pSession->bDesktopShare, "an owner login is not a temporary share");
    CHECK(keepalive_round_trip(&fix, &peer, 81), "the browser and the agent derived the same E2E keys");

    /* A proof without its M1 is a refusal that also closes the session. */
    {
        directgate_srp_client_t client;
        char sAHex[2048];
        char sNonceHex[(DIRECTGATE_SRP_NONCE_SIZE * 2) + 1];
        CHECK(DirectGate_SRP_ClientInit(&client) &&
            DirectGate_SRP_ClientGenerateA(&client, sAHex, sizeof(sAHex), sNonceHex, sizeof(sNonceHex)),
            "start a second client handshake");

        drain(&fix);
        CHECK(deliver(&fix, DirectGate_Proto_BuildAuthHello(AGENT_DEVICE_ID, sAHex, sNonceHex, 82)) == XAPI_CONTINUE,
            "a hello for the proof-without-M1 case is handled");
        drain(&fix);
        CHECK(deliver(&fix, auth_header("proof", NULL, 82)) == XAPI_CONTINUE, "a proof without M1 is handled");
        CHECK(expect_auth(&fix, "failed", "missing M1"), "a proof without M1 is refused by name");
        CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 82) == NULL, "a proof without M1 closes the session");
        DirectGate_SRP_ClientCleanse(&client);
    }

    /* A client value the group rejects (A mod N == 0) must not start a handshake:
       it would pin the shared secret to a value the attacker knows. */
    {
        xjson_obj_t *pHello = DirectGate_Proto_BuildAuthHello(AGENT_DEVICE_ID, "00",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", 83);
        drain(&fix);
        CHECK(deliver(&fix, pHello) == XAPI_CONTINUE, "a hello with a zero client value is handled");
        CHECK(expect_auth(&fix, "failed", "invalid A"), "a zero client value is refused");
    }

    /* The mode the browser asked for before logging in starts right after it.
       Starting a mode registers endpoints, so this part needs an event loop. */
    {
        xapi_t xapi;
        XAPI_Init(&xapi, DirectGate_ServiceCallback, &fix.conn);
        CHECK(XAPI_GetOrCreateEvents(&xapi) != NULL, "an event loop for the started mode");
        fix.api.pApi = &xapi;

        directgate_session_t *pEarly = DirectGate_SessionMgr_GetOrCreate(&fix.conn.mgr, &fix.api, 84);
        CHECK(pEarly != NULL, "create a session that asks for a mode before auth");
        pEarly->eRequestedMode = DIRECTGATE_SESSION_MODE_FILE_MANAGER;

        directgate_e2e_t earlyPeer;
        CHECK(srp_login(&fix, 84, pSecret, NULL, XFALSE, &earlyPeer) == 1, "log in a session with a pending mode");
        CHECK(pEarly->eActiveMode == DIRECTGATE_SESSION_MODE_FILE_MANAGER,
            "the requested file manager mode starts as soon as the session is authenticated");
        DirectGate_E2E_Clear(&earlyPeer);

        DirectGate_Session_Close(pEarly, "test done");
        XAPI_Destroy(&xapi);
        fix.api.pApi = NULL;
    }

    DirectGate_E2E_Clear(&peer);
    teardown(&fix);
    return 0;
}

/* The key half of the agent identity and one authorized client key. */
typedef struct {
    directgate_client_key_t client;
    char sClientPubB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    char sAgentPubB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
} key_setup_t;

static int configure_keys(fixture_t *pFix, key_setup_t *pKeys)
{
    uint8_t agentPub[DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE];
    uint8_t agentSeed[DIRECTGATE_KEYAUTH_ED25519_SEED_SIZE];

    int nOk = DirectGate_KeyAuth_Ed25519Generate(agentPub, agentSeed) &&
        DirectGate_KeyAuth_Base64Encode(agentSeed, sizeof(agentSeed),
            pFix->cfg.keyauth.sIdentitySeedB64, sizeof(pFix->cfg.keyauth.sIdentitySeedB64)) &&
        DirectGate_KeyAuth_Base64Encode(agentPub, sizeof(agentPub),
            pFix->cfg.keyauth.sIdentityPubB64, sizeof(pFix->cfg.keyauth.sIdentityPubB64)) &&
        DirectGate_KeyAuth_KeyGenerate(&pKeys->client) &&
        DirectGate_KeyAuth_Base64Encode(pKeys->client.clientPub, sizeof(pKeys->client.clientPub),
            pKeys->sClientPubB64, sizeof(pKeys->sClientPubB64));

    OPENSSL_cleanse(agentSeed, sizeof(agentSeed));
    if (!nOk) return 0;

    xstrncpy(pKeys->sAgentPubB64, sizeof(pKeys->sAgentPubB64), pFix->cfg.keyauth.sIdentityPubB64);
    xstrncpy(pFix->cfg.keyauth.sAuthorizedKeys[0], sizeof(pFix->cfg.keyauth.sAuthorizedKeys[0]), pKeys->sClientPubB64);
    pFix->cfg.keyauth.nAuthorizedKeyCount = 1;
    return 1;
}

/* Sends the client's key hello and returns the agent's challenge in pChal. */
static int key_hello(fixture_t *pFix, directgate_keyauth_t *pClientAuth, const directgate_client_key_t *pKey,
                     const char *pAgentPubB64, uint32_t nSessionId, directgate_pkg_t *pChal)
{
    char sPub[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    char sEph[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    char sNonce[(DIRECTGATE_KEYAUTH_NONCE_SIZE * 2) + 1];

    DirectGate_KeyAuth_Init(pClientAuth);
    if (!DirectGate_KeyAuth_ClientInit(pClientAuth, AGENT_DEVICE_ID, pKey, pAgentPubB64) ||
        !DirectGate_KeyAuth_ClientBuildHello(pClientAuth, sPub, sizeof(sPub), sEph, sizeof(sEph), sNonce, sizeof(sNonce)))
        return 0;

    drain(pFix);
    if (deliver(pFix, DirectGate_Proto_BuildAuthKeyHello(AGENT_DEVICE_ID, sPub, sEph, sNonce, nSessionId)) != XAPI_CONTINUE)
        return 0;

    return take_packet(pFix, pChal);
}

static int test_key_auth_login(void)
{
    fixture_t fix;
    setup(&fix);

    key_setup_t keys;
    CHECK(configure_keys(&fix, &keys), "configure an agent identity and one authorized client key");

    /* The whole handshake, the way dgcli runs it. */
    directgate_keyauth_t clientAuth;
    directgate_pkg_t chal;
    CHECK(key_hello(&fix, &clientAuth, &keys.client, keys.sAgentPubB64, 90, &chal), "the agent answers a key hello");

    xjson_obj_t *pRoot = chal.jsonHeader.pRootObj;
    const char *pAction = XJSON_GetString(XJSON_GetObject(pRoot, "action"));
    CHECK(pAction != NULL && strcmp(pAction, "challenge") == 0, "a key hello is answered with a challenge");

    char sSig[DIRECTGATE_KEYAUTH_SIG_B64_SIZE];
    CHECK(DirectGate_KeyAuth_ClientProcessChallenge(&clientAuth, &keys.client,
        XJSON_GetString(XJSON_GetObject(pRoot, "agentPubKey")),
        XJSON_GetString(XJSON_GetObject(pRoot, "agentEph")),
        XJSON_GetString(XJSON_GetObject(pRoot, "nonce")),
        XJSON_GetString(XJSON_GetObject(pRoot, "challenge")),
        XJSON_GetString(XJSON_GetObject(pRoot, "agentSig")), sSig, sizeof(sSig)),
        "the challenge is signed by the pinned agent identity and the client can answer it");
    DirectGate_Package_Clear(&chal);

    /* A second hello while the challenge is pending is ignored, not restarted:
       restarting would let a flood keep the agent generating keys. */
    {
        directgate_keyauth_t other;
        drain(&fix);
        char sPub[DIRECTGATE_KEYAUTH_PUB_B64_SIZE], sEph[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
        char sNonce[(DIRECTGATE_KEYAUTH_NONCE_SIZE * 2) + 1];
        DirectGate_KeyAuth_Init(&other);
        CHECK(DirectGate_KeyAuth_ClientInit(&other, AGENT_DEVICE_ID, &keys.client, keys.sAgentPubB64) &&
            DirectGate_KeyAuth_ClientBuildHello(&other, sPub, sizeof(sPub), sEph, sizeof(sEph), sNonce, sizeof(sNonce)),
            "build a second key hello");
        CHECK(deliver(&fix, DirectGate_Proto_BuildAuthKeyHello(AGENT_DEVICE_ID, sPub, sEph, sNonce, 90)) == XAPI_CONTINUE,
            "a second key hello is handled");
        CHECK(no_answer(&fix), "a second key hello while a challenge is pending is ignored");
        DirectGate_KeyAuth_Cleanse(&other);
    }

    drain(&fix);
    CHECK(deliver(&fix, DirectGate_Proto_BuildAuthKeyProof(sSig, 90)) == XAPI_CONTINUE, "the key proof is handled");
    CHECK(expect_auth(&fix, "ok", ""), "a valid key proof authenticates, with no reason attached");

    directgate_session_t *pSession = DirectGate_SessionMgr_Find(&fix.conn.mgr, 90);
    CHECK(pSession != NULL && pSession->bAuthenticated && !pSession->bKeyAuthActive,
        "a key login leaves an authenticated session with no handshake pending");

    CHECK(DirectGate_KeyAuth_ClientAccept(&clientAuth) && DirectGate_KeyAuth_DeriveShared(&clientAuth),
        "the client derives the shared secret");
    directgate_e2e_t peer;
    DirectGate_E2E_Init(&peer);
    CHECK(DirectGate_E2E_DeriveFromKey(&peer, clientAuth.sharedSecret, sizeof(clientAuth.sharedSecret),
        clientAuth.peerNonce, clientAuth.localNonce, DIRECTGATE_KEYAUTH_NONCE_SIZE, AGENT_DEVICE_ID, XFALSE),
        "the client derives its E2E keys");
    CHECK(keepalive_round_trip(&fix, &peer, 90), "the key login produced matching E2E keys on both halves");
    DirectGate_KeyAuth_Cleanse(&clientAuth);
    DirectGate_E2E_Clear(&peer);

    /* A signature that is not the client's is refused and counted. */
    {
        CHECK(key_hello(&fix, &clientAuth, &keys.client, keys.sAgentPubB64, 91, &chal), "start another key handshake");
        DirectGate_Package_Clear(&chal);

        char sBadSig[DIRECTGATE_KEYAUTH_SIG_B64_SIZE];
        uint8_t zero[64];
        memset(zero, 0x41, sizeof(zero));
        CHECK(DirectGate_KeyAuth_Base64Encode(zero, sizeof(zero), sBadSig, sizeof(sBadSig)), "encode a forged signature");

        uint32_t nFailures = fix.conn.mgr.nAuthFailures;
        drain(&fix);
        CHECK(deliver(&fix, DirectGate_Proto_BuildAuthKeyProof(sBadSig, 91)) == XAPI_CONTINUE, "a forged proof is handled");
        CHECK(expect_auth(&fix, "failed", "invalid proof"), "a forged key proof is refused by name");
        CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 91) == NULL, "a forged key proof closes the session");
        CHECK(fix.conn.mgr.nAuthFailures == nFailures + 1, "a forged key proof is counted against the throttle");
        DirectGate_KeyAuth_Cleanse(&clientAuth);
    }

    /* A proof with no signature at all is refused and closes the session. */
    {
        CHECK(key_hello(&fix, &clientAuth, &keys.client, keys.sAgentPubB64, 92, &chal), "start a third key handshake");
        DirectGate_Package_Clear(&chal);

        drain(&fix);
        CHECK(deliver(&fix, auth_header("proof", "key", 92)) == XAPI_CONTINUE, "a key proof without a signature is handled");
        CHECK(expect_auth(&fix, "failed", "missing clientSig"), "a key proof without a signature is refused by name");
        CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 92) == NULL, "a key proof without a signature closes the session");
        DirectGate_KeyAuth_Cleanse(&clientAuth);
    }

    /* A key that is well formed but not on the authorized list gets no challenge. */
    {
        directgate_client_key_t stranger;
        CHECK(DirectGate_KeyAuth_KeyGenerate(&stranger), "generate an unauthorized client key");
        CHECK(key_hello(&fix, &clientAuth, &stranger, keys.sAgentPubB64, 93, &chal),
            "the agent answers an unauthorized key hello");
        const char *pStatus = XJSON_GetString(XJSON_GetObject(chal.jsonHeader.pRootObj, "status"));
        const char *pReason = XJSON_GetString(XJSON_GetObject(chal.jsonHeader.pRootObj, "reason"));
        CHECK(pStatus != NULL && strcmp(pStatus, "failed") == 0 && pReason != NULL &&
            strcmp(pReason, "client not authorized") == 0, "an unauthorized client key is refused by name");
        DirectGate_Package_Clear(&chal);
        DirectGate_KeyAuth_KeyCleanse(&stranger);
        DirectGate_KeyAuth_Cleanse(&clientAuth);
    }

    /* A client public key that does not decode is refused before any crypto runs. */
    {
        drain(&fix);
        CHECK(deliver(&fix, DirectGate_Proto_BuildAuthKeyHello(AGENT_DEVICE_ID, "!!not-base64!!", "!!", "00", 94)) ==
            XAPI_CONTINUE, "a key hello with undecodable keys is handled");
        CHECK(expect_auth(&fix, "failed", "invalid key hello"), "a key hello with undecodable keys is refused by name");
    }

    /* An agent whose own identity is corrupt refuses instead of signing with it. */
    {
        char sSavedSeed[sizeof(fix.cfg.keyauth.sIdentitySeedB64)];
        xstrncpy(sSavedSeed, sizeof(sSavedSeed), fix.cfg.keyauth.sIdentitySeedB64);
        xstrncpy(fix.cfg.keyauth.sIdentitySeedB64, sizeof(fix.cfg.keyauth.sIdentitySeedB64), "c2hvcnQ=");

        CHECK(key_hello(&fix, &clientAuth, &keys.client, keys.sAgentPubB64, 95, &chal),
            "the agent answers a key hello with a corrupt identity");
        const char *pReason = XJSON_GetString(XJSON_GetObject(chal.jsonHeader.pRootObj, "reason"));
        CHECK(pReason != NULL && strcmp(pReason, "agent identity malformed") == 0,
            "an agent with a corrupt identity refuses key logins by name");
        DirectGate_Package_Clear(&chal);
        DirectGate_KeyAuth_Cleanse(&clientAuth);
        xstrncpy(fix.cfg.keyauth.sIdentitySeedB64, sizeof(fix.cfg.keyauth.sIdentitySeedB64), sSavedSeed);
    }

    DirectGate_KeyAuth_KeyCleanse(&keys.client);
    teardown(&fix);
    return 0;
}

/* ---- admin actions and temporary desktop shares ------------------------------ */

static xjson_obj_t* admin_header(const char *pAction, const char *pClientPub, uint32_t nSessionId)
{
    xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("admin", nSessionId);
    if (pHeader == NULL) return NULL;

    if (pAction != NULL) XJSON_AddString(pHeader, "action", pAction);
    if (pClientPub != NULL) XJSON_AddString(pHeader, "clientPub", pClientPub);
    return pHeader;
}

static xjson_obj_t* share_header(const char *pAction, const char *pShareId, const char *pSaltHex,
                                 const char *pVerifierHex, uint32_t nTtlSeconds, uint32_t nSessionId)
{
    xjson_obj_t *pHeader = admin_header(pAction, NULL, nSessionId);
    if (pHeader == NULL) return NULL;

    if (pShareId != NULL) XJSON_AddString(pHeader, "shareId", pShareId);
    if (pSaltHex != NULL) XJSON_AddString(pHeader, "salt", pSaltHex);
    if (pVerifierHex != NULL) XJSON_AddString(pHeader, "verifier", pVerifierHex);
    if (nTtlSeconds) XJSON_AddU32(pHeader, "ttlSeconds", nTtlSeconds);
    return pHeader;
}

/* Admin answers carry their verdict in "status" and the why in "reason". */
static int expect_admin(fixture_t *pFix, directgate_e2e_t *pPeer, const char *pAction,
                        const char *pStatus, const char *pReason)
{
    directgate_pkg_t pkg;
    if (!take_packet_as(pFix, pPeer, &pkg)) return 0;

    xjson_obj_t *pRoot = pkg.jsonHeader.pRootObj;
    const char *pGotAction = XJSON_GetString(XJSON_GetObject(pRoot, "action"));
    const char *pGotStatus = XJSON_GetString(XJSON_GetObject(pRoot, "status"));
    const char *pGotReason = XJSON_GetString(XJSON_GetObject(pRoot, "reason"));

    int nOk = pGotAction != NULL && strcmp(pGotAction, pAction) == 0 &&
        pGotStatus != NULL && strcmp(pGotStatus, pStatus) == 0 &&
        (pReason == NULL || (pGotReason != NULL && strcmp(pGotReason, pReason) == 0));

    DirectGate_Package_Clear(&pkg);
    drain(pFix);
    return nOk;
}

static int test_admin_actions(void)
{
    fixture_t fix;
    setup(&fix);

    char sRoot[] = "/tmp/directgate_auth_flow.XXXXXX";
    CHECK(mkdtemp(sRoot) != NULL, "create a directory for the saved config");
    snprintf(fix.cfg.sCfgPath, sizeof(fix.cfg.sCfgPath), "%s/agent.json", sRoot);

    const char *pSecret = "owner password";
    CHECK(configure_srp(&fix, pSecret), "configure the owner's SRP record");

    directgate_e2e_t peer;
    CHECK(srp_login(&fix, 100, pSecret, NULL, XFALSE, &peer) == 1, "the owner logs in");

    /* Admin traffic from a session that never authenticated is not answered. */
    drain(&fix);
    CHECK(deliver(&fix, admin_header("add-key", "AAAA", 199)) == XAPI_CONTINUE, "admin from a stranger is handled");
    CHECK(no_answer(&fix), "admin traffic from an unauthenticated session is not answered");

    drain(&fix);
    CHECK(deliver_as(&fix, &peer, admin_header(NULL, NULL, 100), 100) == XAPI_CONTINUE, "admin without action is handled");
    CHECK(expect_admin(&fix, &peer, "admin-result", "error", "missing-action"), "admin without action is refused by name");

    CHECK(deliver_as(&fix, &peer, admin_header("reboot", NULL, 100), 100) == XAPI_CONTINUE, "unknown admin is handled");
    CHECK(expect_admin(&fix, &peer, "admin-result", "error", "unknown-action"), "an unknown admin action is refused by name");

    /* add-key: every answer the browser can get. */
    CHECK(deliver_as(&fix, &peer, admin_header("add-key", NULL, 100), 100) == XAPI_CONTINUE, "add-key without key");
    CHECK(expect_admin(&fix, &peer, "add-key-result", "error", "missing-client-pub"), "add-key without a key is refused");

    CHECK(deliver_as(&fix, &peer, admin_header("add-key", "not-a-key", 100), 100) == XAPI_CONTINUE, "add-key bad key");
    CHECK(expect_admin(&fix, &peer, "add-key-result", "error", "invalid-key"), "add-key with a malformed key is refused");

    directgate_client_key_t key;
    char sKeyB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    CHECK(DirectGate_KeyAuth_KeyGenerate(&key) &&
        DirectGate_KeyAuth_Base64Encode(key.clientPub, sizeof(key.clientPub), sKeyB64, sizeof(sKeyB64)),
        "generate a client key to authorize");

    CHECK(deliver_as(&fix, &peer, admin_header("add-key", sKeyB64, 100), 100) == XAPI_CONTINUE, "add-key");
    CHECK(expect_admin(&fix, &peer, "add-key-result", "ok", NULL), "a new key is authorized");
    CHECK(fix.cfg.keyauth.nAuthorizedKeyCount == 1 && strcmp(fix.cfg.keyauth.sAuthorizedKeys[0], sKeyB64) == 0,
        "the authorized key is recorded in the config");

    struct stat st;
    CHECK(stat(fix.cfg.sCfgPath, &st) == 0 && st.st_size > 0, "authorizing a key persists the config");

    CHECK(deliver_as(&fix, &peer, admin_header("add-key", sKeyB64, 100), 100) == XAPI_CONTINUE, "add-key again");
    CHECK(expect_admin(&fix, &peer, "add-key-result", "already", NULL), "a key that is already authorized is reported as such");
    CHECK(fix.cfg.keyauth.nAuthorizedKeyCount == 1, "a repeated key is not stored twice");

    /* A config that cannot be written reports the failure instead of pretending. */
    {
        directgate_client_key_t other;
        char sOtherB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
        CHECK(DirectGate_KeyAuth_KeyGenerate(&other) &&
            DirectGate_KeyAuth_Base64Encode(other.clientPub, sizeof(other.clientPub), sOtherB64, sizeof(sOtherB64)),
            "generate a second client key");

        char sSavedPath[sizeof(fix.cfg.sCfgPath)];
        xstrncpy(sSavedPath, sizeof(sSavedPath), fix.cfg.sCfgPath);
        xstrncpy(fix.cfg.sCfgPath, sizeof(fix.cfg.sCfgPath), "/proc/directgate-no-such-dir/agent.json");

        CHECK(deliver_as(&fix, &peer, admin_header("add-key", sOtherB64, 100), 100) == XAPI_CONTINUE, "add-key unsaved");
        CHECK(expect_admin(&fix, &peer, "add-key-result", "error", "persist-failed"),
            "a key that cannot be persisted is reported as a failure");

        xstrncpy(fix.cfg.sCfgPath, sizeof(fix.cfg.sCfgPath), sSavedPath);
        DirectGate_KeyAuth_KeyCleanse(&other);
    }

    /* The authorized list has a fixed size and says so when it is full. */
    {
        while (fix.cfg.keyauth.nAuthorizedKeyCount < DIRECTGATE_MAX_AUTHORIZED_KEYS)
        {
            uint8_t nIndex = fix.cfg.keyauth.nAuthorizedKeyCount;
            xstrncpy(fix.cfg.keyauth.sAuthorizedKeys[nIndex], sizeof(fix.cfg.keyauth.sAuthorizedKeys[0]), "placeholder");
            fix.cfg.keyauth.sAuthorizedKeys[nIndex][0] = (char)('A' + nIndex);
            fix.cfg.keyauth.nAuthorizedKeyCount++;
        }

        directgate_client_key_t extra;
        char sExtraB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
        CHECK(DirectGate_KeyAuth_KeyGenerate(&extra) &&
            DirectGate_KeyAuth_Base64Encode(extra.clientPub, sizeof(extra.clientPub), sExtraB64, sizeof(sExtraB64)),
            "generate a key for a full list");

        CHECK(deliver_as(&fix, &peer, admin_header("add-key", sExtraB64, 100), 100) == XAPI_CONTINUE, "add-key full");
        CHECK(expect_admin(&fix, &peer, "add-key-result", "error", "capacity-full"), "a full key list refuses by name");
        DirectGate_KeyAuth_KeyCleanse(&extra);
    }

    DirectGate_KeyAuth_KeyCleanse(&key);
    DirectGate_E2E_Clear(&peer);
    teardown(&fix);

    unlink(fix.cfg.sCfgPath);
    rmdir(sRoot);
    return 0;
}

static int find_share(fixture_t *pFix, const char *pShareId)
{
    for (int i = 0; i < DIRECTGATE_MAX_TEMPORARY_DESKTOP_SHARES; i++)
        if (strcmp(pFix->conn.temporaryDesktopShares[i].sShareId, pShareId) == 0) return i;

    return -1;
}

static int test_temporary_shares(void)
{
    fixture_t fix;
    setup(&fix);

    const char *pSecret = "owner password";
    const char *pShareSecret = "one time share code";
    CHECK(configure_srp(&fix, pSecret), "configure the owner's SRP record");

    char sShareSalt[DIRECTGATE_AUTH_SALT_HEX_SIZE];
    char sShareVerifier[DIRECTGATE_AUTH_VERIFIER_HEX_SIZE];
    CHECK(make_srp_record(pShareSecret, 0x5a, sShareSalt, sizeof(sShareSalt), sShareVerifier, sizeof(sShareVerifier)),
        "build the SRP record a temporary share is provisioned with");

    directgate_e2e_t owner;
    CHECK(srp_login(&fix, 110, pSecret, NULL, XFALSE, &owner) == 1, "the owner logs in");

    /* Shares are handed out from a desktop session only. */
    drain(&fix);
    CHECK(deliver_as(&fix, &owner, share_header("desktop-share-provision", "share-1", sShareSalt, sShareVerifier,
        600, 110), 110) == XAPI_CONTINUE, "provision outside a desktop session");
    CHECK(expect_admin(&fix, &owner, "desktop-share-result", "error", "desktop session required"),
        "a share cannot be provisioned outside a desktop session");

    directgate_session_t *pOwner = DirectGate_SessionMgr_Find(&fix.conn.mgr, 110);
    CHECK(pOwner != NULL, "the owner session exists");
    pOwner->eActiveMode = DIRECTGATE_SESSION_MODE_DESKTOP;

    /* Every malformed provision is refused the same way and stores nothing. */
    struct {
        const char *pShareId;
        const char *pSalt;
        const char *pVerifier;
        uint32_t nTtl;
        const char *pMsg;
    } bad[] = {
        { NULL, sShareSalt, sShareVerifier, 600, "a share without an id is refused" },
        { "share-x", NULL, sShareVerifier, 600, "a share without a salt is refused" },
        { "share-x", sShareSalt, NULL, 600, "a share without a verifier is refused" },
        { "share-x", sShareSalt, sShareVerifier, 299, "a share shorter than five minutes is refused" },
        { "share-x", sShareSalt, sShareVerifier, 28801, "a share longer than eight hours is refused" },
        { "share-x", "zz", sShareVerifier, 600, "a share with a salt that is not hex is refused" },
        { "share-x", sShareSalt, "00", 600, "a share with an unusable verifier is refused" }
    };

    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
    {
        CHECK(deliver_as(&fix, &owner, share_header("desktop-share-provision", bad[i].pShareId, bad[i].pSalt,
            bad[i].pVerifier, bad[i].nTtl, 110), 110) == XAPI_CONTINUE, "a malformed provision is handled");
        CHECK(expect_admin(&fix, &owner, "desktop-share-result", "error", "invalid-or-capacity"), bad[i].pMsg);
    }

    CHECK(find_share(&fix, "share-x") < 0, "a refused provision stores nothing");

    CHECK(deliver_as(&fix, &owner, share_header("desktop-share-provision", "share-1", sShareSalt, sShareVerifier,
        600, 110), 110) == XAPI_CONTINUE, "provision a share");
    CHECK(expect_admin(&fix, &owner, "desktop-share-result", "ok", NULL), "a valid share is provisioned");
    CHECK(find_share(&fix, "share-1") >= 0, "the provisioned share is held by the agent");

    /* The share code logs a viewer in once, into a desktop-only session. */
    directgate_e2e_t viewer;
    CHECK(srp_login(&fix, 120, pShareSecret, "share-1", XFALSE, &viewer) == 1, "the share code logs a viewer in");

    directgate_session_t *pViewer = DirectGate_SessionMgr_Find(&fix.conn.mgr, 120);
    CHECK(pViewer != NULL && pViewer->bAuthenticated && pViewer->bDesktopShare,
        "a share login is an authenticated temporary share session");
    CHECK(strcmp(pViewer->sDesktopShareId, "share-1") == 0, "the session remembers which share it came from");
    CHECK(pViewer->nDesktopShareExpiresMs > XTime_GetMonoMs(), "the share session carries the share's expiry");
    CHECK(keepalive_round_trip(&fix, &viewer, 120), "a share session may keep itself alive");

    CHECK(srp_login(&fix, 121, pShareSecret, "share-1", XFALSE, &viewer) == 0, "a used share code does not log in again");
    CHECK(expect_auth(&fix, "failed", "temporary desktop share is invalid or expired"),
        "a used share code is refused as invalid or expired");
    CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 121) == NULL, "a replayed share code closes its session");

    /* A share session may stop itself: that is the one command besides starting the desktop. */
    drain(&fix);
    CHECK(deliver_as(&fix, &viewer, DirectGate_Proto_BuildCmd("stop", NULL, NULL, NULL, 120), 120) == XAPI_CONTINUE,
        "a stop from a share session is handled");
    CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 120) != NULL, "a share session may send stop without being closed");

    /* Anything beyond the desktop - admin actions included - closes a share session
       at the dispatcher, before the message reaches its handler. */
    drain(&fix);
    CHECK(deliver_as(&fix, &viewer, admin_header("add-key", "AAAA", 120), 120) == XAPI_CONTINUE, "admin from a share");
    char sReason[128];
    CHECK(strcmp(take_field(&fix, &viewer, "reason", sReason, sizeof(sReason)),
        "temporary share allows desktop only") == 0, "a share session asking for an admin action is told why it is refused");
    CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 120) == NULL, "a share session asking for an admin action is closed");
    DirectGate_E2E_Clear(&viewer);

    /* A data message is allowed only when it carries desktop control or input. */
    CHECK(deliver_as(&fix, &owner, share_header("desktop-share-provision", "share-1b", sShareSalt, sShareVerifier,
        600, 110), 110) == XAPI_CONTINUE, "provision a share for the data check");
    CHECK(expect_admin(&fix, &owner, "desktop-share-result", "ok", NULL), "the share for the data check is provisioned");
    CHECK(srp_login(&fix, 122, pShareSecret, "share-1b", XFALSE, &viewer) == 1, "a viewer logs in for the data check");

    {
        xjson_obj_t *pData = DirectGate_Proto_BuildData(122);
        CHECK(pData != NULL, "build a data message");
        XJSON_AddString(pData, "payloadType", "terminal/raw");

        drain(&fix);
        CHECK(deliver_as(&fix, &viewer, pData, 122) == XAPI_CONTINUE, "terminal data from a share session is handled");
        CHECK(strcmp(take_field(&fix, &viewer, "reason", sReason, sizeof(sReason)),
            "temporary share allows desktop only") == 0, "terminal data from a share session is refused by name");
        CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 122) == NULL, "terminal data closes a share session");
    }

    DirectGate_E2E_Clear(&viewer);

    /* Of commands, a share session may start a desktop and stop; anything else,
       or a command that does not say what it is, closes it. */
    struct {
        const char *pAction;
        const char *pMode;
        const char *pMsg;
    } cmds[] = {
        { NULL, NULL, "a command without an action from a share session is refused" },
        { "start", NULL, "a start without a mode from a share session is refused" },
        { "start", "terminal", "a terminal from a share session is refused" },
        { "getcwd", NULL, "a working directory query from a share session is refused" }
    };

    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
    {
        char sShareId[32];
        snprintf(sShareId, sizeof(sShareId), "share-cmd-%zu", i);
        CHECK(deliver_as(&fix, &owner, share_header("desktop-share-provision", sShareId, sShareSalt, sShareVerifier,
            600, 110), 110) == XAPI_CONTINUE, "provision a share for the command check");
        CHECK(expect_admin(&fix, &owner, "desktop-share-result", "ok", NULL), "the share for the command check is provisioned");
        CHECK(srp_login(&fix, 124, pShareSecret, sShareId, XFALSE, &viewer) == 1, "a viewer logs in for the command check");

        drain(&fix);
        CHECK(deliver_as(&fix, &viewer, DirectGate_Proto_BuildCmd(cmds[i].pAction, NULL, NULL, cmds[i].pMode, 124), 124) ==
            XAPI_CONTINUE, "a command from a share session is handled");
        CHECK(strcmp(take_field(&fix, &viewer, "reason", sReason, sizeof(sReason)),
            "temporary share allows desktop only") == 0, cmds[i].pMsg);
        CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 124) == NULL, "a refused command closes the share session");
        DirectGate_E2E_Clear(&viewer);
    }

    /* Five wrong codes burn a share, so it cannot be brute forced. */
    CHECK(deliver_as(&fix, &owner, share_header("desktop-share-provision", "share-2", sShareSalt, sShareVerifier,
        600, 110), 110) == XAPI_CONTINUE, "provision a share to brute force");
    CHECK(expect_admin(&fix, &owner, "desktop-share-result", "ok", NULL), "the second share is provisioned");

    for (uint32_t i = 0; i < DIRECTGATE_TEMPORARY_DESKTOP_SHARE_MAX_FAILURES; i++)
    {
        CHECK(srp_login(&fix, 130 + i, pShareSecret, "share-2", XTRUE, &viewer) == 0, "a wrong share code is refused");
        CHECK(expect_auth(&fix, "failed", "invalid proof"), "a wrong share code is refused as an invalid proof");
    }

    fix.conn.mgr.nAuthFailures = 0;
    CHECK(srp_login(&fix, 140, pShareSecret, "share-2", XFALSE, &viewer) == 0,
        "the right code no longer works once a share has been guessed at too often");
    CHECK(expect_auth(&fix, "failed", "temporary desktop share is invalid or expired"),
        "a burned share is refused as invalid or expired");

    /* A share that expires between the hello and the proof is refused at the proof. */
    CHECK(deliver_as(&fix, &owner, share_header("desktop-share-provision", "share-3", sShareSalt, sShareVerifier,
        600, 110), 110) == XAPI_CONTINUE, "provision a share to expire");
    CHECK(expect_admin(&fix, &owner, "desktop-share-result", "ok", NULL), "the third share is provisioned");

    {
        directgate_srp_client_t client;
        char sAHex[2048];
        char sNonceHex[(DIRECTGATE_SRP_NONCE_SIZE * 2) + 1];
        CHECK(DirectGate_SRP_ClientInit(&client) &&
            DirectGate_SRP_ClientGenerateA(&client, sAHex, sizeof(sAHex), sNonceHex, sizeof(sNonceHex)),
            "start a share handshake");

        xjson_obj_t *pHello = DirectGate_Proto_BuildAuthHello(AGENT_DEVICE_ID, sAHex, sNonceHex, 150);
        XJSON_AddString(pHello, "desktopShareId", "share-3");
        drain(&fix);
        CHECK(deliver(&fix, pHello) == XAPI_CONTINUE, "the share hello is handled");
        directgate_pkg_t chal;
        CHECK(take_packet(&fix, &chal), "the share hello is answered with a challenge");
        const char *pSalt = XJSON_GetString(XJSON_GetObject(chal.jsonHeader.pRootObj, "salt"));
        CHECK(pSalt != NULL && strcmp(pSalt, sShareSalt) == 0, "a share challenge carries the share's salt, not the owner's");
        DirectGate_Package_Clear(&chal);

        int nSlot = find_share(&fix, "share-3");
        CHECK(nSlot >= 0, "the share is still held after its hello");
        fix.conn.temporaryDesktopShares[nSlot].nExpiresMs = 1;

        drain(&fix);
        CHECK(deliver(&fix, DirectGate_Proto_BuildAuthProof("aabb", 150)) == XAPI_CONTINUE, "the late proof is handled");
        CHECK(expect_auth(&fix, "failed", "temporary desktop share is invalid or expired"),
            "a share that expired after its hello is refused at the proof");
        CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 150) == NULL, "a proof for an expired share closes the session");
        DirectGate_SRP_ClientCleanse(&client);
    }

    /* Revoking a share closes the sessions it opened. */
    CHECK(deliver_as(&fix, &owner, share_header("desktop-share-provision", "share-4", sShareSalt, sShareVerifier,
        600, 110), 110) == XAPI_CONTINUE, "provision a share to revoke");
    CHECK(expect_admin(&fix, &owner, "desktop-share-result", "ok", NULL), "the fourth share is provisioned");
    CHECK(srp_login(&fix, 160, pShareSecret, "share-4", XFALSE, &viewer) == 1, "a viewer logs in with the fourth share");
    CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 160) != NULL, "the viewer session is open");

    drain(&fix);
    CHECK(deliver_as(&fix, &owner, share_header("desktop-share-revoke", NULL, NULL, NULL, 0, 110), 110) ==
        XAPI_CONTINUE, "a revoke without an id is handled");
    CHECK(expect_admin(&fix, &owner, "desktop-share-result", "error", "invalid-share-id"),
        "a revoke without a share id is refused by name");

    CHECK(deliver_as(&fix, &owner, share_header("desktop-share-revoke", "share-4", NULL, NULL, 0, 110), 110) ==
        XAPI_CONTINUE, "a revoke is handled");
    CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 160) == NULL, "revoking a share closes the session it opened");
    CHECK(find_share(&fix, "share-4") < 0, "a revoked share is forgotten");
    DirectGate_E2E_Clear(&viewer);

    /* The agent holds a bounded number of shares. */
    drain(&fix);
    for (int i = 0; i < DIRECTGATE_MAX_TEMPORARY_DESKTOP_SHARES; i++)
    {
        char sId[32];
        snprintf(sId, sizeof(sId), "fill-%d", i);
        CHECK(deliver_as(&fix, &owner, share_header("desktop-share-provision", sId, sShareSalt, sShareVerifier,
            600, 110), 110) == XAPI_CONTINUE, "fill the share table");
        drain(&fix);
    }

    CHECK(deliver_as(&fix, &owner, share_header("desktop-share-provision", "one-too-many", sShareSalt, sShareVerifier,
        600, 110), 110) == XAPI_CONTINUE, "provision past capacity");
    CHECK(expect_admin(&fix, &owner, "desktop-share-result", "error", "invalid-or-capacity"),
        "a share past the table's capacity is refused");

    /* Provisioning an id that already exists replaces it instead of taking a new slot. */
    CHECK(deliver_as(&fix, &owner, share_header("desktop-share-provision", "fill-0", sShareSalt, sShareVerifier,
        900, 110), 110) == XAPI_CONTINUE, "reprovision an existing share");
    CHECK(expect_admin(&fix, &owner, "desktop-share-result", "ok", NULL), "an existing share id can be provisioned again");

    DirectGate_E2E_Clear(&owner);
    teardown(&fix);
    return 0;
}

/* The type of the one answer queued, or "" when nothing was answered. */
static const char* answer_type(fixture_t *pFix, directgate_e2e_t *pPeer, char *pOut, size_t nOutSize)
{
    return take_field(pFix, pPeer, "type", pOut, nOutSize);
}

static xjson_obj_t* webrtc_header(const char *pAction, const char *pField, const char *pValue, uint32_t nSessionId)
{
    xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("webrtc", nSessionId);
    if (pHeader == NULL) return NULL;

    if (pAction != NULL) XJSON_AddString(pHeader, "action", pAction);
    if (pField != NULL) XJSON_AddString(pHeader, pField, pValue);
    return pHeader;
}

static xjson_obj_t* data_header(const char *pPayloadType, uint32_t nSessionId)
{
    xjson_obj_t *pHeader = DirectGate_Proto_BuildData(nSessionId);
    if (pHeader != NULL && pPayloadType != NULL) XJSON_AddString(pHeader, "payloadType", pPayloadType);
    return pHeader;
}

/* Everything the dispatcher can be handed that is not a well-formed request for
 * a running feature. Each is dropped or answered, never acted on, and none of
 * them costs the session: a keepalive still round-trips after every one. */
static int test_dispatch_corners(void)
{
    fixture_t fix;
    setup(&fix);

    const char *pSecret = "dispatch secret";
    char sType[64];
    CHECK(configure_srp(&fix, pSecret), "configure the SRP record");

    directgate_e2e_t peer;
    CHECK(srp_login(&fix, 130, pSecret, NULL, XFALSE, &peer) == 1, "log in a session to send oddities on");
    directgate_session_t *pSession = DirectGate_SessionMgr_Find(&fix.conn.mgr, 130);
    CHECK(pSession != NULL, "the session exists");

    /* Sealed messages the agent cannot open, for three different reasons. */
    CHECK(deliver_as(&fix, &peer, DirectGate_Proto_BuildKeepalive("ping", 999), 999) == XAPI_CONTINUE && no_answer(&fix),
        "a sealed message for a session that does not exist is dropped");

    directgate_e2e_t stranger;
    uint8_t otherKey[32], nonceA[DIRECTGATE_SRP_NONCE_SIZE], nonceB[DIRECTGATE_SRP_NONCE_SIZE];
    memset(otherKey, 0x11, sizeof(otherKey));
    memset(nonceA, 0x22, sizeof(nonceA));
    memset(nonceB, 0x33, sizeof(nonceB));
    DirectGate_E2E_Init(&stranger);
    CHECK(DirectGate_E2E_DeriveFromSRP(&stranger, otherKey, sizeof(otherKey), nonceA, nonceB, sizeof(nonceA),
        AGENT_DEVICE_ID, XFALSE), "derive keys nobody agreed on");
    CHECK(deliver_as(&fix, &stranger, DirectGate_Proto_BuildKeepalive("ping", 130), 130) == XAPI_CONTINUE && no_answer(&fix),
        "a message sealed under the wrong keys is dropped");
    DirectGate_E2E_Clear(&stranger);

    CHECK(deliver_as(&fix, &peer, DirectGate_Proto_NewHeader("bogus", 130), 130) == XAPI_CONTINUE && no_answer(&fix),
        "a sealed message whose inside is no known message is dropped");
    CHECK(keepalive_round_trip(&fix, &peer, 130), "the session survives messages it could not open");

    /* Keepalives that say nothing, and the answer to one the agent sent. */
    CHECK(deliver_as(&fix, &peer, DirectGate_Proto_BuildKeepalive(NULL, 130), 130) == XAPI_CONTINUE && no_answer(&fix),
        "a keepalive without an action is ignored");
    pSession->nLastKAPongMs = 0;
    CHECK(deliver_as(&fix, &peer, DirectGate_Proto_BuildKeepalive("pong", 130), 130) == XAPI_CONTINUE && no_answer(&fix),
        "a pong is taken without an answer");
    CHECK(pSession->nLastKAPongMs > 0, "a pong is recorded as proof the peer is alive");
    CHECK(deliver_as(&fix, &peer, DirectGate_Proto_BuildKeepalive("nap", 130), 130) == XAPI_CONTINUE && no_answer(&fix),
        "an unknown keepalive action is ignored");

    /* Commands that ask for nothing, or for something that is not there. */
    CHECK(deliver_as(&fix, &peer, DirectGate_Proto_BuildCmd(NULL, NULL, NULL, NULL, 130), 130) == XAPI_CONTINUE &&
        no_answer(&fix), "a command without an action is ignored");
    CHECK(deliver_as(&fix, &peer, DirectGate_Proto_BuildCmd("start", NULL, NULL, NULL, 130), 130) == XAPI_CONTINUE &&
        no_answer(&fix), "a start without a mode starts nothing");
    CHECK(pSession->eActiveMode == DIRECTGATE_SESSION_MODE_NONE, "a start without a mode leaves the session idle");
    CHECK(deliver_as(&fix, &peer, DirectGate_Proto_BuildCmd("getcwd", NULL, NULL, NULL, 130), 130) == XAPI_CONTINUE &&
        no_answer(&fix), "a working directory query without a shell is not answered");
    CHECK(deliver_as(&fix, &peer, DirectGate_Proto_BuildCmd("reboot", NULL, NULL, NULL, 130), 130) == XAPI_CONTINUE &&
        no_answer(&fix), "an unknown command does nothing");

    /* Terminal input with no terminal: refused before a shell is started, dropped after one is gone. */
    CHECK(deliver_payload_as(&fix, &peer, data_header(NULL, 130), "ls\n", 130) == XAPI_CONTINUE, "type into no terminal");
    CHECK(strcmp(answer_type(&fix, &peer, sType, sizeof(sType)), "error") == 0,
        "input for a terminal that was never started is refused out loud");

    pSession->eActiveMode = DIRECTGATE_SESSION_MODE_TERMINAL;
    CHECK(deliver_payload_as(&fix, &peer, data_header(NULL, 130), "ls\n", 130) == XAPI_CONTINUE && no_answer(&fix),
        "input for a shell that is no longer running is dropped");
    CHECK(deliver_payload_as(&fix, &peer, data_header(NULL, 130), NULL, 130) == XAPI_CONTINUE && no_answer(&fix),
        "an empty data message is nothing to write");
    pSession->eActiveMode = DIRECTGATE_SESSION_MODE_NONE;

    /* Desktop traffic for a session that is not sharing a desktop is answered with why. */
    CHECK(deliver_payload_as(&fix, &peer, data_header("desktop-input/json", 130), "{}", 130) == XAPI_CONTINUE,
        "send desktop input to a terminal session");
    CHECK(strcmp(answer_type(&fix, &peer, sType, sizeof(sType)), "error") == 0,
        "desktop input outside a desktop session is refused out loud");

    /* A desktop session takes its two payload types and nothing else. No desktop
       is actually running here, so each must be absorbed without one. */
    pSession->eActiveMode = DIRECTGATE_SESSION_MODE_DESKTOP;
    CHECK(deliver_payload_as(&fix, &peer, data_header(NULL, 130), "{}", 130) == XAPI_CONTINUE && no_answer(&fix),
        "desktop data without a payload type is ignored");
    CHECK(deliver_payload_as(&fix, &peer, data_header("desktop-audio/opus", 130), "xx", 130) == XAPI_CONTINUE &&
        no_answer(&fix), "a desktop payload type the agent does not take is ignored");
    CHECK(deliver_payload_as(&fix, &peer, data_header("desktop-input/json", 130), "{\"action\":\"pointer\"}", 130) >= 0,
        "desktop input without a running desktop is absorbed");
    CHECK(deliver_payload_as(&fix, &peer, data_header("desktop-control/json", 130), "{\"action\":\"none\"}", 130) >= 0,
        "a desktop control message without a running desktop is absorbed");
    CHECK(deliver_payload_as(&fix, &peer, data_header("desktop-control/json", 130), "not json", 130) >= 0,
        "a desktop control message that is not JSON is absorbed");
    pSession->eActiveMode = DIRECTGATE_SESSION_MODE_NONE;
    CHECK(keepalive_round_trip(&fix, &peer, 130), "the session survives desktop traffic it had no desktop for");

    /* WebRTC signalling the agent cannot use. The configured ICE servers are
       handed to the peer connection with the first signalling message. */
    xstrncpy(fix.cfg.sIceServers[0], sizeof(fix.cfg.sIceServers[0]), "stun:127.0.0.1:3478");
    fix.cfg.nIceSrvCount = 1;
    CHECK(deliver_as(&fix, &peer, webrtc_header(NULL, NULL, NULL, 130), 130) == XAPI_CONTINUE && no_answer(&fix),
        "signalling without an action is ignored");
    CHECK(deliver_as(&fix, &peer, webrtc_header("offer", NULL, NULL, 130), 130) == XAPI_CONTINUE && no_answer(&fix),
        "an offer without a description is ignored");
    CHECK(pSession->webrtc.signalCb != NULL && pSession->webrtc.dataCb != NULL,
        "the first signalling message wires the peer connection's callbacks to the session");
    CHECK(deliver_as(&fix, &peer, webrtc_header("offer", "sdp", "v=0\r\nnot a session description\r\n", 130), 130) ==
        XAPI_CONTINUE, "an offer that is not a session description is survived");
    CHECK(deliver_as(&fix, &peer, webrtc_header("migration-commit", NULL, NULL, 130), 130) == XAPI_CONTINUE &&
        no_answer(&fix), "a migration commit with nothing pending changes nothing");
    CHECK(deliver_as(&fix, &peer, webrtc_header("ice", "candidate", "candidate:1 1 UDP 1 127.0.0.1 9 typ host", 130), 130) ==
        XAPI_CONTINUE && no_answer(&fix), "a candidate for a connection that does not exist is dropped");
    CHECK(deliver_as(&fix, &peer, webrtc_header("ice", NULL, NULL, 130), 130) == XAPI_CONTINUE && no_answer(&fix),
        "a candidate message without a candidate is dropped");
    CHECK(deliver_as(&fix, &peer, webrtc_header("renegotiate", NULL, NULL, 130), 130) == XAPI_CONTINUE && no_answer(&fix),
        "an unknown signalling action is dropped");

    /* What the peer connection hands back: signalling goes out sealed on the relay,
       data channel messages come in through the same dispatcher as relay traffic. */
    drain(&fix);
    pSession->webrtc.signalCb("{not json", 9, pSession->webrtc.pSignalCtx);
    CHECK(no_answer(&fix), "signalling the agent produced but cannot parse is not sent");
    pSession->webrtc.signalCb(NULL, 0, pSession->webrtc.pSignalCtx);
    CHECK(no_answer(&fix), "no signalling is nothing to send");

    const char *pAnswer = "{\"type\":\"webrtc\",\"version\":1,\"sessionId\":130,\"action\":\"answer\",\"sdp\":\"v=0\"}";
    pSession->webrtc.signalCb(pAnswer, strlen(pAnswer), pSession->webrtc.pSignalCtx);
    CHECK(strcmp(answer_type(&fix, &peer, sType, sizeof(sType)), "webrtc") == 0,
        "signalling from the peer connection reaches the browser, sealed");

    xbyte_buffer_t packet;
    XByteBuffer_Init(&packet, XSTDNON, XFALSE);
    xjson_obj_t *pPing = DirectGate_Proto_BuildKeepalive("ping", 130);
    CHECK(pPing != NULL && DirectGate_Proto_AddCC(pPing, &peer, 0) &&
        DirectGate_Proto_Build(&packet, pPing, NULL, 0, XFALSE) &&
        DirectGate_Proto_EncryptPackage(&packet, &peer, 130), "seal a ping as the data channel carries it");
    XJSON_FreeObject(pPing);

    drain(&fix);
    pSession->webrtc.dataCb(NULL, 0, pSession->webrtc.pDataCtx);
    CHECK(no_answer(&fix), "an empty data channel message is nothing");

    xapi_session_t *pBound = pSession->pWsSession;
    pSession->pWsSession = NULL;
    pSession->webrtc.dataCb(packet.pData, packet.nUsed, pSession->webrtc.pDataCtx);
    CHECK(no_answer(&fix), "data channel traffic for a session with no relay binding is dropped");
    pSession->pWsSession = pBound;

    pSession->webrtc.dataCb(packet.pData, packet.nUsed, pSession->webrtc.pDataCtx);
    CHECK(strcmp(take_field(&fix, &peer, "action", sType, sizeof(sType)), "pong") == 0,
        "a ping over the data channel is answered like one over the relay");
    XByteBuffer_Clear(&packet);

    CHECK(keepalive_round_trip(&fix, &peer, 130), "the session is still whole after every oddity");

    /* Stopping a desktop session ends the session, not just the mode. */
    pSession->eActiveMode = DIRECTGATE_SESSION_MODE_DESKTOP;
    CHECK(deliver_as(&fix, &peer, DirectGate_Proto_BuildCmd("stop", NULL, NULL, NULL, 130), 130) == XAPI_CONTINUE,
        "stop a desktop session");
    CHECK(DirectGate_SessionMgr_Find(&fix.conn.mgr, 130) == NULL, "stopping a desktop session closes it");

    /* A stop for a session that is already gone is nothing. */
    CHECK(deliver(&fix, DirectGate_Proto_BuildCmd("stop", NULL, NULL, NULL, 130)) == XAPI_CONTINUE,
        "a stop for a closed session is handled");

    DirectGate_E2E_Clear(&peer);
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
    if (test_srp_login()) return 1;
    if (test_key_auth_login()) return 1;
    if (test_admin_actions()) return 1;
    if (test_temporary_shares()) return 1;
    if (test_dispatch_corners()) return 1;

    /* The dispatch test started a peer connection; its transport threads go with it. */
    DirectGate_WebRTC_Cleanup();
    puts("auth_flow_smoke: OK");
    return 0;
}
