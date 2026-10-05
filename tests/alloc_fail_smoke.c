/* Every allocation failure on the paths each message takes: parsing a packet, building one, encrypting,
 * decrypting with the replay check, and framing it for the relay.
 *
 * malloc, calloc, realloc, free and strdup are wrapped by the linker (agent and libxutils code only; OpenSSL and
 * libstdc++ are shared libraries and keep their own allocator). Each scenario runs once to count its allocations,
 * then once per allocation with exactly that one failing. After every run:
 *   - the call reported failure, or what it reported as success is complete and correct,
 *   - everything allocated while it ran was released again, descriptors included.
 * Logging stays on, into a callback that drops the text, so the error paths format their messages too. */

#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "src/common/e2e.h"
#include "src/common/keyauth.h"
#include "src/common/protocol.h"
#include "src/common/srp.h"
#include "src/common/transfer.h"
#include "src/common/websock.h"
#include "src/client/login.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "alloc_fail_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

/* ---------------- the injecting allocator ---------------- */

static volatile long g_nCount;
static volatile long g_nFailAt = -1;
static volatile long g_nLive;
static volatile int g_bArmed;

void *__real_malloc(size_t nSize);
void *__real_calloc(size_t nCount, size_t nSize);
void *__real_realloc(void *pPtr, size_t nSize);
void __real_free(void *pPtr);
char *__real_strdup(const char *pStr);

static int fail_now(void)
{
    return g_bArmed && ++g_nCount == g_nFailAt;
}

void *__wrap_malloc(size_t nSize)
{
    if (fail_now()) return NULL;
    void *p = __real_malloc(nSize);
    if (p != NULL && g_bArmed) g_nLive++;
    return p;
}

void *__wrap_calloc(size_t nCount, size_t nSize)
{
    if (fail_now()) return NULL;
    void *p = __real_calloc(nCount, nSize);
    if (p != NULL && g_bArmed) g_nLive++;
    return p;
}

void *__wrap_realloc(void *pPtr, size_t nSize)
{
    if (fail_now()) return NULL;
    void *p = __real_realloc(pPtr, nSize);
    if (!g_bArmed) return p;

    if (p != NULL && pPtr == NULL) g_nLive++;
    else if (p == NULL && nSize == 0 && pPtr != NULL) g_nLive--;
    return p;
}

void __wrap_free(void *pPtr)
{
    if (pPtr != NULL && g_bArmed) g_nLive--;
    __real_free(pPtr);
}

char *__wrap_strdup(const char *pStr)
{
    if (fail_now()) return NULL;
    char *p = __real_strdup(pStr);
    if (p != NULL && g_bArmed) g_nLive++;
    return p;
}

static void arm(long nFailAt)
{
    g_nCount = 0;
    g_nLive = 0;
    g_nFailAt = nFailAt;
    g_bArmed = 1;
}

static void disarm(void)
{
    g_bArmed = 0;
    g_nFailAt = -1;
}

static int drop_log(const char *pLog, size_t nLength, xlog_flag_t eFlag, void *pCtx)
{
    (void)pLog; (void)nLength; (void)eFlag; (void)pCtx;
    return 0;
}

/* ---------------- fixtures, built before anything is armed ---------------- */

#define SESSION_ID 42U

static directgate_e2e_t g_agent, g_client;
static xbyte_buffer_t g_dataPacket, g_filePacket, g_innerFlat, g_innerNested, g_encrypted;
static uint8_t g_payload[3000];
static char g_sSource[64] = "/tmp/directgate_allocfail_src.XXXXXX";
static char g_sDest[sizeof(g_sSource) + 8];
static uint8_t g_fileData[70000];
static directgate_client_key_t g_clientKey;
static uint8_t g_agentPub[DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE], g_agentSeed[DIRECTGATE_KEYAUTH_ED25519_SEED_SIZE];
static char g_sAgentPubB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
static char g_sKeyPath[sizeof(g_sSource) + 16];
static char g_sAccountPath[sizeof(g_sSource) + 16];
static char g_sAccountBefore[4096];
static size_t g_nAccountBefore;
static uint8_t g_srpSalt[32];
static char g_sSrpSaltHex[sizeof(g_srpSalt) * 2 + 1];
static char g_sVerifierHex[1024];

static int build_fixed(xbyte_buffer_t *pOut, xjson_obj_t *pHeader, const uint8_t *pPayload, size_t nPayload)
{
    XByteBuffer_Init(pOut, 0, XFALSE);
    CHECK(pHeader != NULL, "build a fixture header");
    xbool_t bOk = DirectGate_Proto_Build(pOut, pHeader, pPayload, nPayload, XFALSE);
    XJSON_FreeObject(pHeader);
    CHECK(bOk, "serialize a fixture packet");
    return 0;
}

static int build_raw(xbyte_buffer_t *pOut, const char *pHeader, const uint8_t *pPayload, size_t nPayload)
{
    uint32_t nLength = (uint32_t)strlen(pHeader);
    uint8_t preamble[4] = { (uint8_t)nLength, (uint8_t)(nLength >> 8), (uint8_t)(nLength >> 16), (uint8_t)(nLength >> 24) };

    XByteBuffer_Init(pOut, 0, XFALSE);
    CHECK(XByteBuffer_Add(pOut, preamble, sizeof(preamble)) > 0, "add a preamble");
    CHECK(XByteBuffer_Add(pOut, (const uint8_t*)pHeader, nLength) > 0, "add a header");
    if (nPayload) CHECK(XByteBuffer_Add(pOut, pPayload, nPayload) > 0, "add a payload");
    return 0;
}

static size_t read_file(const char *pPath, char *pOut, size_t nSize)
{
    FILE *pFile = fopen(pPath, "rb");
    if (pFile == NULL) return 0;
    size_t nRead = fread(pOut, 1, nSize - 1, pFile);
    fclose(pFile);
    pOut[nRead] = '\0';
    return nRead;
}

static void fill_account(directgate_account_t *pAccount, const char *pAccess)
{
    memset(pAccount, 0, sizeof(*pAccount));
    xstrncpy(pAccount->sAccessToken, sizeof(pAccount->sAccessToken), pAccess);
    xstrncpy(pAccount->sRefreshToken, sizeof(pAccount->sRefreshToken), "refresh-token");
    xstrncpy(pAccount->sEmail, sizeof(pAccount->sEmail), "user@example.test");
    xstrncpy(pAccount->sUserId, sizeof(pAccount->sUserId), "user-1");
    pAccount->nExpiresAt = 1900000000ULL;
}

static int setup(void)
{
    uint8_t sKey[32], agentNonce[32], clientNonce[32];
    memset(sKey, 0x5c, sizeof(sKey));
    memset(agentNonce, 0x11, sizeof(agentNonce));
    memset(clientNonce, 0x22, sizeof(clientNonce));
    for (size_t i = 0; i < sizeof(g_payload); i++) g_payload[i] = (uint8_t)(i * 7 + 3);

    DirectGate_E2E_Init(&g_agent);
    DirectGate_E2E_Init(&g_client);
    CHECK(DirectGate_E2E_DeriveFromSRP(&g_agent, sKey, sizeof(sKey), agentNonce, clientNonce, 32, "dev", XTRUE) &&
          DirectGate_E2E_DeriveFromSRP(&g_client, sKey, sizeof(sKey), agentNonce, clientNonce, 32, "dev", XFALSE),
          "derive the session keys");

    if (build_fixed(&g_dataPacket, DirectGate_Proto_BuildData(SESSION_ID), g_payload, sizeof(g_payload))) return 1;

    xjson_obj_t *pFile = DirectGate_Proto_NewHeader("file", SESSION_ID);
    CHECK(pFile != NULL, "build a file header");
    XJSON_AddString(pFile, "action", "chunk");
    XJSON_AddString(pFile, "transferId", "transfer-1");
    XJSON_AddString(pFile, "name", "report.pdf");
    XJSON_AddU32(pFile, "index", 3);
    XJSON_AddString(pFile, "size", "123456789012");
    if (build_fixed(&g_filePacket, pFile, g_payload, 512)) return 1;

    /* The inner package a client sends, flat (read in place) and with a nested member (parsed) */
    if (build_raw(&g_innerFlat, "{\"type\":\"data\",\"version\":1,\"sessionId\":42,\"ccScope\":\"session\",\"ce\":0,"
        "\"sc\":1,\"cc\":1,\"payloadSize\":64}", g_payload, 64)) return 1;
    if (build_raw(&g_innerNested, "{\"type\":\"data\",\"meta\":{\"k\":[1,2]},\"sessionId\":42,\"ccScope\":\"input\","
        "\"ce\":0,\"sc\":1,\"cc\":2,\"payloadSize\":64}", g_payload, 64)) return 1;

    /* What arrives from the client: the flat inner package, encrypted under the client's keys */
    XByteBuffer_Init(&g_encrypted, 0, XFALSE);
    CHECK(XByteBuffer_Add(&g_encrypted, g_innerFlat.pData, g_innerFlat.nUsed) > 0, "copy the inner package");
    CHECK(DirectGate_Proto_EncryptPackage(&g_encrypted, &g_client, SESSION_ID), "encrypt the inbound fixture");

    for (size_t i = 0; i < sizeof(g_fileData); i++) g_fileData[i] = (uint8_t)(i * 13 + 5);
    int nFd = mkstemp(g_sSource);
    CHECK(nFd >= 0, "create the source file");
    CHECK(write(nFd, g_fileData, sizeof(g_fileData)) == (ssize_t)sizeof(g_fileData), "write the source file");
    close(nFd);
    snprintf(g_sDest, sizeof(g_sDest), "%s.dst", g_sSource);
    snprintf(g_sKeyPath, sizeof(g_sKeyPath), "%s.key/client.json", g_sSource);
    snprintf(g_sAccountPath, sizeof(g_sAccountPath), "%s.account", g_sSource);

    directgate_account_t account;
    fill_account(&account, "access-old");
    CHECK(DirectGate_Account_Save(&account, g_sAccountPath), "save the account as it was");
    g_nAccountBefore = read_file(g_sAccountPath, g_sAccountBefore, sizeof(g_sAccountBefore));
    CHECK(g_nAccountBefore > 0 && strstr(g_sAccountBefore, "access-old") != NULL, "read the account as it was");

    for (size_t i = 0; i < sizeof(g_srpSalt); i++) g_srpSalt[i] = (uint8_t)(i * 11 + 1);
    for (size_t i = 0; i < sizeof(g_srpSalt); i++) snprintf(&g_sSrpSaltHex[i * 2], 3, "%02x", g_srpSalt[i]);
    CHECK(DirectGate_SRP_CreateVerifier("correct horse battery staple", g_srpSalt, sizeof(g_srpSalt),
        g_sVerifierHex, sizeof(g_sVerifierHex)), "create the SRP verifier");

    CHECK(DirectGate_KeyAuth_KeyGenerate(&g_clientKey), "generate the client key");
    CHECK(DirectGate_KeyAuth_Ed25519Generate(g_agentPub, g_agentSeed), "generate the agent identity");
    CHECK(DirectGate_KeyAuth_Base64Encode(g_agentPub, sizeof(g_agentPub), g_sAgentPubB64, sizeof(g_sAgentPubB64)),
        "encode the agent identity");
    return 0;
}

static void teardown(void)
{
    unlink(g_sKeyPath);
    unlink(g_sAccountPath);
    char sKeyDir[sizeof(g_sKeyPath)];
    snprintf(sKeyDir, sizeof(sKeyDir), "%s.key", g_sSource);
    rmdir(sKeyDir);
    unlink(g_sSource);
    unlink(g_sDest);
    DirectGate_KeyAuth_KeyCleanse(&g_clientKey);
    XByteBuffer_Clear(&g_dataPacket);
    XByteBuffer_Clear(&g_filePacket);
    XByteBuffer_Clear(&g_innerFlat);
    XByteBuffer_Clear(&g_innerNested);
    XByteBuffer_Clear(&g_encrypted);
    DirectGate_E2E_Clear(&g_agent);
    DirectGate_E2E_Clear(&g_client);
}

/* ---------------- the scenarios ---------------- */

/* Each returns non-zero only when a call reported success for something it did not deliver. A failed
   allocation turning into an error return is the expected outcome. */

static int scn_parse_data(void)
{
    directgate_pkg_t pkg;
    if (!DirectGate_Package_Parse(&pkg, g_dataPacket.pData, g_dataPacket.nUsed)) return 0;

    const directgate_pkg_data_t *pData = (const directgate_pkg_data_t*)pkg.pPackage;
    int nBad = pkg.header.eType != DIRECTGATE_PKG_DATA || pkg.header.nSessionId != SESSION_ID || pData == NULL ||
               pData->nPayloadLength != sizeof(g_payload) || memcmp(pData->pPayload, g_payload, sizeof(g_payload));

    DirectGate_Package_Clear(&pkg);
    return nBad;
}

static int scn_parse_file(void)
{
    directgate_pkg_t pkg;
    if (!DirectGate_Package_Parse(&pkg, g_filePacket.pData, g_filePacket.nUsed)) return 0;

    const directgate_pkg_file_t *pFile = (const directgate_pkg_file_t*)pkg.pPackage;
    int nBad = pFile == NULL || pFile->transfer.nChunkIndex != 3 || pFile->transfer.nFileSize != 123456789012ULL ||
               strcmp(pFile->transfer.pTransferId, "transfer-1") || pFile->data.nPayloadLength != 512;

    DirectGate_Package_Clear(&pkg);
    return nBad;
}

static int scn_parse_route(void)
{
    directgate_pkg_t pkg;
    if (!DirectGate_Package_ParseRoute(&pkg, g_encrypted.pData, g_encrypted.nUsed)) return 1;
    int nBad = pkg.header.eType != DIRECTGATE_PKG_ENCRYPTED || pkg.header.nSessionId != SESSION_ID;
    DirectGate_Package_Clear(&pkg);
    return nBad;
}

/* Whatever Build reports as built has to be the whole packet: it is handed straight to a socket */
static xbyte_buffer_t g_built;

static int scn_build(void)
{
    directgate_e2e_t tx = g_agent;
    xjson_obj_t *pHeader = DirectGate_Proto_BuildData(SESSION_ID);
    if (pHeader == NULL) return 0;

    xbool_t bBuilt = DirectGate_Proto_AddCC(pHeader, &tx, 0) &&
                     DirectGate_Proto_Build(&g_built, pHeader, g_payload, sizeof(g_payload), XFALSE);
    XJSON_FreeObject(pHeader);

    if (bBuilt && g_built.nUsed < sizeof(g_payload) + DIRECTGATE_PROTO_PREAMBLE_SIZE)
    {
        fprintf(stderr, "alloc_fail_smoke: Build reported success for a %zu byte packet\n", g_built.nUsed);
        return 1;
    }

    XByteBuffer_Clear(&g_built);
    return 0;
}

static xbyte_buffer_t g_sealed;

static int scn_encrypt(void)
{
    XByteBuffer_Reset(&g_sealed);
    if (XByteBuffer_Add(&g_sealed, g_innerFlat.pData, g_innerFlat.nUsed) <= 0) { XByteBuffer_Clear(&g_sealed); return 0; }

    xbool_t bSealed = DirectGate_Proto_EncryptPackage(&g_sealed, &g_agent, SESSION_ID);
    int nBad = 0;

    if (bSealed)
    {
        /* Checked with nothing armed: the packet has to parse and open to the inner package */
        long nSaved = g_nFailAt;
        int bWasArmed = g_bArmed;
        g_bArmed = 0;

        directgate_pkg_t pkg;
        size_t nOpened = 0;
        uint8_t *pOpened = NULL;

        if (!DirectGate_Package_Parse(&pkg, g_sealed.pData, g_sealed.nUsed)) nBad = 1;
        else
        {
            const directgate_pkg_data_t *pData = (const directgate_pkg_data_t*)pkg.pPackage;
            pOpened = DirectGate_E2E_Decrypt(&g_client, pData->pPayload, pData->nPayloadLength, &nOpened);
            nBad = pOpened == NULL || nOpened != g_innerFlat.nUsed || memcmp(pOpened, g_innerFlat.pData, nOpened);
            free(pOpened);
            DirectGate_Package_Clear(&pkg);
        }

        if (nBad) fprintf(stderr, "alloc_fail_smoke: EncryptPackage reported success for a broken packet\n");
        g_bArmed = bWasArmed;
        g_nFailAt = nSaved;
    }

    XByteBuffer_Clear(&g_sealed);
    return nBad;
}

static int scn_decrypt(void)
{
    /* The outer header is parsed first, as the agent does, then the payload is opened and its counters checked */
    directgate_e2e_t rx = g_agent;
    directgate_pkg_t pkg;
    if (!DirectGate_Package_Parse(&pkg, g_encrypted.pData, g_encrypted.nUsed)) return 0;

    xbyte_buffer_t inner;
    XByteBuffer_Init(&inner, 0, XFALSE);
    xbool_t bOpened = DirectGate_Proto_DecryptPackage(&inner, &pkg, &rx);

    int nBad = 0;
    if (bOpened) nBad = inner.nUsed != g_innerFlat.nUsed || memcmp(inner.pData, g_innerFlat.pData, inner.nUsed) ||
                        rx.rxSessionWindow.nHighest != 1 || rx.rxWindow.nHighest != 1;
    else nBad = rx.rxSessionWindow.nHighest != 0 || rx.rxWindow.nHighest != 0;

    if (nBad) fprintf(stderr, "alloc_fail_smoke: DecryptPackage(%d) left inner(%zu) and windows(%u/%u)\n",
        bOpened, inner.nUsed, rx.rxSessionWindow.nHighest, rx.rxWindow.nHighest);

    XByteBuffer_Clear(&inner);
    DirectGate_Package_Clear(&pkg);
    return nBad;
}

/* A header the scan refuses goes through the parser: a parse that fails for memory drops the packet, and
   leaves the windows as they were */
static int scn_checkcc_parsed(void)
{
    directgate_e2e_t rx = g_agent;
    xbool_t bAccepted = DirectGate_Proto_CheckCC(&g_innerNested, &rx);

    if (bAccepted) return rx.rxInputWindow.nHighest != 1 || rx.rxWindow.nHighest != 2;
    return rx.rxInputWindow.nHighest != 0 || rx.rxWindow.nHighest != 0;
}

static int scn_ws_send(void)
{
    xapi_session_t session;
    memset(&session, 0, sizeof(session));
    session.eRole = XAPI_CLIENT;
    session.sock.nFD = XSOCK_INVALID;
    session.nEvents = XPOLLOUT;     /* Already waiting to write: no event loop is needed to queue a frame */
    XByteBuffer_Init(&session.txBuffer, 0, XFALSE);

    /* Two frames, so the second one grows a buffer that already holds the first */
    int nFirst = DirectGate_WebSock_Send(&session, g_payload, 100);
    size_t nAfterFirst = session.txBuffer.nUsed;
    int nSecond = nFirst == XAPI_CONTINUE ? DirectGate_WebSock_Send(&session, g_payload, sizeof(g_payload)) : nFirst;

    /* A frame that could not be added is not half there: the buffer holds whole frames only */
    int nBad = (nFirst == XAPI_CONTINUE && nAfterFirst != 100 + 2 + 4) ||
               (nSecond == XAPI_CONTINUE && session.txBuffer.nUsed != nAfterFirst + sizeof(g_payload) + 4 + 4) ||
               (nSecond != XAPI_CONTINUE && nFirst == XAPI_CONTINUE && session.txBuffer.nUsed != nAfterFirst);

    XByteBuffer_Clear(&session.txBuffer);
    return nBad;
}

/* A whole file transfer, end to end: what the sender hands its callback is built into a packet, parsed and
   given to the receiver. Whatever both ends report as done has to have delivered the file byte for byte. */

typedef struct {
    directgate_transfer_t *pRx;
    int nStatus;
} transfer_link_t;

static int ack_sink(xjson_obj_t *pHeader, const uint8_t *pPayload, size_t nLen, void *pCtx)
{
    (void)pHeader; (void)pPayload; (void)nLen; (void)pCtx;
    return XSTDOK;
}

static int deliver(xjson_obj_t *pHeader, const uint8_t *pPayload, size_t nLen, void *pCtx)
{
    transfer_link_t *pLink = (transfer_link_t*)pCtx;
    xbyte_buffer_t wire;
    XByteBuffer_Init(&wire, 0, XFALSE);

    directgate_pkg_t pkg;
    if (!DirectGate_Proto_Build(&wire, pHeader, pPayload, nLen, XFALSE) ||
        !DirectGate_Package_Parse(&pkg, wire.pData, wire.nUsed))
    {
        XByteBuffer_Clear(&wire);
        return XSTDERR;
    }

    const directgate_pkg_file_t *pFile = (const directgate_pkg_file_t*)pkg.pPackage;
    int nStatus = XSTDERR;

    if (!strcmp(pFile->pAction, "start")) nStatus = DirectGate_Transfer_HandleStartPath(pLink->pRx, &pkg, g_sDest);
    else if (!strcmp(pFile->pAction, "chunk")) nStatus = DirectGate_Transfer_HandleChunk(pLink->pRx, &pkg);
    else if (!strcmp(pFile->pAction, "end")) nStatus = DirectGate_Transfer_HandleEnd(pLink->pRx, &pkg, ack_sink, NULL);

    DirectGate_Package_Clear(&pkg);
    XByteBuffer_Clear(&wire);
    if (nStatus < 0) pLink->nStatus = nStatus;
    return nStatus;
}

static int scn_transfer(void)
{
    directgate_transfer_t tx, rx;
    DirectGate_Transfer_Init(&tx);
    DirectGate_Transfer_Init(&rx);
    unlink(g_sDest);

    transfer_link_t link = { &rx, XSTDOK };
    if (DirectGate_Transfer_Send(&tx, g_sSource, deliver, &link) == XSTDOK)
    {
        while (DirectGate_Transfer_IsActive(&tx))
            if (DirectGate_Transfer_SendNext(&tx, deliver, &link) < 0) break;
    }

    int nBad = 0;
    if (tx.eState == XTRANSFER_STATE_DONE && rx.eState == XTRANSFER_STATE_DONE)
    {
        /* Read back with nothing armed: delivery is judged on the bytes, not on what either side said */
        int bWasArmed = g_bArmed;
        g_bArmed = 0;

        FILE *pFile = fopen(g_sDest, "rb");
        static uint8_t sBack[sizeof(g_fileData) + 1];
        size_t nBack = pFile != NULL ? fread(sBack, 1, sizeof(sBack), pFile) : 0;
        if (pFile != NULL) fclose(pFile);

        nBad = nBack != sizeof(g_fileData) || memcmp(sBack, g_fileData, nBack);
        if (nBad) fprintf(stderr, "alloc_fail_smoke: transfer reported done with %zu bytes delivered\n", nBack);
        g_bArmed = bWasArmed;
    }
    else if (rx.eState == XTRANSFER_STATE_DONE)
    {
        fprintf(stderr, "alloc_fail_smoke: the receiver finished a transfer the sender failed\n");
        nBad = 1;
    }

    DirectGate_Transfer_Destroy(&tx);
    DirectGate_Transfer_Destroy(&rx);
    unlink(g_sDest);
    return nBad;
}

/* The key handshake both ways, as dgcli and the agent run it, and the client key file round trip. Whatever
   both sides report as authenticated has to end in the same shared secret. */

static int scn_keyauth(void)
{
    const char *pDeviceId = "11111111-2222-3333-4444-555555555555";
    directgate_keyauth_t client, agent;
    DirectGate_KeyAuth_Init(&agent);

    char sClientPub[DIRECTGATE_KEYAUTH_PUB_B64_SIZE], sClientEph[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    char sClientNonce[DIRECTGATE_KEYAUTH_NONCE_SIZE * 2 + 1], sClientSig[DIRECTGATE_KEYAUTH_SIG_B64_SIZE];
    char sAgentPub[DIRECTGATE_KEYAUTH_PUB_B64_SIZE], sAgentEph[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    char sAgentNonce[DIRECTGATE_KEYAUTH_NONCE_SIZE * 2 + 1], sChallenge[DIRECTGATE_KEYAUTH_CHALLENGE_SIZE * 2 + 1];
    char sAgentSig[DIRECTGATE_KEYAUTH_SIG_B64_SIZE];

    xbool_t bAgent = DirectGate_KeyAuth_ClientInit(&client, pDeviceId, &g_clientKey, g_sAgentPubB64) &&
        DirectGate_KeyAuth_ClientBuildHello(&client, sClientPub, sizeof(sClientPub), sClientEph, sizeof(sClientEph),
            sClientNonce, sizeof(sClientNonce)) &&
        DirectGate_KeyAuth_AgentProcessHello(&agent, pDeviceId, sClientPub, sClientEph, sClientNonce) &&
        DirectGate_KeyAuth_AgentBuildChallenge(&agent, g_agentSeed, g_agentPub, sAgentPub, sizeof(sAgentPub),
            sAgentEph, sizeof(sAgentEph), sAgentNonce, sizeof(sAgentNonce), sChallenge, sizeof(sChallenge),
            sAgentSig, sizeof(sAgentSig)) &&
        DirectGate_KeyAuth_ClientProcessChallenge(&client, &g_clientKey, sAgentPub, sAgentEph, sAgentNonce,
            sChallenge, sAgentSig, sClientSig, sizeof(sClientSig)) &&
        DirectGate_KeyAuth_AgentVerifyProof(&agent, sClientSig) &&
        DirectGate_KeyAuth_DeriveShared(&agent);

    xbool_t bClient = bAgent && DirectGate_KeyAuth_ClientAccept(&client) && DirectGate_KeyAuth_DeriveShared(&client);
    int nBad = bClient && memcmp(client.sharedSecret, agent.sharedSecret, sizeof(agent.sharedSecret));
    if (nBad) fprintf(stderr, "alloc_fail_smoke: both sides authenticated with different secrets\n");

    /* An agent that did not finish never reports itself authenticated */
    if (!bAgent && agent.eState == DIRECTGATE_KEYAUTH_STATE_AUTHENTICATED) nBad = 1;

    DirectGate_KeyAuth_Cleanse(&client);
    DirectGate_KeyAuth_Cleanse(&agent);
    if (nBad) return nBad;

    /* The key file: what is saved and reported saved has to load back as the same key */
    unlink(g_sKeyPath);
    if (DirectGate_KeyAuth_KeySave(&g_clientKey, g_sKeyPath))
    {
        directgate_client_key_t loaded;
        memset(&loaded, 0, sizeof(loaded));
        if (DirectGate_KeyAuth_KeyLoad(&loaded, g_sKeyPath) &&
            memcmp(&loaded, &g_clientKey, sizeof(loaded)))
        {
            fprintf(stderr, "alloc_fail_smoke: a saved client key loaded back different\n");
            nBad = 1;
        }
        DirectGate_KeyAuth_KeyCleanse(&loaded);
    }

    unlink(g_sKeyPath);
    return nBad;
}

/* The password handshake, both ends: what both report as authenticated shares one session key */

static int scn_srp(void)
{
    const char *pDeviceId = "dev-srp";
    directgate_srp_client_t client;
    directgate_srp_t server;
    memset(&client, 0, sizeof(client));
    memset(&server, 0, sizeof(server));

    char sA[1024], sB[1024], sClientNonce[DIRECTGATE_SRP_NONCE_SIZE * 2 + 1], sAgentNonce[DIRECTGATE_SRP_NONCE_SIZE * 2 + 1];
    char sM1[DIRECTGATE_SRP_KEY_SIZE * 2 + 1], sM2[DIRECTGATE_SRP_KEY_SIZE * 2 + 1];
    size_t nBytes = 0;

    xbool_t bClient = DirectGate_SRP_ClientInit(&client);
    xbool_t bServer = DirectGate_SRP_Init(&server);
    if (bServer) xstrncpy(server.sDeviceId, sizeof(server.sDeviceId), pDeviceId);

    xbool_t bDone = bClient && bServer &&
        DirectGate_SRP_LoadVerifier(&server, g_srpSalt, sizeof(g_srpSalt), g_sVerifierHex) &&
        DirectGate_SRP_ClientGenerateA(&client, sA, sizeof(sA), sClientNonce, sizeof(sClientNonce)) &&
        DirectGate_SRP_SetClientPublic(&server, sA) &&
        DirectGate_SRP_GenerateChallenge(&server, sB, sizeof(sB), sAgentNonce, sizeof(sAgentNonce)) &&
        DirectGate_SRP_HexToBytes(sClientNonce, server.clientNonce, sizeof(server.clientNonce), &nBytes) &&
        DirectGate_SRP_HexToBytes(sAgentNonce, client.agentNonce, sizeof(client.agentNonce), &nBytes) &&
        DirectGate_SRP_ClientComputeKey(&client, pDeviceId, "correct horse battery staple", g_sSrpSaltHex, sB,
            DIRECTGATE_SRP_SUITE, sM1, sizeof(sM1)) &&
        DirectGate_SRP_VerifyClientProof(&server, sM1, sM2, sizeof(sM2));

    int nBad = 0;
    if (bDone && (!server.bAuthenticated || memcmp(server.K, client.K, sizeof(server.K)) ||
        !DirectGate_SRP_ClientVerifyM2(&client, sB, sM2)))
    {
        fprintf(stderr, "alloc_fail_smoke: SRP reported success without agreeing on a key\n");
        nBad = 1;
    }
    else if (!bDone && server.bAuthenticated)
    {
        fprintf(stderr, "alloc_fail_smoke: an unfinished SRP handshake left the server authenticated\n");
        nBad = 1;
    }

    if (bClient) DirectGate_SRP_ClientCleanse(&client);
    if (bServer) DirectGate_SRP_Destroy(&server);
    return nBad;
}

/* dgcli's account file: an account reported saved loads back whole; a save that failed left the old file */
static int scn_account(void)
{
    directgate_account_t account;
    fill_account(&account, "access-new");
    xbool_t bSaved = DirectGate_Account_Save(&account, g_sAccountPath);

    int bWasArmed = g_bArmed;
    g_bArmed = 0;
    char sNow[sizeof(g_sAccountBefore)];
    size_t nNow = read_file(g_sAccountPath, sNow, sizeof(sNow));
    int nBad = 0;

    if (!bSaved && (nNow != g_nAccountBefore || memcmp(sNow, g_sAccountBefore, nNow)))
    {
        fprintf(stderr, "alloc_fail_smoke: an account save that failed changed the file: %s\n", sNow);
        nBad = 1;
    }
    else if (bSaved)
    {
        directgate_account_t loaded;
        nBad = !DirectGate_Account_Load(&loaded, g_sAccountPath) || strcmp(loaded.sAccessToken, "access-new") ||
               strcmp(loaded.sRefreshToken, "refresh-token") || strcmp(loaded.sEmail, account.sEmail) ||
               strcmp(loaded.sUserId, account.sUserId) || loaded.nExpiresAt != account.nExpiresAt;
        if (nBad) fprintf(stderr, "alloc_fail_smoke: an account reported saved does not load back whole: %s\n", sNow);

        FILE *pFile = fopen(g_sAccountPath, "wb");
        if (pFile == NULL || fwrite(g_sAccountBefore, 1, g_nAccountBefore, pFile) != g_nAccountBefore) nBad = 1;
        if (pFile != NULL) fclose(pFile);
    }

    g_bArmed = bWasArmed;
    return nBad;
}

typedef struct {
    const char *pName;
    int (*run)(void);
} scenario_t;

static const scenario_t g_scenarios[] = {
    { "parse-data", scn_parse_data },
    { "parse-file", scn_parse_file },
    { "parse-route", scn_parse_route },
    { "build", scn_build },
    { "encrypt", scn_encrypt },
    { "decrypt", scn_decrypt },
    { "checkcc-parsed", scn_checkcc_parsed },
    { "ws-send", scn_ws_send },
    { "transfer", scn_transfer },
    { "keyauth", scn_keyauth },
    { "srp", scn_srp },
    { "account", scn_account }
};

static int open_descriptors(void)
{
    int nCount = 0;
    DIR *pDir = opendir("/proc/self/fd");
    if (pDir == NULL) return -1;

    struct dirent *pEntry;
    while ((pEntry = readdir(pDir)) != NULL)
        if (pEntry->d_name[0] != '.') nCount++;

    closedir(pDir);
    return nCount;
}

static int sweep(const scenario_t *pScenario)
{
    /* A clean run first: it has to succeed, release everything and say how many allocations there are */
    int nDescriptors = open_descriptors();
    arm(-1);
    int nResult = pScenario->run();
    long nAllocations = g_nCount, nLeft = g_nLive;
    disarm();

    if (nResult || nLeft || open_descriptors() != nDescriptors)
    {
        fprintf(stderr, "alloc_fail_smoke: %s fails without any injected failure (result %d, live %ld, fds %d -> %d)\n",
            pScenario->pName, nResult, nLeft, nDescriptors, open_descriptors());
        return 1;
    }

    for (long i = 1; i <= nAllocations; i++)
    {
        arm(i);
        nResult = pScenario->run();
        nLeft = g_nLive;
        disarm();

        int nNow = open_descriptors();
        if (nResult || nLeft || nNow != nDescriptors)
        {
            fprintf(stderr, "alloc_fail_smoke: %s with allocation %ld of %ld failing: result %d, %ld block(s) left, "
                "fds %d -> %d\n", pScenario->pName, i, nAllocations, nResult, nLeft, nDescriptors, nNow);
            return 1;
        }
    }

    printf("alloc_fail_smoke: %-15s %3ld allocation failures handled\n", pScenario->pName, nAllocations);
    return 0;
}

int main(int argc, char *argv[])
{
    xlog_init("alloc_fail_smoke", XLOG_ALL, XFALSE);
    xlog_screen(XFALSE);
    xlog_callback(drop_log, NULL);

    if (setup()) return 1;
    XByteBuffer_Init(&g_built, 0, XFALSE);
    XByteBuffer_Init(&g_sealed, 0, XFALSE);

    /* The injection has to be seen by the code under test, or every sweep below is vacuous */
    arm(1);
    xjson_obj_t *pProbe = XJSON_NewObject(NULL, NULL, XFALSE);
    long nCount = g_nCount;
    disarm();
    CHECK(pProbe == NULL && nCount >= 1, "the first allocation of the library is the one that fails");

    int nFailed = 0;
    for (size_t i = 0; i < sizeof(g_scenarios) / sizeof(g_scenarios[0]); i++)
    {
        if (argc > 1 && strcmp(argv[1], g_scenarios[i].pName)) continue;
        nFailed += sweep(&g_scenarios[i]);
    }

    teardown();
    xlog_destroy();
    if (nFailed) return 1;

    puts("alloc_fail_smoke: OK");
    return 0;
}
