/* Every allocation failure inside the agent while it answers a login, both SRP and key auth, and the first
 * messages of the session that follows.
 *
 * Messages arrive through DirectGate_TestHandleTransportMessage, as from the relay. Allocations fail only while
 * the agent handles one: the browser's half (building its messages, opening the answers) always succeeds, so
 * every failure lands in agent code. The scenario runs once to count those allocations, then once per allocation
 * with exactly that one failing. After every run:
 *   - an agent session that is authenticated holds the keys the browser derived (a keepalive round trip works),
 *   - a browser that was told "ok" is talking to a session that is authenticated or gone, never half way,
 *   - tearing the connection down released everything the run allocated.
 * The same sweep runs over a directory listing, the desktop status an authenticated session sends and the agent
 * config saved to disk: what comes out is complete, or nothing comes out (and the file on disk is the old one). */

#include <execinfo.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/crypto.h>

#include "src/agent/config.h"
#include "src/agent/directgate.h"
#include "src/agent/desktop/priv.h"
#include "src/agent/files.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "alloc_fail_agent_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

#define AGENT_DEVICE_ID "device-under-test"
#define SRP_SESSION     70U
#define KEY_SESSION     71U

/* ---------------- the injecting, tracking allocator ---------------- */

/* Allocations are recorded while a run is tracked, so what the fixture held before the run does not count;
   only those made while the agent handles a message are counted towards the one that fails. */
static volatile int g_bTrack, g_bInject;
static volatile long g_nCount, g_nFailAt = -1;

#define SET_SIZE (1U << 17)
static void *g_set[SET_SIZE];
static long g_nLive;
static void *const g_pGone = (void*)1;

void *__real_malloc(size_t nSize);
void *__real_calloc(size_t nCount, size_t nSize);
void *__real_realloc(void *pPtr, size_t nSize);
void __real_free(void *pPtr);
char *__real_strdup(const char *pStr);

static size_t set_slot(const void *p) { return (size_t)((((uintptr_t)p >> 4) * 0x9E3779B97F4A7C15ULL) >> 47) & (SET_SIZE - 1); }

static void set_add(void *p)
{
    for (size_t i = set_slot(p);; i = (i + 1) & (SET_SIZE - 1))
    {
        if (g_set[i] == NULL || g_set[i] == g_pGone) { g_set[i] = p; g_nLive++; return; }
    }
}

static int set_del(void *p)
{
    for (size_t i = set_slot(p), n = 0; n < SET_SIZE && g_set[i] != NULL; i = (i + 1) & (SET_SIZE - 1), n++)
    {
        if (g_set[i] == p) { g_set[i] = g_pGone; g_nLive--; return 1; }
    }

    return 0;
}

/* With XALLOC_BACKTRACE set, the failing allocation prints where it happened */
static int fail_now(void)
{
    if (!g_bInject || ++g_nCount != g_nFailAt) return 0;

    if (getenv("XALLOC_BACKTRACE") != NULL)
    {
        void *pFrames[24];
        int nFrames = backtrace(pFrames, (int)(sizeof(pFrames) / sizeof(*pFrames)));
        fprintf(stderr, "--- failing allocation %ld ---\n", g_nCount);
        backtrace_symbols_fd(pFrames, nFrames, fileno(stderr));
    }

    return 1;
}

void *__wrap_malloc(size_t nSize)
{
    if (fail_now()) return NULL;
    void *p = __real_malloc(nSize);
    if (p != NULL && g_bTrack) set_add(p);
    return p;
}

void *__wrap_calloc(size_t nCount, size_t nSize)
{
    if (fail_now()) return NULL;
    void *p = __real_calloc(nCount, nSize);
    if (p != NULL && g_bTrack) set_add(p);
    return p;
}

void *__wrap_realloc(void *pPtr, size_t nSize)
{
    if (fail_now()) return NULL;
    void *p = __real_realloc(pPtr, nSize);
    if (!g_bTrack || (p == NULL && nSize)) return p;

    /* A block that was tracked stays tracked wherever it moves; one from before the run stays untracked */
    int bTracked = pPtr == NULL || set_del(pPtr);
    if (p != NULL && bTracked) set_add(p);
    return p;
}

void __wrap_free(void *pPtr)
{
    if (pPtr != NULL && g_bTrack) set_del(pPtr);
    __real_free(pPtr);
}

char *__wrap_strdup(const char *pStr)
{
    if (fail_now()) return NULL;
    char *p = __real_strdup(pStr);
    if (p != NULL && g_bTrack) set_add(p);
    return p;
}

static int drop_log(const char *pLog, size_t nLength, xlog_flag_t eFlag, void *pCtx)
{
    (void)pLog; (void)nLength; (void)eFlag; (void)pCtx;
    return 0;
}

/* ---------------- the browser and the relay socket ---------------- */

typedef struct {
    directgate_cfg_t cfg;
    directgate_conn_t conn;
    xapi_session_t api;
    xbyte_buffer_t pktBuf;
} fixture_t;

/* Built once: scrypt is slow and the agent identity is the same for every run */
static char g_sSaltHex[DIRECTGATE_AUTH_SALT_HEX_SIZE], g_sVerifierHex[1024];
static char g_sSeedB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE], g_sAgentPubB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
static char g_sClientPubB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
static directgate_client_key_t g_clientKey;
static const char *g_pSecret = "correct horse battery staple";
static char g_sListDir[] = "/tmp/directgate_allocfail_dir.XXXXXX";
static const char *g_pListNames[] = { "alpha.txt", "beta.bin", "gamma", "link-to-alpha" };
static char g_sCfgPath[] = "/tmp/directgate_allocfail_cfg.XXXXXX";
static char g_sCfgBefore[16384];
static size_t g_nCfgBefore;

static void drain(fixture_t *pFix)
{
    XByteBuffer_Clear(&pFix->api.txBuffer);
    XByteBuffer_Init(&pFix->api.txBuffer, XSTDNON, XFALSE);
}

/* The agent, handling one message: the only place allocations are counted and fail */
static int agent_handle(fixture_t *pFix, xjson_obj_t *pHeader, directgate_e2e_t *pPeer, uint32_t nSessionId)
{
    xbyte_buffer_t packet;
    XByteBuffer_Init(&packet, XSTDNON, XFALSE);
    drain(pFix);

    if (pHeader == NULL) return XSTDERR;
    if (pPeer != NULL) DirectGate_Proto_AddCC(pHeader, pPeer, 0);

    if (!DirectGate_Proto_Build(&packet, pHeader, NULL, 0, XFALSE) ||
        (pPeer != NULL && !DirectGate_Proto_EncryptPackage(&packet, pPeer, nSessionId)))
    {
        XJSON_FreeObject(pHeader);
        XByteBuffer_Clear(&packet);
        return XSTDERR;
    }

    g_bInject = 1;
    int nStatus = DirectGate_TestHandleTransportMessage(&pFix->api, packet.pData, packet.nUsed);
    g_bInject = 0;

    XJSON_FreeObject(pHeader);
    XByteBuffer_Clear(&packet);
    return nStatus;
}

/* The one answer the agent queued, opened with pPeer's keys when it is sealed */
static int take_packet(fixture_t *pFix, directgate_e2e_t *pPeer, directgate_pkg_t *pPkg)
{
    if (pFix->api.txBuffer.nUsed == 0) return 0;

    xws_frame_t frame;
    xws_status_t eStatus = XWebFrame_ParseData(&frame, pFix->api.txBuffer.pData, pFix->api.txBuffer.nUsed);
    if (eStatus != XWS_FRAME_COMPLETE || !frame.bComplete)
    {
        XWebFrame_Clear(&frame);
        return 0;
    }

    XByteBuffer_Clear(&pFix->pktBuf);
    XByteBuffer_Init(&pFix->pktBuf, XSTDNON, XFALSE);
    int nCopied = XByteBuffer_Add(&pFix->pktBuf, XWebFrame_GetPayload(&frame), XWebFrame_GetPayloadLength(&frame)) > 0;
    XWebFrame_Clear(&frame);
    if (!nCopied || !DirectGate_Package_Parse(pPkg, pFix->pktBuf.pData, pFix->pktBuf.nUsed)) return 0;

    if (pPkg->header.eType == DIRECTGATE_PKG_ENCRYPTED)
    {
        if (pPeer == NULL) { DirectGate_Package_Clear(pPkg); return 0; }

        xbyte_buffer_t inner;
        XByteBuffer_Init(&inner, XSTDNON, XFALSE);
        int nInner = DirectGate_Proto_DecryptPackage(&inner, pPkg, pPeer);
        DirectGate_Package_Clear(pPkg);

        XByteBuffer_Clear(&pFix->pktBuf);
        XByteBuffer_Init(&pFix->pktBuf, XSTDNON, XFALSE);
        nCopied = nInner && XByteBuffer_Add(&pFix->pktBuf, inner.pData, inner.nUsed) > 0;
        XByteBuffer_Clear(&inner);
        if (!nCopied || !DirectGate_Package_Parse(pPkg, pFix->pktBuf.pData, pFix->pktBuf.nUsed)) return 0;
    }

    return 1;
}

static const char *field(directgate_pkg_t *pPkg, const char *pName)
{
    return XJSON_GetString(XJSON_GetObject(pPkg->jsonHeader.pRootObj, pName));
}

/* 1 when the browser was told "ok" and holds the session keys in pPeer, 0 when it was not */
static int srp_login(fixture_t *pFix, directgate_e2e_t *pPeer)
{
    directgate_srp_client_t client;
    if (!DirectGate_SRP_ClientInit(&client)) return 0;

    char sA[2048], sNonce[DIRECTGATE_SRP_NONCE_SIZE * 2 + 1], sB[2048], sSalt[DIRECTGATE_AUTH_SALT_HEX_SIZE], sM1[256];
    int nResult = 0;

    do
    {
        directgate_pkg_t pkg;
        if (!DirectGate_SRP_ClientGenerateA(&client, sA, sizeof(sA), sNonce, sizeof(sNonce))) break;
        agent_handle(pFix, DirectGate_Proto_BuildAuthHello(AGENT_DEVICE_ID, sA, sNonce, SRP_SESSION), NULL, SRP_SESSION);
        if (!take_packet(pFix, NULL, &pkg)) break;

        if (strcmp(field(&pkg, "action"), "challenge"))
        {
            DirectGate_Package_Clear(&pkg);
            break;
        }

        xstrncpy(sB, sizeof(sB), field(&pkg, "B"));
        xstrncpy(sSalt, sizeof(sSalt), field(&pkg, "salt"));
        uint32_t nSuite = XJSON_GetU32(XJSON_GetObject(pkg.jsonHeader.pRootObj, "suite"));
        size_t nBytes = 0;
        xbool_t bParsed = DirectGate_SRP_HexToBytes(field(&pkg, "nonce"), client.agentNonce,
            sizeof(client.agentNonce), &nBytes) && nBytes == sizeof(client.agentNonce);
        DirectGate_Package_Clear(&pkg);

        if (!bParsed || !DirectGate_SRP_ClientComputeKey(&client, AGENT_DEVICE_ID, g_pSecret, sSalt, sB, nSuite,
            sM1, sizeof(sM1))) break;

        agent_handle(pFix, DirectGate_Proto_BuildAuthProof(sM1, SRP_SESSION), NULL, SRP_SESSION);
        if (!take_packet(pFix, NULL, &pkg)) break;

        xbool_t bOk = !strcmp(field(&pkg, "status"), "ok") && DirectGate_SRP_ClientVerifyM2(&client, sB, field(&pkg, "M2"));
        DirectGate_Package_Clear(&pkg);
        if (!bOk) break;

        DirectGate_E2E_Init(pPeer);
        nResult = DirectGate_E2E_DeriveFromSRP(pPeer, client.K, sizeof(client.K), client.agentNonce, client.nonce,
            DIRECTGATE_SRP_NONCE_SIZE, AGENT_DEVICE_ID, XFALSE) ? 1 : 0;
    }
    while (0);

    DirectGate_SRP_ClientCleanse(&client);
    return nResult;
}

static int key_login(fixture_t *pFix, directgate_e2e_t *pPeer)
{
    directgate_keyauth_t client;
    DirectGate_KeyAuth_Init(&client);
    char sPub[DIRECTGATE_KEYAUTH_PUB_B64_SIZE], sEph[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
    char sNonce[DIRECTGATE_KEYAUTH_NONCE_SIZE * 2 + 1], sSig[DIRECTGATE_KEYAUTH_SIG_B64_SIZE];
    int nResult = 0;

    do
    {
        directgate_pkg_t pkg;
        if (!DirectGate_KeyAuth_ClientInit(&client, AGENT_DEVICE_ID, &g_clientKey, g_sAgentPubB64) ||
            !DirectGate_KeyAuth_ClientBuildHello(&client, sPub, sizeof(sPub), sEph, sizeof(sEph), sNonce, sizeof(sNonce))) break;

        agent_handle(pFix, DirectGate_Proto_BuildAuthKeyHello(AGENT_DEVICE_ID, sPub, sEph, sNonce, KEY_SESSION), NULL,
            KEY_SESSION);
        if (!take_packet(pFix, NULL, &pkg)) break;

        xbool_t bSigned = !strcmp(field(&pkg, "action"), "challenge") &&
            DirectGate_KeyAuth_ClientProcessChallenge(&client, &g_clientKey, field(&pkg, "agentPubKey"),
                field(&pkg, "agentEph"), field(&pkg, "nonce"), field(&pkg, "challenge"), field(&pkg, "agentSig"),
                sSig, sizeof(sSig));
        DirectGate_Package_Clear(&pkg);
        if (!bSigned) break;

        agent_handle(pFix, DirectGate_Proto_BuildAuthKeyProof(sSig, KEY_SESSION), NULL, KEY_SESSION);
        if (!take_packet(pFix, NULL, &pkg)) break;

        xbool_t bOk = !strcmp(field(&pkg, "status"), "ok");
        DirectGate_Package_Clear(&pkg);
        if (!bOk || !DirectGate_KeyAuth_ClientAccept(&client) || !DirectGate_KeyAuth_DeriveShared(&client)) break;

        DirectGate_E2E_Init(pPeer);
        nResult = DirectGate_E2E_DeriveFromKey(pPeer, client.sharedSecret, sizeof(client.sharedSecret),
            client.peerNonce, client.localNonce, DIRECTGATE_KEYAUTH_NONCE_SIZE, AGENT_DEVICE_ID, XFALSE) ? 1 : 0;
    }
    while (0);

    DirectGate_KeyAuth_Cleanse(&client);
    return nResult;
}

/* With nothing failing: an authenticated agent session answers a sealed ping with a sealed pong */
static int pong(fixture_t *pFix, directgate_e2e_t *pPeer, uint32_t nSessionId)
{
    long nSaved = g_nFailAt;
    g_nFailAt = -1;

    directgate_pkg_t pkg;
    agent_handle(pFix, DirectGate_Proto_BuildKeepalive("ping", nSessionId), pPeer, nSessionId);
    int nOk = take_packet(pFix, pPeer, &pkg);
    if (nOk) nOk = !strcmp(field(&pkg, "action"), "pong");
    if (nOk) DirectGate_Package_Clear(&pkg);

    g_nFailAt = nSaved;
    return nOk;
}

/* Agent and browser have to agree on how a login ended */
static int check_session(fixture_t *pFix, uint32_t nSessionId, int nLoggedIn, directgate_e2e_t *pPeer, const char *pWhat)
{
    directgate_session_t *pSession = DirectGate_SessionMgr_Find(&pFix->conn.mgr, nSessionId);
    xbool_t bAuthenticated = pSession != NULL && pSession->bAuthenticated;

    if (bAuthenticated && !nLoggedIn)
    {
        fprintf(stderr, "alloc_fail_agent_smoke: %s: the agent authenticated a session the browser was not told about\n", pWhat);
        return 1;
    }

    if (nLoggedIn && pSession != NULL && !bAuthenticated)
    {
        fprintf(stderr, "alloc_fail_agent_smoke: %s: the browser was told ok for a session left unauthenticated\n", pWhat);
        return 1;
    }

    if (bAuthenticated && !pong(pFix, pPeer, nSessionId))
    {
        fprintf(stderr, "alloc_fail_agent_smoke: %s: an authenticated session does not answer with the browser's keys\n", pWhat);
        return 1;
    }

    return 0;
}

/* With two monitors to report: the status a session sends is complete, or the call fails and nothing is queued */
static int check_desktop_status(fixture_t *pFix, uint32_t nSessionId, directgate_e2e_t *pPeer)
{
    directgate_session_t *pSession = DirectGate_SessionMgr_Find(&pFix->conn.mgr, nSessionId);
    if (pSession == NULL || !pSession->bAuthenticated) return 0;

    pSession->desktop.nMonitorCount = 2;
    for (uint32_t i = 0; i < 2; i++)
    {
        directgate_desktop_monitor_t *pMonitor = &pSession->desktop.monitors[i];
        snprintf(pMonitor->sId, sizeof(pMonitor->sId), "monitor-%u", i);
        snprintf(pMonitor->sName, sizeof(pMonitor->sName), "Screen %u", i);
        pMonitor->nWidth = 1920;
        pMonitor->nHeight = 1080;
        pMonitor->nModeCount = 2;
        pMonitor->modes[0].nWidth = 1920; pMonitor->modes[0].nHeight = 1080;
        pMonitor->modes[1].nWidth = 1280; pMonitor->modes[1].nHeight = 720;
    }

    drain(pFix);
    g_bInject = 1;
    int nSent = DirectGate_Desktop_SendStatus(pSession, "streaming", NULL);
    g_bInject = 0;

    /* The agent may have closed the session over the failure; what matters is what reached the wire */
    directgate_pkg_t pkg;
    int bQueued = take_packet(pFix, pPeer, &pkg);
    if (!bQueued)
    {
        if (nSent >= 0 && DirectGate_SessionMgr_Find(&pFix->conn.mgr, nSessionId) != NULL)
        {
            fprintf(stderr, "alloc_fail_agent_smoke: a desktop status reported sent never reached the wire\n");
            return 1;
        }
        return 0;
    }

    const directgate_pkg_data_t *pData = (const directgate_pkg_data_t*)pkg.pPackage;
    int nBad = 1;
    if (pData != NULL && pData->pPayload != NULL)
    {
        char sPayload[8192];
        size_t nLength = pData->nPayloadLength < sizeof(sPayload) - 1 ? pData->nPayloadLength : sizeof(sPayload) - 1;
        memcpy(sPayload, pData->pPayload, nLength);
        sPayload[nLength] = '\0';

        nBad = !strstr(sPayload, "\"status\":\"streaming\"") || !strstr(sPayload, "\"id\":\"monitor-0\"") ||
               !strstr(sPayload, "\"id\":\"monitor-1\"") || !strstr(sPayload, "\"modes\":[{\"") ||
               !strstr(sPayload, "\"inputCounterScope\":true");
        if (nBad) fprintf(stderr, "alloc_fail_agent_smoke: an incomplete desktop status went out: %s\n", sPayload);
    }

    DirectGate_Package_Clear(&pkg);
    return nBad;
}

/* A directory listing: complete, or none at all */
static int check_listing(void)
{
    g_bInject = 1;
    xjson_obj_t *pList = DirectGate_Files_ListDir(g_sListDir);
    g_bInject = 0;
    if (pList == NULL) return 0;

    long nSaved = g_nFailAt;
    g_nFailAt = -1;
    char *pDump = XJSON_DumpObj(pList, 0, NULL);
    g_nFailAt = nSaved;
    XJSON_FreeObject(pList);

    /* A listing it could not write is one the agent answers with "failed to serialize listing" */
    if (pDump == NULL) return 0;

    int nBad = 0;
    for (size_t i = 0; i < sizeof(g_pListNames) / sizeof(g_pListNames[0]); i++)
    {
        char sName[64];
        snprintf(sName, sizeof(sName), "\"name\":\"%s\"", g_pListNames[i]);
        if (strstr(pDump, sName) == NULL) nBad = 1;
    }

    if (strstr(pDump, "\"target\":") == NULL || strstr(pDump, "\"permissions\":") == NULL) nBad = 1;
    if (nBad) fprintf(stderr, "alloc_fail_agent_smoke: an incomplete listing was written: %s\n", pDump);
    free(pDump);
    return nBad;
}

static size_t read_whole(const char *pPath, char *pOut, size_t nSize)
{
    FILE *pFile = fopen(pPath, "rb");
    if (pFile == NULL) return 0;
    size_t nRead = fread(pOut, 1, nSize - 1, pFile);
    fclose(pFile);
    pOut[nRead] = '\0';
    return nRead;
}

static void fill_config(directgate_cfg_t *pCfg, const char *pToken)
{
    DirectGate_InitConfig(pCfg);
    xstrncpy(pCfg->sCfgPath, sizeof(pCfg->sCfgPath), g_sCfgPath);
    xstrncpy(pCfg->sRelayUrl, sizeof(pCfg->sRelayUrl), "wss://relay.example.test/websock");
    xstrncpy(pCfg->sRoutingKey, sizeof(pCfg->sRoutingKey), "routing-key");
    xstrncpy(pCfg->sDeviceId, sizeof(pCfg->sDeviceId), AGENT_DEVICE_ID);
    xstrncpy(pCfg->enroll.sApiUrl, sizeof(pCfg->enroll.sApiUrl), "https://api.example.test");
    xstrncpy(pCfg->enroll.sAccessToken, sizeof(pCfg->enroll.sAccessToken), pToken);
    xstrncpy(pCfg->enroll.sRefreshToken, sizeof(pCfg->enroll.sRefreshToken), "refresh-token");
    pCfg->enroll.nAccessTokenExp = 1900000000ULL;
    pCfg->enroll.bEnrolled = XTRUE;
    pCfg->log.nFlags = XLOG_ERROR | XLOG_WARN | XLOG_INFO;
}

/* What a save reports as saved loads back whole; a save that failed left the file as it was */
static int check_config_save(void)
{
    directgate_cfg_t cfg;
    fill_config(&cfg, "access-token-new");

    g_bInject = 1;
    xbool_t bSaved = DirectGate_SaveConfig(&cfg);
    g_bInject = 0;

    long nSaved = g_nFailAt;
    g_nFailAt = -1;
    char sNow[sizeof(g_sCfgBefore)];
    size_t nNow = read_whole(g_sCfgPath, sNow, sizeof(sNow));
    int nBad = 0;

    if (!bSaved && (nNow != g_nCfgBefore || memcmp(sNow, g_sCfgBefore, nNow)))
    {
        fprintf(stderr, "alloc_fail_agent_smoke: a config save that failed changed the file:\n%s\n", sNow);
        nBad = 1;
    }
    else if (bSaved)
    {
        directgate_cfg_t loaded;
        DirectGate_InitConfig(&loaded);
        xstrncpy(loaded.sCfgPath, sizeof(loaded.sCfgPath), g_sCfgPath);

        nBad = !DirectGate_LoadConfig(&loaded, g_sCfgPath) || strcmp(loaded.enroll.sAccessToken, "access-token-new") ||
               strcmp(loaded.enroll.sRefreshToken, "refresh-token") || strcmp(loaded.sRelayUrl, cfg.sRelayUrl) ||
               strcmp(loaded.sRoutingKey, "routing-key") || !loaded.enroll.bEnrolled ||
               loaded.enroll.nAccessTokenExp != 1900000000ULL || (loaded.log.nFlags & cfg.log.nFlags) != cfg.log.nFlags;
        if (nBad) fprintf(stderr, "alloc_fail_agent_smoke: a config reported saved does not load back whole:\n%s\n", sNow);

        /* The next run starts from the old file again */
        FILE *pFile = fopen(g_sCfgPath, "wb");
        if (pFile == NULL || fwrite(g_sCfgBefore, 1, g_nCfgBefore, pFile) != g_nCfgBefore) nBad = 1;
        if (pFile != NULL) fclose(pFile);
    }

    g_nFailAt = nSaved;
    return nBad;
}

typedef enum { LOGIN_SRP, LOGIN_KEY, LISTING, CONFIG } login_t;

static int run(login_t eLogin, long nFailAt, long *pCount, long *pLive)
{
    memset(g_set, 0, sizeof(g_set));
    g_nLive = 0;
    g_nCount = 0;
    g_nFailAt = nFailAt;
    g_bTrack = 1;

    fixture_t fix;
    memset(&fix, 0, sizeof(fix));
    xstrncpy(fix.cfg.sDeviceId, sizeof(fix.cfg.sDeviceId), AGENT_DEVICE_ID);
    xstrncpy(fix.cfg.auth.sSaltHex, sizeof(fix.cfg.auth.sSaltHex), g_sSaltHex);
    xstrncpy(fix.cfg.auth.sVerifierHex, sizeof(fix.cfg.auth.sVerifierHex), g_sVerifierHex);
    fix.cfg.auth.nSuite = DIRECTGATE_SRP_SUITE;
    xstrncpy(fix.cfg.keyauth.sIdentitySeedB64, sizeof(fix.cfg.keyauth.sIdentitySeedB64), g_sSeedB64);
    xstrncpy(fix.cfg.keyauth.sIdentityPubB64, sizeof(fix.cfg.keyauth.sIdentityPubB64), g_sAgentPubB64);
    xstrncpy(fix.cfg.keyauth.sAuthorizedKeys[0], sizeof(fix.cfg.keyauth.sAuthorizedKeys[0]), g_sClientPubB64);
    fix.cfg.keyauth.nAuthorizedKeyCount = 1;

    fix.conn.pCfg = &fix.cfg;
    DirectGate_SessionMgr_Init(&fix.conn.mgr, &fix.cfg);
    fix.api.pSessionData = &fix.conn;
    fix.api.sock.nFD = XSOCK_INVALID;
    fix.api.eRole = XAPI_CLIENT;
    fix.api.nEvents = XPOLLOUT;
    XByteBuffer_Init(&fix.api.txBuffer, XSTDNON, XFALSE);
    XByteBuffer_Init(&fix.pktBuf, XSTDNON, XFALSE);

    directgate_e2e_t srpPeer, keyPeer;
    DirectGate_E2E_Init(&srpPeer);
    DirectGate_E2E_Init(&keyPeer);

    int nBad;
    if (eLogin == LOGIN_SRP) nBad = check_session(&fix, SRP_SESSION, srp_login(&fix, &srpPeer), &srpPeer, "SRP");
    else if (eLogin == LOGIN_KEY)
    {
        nBad = check_session(&fix, KEY_SESSION, key_login(&fix, &keyPeer), &keyPeer, "key auth");
        if (!nBad) nBad = check_desktop_status(&fix, KEY_SESSION, &keyPeer);
    }
    else if (eLogin == LISTING) nBad = check_listing();
    else nBad = check_config_save();

    DirectGate_SessionMgr_Destroy(&fix.conn.mgr);
    XByteBuffer_Clear(&fix.api.txBuffer);
    XByteBuffer_Clear(&fix.pktBuf);
    DirectGate_E2E_Clear(&srpPeer);
    DirectGate_E2E_Clear(&keyPeer);

    g_bTrack = 0;
    g_nFailAt = -1;
    *pCount = g_nCount;
    *pLive = g_nLive;
    return nBad;
}

/* Each SRP login costs the browser half a scrypt derivation, which valgrind slows down fifty times over: there
   every few failure points are run instead of all of them. The leak accounting is this file's own, so a sampled
   sweep under valgrind still checks every path it takes; the other lanes run them all. XALLOC_STRIDE overrides. */
static long sweep_stride(void)
{
    if (getenv("XALLOC_STRIDE") != NULL) return atol(getenv("XALLOC_STRIDE")) > 0 ? atol(getenv("XALLOC_STRIDE")) : 1;
    const char *pPreload = getenv("LD_PRELOAD");
    return (pPreload != NULL && strstr(pPreload, "vgpreload") != NULL) ? 23 : 1;
}

static int sweep(login_t eLogin, const char *pName)
{
    /* Twice clean: the first may set up what the process keeps for good (lazily created state) */
    long nCount = 0, nLive = 0;
    CHECK(run(eLogin, -1, &nCount, &nLive) == 0, "the login succeeds with nothing failing");
    CHECK(run(eLogin, -1, &nCount, &nLive) == 0 && nLive == 0, "a clean run releases everything it allocated");
    CHECK(nCount > 20, "the agent allocates while it handles this, or the sweep below proves nothing");

    /* XALLOC_AT=<n> runs only that failure, for a debugger or XALLOC_BACKTRACE */
    long nFrom = 1, nTo = nCount, nStride = sweep_stride();
    if (getenv("XALLOC_AT") != NULL) nFrom = nTo = atol(getenv("XALLOC_AT"));

    for (long i = nFrom; i <= nTo; i = (i < nTo && i + nStride > nTo) ? nTo : i + nStride)
    {
        long nRunCount = 0;
        if (run(eLogin, i, &nRunCount, &nLive))
        {
            fprintf(stderr, "alloc_fail_agent_smoke: %s with allocation %ld of %ld failing\n", pName, i, nCount);
            return 1;
        }

        if (nLive)
        {
            fprintf(stderr, "alloc_fail_agent_smoke: %s with allocation %ld of %ld failing leaves %ld block(s) behind\n",
                pName, i, nCount, nLive);
            return 1;
        }
    }

    printf("alloc_fail_agent_smoke: %-8s %ld allocation failure points, every %ld run\n", pName, nCount, nStride);
    return 0;
}

int main(void)
{
    xlog_init("alloc_fail_agent_smoke", XLOG_ALL, XFALSE);
    xlog_screen(XFALSE);
    xlog_callback(drop_log, NULL);

    uint8_t salt[DIRECTGATE_SRP_SALT_SIZE], agentPub[DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE];
    uint8_t agentSeed[DIRECTGATE_KEYAUTH_ED25519_SEED_SIZE];
    memset(salt, 0x2b, sizeof(salt));
    for (size_t i = 0; i < sizeof(salt); i++) snprintf(g_sSaltHex + i * 2, 3, "%02x", salt[i]);

    CHECK(DirectGate_SRP_CreateVerifier(g_pSecret, salt, sizeof(salt), g_sVerifierHex, sizeof(g_sVerifierHex)),
        "create the SRP verifier");
    CHECK(DirectGate_KeyAuth_Ed25519Generate(agentPub, agentSeed) &&
          DirectGate_KeyAuth_Base64Encode(agentSeed, sizeof(agentSeed), g_sSeedB64, sizeof(g_sSeedB64)) &&
          DirectGate_KeyAuth_Base64Encode(agentPub, sizeof(agentPub), g_sAgentPubB64, sizeof(g_sAgentPubB64)) &&
          DirectGate_KeyAuth_KeyGenerate(&g_clientKey) &&
          DirectGate_KeyAuth_Base64Encode(g_clientKey.clientPub, sizeof(g_clientKey.clientPub),
              g_sClientPubB64, sizeof(g_sClientPubB64)), "create the agent identity and the client key");
    OPENSSL_cleanse(agentSeed, sizeof(agentSeed));

    /* A directory with a file of each kind and a symlink, for the listing */
    CHECK(mkdtemp(g_sListDir) != NULL, "create the directory to list");
    for (size_t i = 0; i < 3; i++)
    {
        char sPath[256];
        snprintf(sPath, sizeof(sPath), "%s/%s", g_sListDir, g_pListNames[i]);
        FILE *pFile = fopen(sPath, "w");
        CHECK(pFile != NULL && fputs("content", pFile) >= 0 && fclose(pFile) == 0, "create a file to list");
    }

    char sLink[256], sTarget[256];
    snprintf(sLink, sizeof(sLink), "%s/%s", g_sListDir, g_pListNames[3]);
    snprintf(sTarget, sizeof(sTarget), "%s/%s", g_sListDir, g_pListNames[0]);
    CHECK(symlink(sTarget, sLink) == 0, "create a symlink to list");

    /* The config file as it was before any of the saves below */
    int nCfgFd = mkstemp(g_sCfgPath);
    CHECK(nCfgFd >= 0, "create the config file");
    close(nCfgFd);
    {
        directgate_cfg_t cfg;
        fill_config(&cfg, "access-token-old");
        CHECK(DirectGate_SaveConfig(&cfg), "save the config as it was");
        g_nCfgBefore = read_whole(g_sCfgPath, g_sCfgBefore, sizeof(g_sCfgBefore));
        CHECK(g_nCfgBefore > 0 && strstr(g_sCfgBefore, "access-token-old") != NULL, "read the config as it was");
    }

    int nFailed = sweep(LOGIN_SRP, "SRP") || sweep(LOGIN_KEY, "key auth") || sweep(LISTING, "listing") ||
                  sweep(CONFIG, "config");
    unlink(g_sCfgPath);

    for (size_t i = 0; i < sizeof(g_pListNames) / sizeof(g_pListNames[0]); i++)
    {
        char sPath[256];
        snprintf(sPath, sizeof(sPath), "%s/%s", g_sListDir, g_pListNames[i]);
        unlink(sPath);
    }
    rmdir(g_sListDir);
    DirectGate_KeyAuth_KeyCleanse(&g_clientKey);
    xlog_destroy();
    if (nFailed) return 1;

    puts("alloc_fail_agent_smoke: OK");
    return 0;
}
