#include <stdio.h>
#include <string.h>

#include "src/agent/session.h"

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "session_smoke: %s\n", msg); \
            return 1; \
        } \
    } while (0)

void DirectGate_Term_Init(directgate_term_t *pTerm)
{
    memset(pTerm, 0, sizeof(*pTerm));
    pTerm->nMasterFd = XSOCK_INVALID;
    pTerm->nPid = -1;
}

void DirectGate_Term_Clear(directgate_term_t *pTerm)
{
    memset(pTerm, 0, sizeof(*pTerm));
    pTerm->nMasterFd = XSOCK_INVALID;
    pTerm->nPid = -1;
}

void DirectGate_Term_RequestStop(directgate_term_t *pTerm)
{
    if (pTerm != NULL) pTerm->bRunning = XFALSE;
}

xbool_t DirectGate_Term_IsRunning(const directgate_term_t *pTerm)
{
    return pTerm != NULL ? pTerm->bRunning : XFALSE;
}

XSTATUS DirectGate_Term_StartNoEndpoint(directgate_term_t *pTerm, xapi_t *pApi, xapi_session_t *pWsSession)
{
    (void)pApi;
    if (pTerm == NULL || pWsSession == NULL) return XSTDINV;
    pTerm->bRunning = XTRUE;
    pTerm->pWsSession = pWsSession;
    return XSTDOK;
}

void DirectGate_Term_Shutdown(directgate_term_t *pTerm, xbool_t bCloseFd)
{
    (void)bCloseFd;
    if (pTerm != NULL) pTerm->bRunning = XFALSE;
}

void DirectGate_Search_Init(directgate_search_t *pSearch)
{
    memset(pSearch, 0, sizeof(*pSearch));
    pSearch->nPipeFds[0] = -1;
    pSearch->nPipeFds[1] = -1;
}

void DirectGate_Search_Clear(directgate_search_t *pSearch)
{
    if (pSearch != NULL)
    {
        pSearch->nPipeFds[0] = -1;
        pSearch->nPipeFds[1] = -1;
    }
}

int DirectGate_Search_GetPipeFd(const directgate_search_t *pSearch)
{
    return pSearch != NULL ? pSearch->nPipeFds[0] : XSTDERR;
}

void DirectGate_WebRTC_Init(directgate_webrtc_t *pRTC)
{
    memset(pRTC, 0, sizeof(*pRTC));
    pRTC->nPeerConnectionID = -1;
    pRTC->nDataChannelID = -1;
    pRTC->nPipeFds[0] = -1;
    pRTC->nPipeFds[1] = -1;
}

void DirectGate_WebRTC_Clear(directgate_webrtc_t *pRTC)
{
    DirectGate_WebRTC_Init(pRTC);
}

void DirectGate_WebRTC_Destroy(directgate_webrtc_t *pRTC)
{
    DirectGate_WebRTC_Clear(pRTC);
}

xbool_t DirectGate_WebRTC_IsConnected(const directgate_webrtc_t *pRTC)
{
    return pRTC != NULL ? pRTC->bConnected : XFALSE;
}

XSTATUS DirectGate_WebRTC_Send(directgate_webrtc_t *pRTC, const uint8_t *pData, size_t nLen)
{
    (void)pRTC;
    (void)pData;
    (void)nLen;
    return XSTDERR;
}

int DirectGate_WebRTC_GetPipeFd(const directgate_webrtc_t *pRTC)
{
    return pRTC != NULL ? pRTC->nPipeFds[0] : XSTDERR;
}

void DirectGate_Desktop_Init(directgate_desktop_t *pDesktop)
{
    if (pDesktop != NULL) memset(pDesktop, 0, sizeof(*pDesktop));
}

void DirectGate_Desktop_Clear(directgate_desktop_t *pDesktop)
{
    (void)pDesktop;
}

int DirectGate_Desktop_GetTimerFd(const directgate_desktop_t *pDesktop)
{
    (void)pDesktop;
    return XSOCK_INVALID;
}

int DirectGate_Desktop_Start(directgate_session_t *pSession)
{
    (void)pSession;
    return XSTDERR;
}

int DirectGate_WebSock_Send(xapi_session_t *pSession, const uint8_t *pPkg, size_t nLen)
{
    (void)pSession;
    (void)pPkg;
    (void)nLen;
    return XSTDOK;
}

int DirectGate_WebSock_SendBuff(xapi_session_t *pSession, const xbyte_buffer_t *pPkg)
{
    (void)pSession;
    (void)pPkg;
    return XSTDOK;
}

static void fill_key_material(directgate_session_t *pSession)
{
    for (size_t i = 0; i < sizeof(pSession->keyauth.sharedSecret); i++)
        pSession->keyauth.sharedSecret[i] = (uint8_t)(0x20 + i);
    for (size_t i = 0; i < sizeof(pSession->keyauth.localNonce); i++)
    {
        pSession->keyauth.localNonce[i] = (uint8_t)(0x40 + i);
        pSession->keyauth.peerNonce[i] = (uint8_t)(0x80 + i);
    }
    for (size_t i = 0; i < sizeof(pSession->srp.K); i++)
        pSession->srp.K[i] = (uint8_t)(0xa0 + i);
    for (size_t i = 0; i < sizeof(pSession->srp.nonce); i++)
    {
        pSession->srp.nonce[i] = (uint8_t)(0xc0 + i);
        pSession->srp.clientNonce[i] = (uint8_t)(0xe0 + i);
    }
}

int main(void)
{
    CHECK(DirectGate_SessionMode_FromString(NULL) == DIRECTGATE_SESSION_MODE_NONE,
        "NULL mode should map to none");
    CHECK(DirectGate_SessionMode_FromString("terminal") == DIRECTGATE_SESSION_MODE_TERMINAL,
        "terminal mode parse");
    CHECK(DirectGate_SessionMode_FromString("file-manager") == DIRECTGATE_SESSION_MODE_FILE_MANAGER,
        "file-manager mode parse");
    CHECK(DirectGate_SessionMode_FromString("Terminal") == DIRECTGATE_SESSION_MODE_NONE,
        "mode parsing should be case-sensitive");
    CHECK(strcmp(DirectGate_SessionMode_ToString(DIRECTGATE_SESSION_MODE_NONE), "none") == 0,
        "none mode string");
    CHECK(strcmp(DirectGate_SessionMode_ToString(DIRECTGATE_SESSION_MODE_TERMINAL), "terminal") == 0,
        "terminal mode string");
    CHECK(strcmp(DirectGate_SessionMode_ToString(DIRECTGATE_SESSION_MODE_FILE_MANAGER), "file-manager") == 0,
        "file-manager mode string");

    directgate_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.log.nRTCLevel = RTC_LOG_NONE;
    cfg.bAllowTCP = XTRUE;
    xstrncpy(cfg.sShellUser, sizeof(cfg.sShellUser), "session-user");
    xstrncpy(cfg.sShellHome, sizeof(cfg.sShellHome), "/tmp");

    directgate_session_mgr_t mgr;
    DirectGate_SessionMgr_Init(&mgr, &cfg);
    CHECK(DirectGate_SessionMgr_Create(&mgr, 0) == NULL,
        "zero session id should not create session");

    directgate_session_t *pFirst = DirectGate_SessionMgr_Create(&mgr, 1);
    CHECK(pFirst != NULL, "create first session");
    CHECK(pFirst->nSessionId == 1, "first session id");
    CHECK(pFirst->nCreatedMs > 0, "new session should have a creation timestamp");
    CHECK(pFirst->pMgr == &mgr, "session manager back pointer");
    CHECK(pFirst->pCfg == &cfg, "session config pointer");
    CHECK(pFirst->eActiveMode == DIRECTGATE_SESSION_MODE_NONE,
        "new session active mode");
    CHECK(pFirst->webrtc.bAllowTCP == XTRUE,
        "new session should inherit TCP ICE flag");
    CHECK(pFirst->term.pE2E == &pFirst->e2e,
        "term should reference session e2e state");
    CHECK(DirectGate_SessionMgr_Find(&mgr, 1) == pFirst,
        "find created session");
    CHECK(DirectGate_SessionMgr_Find(&mgr, 999) == NULL,
        "find missing session");

    for (uint32_t i = 2; i <= DIRECTGATE_MAX_SESSIONS; i++)
        CHECK(DirectGate_SessionMgr_Create(&mgr, i) != NULL,
            "fill session manager");
    CHECK(DirectGate_SessionMgr_Create(&mgr, DIRECTGATE_MAX_SESSIONS + 1) == NULL,
        "full session manager should reject new session");

    DirectGate_SessionMgr_RemoveWithId(&mgr, 2);
    CHECK(DirectGate_SessionMgr_Find(&mgr, 2) == NULL,
        "remove by id should clear slot");
    directgate_session_t *pReplacement = DirectGate_SessionMgr_Create(&mgr, 100);
    CHECK(pReplacement != NULL && pReplacement->nSessionId == 100,
        "removed slot should be reusable");

    fill_key_material(pFirst);
    CHECK(!DirectGate_E2E_IsInitialized(&pFirst->e2e),
        "session E2E should start clear");
    CHECK(!DirectGate_Session_DeriveE2EFromKey(pFirst, NULL),
        "key E2E derivation should require device id");
    CHECK(DirectGate_Session_DeriveE2EFromKey(pFirst, "device-session"),
        "key E2E derivation should succeed");
    CHECK(DirectGate_E2E_IsInitialized(&pFirst->e2e),
        "key E2E derivation should initialize E2E");
    DirectGate_E2E_Clear(&pFirst->e2e);
    CHECK(DirectGate_Session_DeriveE2EFromSRP(pFirst, "device-session"),
        "SRP E2E derivation should succeed");
    CHECK(DirectGate_E2E_IsInitialized(&pFirst->e2e),
        "SRP E2E derivation should initialize E2E");

    DirectGate_SessionMgr_Destroy(&mgr);

    directgate_session_mgr_t noAuthMgr;
    DirectGate_SessionMgr_Init(&noAuthMgr, &cfg);
    xapi_session_t apiSession;
    memset(&apiSession, 0, sizeof(apiSession));
    CHECK(DirectGate_SessionMgr_GetOrCreate(&noAuthMgr, &apiSession, 200) == NULL,
        "get-or-create should require at least one auth method");

    cfg.keyauth.nAuthorizedKeyCount = 1;
    xstrncpy(cfg.keyauth.sIdentitySeedB64, sizeof(cfg.keyauth.sIdentitySeedB64),
        "ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A=");
    xstrncpy(cfg.keyauth.sIdentityPubB64, sizeof(cfg.keyauth.sIdentityPubB64),
        "MTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1A=");
    xstrncpy(cfg.keyauth.sAuthorizedKeys[0], sizeof(cfg.keyauth.sAuthorizedKeys[0]),
        "G8tzS4EVKlvTqIPkKxTV/jJMHCvQkQCnYJO1B4EFRzE=");

    directgate_session_t *pCreated = DirectGate_SessionMgr_GetOrCreate(&noAuthMgr, &apiSession, 200);
    CHECK(pCreated != NULL, "get-or-create should accept key-auth config");
    CHECK(pCreated->pWsSession == &apiSession,
        "get-or-create should attach websocket session");
    CHECK(strcmp(pCreated->term.sShellUser, "session-user") == 0,
        "get-or-create should copy shell user");
    CHECK(strcmp(pCreated->term.sShellHome, "/tmp") == 0,
        "get-or-create should copy shell home");
    CHECK(DirectGate_SessionMgr_GetOrCreate(&noAuthMgr, &apiSession, 200) == pCreated,
        "get-or-create should return existing session");
    for (uint8_t i = 0; i < DIRECTGATE_AUTH_MAX_MESSAGES; i++)
        CHECK(DirectGate_Session_ConsumeAuthMessage(pCreated),
            "auth messages below the per-session limit should be accepted");
    CHECK(!DirectGate_Session_ConsumeAuthMessage(pCreated),
        "auth messages above the per-session limit should be rejected");

    pCreated->nCreatedMs = XTime_GetMs() - DIRECTGATE_AUTH_TIMEOUT_MS;
    CHECK(DirectGate_SessionMgr_ExpireUnauthenticated(&noAuthMgr, XTime_GetMs()) == 1,
        "expired pre-auth session should be removed");
    CHECK(DirectGate_SessionMgr_Find(&noAuthMgr, 200) == NULL,
        "expired pre-auth session slot should be cleared");
    DirectGate_SessionMgr_Destroy(&noAuthMgr);

    directgate_session_mgr_t rateMgr;
    DirectGate_SessionMgr_Init(&rateMgr, &cfg);
    for (uint32_t i = 0; i < DIRECTGATE_AUTH_RATE_MAX_ATTEMPTS; i++)
    {
        directgate_session_t *pRateSession =
            DirectGate_SessionMgr_GetOrCreate(&rateMgr, &apiSession, 1000 + i);
        CHECK(pRateSession != NULL, "pre-auth session below rate limit should be accepted");
        DirectGate_SessionMgr_Remove(&rateMgr, pRateSession);
    }
    CHECK(DirectGate_SessionMgr_GetOrCreate(&rateMgr, &apiSession, 2000) == NULL,
        "pre-auth session above rate limit should be rejected");
    DirectGate_SessionMgr_Destroy(&rateMgr);
    CHECK(DirectGate_SessionMgr_GetOrCreate(&rateMgr, &apiSession, 2000) == NULL,
        "session cleanup should not reset the pre-auth rate limit");
    rateMgr.nAuthWindowStartMs = 0;
    CHECK(DirectGate_SessionMgr_GetOrCreate(&rateMgr, &apiSession, 2001) != NULL,
        "pre-auth rate limit should reset for a new window");
    DirectGate_SessionMgr_Destroy(&rateMgr);

    puts("session_smoke: OK");
    return 0;
}
