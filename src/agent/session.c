/*!
 * @file directgate-agent/src/agent/session.c
 * @brief Agent-side PTY session manager for multi-session support.
 *
 *  Copyright (c) 2025-2026 DirectGate. All rights reserved.
 *  Author: Sandro Kalatozishvili (sandro@directgate.io)
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "session.h"
#include "websock.h"
#include "protocol.h"
#include "files.h"

static int DirectGate_Session_GetWsFd(const directgate_session_t *pSession)
{
    XCHECK_NL((pSession != NULL), (int)XSOCK_INVALID);
    XCHECK_NL((pSession->pWsSession != NULL), (int)XSOCK_INVALID);
    return (int)pSession->pWsSession->sock.nFD;
}

static void DirectGate_Session_CleanupPendingUpload(directgate_session_t *pSession)
{
    XCHECK_VOID_NL((pSession != NULL));

    xbool_t bOwnsTempPath = xstrused(pSession->sSaveTempPath) &&
        xstrused(pSession->transfer.sPath) &&
        xstrcmp(pSession->sSaveTempPath, pSession->transfer.sPath);

    DirectGate_Transfer_Destroy(&pSession->transfer);

    if (xstrused(pSession->sSaveTempPath) && !bOwnsTempPath)
    {
        if (remove(pSession->sSaveTempPath) != 0 && errno != ENOENT)
        {
            xlogw("Failed to remove pending upload temp file during session destroy: sid(%u), path(%s), errno(%d)",
                pSession->nSessionId, pSession->sSaveTempPath, errno);
        }
    }

    pSession->sSavePath[0] = '\0';
    pSession->sSaveTempPath[0] = '\0';
    pSession->bSaveForce = XFALSE;
}

static void DirectGate_Session_Destroy(directgate_session_t *pSession)
{
    XCHECK_VOID_NL((pSession != NULL));
    pSession->bClosing = XTRUE;

    DirectGate_Term_RequestStop(&pSession->term);
    DirectGate_Term_Clear(&pSession->term);
    DirectGate_CMD_Clear(&pSession->command);
    DirectGate_E2E_Clear(&pSession->e2e);
    DirectGate_SRP_Destroy(&pSession->srp);
    DirectGate_KeyAuth_Cleanse(&pSession->keyauth);

    if (pSession->pPipeSession != NULL)
    {
        xapi_session_t *pApiSession = pSession->pPipeSession;
        pSession->pPipeSession = NULL;
        XAPI_Disconnect(pApiSession);
    }

    if (pSession->pSearchSession != NULL)
    {
        xapi_session_t *pApiSession = pSession->pSearchSession;
        pSession->pSearchSession = NULL;
        XAPI_Disconnect(pApiSession);
    }

    if (pSession->pDesktopSession != NULL)
    {
        xapi_session_t *pApiSession = pSession->pDesktopSession;
        pSession->pDesktopSession = NULL;
        XAPI_Disconnect(pApiSession);
    }

    /* A copy or delete still running is left to finish on its own worker. */
    DirectGate_Files_ReleaseOp(pSession);
    DirectGate_Desktop_Clear(&pSession->desktop);
    DirectGate_WebRTC_Clear(&pSession->webrtc);
    DirectGate_Search_Clear(&pSession->search);
    DirectGate_Session_CleanupPendingUpload(pSession);
    free(pSession);
}

void DirectGate_SessionMgr_Init(directgate_session_mgr_t *pMgr, const directgate_cfg_t *pCfg)
{
    XCHECK_VOID_NL((pMgr != NULL));
    memset(pMgr, 0, sizeof(*pMgr));
    pMgr->pCfg = pCfg;
}

void DirectGate_SessionMgr_Destroy(directgate_session_mgr_t *pMgr)
{
    XCHECK_VOID_NL((pMgr != NULL));
    const char *pDeviceId = (pMgr->pCfg != NULL && xstrused(pMgr->pCfg->sDeviceId)) ? pMgr->pCfg->sDeviceId : "N/A";
    xlogd("Destroying session manager: dev(%s)", pDeviceId);

    for (int i = 0; i < DIRECTGATE_MAX_SESSIONS; i++)
    {
        if (pMgr->pSessions[i] != NULL)
        {
            directgate_session_t *pSession = pMgr->pSessions[i];

            xlogd("Destroying session slot: slot(%d), sid(%u), wsfd(%d)",
                i, pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

            pSession->bClosing = XTRUE;
            pMgr->pSessions[i] = NULL;
            DirectGate_Session_Destroy(pSession);
        }
    }
}

xbool_t DirectGate_SessionMgr_IsEmpty(const directgate_session_mgr_t *pMgr)
{
    XCHECK_NL((pMgr != NULL), XFALSE);

    for (int i = 0; i < DIRECTGATE_MAX_SESSIONS; i++)
    {
        if (pMgr->pSessions[i] != NULL)
            return XFALSE;
    }

    return XTRUE;
}

void DirectGate_SessionMgr_RemoveWithId(directgate_session_mgr_t *pMgr, uint32_t nSessionId)
{
    XCHECK_VOID((pMgr != NULL));
    XCHECK_VOID((nSessionId != 0));

    for (int i = 0; i < DIRECTGATE_MAX_SESSIONS; i++)
    {
        directgate_session_t *pSession = pMgr->pSessions[i];
        if (pSession && pSession->nSessionId == nSessionId)
        {
            xlogd("Removing session slot: slot(%d), sid(%u), wsfd(%d)",
                i, pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

            pSession->bClosing = XTRUE;
            pMgr->pSessions[i] = NULL;
            DirectGate_Session_Destroy(pSession);
            return;
        }
    }
}

void DirectGate_SessionMgr_Remove(directgate_session_mgr_t *pMgr, directgate_session_t *pSession)
{
    XCHECK_VOID((pMgr != NULL));
    XCHECK_VOID((pSession != NULL));

    for (int i = 0; i < DIRECTGATE_MAX_SESSIONS; i++)
    {
        if (pMgr->pSessions[i] == pSession)
        {
            xlogd("Removing session slot: slot(%d), sid(%u), wsfd(%d)",
                i, pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

            pSession->bClosing = XTRUE;
            pMgr->pSessions[i] = NULL;
            DirectGate_Session_Destroy(pSession);
            return;
        }
    }
}

directgate_session_t* DirectGate_SessionMgr_Find(directgate_session_mgr_t *pMgr, uint32_t nSessionId)
{
    XCHECK_NL((pMgr != NULL), NULL);
    XCHECK_NL((nSessionId != 0), NULL);

    for (int i = 0; i < DIRECTGATE_MAX_SESSIONS; i++)
    {
        directgate_session_t *pSession = pMgr->pSessions[i];
        if (pSession && pSession->nSessionId == nSessionId) return pSession;
    }

    return NULL;
}

directgate_session_t* DirectGate_SessionMgr_FindResumed(directgate_session_mgr_t *pMgr, uint32_t nPrevId, uint64_t nNowMs)
{
    XCHECK_NL((pMgr != NULL), NULL);
    XCHECK_NL((nPrevId != 0), NULL);

    for (int i = 0; i < DIRECTGATE_MAX_SESSIONS; i++)
    {
        directgate_session_t *pSession = pMgr->pSessions[i];
        if (pSession && pSession->nPrevSessionId == nPrevId && nNowMs < pSession->nPrevSessionUntilMs) return pSession;
    }

    return NULL;
}

directgate_session_t* DirectGate_SessionMgr_Create(directgate_session_mgr_t *pMgr, uint32_t nSessionId)
{
    XCHECK((pMgr != NULL), xthrowp(NULL, "Invalid manager"));
    XCHECK((pMgr->pCfg != NULL), xthrowp(NULL, "Invalid config"));
    XCHECK((nSessionId != 0), xthrowp(NULL, "Invalid session ID"));

    const directgate_cfg_t *pCfg = pMgr->pCfg;
    int nSlot = -1;

    for (int i = 0; i < DIRECTGATE_MAX_SESSIONS; i++)
    {
        if (pMgr->pSessions[i] == NULL)
        {
            nSlot = i;
            break;
        }
    }

    if (nSlot < 0)
    {
        const char *pDeviceId = (xstrused(pCfg->sDeviceId)) ? pCfg->sDeviceId : "N/A";
        xloge("Session limit reached: dev(%s), max(%d)", pDeviceId, DIRECTGATE_MAX_SESSIONS);
        return NULL;
    }

    directgate_session_t *pSession = (directgate_session_t*)calloc(1, sizeof(directgate_session_t));
    XCHECK((pSession != NULL), xthrowp(NULL, "Failed to allocate session"));

    DirectGate_Term_Init(&pSession->term);
    DirectGate_CMD_Init(&pSession->command);
    DirectGate_E2E_Init(&pSession->e2e);
    DirectGate_WebRTC_Init(&pSession->webrtc);
    DirectGate_Search_Init(&pSession->search);
    DirectGate_Desktop_Init(&pSession->desktop);
    DirectGate_Transfer_Init(&pSession->transfer);
    DirectGate_KeyAuth_Init(&pSession->keyauth);

    pSession->term.pE2E = &pSession->e2e;
    pSession->term.nSessionId = nSessionId;
    pSession->webrtc.logLevel = pCfg->log.nRTCLevel;
    pSession->webrtc.bAllowTCP = pCfg->bAllowTCP;

    pSession->eRequestedMode = DIRECTGATE_SESSION_MODE_NONE;
    pSession->eActiveMode = DIRECTGATE_SESSION_MODE_NONE;
    pSession->bKeyAuthActive = XFALSE;
    pSession->bAuthenticated = XFALSE;
    pSession->bDesktopShare = XFALSE;
    pSession->bDesktopSharePending = XFALSE;
    pSession->nDesktopShareExpiresMs = 0;
    pSession->sDesktopShareId[0] = XSTR_NUL;
    pSession->bSaveForce = XFALSE;
    pSession->bClosing = XFALSE;
    pSession->pSearchSession = NULL;
    pSession->pDesktopSession = NULL;
    pSession->pFileOpSession = NULL;
    pSession->pFileOp = NULL;
    pSession->pPipeSession = NULL;
    pSession->pWsSession = NULL;
    pSession->nSessionId = nSessionId;
    pSession->nCreatedMs = XTime_GetMonoMs();
    pSession->nAuthMessages = 0;
    pSession->nLastKAPingMs = XSTDNON;
    pSession->nLastKAPongMs = XSTDNON;
    pSession->pCfg = pCfg;
    pSession->pMgr = pMgr;

    pMgr->pSessions[nSlot] = pSession;
    xlogn("Session created: slot(%d), sid(%u), wsfd(%d)", nSlot, nSessionId, XSOCK_INVALID);

    return pSession;
}

directgate_session_t* DirectGate_SessionMgr_GetOrCreate(directgate_session_mgr_t *pMgr, xapi_session_t *pApiSession, uint32_t nSessionId)
{
    XCHECK((pMgr != NULL), NULL);
    XCHECK((nSessionId != 0), NULL);

    const directgate_cfg_t *pCfg = pMgr->pCfg;
    XCHECK((pCfg != NULL), NULL);

    directgate_session_t *pSession = DirectGate_SessionMgr_Find(pMgr, nSessionId);
    if (pSession != NULL) return pSession;

    xbool_t bSrpReady = DirectGate_AuthIsConfigured(&pCfg->auth);
    xbool_t bKeyReady = (pCfg->keyauth.nAuthorizedKeyCount > 0 &&
                        xstrused(pCfg->keyauth.sIdentitySeedB64) &&
                        xstrused(pCfg->keyauth.sIdentityPubB64));

    XCHECK((bSrpReady || bKeyReady),
        xthrowp(NULL, "Failed to create session: no auth method configured"));

    uint64_t nRemainMs = 0;
    if (DirectGate_SessionMgr_IsAuthLocked(pMgr, &nRemainMs))
    {
        xlogw("Pre-auth session refused while authentication is throttled: sid(%u), failures(%u), remainMs(%llu)",
            nSessionId, pMgr->nAuthFailures, (unsigned long long)nRemainMs);

        return NULL;
    }

    uint64_t nNowMs = XTime_GetMonoMs();
    if (pMgr->nAuthWindowStartMs == 0 || nNowMs < pMgr->nAuthWindowStartMs ||
        nNowMs - pMgr->nAuthWindowStartMs >= DIRECTGATE_AUTH_RATE_WINDOW_MS)
    {
        pMgr->nAuthWindowStartMs = nNowMs;
        pMgr->nAuthAttempts = 0;
    }

    if (pMgr->nAuthAttempts >= DIRECTGATE_AUTH_RATE_MAX_ATTEMPTS)
    {
        xlogw("Pre-auth session rate limit reached: sid(%u), attempts(%u), windowMs(%llu)",
            nSessionId, pMgr->nAuthAttempts, (unsigned long long)DIRECTGATE_AUTH_RATE_WINDOW_MS);
        return NULL;
    }

    ++pMgr->nAuthAttempts;

    pSession = DirectGate_SessionMgr_Create(pMgr, nSessionId);
    XCHECK((pSession != NULL), xthrowp(NULL, "Failed to create session: slot not found"));

    if (xstrused(pCfg->sShellUser))
        xstrncpy(pSession->term.sShellUser, sizeof(pSession->term.sShellUser), pCfg->sShellUser);

    if (xstrused(pCfg->sShellHome))
        xstrncpy(pSession->term.sShellHome, sizeof(pSession->term.sShellHome), pCfg->sShellHome);

    if (bSrpReady)
    {
        if (!DirectGate_SRP_Init(&pSession->srp))
        {
            int nWsFd = pApiSession != NULL ? (int)pApiSession->sock.nFD : (int)XSOCK_INVALID;
            xloge("Failed to initialize SRP state: sid(%u), wsfd(%d)", nSessionId, nWsFd);

            DirectGate_SessionMgr_Remove(pMgr, pSession);
            return NULL;
        }

        uint8_t salt[DIRECTGATE_SRP_SALT_SIZE];
        if (!DirectGate_AuthSaltHexToBytes(pCfg->auth.sSaltHex, salt, sizeof(salt)) ||
            !DirectGate_SRP_LoadVerifier(&pSession->srp, salt, sizeof(salt), pCfg->auth.sVerifierHex))
        {
            int nWsFd = pApiSession != NULL ? (int)pApiSession->sock.nFD : (int)XSOCK_INVALID;
            xloge("Failed to load SRP verifier: sid(%u), wsfd(%d)", nSessionId, nWsFd);

            DirectGate_SessionMgr_Remove(pMgr, pSession);
            OPENSSL_cleanse(salt, sizeof(salt));
            return NULL;
        }

        OPENSSL_cleanse(salt, sizeof(salt));
    }

    pSession->pWsSession = pApiSession;
    return pSession;
}

size_t DirectGate_SessionMgr_ExpireUnauthenticated(directgate_session_mgr_t *pMgr, uint64_t nNowMs)
{
    XCHECK_NL((pMgr != NULL), 0);
    size_t nExpired = 0;

    for (int i = 0; i < DIRECTGATE_MAX_SESSIONS; i++)
    {
        directgate_session_t *pSession = pMgr->pSessions[i];
        if (pSession == NULL || pSession->bAuthenticated || pSession->bClosing)
            continue;

        if (nNowMs >= pSession->nCreatedMs &&
            nNowMs - pSession->nCreatedMs >= DIRECTGATE_AUTH_TIMEOUT_MS)
        {
            xlogw("Pre-auth session timed out: sid(%u), timeoutMs(%llu)",
                pSession->nSessionId, (unsigned long long)DIRECTGATE_AUTH_TIMEOUT_MS);

            DirectGate_Session_Close(pSession, "authentication timeout");
            ++nExpired;
        }
    }

    return nExpired;
}

xbool_t DirectGate_SessionMgr_IsAuthLocked(directgate_session_mgr_t *pMgr, uint64_t *pRemainMs)
{
    XCHECK_NL((pMgr != NULL), XFALSE);
    uint64_t nNowMs = XTime_GetMonoMs();

    /* A clock that jumped backwards must not hold the door shut for longer than a lockout could ever last. */
    if (pMgr->nAuthLockoutUntilMs > nNowMs + DIRECTGATE_AUTH_LOCKOUT_MAX_MS) pMgr->nAuthLockoutUntilMs = 0;
    if (nNowMs >= pMgr->nAuthLockoutUntilMs) return XFALSE;

    if (pRemainMs != NULL) *pRemainMs = pMgr->nAuthLockoutUntilMs - nNowMs;
    return XTRUE;
}

void DirectGate_SessionMgr_NoteAuthFailure(directgate_session_mgr_t *pMgr)
{
    XCHECK_VOID_NL((pMgr != NULL));
    if (pMgr->nAuthFailures < UINT32_MAX) pMgr->nAuthFailures++;
    if (pMgr->nAuthFailures <= DIRECTGATE_AUTH_FAILURE_GRACE) return;

    uint32_t nSteps = pMgr->nAuthFailures - DIRECTGATE_AUTH_FAILURE_GRACE - 1;
    uint64_t nDelayMs = DIRECTGATE_AUTH_LOCKOUT_MAX_MS;

    if (nSteps < 32)
    {
        nDelayMs = DIRECTGATE_AUTH_LOCKOUT_BASE_MS << nSteps;
        if (nDelayMs > DIRECTGATE_AUTH_LOCKOUT_MAX_MS) nDelayMs = DIRECTGATE_AUTH_LOCKOUT_MAX_MS;
    }

    pMgr->nAuthLockoutUntilMs = XTime_GetMonoMs() + nDelayMs;

    xlogw("Throttling authentication after repeated failures: failures(%u), lockoutMs(%llu)",
        pMgr->nAuthFailures, (unsigned long long)nDelayMs);
}

void DirectGate_SessionMgr_NoteAuthSuccess(directgate_session_mgr_t *pMgr)
{
    XCHECK_VOID_NL((pMgr != NULL));

    if (pMgr->nAuthFailures > 0)
        xlogi("Authentication succeeded, clearing the failure count: failures(%u)", pMgr->nAuthFailures);

    pMgr->nAuthFailures = 0;
    pMgr->nAuthLockoutUntilMs = 0;
}

xbool_t DirectGate_Session_ConsumeAuthMessage(directgate_session_t *pSession)
{
    XCHECK_NL((pSession != NULL), XFALSE);
    XCHECK_NL((!pSession->bAuthenticated), XFALSE);

    if (pSession->nAuthMessages >= DIRECTGATE_AUTH_MAX_MESSAGES)
        return XFALSE;

    ++pSession->nAuthMessages;
    return XTRUE;
}

int DirectGate_SessionMgr_Close(directgate_session_mgr_t *pMgr, uint32_t nSessionId, const char *pReason)
{
    XCHECK_NL((pMgr != NULL), XAPI_CONTINUE);
    XCHECK_NL((nSessionId > 0), XAPI_CONTINUE);

    directgate_session_t *pSession = DirectGate_SessionMgr_Find(pMgr, nSessionId);
    XCHECK_NL((pSession != NULL), XAPI_CONTINUE);

    DirectGate_Session_Close(pSession, pReason);
    return XAPI_CONTINUE;
}

void DirectGate_Session_Remove(directgate_session_t *pSession)
{
    XCHECK_VOID((pSession != NULL));
    XCHECK_VOID((pSession->pMgr != NULL));

    directgate_session_mgr_t *pMgr = pSession->pMgr;
    DirectGate_SessionMgr_Remove(pMgr, pSession);
}

int DirectGate_Session_Close(directgate_session_t *pSession, const char *pReason)
{
    XCHECK_NL((pSession != NULL), XAPI_CONTINUE);
    XCHECK_NL((!pSession->bClosing), XAPI_CONTINUE);
    pSession->bClosing = XTRUE;

    xlogn("Closing session: sid(%u), wsfd(%d), reason(%s)",
        pSession->nSessionId, DirectGate_Session_GetWsFd(pSession),
        xstrused(pReason) ? pReason : "session error");

    /* NOTE: Send closed status via WebSocket directly to avoid WebRTC because
       Session_Remove destroys WebRTC immediately after, racing the async send.
       A detached session has no relay route, and its id may belong to another client of the relay by now. */
    xjson_obj_t *pHeader = DirectGate_Proto_BuildStatus("closed", pSession->nSessionId);
    if (pHeader != NULL)
    {
        if (pSession->pWsSession != NULL && !pSession->bDetached)
        {
            xbyte_buffer_t msg;
            XByteBuffer_Init(&msg, XSTDNON, XFALSE);

            if (DirectGate_Proto_Build(&msg, pHeader, NULL, 0, XFALSE))
                DirectGate_WebSock_SendBuff(pSession->pWsSession, &msg);

            XByteBuffer_Clear(&msg);
        }

        XJSON_FreeObject(pHeader);
    }

    DirectGate_Session_Remove(pSession);
    return XAPI_CONTINUE;
}

/* bRelayOnly: bulk data pinned to the relay is not moved to a channel that came up meanwhile */
/* What the session keeps to on the relay: a sixteenth below the relay's rate (see DIRECTGATE_RELAY_PACE_UNIT) */
static uint64_t DirectGate_Session_GetPaceRate(const directgate_session_mgr_t *pMgr)
{
    return (uint64_t)pMgr->nRelayRateBytes - pMgr->nRelayRateBytes / DIRECTGATE_RELAY_PACE_SHARE;
}

/* The session's relay bucket at nNowMs, counting nothing: full before its first send, topped up since. A limit
   lowered meanwhile - a new relay link - holds what was left to the new burst. */
static int64_t DirectGate_Session_GetRelayLevel(const directgate_session_t *pSession, uint64_t nNowMs)
{
    const directgate_session_mgr_t *pMgr = pSession->pMgr;
    int64_t nBurst = (int64_t)(pMgr->nRelayBurstBytes / 2) * DIRECTGATE_RELAY_PACE_UNIT;
    if (!pSession->nRelayTokensMs) return nBurst;

    int64_t nLevel = pSession->nRelayTokens < nBurst ? pSession->nRelayTokens : nBurst;
    if (nNowMs <= pSession->nRelayTokensMs || nLevel == nBurst) return nLevel;

    /* Comparing with the room first keeps the product in range */
    uint64_t nRate = DirectGate_Session_GetPaceRate(pMgr);
    uint64_t nElapsedMs = nNowMs - pSession->nRelayTokensMs;
    uint64_t nRoom = (uint64_t)(nBurst - nLevel);
    if (nElapsedMs > nRoom / nRate) return nBurst;
    return nLevel + (int64_t)(nElapsedMs * nRate);
}

/* Everything the session sends the relay counts, as the relay counts it: the frame's payload */
static void DirectGate_Session_CountRelay(directgate_session_t *pSession, size_t nBytes)
{
    const directgate_session_mgr_t *pMgr = pSession->pMgr;
    XCHECK_VOID_NL((pMgr != NULL && pMgr->nRelayRateBytes));

    uint64_t nNowMs = XTime_GetMonoMs();
    int64_t nLevel = DirectGate_Session_GetRelayLevel(pSession, nNowMs);
    int64_t nCost = (int64_t)(nBytes < UINT32_MAX ? nBytes : UINT32_MAX) * DIRECTGATE_RELAY_PACE_UNIT;

    pSession->nRelayTokens = nLevel - nCost > DIRECTGATE_RELAY_PACE_FLOOR ? nLevel - nCost : DIRECTGATE_RELAY_PACE_FLOOR;
    pSession->nRelayTokensMs = nNowMs;
}

#ifdef DIRECTGATE_TESTING
int64_t DirectGate_Session_TestRelayLevel(const directgate_session_t *pSession, uint64_t nNowMs)
{
    return DirectGate_Session_GetRelayLevel(pSession, nNowMs);
}
#endif

uint32_t DirectGate_Session_GetRelayWaitMs(const directgate_session_t *pSession, uint64_t nNowMs)
{
    XCHECK_NL((pSession != NULL && pSession->pMgr != NULL && pSession->pMgr->nRelayRateBytes), 0);

    int64_t nLevel = DirectGate_Session_GetRelayLevel(pSession, nNowMs);
    XCHECK_NL((nLevel < 0), 0);

    uint64_t nRate = DirectGate_Session_GetPaceRate(pSession->pMgr);
    uint64_t nWaitMs = ((uint64_t)-nLevel + nRate - 1) / nRate;
    return nWaitMs < DIRECTGATE_COMMAND_WAIT_NONE ? (uint32_t)nWaitMs : DIRECTGATE_COMMAND_WAIT_NONE - 1;
}

void DirectGate_SessionMgr_SetRelayLimit(directgate_session_mgr_t *pMgr, uint32_t nRateBytes, uint32_t nBurstBytes)
{
    XCHECK_VOID_NL((pMgr != NULL));
    XCHECK_VOID_NL((pMgr->nRelayRateBytes != nRateBytes || pMgr->nRelayBurstBytes != nBurstBytes));

    if (nRateBytes) xlogn("Relay limit per session: rate(%u), burst(%u)", nRateBytes, nBurstBytes);
    pMgr->nRelayRateBytes = nRateBytes;
    pMgr->nRelayBurstBytes = nBurstBytes;
}

static int DirectGate_Session_SendVia(directgate_session_t *pSession, xjson_obj_t *pHeader,
                                      const uint8_t *pPayload, size_t nPayloadLength, xbool_t bRelayOnly)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    XCHECK((pHeader != NULL), XAPI_DISCONNECT);

    xapi_session_t *pApiSession = pSession->pWsSession;
    directgate_webrtc_t *pRTC = &pSession->webrtc;
    directgate_e2e_t *pE2E = &pSession->e2e;

    /* Add packet counter for authenticated sessions */
    if (DirectGate_E2E_IsInitialized(&pSession->e2e))
        DirectGate_Proto_AddCC(pHeader, pE2E, pRTC->nSignalGeneration);

    xbyte_buffer_t msg;
    XByteBuffer_Init(&msg, XSTDNON, XFALSE);

    if (!DirectGate_Proto_Build(&msg, pHeader, pPayload, nPayloadLength, XFALSE))
    {
        XByteBuffer_Clear(&msg);
        return XAPI_DISCONNECT;
    }

    if (DirectGate_E2E_IsInitialized(pE2E))
    {
        if (!DirectGate_Proto_EncryptPackage(&msg, pE2E, pSession->nSessionId))
        {
            xloge("Failed to encrypt session message: sid(%u), wsfd(%d)",
                pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

            XByteBuffer_Clear(&msg);
            return XAPI_DISCONNECT;
        }
    }

    int nStatus;
    if (!bRelayOnly && DirectGate_WebRTC_IsConnected(pRTC))
    {
        int nRet = DirectGate_WebRTC_Send(pRTC, msg.pData, msg.nUsed);
        if (nRet >= 0)
        {
            XByteBuffer_Clear(&msg);
            return XSTDOK;
        }

        xlogw("WebRTC send failed, falling back to relay: sid(%u), wsfd(%d), bytes(%zu)",
            pSession->nSessionId, DirectGate_Session_GetWsFd(pSession), msg.nUsed);

        DirectGate_WebRTC_NoteSendFailure(pRTC);
    }

    /* Nowhere else to go: the relay may have handed this session's id to another client */
    if (pSession->bDetached)
    {
        XByteBuffer_Clear(&msg);
        return XAPI_DISCONNECT;
    }

    nStatus = DirectGate_WebSock_Send(pApiSession, msg.pData, msg.nUsed);
    if (nStatus >= 0) DirectGate_Session_CountRelay(pSession, msg.nUsed);

    XByteBuffer_Clear(&msg);
    return nStatus;
}

/* While bulk data is pinned to the relay, everything the session sends goes there too: one transport keeps what it
   sends in the order it was sent, where a channel that came up meanwhile could deliver a later message first. */
int DirectGate_Session_Send(directgate_session_t *pSession, xjson_obj_t *pHeader,
                            const uint8_t *pPayload, size_t nPayloadLength)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    xbool_t bRelayOnly = pSession->eBulkPin == DIRECTGATE_BULK_RELAY ? XTRUE : XFALSE;
    return DirectGate_Session_SendVia(pSession, pHeader, pPayload, nPayloadLength, bRelayOnly);
}

directgate_bulk_route_t DirectGate_Session_GetBulkRoute(directgate_session_t *pSession, uint64_t nNowMs)
{
    XCHECK_NL((pSession != NULL), DIRECTGATE_BULK_WAIT);

    /* Started on the relay, it finishes there. A detached session has no relay route at all. */
    if (pSession->eBulkPin == DIRECTGATE_BULK_RELAY)
        return pSession->bDetached ? DIRECTGATE_BULK_WAIT : DIRECTGATE_BULK_RELAY;

    if (DirectGate_WebRTC_IsConnected(&pSession->webrtc))
    {
        /* WebRTC works: should the channel go, what is in flight waits for it to come back */
        pSession->nBulkWaitMs = 0;
        pSession->bBulkRelay = XFALSE;
        return DIRECTGATE_BULK_CHANNEL;
    }

    if (pSession->bDetached) return DIRECTGATE_BULK_WAIT;
    if (pSession->bBulkRelay) return DIRECTGATE_BULK_RELAY;

    if (!pSession->nBulkWaitMs) pSession->nBulkWaitMs = nNowMs;
    if (nNowMs - pSession->nBulkWaitMs < DIRECTGATE_BULK_CHANNEL_WAIT_MS) return DIRECTGATE_BULK_WAIT;

    xlogw("No data channel came up, bulk data takes the relay: sid(%u), wsfd(%d), waitedMs(%llu)",
        pSession->nSessionId, DirectGate_Session_GetWsFd(pSession), (unsigned long long)(nNowMs - pSession->nBulkWaitMs));

    pSession->bBulkRelay = XTRUE;
    return DIRECTGATE_BULK_RELAY;
}

xbool_t DirectGate_Session_IsBulkOnRelay(const directgate_session_t *pSession)
{
    XCHECK_NL((pSession != NULL && !pSession->bDetached), XFALSE);
    if (pSession->eBulkPin == DIRECTGATE_BULK_RELAY) return XTRUE;
    return (pSession->bBulkRelay && !DirectGate_WebRTC_IsConnected(&pSession->webrtc)) ? XTRUE : XFALSE;
}

uint32_t DirectGate_Session_GetBulkWaitMs(const directgate_session_t *pSession, uint64_t nNowMs)
{
    XCHECK_NL((pSession != NULL), DIRECTGATE_COMMAND_WAIT_NONE);

    /* On the relay, until what the session sent has made room again under the relay's limit */
    if (DirectGate_Session_IsBulkOnRelay(pSession))
    {
        uint32_t nRelayMs = DirectGate_Session_GetRelayWaitMs(pSession, nNowMs);
        return nRelayMs ? nRelayMs : DIRECTGATE_COMMAND_WAIT_NONE;
    }

    XCHECK_NL((pSession->nBulkWaitMs && !pSession->bBulkRelay && !pSession->bDetached), DIRECTGATE_COMMAND_WAIT_NONE);
    XCHECK_NL((!DirectGate_WebRTC_IsConnected(&pSession->webrtc)), DIRECTGATE_COMMAND_WAIT_NONE);

    /* At least a millisecond: a deadline already due asks for the next pass, never for a spin */
    uint64_t nDueMs = pSession->nBulkWaitMs + DIRECTGATE_BULK_CHANNEL_WAIT_MS;
    return nDueMs > nNowMs ? (uint32_t)(nDueMs - nNowMs) : 1;
}

int DirectGate_Session_SendBulk(directgate_session_t *pSession, directgate_bulk_route_t eRoute,
                                xjson_obj_t *pHeader, const uint8_t *pPayload, size_t nPayloadLength)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    XCHECK((eRoute != DIRECTGATE_BULK_WAIT), XAPI_DISCONNECT);

    if (pSession->eBulkPin == DIRECTGATE_BULK_WAIT) pSession->eBulkPin = eRoute;
    return DirectGate_Session_Send(pSession, pHeader, pPayload, nPayloadLength);
}

xbool_t DirectGate_Session_HasBulk(const directgate_session_t *pSession)
{
    XCHECK_NL((pSession != NULL), XFALSE);
    return (pSession->transfer.eState == XTRANSFER_STATE_SENDING || pSession->bPendingOpen ||
            DirectGate_CMD_IsRunning(&pSession->command)) ? XTRUE : XFALSE;
}

void DirectGate_Session_ReleaseBulk(directgate_session_t *pSession)
{
    XCHECK_VOID_NL((pSession != NULL));
    pSession->eBulkPin = DIRECTGATE_BULK_WAIT;
}

void DirectGate_Session_SetBulkRelay(directgate_session_t *pSession)
{
    XCHECK_VOID_NL((pSession != NULL));
    if (pSession->bBulkRelay) return;

    xlogi("Client found WebRTC impossible, bulk data may take the relay: sid(%u), wsfd(%d)",
        pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

    pSession->bBulkRelay = XTRUE;
}

int DirectGate_Session_SendKeepalive(directgate_session_t *pSession, const char *pAction)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);

    xjson_obj_t *pHeader = DirectGate_Proto_BuildKeepalive(pAction, pSession->nSessionId);
    XCHECK((pHeader != NULL), xthrowr(XAPI_DISCONNECT, "Proto: Failed to build keepalive header"));

    int nStatus = DirectGate_Session_Send(pSession, pHeader, NULL, XSTDNON);
    XJSON_FreeObject(pHeader);
    return nStatus;
}

directgate_session_mode_t DirectGate_SessionMode_FromString(const char *pMode)
{
    if (xstrused(pMode) && xstrcmp(pMode, "terminal"))
        return DIRECTGATE_SESSION_MODE_TERMINAL;

    if (xstrused(pMode) && xstrcmp(pMode, "file-manager"))
        return DIRECTGATE_SESSION_MODE_FILE_MANAGER;

    if (xstrused(pMode) && xstrcmp(pMode, "desktop"))
        return DIRECTGATE_SESSION_MODE_DESKTOP;

    if (xstrused(pMode) && xstrcmp(pMode, "exec"))
        return DIRECTGATE_SESSION_MODE_EXEC;

    if (xstrused(pMode) && xstrcmp(pMode, "remote"))
        return DIRECTGATE_SESSION_MODE_REMOTE;

    return DIRECTGATE_SESSION_MODE_NONE;
}

/* See DirectGate_Session_SetPreLogon in session.h for what this gates. */
static xbool_t g_bPreLogon = XFALSE;

void DirectGate_Session_SetPreLogon(xbool_t bPreLogon)
{
    g_bPreLogon = bPreLogon;
}

xbool_t DirectGate_Session_IsPreLogon(void)
{
    return g_bPreLogon;
}

const char* DirectGate_SessionMode_ToString(directgate_session_mode_t eMode)
{
    if (eMode == DIRECTGATE_SESSION_MODE_TERMINAL) return "terminal";
    if (eMode == DIRECTGATE_SESSION_MODE_FILE_MANAGER) return "file-manager";
    if (eMode == DIRECTGATE_SESSION_MODE_DESKTOP) return "desktop";
    if (eMode == DIRECTGATE_SESSION_MODE_REMOTE) return "remote";
    if (eMode == DIRECTGATE_SESSION_MODE_EXEC) return "exec";
    return "none";
}

int DirectGate_Session_EnsureMode(directgate_session_t *pSession, directgate_session_mode_t eMode, const char *pReason)
{
    XCHECK_NL((pSession != NULL), XSTDERR);

    /* Refusals return XSTDERR, never XAPI_CONTINUE: that one is XSTDOK under another name, and every caller's
       "!= XSTDOK" guard read it as a pass - running the handler on a session this call had just freed. */
    if (!pSession->bAuthenticated)
    {
        xloge("Session is not authenticated for requested mode: sid(%u), wsfd(%d), required(%s)",
            pSession->nSessionId, DirectGate_Session_GetWsFd(pSession), DirectGate_SessionMode_ToString(eMode));

        DirectGate_Session_Close(pSession, "session not authenticated");
        return XSTDERR;
    }

    /* A remote session does what an exec session and a file-manager session do */
    xbool_t bRemoteServes = (pSession->eActiveMode == DIRECTGATE_SESSION_MODE_REMOTE &&
        (eMode == DIRECTGATE_SESSION_MODE_EXEC || eMode == DIRECTGATE_SESSION_MODE_FILE_MANAGER)) ? XTRUE : XFALSE;

    if (pSession->eActiveMode != eMode && !bRemoteServes)
    {
        xlogw("Session mode mismatch: sid(%u), wsfd(%d), active(%s), required(%s)",
            pSession->nSessionId, DirectGate_Session_GetWsFd(pSession),
            DirectGate_SessionMode_ToString(pSession->eActiveMode),
            DirectGate_SessionMode_ToString(eMode));

        if (xstrused(pReason))
            DirectGate_Session_SendErrorMsg(pSession, pReason);

        return XSTDERR;
    }

    return XSTDOK;
}

int DirectGate_Session_SendErrorMsg(directgate_session_t *pSession, const char *pReason)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);

    xjson_obj_t *pHeader = DirectGate_Proto_BuildError(pReason, pSession->nSessionId);
    XCHECK((pHeader != NULL), xthrowr(XAPI_DISCONNECT, "Proto: Failed to build error header"));

    int nStatus = DirectGate_Session_Send(pSession, pHeader, NULL, XSTDNON);
    XJSON_FreeObject(pHeader);
    return nStatus;
}

int DirectGate_Session_SendAuthResp(directgate_session_t *pSession, const char *pStatus, const char *pM2, const char *pReason)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);

    xjson_obj_t *pHeader = DirectGate_Proto_BuildAuthResult(pStatus, pM2, pReason, pSession->nSessionId, g_bPreLogon);
    XCHECK((pHeader != NULL), xthrowr(XAPI_DISCONNECT, "Proto: Failed to build auth result header"));

    /* A client that reads this may resume the session under a new relay socket when it loses its own, see
       DirectGate_Session_HandleResume. One that does not authenticates afresh, as every client always has. */
    if (xstrcmp(pStatus, "ok") && !pSession->bDesktopShare) XJSON_AddBool(pHeader, "resume", XTRUE);

    /* Non-interactive commands (mode "exec"): a client that does not see this is talking to an agent without them,
       and says so rather than sending messages it would only drop. Never offered where only a desktop is allowed.
       Commands, and with them remote sessions: never offered to a temporary share or before anyone has logged on */
    if (xstrcmp(pStatus, "ok") && !pSession->bDesktopShare && !g_bPreLogon)
    {
        XJSON_AddBool(pHeader, "exec", XTRUE);
        XJSON_AddBool(pHeader, "remote", XTRUE);
    }

    int nStatus = DirectGate_Session_Send(pSession, pHeader, NULL, XSTDNON);
    XJSON_FreeObject(pHeader);
    return nStatus;
}

int DirectGate_Session_SendManagerResp(directgate_session_t *pSession,
                                       const char *pAction, const char *pStatus,
                                       const char *pReason, const char *pPath)
{
    XCHECK_NL((pSession != NULL), xthrowr(XAPI_CONTINUE, "Invalid session data"));
    XCHECK_NL((xstrused(pAction)), xthrowr(XAPI_CONTINUE, "Manager response action is required"));

    if (!pSession->bAuthenticated)
    {
        xloge("Manager action rejected, session is not authenticated: sid(%u), wsfd(%d), action(%s)",
            pSession->nSessionId, DirectGate_Session_GetWsFd(pSession), pAction);

        DirectGate_Session_Close(pSession, "session not authenticated for manager action");
        return XAPI_CONTINUE;
    }

    xjson_obj_t *pHeader = DirectGate_Proto_BuildManager(pAction, pStatus, pPath, pReason, pSession->nSessionId);
    XCHECK_NL((pHeader != NULL), xthrowr(XAPI_DISCONNECT, "Proto: Failed to build manager response header"));

    XCHECK_CALL((DirectGate_Session_Send(pSession, pHeader, NULL, XSTDNON) >= 0),
        XJSON_FreeObject, pHeader, xthrowr(XAPI_DISCONNECT, "Failed to send manager response"));

    XJSON_FreeObject(pHeader);
    return XAPI_CONTINUE;
}

int DirectGate_Session_SendManagerData(directgate_session_t *pSession, const char *pAction,
                                   const char *pStatus, const char *pPath,
                                   const uint8_t *pPayload, size_t nPayloadLen)
{
    XCHECK_NL((pSession != NULL), xthrowr(XAPI_CONTINUE, "Invalid session data"));
    XCHECK_NL((xstrused(pAction)), xthrowr(XAPI_CONTINUE, "Manager response action is required"));

    if (!pSession->bAuthenticated)
    {
        xloge("Manager payload rejected, session is not authenticated: sid(%u), wsfd(%d), action(%s)",
            pSession->nSessionId, DirectGate_Session_GetWsFd(pSession), pAction);

        DirectGate_Session_Close(pSession, "session not authenticated for manager action");
        return XAPI_CONTINUE;
    }

    xjson_obj_t *pHeader = DirectGate_Proto_BuildManager(pAction, pStatus, pPath, NULL, pSession->nSessionId);
    XCHECK_NL((pHeader != NULL), xthrowr(XAPI_DISCONNECT, "Proto: Failed to build manager response header"));

    if (pPayload != NULL && nPayloadLen > 0)
        XJSON_AddString(pHeader, "payloadType", "json");

    XCHECK_CALL((DirectGate_Session_Send(pSession, pHeader, pPayload, nPayloadLen) >= 0),
        XJSON_FreeObject, pHeader, xthrowr(XAPI_DISCONNECT, "Failed to send manager response"));

    XJSON_FreeObject(pHeader);
    return XAPI_CONTINUE;
}

static int DirectGate_Session_AddRTCPipeEndpoint(directgate_session_t *pSession)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    XCHECK((pSession->pWsSession != NULL), XAPI_DISCONNECT);
    if (pSession->pPipeSession != NULL) return XAPI_CONTINUE;

    int nPipeFd = DirectGate_WebRTC_GetPipeFd(&pSession->webrtc);
    if (nPipeFd < 0) return XAPI_CONTINUE;

    xapi_endpoint_t pipeEp;
    XAPI_InitEndpoint(&pipeEp);

    pipeEp.eType = XAPI_EVENT;
    pipeEp.eRole = XAPI_CUSTOM;
    pipeEp.nEvents = XPOLLIN;
    pipeEp.bUnix = XTRUE;
    pipeEp.nFD = nPipeFd;
    pipeEp.pSessionData = pSession;

    if (XAPI_AddEndpoint(pSession->pWsSession->pApi, &pipeEp) < 0)
    {
        xloge("Failed to register WebRTC pipe endpoint: sid(%u), wsfd(%d), pipefd(%d)",
            pSession->nSessionId, DirectGate_Session_GetWsFd(pSession), nPipeFd);

        /* A failed registration has already closed the descriptor; closing it again at teardown could hit
           whatever another thread opened under the same number in between. */
        pSession->webrtc.nPipeFds[0] = XSOCK_INVALID;
        DirectGate_Session_Close(pSession, "pipe registration failed");
        return XAPI_DISCONNECT;
    }

    return XAPI_CONTINUE;
}

static int DirectGate_Session_AddSearchPipeEndpoint(directgate_session_t *pSession)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    XCHECK((pSession->pWsSession != NULL), XAPI_DISCONNECT);
    if (pSession->pSearchSession != NULL) return XAPI_CONTINUE;

    int nPipeFd = DirectGate_Search_GetPipeFd(&pSession->search);
    if (nPipeFd < 0) return XAPI_CONTINUE;

    xapi_endpoint_t pipeEp;
    XAPI_InitEndpoint(&pipeEp);

    pipeEp.eType = XAPI_EVENT;
    pipeEp.eRole = XAPI_CUSTOM;
    pipeEp.nEvents = XPOLLIN;
    pipeEp.bUnix = XTRUE;
    pipeEp.nFD = nPipeFd;
    pipeEp.pSessionData = pSession;

    if (XAPI_AddEndpoint(pSession->pWsSession->pApi, &pipeEp) < 0)
    {
        xloge("Failed to register search pipe endpoint: sid(%u), wsfd(%d), pipefd(%d)",
            pSession->nSessionId, DirectGate_Session_GetWsFd(pSession), nPipeFd);

        /* Already closed by the failed registration, see the WebRTC pipe above. */
        pSession->search.nPipeFds[0] = XSOCK_INVALID;

        /* Session is freed by Close; report failure so no caller touches it. */
        DirectGate_Session_Close(pSession, "search pipe registration failed");
        return XAPI_DISCONNECT;
    }

    return XAPI_CONTINUE;
}

static int DirectGate_Session_AddDesktopEndpoint(directgate_session_t *pSession)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    XCHECK((pSession->pWsSession != NULL), XAPI_DISCONNECT);
    if (pSession->pDesktopSession != NULL) return XAPI_CONTINUE;

    int nTimerFd = DirectGate_Desktop_GetTimerFd(&pSession->desktop);
    if (nTimerFd < 0) return XAPI_CONTINUE;

    xapi_endpoint_t timerEp;
    XAPI_InitEndpoint(&timerEp);

    timerEp.eType = XAPI_EVENT;
    timerEp.eRole = XAPI_CUSTOM;
    timerEp.nEvents = XPOLLIN;
    timerEp.bUnix = XTRUE;
    timerEp.nFD = nTimerFd;
    timerEp.pSessionData = pSession;

    if (XAPI_AddEndpoint(pSession->pWsSession->pApi, &timerEp) < 0)
    {
        xloge("Failed to register desktop timer endpoint: sid(%u), wsfd(%d), timerfd(%d)",
            pSession->nSessionId, DirectGate_Session_GetWsFd(pSession), nTimerFd);

        /* Already closed by the failed registration, see the WebRTC pipe above. */
        pSession->desktop.nTimerFd = XSOCK_INVALID;

        /* Session is freed by Close; report failure so no caller touches it. */
        DirectGate_Session_Close(pSession, "desktop endpoint registration failed");
        return XAPI_DISCONNECT;
    }

    return XAPI_CONTINUE;
}

int DirectGate_Session_StartTerminal(directgate_session_t *pSession)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    XCHECK((pSession->pWsSession != NULL), XAPI_DISCONNECT);
    xapi_session_t *pApiSession = pSession->pWsSession;

    if (DirectGate_Term_IsRunning(&pSession->term))
    {
        pSession->eActiveMode = DIRECTGATE_SESSION_MODE_TERMINAL;
        return XAPI_CONTINUE;
    }

    xlogn("Starting terminal mode: sid(%u), wsfd(%d), connId(%u)",
        pSession->nSessionId, DirectGate_Session_GetWsFd(pSession), pApiSession->nID);

    // Link WebRTC to terminal for direct data forwarding
    pSession->term.pWebRTC = &pSession->webrtc;

    if (DirectGate_Term_StartNoEndpoint(&pSession->term, pApiSession->pApi, pApiSession) < 0)
    {
        xloge("Failed to start shell terminal: sid(%u), wsfd(%d)",
            pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

        return DirectGate_Session_Close(pSession, "terminal start failed");
    }

    xapi_endpoint_t endpt;
    XAPI_InitEndpoint(&endpt);

    endpt.eType = XAPI_EVENT;
    endpt.eRole = XAPI_CUSTOM;
    endpt.nEvents = XPOLLIN;
    endpt.bUnix = XTRUE;
    endpt.nFD = pSession->term.nMasterFd;
    endpt.pSessionData = pSession;

    if (XAPI_AddEndpoint(pApiSession->pApi, &endpt) < 0)
    {
        xloge("Failed to register PTY endpoint: sid(%u), wsfd(%d), ptfd(%d)",
            pSession->nSessionId, DirectGate_Session_GetWsFd(pSession), pSession->term.nMasterFd);

        /* The failed registration closed the PTY master already: reap the shell without closing it again. */
        DirectGate_Term_Shutdown(&pSession->term, XFALSE);
        return DirectGate_Session_Close(pSession, "endpoint registration failed");
    }

    if (DirectGate_Session_AddRTCPipeEndpoint(pSession) < 0)
        return XAPI_DISCONNECT;

    if (DirectGate_Session_AddSearchPipeEndpoint(pSession) < 0)
        return XAPI_DISCONNECT;

    pSession->eActiveMode = DIRECTGATE_SESSION_MODE_TERMINAL;
    return XAPI_CONTINUE;
}

int DirectGate_Session_StartMode(directgate_session_t *pSession, directgate_session_mode_t eMode)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);

    if (pSession->bDesktopShare && eMode != DIRECTGATE_SESSION_MODE_DESKTOP)
    {
        xlogw("Temporary desktop share rejected non-desktop mode: sid(%u), requested(%s)",
            pSession->nSessionId, DirectGate_SessionMode_ToString(eMode));

        DirectGate_Session_SendErrorMsg(pSession, "temporary share allows desktop only");
        return DirectGate_Session_Close(pSession, "temporary share capability violation");
    }

    if (eMode == DIRECTGATE_SESSION_MODE_NONE)
        return XAPI_CONTINUE;

    /* The single choke point every mode passes through, which is why the
       pre-logon restriction lives here and not in each mode's own start-up. */
    if (g_bPreLogon && eMode != DIRECTGATE_SESSION_MODE_DESKTOP)
    {
        xlogw("Pre-logon agent rejected a non-desktop mode: sid(%u), requested(%s)",
            pSession->nSessionId, DirectGate_SessionMode_ToString(eMode));

        return DirectGate_Session_SendErrorMsg(pSession,
            "nobody is logged on: sign in over the desktop session first");
    }

    if (pSession->eActiveMode == eMode)
        return XAPI_CONTINUE;

    if (pSession->eActiveMode != DIRECTGATE_SESSION_MODE_NONE &&
        pSession->eActiveMode != eMode)
    {
        xlogw("Refusing session mode switch: sid(%u), wsfd(%d), active(%s), next(%s)",
            pSession->nSessionId, DirectGate_Session_GetWsFd(pSession),
            DirectGate_SessionMode_ToString(pSession->eActiveMode),
            DirectGate_SessionMode_ToString(eMode));

        return DirectGate_Session_SendErrorMsg(pSession, "session mode already active");
    }

    if (eMode == DIRECTGATE_SESSION_MODE_FILE_MANAGER)
    {
        if (DirectGate_Session_AddRTCPipeEndpoint(pSession) < 0) return XAPI_DISCONNECT;
        if (DirectGate_Session_AddSearchPipeEndpoint(pSession) < 0) return XAPI_DISCONNECT;
        pSession->eActiveMode = DIRECTGATE_SESSION_MODE_FILE_MANAGER;

        xlogi("File manager mode activated: sid(%u), wsfd(%d)",
            pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

        return XAPI_CONTINUE;
    }

    if (eMode == DIRECTGATE_SESSION_MODE_REMOTE)
    {
        if (DirectGate_Session_AddRTCPipeEndpoint(pSession) < 0) return XAPI_DISCONNECT;
        if (DirectGate_Session_AddSearchPipeEndpoint(pSession) < 0) return XAPI_DISCONNECT;
        pSession->eActiveMode = DIRECTGATE_SESSION_MODE_REMOTE;

        xlogi("Remote mode activated: sid(%u), wsfd(%d)",
            pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

        return XAPI_CONTINUE;
    }

    if (eMode == DIRECTGATE_SESSION_MODE_EXEC)
    {
        if (DirectGate_Session_AddRTCPipeEndpoint(pSession) < 0) return XAPI_DISCONNECT;
        pSession->eActiveMode = DIRECTGATE_SESSION_MODE_EXEC;

        xlogi("Exec mode activated: sid(%u), wsfd(%d)",
            pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

        return XAPI_CONTINUE;
    }

    if (eMode == DIRECTGATE_SESSION_MODE_DESKTOP)
    {
        if (DirectGate_Session_AddRTCPipeEndpoint(pSession) < 0) return XAPI_DISCONNECT;
        if (DirectGate_Desktop_Start(pSession) < 0) return XAPI_CONTINUE;
        if (DirectGate_Session_AddDesktopEndpoint(pSession) < 0) return XAPI_DISCONNECT;

        pSession->eActiveMode = DIRECTGATE_SESSION_MODE_DESKTOP;
        return XAPI_CONTINUE;
    }

    return DirectGate_Session_StartTerminal(pSession);
}

int DirectGate_Session_DeriveE2EFromSRP(directgate_session_t *pSession, const char *pDeviceId)
{
    XCHECK((pSession != NULL), XFALSE);
    XCHECK((xstrused(pDeviceId)), XFALSE);

    return DirectGate_E2E_DeriveFromSRP(&pSession->e2e,
        pSession->srp.K,
        sizeof(pSession->srp.K),
        pSession->srp.nonce,
        pSession->srp.clientNonce,
        DIRECTGATE_SRP_NONCE_SIZE,
        pDeviceId, XTRUE);
}

int DirectGate_Session_DeriveE2EFromKey(directgate_session_t *pSession, const char *pDeviceId)
{
    XCHECK((pSession != NULL), XFALSE);
    XCHECK((xstrused(pDeviceId)), XFALSE);

    return DirectGate_E2E_DeriveFromKey(&pSession->e2e,
        pSession->keyauth.sharedSecret,
        sizeof(pSession->keyauth.sharedSecret),
        pSession->keyauth.localNonce,
        pSession->keyauth.peerNonce,
        DIRECTGATE_KEYAUTH_NONCE_SIZE,
        pDeviceId, XTRUE);
}

/* Only a desktop with a working data channel outlives its relay route: that is the picture
   a viewer sees freeze, and its client reconnects in the background while it keeps drawing.
   A temporary share's guest does not, and neither does a session already on its way out. */
xbool_t DirectGate_Session_CanDetach(const directgate_session_t *pSession)
{
    XCHECK_NL((pSession != NULL), XFALSE);
    return (pSession->bAuthenticated && !pSession->bClosing && !pSession->bDesktopShare &&
            pSession->eActiveMode == DIRECTGATE_SESSION_MODE_DESKTOP &&
            DirectGate_WebRTC_IsConnected(&pSession->webrtc)) ? XTRUE : XFALSE;
}

/* The proof a client resumes with: an auth "resume" sealed under the session's own keys, for this device and the id
   of the socket it now speaks on, at a counter the session's replay window has not seen. Opening it is the check that
   the client holds the keys, and moves that window on, so one proof is good once. NULL when it holds. */
static const char* DirectGate_Session_CheckResumeProof(directgate_session_t *pSession, const char *pDeviceId,
                                                       uint32_t nPrevId, uint32_t nNewId, const char *pProof)
{
    /* Bounded before decoding: the decoder allocates for whatever it is given */
    if (strlen(pProof) > ((DIRECTGATE_SESSION_RESUME_PROOF_MAX + 2U) / 3U) * 4U) return "malformed proof";

    uint8_t sDecoded[DIRECTGATE_SESSION_RESUME_PROOF_MAX];
    size_t nDecoded = 0;
    if (!DirectGate_KeyAuth_Base64Decode(pProof, sDecoded, sizeof(sDecoded), &nDecoded)) return "malformed proof";

    directgate_pkg_t sealed;
    if (!DirectGate_Package_Parse(&sealed, sDecoded, nDecoded)) return "malformed proof";

    xbyte_buffer_t inner;
    XByteBuffer_Init(&inner, XSTDNON, XFALSE);
    const char *pRefused = NULL;

    do
    {
        if (sealed.header.eType != DIRECTGATE_PKG_ENCRYPTED || sealed.header.nSessionId != nPrevId)
        {
            pRefused = "malformed proof";
            break;
        }

        if (!DirectGate_Proto_DecryptPackage(&inner, &sealed, &pSession->e2e))
        {
            pRefused = "invalid proof";
            break;
        }

        directgate_pkg_t proof;
        if (!DirectGate_Package_Parse(&proof, inner.pData, inner.nUsed))
        {
            pRefused = "invalid proof";
            break;
        }

        const directgate_pkg_auth_t *pAuth = (const directgate_pkg_auth_t*)proof.pPackage;
        uint32_t nProofNewId = XJSON_GetU32(XJSON_GetObject(proof.jsonHeader.pRootObj, "newSessionId"));

        if (proof.header.eType != DIRECTGATE_PKG_AUTH || pAuth == NULL || !xstrcmp(pAuth->pAction, "resume") ||
            proof.header.nSessionId != nPrevId || nProofNewId != nNewId || !xstrcmp(pAuth->pDeviceId, pDeviceId))
            pRefused = "invalid proof";

        DirectGate_Package_Clear(&proof);
    }
    while (0);

    XByteBuffer_Clear(&inner);
    DirectGate_Package_Clear(&sealed);
    return pRefused;
}

/* Everything a resume has to hold before the session moves: the ids of the request, a live desktop that could outlive
   its relay route, inside the minute it may live detached, and last, the proof itself. NULL when it all holds. The new
   id may be the old one: a relay that restarted hands its ids out from 1 again. */
static const char* DirectGate_Session_CheckResume(directgate_session_mgr_t *pMgr, directgate_session_t *pSession,
                                                  uint32_t nPrevId, uint32_t nNewId, const char *pProof)
{
    if (!nNewId || !nPrevId || !xstrused(pProof)) return "malformed request";
    if (pMgr->pCfg == NULL || !xstrused(pMgr->pCfg->sDeviceId)) return "device not configured";
    if (nNewId != nPrevId && DirectGate_SessionMgr_Find(pMgr, nNewId) != NULL) return "new id in use";
    if (pSession == NULL) return "no such session";
    if (!DirectGate_Session_CanDetach(pSession)) return "session cannot be resumed";

    if (pSession->bDetached && XTime_GetMonoMs() - pSession->nDetachedMs >= DIRECTGATE_SESSION_DETACHED_MAX_MS)
        return "session expired";

    return DirectGate_Session_CheckResumeProof(pSession, pMgr->pCfg->sDeviceId, nPrevId, nNewId, pProof);
}

/* What the agent answers a valid resume with, sealed under the session's keys at its next counter: the client takes
   the session back on the agent's word, never on that of whoever relays the plaintext "ok" around it. */
static xbool_t DirectGate_Session_SealResumeProof(directgate_session_t *pSession, const char *pDeviceId,
                                                  uint32_t nPrevId, uint32_t nNewId, char *pOut, size_t nOutSize)
{
    xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("auth", nNewId);
    XCHECK((pHeader != NULL), XFALSE);

    xbyte_buffer_t msg;
    XByteBuffer_Init(&msg, XSTDNON, XFALSE);

    xbool_t bOk = XJSON_AddString(pHeader, "action", "resumed") == XJSON_ERR_NONE &&
        XJSON_AddU32(pHeader, "prevSessionId", nPrevId) == XJSON_ERR_NONE &&
        XJSON_AddString(pHeader, "deviceId", pDeviceId) == XJSON_ERR_NONE &&
        DirectGate_Proto_AddCC(pHeader, &pSession->e2e, pSession->webrtc.nSignalGeneration) &&
        DirectGate_Proto_Build(&msg, pHeader, NULL, 0, XFALSE) && DirectGate_Proto_EncryptPackage(&msg, &pSession->e2e, nNewId) &&
        DirectGate_KeyAuth_Base64Encode(msg.pData, msg.nUsed, pOut, nOutSize);

    XJSON_FreeObject(pHeader);
    XByteBuffer_Clear(&msg);
    return bOk;
}

/* Plaintext and on the relay link, as every auth result: the relay lets a client's socket carry session traffic only
   once it has seen an "ok" for its id, and nothing on the data channel is the relay's to see. */
static void DirectGate_Session_SendResumeResult(xapi_session_t *pRelay, uint32_t nSessionId, const char *pProof)
{
    xbool_t bResumed = xstrused(pProof);
    xjson_obj_t *pHeader = DirectGate_Proto_BuildAuthResult(bResumed ? "ok" : "failed", NULL,
        bResumed ? NULL : "resume refused", nSessionId, g_bPreLogon);
    XCHECK_VOID((pHeader != NULL));

    if (bResumed)
    {
        XJSON_AddBool(pHeader, "resume", XTRUE);
        XJSON_AddBool(pHeader, "resumed", XTRUE);
        XJSON_AddString(pHeader, "proof", pProof);
    }

    xbyte_buffer_t msg;
    XByteBuffer_Init(&msg, XSTDNON, XFALSE);

    if (DirectGate_Proto_Build(&msg, pHeader, NULL, 0, XFALSE)) DirectGate_WebSock_SendBuff(pRelay, &msg);

    XJSON_FreeObject(pHeader);
    XByteBuffer_Clear(&msg);
}

int DirectGate_Session_HandleResume(directgate_session_mgr_t *pMgr, xapi_session_t *pRelay, const directgate_pkg_t *pPkg)
{
    XCHECK((pMgr != NULL), XAPI_CONTINUE);
    XCHECK((pRelay != NULL), XAPI_CONTINUE);
    XCHECK((pPkg != NULL), XAPI_CONTINUE);

    xjson_obj_t *pRoot = pPkg->jsonHeader.pRootObj;
    uint32_t nPrevId = XJSON_GetU32(XJSON_GetObject(pRoot, "resumeSid"));
    const char *pProof = XJSON_GetString(XJSON_GetObject(pRoot, "proof"));
    uint32_t nNewId = pPkg->header.nSessionId;

    directgate_session_t *pSession = DirectGate_SessionMgr_Find(pMgr, nPrevId);
    const char *pRefused = DirectGate_Session_CheckResume(pMgr, pSession, nPrevId, nNewId, pProof);

    /* Sealed before anything moves, so a session the answer cannot be built for stays exactly as it was */
    char sProof[((DIRECTGATE_SESSION_RESUME_PROOF_MAX + 2U) / 3U) * 4U + 1U];
    if (pRefused == NULL &&
        !DirectGate_Session_SealResumeProof(pSession, pMgr->pCfg->sDeviceId, nPrevId, nNewId, sProof, sizeof(sProof)))
        pRefused = "answer could not be sealed";

    if (pRefused != NULL)
    {
        xlogw("Session resume refused: sid(%u), prevSid(%u), reason(%s)", nNewId, nPrevId, pRefused);
        DirectGate_Session_SendResumeResult(pRelay, nNewId, NULL);
        return XAPI_CONTINUE;
    }

    uint64_t nNowMs = XTime_GetMonoMs();
    xlogi("Session resumed on a new relay socket: sid(%u), prevSid(%u), detached(%d), detachedMs(%llu)",
        nNewId, nPrevId, pSession->bDetached, pSession->bDetached ? (unsigned long long)(nNowMs - pSession->nDetachedMs) : 0ULL);

    /* Under the same id nothing is in flight under another one, and no alias is kept */
    if (nNewId != nPrevId)
    {
        pSession->nPrevSessionId = nPrevId;
        pSession->nPrevSessionUntilMs = nNowMs + DIRECTGATE_SESSION_RESUME_ALIAS_MS;
    }

    pSession->nSessionId = nNewId;
    pSession->pWsSession = pRelay;
    pSession->bDetached = XFALSE;
    pSession->nDetachedMs = 0;

    DirectGate_Session_SendResumeResult(pRelay, nNewId, sProof);
    return XAPI_CONTINUE;
}
