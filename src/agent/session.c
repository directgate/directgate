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
    DirectGate_E2E_Init(&pSession->e2e);
    DirectGate_WebRTC_Init(&pSession->webrtc);
    DirectGate_Search_Init(&pSession->search);
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
    pSession->bSaveForce = XFALSE;
    pSession->bClosing = XFALSE;
    pSession->pSearchSession = NULL;
    pSession->pPipeSession = NULL;
    pSession->pWsSession = NULL;
    pSession->nSessionId = nSessionId;
    pSession->nCreatedMs = XTime_GetMs();
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

    uint64_t nNowMs = XTime_GetMs();
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
       Session_Remove destroys WebRTC immediately after, racing the async send */
    xjson_obj_t *pHeader = DirectGate_Proto_BuildStatus("closed", pSession->nSessionId);
    if (pHeader != NULL)
    {
        if (pSession->pWsSession != NULL)
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

int DirectGate_Session_Send(directgate_session_t *pSession, xjson_obj_t *pHeader,
                            const uint8_t *pPayload, size_t nPayloadLength)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    XCHECK((pHeader != NULL), XAPI_DISCONNECT);

    xapi_session_t *pApiSession = pSession->pWsSession;
    directgate_webrtc_t *pRTC = &pSession->webrtc;
    directgate_e2e_t *pE2E = &pSession->e2e;

    /* Add packet counter for authenticated sessions */
    if (DirectGate_E2E_IsInitialized(&pSession->e2e))
        XJSON_AddU32(pHeader, "cc", ++pE2E->nTxPacketId);

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
    if (DirectGate_WebRTC_IsConnected(pRTC))
    {
        int nRet = DirectGate_WebRTC_Send(pRTC, msg.pData, msg.nUsed);
        if (nRet >= 0)
        {
            XByteBuffer_Clear(&msg);
            return XSTDOK;
        }

        xlogw("WebRTC send failed, falling back to relay: sid(%u), wsfd(%d)",
            pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

        pRTC->bConnected = XFALSE;
    }

    nStatus = DirectGate_WebSock_Send(pApiSession, msg.pData, msg.nUsed);
    XByteBuffer_Clear(&msg);
    return nStatus;
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

    return DIRECTGATE_SESSION_MODE_NONE;
}

const char* DirectGate_SessionMode_ToString(directgate_session_mode_t eMode)
{
    if (eMode == DIRECTGATE_SESSION_MODE_TERMINAL) return "terminal";
    if (eMode == DIRECTGATE_SESSION_MODE_FILE_MANAGER) return "file-manager";
    return "none";
}

int DirectGate_Session_EnsureMode(directgate_session_t *pSession, directgate_session_mode_t eMode, const char *pReason)
{
    XCHECK_NL((pSession != NULL), XAPI_CONTINUE);

    if (!pSession->bAuthenticated)
    {
        xloge("Session is not authenticated for requested mode: sid(%u), wsfd(%d), required(%s)",
            pSession->nSessionId, DirectGate_Session_GetWsFd(pSession), DirectGate_SessionMode_ToString(eMode));

        DirectGate_Session_Close(pSession, "session not authenticated");
        return XAPI_CONTINUE;
    }

    if (pSession->eActiveMode != eMode)
    {
        xlogw("Session mode mismatch: sid(%u), wsfd(%d), active(%s), required(%s)",
            pSession->nSessionId, DirectGate_Session_GetWsFd(pSession),
            DirectGate_SessionMode_ToString(pSession->eActiveMode),
            DirectGate_SessionMode_ToString(eMode));

        if (xstrused(pReason))
            DirectGate_Session_SendErrorMsg(pSession, pReason);

        return XAPI_CONTINUE;
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

    xjson_obj_t *pHeader = DirectGate_Proto_BuildAuthResult(pStatus, pM2, pReason, pSession->nSessionId);
    XCHECK((pHeader != NULL), xthrowr(XAPI_DISCONNECT, "Proto: Failed to build auth result header"));

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

        return DirectGate_Session_Close(pSession, "pipe registration failed");
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

        return DirectGate_Session_Close(pSession, "search pipe registration failed");
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
        DirectGate_Term_Shutdown(&pSession->term, XTRUE);
        xloge("Failed to register PTY endpoint: sid(%u), wsfd(%d), ptfd(%d)",
            pSession->nSessionId, DirectGate_Session_GetWsFd(pSession), pSession->term.nMasterFd);

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

    if (eMode == DIRECTGATE_SESSION_MODE_NONE)
        return XAPI_CONTINUE;

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
