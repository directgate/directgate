/*!
 * @file directgate-agent/src/agent/directgate.c
 * @brief Agent-side WS client that exposes a PTY over the bridge server.
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "directgate.h"
#include "version.h"
#include "common.h"
#include "protocol.h"
#include "transfer.h"
#include "websock.h"
#include "webrtc.h"
#include "enroll.h"
#include "files.h"
#include "term.h"
#include "e2e.h"
#include "srp.h"

#define DIRECTGATE_RECONNECT_BASE_MS        3000U
#define DIRECTGATE_RECONNECT_MAX_MS         120000U
#define DIRECTGATE_RECONNECT_WAIT_MAX_MS    5000U

/* After this many consecutive failed reconnect attempts, ask the API for a
 * fresh relayUrl. The API returns a different relay if our pinned one is
 * no longer healthy (presence has expired or its :alive is gone). */
#define DIRECTGATE_RECONNECT_REPROBE_AFTER  5U

/* Don't re-probe the API more often than this — a relay that's unreachable
 * to us may briefly reappear in the registry and we don't want to flap. */
#define DIRECTGATE_RECONNECT_REPROBE_GAP_MS 30000U

#define DIRECTGATE_SLEEP_USEC_PER_MS        1000U
#define DIRECTGATE_EVENT_LOOP_WAIT_MS       100U
#define DIRECTGATE_TRANSFER_WAIT_MS         5U
#define DIRECTGATE_TRANSFER_BUDGET          4U
#define DIRECTGATE_TRANSFER_WS_BUFFER_MAX   (8U * 1024U * 1024U)
#define DIRECTGATE_TRANSFER_RTC_BUFFER_MAX  (8U * 1024U * 1024U)
#define DIRECTGATE_RELAY_KA_TIMEOUT_MS      60000ULL

#define DIRECTGATE_NO_ANSWER                "N/A"

static xbool_t g_bFinish = XFALSE;

static int DirectGate_HandleTransportMessage(xapi_session_t *pApiSession,
    const uint8_t *pPayload, size_t nPayload, const char *pTransport);

static int DirectGate_Conn_GetFD(const directgate_conn_t *pConn, xapi_session_t *pApiSession)
{
    if (pApiSession == NULL && pConn != NULL) pApiSession = pConn->pWsSession;
    return pApiSession != NULL ? (int)pApiSession->sock.nFD : (int)XSOCK_INVALID;
}

static uint32_t DirectGate_Conn_GetID(const directgate_conn_t *pConn, xapi_session_t *pApiSession)
{
    if (pApiSession == NULL && pConn != NULL) pApiSession = pConn->pWsSession;
    return pApiSession != NULL ? (uint32_t)pApiSession->nID : 0;
}

static const char* DirectGate_Conn_GetAddr(const directgate_conn_t *pConn, xapi_session_t *pApiSession)
{
    if (pApiSession == NULL && pConn != NULL) pApiSession = pConn->pWsSession;
    if (pApiSession != NULL && xstrused(pApiSession->sAddr)) return pApiSession->sAddr;
    if (pConn != NULL && xstrused(pConn->relayLink.sAddr)) return pConn->relayLink.sAddr;
    return DIRECTGATE_NO_ANSWER;
}

static uint16_t DirectGate_Conn_GetPort(const directgate_conn_t *pConn, xapi_session_t *pApiSession)
{
    if (pApiSession == NULL && pConn != NULL) pApiSession = pConn->pWsSession;
    if (pApiSession != NULL) return pApiSession->nPort;
    if (pConn != NULL) return pConn->relayLink.nPort;
    return 0;
}

static int DirectGate_Session_GetWsFd(const directgate_session_t *pSession)
{
    XCHECK_NL((pSession != NULL), (int)XSOCK_INVALID);
    XCHECK_NL((pSession->pWsSession != NULL), (int)XSOCK_INVALID);
    return (int)pSession->pWsSession->sock.nFD;
}

static xbool_t DirectGate_Session_HasOutboundTransfer(const directgate_session_t *pSession)
{
    XCHECK_NL((pSession != NULL), XFALSE);
    return pSession->transfer.eState == XTRANSFER_STATE_SENDING;
}

static xbool_t DirectGate_Conn_HasOutboundTransfers(const directgate_conn_t *pConn)
{
    XCHECK_NL((pConn != NULL), XFALSE);
    unsigned int i;

    for (i = 0; i < DIRECTGATE_MAX_SESSIONS; i++)
    {
        const directgate_session_t *pSession = pConn->mgr.pSessions[i];
        if (DirectGate_Session_HasOutboundTransfer(pSession)) return XTRUE;
    }

    return XFALSE;
}

static xbool_t DirectGate_Session_IsTransferWritable(const directgate_session_t *pSession)
{
    XCHECK_NL((pSession != NULL), XFALSE);
    XCHECK_NL(DirectGate_Session_HasOutboundTransfer(pSession), XFALSE);

    if (DirectGate_WebRTC_IsConnected(&pSession->webrtc))
    {
        int nBuffered = DirectGate_WebRTC_GetBufferedAmount(&pSession->webrtc);
        if (nBuffered < 0) return XTRUE;
        return (uint32_t)nBuffered < DIRECTGATE_TRANSFER_RTC_BUFFER_MAX;
    }

    XCHECK_NL((pSession->pWsSession != NULL), XFALSE);
    return pSession->pWsSession->txBuffer.nUsed < DIRECTGATE_TRANSFER_WS_BUFFER_MAX;
}

static void DirectGate_PumpOutboundTransfers(directgate_conn_t *pConn)
{
    XCHECK_VOID_NL((pConn != NULL));
    unsigned int i;

    for (i = 0; i < DIRECTGATE_MAX_SESSIONS; i++)
    {
        directgate_session_t *pSession = pConn->mgr.pSessions[i];
        if (!DirectGate_Session_HasOutboundTransfer(pSession)) continue;
        unsigned int j;

        for (j = 0; j < DIRECTGATE_TRANSFER_BUDGET; j++)
        {
            if (!DirectGate_Session_HasOutboundTransfer(pSession)) break;
            if (!DirectGate_Session_IsTransferWritable(pSession)) break;
            DirectGate_Files_ProcessTransfer(pSession);
        }
    }
}

static uint32_t DirectGate_GetServiceWaitMs(const directgate_conn_t *pConn)
{
    return DirectGate_Conn_HasOutboundTransfers(pConn) ?
                        DIRECTGATE_TRANSFER_WAIT_MS :
                        DIRECTGATE_EVENT_LOOP_WAIT_MS;
}

static uint32_t DirectGate_ReconnectDelayMs(uint32_t nAttempt)
{
    uint32_t nDelay = DIRECTGATE_RECONNECT_BASE_MS;

    if (nAttempt > 0)
    {
        uint32_t nShift = nAttempt;
        if (nShift > 10) nShift = 10;
        nDelay = DIRECTGATE_RECONNECT_BASE_MS << nShift;
    }

    if (nDelay > DIRECTGATE_RECONNECT_MAX_MS)
        nDelay = DIRECTGATE_RECONNECT_MAX_MS;

    uint32_t nJitter = nDelay / 4;
    if (nJitter > 0)
    {
        uint32_t nRand = (uint32_t)(XTime_GetMs() % (uint64_t)(nJitter + 1));
        nDelay = (nDelay - nJitter) + nRand;
    }

    return nDelay;
}

static uint32_t DirectGate_ReconnectWaitMs(uint64_t nNextReconnectMs)
{
    uint64_t nNowMs = XTime_GetMs();
    if (nNextReconnectMs == 0 ||
        nNextReconnectMs <= nNowMs)
        return 0;

    uint64_t nWaitMs = nNextReconnectMs - nNowMs;
    if (nWaitMs > DIRECTGATE_RECONNECT_WAIT_MAX_MS)
        nWaitMs = DIRECTGATE_RECONNECT_WAIT_MAX_MS;

    return (uint32_t)nWaitMs;
}

static const char* DirectGate_GetRelayUrl(const directgate_cfg_t *pCfg)
{
    XCHECK_NL((pCfg != NULL), NULL);
    XCHECK_NL(xstrused(pCfg->sRelayUrl), NULL);
    return pCfg->sRelayUrl;
}

static xbool_t DirectGate_IsReconnectSuppressedReason(const char *pReason)
{
    XCHECK_NL((xstrused(pReason)), XFALSE);
    return (xstrcmp(pReason, "device-revoked") ||
            xstrcmp(pReason, "device-enrollment-expired") ||
            xstrcmp(pReason, "device-reenroll") ||
            xstrcmp(pReason, "refresh-token-reuse") ||
            xstrcmp(pReason, "invalid-refresh-token"));
}

static void DirectGate_ClearEnrollmentState(directgate_cfg_t *pCfg)
{
    XCHECK_VOID_NL((pCfg != NULL));
    pCfg->sRelayUrl[0] = XSTR_NUL;
    pCfg->sRoutingKey[0] = XSTR_NUL;

    pCfg->enroll.sAccessToken[0] = XSTR_NUL;
    pCfg->enroll.sRefreshToken[0] = XSTR_NUL;
    pCfg->enroll.sEnrollExpiresAt[0] = XSTR_NUL;

    pCfg->enroll.nAccessTokenExp = 0;
    pCfg->enroll.nRefreshTokenExp = 0;
    pCfg->enroll.bEnrolled = XFALSE;
}

static void DirectGate_SuppressReconnect(directgate_conn_t *pConn, const char *pReason)
{
    XCHECK_VOID_NL((pConn != NULL));
    XCHECK_VOID_NL((pConn->pCfg != NULL));

    const char *pReasonStr = xstrused(pReason) ? pReason : "session invalidated";
    xstrncpy(pConn->sDisconnectReason, sizeof(pConn->sDisconnectReason), pReasonStr);

    pConn->bReconnectSuppressed = XTRUE;
    pConn->nReconnectAttempt = 0;
    pConn->nNextReconnectMs = 0;
    pConn->nNextRefreshProbeMs = 0;

    DirectGate_ClearEnrollmentState(pConn->pCfg);
    if (!DirectGate_SaveConfig(pConn->pCfg))
    {
        xloge("Failed to persist cleared enrollment state: id(%u), fd(%d), reason(%s)",
            DirectGate_Conn_GetID(pConn, NULL), DirectGate_Conn_GetFD(pConn, NULL), pReasonStr);
    }

    xlogw("Reconnect suppressed: id(%u), fd(%d), reason(%s)",
        DirectGate_Conn_GetID(pConn, NULL), DirectGate_Conn_GetFD(pConn, NULL), pReasonStr);
}

static xbool_t DirectGate_HandleRefreshStatus(directgate_conn_t *pConn,
                                              directgate_enroll_status_t eStatus,
                                              const char *pReason,
                                              const char *pStage,
                                              xbool_t bDisconnectSocket)
{
    XCHECK((pConn != NULL), XFALSE);
    XCHECK((pConn->pCfg != NULL), XFALSE);

    if (eStatus == DIRECTGATE_ENROLL_REFRESH_OK) return XTRUE;
    const char *pReasonStr = xstrused(pReason) ? pReason : "token refresh failed";

    if (eStatus == DIRECTGATE_ENROLL_REFRESH_TERMINAL)
    {
        xlogw("%s reached terminal enrollment state: id(%u), fd(%d), reason(%s)",
            xstrused(pStage) ? pStage : "token refresh",
            DirectGate_Conn_GetID(pConn, pConn->pWsSession),
            DirectGate_Conn_GetFD(pConn, pConn->pWsSession),
            pReasonStr);

        DirectGate_SuppressReconnect(pConn, pReasonStr);

        if (bDisconnectSocket && pConn->pWsSession != NULL)
            XAPI_Disconnect(pConn->pWsSession);

        return XFALSE;
    }

    if (DirectGate_Enroll_AccessTokenIsUsable(pConn->pCfg))
    {
        xlogw("%s failed transiently, keeping current access token: id(%u), fd(%d), relay(%s)",
            xstrused(pStage) ? pStage : "token refresh",
            DirectGate_Conn_GetID(pConn, pConn->pWsSession),
            DirectGate_Conn_GetFD(pConn, pConn->pWsSession),
            xstrused(pConn->pCfg->sRelayUrl) ? pConn->pCfg->sRelayUrl : DIRECTGATE_NO_ANSWER);

        return XTRUE;
    }

    xlogw("%s failed and no usable access token remains: id(%u), fd(%d), reason(%s)",
        xstrused(pStage) ? pStage : "token refresh",
        DirectGate_Conn_GetID(pConn, pConn->pWsSession),
        DirectGate_Conn_GetFD(pConn, pConn->pWsSession),
        pReasonStr);

    if (bDisconnectSocket && pConn->pWsSession != NULL)
    {
        xstrncpy(pConn->sDisconnectReason, sizeof(pConn->sDisconnectReason), pReasonStr);
        XAPI_Disconnect(pConn->pWsSession);
    }

    return XFALSE;
}

static xbool_t DirectGate_PrepareEndpoint(directgate_conn_t *pConn, xapi_endpoint_t *pEndpt)
{
    XCHECK((pConn != NULL), XFALSE);
    XCHECK((pEndpt != NULL), XFALSE);
    XCHECK((pConn->pCfg != NULL), XFALSE);

    const directgate_cfg_t *pCfg = pConn->pCfg;
    const char *pRelayUrl = DirectGate_GetRelayUrl(pCfg);

    XCHECK((xstrused(pRelayUrl)), XFALSE);
    XCHECK((xstrused(pCfg->sRoutingKey)), XFALSE);
    XCHECK((xstrused(pCfg->enroll.sAccessToken)), XFALSE);

    if (XLink_Parse(&pConn->relayLink, pRelayUrl) < 0)
    {
        xloge("Failed to parse relay URL: id(%u), fd(%d), relayUrl(%s)",
            DirectGate_Conn_GetID(pConn, NULL), DirectGate_Conn_GetFD(pConn, NULL), pRelayUrl);

        return XFALSE;
    }

    if (!xstrused(pConn->relayLink.sAddr) || !pConn->relayLink.nPort)
    {
        xloge("Invalid relay target: id(%u), fd(%d), relayUrl(%s)",
            DirectGate_Conn_GetID(pConn, NULL), DirectGate_Conn_GetFD(pConn, NULL), pRelayUrl);

        return XFALSE;
    }

    pEndpt->pAddr = pConn->relayLink.sAddr;
    pEndpt->nPort = pConn->relayLink.nPort;
    pEndpt->pUri = pConn->relayLink.sUri;
    pEndpt->bTLS = xstrcmp(pConn->relayLink.sProtocol, "wss");

    /*
    * In debug builds, both WS and WSS endpoints are allowed to simplify
    * local development and testing. Production builds require WSS only.
    *
    * For transparency, the agent always reports whether it is running in a
    * debug or production build, allowing users to verify that transport
    * security requirements have not been relaxed.
    */
#ifndef DIRECTGATE_DEBUG
    if (!pEndpt->bTLS)
    {
        xloge("Unencrypted relay connection not allowed in production mode: id(%u), fd(%d), relayUrl(%s)",
            DirectGate_Conn_GetID(pConn, NULL), DirectGate_Conn_GetFD(pConn, NULL), pRelayUrl);

        return XFALSE;
    }
#endif

    return XTRUE;
}

static xbool_t DirectGate_PreConnectRefresh(directgate_conn_t *pConn)
{
    XCHECK((pConn != NULL), XFALSE);
    XCHECK((pConn->pCfg != NULL), XFALSE);

    directgate_cfg_t *pCfg = pConn->pCfg;
    XCHECK_NL((pCfg->enroll.bEnrolled), XFALSE);

    xbool_t bStartupRefresh = !pConn->bStartupRelayRefreshDone;
    if (!bStartupRefresh && !DirectGate_Enroll_NeedsRefresh(pCfg)) return XTRUE;
    if (bStartupRefresh) pConn->bStartupRelayRefreshDone = XTRUE;

    xlogi("%s access token before connect: id(%u), fd(%d), relay(%s)",
        bStartupRefresh ? "Resolving relay and refreshing" : "Refreshing",
        DirectGate_Conn_GetID(pConn, NULL), DirectGate_Conn_GetFD(pConn, NULL),
        xstrused(pCfg->sRelayUrl) ? pCfg->sRelayUrl : DIRECTGATE_NO_ANSWER);

    char sReason[XSTR_TINY];
    directgate_enroll_status_t eStatus = DirectGate_Enroll_Refresh(pCfg, sReason, sizeof(sReason));

    return DirectGate_HandleRefreshStatus(pConn, eStatus, sReason, bStartupRefresh ?
        "startup relay refresh" : "pre-connect token refresh", XFALSE);
}

/* If reconnects keep failing, ask the API for a fresh relay URL. If presence
 * has expired (≤30 s after the relay died) the API's preferred-device path
 * fails and falls through to registry selection, returning a different
 * relay. Returns XTRUE if we migrated to a new URL. */
static xbool_t DirectGate_TryRelayReprobe(directgate_conn_t *pConn, uint64_t nNowMs)
{
    XCHECK_NL((pConn != NULL), XFALSE);
    XCHECK_NL((pConn->pCfg != NULL), XFALSE);
    XCHECK_NL((pConn->pCfg->enroll.bEnrolled), XFALSE);

    if (pConn->nReconnectAttempt < DIRECTGATE_RECONNECT_REPROBE_AFTER) return XFALSE;
    if (nNowMs < pConn->nNextRefreshProbeMs) return XFALSE;

    char sPrevUrl[XPATH_MAX];
    sPrevUrl[0] = XSTR_NUL;

    pConn->nNextRefreshProbeMs = nNowMs + DIRECTGATE_RECONNECT_REPROBE_GAP_MS;
    if (xstrused(pConn->pCfg->sRelayUrl)) xstrncpy(sPrevUrl, sizeof(sPrevUrl), pConn->pCfg->sRelayUrl);

    char sReason[XSTR_TINY];
    sReason[0] = XSTR_NUL;

    directgate_enroll_status_t eStatus = DirectGate_Enroll_Refresh(pConn->pCfg, sReason, sizeof(sReason));
    if (eStatus != DIRECTGATE_ENROLL_REFRESH_OK)
    {
        xlogw("Relay reprobe via API refresh failed: id(%u), attempt(%u), status(%d), reason(%s)",
            DirectGate_Conn_GetID(pConn, NULL), pConn->nReconnectAttempt, (int)eStatus,
            xstrused(sReason) ? sReason : DIRECTGATE_NO_ANSWER);

        return XFALSE;
    }

    const char *pNewUrl = DirectGate_GetRelayUrl(pConn->pCfg);
    if (!xstrused(pNewUrl) || (xstrused(sPrevUrl) && xstrcmp(pNewUrl, sPrevUrl))) return XFALSE;

    xlogn("Relay migration: id(%u), prev(%s), next(%s)", DirectGate_Conn_GetID(pConn, NULL), sPrevUrl, pNewUrl);

    /* New URL: restart backoff at the base delay so we hit the new relay fast. */
    pConn->nReconnectAttempt = 0;
    return XTRUE;
}

static void DirectGate_ScheduleReconnect(directgate_conn_t *pConn, const char *pReason)
{
    XCHECK_VOID((pConn != NULL));
    XCHECK_VOID_NL((!g_bFinish));
    XCHECK_VOID_NL((!pConn->bReconnectSuppressed));

    uint64_t nNowMs = XTime_GetMs();
    DirectGate_TryRelayReprobe(pConn, nNowMs);

    uint32_t nDelayMs = DirectGate_ReconnectDelayMs(pConn->nReconnectAttempt);
    uint32_t nAttempt = pConn->nReconnectAttempt + 1;

    pConn->nReconnectAttempt = nAttempt;
    pConn->nNextReconnectMs = nNowMs + (uint64_t)nDelayMs;

    const directgate_cfg_t *pCfg = pConn->pCfg;
    const char *pUrl = pCfg != NULL ? DirectGate_GetRelayUrl(pCfg) : NULL;

    xlogi("Reconnect scheduled: id(%u), fd(%d), attempt(%u), delayMs(%u), reason(%s), target(%s)",
        DirectGate_Conn_GetID(pConn, NULL), DirectGate_Conn_GetFD(pConn, NULL), nAttempt, nDelayMs,
        xstrused(pReason) ? pReason : "disconnected", xstrused(pUrl) ? pUrl : DIRECTGATE_NO_ANSWER);
}

static void DirectGate_Connection_Init(directgate_conn_t *pConn, directgate_cfg_t *pCfg)
{
    XCHECK_VOID((pConn != NULL));
    XCHECK_VOID((pCfg != NULL));

    memset(pConn, 0, sizeof(directgate_conn_t));
    DirectGate_SessionMgr_Init(&pConn->mgr, pCfg);
    pConn->pCfg = pCfg;
}

void DirectGate_SignalCallback(int sig)
{
#ifndef _WIN32
    if (sig == SIGPIPE) return;
#endif
    if (sig == SIGINT) printf("\n");
    g_bFinish = XTRUE;
}

static directgate_conn_t* DirectGate_GetConn(xapi_session_t *pApiSession)
{
    XCHECK_NL((pApiSession != NULL), NULL);
    return (directgate_conn_t*)pApiSession->pSessionData;
}

static xbool_t DirectGate_IsDetachedApiSession(xapi_session_t *pApiSession)
{
    return (pApiSession == NULL ||
            pApiSession->eRole == XAPI_INACTIVE ||
            pApiSession->pSessionData == NULL);
}

int DirectGate_LogStatus(xapi_ctx_t *pCtx, xapi_session_t *pSession)
{
    xapi_type_t eType = pCtx ? pCtx->eStatType : XAPI_NONE;
    directgate_conn_t *pConn = DirectGate_GetConn(pSession);
    const char *pType = XAPI_GetTypeStr(eType);
    const char *pStr = XAPI_GetStatus(pCtx);

    if (XAPI_IsDestroyEvent(pCtx)) xlogd("%s status: %s", pType, pStr);
    else xlogd("%s status: %s, id(%u), fd(%d), addr(%s), port(%u)", pType, pStr,
        DirectGate_Conn_GetID(pConn, pSession), DirectGate_Conn_GetFD(pConn, pSession),
        DirectGate_Conn_GetAddr(pConn, pSession), DirectGate_Conn_GetPort(pConn, pSession));

    XCHECK_NL((!g_bFinish), XAPI_CONTINUE);
    XCHECK_NL((pCtx != NULL), XAPI_CONTINUE);
    XCHECK_NL((pSession != NULL), XAPI_CONTINUE);
    XCHECK((pConn != NULL), XAPI_CONTINUE);

    if (pConn->nNextReconnectMs == 0)
    {
        if (pCtx->eStatType == XAPI_SOCK && pCtx->nStatus == XSOCK_EOF)
        {
            if (pConn->pWsSession == pSession) pConn->pWsSession = NULL;
            DirectGate_ScheduleReconnect(pConn, "remote FIN");
        }
        else if (pCtx->eStatType == XAPI_SELF &&
                (pCtx->nStatus == XAPI_CLOSED ||
                 pCtx->nStatus == XAPI_HUNGED))
        {
            if (pConn->pWsSession == pSession) pConn->pWsSession = NULL;
            DirectGate_ScheduleReconnect(pConn, "socket closed");
        }
    }

    return XAPI_CONTINUE;
}

int DirectGate_LogError(xapi_ctx_t *pCtx, xapi_session_t *pSession)
{
    xapi_type_t eType = pCtx ? pCtx->eStatType : XAPI_NONE;
    directgate_conn_t *pConn = DirectGate_GetConn(pSession);
    const char *pType = XAPI_GetTypeStr(eType);
    const char *pStr = XAPI_GetStatus(pCtx);

    xloge("%s error: id(%u), fd(%d), addr(%s), port(%u), errno(%d), status(%s)", pType,
        DirectGate_Conn_GetID(pConn, pSession), DirectGate_Conn_GetFD(pConn, pSession),
        DirectGate_Conn_GetAddr(pConn, pSession), DirectGate_Conn_GetPort(pConn, pSession),
        errno, pStr);

    if (pCtx != NULL &&
        pCtx->eStatType == XAPI_SELF &&
        pCtx->nStatus == XAPI_INVALID_ROLE &&
        DirectGate_IsDetachedApiSession(pSession))
    {
        return XAPI_CONTINUE;
    }

    return XAPI_CONTINUE;
}

static int DirectGate_HandleCustomRead(xapi_session_t *pApiSession)
{
    XCHECK((pApiSession != NULL), XAPI_DISCONNECT);
    XCHECK((pApiSession->pSessionData != NULL), XAPI_DISCONNECT);

    directgate_session_t *pSession = (directgate_session_t*)pApiSession->pSessionData;
    XCHECK_NL((!pSession->bClosing), XAPI_DISCONNECT);

    int nPipeFd = DirectGate_WebRTC_GetPipeFd(&pSession->webrtc);
    int nSearchFd = DirectGate_Search_GetPipeFd(&pSession->search);

    if ((int)pApiSession->sock.nFD == nPipeFd)
    {
        DirectGate_WebRTC_ProcessQueue(&pSession->webrtc);
        return XAPI_CONTINUE;
    }

    if ((int)pApiSession->sock.nFD == nSearchFd)
        return DirectGate_Search_Process(pSession);

    XCHECK(DirectGate_Term_IsRunning(&pSession->term), XAPI_DISCONNECT);
    return DirectGate_Term_OnRead(&pSession->term);
}

static int DirectGate_HandleCustomWrite(xapi_session_t *pApiSession)
{
    XCHECK((pApiSession != NULL), XAPI_DISCONNECT);
    XCHECK((pApiSession->pSessionData != NULL), XAPI_DISCONNECT);

    directgate_session_t *pSession = (directgate_session_t*)pApiSession->pSessionData;
    XCHECK_NL((!pSession->bClosing), XAPI_DISCONNECT);

    int nPipeFd = DirectGate_WebRTC_GetPipeFd(&pSession->webrtc);
    if ((int)pApiSession->sock.nFD == nPipeFd) return XAPI_CONTINUE;

    XCHECK(DirectGate_Term_IsRunning(&pSession->term), XAPI_DISCONNECT);
    return DirectGate_Term_OnWrite(&pSession->term);
}

static int DirectGate_HandleRegistered(xapi_session_t *pApiSession)
{
    XCHECK((pApiSession != NULL), XAPI_DISCONNECT);
    XCHECK_NL((pApiSession->eRole == XAPI_CUSTOM), XAPI_CONTINUE);
    XCHECK((pApiSession->pSessionData != NULL), XAPI_DISCONNECT);

    directgate_session_t *pSession = (directgate_session_t*)pApiSession->pSessionData;
    XCHECK_NL((!pSession->bClosing), XAPI_DISCONNECT);

    int nPipeFd = DirectGate_WebRTC_GetPipeFd(&pSession->webrtc);
    int nSearchFd = DirectGate_Search_GetPipeFd(&pSession->search);

    if ((int)pApiSession->sock.nFD == nPipeFd)
    {
        pSession->pPipeSession = pApiSession;
        return XAPI_CONTINUE;
    }

    if ((int)pApiSession->sock.nFD == nSearchFd)
    {
        pSession->pSearchSession = pApiSession;
        return XAPI_CONTINUE;
    }

    DirectGate_Term_AttachEvent(&pSession->term, pApiSession);
    return XAPI_CONTINUE;
}

static int DirectGate_HandleClosed(xapi_session_t *pApiSession)
{
    XCHECK((pApiSession != NULL), XAPI_DISCONNECT);
    XCHECK_NL((pApiSession->eRole == XAPI_CUSTOM), XAPI_CONTINUE);

    directgate_session_t *pSession = (directgate_session_t*)pApiSession->pSessionData;
    XCHECK_NL((pSession != NULL), XAPI_NO_ACTION);

    int nPipeFd = DirectGate_WebRTC_GetPipeFd(&pSession->webrtc);
    int nSearchFd = DirectGate_Search_GetPipeFd(&pSession->search);
    if ((int)pApiSession->sock.nFD == nPipeFd)
    {
        pSession->webrtc.nPipeFds[0] = -1;
        pSession->pPipeSession = NULL;
        return XAPI_NO_ACTION;
    }

    if ((int)pApiSession->sock.nFD == nSearchFd)
    {
        pSession->search.nPipeFds[0] = XSOCK_INVALID;
        if (pSession->search.nPipeFds[1] != XSOCK_INVALID)
        {
            xclosesock(pSession->search.nPipeFds[1]);
            pSession->search.nPipeFds[1] = XSOCK_INVALID;
        }

        pSession->pSearchSession = NULL;
        return XAPI_NO_ACTION;
    }

    // Detach terminal events to avoid use-after-free
    DirectGate_Term_DetachEvent(&pSession->term);

    if (DirectGate_Term_IsRunning(&pSession->term))
        DirectGate_Term_Shutdown(&pSession->term, XFALSE);

    if (pSession->bClosing)
        return XAPI_NO_ACTION;

    DirectGate_Session_Close(pSession, "terminal exited");
    return XAPI_NO_ACTION;
}

int DirectGate_HandshakeRequest(xapi_ctx_t *pCtx, xapi_session_t *pApiSession)
{
    XCHECK((pCtx != NULL), XAPI_DISCONNECT);
    XCHECK((pApiSession != NULL), XAPI_DISCONNECT);

    xhttp_t *pHandle = (xhttp_t*)pApiSession->pPacket;
    directgate_conn_t *pConn = (directgate_conn_t*)pApiSession->pSessionData;
    XCHECK((pConn != NULL), XAPI_DISCONNECT);

    xlogi("Sending handshake request: id(%u), fd(%d), addr(%s), port(%u), uri(%s), bytes(%zu)",
        DirectGate_Conn_GetID(pConn, pApiSession), DirectGate_Conn_GetFD(pConn, pApiSession),
        DirectGate_Conn_GetAddr(pConn, pApiSession), DirectGate_Conn_GetPort(pConn, pApiSession),
        pHandle->sUri, pHandle->rawData.nUsed);

    const directgate_cfg_t *pCfg = pConn->pCfg;
    XCHECK((pCfg != NULL), XAPI_DISCONNECT);

    /* Keep the pre-role refresh path as a last-minute fallback. */
    if (pCfg->enroll.bEnrolled && DirectGate_Enroll_NeedsRefresh(pCfg))
    {
        xlogi("Refreshing access token before role send: id(%u), fd(%d)",
            DirectGate_Conn_GetID(pConn, pApiSession), DirectGate_Conn_GetFD(pConn, pApiSession));

        char sReason[XSTR_TINY];
        directgate_enroll_status_t eStatus = DirectGate_Enroll_Refresh((directgate_cfg_t*)pCfg, sReason, sizeof(sReason));
        if (!DirectGate_HandleRefreshStatus(pConn, eStatus, sReason, "pre-role token refresh", XTRUE)) return XAPI_DISCONNECT;
    }

    XCHECK(xstrused(pCfg->enroll.sAccessToken),
        xthrowr(XAPI_DISCONNECT, "Missing access token: id(%u), fd(%d), enrolled(%s)",
            DirectGate_Conn_GetID(pConn, pApiSession),
            DirectGate_Conn_GetFD(pConn, pApiSession),
            pCfg->enroll.bEnrolled ? "true" : "false"));

    XCHECK((xstrused(pCfg->sRoutingKey)),
        xthrowr(XAPI_DISCONNECT, "Missing routing key: id(%u), fd(%d)",
            DirectGate_Conn_GetID(pConn, pApiSession), DirectGate_Conn_GetFD(pConn, pApiSession)));

    char sUri[XHTTP_URL_MAX];
    const char *pSep = strchr(pHandle->sUri, '?') != NULL ? "&" : "?";
    xstrncpyf(sUri, sizeof(sUri), "%s%srk=%s", pHandle->sUri, pSep, pCfg->sRoutingKey);
    xstrncpy(pHandle->sUri, sizeof(pHandle->sUri), sUri);

    const uint8_t *pContent = XHTTP_GetBody(pHandle);
    size_t nLength = XHTTP_GetBodySize(pHandle);
    uint8_t *pBuffer = NULL;

    if (nLength > 0)
    {
        pBuffer = (uint8_t*)malloc(nLength);
        XCHECK((pBuffer != NULL), XAPI_DISCONNECT);
        memcpy(pBuffer, pContent, nLength);
    }

    XByteBuffer_Clear(&pHandle->rawData);
    pHandle->nComplete = XFALSE;

    XCHECK((XHTTP_Assemble(pHandle, pBuffer, nLength) != NULL),
        xthrowr(XAPI_DISCONNECT, "Failed to assemble handshake request: id(%u), fd(%d), uri(%s)",
            DirectGate_Conn_GetID(pConn, pApiSession), DirectGate_Conn_GetFD(pConn, pApiSession), pHandle->sUri));

    char *pHeader = XHTTP_GetHeaderRaw(pHandle);
    if (pHeader != NULL)
    {
        xlogd("Handshake request headers: id(%u), fd(%d), uri(%s)\n%s",
            DirectGate_Conn_GetID(pConn, pApiSession),
            DirectGate_Conn_GetFD(pConn, pApiSession),
            pHandle->sUri, pHeader);

        free(pHeader);
    }

    return XAPI_CONTINUE;
}

int DirectGate_HandshakeResponse(xapi_ctx_t *pCtx, xapi_session_t *pApiSession)
{
    XCHECK((pCtx != NULL), XAPI_DISCONNECT);
    XCHECK((pApiSession != NULL), XAPI_DISCONNECT);

    xhttp_t *pHandle = (xhttp_t*)pApiSession->pPacket;
    directgate_conn_t *pConn = (directgate_conn_t*)pApiSession->pSessionData;

    xlogi("Received handshake response: id(%u), fd(%d), addr(%s), port(%u), bytes(%zu)",
        DirectGate_Conn_GetID(pConn, pApiSession), DirectGate_Conn_GetFD(pConn, pApiSession),
        DirectGate_Conn_GetAddr(pConn, pApiSession), DirectGate_Conn_GetPort(pConn, pApiSession),
        pHandle->rawData.nUsed);

    char *pHeader = XHTTP_GetHeaderRaw(pHandle);
    if (pHeader != NULL)
    {
        xlogd("Handshake response headers: fd(%d)\n%s", (int)pApiSession->sock.nFD, pHeader);
        free(pHeader);
    }

    if (pConn != NULL && pConn->pCfg != NULL && !pConn->bRoleSent)
    {
        const directgate_cfg_t *pCfg = pConn->pCfg;
        if (!xstrused(pCfg->sDeviceId))
        {
            xloge("Cannot send agent role, device id is missing: id(%u), fd(%d)",
                DirectGate_Conn_GetID(pConn, pApiSession), DirectGate_Conn_GetFD(pConn, pApiSession));

            return XAPI_CONTINUE;
        }

        xjson_obj_t *pHeader = DirectGate_Proto_BuildRole("agent", pCfg->sDeviceId);
        XCHECK((pHeader != NULL), XAPI_DISCONNECT);

        if (pCfg->enroll.bEnrolled && xstrused(pCfg->enroll.sAccessToken))
            XJSON_AddString(pHeader, "accessToken", pCfg->enroll.sAccessToken);

        xbyte_buffer_t msg;
        XByteBuffer_Init(&msg, XSTDNON, XFALSE);

        /* Role is pre-auth, send directly without cc/encrypt */
        int nStatus = DirectGate_Proto_Build(&msg, pHeader, NULL, 0, XFALSE) ?
                      DirectGate_WebSock_SendBuff(pApiSession, &msg) : XAPI_DISCONNECT;

        if (nStatus >= 0)
        {
            pConn->bRoleSent = XTRUE;
            pConn->nReconnectAttempt = 0;
            pConn->nNextRefreshProbeMs = 0;
        }

        XJSON_FreeObject(pHeader);
        XByteBuffer_Clear(&msg);
        return nStatus;
    }

    return XAPI_CONTINUE;
}

int DirectGate_SendPong(xapi_session_t *pApiSession)
{
    XCHECK((pApiSession != NULL), XAPI_DISCONNECT);
    directgate_conn_t *pConn = (directgate_conn_t*)pApiSession->pSessionData;

    xws_status_t status;
    xws_frame_t frame;

    status = XWebFrame_Create(&frame, NULL, 0, XWS_PONG, XTRUE, XTRUE);
    if (status != XWS_ERR_NONE)
    {
        xloge("Failed to create PONG frame: id(%u), fd(%d), status(%s)",
            DirectGate_Conn_GetID(pConn, pApiSession),
            DirectGate_Conn_GetFD(pConn, pApiSession),
            XWebSock_GetStatusStr(status));

        return XAPI_DISCONNECT;
    }

    xlogd("Sending WS PONG: id(%u), fd(%d), bytes(%zu)",
        DirectGate_Conn_GetID(pConn, pApiSession),
        DirectGate_Conn_GetFD(pConn, pApiSession),
        frame.buffer.nUsed);

    XByteBuffer_AddBuff(&pApiSession->txBuffer, &frame.buffer);
    XWebFrame_Clear(&frame);

    return XAPI_EnableEvent(pApiSession, XPOLLOUT);
}

static int DirectGate_HandleError(xapi_session_t *pApiSession, directgate_pkg_t *pPkg)
{
    const directgate_pkg_error_t *pErrPkg = pPkg != NULL ? (const directgate_pkg_error_t*)pPkg->pPackage : NULL;
    const char *pReason = (pErrPkg && xstrused(pErrPkg->pReason)) ? pErrPkg->pReason : DIRECTGATE_NO_ANSWER;

    directgate_conn_t *pConn = (pApiSession != NULL) ? (directgate_conn_t*)pApiSession->pSessionData : NULL;
    if (pConn != NULL) xstrncpy(pConn->sDisconnectReason, sizeof(pConn->sDisconnectReason), pReason);

    xloge("Received relay error: id(%u), fd(%d), reason(%s)",
        DirectGate_Conn_GetID(pConn, pApiSession),
        DirectGate_Conn_GetFD(pConn, pApiSession),
        pReason);

    if (pConn != NULL && DirectGate_IsReconnectSuppressedReason(pReason))
        DirectGate_SuppressReconnect(pConn, pReason);

    return XAPI_CONTINUE;
}

static int DirectGate_InitConnection(xapi_ctx_t *pCtx, xapi_session_t *pApiSession)
{
    XCHECK((pCtx != NULL), XAPI_DISCONNECT);
    XCHECK((pApiSession != NULL), XAPI_DISCONNECT);

    directgate_conn_t *pConn = (directgate_conn_t*)pApiSession->pSessionData;
    XCHECK((pConn != NULL), xthrowr(XAPI_DISCONNECT, "Invalid connection"));

    if (!DirectGate_SessionMgr_IsEmpty(&pConn->mgr))
    {
        xlogw("Cleaning stale logical sessions before relay connection: id(%u), fd(%d)",
            DirectGate_Conn_GetID(pConn, pApiSession),
            DirectGate_Conn_GetFD(pConn, pApiSession));

        DirectGate_SessionMgr_Destroy(&pConn->mgr);
        XCHECK((DirectGate_SessionMgr_IsEmpty(&pConn->mgr)),
            xthrowr(XAPI_DISCONNECT, "Failed to clean stale logical sessions"));
    }

    xlogn("Connected to relay: id(%u), fd(%d), addr(%s), port(%u)",
        DirectGate_Conn_GetID(pConn, pApiSession), DirectGate_Conn_GetFD(pConn, pApiSession),
        DirectGate_Conn_GetAddr(pConn, pApiSession), DirectGate_Conn_GetPort(pConn, pApiSession));

    pConn->pWsSession = pApiSession;
    pConn->nLastRelayRecvMs = XTime_GetMs();
    pConn->nNextReconnectMs = 0;
    pConn->sDisconnectReason[0] = XSTR_NUL;
    pConn->bStartupRelayRefreshDone = XFALSE;
    pConn->bRoleSent = XFALSE;

    const directgate_cfg_t *pCfg = pConn->pCfg;
    if (pCfg == NULL || !DirectGate_AuthIsConfigured(&pCfg->auth))
    {
        xloge("SRP auth is not configured: id(%u), fd(%d)",
            DirectGate_Conn_GetID(pConn, pApiSession),
            DirectGate_Conn_GetFD(pConn, pApiSession));

        return XAPI_DISCONNECT;
    }

    if (pApiSession->bHandshakeDone)
        return XAPI_SetEvents(pApiSession, XPOLLIN);

    return XAPI_CONTINUE;
}

static int DirectGate_DestroyConnection(xapi_ctx_t *pCtx, xapi_session_t *pApiSession)
{
    XCHECK((pCtx != NULL), XAPI_DISCONNECT);
    XCHECK((pApiSession != NULL), XAPI_DISCONNECT);

    if (pApiSession->eRole == XAPI_CUSTOM)
        return DirectGate_HandleClosed(pApiSession);

    directgate_conn_t *pConn = (directgate_conn_t*)pApiSession->pSessionData;
    if (pConn == NULL)
    {
        xlogw("Ignoring closed API session without connection: role(%d), type(%s), id(%u), fd(%d)",
            (int)pApiSession->eRole, XAPI_GetTypeStr(pApiSession->eType),
            pApiSession->nID, (int)pApiSession->sock.nFD);

        return XAPI_CONTINUE;
    }

    xlogn("Relay connection closed: id(%u), fd(%d), addr(%s), port(%u), reason(%s)",
        DirectGate_Conn_GetID(pConn, pApiSession), DirectGate_Conn_GetFD(pConn, pApiSession),
        DirectGate_Conn_GetAddr(pConn, pApiSession), DirectGate_Conn_GetPort(pConn, pApiSession),
        xstrused(pConn->sDisconnectReason) ? pConn->sDisconnectReason : DIRECTGATE_NO_ANSWER);

    DirectGate_SessionMgr_Destroy(&pConn->mgr);
    pConn->pWsSession = NULL;

    if (pConn->nNextReconnectMs == 0)
        DirectGate_ScheduleReconnect(pConn, "connection closed");

    return XAPI_CONTINUE;
}

static int DirectGate_HandleResize(xapi_session_t *pApiSession, directgate_pkg_t *pPkg)
{
    const directgate_pkg_size_t *pSizePkg = (const directgate_pkg_size_t*)pPkg->pPackage;
    directgate_conn_t *pConn = (directgate_conn_t*)pApiSession->pSessionData;
    XCHECK((pConn != NULL), xthrowr(XAPI_DISCONNECT, "Invalid connection"));

    directgate_session_t *pSession = DirectGate_SessionMgr_Find(&pConn->mgr, pPkg->header.nSessionId);
    XCHECK_NL((pSession != NULL), XAPI_CONTINUE);

    if (DirectGate_Session_EnsureMode(pSession, DIRECTGATE_SESSION_MODE_TERMINAL,
        "terminal session not started") != XSTDOK) return XAPI_CONTINUE;

    struct winsize winSize;
    memset(&winSize, 0, sizeof(winSize));

    winSize.ws_row = (uint16_t)pSizePkg->nRows;
    winSize.ws_col = (uint16_t)pSizePkg->nCols;
    winSize.ws_xpixel = (uint16_t)pSizePkg->nWidth;
    winSize.ws_ypixel = (uint16_t)pSizePkg->nHeight;

    DirectGate_Term_UpdateWinSize(&pSession->term, &winSize);
    return XAPI_CONTINUE;
}

static int DirectGate_HandleCmd(xapi_session_t *pApiSession, directgate_pkg_t *pPkg)
{
    const directgate_pkg_cmd_t *pCmdPkg = (const directgate_pkg_cmd_t*)pPkg->pPackage;
    directgate_conn_t *pConn = (directgate_conn_t*)pApiSession->pSessionData;
    XCHECK((pConn != NULL), xthrowr(XAPI_DISCONNECT, "Invalid connection"));

    if (!xstrused(pCmdPkg->pAction))
    {
        xlogw("Command message is missing action: id(%u), fd(%d), sid(%u)",
            DirectGate_Conn_GetID(pConn, pApiSession),
            DirectGate_Conn_GetFD(pConn, pApiSession),
            pPkg->header.nSessionId);

        return XAPI_CONTINUE;
    }

    if (xstrcmp(pCmdPkg->pAction, "start") && pPkg->header.nSessionId)
    {
        directgate_session_t *pSession = DirectGate_SessionMgr_Find(&pConn->mgr, pPkg->header.nSessionId);
        if (pSession == NULL || !pSession->bAuthenticated)
        {
            xlogw("Start command rejected, session is not authenticated: id(%u), fd(%d), sid(%u)",
                DirectGate_Conn_GetID(pConn, pApiSession),
                DirectGate_Conn_GetFD(pConn, pApiSession),
                pPkg->header.nSessionId);

            return XAPI_CONTINUE;
        }

        pSession->pWsSession = pApiSession;
        directgate_session_mode_t eMode = DirectGate_SessionMode_FromString(pCmdPkg->pMode);

        if (eMode == DIRECTGATE_SESSION_MODE_NONE)
        {
            xlogd("Start command received without mode: sid(%u), wsfd(%d)",
                pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

            return XAPI_CONTINUE;
        }

        pSession->eRequestedMode = eMode;
        return DirectGate_Session_StartMode(pSession, eMode);
    }

    if (xstrcmp(pCmdPkg->pAction, "stop") && pPkg->header.nSessionId)
    {
        directgate_session_t *pSession = DirectGate_SessionMgr_Find(&pConn->mgr, pPkg->header.nSessionId);
        if (pSession != NULL)
        {
            xlogi("Stopping session terminal: sid(%u), wsfd(%d)",
                pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

            DirectGate_Term_RequestStop(&pSession->term);
            pSession->eActiveMode = DIRECTGATE_SESSION_MODE_NONE;
            pSession->eRequestedMode = DIRECTGATE_SESSION_MODE_NONE;
        }

        return XAPI_CONTINUE;
    }

    if (xstrcmp(pCmdPkg->pAction, "getcwd") && pPkg->header.nSessionId)
    {
        directgate_session_t *pSession = DirectGate_SessionMgr_Find(&pConn->mgr, pPkg->header.nSessionId);
        xlogd("Terminal CWD query: sid(%u), wsfd(%d)", pPkg->header.nSessionId, DirectGate_Session_GetWsFd(pSession));

        if (pSession != NULL && DirectGate_Term_IsRunning(&pSession->term))
        {
            char sCwd[XPATH_MAX];
            if (DirectGate_Term_GetCwd(&pSession->term, sCwd, sizeof(sCwd)) >= 0)
            {
#ifdef _WIN32
                /* File-manager paths travel with forward slashes */
                char *pSep = sCwd;
                for (; *pSep != '\0'; pSep++)
                    if (*pSep == '\\') *pSep = '/';
#endif

                xlogi("Terminal CWD query: sid(%u), wsfd(%d), cwd(%s)",
                    pSession->nSessionId, DirectGate_Session_GetWsFd(pSession), sCwd);

                xjson_obj_t *pHeader = DirectGate_Proto_BuildCmd("cwd", NULL, NULL, NULL, pSession->nSessionId);
                if (pHeader != NULL)
                {
                    XJSON_AddString(pHeader, "path", sCwd);
                    DirectGate_Session_Send(pSession, pHeader, NULL, 0);
                    XJSON_FreeObject(pHeader);
                }
            }
            else
            {
                xlogw("Failed to read terminal CWD: sid(%u), wsfd(%d), pid(%d), errno(%d)",
                    pSession->nSessionId, DirectGate_Session_GetWsFd(pSession),
                    (int)pSession->term.nPid, errno);
            }
        }
        else
        {
            xlogw("Terminal CWD query for inactive session: sid(%u)",
                pPkg->header.nSessionId);
        }

        return XAPI_CONTINUE;
    }

    return XAPI_CONTINUE;
}

static int DirectGate_Admin_SendResp(directgate_session_t *pSession, const char *pStatus, const char *pReason)
{
    XCHECK_NL((pSession != NULL), XAPI_CONTINUE);

    xjson_obj_t *pHeader = DirectGate_Proto_BuildAdmin("add-key-result", NULL, pStatus, pReason, pSession->nSessionId);
    XCHECK_NL((pHeader != NULL), xthrowr(XAPI_DISCONNECT, "Proto: Failed to build admin response header"));

    int nStatus = DirectGate_Session_Send(pSession, pHeader, NULL, XSTDNON);
    XJSON_FreeObject(pHeader);
    return nStatus;
}

static int DirectGate_HandleAdmin(xapi_session_t *pApiSession, directgate_pkg_t *pPkg)
{
    const directgate_pkg_admin_t *pAdminPkg = (const directgate_pkg_admin_t*)pPkg->pPackage;
    directgate_conn_t *pConn = (directgate_conn_t*)pApiSession->pSessionData;
    XCHECK((pConn != NULL), xthrowr(XAPI_DISCONNECT, "Invalid connection"));

    directgate_session_t *pSession = DirectGate_SessionMgr_Find(&pConn->mgr, pPkg->header.nSessionId);
    if (pSession == NULL || !pSession->bAuthenticated)
    {
        xloge("Admin message rejected, session is not authenticated: id(%u), fd(%d), sid(%u), action(%s)",
            DirectGate_Conn_GetID(pConn, pApiSession), DirectGate_Conn_GetFD(pConn, pApiSession),
            pPkg->header.nSessionId, pAdminPkg->pAction ? pAdminPkg->pAction : "N/A");

        return XAPI_CONTINUE;
    }

    if (!xstrused(pAdminPkg->pAction))
    {
        xlogw("Admin message is missing action: sid(%u), wsfd(%d)",
            pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

        return DirectGate_Admin_SendResp(pSession, "error", "missing-action");
    }

    if (xstrcmp(pAdminPkg->pAction, "add-key"))
    {
        if (!xstrused(pAdminPkg->pClientPub))
        {
            xlogw("admin/add-key missing clientPub: sid(%u), wsfd(%d)",
                pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

            return DirectGate_Admin_SendResp(pSession, "error", "missing-client-pub");
        }

        directgate_add_key_result_t eResult = DirectGate_AddAuthorizedKey(pConn->pCfg, pAdminPkg->pClientPub);

        if (eResult == DIRECTGATE_ADD_KEY_INVALID)
        {
            xlogw("admin/add-key rejected invalid pubkey: sid(%u), wsfd(%d)",
                pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

            return DirectGate_Admin_SendResp(pSession, "error", "invalid-key");
        }

        if (eResult == DIRECTGATE_ADD_KEY_FULL)
        {
            xloge("admin/add-key rejected, authorizedKeys full: sid(%u), wsfd(%d), max(%d)",
                pSession->nSessionId, DirectGate_Session_GetWsFd(pSession), DIRECTGATE_MAX_AUTHORIZED_KEYS);

            return DirectGate_Admin_SendResp(pSession, "error", "capacity-full");
        }

        if (eResult == DIRECTGATE_ADD_KEY_ALREADY)
        {
            xlogi("admin/add-key already present: sid(%u), wsfd(%d)",
                pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

            return DirectGate_Admin_SendResp(pSession, "already", NULL);
        }

        if (!DirectGate_SaveConfig(pConn->pCfg))
        {
            xloge("admin/add-key failed to persist config: sid(%u), wsfd(%d), cfg(%s)",
                pSession->nSessionId, DirectGate_Session_GetWsFd(pSession),
                pConn->pCfg->sCfgPath);

            return DirectGate_Admin_SendResp(pSession, "error", "persist-failed");
        }

        xlogi("admin/add-key appended authorized key: sid(%u), wsfd(%d), count(%u)",
            pSession->nSessionId, DirectGate_Session_GetWsFd(pSession),
            (unsigned)pConn->pCfg->keyauth.nAuthorizedKeyCount);

        return DirectGate_Admin_SendResp(pSession, "ok", NULL);
    }

    xlogw("Unknown admin action: sid(%u), wsfd(%d), action(%s)",
        pSession->nSessionId, DirectGate_Session_GetWsFd(pSession), pAdminPkg->pAction);

    return DirectGate_Admin_SendResp(pSession, "error", "unknown-action");
}

static int DirectGate_HandleData(xapi_session_t *pApiSession, directgate_pkg_t *pPkg)
{
    const directgate_pkg_data_t *pDataPkg = (const directgate_pkg_data_t*)pPkg->pPackage;
    directgate_conn_t *pConn = (directgate_conn_t*)pApiSession->pSessionData;
    XCHECK((pConn != NULL), xthrowr(XAPI_DISCONNECT, "Invalid connection"));

    directgate_session_t *pSession = DirectGate_SessionMgr_Find(&pConn->mgr, pPkg->header.nSessionId);
    XCHECK_NL((pSession != NULL), XAPI_CONTINUE);

    if (DirectGate_Session_EnsureMode(pSession, DIRECTGATE_SESSION_MODE_TERMINAL,
        "terminal session not started") != XSTDOK) return XAPI_CONTINUE;

    if (pDataPkg->pPayload && pDataPkg->nPayloadLength && !DirectGate_Term_IsRunning(&pSession->term))
    {
        xlogw("Terminal data received while PTY is not running: sid(%u), wsfd(%d), bytes(%zu)",
            pSession->nSessionId, DirectGate_Session_GetWsFd(pSession), pDataPkg->nPayloadLength);

        return XAPI_CONTINUE;
    }

    if (pDataPkg->pPayload && pDataPkg->nPayloadLength)
    {
        if (DirectGate_Term_Write(&pSession->term, pDataPkg->pPayload, pDataPkg->nPayloadLength) < 0)
            return DirectGate_Session_Close(pSession, "PTY: Terminal write failed");
    }

    return XAPI_CONTINUE;
}

static int DirectGate_HandleStatus(xapi_session_t *pApiSession, directgate_pkg_t *pPkg)
{
    const directgate_pkg_status_t *pStatusPkg = (const directgate_pkg_status_t*)pPkg->pPackage;
    directgate_conn_t *pConn = (directgate_conn_t*)pApiSession->pSessionData;
    XCHECK((pConn != NULL), xthrowr(XAPI_DISCONNECT, "Invalid connection"));

    if (xstrused(pStatusPkg->pStatus) && xstrcmp(pStatusPkg->pStatus, "closed"))
    {
        directgate_session_t *pSession = DirectGate_SessionMgr_Find(&pConn->mgr, pPkg->header.nSessionId);
        if (pSession == NULL || !pSession->bAuthenticated)
        {
            xlogw("Closed status rejected, session is not authenticated: id(%u), fd(%d), sid(%u)",
                DirectGate_Conn_GetID(pConn, pApiSession),
                DirectGate_Conn_GetFD(pConn, pApiSession),
                pPkg->header.nSessionId);

            return XAPI_CONTINUE;
        }

        xlogn("Remote client closed session: sid(%u), wsfd(%d)",
            pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

        DirectGate_SessionMgr_Remove(&pConn->mgr, pSession);
    }

    return XAPI_CONTINUE;
}

/* WebRTC signaling callback: parse enqueued JSON string and relay via unified send */
static void DirectGate_WebRTC_SignalCb(const char *pData, size_t nLen, void *pCtx)
{
    directgate_session_t *pSession = (directgate_session_t*)pCtx;
    XCHECK_VOID((pSession != NULL));
    XCHECK_VOID((pData != NULL));
    XCHECK_VOID((nLen > 0));

    xjson_t json;
    if (!XJSON_Parse(&json, NULL, pData, nLen))
    {
        xloge("Failed to parse WebRTC signaling JSON: sid(%u), wsfd(%d), bytes(%zu)",
            pSession->nSessionId, DirectGate_Session_GetWsFd(pSession), nLen);

        return;
    }

    DirectGate_Session_Send(pSession, json.pRootObj, NULL, 0);
    XJSON_Destroy(&json);
}

static void DirectGate_WebRTC_DataCb(const uint8_t *pData, size_t nLen, void *pCtx)
{
    directgate_session_t *pSession = (directgate_session_t*)pCtx;
    XCHECK_VOID((pSession != NULL));
    XCHECK_VOID((pData != NULL));
    XCHECK_VOID((nLen > 0));

    if (pSession->pWsSession == NULL)
    {
        xlogw("Dropping WebRTC message because WS session is not bound: sid(%u), wsfd(%d), bytes(%zu)",
            pSession->nSessionId, DirectGate_Session_GetWsFd(pSession), nLen);

        return;
    }

    DirectGate_HandleTransportMessage(pSession->pWsSession, pData, nLen, "WebRTC");
}

static int DirectGate_HandleWebRTC(xapi_session_t *pApiSession, directgate_pkg_t *pPkg)
{
    const directgate_pkg_webrtc_t *pWebRTC = (const directgate_pkg_webrtc_t*)pPkg->pPackage;
    directgate_conn_t *pConn = (directgate_conn_t*)pApiSession->pSessionData;
    XCHECK((pConn != NULL), xthrowr(XAPI_DISCONNECT, "Invalid connection"));

    directgate_session_t *pSession = DirectGate_SessionMgr_Find(&pConn->mgr, pPkg->header.nSessionId);
    if (pSession == NULL || !pSession->bAuthenticated)
    {
        xlogw("WebRTC signaling rejected, session is not authenticated: id(%u), fd(%d), sid(%u)",
            DirectGate_Conn_GetID(pConn, pApiSession),
            DirectGate_Conn_GetFD(pConn, pApiSession),
            pPkg->header.nSessionId);

        return XAPI_CONTINUE;
    }

    if (!xstrused(pWebRTC->pAction))
    {
        xlogw("WebRTC signaling message is missing action: sid(%u), wsfd(%d)",
            pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

        return XAPI_CONTINUE;
    }

    directgate_webrtc_t *pRTC = &pSession->webrtc;
    const directgate_cfg_t *pCfg = pConn->pCfg;

    if (pRTC->signalCb == NULL)
    {
        pRTC->signalCb = DirectGate_WebRTC_SignalCb;
        pRTC->pSignalCtx = pSession;
        pRTC->dataCb = DirectGate_WebRTC_DataCb;
        pRTC->pDataCtx = pSession;

        if (pCfg != NULL && pCfg->nIceSrvCount > 0)
            DirectGate_WebRTC_SetIceServers(pRTC, pCfg->sIceServers, pCfg->nIceSrvCount);
    }

    if (xstrcmp(pWebRTC->pAction, "offer"))
    {
        xjson_obj_t *pHdrObj = pPkg->jsonHeader.pRootObj;
        const char *pSdp = NULL;

        if (pHdrObj != NULL)
        {
            xjson_obj_t *pSdpObj = XJSON_GetObject(pHdrObj, "sdp");
            if (pSdpObj != NULL) pSdp = XJSON_GetString(pSdpObj);
        }

        if (!xstrused(pSdp))
        {
            xloge("WebRTC offer is missing SDP: sid(%u), wsfd(%d)",
                pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

            return XAPI_CONTINUE;
        }

        xlogi("Received WebRTC offer: sid(%u), wsfd(%d)", pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));
        xlogd("WebRTC offer SDP: sid(%u), wsfd(%d), sdp(%s)", pSession->nSessionId, DirectGate_Session_GetWsFd(pSession), pSdp);

        if (DirectGate_WebRTC_HandleOffer(pRTC, pSdp) < 0)
        {
            xloge("Failed to handle WebRTC offer: sid(%u), wsfd(%d)",
                pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

            return XAPI_CONTINUE;
        }
    }
    else if (xstrcmp(pWebRTC->pAction, "ice"))
    {
        xjson_obj_t *pHdrObj = pPkg->jsonHeader.pRootObj;
        const char *pCandidate = NULL;
        const char *pMid = NULL;

        if (pHdrObj != NULL)
        {
            xjson_obj_t *pCandObj = XJSON_GetObject(pHdrObj, "candidate");
            if (pCandObj != NULL) pCandidate = XJSON_GetString(pCandObj);

            xjson_obj_t *pMidObj = XJSON_GetObject(pHdrObj, "sdpMid");
            if (pMidObj != NULL) pMid = XJSON_GetString(pMidObj);
        }

        if (xstrused(pCandidate))
            DirectGate_WebRTC_HandleIceCandidate(pRTC, pCandidate, pMid);
    }

    return XAPI_CONTINUE;
}

static int DirectGate_HandleAuth(xapi_session_t *pApiSession, directgate_pkg_t *pPkg)
{
    directgate_conn_t *pConn = (directgate_conn_t*)pApiSession->pSessionData;
    XCHECK((pConn != NULL), xthrowr(XAPI_DISCONNECT, "Invalid connection"));

    const directgate_cfg_t *pCfg = pConn->pCfg;
    XCHECK((pCfg != NULL), XAPI_DISCONNECT);

    const directgate_pkg_auth_t *pAuth = (const directgate_pkg_auth_t*)pPkg->pPackage;
    uint32_t nSessId = pPkg->header.nSessionId;

    if (!xstrused(pAuth->pAction))
    {
        xlogw("Auth message is missing action: id(%u), fd(%d), sid(%u)",
            DirectGate_Conn_GetID(pConn, pApiSession), DirectGate_Conn_GetFD(pConn, pApiSession), nSessId);

        return XAPI_CONTINUE;
    }

    directgate_session_t *pSession = DirectGate_SessionMgr_GetOrCreate(&pConn->mgr, pApiSession, nSessId);
    if (pSession == NULL)
    {
        xlogw("Auth message rejected because session limit is reached: id(%u), fd(%d), sid(%u)",
            DirectGate_Conn_GetID(pConn, pApiSession), DirectGate_Conn_GetFD(pConn, pApiSession), nSessId);

        return XAPI_CONTINUE;
    }

    if (pSession->bAuthenticated)
    {
        xlogw("Received duplicate SRP auth message after authentication: sid(%u), wsfd(%d)",
            pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

        DirectGate_Session_SendAuthResp(pSession, "failed", NULL, "already authenticated");
        return XAPI_CONTINUE;
    }

    if (!DirectGate_Session_ConsumeAuthMessage(pSession))
    {
        xlogw("Pre-auth message limit reached: sid(%u), wsfd(%d), max(%u)",
            pSession->nSessionId, DirectGate_Session_GetWsFd(pSession), DIRECTGATE_AUTH_MAX_MESSAGES);

        DirectGate_Session_SendAuthResp(pSession, "failed", NULL, "authentication attempt limit reached");
        return DirectGate_Session_Close(pSession, "authentication attempt limit reached");
    }

    xbool_t bKeyMethod = (xstrused(pAuth->pMethod) && xstrcmp(pAuth->pMethod, "key"));

    if (bKeyMethod && xstrcmp(pAuth->pAction, "hello") && pSession->bKeyAuthActive)
    {
        xlogw("Ignoring duplicate key-auth hello while challenge is pending: sid(%u), wsfd(%d), state(%s)",
            pSession->nSessionId, DirectGate_Session_GetWsFd(pSession),
            DirectGate_KeyAuth_StateName(pSession->keyauth.eState));

        return XAPI_CONTINUE;
    }

    if (bKeyMethod && xstrcmp(pAuth->pAction, "hello"))
    {
        if (!xstrused(pAuth->pDeviceId) ||
            !xstrused(pAuth->pClientPub) ||
            !xstrused(pAuth->pClientEph) ||
            !xstrused(pAuth->pNonce))
        {
            xloge("Key-auth hello is missing required fields: sid(%u), wsfd(%d)",
                pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

            DirectGate_Session_SendAuthResp(pSession, "failed", NULL, "missing key hello fields");
            return XAPI_CONTINUE;
        }

        if (!xstrcmp(pAuth->pDeviceId, pCfg->sDeviceId))
        {
            xloge("Key-auth hello device id mismatch: sid(%u), wsfd(%d), got(%s)",
                pSession->nSessionId, DirectGate_Session_GetWsFd(pSession), pAuth->pDeviceId);

            DirectGate_Session_SendAuthResp(pSession, "failed", NULL, "invalid device ID");
            return XAPI_CONTINUE;
        }

        if (pCfg->keyauth.nAuthorizedKeyCount == 0 ||
            !xstrused(pCfg->keyauth.sIdentitySeedB64) ||
            !xstrused(pCfg->keyauth.sIdentityPubB64))
        {
            xlogw("Key-auth not configured on agent; rejecting so client may fallback: sid(%u), wsfd(%d)",
                pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

            DirectGate_KeyAuth_Cleanse(&pSession->keyauth);
            pSession->bKeyAuthActive = XFALSE;
            DirectGate_Session_SendAuthResp(pSession, "failed", NULL, "key auth not configured");
            return XAPI_CONTINUE;
        }

        if (!DirectGate_KeyAuth_AgentProcessHello(&pSession->keyauth, pAuth->pDeviceId,
                pAuth->pClientPub, pAuth->pClientEph, pAuth->pNonce))
        {
            xloge("Key-auth hello decode failed: sid(%u), wsfd(%d)",
                pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

            DirectGate_KeyAuth_Cleanse(&pSession->keyauth);
            pSession->bKeyAuthActive = XFALSE;
            DirectGate_Session_SendAuthResp(pSession, "failed", NULL, "invalid key hello");
            return XAPI_CONTINUE;
        }

        const char *pAuthorizedKeyPtrs[DIRECTGATE_MAX_AUTHORIZED_KEYS];
        for (uint8_t i = 0; i < pCfg->keyauth.nAuthorizedKeyCount; i++)
            pAuthorizedKeyPtrs[i] = pCfg->keyauth.sAuthorizedKeys[i];

        if (!DirectGate_KeyAuth_IsClientAuthorized(pSession->keyauth.clientPubKey,
                pAuthorizedKeyPtrs, pCfg->keyauth.nAuthorizedKeyCount))
        {
            xlogw("Key-auth client not authorized: sid(%u), wsfd(%d), dev(%s)",
                pSession->nSessionId, DirectGate_Session_GetWsFd(pSession), pAuth->pDeviceId);

            DirectGate_KeyAuth_Cleanse(&pSession->keyauth);
            pSession->bKeyAuthActive = XFALSE;
            DirectGate_Session_SendAuthResp(pSession, "failed", NULL, "client not authorized");
            return XAPI_CONTINUE;
        }

        uint8_t agentIdentitySeed[DIRECTGATE_KEYAUTH_ED25519_SEED_SIZE];
        uint8_t agentIdentityPub[DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE];
        size_t nSeedLen = 0, nPubLen = 0;

        if (!DirectGate_KeyAuth_Base64Decode(pCfg->keyauth.sIdentitySeedB64,
                agentIdentitySeed, sizeof(agentIdentitySeed), &nSeedLen) ||
            nSeedLen != DIRECTGATE_KEYAUTH_ED25519_SEED_SIZE ||
            !DirectGate_KeyAuth_Base64Decode(pCfg->keyauth.sIdentityPubB64,
                agentIdentityPub, sizeof(agentIdentityPub), &nPubLen) ||
            nPubLen != DIRECTGATE_KEYAUTH_ED25519_PUB_SIZE)
        {
            xloge("Agent identity keypair is malformed: sid(%u), wsfd(%d)",
                pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

            OPENSSL_cleanse(agentIdentitySeed, sizeof(agentIdentitySeed));
            DirectGate_KeyAuth_Cleanse(&pSession->keyauth);
            pSession->bKeyAuthActive = XFALSE;

            DirectGate_Session_SendAuthResp(pSession, "failed", NULL, "agent identity malformed");
            return XAPI_CONTINUE;
        }

        char sagentPubB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
        char sagentEphB64[DIRECTGATE_KEYAUTH_PUB_B64_SIZE];
        char sagentNonceHex[(DIRECTGATE_KEYAUTH_NONCE_SIZE * 2) + 1];
        char sChallengeHex[(DIRECTGATE_KEYAUTH_CHALLENGE_SIZE * 2) + 1];
        char sagentSigB64[DIRECTGATE_KEYAUTH_SIG_B64_SIZE];

        xbool_t bBuilt = DirectGate_KeyAuth_AgentBuildChallenge(&pSession->keyauth,
                agentIdentitySeed, agentIdentityPub,
                sagentPubB64, sizeof(sagentPubB64),
                sagentEphB64, sizeof(sagentEphB64),
                sagentNonceHex, sizeof(sagentNonceHex),
                sChallengeHex, sizeof(sChallengeHex),
                sagentSigB64, sizeof(sagentSigB64));

        OPENSSL_cleanse(agentIdentitySeed, sizeof(agentIdentitySeed));

        if (!bBuilt)
        {
            xloge("Failed to build key-auth challenge: sid(%u), wsfd(%d)",
                pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

            DirectGate_KeyAuth_Cleanse(&pSession->keyauth);
            pSession->bKeyAuthActive = XFALSE;

            DirectGate_Session_SendAuthResp(pSession, "failed", NULL, "agent error");
            return XAPI_CONTINUE;
        }

        xjson_obj_t *pChal = DirectGate_Proto_BuildAuthKeyChallenge(
            sagentPubB64, sagentEphB64, sagentNonceHex, sChallengeHex, sagentSigB64, nSessId);
        XCHECK((pChal != NULL), xthrowr(XAPI_DISCONNECT, "Key-auth: challenge build failed"));

        XCHECK_CALL((DirectGate_Session_Send(pSession, pChal, NULL, 0) >= 0),
            XJSON_FreeObject, pChal, xthrowr(XAPI_DISCONNECT, "Key-auth: challenge send failed"));

        XJSON_FreeObject(pChal);
        pSession->bKeyAuthActive = XTRUE;
        return XAPI_CONTINUE;
    }

    if (pSession->bKeyAuthActive && xstrcmp(pAuth->pAction, "proof"))
    {
        if (!xstrused(pAuth->pClientSig))
        {
            xloge("Key-auth proof is missing clientSig: sid(%u), wsfd(%d)",
                pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

            DirectGate_Session_SendAuthResp(pSession, "failed", NULL, "missing clientSig");
            return DirectGate_Session_Close(pSession, "key-auth proof missing signature");
        }

        if (!DirectGate_KeyAuth_AgentVerifyProof(&pSession->keyauth, pAuth->pClientSig))
        {
            xloge("Key-auth proof verification failed: sid(%u), wsfd(%d)",
                pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

            DirectGate_KeyAuth_Cleanse(&pSession->keyauth);
            pSession->bKeyAuthActive = XFALSE;

            DirectGate_Session_SendAuthResp(pSession, "failed", NULL, "invalid proof");
            return DirectGate_Session_Close(pSession, "key-auth proof failed");
        }

        if (!DirectGate_KeyAuth_DeriveShared(&pSession->keyauth))
        {
            xloge("Key-auth shared secret derivation failed: sid(%u), wsfd(%d)",
                pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

            DirectGate_KeyAuth_Cleanse(&pSession->keyauth);
            pSession->bKeyAuthActive = XFALSE;

            return DirectGate_Session_Close(pSession, "key-auth ECDH failed");
        }

        xlogn("Key-auth handshake completed: sid(%u), wsfd(%d)",
            pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

        /* M2 equivalent: plain "ok" result is sent BEFORE enabling encryption
           so client can mirror the SRP fallback's ordering and fully verify
           before the first encrypted payload. */
        if (DirectGate_Session_SendAuthResp(pSession, "ok", NULL, NULL) < 0)
        {
            xloge("Failed to send key-auth response: sid(%u), wsfd(%d)",
                pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

            return DirectGate_Session_Close(pSession, "key-auth response send failed");
        }

        if (!DirectGate_Session_DeriveE2EFromKey(pSession, pCfg->sDeviceId))
        {
            xloge("Failed to derive E2E keys from key-auth: sid(%u), wsfd(%d)",
                pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

            return DirectGate_Session_Close(pSession, "E2E key derivation failed");
        }

        DirectGate_KeyAuth_Cleanse(&pSession->keyauth);
        pSession->bKeyAuthActive = XFALSE;
        pSession->bAuthenticated = XTRUE;
        pSession->term.bEncrypt = XTRUE;

        if (pSession->eRequestedMode != DIRECTGATE_SESSION_MODE_NONE)
            return DirectGate_Session_StartMode(pSession, pSession->eRequestedMode);

        return XAPI_CONTINUE;
    }

    if (xstrcmp(pAuth->pAction, "hello"))
    {
        if (!DirectGate_AuthIsConfigured(&pCfg->auth))
        {
            xlogw("SRP hello received but SRP is not configured: sid(%u), wsfd(%d)",
                pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

            DirectGate_Session_SendAuthResp(pSession, "failed", NULL, "srp not configured");
            return XAPI_CONTINUE;
        }

        if (!xstrused(pAuth->pDeviceId))
        {
            xloge("SRP hello is missing device id: sid(%u), wsfd(%d)",
                pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

            DirectGate_Session_SendAuthResp(pSession, "failed", NULL, "missing device ID");
            return XAPI_CONTINUE;
        }

        if (!xstrused(pAuth->pA))
        {
            xloge("SRP hello is missing client public value: sid(%u), wsfd(%d)",
                pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

            DirectGate_Session_SendAuthResp(pSession, "failed", NULL, "missing A");
            return XAPI_CONTINUE;
        }

        if (!xstrused(pAuth->pNonce))
        {
            xloge("SRP hello is missing client nonce: sid(%u), wsfd(%d)",
                pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

            DirectGate_Session_SendAuthResp(pSession, "failed", NULL, "missing nonce");
            return XAPI_CONTINUE;
        }

        if (!xstrcmp(pAuth->pDeviceId, pCfg->sDeviceId))
        {
            xloge("SRP hello device id mismatch: sid(%u), wsfd(%d), got(%s)",
                pSession->nSessionId, DirectGate_Session_GetWsFd(pSession), pAuth->pDeviceId);

            DirectGate_Session_SendAuthResp(pSession, "failed", NULL, "invalid device ID");
            return XAPI_CONTINUE;
        }

        size_t nNonceLen = 0;
        if (!DirectGate_SRP_HexToBytes(pAuth->pNonce, pSession->srp.clientNonce,
                                   sizeof(pSession->srp.clientNonce), &nNonceLen) ||
                                   nNonceLen != DIRECTGATE_SRP_NONCE_SIZE)
        {
            xloge("Invalid SRP client nonce: sid(%u), wsfd(%d)",
                pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

            DirectGate_Session_SendAuthResp(pSession, "failed", NULL, "invalid nonce");
            return XAPI_CONTINUE;
        }

        char sBHex[1024];
        char sNonceHex[(DIRECTGATE_SRP_NONCE_SIZE * 2) + 1];
        xstrncpy(pSession->srp.sDeviceId, sizeof(pSession->srp.sDeviceId), pAuth->pDeviceId);

        if (!DirectGate_SRP_SetClientPublic(&pSession->srp, pAuth->pA))
        {
            xloge("Invalid SRP client public value: sid(%u), wsfd(%d)",
                pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

            DirectGate_Session_SendAuthResp(pSession, "failed", NULL, "invalid A");
            return XAPI_CONTINUE;
        }

        if (!DirectGate_SRP_GenerateChallenge(&pSession->srp, sBHex, sizeof(sBHex), sNonceHex, sizeof(sNonceHex)))
        {
            xloge("Failed to generate SRP challenge: sid(%u), wsfd(%d)",
                pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

            DirectGate_Session_SendAuthResp(pSession, "failed", NULL, "agent error");
            return XAPI_CONTINUE;
        }

        xjson_obj_t *pChal = DirectGate_Proto_BuildAuthChallenge(pCfg->auth.sSaltHex, sBHex, sNonceHex, pCfg->auth.nSuite, nSessId);
        XCHECK((pChal != NULL), xthrowr(XAPI_DISCONNECT, "SRP: Failed to build auth challenge header"));

        XCHECK_CALL((DirectGate_Session_Send(pSession, pChal, NULL, 0) >= 0),
            XJSON_FreeObject, pChal, xthrowr(XAPI_DISCONNECT, "SRP: Failed to send auth challenge"));

        XJSON_FreeObject(pChal);
        return XAPI_CONTINUE;
    }

    if (xstrcmp(pAuth->pAction, "proof"))
    {
        if (!xstrused(pAuth->pM1))
        {
            xloge("SRP proof is missing M1: sid(%u), wsfd(%d)",
                pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

            DirectGate_Session_SendAuthResp(pSession, "failed", NULL, "missing M1");
            return DirectGate_Session_Close(pSession, "SRP proof missing M1");
        }

        char sM2Hex[128];
        if (!DirectGate_SRP_VerifyClientProof(&pSession->srp, pAuth->pM1, sM2Hex, sizeof(sM2Hex)))
        {
            xloge("SRP proof verification failed: sid(%u), wsfd(%d)",
                pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

            DirectGate_Session_SendAuthResp(pSession, "failed", NULL, "invalid proof");
            return DirectGate_Session_Close(pSession, "SRP proof failed");
        }

        xlogn("SRP authentication completed: sid(%u), wsfd(%d)",
            pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

        /* Send auth result with M2 BEFORE deriving E2E keys, because the
           client needs M2 to derive its own keys and cannot yet decrypt. */
        if (DirectGate_Session_SendAuthResp(pSession, "ok", sM2Hex, NULL) < 0)
        {
            xloge("Failed to send SRP auth response: sid(%u), wsfd(%d)",
                pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

            return DirectGate_Session_Close(pSession, "auth response send failed");
        }

        if (!DirectGate_Session_DeriveE2EFromSRP(pSession, pCfg->sDeviceId))
        {
            xloge("Failed to derive E2E keys from SRP: sid(%u), wsfd(%d)",
                pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

            return DirectGate_Session_Close(pSession, "E2E key derivation failed");
        }

        pSession->bAuthenticated = XTRUE;
        pSession->term.bEncrypt = XTRUE;

        if (pSession->eRequestedMode != DIRECTGATE_SESSION_MODE_NONE)
            return DirectGate_Session_StartMode(pSession, pSession->eRequestedMode);

        return XAPI_CONTINUE;
    }

    xlogw("Unexpected SRP auth action: sid(%u), wsfd(%d), action(%s)",
        pSession->nSessionId, DirectGate_Session_GetWsFd(pSession), pAuth->pAction);

    DirectGate_Session_SendAuthResp(pSession, "failed", NULL, "unexpected action");
    return DirectGate_Session_Close(pSession, "unexpected auth action");
}

static int DirectGate_HandleVerify(xapi_session_t *pApiSession, directgate_pkg_t *pPkg)
{
    (void)pApiSession;
    const directgate_pkg_verify_t *pVerify = (const directgate_pkg_verify_t*)pPkg->pPackage;
    directgate_conn_t *pConn = (directgate_conn_t*)pApiSession->pSessionData;

    if (!xstrused(pVerify->pAction))
    {
        xlogw("Verify message is missing action: id(%u), fd(%d)",
            DirectGate_Conn_GetID(pConn, pApiSession), DirectGate_Conn_GetFD(pConn, pApiSession));

        return XAPI_CONTINUE;
    }

    if (xstrcmp(pVerify->pAction, "ack"))
    {
        const char *pReqId = xstrused(pVerify->pRequestId) ? pVerify->pRequestId : DIRECTGATE_NO_ANSWER;
        const char *pReason = xstrused(pVerify->pReason) ? pVerify->pReason : DIRECTGATE_NO_ANSWER;

        if (xstrused(pVerify->pStatus) && xstrcmp(pVerify->pStatus, "ok"))
        {
            xlogi("Token update acknowledged: id(%u), fd(%d), reqId(%s), exp(%lu)",
                DirectGate_Conn_GetID(pConn, pApiSession),
                DirectGate_Conn_GetFD(pConn, pApiSession),
                pReqId, (unsigned long)pVerify->nExp);
        }
        else
        {
            xloge("Token update rejected: id(%u), fd(%d), reqId(%s), reason(%s)",
                DirectGate_Conn_GetID(pConn, pApiSession),
                DirectGate_Conn_GetFD(pConn, pApiSession),
                pReqId, pReason);
        }
    }

    return XAPI_CONTINUE;
}

static int DirectGate_HandleKeepalive(xapi_session_t *pApiSession, directgate_pkg_t *pPkg)
{
    const directgate_pkg_keepalive_t *pKAPkg = (const directgate_pkg_keepalive_t*)pPkg->pPackage;
    directgate_conn_t *pConn = (directgate_conn_t*)pApiSession->pSessionData;
    XCHECK((pConn != NULL), xthrowr(XAPI_DISCONNECT, "Invalid connection"));

    if (!xstrused(pKAPkg->pAction))
    {
        xlogw("Keepalive message is missing action: id(%u), fd(%d), sid(%u)",
            DirectGate_Conn_GetID(pConn, pApiSession),
            DirectGate_Conn_GetFD(pConn, pApiSession),
            pPkg->header.nSessionId);

        return XAPI_CONTINUE;
    }

    directgate_session_t *pSession = DirectGate_SessionMgr_Find(&pConn->mgr, pPkg->header.nSessionId);
    XCHECK_NL((pSession != NULL), XAPI_CONTINUE);

    if (xstrcmp(pKAPkg->pAction, "pong"))
    {
        xlogd("Received keepalive pong: sid(%u), wsfd(%d)",
            pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

        pSession->nLastKAPongMs = XTime_GetMs();
    }
    else if (xstrcmp(pKAPkg->pAction, "ping"))
    {
        xlogd("Received keepalive ping, sending pong: sid(%u), wsfd(%d)",
            pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

        return DirectGate_Session_SendKeepalive(pSession, "pong");
    }

    return XAPI_CONTINUE;
}

static int DirectGate_DispatchMessage(xapi_session_t *pApiSession, directgate_pkg_t *pPkg)
{
    XCHECK((pPkg != NULL), XAPI_DISCONNECT);
    XCHECK((pApiSession != NULL), XAPI_DISCONNECT);
    XCHECK((pPkg->pPackage != NULL), XAPI_DISCONNECT);

    if (xstrcmp(pPkg->header.pType, "error")) return DirectGate_HandleError(pApiSession, pPkg);
    if (xstrcmp(pPkg->header.pType, "auth")) return DirectGate_HandleAuth(pApiSession, pPkg);
    if (xstrcmp(pPkg->header.pType, "verify")) return DirectGate_HandleVerify(pApiSession, pPkg);
    if (xstrcmp(pPkg->header.pType, "status")) return DirectGate_HandleStatus(pApiSession, pPkg);
    if (xstrcmp(pPkg->header.pType, "resize")) return DirectGate_HandleResize(pApiSession, pPkg);
    if (xstrcmp(pPkg->header.pType, "webrtc")) return DirectGate_HandleWebRTC(pApiSession, pPkg);
    if (xstrcmp(pPkg->header.pType, "cmd")) return DirectGate_HandleCmd(pApiSession, pPkg);
    if (xstrcmp(pPkg->header.pType, "data")) return DirectGate_HandleData(pApiSession, pPkg);
    if (xstrcmp(pPkg->header.pType, "file")) return DirectGate_Files_HandleFile(pApiSession, pPkg);
    if (xstrcmp(pPkg->header.pType, "manager")) return DirectGate_Files_HandleManager(pApiSession, pPkg);
    if (xstrcmp(pPkg->header.pType, "admin")) return DirectGate_HandleAdmin(pApiSession, pPkg);
    if (xstrcmp(pPkg->header.pType, "keepalive")) return DirectGate_HandleKeepalive(pApiSession, pPkg);

    directgate_conn_t *pConn = (directgate_conn_t*)pApiSession->pSessionData;
    xlogw("Unknown protocol message type: id(%u), fd(%d), type(%s), sid(%u)",
        DirectGate_Conn_GetID(pConn, pApiSession),
        DirectGate_Conn_GetFD(pConn, pApiSession),
        pPkg->header.pType, pPkg->header.nSessionId);

    return XAPI_CONTINUE;
}

static int DirectGate_HandleEncryptedMsg(xapi_session_t *pApiSession, directgate_pkg_t *pPkg,
                                     const char *pTransport)
{
    directgate_conn_t *pConn = (directgate_conn_t*)pApiSession->pSessionData;
    XCHECK((pConn != NULL), xthrowr(XAPI_DISCONNECT, "Invalid connection"));

    directgate_session_t *pSession = DirectGate_SessionMgr_Find(&pConn->mgr, pPkg->header.nSessionId);
    if (pSession == NULL || !DirectGate_E2E_IsInitialized(&pSession->e2e))
    {
        xloge("Received encrypted %s message without session E2E context: id(%u), fd(%d), sid(%u)",
            xstrused(pTransport) ? pTransport : "transport",
            DirectGate_Conn_GetID(pConn, pApiSession),
            DirectGate_Conn_GetFD(pConn, pApiSession),
            pPkg->header.nSessionId);

        return XAPI_CONTINUE;
    }

    xbyte_buffer_t inner;
    XByteBuffer_Init(&inner, XSTDNON, XFALSE);

    if (!DirectGate_Proto_DecryptPackage(&inner, pPkg, &pSession->e2e))
    {
        xloge("Failed to decrypt %s message: sid(%u), wsfd(%d)",
            xstrused(pTransport) ? pTransport : "transport",
            pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

        XByteBuffer_Clear(&inner);
        return XAPI_CONTINUE;
    }

    directgate_pkg_t innerPkg;
    if (!DirectGate_Package_Parse(&innerPkg, inner.pData, inner.nUsed))
    {
        xloge("Failed to parse decrypted %s message: sid(%u), wsfd(%d), bytes(%zu)",
            xstrused(pTransport) ? pTransport : "transport",
            pSession->nSessionId, DirectGate_Session_GetWsFd(pSession), inner.nUsed);

        XByteBuffer_Clear(&inner);
        return XAPI_CONTINUE;
    }

    uint32_t nInnerSessionId = innerPkg.header.nSessionId;
    if (!DirectGate_Proto_BindInnerSessionId(pPkg->header.nSessionId, &innerPkg))
    {
        xloge("Encrypted %s session id mismatch: sid(%u), innerSid(%u), wsfd(%d)",
            xstrused(pTransport) ? pTransport : "transport",
            pPkg->header.nSessionId, nInnerSessionId, DirectGate_Session_GetWsFd(pSession));

        DirectGate_Package_Clear(&innerPkg);
        XByteBuffer_Clear(&inner);
        return DirectGate_Session_Close(pSession, "encrypted session id mismatch");
    }

    int nStatus = DirectGate_DispatchMessage(pApiSession, &innerPkg);
    DirectGate_Package_Clear(&innerPkg);
    XByteBuffer_Clear(&inner);

    return nStatus;
}

static xbool_t DirectGate_RequiresEncryption(directgate_conn_t *pConn, directgate_pkg_t *pPkg)
{
    XCHECK((pConn != NULL), xthrowr(XSTDERR, "Invalid session pointer"));
    XCHECK((pPkg != NULL), xthrowr(XSTDERR, "Invalid message pointer"));
    XCHECK_NL(pPkg->header.nSessionId, XFALSE);

    directgate_session_t *pSession = DirectGate_SessionMgr_Find(&pConn->mgr, pPkg->header.nSessionId);
    if (pSession == NULL || !pSession->bAuthenticated) return XFALSE;

    /*
    * Error, status and verify messages are generated by the relay and are intentionally
    * not encrypted. They contain no sensitive information and are used solely for
    * relay-side status reporting such as disconnect notices, errors in the network, etc.
    *
    * This does not weaken the security model: a compromised relay could already
    * drop the connection entirely, so sending a disconnect notification provides
    * no additional capability beyond denial of service.
    */

    return (xstrcmp(pPkg->header.pType, "cmd") ||
            xstrcmp(pPkg->header.pType, "auth") ||
            xstrcmp(pPkg->header.pType, "data") ||
            xstrcmp(pPkg->header.pType, "file") ||
            xstrcmp(pPkg->header.pType, "manager") ||
            xstrcmp(pPkg->header.pType, "resize") ||
            xstrcmp(pPkg->header.pType, "webrtc") ||
            xstrcmp(pPkg->header.pType, "role") ||
            xstrcmp(pPkg->header.pType, "admin") ||
            xstrcmp(pPkg->header.pType, "keepalive"));
}

static int DirectGate_HandleTransportMessage(xapi_session_t *pApiSession,
                                             const uint8_t *pPayload,
                                             size_t nPayload,
                                             const char *pTransport)
{
    XCHECK((pApiSession != NULL), xthrowr(XAPI_DISCONNECT, "Invalid API session"));
    XCHECK((pPayload != NULL), XAPI_CONTINUE);
    XCHECK((nPayload > 0), XAPI_CONTINUE);

    directgate_conn_t *pConn = (directgate_conn_t*)pApiSession->pSessionData;
    XCHECK((pConn != NULL), xthrowr(XAPI_DISCONNECT, "Invalid connection"));

    int nStatus = XAPI_CONTINUE;
    directgate_pkg_t pkg;

    if (!DirectGate_Package_Parse(&pkg, pPayload, nPayload))
    {
        xlogw("Invalid protocol message from %s: id(%u), fd(%d), bytes(%zu)",
            xstrused(pTransport) ? pTransport : "transport",
            DirectGate_Conn_GetID(pConn, pApiSession),
            DirectGate_Conn_GetFD(pConn, pApiSession),
            nPayload);

        return XAPI_DISCONNECT;
    }

    if (!xstrused(pkg.header.pType))
    {
        xlogw("%s message is missing type: id(%u), fd(%d)",
            xstrused(pTransport) ? pTransport : "Transport",
            DirectGate_Conn_GetID(pConn, pApiSession),
            DirectGate_Conn_GetFD(pConn, pApiSession));

        DirectGate_Package_Clear(&pkg);
        return XAPI_CONTINUE;
    }

    if (xstrcmp(pkg.header.pType, "encrypted"))
    {
        xlogt("Dispatching encrypted %s message: id(%u), fd(%d), sid(%u)",
            xstrused(pTransport) ? pTransport : "transport",
            DirectGate_Conn_GetID(pConn, pApiSession),
            DirectGate_Conn_GetFD(pConn, pApiSession),
            pkg.header.nSessionId);

        nStatus = DirectGate_HandleEncryptedMsg(pApiSession, &pkg, pTransport);
    }
    else if (DirectGate_RequiresEncryption(pConn, &pkg))
    {
        xloge("Protocol violation, expected encrypted %s message: id(%u), fd(%d), type(%s), sid(%u)",
            xstrused(pTransport) ? pTransport : "transport",
            DirectGate_Conn_GetID(pConn, pApiSession),
            DirectGate_Conn_GetFD(pConn, pApiSession),
            pkg.header.pType, pkg.header.nSessionId);

        nStatus = XAPI_CONTINUE;
    }
    else
    {
        xlogt("Dispatching unencrypted %s message: id(%u), fd(%d), sid(%u)",
            xstrused(pTransport) ? pTransport : "transport",
            DirectGate_Conn_GetID(pConn, pApiSession),
            DirectGate_Conn_GetFD(pConn, pApiSession),
            pkg.header.nSessionId);

        nStatus = DirectGate_DispatchMessage(pApiSession, &pkg);
    }

    DirectGate_Package_Clear(&pkg);
    return nStatus;
}

#ifdef DIRECTGATE_TESTING
int DirectGate_TestHandleTransportMessage(xapi_session_t *pApiSession,
                                          const uint8_t *pPayload,
                                          size_t nPayload)
{
    return DirectGate_HandleTransportMessage(pApiSession, pPayload, nPayload, "test");
}
#endif

int DirectGate_HandleFrame(xapi_ctx_t *pCtx, xapi_session_t *pApiSession)
{
    XCHECK((pApiSession != NULL), xthrowr(XAPI_DISCONNECT, "Invalid session pointer"));
    if (pApiSession->eRole == XAPI_CUSTOM) return DirectGate_HandleCustomRead(pApiSession);

    directgate_conn_t *pConn = (directgate_conn_t*)pApiSession->pSessionData;
    xws_frame_t *pFrame = (xws_frame_t*)pApiSession->pPacket;
    (void)pCtx;

    XCHECK((pConn != NULL), xthrowr(XAPI_DISCONNECT, "Invalid connection"));
    XCHECK((pFrame != NULL), xthrowr(XAPI_DISCONNECT, "Invalid frame"));
    pConn->nLastRelayRecvMs = XTime_GetMs();

    xlogd("Received WS frame: id(%u), fd(%d), type(%s), fin(%s), hdr(%zu), pl(%zu), bytes(%zu)",
        DirectGate_Conn_GetID(pConn, pApiSession), DirectGate_Conn_GetFD(pConn, pApiSession),
        XWS_FrameTypeStr(pFrame->eType), pFrame->bFin ? "true" : "false",
        pFrame->nHeaderSize, pFrame->nPayloadLength, pFrame->buffer.nUsed);

    if (pFrame->eType == XWS_PING) return DirectGate_SendPong(pApiSession);
    if (pFrame->eType == XWS_CLOSE) return XAPI_DISCONNECT;

    const uint8_t* pPayload = XWebFrame_GetPayload(pFrame);
    size_t nPayload = pFrame->nPayloadLength;

    if (pPayload == NULL || !nPayload) return XAPI_CONTINUE;
    if (pFrame->eType != XWS_BINARY) return XAPI_CONTINUE;

    return DirectGate_HandleTransportMessage(pApiSession, pPayload, nPayload, "relay");
}

int DirectGate_SendFrame(xapi_ctx_t *pCtx, xapi_session_t *pApiSession)
{
    XCHECK((pApiSession != NULL), XAPI_DISCONNECT);
    XCHECK((pCtx != NULL), XAPI_DISCONNECT);

    if (pApiSession->eRole == XAPI_CUSTOM)
        return DirectGate_HandleCustomWrite(pApiSession);

    return XAPI_NO_ACTION;
}

static int DirectGate_HandleInterrupt(xapi_ctx_t *pCtx, xapi_session_t *pApiSession)
{
    (void)pApiSession;
    if (g_bFinish) return XAPI_DISCONNECT;
    XCHECK((pCtx != NULL), XAPI_DISCONNECT);
    return XAPI_CONTINUE;
}

static int DirectGate_HandleTick(xapi_ctx_t *pCtx, xapi_session_t *pApiSession)
{
    (void)pApiSession;
    if (g_bFinish) return XAPI_DISCONNECT;
    XCHECK((pCtx != NULL), XAPI_DISCONNECT);

    directgate_conn_t *pConn = (directgate_conn_t*)pCtx->pApi->pUserCtx;
    if (pConn != NULL) DirectGate_PumpOutboundTransfers(pConn);

    return XAPI_CONTINUE;
}

static int DirectGate_HandleComplete(xapi_ctx_t *pCtx, xapi_session_t *pApiSession)
{
    XCHECK((pCtx != NULL), XAPI_DISCONNECT);
    XCHECK((pApiSession != NULL), XAPI_DISCONNECT);

    directgate_conn_t *pConn = (directgate_conn_t*)pApiSession->pSessionData;
    XCHECK_NL((pConn != NULL), XAPI_CONTINUE);

    xlogd("WebSocket TX complete: id(%u), fd(%d)",
        DirectGate_Conn_GetID(pConn, pApiSession),
        DirectGate_Conn_GetFD(pConn, pApiSession));

    return XAPI_CONTINUE;
}

int DirectGate_ServiceCallback(xapi_ctx_t *pCtx, xapi_session_t *pApiSession)
{
    switch (pCtx->eCbType)
    {
        case XAPI_CB_HANDSHAKE_REQUEST:
            return DirectGate_HandshakeRequest(pCtx, pApiSession);
        case XAPI_CB_HANDSHAKE_RESPONSE:
            return DirectGate_HandshakeResponse(pCtx, pApiSession);
        case XAPI_CB_REGISTERED:
            return DirectGate_HandleRegistered(pApiSession);
        case XAPI_CB_CONNECTED:
            return DirectGate_InitConnection(pCtx, pApiSession);
        case XAPI_CB_CLOSED:
            return DirectGate_DestroyConnection(pCtx, pApiSession);
        case XAPI_CB_READ:
            return DirectGate_HandleFrame(pCtx, pApiSession);
        case XAPI_CB_WRITE:
            return DirectGate_SendFrame(pCtx, pApiSession);
        case XAPI_CB_ERROR:
            return DirectGate_LogError(pCtx, pApiSession);
        case XAPI_CB_STATUS:
            return DirectGate_LogStatus(pCtx, pApiSession);
        case XAPI_CB_INTERRUPT:
            return DirectGate_HandleInterrupt(pCtx, pApiSession);
        case XAPI_CB_TICK:
            return DirectGate_HandleTick(pCtx, pApiSession);
        case XAPI_CB_COMPLETE:
            return DirectGate_HandleComplete(pCtx, pApiSession);
        default:
            break;
    }

    return XAPI_CONTINUE;
}

static void DirectGate_InitialConnect(xapi_t *pApi, xapi_endpoint_t *pEndpt, directgate_conn_t *pSessData)
{
    while (!g_bFinish)
    {
        uint32_t nWaitMs = DirectGate_ReconnectWaitMs(pSessData->nNextReconnectMs);
        if (nWaitMs > 0)
        {
            xusleep(nWaitMs * DIRECTGATE_SLEEP_USEC_PER_MS);
            continue;
        }

        if (!DirectGate_PreConnectRefresh(pSessData))
        {
            if (pSessData->bReconnectSuppressed) return;
            DirectGate_ScheduleReconnect(pSessData, "pre-connect refresh failed");
            continue;
        }

        if (!DirectGate_PrepareEndpoint(pSessData, pEndpt))
        {
            xloge("Relay endpoint is incomplete, missing target, key, or token: id(%u), fd(%d)",
                DirectGate_Conn_GetID(pSessData, NULL), DirectGate_Conn_GetFD(pSessData, NULL));

            return;
        }

        if (XAPI_AddEndpoint(pApi, pEndpt) >= 0) break;
        DirectGate_ScheduleReconnect(pSessData, "initial connect failed");
    }
}

static int DirectGate_SendVerifyUpdate(directgate_conn_t *pConn)
{
    XCHECK((pConn != NULL), XSTDERR);
    XCHECK((pConn->pWsSession != NULL), XSTDERR);
    XCHECK((pConn->pCfg != NULL), XSTDERR);

    const directgate_enroll_t *pEnroll = &pConn->pCfg->enroll;
    XCHECK((xstrused(pEnroll->sAccessToken)), XSTDERR);

    /* Generate a random requestId for correlation */
    char sRequestId[17];
    uint64_t nRand = XTime_GetMs() ^ (uint64_t)getpid();
    snprintf(sRequestId, sizeof(sRequestId), "%016" PRIx64, nRand);

    xjson_obj_t *pHeader = DirectGate_Proto_BuildVerify("update",
        pEnroll->sAccessToken, sRequestId, 0, NULL, NULL);
    XCHECK((pHeader != NULL), XSTDERR);

    xbyte_buffer_t msg;
    XByteBuffer_Init(&msg, XSTDNON, XFALSE);

    int nStatus = DirectGate_Proto_Build(&msg, pHeader, NULL, 0, XFALSE) ?
                  DirectGate_WebSock_SendBuff(pConn->pWsSession, &msg) : XSTDERR;

    XJSON_FreeObject(pHeader);
    XByteBuffer_Clear(&msg);

    return nStatus;
}

static xbool_t DirectGate_CheckTokenRefresh(directgate_conn_t *pConn)
{
    XCHECK((pConn != NULL), XFALSE);
    XCHECK((pConn->pCfg != NULL), XFALSE);

    XCHECK_NL((pConn->pWsSession != NULL), XFALSE);
    XCHECK_NL((pConn->bRoleSent), XFALSE);

    directgate_cfg_t *pCfg = pConn->pCfg;
    XCHECK_NL((pCfg->enroll.bEnrolled), XFALSE);

    if (!DirectGate_Enroll_NeedsRefresh(pCfg)) return XTRUE;

    xlogi("Refreshing access token for active relay session: id(%u), fd(%d), relay(%s)",
        DirectGate_Conn_GetID(pConn, pConn->pWsSession),
        DirectGate_Conn_GetFD(pConn, pConn->pWsSession),
        xstrused(pCfg->sRelayUrl) ? pCfg->sRelayUrl : DIRECTGATE_NO_ANSWER);

    char sReason[XSTR_TINY];
    directgate_enroll_status_t eStatus;

    eStatus = DirectGate_Enroll_Refresh(pCfg, sReason, sizeof(sReason));
    if (eStatus != DIRECTGATE_ENROLL_REFRESH_OK)
    {
        xlogw("Token refresh failed: id(%u), fd(%d), status(%d), reason(%s)",
            DirectGate_Conn_GetID(pConn, pConn->pWsSession),
            DirectGate_Conn_GetFD(pConn, pConn->pWsSession),
            eStatus, sReason);

        return DirectGate_HandleRefreshStatus(pConn, eStatus, sReason, "active-session token refresh", XTRUE);
    }

    if (DirectGate_SendVerifyUpdate(pConn) < 0)
    {
        xloge("Failed to send verify update after token refresh: id(%u), fd(%d)",
            DirectGate_Conn_GetID(pConn, pConn->pWsSession),
            DirectGate_Conn_GetFD(pConn, pConn->pWsSession));

        return XFALSE;
    }

    xlogi("Sent verify update to relay: id(%u), fd(%d)",
        DirectGate_Conn_GetID(pConn, pConn->pWsSession),
        DirectGate_Conn_GetFD(pConn, pConn->pWsSession));

    return XTRUE;
}

static void DirectGate_CheckRelayKeepalive(directgate_conn_t *pConn)
{
    XCHECK_VOID((pConn != NULL));
    XCHECK_VOID_NL((pConn->pWsSession != NULL));
    XCHECK_VOID_NL((pConn->nLastRelayRecvMs > 0));

    uint64_t nNowMs = XTime_GetMs();
    uint64_t nSinceRecv = nNowMs - pConn->nLastRelayRecvMs;
    if (nSinceRecv < DIRECTGATE_RELAY_KA_TIMEOUT_MS) return;

    xlogw("Relay keepalive timeout, no data received for %" PRIu64 "ms: id(%u), fd(%d)", nSinceRecv,
        DirectGate_Conn_GetID(pConn, pConn->pWsSession), DirectGate_Conn_GetFD(pConn, pConn->pWsSession));

    /* We have a stale connection here */
    XAPI_Disconnect(pConn->pWsSession);
}

static void DirectGate_CheckAuthTimeouts(directgate_conn_t *pConn)
{
    XCHECK_VOID((pConn != NULL));
    DirectGate_SessionMgr_ExpireUnauthenticated(&pConn->mgr, XTime_GetMs());
}

static void DirectGate_CheckWebRTCKeepalive(directgate_conn_t *pConn)
{
    XCHECK_VOID((pConn != NULL));
    XCHECK_VOID((pConn->pCfg != NULL));
    XCHECK_VOID_NL((pConn->pCfg->nKAInterval > 0));

    uint64_t nNowMs = XTime_GetMs();
    uint16_t nInterval = pConn->pCfg->nKAInterval;
    uint64_t nIntervalMs = (uint64_t)nInterval * 1000ULL;
    uint64_t nTimeoutMs = nIntervalMs * 3ULL;
    int i;

    for (i = 0; i < DIRECTGATE_MAX_SESSIONS; i++)
    {
        directgate_session_t *pSession = pConn->mgr.pSessions[i];
        if (pSession == NULL || !pSession->bAuthenticated) continue;
        if (!DirectGate_WebRTC_IsConnected(&pSession->webrtc)) continue;

        if (pSession->nLastKAPingMs == 0)
        {
            /* Stagger first ping per session with deterministic jitter to avoid burst */
            uint64_t nJitterMax = (nIntervalMs >= 2) ? (nIntervalMs / 2ULL) : 1ULL;
            uint32_t nJitter = (uint32_t)((pSession->nSessionId * 2654435761u) % (uint32_t)nJitterMax);

            pSession->nLastKAPingMs = nNowMs + (uint64_t)nJitter;
            pSession->nLastKAPongMs = nNowMs;
            continue;
        }

        uint64_t nSincePing = nNowMs - pSession->nLastKAPingMs;
        uint64_t nSincePong = nNowMs - pSession->nLastKAPongMs;

        /* If event loop was stalled, resync ping schedule */
        if (nSincePing > nTimeoutMs * 2ULL)
        {
            pSession->nLastKAPingMs = nNowMs;
            nSincePing = 0;
        }

        /* Pong timeout: no pong within interval*3 */
        if (pSession->nLastKAPongMs > 0 && nSincePong >= nTimeoutMs)
        {
            xlogw("Keepalive pong timeout, closing session: sid(%u), wsfd(%d), timeoutMs(%" PRIu64 ")",
                pSession->nSessionId, DirectGate_Session_GetWsFd(pSession), nTimeoutMs);

            DirectGate_Session_Close(pSession, "keepalive timeout");
            continue;
        }

        if (nSincePing < nIntervalMs) continue;
        xlogd("Sending keepalive ping: sid(%u), wsfd(%d)",
            pSession->nSessionId, DirectGate_Session_GetWsFd(pSession));

        DirectGate_Session_SendKeepalive(pSession, "ping");
        pSession->nLastKAPingMs = nNowMs;
    }
}

static void DirectGate_RunService(xapi_t *pApi, xapi_endpoint_t *pEndpt, directgate_conn_t *pSessData)
{
    while (!g_bFinish)
    {
        xevent_status_t status = XEVENTS_SUCCESS;

        if (pApi->bHaveEvents)
        {
            status = XAPI_Service(pApi, (int)DirectGate_GetServiceWaitMs(pSessData));
            if (g_bFinish) break;

            if (status != XEVENTS_SUCCESS)
            {
                xlogw("Event loop returned error: id(%u), fd(%d), status(%s), code(%d)",
                    DirectGate_Conn_GetID(pSessData, pSessData->pWsSession),
                    DirectGate_Conn_GetFD(pSessData, pSessData->pWsSession),
                    XEvents_GetStatusStr(status), (int)status);

                xusleep(DirectGate_GetServiceWaitMs(pSessData) * DIRECTGATE_SLEEP_USEC_PER_MS);
                status = XEVENTS_SUCCESS;
            }
        }
        else
        {
            xusleep(DirectGate_GetServiceWaitMs(pSessData) * DIRECTGATE_SLEEP_USEC_PER_MS);
        }

        DirectGate_CheckTokenRefresh(pSessData);
        DirectGate_CheckAuthTimeouts(pSessData);
        DirectGate_CheckRelayKeepalive(pSessData);
        DirectGate_CheckWebRTCKeepalive(pSessData);

        if (pSessData->pWsSession == NULL &&
            !pSessData->bReconnectSuppressed &&
            pSessData->nNextReconnectMs > 0)
        {
            uint64_t nNow = XTime_GetMs();
            if (nNow >= pSessData->nNextReconnectMs)
            {
                if (!DirectGate_PreConnectRefresh(pSessData))
                {
                    if (!pSessData->bReconnectSuppressed)
                        DirectGate_ScheduleReconnect(pSessData, "pre-connect refresh failed");

                    continue;
                }

                if (!DirectGate_PrepareEndpoint(pSessData, pEndpt))
                {
                    xloge("Reconnect target is no longer valid: id(%u), fd(%d)",
                        DirectGate_Conn_GetID(pSessData, NULL), DirectGate_Conn_GetFD(pSessData, NULL));

                    pSessData->nNextReconnectMs = 0;
                    continue;
                }

                xlogi("Reconnect attempt: id(%u), fd(%d), attempt(%u), target(%s:%u), tls(%s)",
                    DirectGate_Conn_GetID(pSessData, NULL), DirectGate_Conn_GetFD(pSessData, NULL), pSessData->nReconnectAttempt,
                    xstrused(pEndpt->pAddr) ? pEndpt->pAddr : "?", (unsigned)pEndpt->nPort, pEndpt->bTLS ? "yes" : "no");

                if (XAPI_Connect(pApi, pEndpt) < 0)
                    DirectGate_ScheduleReconnect(pSessData, "reconnect failed");
            }
        }
    }
}

#ifdef _WIN32
static xbool_t DirectGate_DropPrivileges(const directgate_cfg_t *pCfg)
{
    XCHECK((pCfg != NULL), XFALSE);

    if (!xstrused(pCfg->sShellUser))
    {
        /* Same policy as POSIX: no silent identity fallback. The operator
           must state explicitly which account owns the sessions. */
        xloge("shell.user is not configured, refusing to start: set shell.user "
              "to the account that should own terminal and file-manager sessions");

        return XFALSE;
    }

    /*
        Windows has no setuid(): process identity is fixed by whoever
        started the agent (the service account). Mirroring the POSIX
        builds, identity is verified instead of silently adjusted - if
        the configured shell.user is not the account the agent already
        runs as, startup is refused so sessions can never run under an
        unexpected identity. Account names compare case-insensitively.
    */
    char sCurrentUser[XSTR_MID] = {0};
    DirectGate_GetUserName(sCurrentUser, sizeof(sCurrentUser));

    if (!xstrused(sCurrentUser))
    {
        xloge("Failed to resolve the agent account, refusing to start: error(%lu)", GetLastError());
        return XFALSE;
    }

    if (_stricmp(sCurrentUser, pCfg->sShellUser) != 0)
    {
        xloge("Configured shell.user does not match the agent account and user "
              "switching is not supported on Windows, refusing to start: "
              "shell.user(%s), agent(%s). Run the agent service as shell.user instead.",
            pCfg->sShellUser, sCurrentUser);

        return XFALSE;
    }

    xlogd("Agent already runs as the configured shell user: user(%s)", sCurrentUser);
    return XTRUE;
}
#else
static void DirectGate_ChownToUser(const char *pPath, uid_t nUid, gid_t nGid)
{
    if (!xstrused(pPath)) return;

    if (chown(pPath, nUid, nGid) != 0 && errno != ENOENT)
    {
        xlogw("Failed to hand path to shell user, runtime writes may fail: "
              "path(%s), uid(%u), errno(%d)", pPath, (unsigned)nUid, errno);
    }
}

static xbool_t DirectGate_DropPrivileges(const directgate_cfg_t *pCfg)
{
    XCHECK((pCfg != NULL), XFALSE);

    if (!xstrused(pCfg->sShellUser))
    {
        /* NOTE: We are not allowing silent fallback to root, however running
           sessions as root is allowed, but it must be an explicit choice to
           set shell.user="root". This mirrors how sshd does not forbid root
           login on its own (PermitRootLogin) and leaves that decision to the
           operator. */

        xloge("shell.user is not configured, refusing to start: set shell.user "
              "to the account that should own terminal and file-manager sessions");

        return XFALSE;
    }

    errno = 0;
    struct passwd *pUser = getpwnam(pCfg->sShellUser);
    if (pUser == NULL)
    {
        xloge("Configured shell user not found, refusing to start: user(%s), errno(%d)",
            pCfg->sShellUser, errno);

        return XFALSE;
    }

    if (pUser->pw_uid == getuid() && pUser->pw_gid == getgid())
    {
        xlogd("Already running as shell user, no privilege drop needed: user(%s)", pCfg->sShellUser);
        return XTRUE;
    }

    if (getuid() != 0)
    {
        /* Not privileged enough to change user. The PTY would hit the same
           wall, so continue as the current user rather than fail to start. */
        xlogw("Not running as root; cannot drop to shell user: user(%s), uid(%u)",
            pCfg->sShellUser, (unsigned)getuid());

        return XTRUE;
    }

    /* Hand the persisted config (and log dir) to the target user so runtime
       token refresh can still rewrite them after the drop. The config must
       live in a directory reachable by shell.user (e.g. /etc/directgate), not
       under another user's private home such as /root. */
    DirectGate_ChownToUser(pCfg->sCfgPath, pUser->pw_uid, pUser->pw_gid);

    char sCfgDir[XPATH_MAX];
    xstrncpy(sCfgDir, sizeof(sCfgDir), pCfg->sCfgPath);

    char *pSlash = strrchr(sCfgDir, '/');
    if (pSlash != NULL && pSlash != sCfgDir)
    {
        *pSlash = '\0';
        DirectGate_ChownToUser(sCfgDir, pUser->pw_uid, pUser->pw_gid);
    }

    if (pCfg->log.bToFile && xstrused(pCfg->log.sPath))
        DirectGate_ChownToUser(pCfg->log.sPath, pUser->pw_uid, pUser->pw_gid);

    /* Order matters: supplementary groups, then gid, then uid. */
    if (initgroups(pUser->pw_name, pUser->pw_gid) != 0)
    {
        xloge("Failed to initialize supplementary groups: user(%s), gid(%u), errno(%d)",
            pUser->pw_name, (unsigned)pUser->pw_gid, errno);

        return XFALSE;
    }

    if (setgid(pUser->pw_gid) != 0)
    {
        xloge("Failed to setgid to shell user: user(%s), gid(%u), errno(%d)",
            pUser->pw_name, (unsigned)pUser->pw_gid, errno);

        return XFALSE;
    }

    if (setuid(pUser->pw_uid) != 0)
    {
        xloge("Failed to setuid to shell user: user(%s), uid(%u), errno(%d)",
            pUser->pw_name, (unsigned)pUser->pw_uid, errno);

        return XFALSE;
    }

    /* Verify the drop took and that root cannot be regained. */
    if (getuid() != pUser->pw_uid || geteuid() != pUser->pw_uid ||
        getgid() != pUser->pw_gid || getegid() != pUser->pw_gid)
    {
        xloge("Privilege drop verification failed, refusing to start: user(%s)", pUser->pw_name);
        return XFALSE;
    }

    if (setuid(0) == 0)
    {
        xloge("Privilege drop incomplete; able to regain root, refusing to start: user(%s)", pUser->pw_name);
        return XFALSE;
    }

    xlogn("Dropped privileges to shell user: user(%s), uid(%u), gid(%u)",
        pUser->pw_name, (unsigned)pUser->pw_uid, (unsigned)pUser->pw_gid);

    return XTRUE;
}
#endif /* _WIN32 */

#ifndef DIRECTGATE_TESTING
static int DirectGate_RunAgent(int argc, char* argv[])
{
    xlog_defaults();
    xlog_coloring(XFALSE);
    xlog_timing(XLOG_DATE);
    xlog_indent(XTRUE);

#ifdef _WIN32
    /* No SIGPIPE on Windows; socket errors surface through WSA codes */
    int nSignals[2] = { SIGTERM, SIGINT };
    XSig_Register(nSignals, 2, DirectGate_SignalCallback);
#else
    int nSignals[3] = { SIGTERM, SIGINT, SIGPIPE };
    XSig_Register(nSignals, 3, DirectGate_SignalCallback);
#endif

    directgate_cfg_t args;
    if (!DirectGate_ParseArgs(&args, argc, argv))
    {
        XLog_Destroy();
        return args.bHelp ? XSTDNON : XSTDERR;
    }

    int nStatus = DirectGate_ApplyConfig(&args);
    if (nStatus <= 0)
    {
        XLog_Destroy();
        return nStatus;
    }

    xlogn("Starting directgate agent: v%s", DirectGate_GetVersionLong());
    xlogi("libxutils version: %s", XUtils_Version());
    xlogi("WebRTC library: v%s", RTC_VERSION);

#ifdef DIRECTGATE_DEBUG
    xlogn("DirectGate agent is running in debug mode");
#else
    xlogn("DirectGate agent is running in production mode");
#endif

    /* Drop to the configured shell user before opening the relay or any PTY,
       so the file manager runs with the same privilege as the terminal. */
    if (!DirectGate_DropPrivileges(&args))
    {
        XLog_Destroy();
        return XSTDERR;
    }

    directgate_conn_t conn;
    DirectGate_Connection_Init(&conn, &args);

    xapi_endpoint_t endpt;
    XAPI_InitEndpoint(&endpt);

    endpt.eType = XAPI_WS;
    endpt.eRole = XAPI_CLIENT;
    endpt.pSessionData = &conn;

    xapi_t api;
    XAPI_Init(&api, DirectGate_ServiceCallback, &conn);

    DirectGate_InitialConnect(&api, &endpt, &conn);
    DirectGate_RunService(&api, &endpt, &conn);

    DirectGate_SessionMgr_Destroy(&conn.mgr);
    DirectGate_WebRTC_Cleanup();
    XAPI_Destroy(&api);
    XLog_Destroy();

    return 0;
}

#ifdef _WIN32
/*
    Windows Service Control Manager integration: the systemd/launchd
    counterpart on Windows. The SCM kills any service process that does
    not register a control handler, so the agent cannot simply run its
    console main under the SCM. Installed as:

      sc.exe create directgate-agent binPath= "C:\path\directgate.exe --win-service" \
             start= auto obj= ".\<user>" password= <password>

    A STOP/SHUTDOWN control sets the same g_bFinish flag as SIGTERM, so
    the shutdown path is byte-for-byte the console one.
*/
#define DIRECTGATE_WIN_SERVICE_NAME "directgate-agent"
#define DIRECTGATE_WIN_SERVICE_FLAG "--win-service"

static SERVICE_STATUS_HANDLE g_hSvcStatusHandle = NULL;
static int g_nSvcArgc = 0;
static char **g_pSvcArgv = NULL;

static void DirectGate_SvcReportState(DWORD nState, DWORD nExitCode)
{
    if (g_hSvcStatusHandle == NULL) return;

    SERVICE_STATUS status;
    memset(&status, 0, sizeof(status));

    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = nState;
    status.dwWin32ExitCode = nExitCode;
    status.dwControlsAccepted = (nState == SERVICE_RUNNING) ?
        (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN) : 0;

    SetServiceStatus(g_hSvcStatusHandle, &status);
}

static void WINAPI DirectGate_SvcCtrlHandler(DWORD nControl)
{
    switch (nControl)
    {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            DirectGate_SvcReportState(SERVICE_STOP_PENDING, NO_ERROR);
            g_bFinish = XTRUE;
            break;
        default:
            break;
    }
}

static void WINAPI DirectGate_SvcMain(DWORD nArgc, LPSTR *pArgv)
{
    /* SCM start parameters are ignored: the agent arguments come from
       the binPath command line captured before the dispatcher started */
    (void)nArgc;
    (void)pArgv;

    g_hSvcStatusHandle = RegisterServiceCtrlHandlerA(
        DIRECTGATE_WIN_SERVICE_NAME, DirectGate_SvcCtrlHandler);

    if (g_hSvcStatusHandle == NULL) return;

    DirectGate_SvcReportState(SERVICE_RUNNING, NO_ERROR);
    int nStatus = DirectGate_RunAgent(g_nSvcArgc, g_pSvcArgv);

    DirectGate_SvcReportState(SERVICE_STOPPED,
        nStatus < 0 ? ERROR_SERVICE_SPECIFIC_ERROR : NO_ERROR);
}
#endif /* _WIN32 */

int main(int argc, char* argv[])
{
#ifdef _WIN32
    /* Strip the dispatcher flag so the regular argument parser never
       sees it, whether the service mode is requested or not */
    static char *pFilteredArgv[64];
    xbool_t bWinService = XFALSE;
    int i, nFiltered = 0;

    for (i = 0; i < argc && nFiltered < (int)XARR_SIZE(pFilteredArgv) - 1; i++)
    {
        if (strcmp(argv[i], DIRECTGATE_WIN_SERVICE_FLAG) == 0)
        {
            bWinService = XTRUE;
            continue;
        }

        pFilteredArgv[nFiltered++] = argv[i];
    }

    pFilteredArgv[nFiltered] = NULL;

    if (bWinService)
    {
        g_nSvcArgc = nFiltered;
        g_pSvcArgv = pFilteredArgv;

        SERVICE_TABLE_ENTRYA svcTable[] = {
            { (LPSTR)DIRECTGATE_WIN_SERVICE_NAME, DirectGate_SvcMain },
            { NULL, NULL }
        };

        /* Blocks until the service is stopped */
        if (!StartServiceCtrlDispatcherA(svcTable))
        {
            fprintf(stderr, "Failed to connect to the service control manager "
                "(error %lu): %s is only valid when the agent is started as a "
                "Windows service\n", GetLastError(), DIRECTGATE_WIN_SERVICE_FLAG);

            return XSTDERR;
        }

        return 0;
    }

    return DirectGate_RunAgent(nFiltered, pFilteredArgv);
#else
    return DirectGate_RunAgent(argc, argv);
#endif
}
#endif
