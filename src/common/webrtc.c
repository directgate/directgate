/*!
 * @file directgate-agent/src/common/webrtc.c
 * @brief WebRTC peer connection wrapper using libdatachannel.
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

#include "webrtc.h"
#include "protocol.h"

#define DIRECTGATE_RTC_DEFAULT_MID  "0"

static const char *g_pIceServers[] = {
    "stun:stun.cloudflare.com:3478",
    "stun:stun.l.google.com:19302",
};

static xbool_t g_bRtcInitialized = XFALSE;

static int DirectGate_WebRTC_GetPC(const directgate_webrtc_t *pRTC)
{
    XCHECK_NL((pRTC != NULL), XSTDERR);
    return pRTC->nPeerConnectionID;
}

static int DirectGate_WebRTC_GetDC(const directgate_webrtc_t *pRTC)
{
    XCHECK_NL((pRTC != NULL), XSTDERR);
    return pRTC->nDataChannelID;
}

static int DirectGate_WebRTC_GetPipe(const directgate_webrtc_t *pRTC)
{
    XCHECK_NL((pRTC != NULL), XSTDERR);
    /* SOCKET values fit in 32 bits (WinAPI interop guarantee) and
       INVALID_SOCKET casts to -1, matching the POSIX convention */
    return (int)pRTC->nPipeFds[0];
}

/* Unescape JSON string sequences (\r \n \t \\ \") in place.
   The xutils JSON parser does not unescape string values, so
   SDP strings arrive with literal \r\n instead of CR/LF. */
static char *DirectGate_JSON_Unescape(const char *pSrc)
{
    XCHECK(xstrused(pSrc), NULL);
    size_t nLen = strlen(pSrc);

    char *pDst = (char*)malloc(nLen + 1);
    XCHECK((pDst != NULL), NULL);

    size_t j = 0;
    for (size_t i = 0; i < nLen; i++)
    {
        if (pSrc[i] == '\\' && i + 1 < nLen)
        {
            switch (pSrc[i + 1])
            {
                case 'r':  pDst[j++] = '\r'; i++; break;
                case 'n':  pDst[j++] = '\n'; i++; break;
                case 't':  pDst[j++] = '\t'; i++; break;
                case '\\': pDst[j++] = '\\'; i++; break;
                case '"':  pDst[j++] = '"';  i++; break;
                case '/':  pDst[j++] = '/';  i++; break;
                default:   pDst[j++] = pSrc[i]; break;
            }
        }
        else
        {
            pDst[j++] = pSrc[i];
        }
    }

    pDst[j] = '\0';
    return pDst;
}

/* Escape special characters for JSON string values.
   The xutils JSON writer does not escape strings,
   so \r\n in SDP would produce invalid JSON. */
static char *DirectGate_JSON_Escape(const char *pSrc)
{
    XCHECK(xstrused(pSrc), NULL);
    size_t nLen = strlen(pSrc);

    char *pDst = (char*)malloc(nLen * 2 + 1);
    XCHECK((pDst != NULL), NULL);

    size_t j = 0;
    for (size_t i = 0; i < nLen; i++)
    {
        switch (pSrc[i])
        {
            case '\r': pDst[j++] = '\\'; pDst[j++] = 'r';  break;
            case '\n': pDst[j++] = '\\'; pDst[j++] = 'n';  break;
            case '\t': pDst[j++] = '\\'; pDst[j++] = 't';  break;
            case '\\': pDst[j++] = '\\'; pDst[j++] = '\\'; break;
            case '"':  pDst[j++] = '\\'; pDst[j++] = '"';  break;
            default:   pDst[j++] = pSrc[i]; break;
        }
    }

    pDst[j] = '\0';
    return pDst;
}

static int DirectGate_WebRTC_NotifyPipe(directgate_webrtc_t *pRTC)
{
    XCHECK((pRTC != NULL), XSTDERR);
    char cValue = 1; // Send notification byte

#ifdef _WIN32
    return (int)send(pRTC->nPipeFds[1], &cValue, 1, 0);
#else
    return (int)write(pRTC->nPipeFds[1], &cValue, 1);
#endif
}

static void DirectGate_WebRTC_DrainPipe(directgate_webrtc_t *pRTC)
{
    XCHECK_VOID((pRTC != NULL));
    char buf[64]; /* Drain notification bytes from pipe */

#ifdef _WIN32
    while (recv(pRTC->nPipeFds[0], buf, sizeof(buf), 0) > 0){}
#else
    while (read(pRTC->nPipeFds[0], buf, sizeof(buf)) > 0){}
#endif
}

static directgate_webrtc_event_t* XSell_WebRTC_DetachQueue(directgate_webrtc_t *pRTC)
{
    XCHECK((pRTC != NULL), NULL);
    XSync_Lock(&pRTC->queueLock);
    directgate_webrtc_event_t *pHead = pRTC->pQueueHead;
    pRTC->pQueueHead = NULL;
    pRTC->pQueueTail = NULL;
    XSync_Unlock(&pRTC->queueLock);
    return pHead;
}

static void DirectGate_WebRTC_Enqueue(directgate_webrtc_t *pRTC, directgate_webrtc_event_type_t eType,
                                      int nSourceID, const uint8_t *pData, size_t nLen)
{
    XCHECK_VOID((pRTC != NULL));
    directgate_webrtc_event_t *pEvt;

    pEvt = (directgate_webrtc_event_t*)malloc(sizeof(*pEvt));
    XCHECK_VOID((pEvt != NULL));

    pEvt->nSourceID = nSourceID;
    pEvt->eType = eType;
    pEvt->pNext = NULL;
    pEvt->pData = NULL;
    pEvt->nLength = 0;

    if (pData != NULL && nLen > 0)
    {
        pEvt->pData = (uint8_t*)malloc(nLen);
        if (pEvt->pData == NULL)
        {
            xloge("Failed to allocate WebRTC event buffer: pc(%d), dc(%d), pipefd(%d), bytes(%zu), errno(%d)",
                DirectGate_WebRTC_GetPC(pRTC), DirectGate_WebRTC_GetDC(pRTC),
                DirectGate_WebRTC_GetPipe(pRTC), nLen, errno);

            free(pEvt);
            return;
        }

        memcpy(pEvt->pData, pData, nLen);
        pEvt->nLength = nLen;
    }

    XSync_Lock(&pRTC->queueLock);

    if (pRTC->pQueueTail != NULL)
        pRTC->pQueueTail->pNext = pEvt;
    else pRTC->pQueueHead = pEvt;

    pRTC->pQueueTail = pEvt;
    XSync_Unlock(&pRTC->queueLock);

    DirectGate_WebRTC_NotifyPipe(pRTC);
}

static void DirectGate_WebRTC_DetachDataChannel(int nDC)
{
    if (nDC < 0) return;
    rtcSetUserPointer(nDC, NULL);
    rtcSetOpenCallback(nDC, NULL);
    rtcSetClosedCallback(nDC, NULL);
    rtcSetErrorCallback(nDC, NULL);
    rtcSetMessageCallback(nDC, NULL);
}

static void DirectGate_WebRTC_CloseDataChannel(int nDC)
{
    if (nDC < 0) return;
    DirectGate_WebRTC_DetachDataChannel(nDC);
    rtcClose(nDC);
    rtcDelete(nDC);
}

static void DirectGate_WebRTC_DrainQueue(directgate_webrtc_t *pRTC)
{
    directgate_webrtc_event_t *pHead;
    pHead = XSell_WebRTC_DetachQueue(pRTC);

    while (pHead != NULL)
    {
        directgate_webrtc_event_t *pNext = pHead->pNext;
        free(pHead->pData);
        free(pHead);
        pHead = pNext;
    }
}

static void DirectGate_WebRTC_BufferIce(directgate_webrtc_t *pRTC, const char *pCandidate, const char *pMid)
{
    XCHECK_VOID((pRTC != NULL));
    XCHECK_VOID(xstrused(pCandidate));

    directgate_pending_ice_t *pIce = (directgate_pending_ice_t*)malloc(sizeof(*pIce));
    XCHECK_VOID((pIce != NULL));

    const char *pUseMid = xstrused(pMid) ? pMid : DIRECTGATE_RTC_DEFAULT_MID;
    xstrncpy(pIce->sCandidate, sizeof(pIce->sCandidate), pCandidate);
    xstrncpy(pIce->sMid, sizeof(pIce->sMid), pUseMid);
    pIce->pNext = NULL;

    /* Append to the end of pending list */
    if (pRTC->pPendingIce == NULL)
    {
        pRTC->pPendingIce = pIce;
    }
    else
    {
        directgate_pending_ice_t *pTail = pRTC->pPendingIce;
        while (pTail->pNext != NULL) pTail = pTail->pNext;
        pTail->pNext = pIce;
    }

    xlogd("Buffered remote ICE candidate (peer connection pending): dc(%d)",
        DirectGate_WebRTC_GetDC(pRTC));
}

static void DirectGate_WebRTC_FlushPendingIce(directgate_webrtc_t *pRTC)
{
    XCHECK_VOID((pRTC != NULL));

    directgate_pending_ice_t *pIce = pRTC->pPendingIce;
    pRTC->pPendingIce = NULL;

    while (pIce != NULL)
    {
        directgate_pending_ice_t *pNext = pIce->pNext;

        if (pRTC->nPeerConnectionID >= 0)
        {
            xlogd("Applying buffered ICE candidate: pc(%d), mid(%s)", pRTC->nPeerConnectionID, pIce->sMid);
            rtcAddRemoteCandidate(pRTC->nPeerConnectionID, pIce->sCandidate, pIce->sMid);
        }

        free(pIce);
        pIce = pNext;
    }
}

static void DirectGate_WebRTC_ClearPendingIce(directgate_webrtc_t *pRTC)
{
    XCHECK_VOID_NL((pRTC != NULL));

    directgate_pending_ice_t *pIce = pRTC->pPendingIce;
    directgate_pending_ice_t *pNext = NULL;
    pRTC->pPendingIce = NULL;

    while (pIce != NULL)
    {
        pNext = pIce->pNext;
        free(pIce);
        pIce = pNext;
    }
}

static void DirectGate_WebRTC_LogCallback(rtcLogLevel level, const char *msg)
{
    switch (level)
    {
        case RTC_LOG_FATAL:
            xlogf("%s", msg); return;
        case RTC_LOG_ERROR:
            xloge("%s", msg); return;
        case RTC_LOG_WARNING:
            xlogw("%s", msg); return;
        case RTC_LOG_INFO:
            xlogi("%s", msg); return;
        case RTC_LOG_DEBUG:
            xlogd("%s", msg); return;
        case RTC_LOG_VERBOSE:
            xlogt("%s", msg); return;
        default: break;
    }
}

static void DirectGate_WebRTC_InitLib(directgate_webrtc_t *pRTC)
{
    if (!g_bRtcInitialized && pRTC)
    {
        rtcInitLogger(pRTC->logLevel, DirectGate_WebRTC_LogCallback);
        g_bRtcInitialized = XTRUE;
    }
}

void DirectGate_WebRTC_Init(directgate_webrtc_t *pRTC)
{
    XCHECK_VOID((pRTC != NULL));
    memset(pRTC, 0, sizeof(*pRTC));

    pRTC->logLevel = RTC_LOG_ERROR;
    pRTC->nPeerConnectionID = -1;
    pRTC->nDataChannelID = -1;
    pRTC->nIceSrvCount = 0;
    pRTC->bConnected = XFALSE;

    pRTC->pQueueHead = NULL;
    pRTC->pQueueTail = NULL;
    pRTC->pPendingIce = NULL;
    pRTC->bAllowTCP = XFALSE;
    XSync_Init(&pRTC->queueLock);

#ifdef _WIN32
    /* WSAPoll handles only sockets, so the notification channel is a
       private loopback socket pair instead of an anonymous pipe */
    if (XSock_CreatePair(pRTC->nPipeFds) < 0)
    {
        xloge("Failed to create WebRTC notification socket pair: pc(%d), dc(%d), error(%d)",
            DirectGate_WebRTC_GetPC(pRTC), DirectGate_WebRTC_GetDC(pRTC), WSAGetLastError());

        pRTC->nPipeFds[0] = XSOCK_INVALID;
        pRTC->nPipeFds[1] = XSOCK_INVALID;
        return;
    }

    u_long nNonBlock = 1;
    ioctlsocket(pRTC->nPipeFds[0], FIONBIO, &nNonBlock);
    ioctlsocket(pRTC->nPipeFds[1], FIONBIO, &nNonBlock);
#else
    if (pipe(pRTC->nPipeFds) < 0)
    {
        xloge("Failed to create WebRTC notification pipe: pc(%d), dc(%d), errno(%d)",
            DirectGate_WebRTC_GetPC(pRTC), DirectGate_WebRTC_GetDC(pRTC), errno);

        pRTC->nPipeFds[0] = -1;
        pRTC->nPipeFds[1] = -1;
        return;
    }

    fcntl(pRTC->nPipeFds[0], F_SETFL, O_NONBLOCK);
    fcntl(pRTC->nPipeFds[1], F_SETFL, O_NONBLOCK);
#endif
}

xbool_t DirectGate_WebRTC_LoadIceServers(directgate_ice_server_t *pServers, uint8_t *pCount, xjson_obj_t *pRoot)
{
    XCHECK_NL((pServers != NULL), XFALSE);
    XCHECK_NL((pCount != NULL), XFALSE);
    XCHECK_NL((pRoot != NULL), XFALSE);

    *pCount = 0;
    size_t i;

    xjson_obj_t *pIce = XJSON_GetObject(pRoot, "iceServers");
    if (pIce != NULL && pIce->nType == XJSON_TYPE_ARRAY)
    {
        size_t nCount = XJSON_GetArrayLength(pIce);
        if (nCount > DIRECTGATE_MAX_ICE_SERVERS)
            nCount = DIRECTGATE_MAX_ICE_SERVERS;

        for (i = 0; i < nCount; i++)
        {
            xjson_obj_t *pItem = XJSON_GetArrayItem(pIce, i);
            const char *pUrl = XJSON_GetString(pItem);
            if (!xstrused(pUrl)) continue;

            xstrncpy(pServers[*pCount], DIRECTGATE_ICE_URL_SIZE, pUrl);
            (*pCount)++;
        }
    }

    if (*pCount) return XTRUE;

    for (i = 0; i < XARR_SIZE(g_pIceServers) && *pCount < DIRECTGATE_MAX_ICE_SERVERS; i++)
    {
        if (!xstrused(g_pIceServers[i])) continue;
        xstrncpy(pServers[*pCount], DIRECTGATE_ICE_URL_SIZE, g_pIceServers[i]);
        (*pCount)++;
    }

    return (*pCount) ? XTRUE : XFALSE;
}

void DirectGate_WebRTC_SetIceServers(directgate_webrtc_t *pRTC, const directgate_ice_server_t *pServers, uint8_t nCount)
{
    XCHECK_VOID((pRTC != NULL));
    XCHECK_VOID((pServers != NULL));
    XCHECK_VOID_NL((nCount > 0));

    if (nCount > DIRECTGATE_MAX_ICE_SERVERS)
        nCount = DIRECTGATE_MAX_ICE_SERVERS;

    pRTC->nIceSrvCount = 0;
    uint8_t i;

    for (i = 0; i < nCount; i++)
    {
        if (xstrused(pServers[i]))
        {
            char *pIceServer = pRTC->sIceServers[pRTC->nIceSrvCount];
            if (!pRTC->bAllowTCP && strstr(pServers[i], "transport=tcp") != NULL) continue;

            xstrncpy(pIceServer, DIRECTGATE_ICE_URL_SIZE, pServers[i]);
            pRTC->nIceSrvCount++;
        }
    }

    xlogi("Configured WebRTC ICE servers: pc(%d), dc(%d), ice(%u)",
        DirectGate_WebRTC_GetPC(pRTC),
        DirectGate_WebRTC_GetDC(pRTC),
        pRTC->nIceSrvCount);
}

void DirectGate_WebRTC_Destroy(directgate_webrtc_t *pRTC)
{
    XCHECK_VOID_NL((pRTC != NULL));

    if (pRTC->nDataChannelID >= 0)
    {
        DirectGate_WebRTC_CloseDataChannel(pRTC->nDataChannelID);
        pRTC->nDataChannelID = -1;
    }

    if (pRTC->nPeerConnectionID >= 0)
    {
        rtcClosePeerConnection(pRTC->nPeerConnectionID);
        rtcDeletePeerConnection(pRTC->nPeerConnectionID);
        pRTC->nPeerConnectionID = -1;
    }

    pRTC->bConnected = XFALSE;
    DirectGate_WebRTC_DrainQueue(pRTC);
    DirectGate_WebRTC_ClearPendingIce(pRTC);
}

void DirectGate_WebRTC_Clear(directgate_webrtc_t *pRTC)
{
    XCHECK_VOID_NL((pRTC != NULL));
    DirectGate_WebRTC_Destroy(pRTC);

    if (pRTC->nPipeFds[0] != XSOCK_INVALID)
    {
        xclosesock(pRTC->nPipeFds[0]);
        pRTC->nPipeFds[0] = XSOCK_INVALID;
    }

    if (pRTC->nPipeFds[1] != XSOCK_INVALID)
    {
        xclosesock(pRTC->nPipeFds[1]);
        pRTC->nPipeFds[1] = XSOCK_INVALID;
    }

    XSync_Destroy(&pRTC->queueLock);
}

void DirectGate_WebRTC_Cleanup(void)
{
    rtcCleanup();
}

/* Enqueue a signaling message for dispatch on the main thread */
static void DirectGate_WebRTC_SendSignal(directgate_webrtc_t *pRTC, const char *pJson, size_t nLen)
{
    XCHECK_VOID((pRTC != NULL));
    XCHECK_VOID_NL((pJson != NULL && nLen > 0));
    DirectGate_WebRTC_Enqueue(pRTC, DIRECTGATE_WEBRTC_SIGNAL, -1, (const uint8_t*)pJson, nLen);
}

/* Callback: local description generated (answer SDP) */
static void DirectGate_WebRTC_OnLocalDescription(int nPC, const char *pSdp, const char *pType, void *pPtr)
{
    directgate_webrtc_t *pRTC = (directgate_webrtc_t*)pPtr;
    XCHECK_VOID((pRTC != NULL));
    XCHECK_VOID((pSdp != NULL));
    XCHECK_VOID((pType != NULL));
    pRTC->nPeerConnectionID = nPC;

    xlogi("Generated local WebRTC description: pc(%d), dc(%d), type(%s)",
        DirectGate_WebRTC_GetPC(pRTC), DirectGate_WebRTC_GetDC(pRTC), pType);

    xjson_obj_t *pHeader = XJSON_NewObject(NULL, NULL, XSTDNON);
    XCHECK_VOID((pHeader != NULL));

    /* Escape SDP for JSON (xutils writer does not escape string values) */
    char *pEscaped = DirectGate_JSON_Escape(pSdp);
    if (pEscaped == NULL)
    {
        xloge("Failed to escape WebRTC SDP for JSON: pc(%d), dc(%d), type(%s)",
            DirectGate_WebRTC_GetPC(pRTC), DirectGate_WebRTC_GetDC(pRTC), pType);

        XJSON_FreeObject(pHeader);
        return;
    }

    XJSON_AddString(pHeader, "type", "webrtc");
    XJSON_AddString(pHeader, "action", pType);
    XJSON_AddString(pHeader, "sdp", pEscaped);

    free(pEscaped);
    size_t nLen = 0;

    char *pJson = XJSON_DumpObj(pHeader, 0, &nLen);
    if (pJson != NULL)
    {
        DirectGate_WebRTC_SendSignal(pRTC, pJson, nLen);
        free(pJson);
    }

    XJSON_FreeObject(pHeader);
}

/* Callback: local ICE candidate generated */
static void DirectGate_WebRTC_OnLocalCandidate(int nPC, const char *pCand, const char *pMid, void *pPtr)
{
    directgate_webrtc_t *pRTC = (directgate_webrtc_t*)pPtr;
    XCHECK_VOID((pRTC != NULL));
    XCHECK_VOID((pCand != NULL));

    pRTC->nPeerConnectionID = nPC;
    const char *pUseMid = xstrused(pMid) ? pMid : DIRECTGATE_RTC_DEFAULT_MID;

    xlogd("Generated local WebRTC ICE candidate: pc(%d), dc(%d), mid(%s)",
        DirectGate_WebRTC_GetPC(pRTC), DirectGate_WebRTC_GetDC(pRTC), pUseMid);

    xjson_obj_t *pHeader = XJSON_NewObject(NULL, NULL, XSTDNON);
    XCHECK_VOID((pHeader != NULL));

    XJSON_AddString(pHeader, "type", "webrtc");
    XJSON_AddString(pHeader, "action", "ice");
    XJSON_AddString(pHeader, "candidate", pCand);
    XJSON_AddString(pHeader, "sdpMid", pUseMid);

    size_t nLen = 0;
    char *pJson = XJSON_DumpObj(pHeader, 0, &nLen);
    if (pJson != NULL)
    {
        DirectGate_WebRTC_SendSignal(pRTC, pJson, nLen);
        free(pJson);
    }

    XJSON_FreeObject(pHeader);
}

/* Callback: ICE gathering state change */
static void DirectGate_WebRTC_OnGatheringStateChange(int nPC, rtcGatheringState state, void *pPtr)
{
    directgate_webrtc_t *pRTC = (directgate_webrtc_t*)pPtr;
    if (pRTC != NULL) pRTC->nPeerConnectionID = nPC;

    const char *pStates[] = {"new", "inprogress", "complete"};
    const char *pStateStr = (state >= 0 && state <= 2) ? pStates[state] : "unknown";

    xlogd("ICE gathering state changed: pc(%d), dc(%d), state(%s)",
        DirectGate_WebRTC_GetPC(pRTC), DirectGate_WebRTC_GetDC(pRTC), pStateStr);
}

/* Callback: peer connection state change */
static void DirectGate_WebRTC_OnStateChange(int nPC, rtcState state, void *pPtr)
{
    directgate_webrtc_t *pRTC = (directgate_webrtc_t*)pPtr;
    if (pRTC != NULL) pRTC->nPeerConnectionID = nPC;

    const char *pStates[] = {
        "new",
        "connecting",
        "connected",
        "disconnected",
        "failed",
        "closed"
    };

    xlogi("Peer connection state changed: pc(%d), dc(%d), state(%s)",
        DirectGate_WebRTC_GetPC(pRTC), DirectGate_WebRTC_GetDC(pRTC),
        (state >= 0 && state <= 5) ? pStates[state] : "unknown");
}

/* Callback: ICE connection state change */
static void DirectGate_WebRTC_OnIceStateChange(int nPC, rtcIceState state, void *pPtr)
{
    directgate_webrtc_t *pRTC = (directgate_webrtc_t*)pPtr;
    if (pRTC != NULL) pRTC->nPeerConnectionID = nPC;

    const char *pStates[] = {
        "new",
        "checking",
        "connected",
        "completed",
        "failed",
        "disconnected",
        "closed"
    };

    xlogi("ICE state changed: pc(%d), dc(%d), state(%s)",
        DirectGate_WebRTC_GetPC(pRTC), DirectGate_WebRTC_GetDC(pRTC),
        (state >= 0 && state <= 6) ? pStates[state] : "unknown");
}

/* Callback: signaling state change */
static void DirectGate_WebRTC_OnSignalingStateChange(int nPC, rtcSignalingState state, void *pPtr)
{
    directgate_webrtc_t *pRTC = (directgate_webrtc_t*)pPtr;
    if (pRTC != NULL) pRTC->nPeerConnectionID = nPC;

    const char *pStates[] = {
        "stable",
        "have-local-offer",
        "have-remote-offer",
        "have-local-answer",
        "have-remote-answer"
    };

    xlogd("Signaling state changed: pc(%d), dc(%d), state(%s)",
        DirectGate_WebRTC_GetPC(pRTC), DirectGate_WebRTC_GetDC(pRTC),
        (state >= 0 && state <= 4) ? pStates[state] : "unknown");
}

/* Callback: data channel opened (libdatachannel thread) */
static void DirectGate_WebRTC_OnDataChannelOpen(int nDC, void *pPtr)
{
    directgate_webrtc_t *pRTC = (directgate_webrtc_t*)pPtr;
    XCHECK_VOID((pRTC != NULL));

    if (pRTC->nDataChannelID != nDC)
    {
        xlogd("Ignoring stale WebRTC data channel open: pc(%d), dc(%d), current(%d)",
            DirectGate_WebRTC_GetPC(pRTC), nDC, DirectGate_WebRTC_GetDC(pRTC));

        return;
    }

    xlogn("WebRTC data channel opened: pc(%d), dc(%d), pipefd(%d)",
        DirectGate_WebRTC_GetPC(pRTC), nDC, DirectGate_WebRTC_GetPipe(pRTC));

    DirectGate_WebRTC_Enqueue(pRTC, DIRECTGATE_WEBRTC_OPEN, nDC, NULL, 0);
}

/* Callback: data channel closed (libdatachannel thread) */
static void DirectGate_WebRTC_OnDataChannelClosed(int nDC, void *pPtr)
{
    directgate_webrtc_t *pRTC = (directgate_webrtc_t*)pPtr;
    XCHECK_VOID((pRTC != NULL));

    if (pRTC->nDataChannelID != nDC)
    {
        xlogd("Ignoring stale WebRTC data channel close: pc(%d), dc(%d), current(%d)",
            DirectGate_WebRTC_GetPC(pRTC), nDC, DirectGate_WebRTC_GetDC(pRTC));

        return;
    }

    xlogn("WebRTC data channel closed: pc(%d), dc(%d), pipefd(%d)",
        DirectGate_WebRTC_GetPC(pRTC), nDC, DirectGate_WebRTC_GetPipe(pRTC));

    DirectGate_WebRTC_Enqueue(pRTC, DIRECTGATE_WEBRTC_CLOSED, nDC, NULL, 0);
}

/* Callback: data channel error */
static void DirectGate_WebRTC_OnDataChannelError(int nDC, const char *pError, void *pPtr)
{
    directgate_webrtc_t *pRTC = (directgate_webrtc_t*)pPtr;
    if (pRTC != NULL && pRTC->nDataChannelID != nDC)
    {
        xlogd("Ignoring stale WebRTC data channel error: pc(%d), dc(%d), current(%d), error(%s)",
            DirectGate_WebRTC_GetPC(pRTC), nDC, DirectGate_WebRTC_GetDC(pRTC), pError ? pError : "unknown");

        return;
    }

    xloge("WebRTC data channel error: pc(%d), dc(%d), error(%s)",
        DirectGate_WebRTC_GetPC(pRTC), nDC, pError ? pError : "unknown");
}

/* Callback: data channel message received (libdatachannel thread) */
static void DirectGate_WebRTC_OnDataChannelMessage(int nDC, const char *pMessage, int nSize, void *pPtr)
{
    directgate_webrtc_t *pRTC = (directgate_webrtc_t*)pPtr;
    XCHECK_VOID((pRTC != NULL));
    XCHECK_VOID((pMessage != NULL));
    XCHECK_VOID((nSize > 0));

    if (pRTC->nDataChannelID != nDC)
    {
        xlogd("Ignoring stale WebRTC data channel message: pc(%d), dc(%d), current(%d), bytes(%d)",
            DirectGate_WebRTC_GetPC(pRTC), nDC, DirectGate_WebRTC_GetDC(pRTC), nSize);

        return;
    }

    xlogd("Received WebRTC data channel message: pc(%d), dc(%d), bytes(%d)",
        DirectGate_WebRTC_GetPC(pRTC), DirectGate_WebRTC_GetDC(pRTC), nSize);

    DirectGate_WebRTC_Enqueue(pRTC, DIRECTGATE_WEBRTC_DATA, nDC, (const uint8_t*)pMessage, (size_t)nSize);
}

/* Callback: incoming data channel (from remote peer) */
static void DirectGate_WebRTC_OnDataChannel(int nPC, int nDC, void *pPtr)
{
    directgate_webrtc_t *pRTC = (directgate_webrtc_t*)pPtr;
    XCHECK_VOID((pRTC != NULL));

    if (pRTC->nDataChannelID >= 0 && pRTC->nDataChannelID != nDC)
    {
        xlogw("Replacing stale WebRTC data channel: pc(%d), oldDc(%d), newDc(%d)",
            DirectGate_WebRTC_GetPC(pRTC), pRTC->nDataChannelID, nDC);

        DirectGate_WebRTC_CloseDataChannel(pRTC->nDataChannelID);
    }

    pRTC->nDataChannelID = nDC;
    pRTC->nPeerConnectionID = nPC;

    xlogi("Accepted incoming WebRTC data channel: pc(%d), dc(%d), pipefd(%d)",
        DirectGate_WebRTC_GetPC(pRTC), DirectGate_WebRTC_GetDC(pRTC), DirectGate_WebRTC_GetPipe(pRTC));

    rtcSetUserPointer(nDC, pRTC);
    rtcSetOpenCallback(nDC, DirectGate_WebRTC_OnDataChannelOpen);
    rtcSetClosedCallback(nDC, DirectGate_WebRTC_OnDataChannelClosed);
    rtcSetErrorCallback(nDC, DirectGate_WebRTC_OnDataChannelError);
    rtcSetMessageCallback(nDC, DirectGate_WebRTC_OnDataChannelMessage);
}

XSTATUS DirectGate_WebRTC_CreateOffer(directgate_webrtc_t *pRTC)
{
    XCHECK((pRTC != NULL), XSTDERR);

    DirectGate_WebRTC_InitLib(pRTC);

    /* Destroy existing connection if any */
    if (pRTC->nPeerConnectionID >= 0)
        DirectGate_WebRTC_Destroy(pRTC);

    /* Create peer connection with ICE servers */
    rtcConfiguration config;
    memset(&config, 0, sizeof(config));

    const char *pConfigServers[DIRECTGATE_MAX_ICE_SERVERS];
    if (pRTC->nIceSrvCount > 0)
    {
        for (int i = 0; i < pRTC->nIceSrvCount; i++)
            pConfigServers[i] = pRTC->sIceServers[i];

        config.iceServers = pConfigServers;
        config.iceServersCount = pRTC->nIceSrvCount;
    }
    else
    {
        config.iceServers = g_pIceServers;
        config.iceServersCount = 2;
    }

    pRTC->nPeerConnectionID = rtcCreatePeerConnection(&config);
    XCHECK((pRTC->nPeerConnectionID >= 0),
        xthrow("Failed to create peer connection: iceServers(%d)", config.iceServersCount));

    xlogn("Created WebRTC peer connection: pc(%d), dc(%d), iceServers(%d)",
        DirectGate_WebRTC_GetPC(pRTC), DirectGate_WebRTC_GetDC(pRTC), config.iceServersCount);

    /* Set callbacks */
    rtcSetUserPointer(pRTC->nPeerConnectionID, pRTC);
    rtcSetLocalDescriptionCallback(pRTC->nPeerConnectionID, DirectGate_WebRTC_OnLocalDescription);
    rtcSetLocalCandidateCallback(pRTC->nPeerConnectionID, DirectGate_WebRTC_OnLocalCandidate);
    rtcSetStateChangeCallback(pRTC->nPeerConnectionID, DirectGate_WebRTC_OnStateChange);
    rtcSetIceStateChangeCallback(pRTC->nPeerConnectionID, DirectGate_WebRTC_OnIceStateChange);
    rtcSetGatheringStateChangeCallback(pRTC->nPeerConnectionID, DirectGate_WebRTC_OnGatheringStateChange);
    rtcSetSignalingStateChangeCallback(pRTC->nPeerConnectionID, DirectGate_WebRTC_OnSignalingStateChange);

    /* Create data channel — triggers offer SDP generation */
    pRTC->nDataChannelID = rtcCreateDataChannel(pRTC->nPeerConnectionID, "directgate");
    if (pRTC->nDataChannelID < 0)
    {
        xloge("Failed to create WebRTC data channel: pc(%d)", DirectGate_WebRTC_GetPC(pRTC));
        DirectGate_WebRTC_Destroy(pRTC);
        return XSTDERR;
    }

    rtcSetUserPointer(pRTC->nDataChannelID, pRTC);
    rtcSetOpenCallback(pRTC->nDataChannelID, DirectGate_WebRTC_OnDataChannelOpen);
    rtcSetClosedCallback(pRTC->nDataChannelID, DirectGate_WebRTC_OnDataChannelClosed);
    rtcSetErrorCallback(pRTC->nDataChannelID, DirectGate_WebRTC_OnDataChannelError);
    rtcSetMessageCallback(pRTC->nDataChannelID, DirectGate_WebRTC_OnDataChannelMessage);

    xlogi("Initiated WebRTC offer, waiting for SDP generation: pc(%d), dc(%d)",
        DirectGate_WebRTC_GetPC(pRTC), DirectGate_WebRTC_GetDC(pRTC));

    return XSTDOK;
}

XSTATUS DirectGate_WebRTC_HandleAnswer(directgate_webrtc_t *pRTC, const char *pSdp)
{
    XCHECK((pRTC != NULL), XSTDERR);
    XCHECK((pSdp != NULL), XSTDERR);

    if (pRTC->nPeerConnectionID < 0)
    {
        xlogw("Dropping WebRTC answer, peer connection not exists: dc(%d)",
            DirectGate_WebRTC_GetDC(pRTC));

        return XSTDERR;
    }

    char *pUnescaped = DirectGate_JSON_Unescape(pSdp);
    if (pUnescaped == NULL)
    {
        xloge("Failed to allocate memory for answer SDP: pc(%d), dc(%d)",
            DirectGate_WebRTC_GetPC(pRTC), DirectGate_WebRTC_GetDC(pRTC));

        return XSTDERR;
    }

    int nRet = rtcSetRemoteDescription(pRTC->nPeerConnectionID, pUnescaped, "answer");
    free(pUnescaped);

    if (nRet < 0)
    {
        xloge("Failed to set remote WebRTC answer: pc(%d), dc(%d), ret(%d)",
            DirectGate_WebRTC_GetPC(pRTC), DirectGate_WebRTC_GetDC(pRTC), nRet);

        return XSTDERR;
    }

    xlogi("Remote WebRTC answer applied, waiting for data channel open: pc(%d), dc(%d)",
        DirectGate_WebRTC_GetPC(pRTC), DirectGate_WebRTC_GetDC(pRTC));

    return XSTDOK;
}

XSTATUS DirectGate_WebRTC_HandleOffer(directgate_webrtc_t *pRTC, const char *pSdp)
{
    XCHECK((pRTC != NULL), XSTDERR);
    XCHECK((pSdp != NULL), XSTDERR);

    DirectGate_WebRTC_InitLib(pRTC);

    /* Destroy existing connection if any */
    if (pRTC->nPeerConnectionID >= 0)
        DirectGate_WebRTC_Destroy(pRTC);

    /* Create peer connection with ICE servers */
    rtcConfiguration config;
    memset(&config, 0, sizeof(config));

    const char *pConfigServers[DIRECTGATE_MAX_ICE_SERVERS];
    if (pRTC->nIceSrvCount > 0)
    {
        for (int i = 0; i < pRTC->nIceSrvCount; i++)
            pConfigServers[i] = pRTC->sIceServers[i];

        config.iceServers = pConfigServers;
        config.iceServersCount = pRTC->nIceSrvCount;
    }
    else
    {
        config.iceServers = g_pIceServers;
        config.iceServersCount = 2;
    }

    pRTC->nPeerConnectionID = rtcCreatePeerConnection(&config);
    XCHECK((pRTC->nPeerConnectionID >= 0),
        xthrow("Failed to create peer connection: iceServers(%d)", config.iceServersCount));

    xlogn("Created WebRTC peer connection: pc(%d), dc(%d), iceServers(%d)",
        DirectGate_WebRTC_GetPC(pRTC), DirectGate_WebRTC_GetDC(pRTC), config.iceServersCount);

    /* Set callbacks */
    rtcSetUserPointer(pRTC->nPeerConnectionID, pRTC);
    rtcSetLocalDescriptionCallback(pRTC->nPeerConnectionID, DirectGate_WebRTC_OnLocalDescription);
    rtcSetLocalCandidateCallback(pRTC->nPeerConnectionID, DirectGate_WebRTC_OnLocalCandidate);
    rtcSetStateChangeCallback(pRTC->nPeerConnectionID, DirectGate_WebRTC_OnStateChange);
    rtcSetDataChannelCallback(pRTC->nPeerConnectionID, DirectGate_WebRTC_OnDataChannel);
    rtcSetIceStateChangeCallback(pRTC->nPeerConnectionID, DirectGate_WebRTC_OnIceStateChange);
    rtcSetGatheringStateChangeCallback(pRTC->nPeerConnectionID, DirectGate_WebRTC_OnGatheringStateChange);
    rtcSetSignalingStateChangeCallback(pRTC->nPeerConnectionID, DirectGate_WebRTC_OnSignalingStateChange);

    /* Unescape JSON string (xutils parser does not unescape \r\n etc.) */
    char *pUnescaped = DirectGate_JSON_Unescape(pSdp);
    if (pUnescaped == NULL)
    {
        xloge("Failed to allocate memory for offer SDP: pc(%d), dc(%d)",
            DirectGate_WebRTC_GetPC(pRTC), DirectGate_WebRTC_GetDC(pRTC));

        DirectGate_WebRTC_Destroy(pRTC);
        return XSTDERR;
    }

    /* Set the remote description (offer from client) — this triggers answer generation */
    int nRet = rtcSetRemoteDescription(pRTC->nPeerConnectionID, pUnescaped, "offer");
    free(pUnescaped);

    if (nRet < 0)
    {
        xloge("Failed to set remote WebRTC offer: pc(%d), dc(%d), ret(%d)",
            DirectGate_WebRTC_GetPC(pRTC), DirectGate_WebRTC_GetDC(pRTC), nRet);

        DirectGate_WebRTC_Destroy(pRTC);
        return XSTDERR;
    }

    xlogi("Remote WebRTC offer applied, answer generation pending: pc(%d), dc(%d)",
        DirectGate_WebRTC_GetPC(pRTC), DirectGate_WebRTC_GetDC(pRTC));

    /* Apply any ICE candidates that arrived before the offer */
    DirectGate_WebRTC_FlushPendingIce(pRTC);

    return XSTDOK;
}

XSTATUS DirectGate_WebRTC_HandleIceCandidate(directgate_webrtc_t *pRTC, const char *pCandidate, const char *pMid)
{
    XCHECK((pRTC != NULL), XSTDERR);
    XCHECK((pCandidate != NULL), XSTDERR);

    if (pRTC->nPeerConnectionID < 0)
    {
        /* Buffer the candidate as it arrived before the offer was processed */
        DirectGate_WebRTC_BufferIce(pRTC, pCandidate, pMid);
        return XSTDOK;
    }

    /* Use DIRECTGATE_RTC_DEFAULT_MID as fallback when sdpMid is NULL or empty */
    const char *pUseMid = xstrused(pMid) ? pMid : DIRECTGATE_RTC_DEFAULT_MID;
    int nRet = rtcAddRemoteCandidate(pRTC->nPeerConnectionID, pCandidate, pUseMid);
    if (nRet < 0)
    {
        xloge("Failed to add remote ICE candidate: pc(%d), dc(%d), ret(%d), mid(%s)",
            DirectGate_WebRTC_GetPC(pRTC), DirectGate_WebRTC_GetDC(pRTC), nRet, pUseMid);

        return XSTDERR;
    }

    return XSTDOK;
}

XSTATUS DirectGate_WebRTC_Send(directgate_webrtc_t *pRTC, const uint8_t *pData, size_t nLen)
{
    XCHECK((pRTC != NULL), XSTDERR);
    XCHECK((pData != NULL), XSTDERR);
    XCHECK((nLen > 0), XSTDERR);

    XCHECK_NL((pRTC->nPeerConnectionID >= 0), XSTDERR);
    XCHECK_NL(pRTC->bConnected, XSTDERR);

    int nRet = rtcSendMessage(pRTC->nDataChannelID, (const char*)pData, (int)nLen);
    return (nRet >= 0) ? XSTDOK : XSTDERR;
}

xbool_t DirectGate_WebRTC_IsConnected(const directgate_webrtc_t *pRTC)
{
    XCHECK_NL((pRTC != NULL), XFALSE);
    return pRTC->bConnected && pRTC->nDataChannelID >= 0;
}

int DirectGate_WebRTC_GetBufferedAmount(const directgate_webrtc_t *pRTC)
{
    XCHECK((pRTC != NULL), XSTDERR);
    XCHECK_NL((pRTC->nDataChannelID >= 0), XSTDERR);
    return rtcGetBufferedAmount(pRTC->nDataChannelID);
}

static void DirectGate_WebRTC_DispatchDataCb(directgate_webrtc_t *pRTC, directgate_webrtc_event_t *pEvt)
{
    XCHECK_VOID((pRTC != NULL));
    XCHECK_VOID((pEvt != NULL));
    XCHECK_VOID_NL((pRTC->dataCb != NULL));

    xlogd("Dispatching WebRTC data callback: pc(%d), dc(%d), bytes(%zu)",
        DirectGate_WebRTC_GetPC(pRTC), DirectGate_WebRTC_GetDC(pRTC), pEvt->nLength);

    pRTC->dataCb(pEvt->pData, pEvt->nLength, pRTC->pDataCtx);
}

static void DirectGate_WebRTC_DispatchSignalCb(directgate_webrtc_t *pRTC, directgate_webrtc_event_t *pEvt)
{
    XCHECK_VOID((pRTC != NULL));
    XCHECK_VOID((pEvt != NULL));
    XCHECK_VOID_NL((pRTC->signalCb != NULL));

    xlogd("Dispatching WebRTC signal callback: pc(%d), dc(%d), bytes(%zu)",
        DirectGate_WebRTC_GetPC(pRTC), DirectGate_WebRTC_GetDC(pRTC), pEvt->nLength);

    pRTC->signalCb((const char*)pEvt->pData, pEvt->nLength, pRTC->pSignalCtx);
}

void DirectGate_WebRTC_ProcessQueue(directgate_webrtc_t *pRTC)
{
    XCHECK_VOID((pRTC != NULL));

    /* Drain notification bytes from pipe */
    DirectGate_WebRTC_DrainPipe(pRTC);

    directgate_webrtc_event_t *pHead;
    pHead = XSell_WebRTC_DetachQueue(pRTC);

    /* Dispatch events in order on the main thread */
    while (pHead != NULL)
    {
        directgate_webrtc_event_t *pEvt = pHead;
        pHead = pHead->pNext;

        if (pEvt->nSourceID >= 0 &&
            pEvt->eType != DIRECTGATE_WEBRTC_SIGNAL &&
            pEvt->nSourceID != pRTC->nDataChannelID)
        {
            xlogd("Dropping stale WebRTC queue event: pc(%d), dc(%d), current(%d), type(%d)",
                DirectGate_WebRTC_GetPC(pRTC), pEvt->nSourceID, DirectGate_WebRTC_GetDC(pRTC), (int)pEvt->eType);

            free(pEvt->pData);
            free(pEvt);
            continue;
        }

        switch (pEvt->eType)
        {
            case DIRECTGATE_WEBRTC_OPEN:
            {
                pRTC->bConnected = XTRUE;
                xlogn("WebRTC P2P data channel is active: pc(%d), dc(%d), pipefd(%d)",
                    DirectGate_WebRTC_GetPC(pRTC), DirectGate_WebRTC_GetDC(pRTC), DirectGate_WebRTC_GetPipe(pRTC));

                break;
            }
            case DIRECTGATE_WEBRTC_CLOSED:
            {
                pRTC->bConnected = XFALSE;
                xlogn("WebRTC P2P data channel is inactive: pc(%d), dc(%d), pipefd(%d)",
                    DirectGate_WebRTC_GetPC(pRTC), pEvt->nSourceID, DirectGate_WebRTC_GetPipe(pRTC));

                if (pRTC->nDataChannelID == pEvt->nSourceID)
                    pRTC->nDataChannelID = -1;

                break;
            }
            case DIRECTGATE_WEBRTC_DATA:
                DirectGate_WebRTC_DispatchDataCb(pRTC, pEvt);
                break;
            case DIRECTGATE_WEBRTC_SIGNAL:
                DirectGate_WebRTC_DispatchSignalCb(pRTC, pEvt);
                break;
        }

        free(pEvt->pData);
        free(pEvt);
    }
}

int DirectGate_WebRTC_GetPipeFd(const directgate_webrtc_t *pRTC)
{
    XCHECK_NL((pRTC != NULL), XSTDERR);
    return (int)pRTC->nPipeFds[0];
}
