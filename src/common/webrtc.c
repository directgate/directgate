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

#include <openssl/rand.h>
#include <strings.h>
#include <time.h>

#define DIRECTGATE_RTC_DEFAULT_MID  "0"
#define DIRECTGATE_RTC_VIDEO_CLOCK_RATE 90000U
#define DIRECTGATE_RTC_H264_PAYLOAD_TYPE 102U
#define DIRECTGATE_RTC_RTP_HEADER_BYTES 12U
#define DIRECTGATE_RTC_RTP_MAX_PAYLOAD 1188U
/* Retransmission cache in packets: ~1s of video at 12 Mbps with
 * 1200-byte packets. Bounded memory (< ~1.5 MB) per session. */
#define DIRECTGATE_RTC_NACK_CACHE 1024U
#define DIRECTGATE_RTC_H264_FU_A 28U
#define DIRECTGATE_RTC_H264_START 0x80U
#define DIRECTGATE_RTC_H264_END 0x40U

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

static int DirectGate_WebRTC_GetVideoTrack(const directgate_webrtc_t *pRTC)
{
    XCHECK_NL((pRTC != NULL), XSTDERR);
    return pRTC->nVideoTrackID;
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

static uint32_t DirectGate_WebRTC_RandomU32(uint32_t nFallback)
{
    uint32_t nValue = 0;
    if (RAND_bytes((uint8_t*)&nValue, sizeof(nValue)) != 1 || nValue == 0)
        nValue = nFallback ? nFallback : (uint32_t)time(NULL);

    return nValue;
}

static void DirectGate_WebRTC_CopySdpLine(char *pDst, size_t nDstSize,
                                      const char *pLine, size_t nLineLen)
{
    XCHECK_VOID_NL((pDst != NULL && nDstSize > 0));
    if (pLine == NULL)
    {
        pDst[0] = '\0';
        return;
    }

    if (nLineLen >= nDstSize)
        nLineLen = nDstSize - 1U;

    memcpy(pDst, pLine, nLineLen);
    pDst[nLineLen] = '\0';
}

static xbool_t DirectGate_WebRTC_ParseRemoteH264(const char *pSdp,
                                             uint8_t *pPayloadType,
                                             char *pMid,
                                             size_t nMidSize,
                                             char *pProfile,
                                             size_t nProfileSize)
{
    XCHECK_NL(xstrused(pSdp), XFALSE);
    XCHECK_NL((pPayloadType != NULL), XFALSE);
    XCHECK_NL((pMid != NULL && nMidSize > 0), XFALSE);
    XCHECK_NL((pProfile != NULL && nProfileSize > 0), XFALSE);

    xbool_t bInVideo = XFALSE;
    xbool_t bFound = XFALSE;
    uint32_t nPayload = 0;
    pMid[0] = '\0';
    pProfile[0] = '\0';

    const char *p = pSdp;
    while (*p)
    {
        const char *pLine = p;
        while (*p && *p != '\r' && *p != '\n') p++;
        size_t nLineLen = (size_t)(p - pLine);
        while (*p == '\r' || *p == '\n') p++;

        if (nLineLen >= 2 && !strncmp(pLine, "m=", 2))
        {
            bInVideo = (nLineLen >= 8 && !strncmp(pLine, "m=video", 7)) ? XTRUE : XFALSE;
            continue;
        }

        if (!bInVideo) continue;

        if (nLineLen > 6 && !strncmp(pLine, "a=mid:", 6))
        {
            DirectGate_WebRTC_CopySdpLine(pMid, nMidSize, pLine + 6, nLineLen - 6);
            continue;
        }

        if (!bFound && nLineLen > 9 && !strncmp(pLine, "a=rtpmap:", 9))
        {
            const char *pCodec = memchr(pLine, ' ', nLineLen);
            if (pCodec == NULL) continue;

            size_t nCodecLen = nLineLen - (size_t)(pCodec - pLine) - 1U;
            if (nCodecLen >= 10 && !strncasecmp(pCodec + 1, "H264/90000", 10))
            {
                nPayload = (uint32_t)atoi(pLine + 9);
                if (nPayload > 0 && nPayload <= 127U)
                    bFound = XTRUE;
            }

            continue;
        }

        if (bFound && nLineLen > 7 && !strncmp(pLine, "a=fmtp:", 7))
        {
            uint32_t nFmtpPayload = (uint32_t)atoi(pLine + 7);
            if (nFmtpPayload != nPayload) continue;

            const char *pSpace = memchr(pLine, ' ', nLineLen);
            if (pSpace != NULL)
            {
                size_t nProfileLen = nLineLen - (size_t)(pSpace - pLine) - 1U;
                DirectGate_WebRTC_CopySdpLine(pProfile, nProfileSize, pSpace + 1, nProfileLen);
            }
        }
    }

    if (!bFound) return XFALSE;
    *pPayloadType = (uint8_t)nPayload;
    if (!xstrused(pMid))
        xstrncpy(pMid, nMidSize, DIRECTGATE_RTC_DEFAULT_MID);

    return XTRUE;
}

static const uint8_t *DirectGate_WebRTC_FindStartCode(const uint8_t *pData,
                                                  const uint8_t *pEnd,
                                                  size_t *pStartLen)
{
    const uint8_t *p = pData;
    while (p + 3 <= pEnd)
    {
        if (p[0] == 0 && p[1] == 0 && p[2] == 1)
        {
            if (pStartLen != NULL) *pStartLen = 3U;
            return p;
        }

        if (p + 4 <= pEnd && p[0] == 0 && p[1] == 0 && p[2] == 0 && p[3] == 1)
        {
            if (pStartLen != NULL) *pStartLen = 4U;
            return p;
        }

        p++;
    }

    return NULL;
}

static void DirectGate_WebRTC_WriteRtpHeader(uint8_t *pPacket,
                                         const directgate_webrtc_t *pRTC,
                                         uint16_t nSeq,
                                         uint32_t nTimestamp,
                                         xbool_t bMarker)
{
    pPacket[0] = 0x80;
    pPacket[1] = (uint8_t)((bMarker ? 0x80U : 0U) | pRTC->nVideoPayloadType);
    pPacket[2] = (uint8_t)(nSeq >> 8);
    pPacket[3] = (uint8_t)(nSeq & 0xFFU);
    pPacket[4] = (uint8_t)(nTimestamp >> 24);
    pPacket[5] = (uint8_t)(nTimestamp >> 16);
    pPacket[6] = (uint8_t)(nTimestamp >> 8);
    pPacket[7] = (uint8_t)(nTimestamp & 0xFFU);
    pPacket[8] = (uint8_t)(pRTC->nVideoSsrc >> 24);
    pPacket[9] = (uint8_t)(pRTC->nVideoSsrc >> 16);
    pPacket[10] = (uint8_t)(pRTC->nVideoSsrc >> 8);
    pPacket[11] = (uint8_t)(pRTC->nVideoSsrc & 0xFFU);
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

static void DirectGate_WebRTC_DetachVideoTrack(int nTrack)
{
    if (nTrack < 0) return;
    rtcSetUserPointer(nTrack, NULL);
    rtcSetOpenCallback(nTrack, NULL);
    rtcSetClosedCallback(nTrack, NULL);
    rtcSetErrorCallback(nTrack, NULL);
    rtcSetMessageCallback(nTrack, NULL);
}

static void DirectGate_WebRTC_CloseVideoTrack(int nTrack)
{
    if (nTrack < 0) return;
    DirectGate_WebRTC_DetachVideoTrack(nTrack);
    rtcClose(nTrack);
    rtcDeleteTrack(nTrack);
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
    pRTC->nVideoTrackID = -1;
    pRTC->nIceSrvCount = 0;
    pRTC->bConnected = XFALSE;
    pRTC->bVideoEnabled = XFALSE;
    pRTC->bVideoTrackOpen = XFALSE;
    pRTC->bVideoKeyframeRequested = XFALSE;
    pRTC->nVideoPayloadType = DIRECTGATE_RTC_H264_PAYLOAD_TYPE;
    pRTC->nVideoSeq = (uint16_t)(DirectGate_WebRTC_RandomU32(1U) & 0xFFFFU);
    pRTC->nVideoSsrc = DirectGate_WebRTC_RandomU32(0x58485348U);
    pRTC->nVideoTimestamp = DirectGate_WebRTC_RandomU32(0x44534b54U);
    pRTC->nVideoLastPtsUs = 0;
    pRTC->bVideoHasTimestamp = XFALSE;
    pRTC->bVideoLossUpdated = XFALSE;
    pRTC->nVideoFractionLost = -1;
    pRTC->sVideoMid[0] = '\0';

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

    if (pRTC->nVideoTrackID >= 0)
    {
        DirectGate_WebRTC_CloseVideoTrack(pRTC->nVideoTrackID);
        pRTC->nVideoTrackID = -1;
    }

    if (pRTC->nPeerConnectionID >= 0)
    {
        rtcClosePeerConnection(pRTC->nPeerConnectionID);
        rtcDeletePeerConnection(pRTC->nPeerConnectionID);
        pRTC->nPeerConnectionID = -1;
    }

    pRTC->bConnected = XFALSE;
    pRTC->bVideoTrackOpen = XFALSE;
    pRTC->bVideoKeyframeRequested = XFALSE;
    pRTC->bVideoHasTimestamp = XFALSE;
    pRTC->bVideoLossUpdated = XFALSE;
    pRTC->nVideoFractionLost = -1;
    pRTC->sVideoMid[0] = '\0';
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

void DirectGate_WebRTC_ParseRtcp(const uint8_t *pData, size_t nSize,
                             xbool_t *pKeyframeRequest, int *pFractionLost)
{
    if (pKeyframeRequest != NULL) *pKeyframeRequest = XFALSE;
    if (pFractionLost != NULL) *pFractionLost = -1;
    XCHECK_VOID_NL((pData != NULL && nSize >= 4));

    /* Browsers deliver compound RTCP: RR + SDES + feedback packets in one
     * datagram. Walk every packet; a PLI hiding behind an RR must still be
     * seen, and the RR report blocks carry the loss signal the adaptive
     * bitrate controller feeds on. */
    size_t nOffset = 0;
    while (nOffset + 4U <= nSize)
    {
        const uint8_t *p = pData + nOffset;
        if ((p[0] >> 6U) != 2U) break; /* RTCP version must be 2 */

        uint8_t nCount = p[0] & 0x1FU;
        uint8_t nType = p[1];
        size_t nLength = ((size_t)((p[2] << 8U) | p[3]) + 1U) * 4U;
        if (nOffset + nLength > nSize) break;

        if (nType == 206 && (nCount == 1 || nCount == 4))
        {
            /* PLI: PT=PSFB(206), FMT=1. FIR: PT=PSFB(206), FMT=4. */
            if (pKeyframeRequest != NULL) *pKeyframeRequest = XTRUE;
        }
        else if (nType == 192)
        {
            /* Some legacy stacks still emit FIR as PT=192. */
            if (pKeyframeRequest != NULL) *pKeyframeRequest = XTRUE;
        }
        else if ((nType == 201 || nType == 200) && nCount > 0)
        {
            /* RR(201): report blocks start after header(4) + SSRC(4).
             * SR(200): after header(4) + SSRC(4) + sender info(20).
             * Each 24-byte block leads with the source SSRC followed by
             * the fraction-lost octet (lost/256 since the last report). */
            size_t nBlockBase = (nType == 200) ? 28U : 8U;
            for (uint8_t i = 0; i < nCount; i++)
            {
                size_t nBlock = nBlockBase + (size_t)i * 24U;
                if (nBlock + 24U > nLength) break;

                int nFraction = p[nBlock + 4U];
                if (pFractionLost != NULL && nFraction > *pFractionLost)
                    *pFractionLost = nFraction;
            }
        }

        nOffset += nLength;
    }
}

static void DirectGate_WebRTC_OnVideoTrackOpen(int nTrack, void *pPtr)
{
    directgate_webrtc_t *pRTC = (directgate_webrtc_t*)pPtr;
    XCHECK_VOID((pRTC != NULL));

    if (pRTC->nVideoTrackID != nTrack)
    {
        xlogd("Ignoring stale WebRTC video track open: pc(%d), track(%d), current(%d)",
            DirectGate_WebRTC_GetPC(pRTC), nTrack, DirectGate_WebRTC_GetVideoTrack(pRTC));

        return;
    }

    xlogn("WebRTC video track opened: pc(%d), track(%d), pt(%u), ssrc(%u), mid(%s)",
        DirectGate_WebRTC_GetPC(pRTC), nTrack, pRTC->nVideoPayloadType,
        pRTC->nVideoSsrc, pRTC->sVideoMid);

    DirectGate_WebRTC_Enqueue(pRTC, DIRECTGATE_WEBRTC_VIDEO_OPEN, nTrack, NULL, 0);
}

static void DirectGate_WebRTC_OnVideoTrackClosed(int nTrack, void *pPtr)
{
    directgate_webrtc_t *pRTC = (directgate_webrtc_t*)pPtr;
    XCHECK_VOID((pRTC != NULL));

    if (pRTC->nVideoTrackID != nTrack)
    {
        xlogd("Ignoring stale WebRTC video track close: pc(%d), track(%d), current(%d)",
            DirectGate_WebRTC_GetPC(pRTC), nTrack, DirectGate_WebRTC_GetVideoTrack(pRTC));

        return;
    }

    xlogn("WebRTC video track closed: pc(%d), track(%d)",
        DirectGate_WebRTC_GetPC(pRTC), nTrack);

    DirectGate_WebRTC_Enqueue(pRTC, DIRECTGATE_WEBRTC_VIDEO_CLOSED, nTrack, NULL, 0);
}

static void DirectGate_WebRTC_OnVideoTrackError(int nTrack, const char *pError, void *pPtr)
{
    directgate_webrtc_t *pRTC = (directgate_webrtc_t*)pPtr;
    XCHECK_VOID((pRTC != NULL));

    if (pRTC->nVideoTrackID != nTrack)
    {
        xlogd("Ignoring stale WebRTC video track error: pc(%d), track(%d), current(%d), error(%s)",
            DirectGate_WebRTC_GetPC(pRTC), nTrack, DirectGate_WebRTC_GetVideoTrack(pRTC),
            pError ? pError : "unknown");

        return;
    }

    xloge("WebRTC video track error: pc(%d), track(%d), error(%s)",
        DirectGate_WebRTC_GetPC(pRTC), nTrack, pError ? pError : "unknown");
}

static void DirectGate_WebRTC_OnVideoTrackMessage(int nTrack, const char *pMessage, int nSize, void *pPtr)
{
    directgate_webrtc_t *pRTC = (directgate_webrtc_t*)pPtr;
    XCHECK_VOID((pRTC != NULL));
    XCHECK_VOID((pMessage != NULL));
    XCHECK_VOID((nSize > 0));

    if (pRTC->nVideoTrackID != nTrack)
    {
        xlogd("Ignoring stale WebRTC video track message: pc(%d), track(%d), current(%d), bytes(%d)",
            DirectGate_WebRTC_GetPC(pRTC), nTrack, DirectGate_WebRTC_GetVideoTrack(pRTC), nSize);

        return;
    }

    xbool_t bKeyframeRequest = XFALSE;
    int nFractionLost = -1;
    DirectGate_WebRTC_ParseRtcp((const uint8_t*)pMessage, (size_t)nSize,
        &bKeyframeRequest, &nFractionLost);

    if (bKeyframeRequest)
    {
        xlogd("Received RTCP keyframe request: pc(%d), track(%d), bytes(%d)",
            DirectGate_WebRTC_GetPC(pRTC), nTrack, nSize);

        DirectGate_WebRTC_Enqueue(pRTC, DIRECTGATE_WEBRTC_VIDEO_KEYFRAME, nTrack, NULL, 0);
    }

    if (nFractionLost >= 0)
    {
        /* Single writer (libdatachannel thread), single reader (main loop);
         * a torn read of an int is not possible on supported targets. */
        pRTC->nVideoFractionLost = nFractionLost;
        pRTC->bVideoLossUpdated = XTRUE;
    }
}

static XSTATUS DirectGate_WebRTC_AddDesktopVideoTrack(directgate_webrtc_t *pRTC, const char *pRemoteSdp)
{
    XCHECK((pRTC != NULL), XSTDERR);
    XCHECK((pRTC->nPeerConnectionID >= 0), XSTDERR);
    XCHECK_NL(pRTC->bVideoEnabled, XSTDERR);

    uint8_t nPayloadType = DIRECTGATE_RTC_H264_PAYLOAD_TYPE;
    char sMid[DIRECTGATE_RTC_VIDEO_MID_SIZE];
    char sProfile[256];
    memset(sMid, 0, sizeof(sMid));
    memset(sProfile, 0, sizeof(sProfile));

    if (!DirectGate_WebRTC_ParseRemoteH264(pRemoteSdp, &nPayloadType,
        sMid, sizeof(sMid), sProfile, sizeof(sProfile)))
    {
        xlogw("Remote WebRTC offer does not advertise H.264 video; media track disabled: pc(%d), dc(%d)",
            DirectGate_WebRTC_GetPC(pRTC), DirectGate_WebRTC_GetDC(pRTC));

        return XSTDERR;
    }

    rtcTrackInit init;
    memset(&init, 0, sizeof(init));
    init.direction = RTC_DIRECTION_SENDONLY;
    init.codec = RTC_CODEC_H264;
    init.payloadType = nPayloadType;
    init.ssrc = DirectGate_WebRTC_RandomU32(0x58485348U);
    init.mid = sMid;
    init.name = "desktop";
    init.msid = "directgate-desktop";
    init.trackId = "desktop-video";
    init.profile = xstrused(sProfile) ? sProfile : NULL;

    int nTrack = rtcAddTrackEx(pRTC->nPeerConnectionID, &init);
    if (nTrack < 0)
    {
        xlogw("Failed to add WebRTC H.264 video track: pc(%d), dc(%d), ret(%d)",
            DirectGate_WebRTC_GetPC(pRTC), DirectGate_WebRTC_GetDC(pRTC), nTrack);

        return XSTDERR;
    }

    pRTC->nVideoTrackID = nTrack;
    pRTC->bVideoTrackOpen = XFALSE;
    pRTC->bVideoKeyframeRequested = XFALSE;
    pRTC->nVideoPayloadType = nPayloadType;
    pRTC->nVideoSsrc = init.ssrc;
    pRTC->nVideoSeq = (uint16_t)(DirectGate_WebRTC_RandomU32(1U) & 0xFFFFU);
    pRTC->nVideoTimestamp = DirectGate_WebRTC_RandomU32(0x44534b54U);
    pRTC->nVideoLastPtsUs = 0;
    pRTC->bVideoHasTimestamp = XFALSE;
    pRTC->bVideoLossUpdated = XFALSE;
    pRTC->nVideoFractionLost = -1;
    xstrncpy(pRTC->sVideoMid, sizeof(pRTC->sVideoMid), sMid);

    rtcSetUserPointer(nTrack, pRTC);
    rtcSetOpenCallback(nTrack, DirectGate_WebRTC_OnVideoTrackOpen);
    rtcSetClosedCallback(nTrack, DirectGate_WebRTC_OnVideoTrackClosed);
    rtcSetErrorCallback(nTrack, DirectGate_WebRTC_OnVideoTrackError);
    rtcSetMessageCallback(nTrack, DirectGate_WebRTC_OnVideoTrackMessage);

    /* Cache outgoing RTP so browser NACKs are answered with retransmissions.
     * Without this the browser waits for a retransmission that never comes,
     * escalates to PLI and forces a full IDR burst - the main source of
     * periodic stutter on lossy links (the answer SDP already advertises
     * nack, so the browser expects it to work). */
    if (rtcChainRtcpNackResponder(nTrack, DIRECTGATE_RTC_NACK_CACHE) < 0)
        xlogw("Failed to chain RTCP NACK responder: pc(%d), track(%d)",
            DirectGate_WebRTC_GetPC(pRTC), nTrack);

    xlogi("Added WebRTC H.264 video track: pc(%d), track(%d), pt(%u), ssrc(%u), mid(%s)",
        DirectGate_WebRTC_GetPC(pRTC), nTrack, pRTC->nVideoPayloadType,
        pRTC->nVideoSsrc, pRTC->sVideoMid);

    return XSTDOK;
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

    /* Create data channel - triggers offer SDP generation */
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

    if (pRTC->bVideoEnabled)
        (void)DirectGate_WebRTC_AddDesktopVideoTrack(pRTC, pUnescaped);

    /* Set the remote description (offer from client) - this triggers answer generation */
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

void DirectGate_WebRTC_SetVideoEnabled(directgate_webrtc_t *pRTC, xbool_t bEnabled)
{
    XCHECK_VOID_NL((pRTC != NULL));
    pRTC->bVideoEnabled = bEnabled ? XTRUE : XFALSE;
}

xbool_t DirectGate_WebRTC_HasVideoTrack(const directgate_webrtc_t *pRTC)
{
    XCHECK_NL((pRTC != NULL), XFALSE);
    return pRTC->nVideoTrackID >= 0 ? XTRUE : XFALSE;
}

xbool_t DirectGate_WebRTC_IsVideoOpen(const directgate_webrtc_t *pRTC)
{
    XCHECK_NL((pRTC != NULL), XFALSE);
    if (pRTC->nVideoTrackID < 0) return XFALSE;
    if (pRTC->bVideoTrackOpen) return XTRUE;
    return rtcIsOpen(pRTC->nVideoTrackID) ? XTRUE : XFALSE;
}

xbool_t DirectGate_WebRTC_TakeVideoKeyframeRequest(directgate_webrtc_t *pRTC)
{
    XCHECK_NL((pRTC != NULL), XFALSE);
    if (!pRTC->bVideoKeyframeRequested) return XFALSE;
    pRTC->bVideoKeyframeRequested = XFALSE;
    return XTRUE;
}

xbool_t DirectGate_WebRTC_TakeVideoLossReport(directgate_webrtc_t *pRTC, uint8_t *pFractionLost)
{
    XCHECK_NL((pRTC != NULL), XFALSE);
    if (!pRTC->bVideoLossUpdated) return XFALSE;

    int nFraction = pRTC->nVideoFractionLost;
    pRTC->bVideoLossUpdated = XFALSE;
    if (nFraction < 0) return XFALSE;

    if (pFractionLost != NULL)
        *pFractionLost = (uint8_t)(nFraction > 255 ? 255 : nFraction);

    return XTRUE;
}

static uint32_t DirectGate_WebRTC_NextVideoTimestamp(directgate_webrtc_t *pRTC, uint64_t nPtsUs)
{
    XCHECK((pRTC != NULL), 0);

    if (!pRTC->bVideoHasTimestamp)
    {
        pRTC->bVideoHasTimestamp = XTRUE;
        pRTC->nVideoLastPtsUs = nPtsUs;
        return pRTC->nVideoTimestamp;
    }

    uint32_t nDelta = DIRECTGATE_RTC_VIDEO_CLOCK_RATE / 30U;
    if (nPtsUs > pRTC->nVideoLastPtsUs)
    {
        uint64_t nPtsDelta = nPtsUs - pRTC->nVideoLastPtsUs;
        uint64_t nRtpDelta = (nPtsDelta * DIRECTGATE_RTC_VIDEO_CLOCK_RATE) / 1000000ULL;
        if (nRtpDelta > 0 && nRtpDelta < UINT32_MAX)
            nDelta = (uint32_t)nRtpDelta;
    }

    pRTC->nVideoTimestamp += nDelta;
    pRTC->nVideoLastPtsUs = nPtsUs;
    return pRTC->nVideoTimestamp;
}

static XSTATUS DirectGate_WebRTC_SendRtpPacket(directgate_webrtc_t *pRTC,
                                           const uint8_t *pPayload,
                                           size_t nPayloadLen,
                                           uint32_t nTimestamp,
                                           xbool_t bMarker)
{
    XCHECK((pRTC != NULL), XSTDERR);
    XCHECK((pPayload != NULL && nPayloadLen > 0), XSTDERR);
    XCHECK((nPayloadLen <= DIRECTGATE_RTC_RTP_MAX_PAYLOAD), XSTDERR);
    XCHECK_NL((pRTC->nVideoTrackID >= 0), XSTDERR);
    XCHECK_NL(DirectGate_WebRTC_IsVideoOpen(pRTC), XSTDERR);

    uint8_t packet[DIRECTGATE_RTC_RTP_HEADER_BYTES + DIRECTGATE_RTC_RTP_MAX_PAYLOAD];
    uint16_t nSeq = pRTC->nVideoSeq++;
    DirectGate_WebRTC_WriteRtpHeader(packet, pRTC, nSeq, nTimestamp, bMarker);
    memcpy(packet + DIRECTGATE_RTC_RTP_HEADER_BYTES, pPayload, nPayloadLen);

    int nRet = rtcSendMessage(pRTC->nVideoTrackID, (const char*)packet,
        (int)(DIRECTGATE_RTC_RTP_HEADER_BYTES + nPayloadLen));

    return (nRet >= 0) ? XSTDOK : XSTDERR;
}

static XSTATUS DirectGate_WebRTC_SendH264Nal(directgate_webrtc_t *pRTC,
                                         const uint8_t *pNal,
                                         size_t nNalLen,
                                         uint32_t nTimestamp,
                                         xbool_t bMarker)
{
    XCHECK((pRTC != NULL), XSTDERR);
    XCHECK((pNal != NULL && nNalLen > 0), XSTDERR);

    if (nNalLen <= DIRECTGATE_RTC_RTP_MAX_PAYLOAD)
        return DirectGate_WebRTC_SendRtpPacket(pRTC, pNal, nNalLen, nTimestamp, bMarker);

    uint8_t nHeader = pNal[0];
    uint8_t nFuIndicator = (uint8_t)((nHeader & 0xE0U) | DIRECTGATE_RTC_H264_FU_A);
    uint8_t nNalType = (uint8_t)(nHeader & 0x1FU);
    const uint8_t *pBody = pNal + 1;
    size_t nBodyLen = nNalLen - 1U;
    size_t nOffset = 0;
    size_t nMaxFragment = DIRECTGATE_RTC_RTP_MAX_PAYLOAD - 2U;

    while (nOffset < nBodyLen)
    {
        size_t nFragment = nBodyLen - nOffset;
        if (nFragment > nMaxFragment)
            nFragment = nMaxFragment;

        xbool_t bStart = (nOffset == 0) ? XTRUE : XFALSE;
        xbool_t bEnd = (nOffset + nFragment >= nBodyLen) ? XTRUE : XFALSE;
        uint8_t payload[DIRECTGATE_RTC_RTP_MAX_PAYLOAD];
        payload[0] = nFuIndicator;
        payload[1] = (uint8_t)((bStart ? DIRECTGATE_RTC_H264_START : 0U) |
            (bEnd ? DIRECTGATE_RTC_H264_END : 0U) | nNalType);
        memcpy(payload + 2, pBody + nOffset, nFragment);

        if (DirectGate_WebRTC_SendRtpPacket(pRTC, payload, nFragment + 2U,
            nTimestamp, (bMarker && bEnd) ? XTRUE : XFALSE) < 0)
        {
            return XSTDERR;
        }

        nOffset += nFragment;
    }

    return XSTDOK;
}

XSTATUS DirectGate_WebRTC_SendH264AnnexB(directgate_webrtc_t *pRTC,
                                     const uint8_t *pData,
                                     size_t nLen,
                                     uint64_t nPtsUs)
{
    XCHECK((pRTC != NULL), XSTDERR);
    XCHECK((pData != NULL && nLen > 0), XSTDERR);
    XCHECK_NL((pRTC->nVideoTrackID >= 0), XSTDERR);
    XCHECK_NL(DirectGate_WebRTC_IsVideoOpen(pRTC), XSTDERR);

    const uint8_t *pEnd = pData + nLen;
    const uint8_t *pStart = DirectGate_WebRTC_FindStartCode(pData, pEnd, NULL);
    uint32_t nTimestamp = DirectGate_WebRTC_NextVideoTimestamp(pRTC, nPtsUs);

    if (pStart == NULL)
        return DirectGate_WebRTC_SendH264Nal(pRTC, pData, nLen, nTimestamp, XTRUE);

    const uint8_t *pCursor = pStart;
    while (pCursor != NULL && pCursor < pEnd)
    {
        size_t nCurrentStartLen = 0;
        const uint8_t *pNalStart = DirectGate_WebRTC_FindStartCode(pCursor, pEnd, &nCurrentStartLen);
        if (pNalStart == NULL) break;

        const uint8_t *pNal = pNalStart + nCurrentStartLen;
        const uint8_t *pNext = DirectGate_WebRTC_FindStartCode(pNal, pEnd, NULL);
        const uint8_t *pNalEnd = pNext != NULL ? pNext : pEnd;

        while (pNalEnd > pNal && pNalEnd[-1] == 0)
            pNalEnd--;

        if (pNalEnd > pNal)
        {
            xbool_t bMarker = (pNext == NULL) ? XTRUE : XFALSE;
            if (DirectGate_WebRTC_SendH264Nal(pRTC, pNal, (size_t)(pNalEnd - pNal),
                nTimestamp, bMarker) < 0)
            {
                return XSTDERR;
            }
        }

        pCursor = pNext;
    }

    return XSTDOK;
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

        if (pEvt->nSourceID >= 0 && pEvt->eType != DIRECTGATE_WEBRTC_SIGNAL)
        {
            xbool_t bVideoEvent =
                (pEvt->eType == DIRECTGATE_WEBRTC_VIDEO_OPEN ||
                 pEvt->eType == DIRECTGATE_WEBRTC_VIDEO_CLOSED ||
                 pEvt->eType == DIRECTGATE_WEBRTC_VIDEO_KEYFRAME) ? XTRUE : XFALSE;
            int nCurrent = bVideoEvent ? pRTC->nVideoTrackID : pRTC->nDataChannelID;

            if (pEvt->nSourceID != nCurrent)
            {
                xlogd("Dropping stale WebRTC queue event: pc(%d), source(%d), current(%d), type(%d)",
                    DirectGate_WebRTC_GetPC(pRTC), pEvt->nSourceID, nCurrent, (int)pEvt->eType);

                free(pEvt->pData);
                free(pEvt);
                continue;
            }
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
            case DIRECTGATE_WEBRTC_VIDEO_OPEN:
            {
                pRTC->bVideoTrackOpen = XTRUE;
                xlogn("WebRTC media video track is active: pc(%d), track(%d), mid(%s)",
                    DirectGate_WebRTC_GetPC(pRTC), DirectGate_WebRTC_GetVideoTrack(pRTC), pRTC->sVideoMid);

                break;
            }
            case DIRECTGATE_WEBRTC_VIDEO_CLOSED:
            {
                pRTC->bVideoTrackOpen = XFALSE;
                xlogn("WebRTC media video track is inactive: pc(%d), track(%d)",
                    DirectGate_WebRTC_GetPC(pRTC), pEvt->nSourceID);

                if (pRTC->nVideoTrackID == pEvt->nSourceID)
                    pRTC->nVideoTrackID = -1;

                break;
            }
            case DIRECTGATE_WEBRTC_VIDEO_KEYFRAME:
                pRTC->bVideoKeyframeRequested = XTRUE;
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
