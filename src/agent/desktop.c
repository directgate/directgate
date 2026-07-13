/*!
 * @file directgate-agent/src/agent/desktop.c
 * @brief Agent-side desktop streaming and input control.
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

#include "desktop.h"
#include "session.h"
#include "protocol.h"
#include "webrtc.h"

#include <ctype.h>

/* The raw-RGBA path keeps a conservative FPS budget; the H.264 path
 * picks its own FPS from the active preset. The encoded path supersedes
 * the raw path on macOS unless DIRECTGATE_DESKTOP_FORCE_RAW is set. */
#define DIRECTGATE_DESKTOP_DEFAULT_FPS       6U
#define DIRECTGATE_DESKTOP_CHUNK_SIZE        (128U * 1024U)
#define DIRECTGATE_DESKTOP_MAX_FRAME_EDGE    1280U
#define DIRECTGATE_DESKTOP_RAW_BALANCED_EDGE 1600U

/* H.264 encoded transport never sends more than one frame in flight to the
 * data channel; this is the backpressure threshold (bytes) above which we
 * skip a capture and ask the encoder for a fresh keyframe later. 256 KB is
 * ~250 ms of queue at the balanced 8 Mbps target: enough to ride out jitter
 * without letting the fallback path accumulate a second of latency. */
#define DIRECTGATE_DESKTOP_ENCODED_BUFFER_LIMIT (256U * 1024U)

/* Adaptive bitrate bounds: never throttle below this floor, and step back
 * up toward the preset target when the link stays clean. */
#define DIRECTGATE_DESKTOP_MIN_BITRATE_KBPS   1000U
#define DIRECTGATE_DESKTOP_ABR_HOLD_TICKS     60U  /* ~2s at 30 fps */
#define DIRECTGATE_DESKTOP_ABR_RAISE_TICKS    150U /* ~5s clean before raising */
#define DIRECTGATE_DESKTOP_ABR_LOSS_THRESHOLD 8U   /* ~3% fraction lost */

#if defined(__linux__)
#include <dlfcn.h>
#include <sys/timerfd.h>
#include <dirent.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/keysym.h>
#include <X11/extensions/Xrandr.h>

typedef Bool (*directgate_xtest_motion_fn)(Display*, int, int, int, unsigned long);
typedef Bool (*directgate_xtest_button_fn)(Display*, unsigned int, Bool, unsigned long);
typedef Bool (*directgate_xtest_key_fn)(Display*, unsigned int, Bool, unsigned long);
#elif defined(__APPLE__)
#include <stdbool.h>
#include <ApplicationServices/ApplicationServices.h>
#include <Carbon/Carbon.h>
#endif

static void DirectGate_Desktop_SetReason(directgate_desktop_t *pDesktop, const char *pReason)
{
    XCHECK_VOID_NL((pDesktop != NULL));
    xstrncpy(pDesktop->sReason, sizeof(pDesktop->sReason),
        xstrused(pReason) ? pReason : "desktop unavailable");
}

static int DirectGate_Desktop_SendStatus(directgate_session_t *pSession, const char *pStatus, const char *pReason);
#if defined(__linux__) || defined(__APPLE__) || defined(_WIN32)
static void DirectGate_Desktop_RestoreDisplayMode(directgate_desktop_t *pDesktop);
#endif

const char* DirectGate_Desktop_PresetName(directgate_desktop_preset_t ePreset)
{
    if (ePreset == DIRECTGATE_DESKTOP_PRESET_QUALITY) return "quality";
    if (ePreset == DIRECTGATE_DESKTOP_PRESET_LOW_LATENCY) return "low-latency";
    return "balanced";
}

const char* DirectGate_Desktop_PipelineName(directgate_desktop_pipeline_t ePipeline)
{
    if (ePipeline == DIRECTGATE_DESKTOP_PIPELINE_WEBRTC_VIDEO) return "webrtc-video";
    if (ePipeline == DIRECTGATE_DESKTOP_PIPELINE_H264_DC) return "h264-datachannel";
    return "raw-rgba";
}

const char* DirectGate_Desktop_ResizeModeName(directgate_desktop_resize_mode_t eMode)
{
    return eMode == DIRECTGATE_DESKTOP_RESIZE_DISPLAY ? "display" : "scale";
}

static const char* DirectGate_Desktop_TransportName(directgate_desktop_pipeline_t ePipeline)
{
    if (ePipeline == DIRECTGATE_DESKTOP_PIPELINE_WEBRTC_VIDEO) return "dtls-srtp";
    if (ePipeline == DIRECTGATE_DESKTOP_PIPELINE_H264_DC) return "aes-siv-datachannel";
    return "aes-siv-datachannel";
}

static void DirectGate_Desktop_SetFallbackReason(directgate_desktop_t *pDesktop, const char *pReason)
{
    XCHECK_VOID_NL((pDesktop != NULL));
    xstrncpy(pDesktop->sFallbackReason, sizeof(pDesktop->sFallbackReason),
        xstrused(pReason) ? pReason : "");
}

void DirectGate_Desktop_ApplyPreset(directgate_desktop_t *pDesktop, directgate_desktop_preset_t ePreset)
{
    XCHECK_VOID_NL((pDesktop != NULL));
    pDesktop->quality.ePreset = ePreset;

    /* GOPs are long on purpose: an IDR is 10-50x the size of a P-frame,
     * so periodic keyframes turn into periodic burst-loss stutter on
     * constrained links. Recovery and late-join are handled on demand via
     * RTCP PLI / request-keyframe, and NACK retransmission covers small
     * loss without any keyframe at all. */
    switch (ePreset)
    {
        case DIRECTGATE_DESKTOP_PRESET_QUALITY:
            /* Headroom for unscaled 1080p screen content with fine text. */
            pDesktop->quality.nMaxEdge = 1920U;
            pDesktop->quality.nFps = 30U;
            pDesktop->quality.nBitrateKbps = 12000U;
            pDesktop->quality.nKeyframeFrames = 300U;
            pDesktop->quality.bRealtime = XFALSE;
            break;
        case DIRECTGATE_DESKTOP_PRESET_LOW_LATENCY:
            pDesktop->quality.nMaxEdge = 1280U;
            pDesktop->quality.nFps = 30U;
            pDesktop->quality.nBitrateKbps = 4000U;
            pDesktop->quality.nKeyframeFrames = 300U;
            pDesktop->quality.bRealtime = XTRUE;
            break;
        case DIRECTGATE_DESKTOP_PRESET_BALANCED:
        default:
            pDesktop->quality.ePreset = DIRECTGATE_DESKTOP_PRESET_BALANCED;
            pDesktop->quality.nMaxEdge = 1920U;
            pDesktop->quality.nFps = 30U;
            pDesktop->quality.nBitrateKbps = 8000U;
            pDesktop->quality.nKeyframeFrames = 300U;
            pDesktop->quality.bRealtime = XTRUE;
            break;
    }

    pDesktop->nFps = pDesktop->quality.nFps;
    pDesktop->nCurrentBitrateKbps = pDesktop->quality.nBitrateKbps;
    pDesktop->nAbrCleanTicks = 0;
    pDesktop->nAbrHoldTicks = 0;
    pDesktop->bRequestKeyframe = XTRUE;
}

int DirectGate_Desktop_SendEncodedFrame(directgate_session_t *pSession,
                                    const uint8_t *pPayload,
                                    size_t nPayloadLength,
                                    uint32_t nWidth,
                                    uint32_t nHeight,
                                    xbool_t bKeyframe,
                                    uint64_t nPtsUs)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    XCHECK_NL((pPayload != NULL && nPayloadLength > 0), XAPI_CONTINUE);

    directgate_desktop_t *pDesktop = &pSession->desktop;

    if (pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_WEBRTC_VIDEO)
    {
        if (DirectGate_WebRTC_SendH264AnnexB(&pSession->webrtc, pPayload, nPayloadLength, nPtsUs) >= 0)
        {
            pDesktop->nFrameWidth = nWidth;
            pDesktop->nFrameHeight = nHeight;
            return XAPI_CONTINUE;
        }

        pDesktop->ePipeline = DIRECTGATE_DESKTOP_PIPELINE_H264_DC;
        pDesktop->bWebRTCVideoFailed = XTRUE;
        DirectGate_Desktop_SetFallbackReason(pDesktop,
            "WebRTC video track send failed; using encrypted H.264 data channel.");
        DirectGate_Desktop_SendStatus(pSession, "streaming", NULL);
    }

    uint64_t nFrameId = ++pDesktop->nFrameId;
    uint32_t nChunks = (uint32_t)((nPayloadLength + DIRECTGATE_DESKTOP_CHUNK_BYTES - 1U) /
        DIRECTGATE_DESKTOP_CHUNK_BYTES);
    if (!nChunks) nChunks = 1U;

    for (uint32_t i = 0; i < nChunks; i++)
    {
        size_t nOffset = (size_t)i * DIRECTGATE_DESKTOP_CHUNK_BYTES;
        size_t nChunk = nPayloadLength - nOffset;
        if (nChunk > DIRECTGATE_DESKTOP_CHUNK_BYTES) nChunk = DIRECTGATE_DESKTOP_CHUNK_BYTES;

        xjson_obj_t *pHeader = DirectGate_Proto_BuildData(pSession->nSessionId);
        XCHECK((pHeader != NULL), XAPI_DISCONNECT);

        XJSON_AddString(pHeader, "payloadType", "desktop-frame-encoded");
        XJSON_AddString(pHeader, "codec", xstrused(pDesktop->sCodec) ? pDesktop->sCodec : "h264");
        XJSON_AddU64(pHeader, "frameId", nFrameId);
        XJSON_AddU32(pHeader, "chunkIndex", i);
        XJSON_AddU32(pHeader, "chunks", nChunks);
        XJSON_AddU32(pHeader, "totalBytes", (uint32_t)nPayloadLength);
        XJSON_AddU32(pHeader, "width", nWidth);
        XJSON_AddU32(pHeader, "height", nHeight);
        XJSON_AddU32(pHeader, "screenWidth", pDesktop->nCaptureWidth);
        XJSON_AddU32(pHeader, "screenHeight", pDesktop->nCaptureHeight);
        XJSON_AddBool(pHeader, "keyframe", bKeyframe);
        XJSON_AddU64(pHeader, "ptsUs", nPtsUs);
        XJSON_AddString(pHeader, "monitorId", pDesktop->sSelectedMonitor);

        int nStatus = DirectGate_Session_Send(pSession, pHeader, pPayload + nOffset, nChunk);
        XJSON_FreeObject(pHeader);
        if (nStatus < 0) return nStatus;
    }

    pDesktop->nFrameWidth = nWidth;
    pDesktop->nFrameHeight = nHeight;
    return XAPI_CONTINUE;
}

xbool_t DirectGate_Desktop_ShouldSkipForBackpressure(const directgate_session_t *pSession)
{
    XCHECK_NL((pSession != NULL), XFALSE);
    if (pSession->desktop.ePipeline == DIRECTGATE_DESKTOP_PIPELINE_WEBRTC_VIDEO)
        return XFALSE;

    int nBuffered = DirectGate_WebRTC_GetBufferedAmount(&pSession->webrtc);
    if (nBuffered < 0) return XFALSE;
    return ((size_t)nBuffered > DIRECTGATE_DESKTOP_ENCODED_BUFFER_LIMIT) ? XTRUE : XFALSE;
}

#if defined(__linux__) || defined(__APPLE__) || defined(_WIN32)
/* Adaptive bitrate: multiplicative decrease on congestion, slow stepwise
 * recovery toward the preset target on a clean link. RTCP receiver reports
 * (fraction lost) are the signal on the media track; on the data-channel
 * fallback the only available signal is transport backpressure. Runs once
 * per timer tick while an encoded pipeline is active. */
static void DirectGate_Desktop_AdaptBitrate(directgate_session_t *pSession)
{
    directgate_desktop_t *pDesktop = &pSession->desktop;
    uint32_t nTarget = pDesktop->quality.nBitrateKbps;
    XCHECK_VOID_NL((nTarget > 0));

    uint32_t nCurrent = pDesktop->nCurrentBitrateKbps ?
        pDesktop->nCurrentBitrateKbps : nTarget;

    xbool_t bCongested = XFALSE;
    uint8_t nFractionLost = 0;
    if (DirectGate_WebRTC_TakeVideoLossReport(&pSession->webrtc, &nFractionLost) &&
        nFractionLost >= DIRECTGATE_DESKTOP_ABR_LOSS_THRESHOLD)
        bCongested = XTRUE;

    if (pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_H264_DC &&
        DirectGate_Desktop_ShouldSkipForBackpressure(pSession))
        bCongested = XTRUE;

    if (pDesktop->nAbrHoldTicks > 0)
        pDesktop->nAbrHoldTicks--;

    uint32_t nNext = nCurrent;
    if (bCongested)
    {
        pDesktop->nAbrCleanTicks = 0;
        if (!pDesktop->nAbrHoldTicks)
        {
            nNext = (nCurrent * 3U) / 4U;
            if (nNext < DIRECTGATE_DESKTOP_MIN_BITRATE_KBPS)
                nNext = DIRECTGATE_DESKTOP_MIN_BITRATE_KBPS;

            /* Receiver reports lag the rate change; hold before the next
             * step so one loss episode is not punished twice. */
            pDesktop->nAbrHoldTicks = DIRECTGATE_DESKTOP_ABR_HOLD_TICKS;
        }
    }
    else if (nCurrent < nTarget && ++pDesktop->nAbrCleanTicks >= DIRECTGATE_DESKTOP_ABR_RAISE_TICKS)
    {
        pDesktop->nAbrCleanTicks = 0;
        nNext = nCurrent + nTarget / 10U + 1U;
        if (nNext > nTarget) nNext = nTarget;
    }

    pDesktop->nCurrentBitrateKbps = nNext;
    if (nNext == nCurrent) return;

#if defined(__APPLE__)
    DirectGate_Desktop_MacEncoder_SetBitrate(pSession, nNext);
#elif defined(_WIN32)
    DirectGate_Desktop_WinEncoder_SetBitrate(pSession, nNext);
#else
    DirectGate_Desktop_LinuxEncoder_SetBitrate(pSession, nNext);
#endif

    xlogi("Desktop bitrate adapted: sid(%u), step(%s), rate(%u -> %u kbps), target(%u)",
        pSession->nSessionId, nNext < nCurrent ? "down" : "up",
        nCurrent, nNext, nTarget);
}
#endif /* __linux__ || __APPLE__ || _WIN32 */

void DirectGate_Desktop_ComputeOutputSize(const directgate_desktop_t *pDesktop,
                                          uint32_t nSourceWidth, uint32_t nSourceHeight,
                                          uint32_t *pWidth, uint32_t *pHeight)
{
    uint32_t nWidth = nSourceWidth ? nSourceWidth : 1U;
    uint32_t nHeight = nSourceHeight ? nSourceHeight : 1U;
    uint32_t nEdge = nWidth > nHeight ? nWidth : nHeight;
    uint32_t nMaxEdge = (pDesktop != NULL && pDesktop->quality.nMaxEdge > 0U) ?
        pDesktop->quality.nMaxEdge : DIRECTGATE_DESKTOP_MAX_FRAME_EDGE;

    /* In display mode capture already has the requested OS display size, so
     * a second scaler would defeat the mode's purpose. In scale mode the
     * browser supplies an aspect-fit box. Clamp both axes to the source so a
     * large browser never makes the host waste time on an upscale. */
    if (pDesktop != NULL && pDesktop->eResizeMode == DIRECTGATE_DESKTOP_RESIZE_DISPLAY)
    {
        nMaxEdge = 0U;
    }
    else if (pDesktop != NULL && pDesktop->nTargetWidth > 0U && pDesktop->nTargetHeight > 0U)
    {
        uint32_t nTargetWidth = pDesktop->nTargetWidth;
        uint32_t nTargetHeight = pDesktop->nTargetHeight;
        if (nTargetWidth < nWidth || nTargetHeight < nHeight)
        {
            if ((uint64_t)nWidth * nTargetHeight > (uint64_t)nHeight * nTargetWidth)
            {
                nHeight = (uint32_t)(((uint64_t)nHeight * nTargetWidth) / nWidth);
                nWidth = nTargetWidth;
            }
            else
            {
                nWidth = (uint32_t)(((uint64_t)nWidth * nTargetHeight) / nHeight);
                nHeight = nTargetHeight;
            }
        }
        nMaxEdge = 0U;
    }

#if defined(__linux__) || defined(_WIN32)
    /* The raw path converts every pixel on the CPU per frame; cap the
     * balanced preset so the fallback stays responsive. */
    if (pDesktop != NULL &&
        pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_RAW &&
        pDesktop->quality.ePreset == DIRECTGATE_DESKTOP_PRESET_BALANCED &&
        nMaxEdge > DIRECTGATE_DESKTOP_RAW_BALANCED_EDGE)
        nMaxEdge = DIRECTGATE_DESKTOP_RAW_BALANCED_EDGE;
#endif

    if (nMaxEdge > 0U && nEdge > nMaxEdge)
    {
        if (nWidth >= nHeight)
        {
            nHeight = (uint32_t)(((uint64_t)nHeight * nMaxEdge) / nWidth);
            nWidth = nMaxEdge;
        }
        else
        {
            nWidth = (uint32_t)(((uint64_t)nWidth * nMaxEdge) / nHeight);
            nHeight = nMaxEdge;
        }
    }

    if (!nWidth) nWidth = 1U;
    if (!nHeight) nHeight = 1U;
    if (pWidth != NULL) *pWidth = nWidth;
    if (pHeight != NULL) *pHeight = nHeight;
}

static void DirectGate_Desktop_LimitFrameSize(const directgate_desktop_t *pDesktop,
                                              uint32_t *pWidth, uint32_t *pHeight)
{
    uint32_t nWidth = (pWidth != NULL && *pWidth) ? *pWidth : 1U;
    uint32_t nHeight = (pHeight != NULL && *pHeight) ? *pHeight : 1U;
    DirectGate_Desktop_ComputeOutputSize(pDesktop, nWidth, nHeight, pWidth, pHeight);
}

static void DirectGate_Desktop_ReadResizeRequest(directgate_desktop_t *pDesktop, xjson_obj_t *pRoot)
{
    XCHECK_VOID_NL((pDesktop != NULL && pRoot != NULL));
    const char *pMode = XJSON_GetString(XJSON_GetObject(pRoot, "mode"));
    uint32_t nWidth = XJSON_GetU32(XJSON_GetObject(pRoot, "width"));
    uint32_t nHeight = XJSON_GetU32(XJSON_GetObject(pRoot, "height"));

    if (xstrcmp(pMode, "display"))
        pDesktop->eResizeMode = DIRECTGATE_DESKTOP_RESIZE_DISPLAY;
    else if (xstrcmp(pMode, "scale"))
        pDesktop->eResizeMode = DIRECTGATE_DESKTOP_RESIZE_SCALE;

    /* Bound allocations and reject partial sizes. 8K on either axis is well
     * beyond current browser viewports while still allowing native 8K hosts. */
    if (nWidth > 0U && nHeight > 0U && nWidth <= 8192U && nHeight <= 8192U)
    {
        pDesktop->nTargetWidth = nWidth;
        pDesktop->nTargetHeight = nHeight;
    }
}

void DirectGate_Desktop_Init(directgate_desktop_t *pDesktop)
{
    XCHECK_VOID_NL((pDesktop != NULL));
    memset(pDesktop, 0, sizeof(*pDesktop));
    pDesktop->nTimerFd = XSOCK_INVALID;
#if defined(__APPLE__) || defined(_WIN32)
    pDesktop->nTimerWriteFd = XSOCK_INVALID;
#endif
    pDesktop->nFps = DIRECTGATE_DESKTOP_DEFAULT_FPS;
    pDesktop->ePipeline = DIRECTGATE_DESKTOP_PIPELINE_RAW;
    pDesktop->eResizeMode = DIRECTGATE_DESKTOP_RESIZE_SCALE;
    pDesktop->pEncoder = NULL;
    pDesktop->bForceRaw = XFALSE;
    pDesktop->bRequestKeyframe = XFALSE;
    pDesktop->bWebRTCVideoFailed = XFALSE;
    pDesktop->sFallbackReason[0] = '\0';
    xstrncpy(pDesktop->sCodec, sizeof(pDesktop->sCodec), "raw-rgba");
    DirectGate_Desktop_ApplyPreset(pDesktop, DIRECTGATE_DESKTOP_PRESET_BALANCED);

#if defined(__APPLE__) || defined(__linux__) || defined(_WIN32)
    const char *pForce = getenv("DIRECTGATE_DESKTOP_FORCE_RAW");
    if (xstrused(pForce) && pForce[0] != '0')
        pDesktop->bForceRaw = XTRUE;

    const char *pEnvPreset = getenv("DIRECTGATE_DESKTOP_PRESET");
    if (xstrused(pEnvPreset))
    {
        if (xstrcmp(pEnvPreset, "quality"))
            DirectGate_Desktop_ApplyPreset(pDesktop, DIRECTGATE_DESKTOP_PRESET_QUALITY);
        else if (xstrcmp(pEnvPreset, "low-latency"))
            DirectGate_Desktop_ApplyPreset(pDesktop, DIRECTGATE_DESKTOP_PRESET_LOW_LATENCY);
    }
#endif
}

void DirectGate_Desktop_Clear(directgate_desktop_t *pDesktop)
{
    XCHECK_VOID_NL((pDesktop != NULL));

#if defined(__APPLE__)
    if (pDesktop->pEncoder != NULL)
    {
        /* The encoder owns its own queue/thread; this stops + drains it. */
        DirectGate_Desktop_MacEncoder_StopDesktop(pDesktop);
    }

    DirectGate_Desktop_RestoreDisplayMode(pDesktop);

    if (pDesktop->bTimerThreadRunning)
    {
        pDesktop->bTimerThreadRunning = XFALSE;
        if (pDesktop->nTimerWriteFd != XSOCK_INVALID)
        {
            const char cStop = 'x';
            (void)write(pDesktop->nTimerWriteFd, &cStop, sizeof(cStop));
        }

        pthread_join(pDesktop->timerThread, NULL);
    }
#endif

#if defined(__linux__) || defined(__APPLE__)
    if (pDesktop->nTimerFd != XSOCK_INVALID)
    {
        close(pDesktop->nTimerFd);
        pDesktop->nTimerFd = XSOCK_INVALID;
    }
#endif

#if defined(__APPLE__)
    if (pDesktop->nTimerWriteFd != XSOCK_INVALID)
    {
        close(pDesktop->nTimerWriteFd);
        pDesktop->nTimerWriteFd = XSOCK_INVALID;
    }
#endif

#if defined(__linux__)
    /* Detaches the XShm segment, so it must run before the display closes. */
    if (pDesktop->pEncoder != NULL)
        DirectGate_Desktop_LinuxEncoder_StopDesktop(pDesktop);

    DirectGate_Desktop_RestoreDisplayMode(pDesktop);

    if (pDesktop->pDisplay != NULL)
    {
        XCloseDisplay((Display*)pDesktop->pDisplay);
        pDesktop->pDisplay = NULL;
    }

    if (pDesktop->pXtst != NULL)
    {
        dlclose(pDesktop->pXtst);
        pDesktop->pXtst = NULL;
    }
#endif

#if defined(_WIN32)
    /* The capture thread writes to the timer socket pair; join it (and the
     * tick thread) before the sockets close. */
    if (pDesktop->pEncoder != NULL)
        DirectGate_Desktop_WinEncoder_StopDesktop(pDesktop);

    DirectGate_Desktop_RestoreDisplayMode(pDesktop);

    if (pDesktop->bTimerThreadRunning)
    {
        pDesktop->bTimerThreadRunning = XFALSE;
        if (pDesktop->pTimerThread != NULL)
        {
            WaitForSingleObject((HANDLE)pDesktop->pTimerThread, INFINITE);
            CloseHandle((HANDLE)pDesktop->pTimerThread);
            pDesktop->pTimerThread = NULL;
        }
    }

    if (pDesktop->nTimerFd != XSOCK_INVALID)
    {
        xclosesock(pDesktop->nTimerFd);
        pDesktop->nTimerFd = XSOCK_INVALID;
    }

    if (pDesktop->nTimerWriteFd != XSOCK_INVALID)
    {
        xclosesock(pDesktop->nTimerWriteFd);
        pDesktop->nTimerWriteFd = XSOCK_INVALID;
    }
#endif

    pDesktop->bRunning = XFALSE;
    pDesktop->bInputReady = XFALSE;
    pDesktop->bCaptureReady = XFALSE;
    pDesktop->pFakeMotion = NULL;
    pDesktop->pFakeButton = NULL;
    pDesktop->pFakeKey = NULL;
    pDesktop->nScreenWidth = 0;
    pDesktop->nScreenHeight = 0;
    pDesktop->nCaptureX = 0;
    pDesktop->nCaptureY = 0;
    pDesktop->nCaptureWidth = 0;
    pDesktop->nCaptureHeight = 0;
    pDesktop->nFrameWidth = 0;
    pDesktop->nFrameHeight = 0;
    pDesktop->eResizeMode = DIRECTGATE_DESKTOP_RESIZE_SCALE;
    pDesktop->nTargetWidth = 0;
    pDesktop->nTargetHeight = 0;
    pDesktop->bDisplayModeChanged = XFALSE;
    pDesktop->pOriginalDisplayMode = NULL;
    pDesktop->nPointerButtons = 0;
    pDesktop->nFrameId = 0;
    pDesktop->nMonitorCount = 0;
    memset(pDesktop->monitors, 0, sizeof(pDesktop->monitors));
    pDesktop->sSelectedMonitor[0] = '\0';
    pDesktop->ePipeline = DIRECTGATE_DESKTOP_PIPELINE_RAW;
    pDesktop->bRequestKeyframe = XFALSE;
    pDesktop->bWebRTCVideoFailed = XFALSE;
    pDesktop->pEncoder = NULL;
    pDesktop->sFallbackReason[0] = '\0';
    xstrncpy(pDesktop->sCodec, sizeof(pDesktop->sCodec), "raw-rgba");
}

void DirectGate_Desktop_DetachEvent(directgate_desktop_t *pDesktop)
{
    XCHECK_VOID_NL((pDesktop != NULL));
#if defined(__APPLE__) || defined(_WIN32)
    /* poll-backed events do not own the pipe fd; Clear stops the timer thread
     * and closes both pipe ends after the session is torn down. */
    return;
#endif
    pDesktop->nTimerFd = XSOCK_INVALID;
}

int DirectGate_Desktop_GetTimerFd(const directgate_desktop_t *pDesktop)
{
    XCHECK_NL((pDesktop != NULL), -1);
    if (pDesktop->nTimerFd == XSOCK_INVALID) return -1;
    return (int)pDesktop->nTimerFd;
}

xbool_t DirectGate_Desktop_IsRunning(const directgate_desktop_t *pDesktop)
{
    XCHECK_NL((pDesktop != NULL), XFALSE);
    return pDesktop->bRunning;
}

const char* DirectGate_Desktop_GetReason(const directgate_desktop_t *pDesktop)
{
    XCHECK_NL((pDesktop != NULL), "desktop unavailable");
    return xstrused(pDesktop->sReason) ? pDesktop->sReason : "desktop unavailable";
}

static int DirectGate_Desktop_SendStatus(directgate_session_t *pSession, const char *pStatus, const char *pReason)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);

    xjson_obj_t *pRoot = XJSON_NewObject(NULL, NULL, XFALSE);
    XCHECK((pRoot != NULL), XAPI_DISCONNECT);

    XJSON_AddString(pRoot, "status", xstrused(pStatus) ? pStatus : "unknown");
    XJSON_AddString(pRoot, "backend", xstrused(pSession->desktop.sBackend) ? pSession->desktop.sBackend : "unknown");
    XJSON_AddString(pRoot, "display", xstrused(pSession->desktop.sDisplay) ? pSession->desktop.sDisplay : "");
    XJSON_AddBool(pRoot, "input", pSession->desktop.bInputReady);
    XJSON_AddU32(pRoot, "screenWidth", pSession->desktop.nScreenWidth);
    XJSON_AddU32(pRoot, "screenHeight", pSession->desktop.nScreenHeight);
    XJSON_AddBool(pRoot, "captureReady", pSession->desktop.bCaptureReady);
    XJSON_AddStrIfUsed(pRoot, "selectedMonitor", pSession->desktop.sSelectedMonitor);
    XJSON_AddString(pRoot, "pipeline", DirectGate_Desktop_PipelineName(pSession->desktop.ePipeline));
    XJSON_AddString(pRoot, "codec", xstrused(pSession->desktop.sCodec) ? pSession->desktop.sCodec : "raw-rgba");
    XJSON_AddString(pRoot, "preset", DirectGate_Desktop_PresetName(pSession->desktop.quality.ePreset));
    XJSON_AddString(pRoot, "transport", DirectGate_Desktop_TransportName(pSession->desktop.ePipeline));
    XJSON_AddU32(pRoot, "frameWidth", pSession->desktop.nFrameWidth);
    XJSON_AddU32(pRoot, "frameHeight", pSession->desktop.nFrameHeight);
    XJSON_AddString(pRoot, "resizeMode", DirectGate_Desktop_ResizeModeName(pSession->desktop.eResizeMode));
    XJSON_AddU32(pRoot, "targetWidth", pSession->desktop.nTargetWidth);
    XJSON_AddU32(pRoot, "targetHeight", pSession->desktop.nTargetHeight);
    XJSON_AddU32(pRoot, "fps", pSession->desktop.quality.nFps);
    XJSON_AddU32(pRoot, "bitrateKbps", pSession->desktop.nCurrentBitrateKbps ?
        pSession->desktop.nCurrentBitrateKbps : pSession->desktop.quality.nBitrateKbps);
    XJSON_AddBool(pRoot, "fallbackRaw", pSession->desktop.bForceRaw);
    XJSON_AddStrIfUsed(pRoot, "fallbackReason", pSession->desktop.sFallbackReason);

    if (xstrused(pReason)) XJSON_AddString(pRoot, "reason", pReason);
    else if (xstrused(pSession->desktop.sReason)) XJSON_AddString(pRoot, "reason", pSession->desktop.sReason);

    xjson_obj_t *pMonitors = XJSON_NewArray(NULL, "monitors", XFALSE);
    if (pMonitors != NULL)
    {
        for (uint32_t i = 0; i < pSession->desktop.nMonitorCount; i++)
        {
            const directgate_desktop_monitor_t *pMonitor = &pSession->desktop.monitors[i];
            xjson_obj_t *pItem = XJSON_NewObject(NULL, NULL, XFALSE);
            if (pItem == NULL) continue;

            XJSON_AddString(pItem, "id", pMonitor->sId);
            XJSON_AddString(pItem, "name", pMonitor->sName);
            XJSON_AddInt(pItem, "x", pMonitor->nX);
            XJSON_AddInt(pItem, "y", pMonitor->nY);
            XJSON_AddU32(pItem, "width", pMonitor->nWidth);
            XJSON_AddU32(pItem, "height", pMonitor->nHeight);
            XJSON_AddBool(pItem, "primary", pMonitor->bPrimary);
            XJSON_AddObject(pMonitors, pItem);
        }

        XJSON_AddObject(pRoot, pMonitors);
    }

    size_t nPayloadLen = 0;
    char *pPayload = XJSON_DumpObj(pRoot, 0, &nPayloadLen);
    XJSON_FreeObject(pRoot);
    XCHECK((pPayload != NULL), XAPI_DISCONNECT);

    xjson_obj_t *pHeader = DirectGate_Proto_BuildData(pSession->nSessionId);
    if (pHeader == NULL)
    {
        free(pPayload);
        return XAPI_DISCONNECT;
    }

    XJSON_AddString(pHeader, "payloadType", "desktop-status");
    int nStatus = DirectGate_Session_Send(pSession, pHeader, (const uint8_t*)pPayload, nPayloadLen);
    XJSON_FreeObject(pHeader);
    free(pPayload);
    return nStatus;
}

#if defined(__linux__)
static uint32_t DirectGate_Desktop_MaskShift(unsigned long nMask)
{
    uint32_t nShift = 0;
    if (!nMask) return 0;
    while ((nMask & 1UL) == 0)
    {
        nShift++;
        nMask >>= 1;
    }
    return nShift;
}

static uint8_t DirectGate_Desktop_PixelComponent(unsigned long nPixel, unsigned long nMask, uint32_t nShift)
{
    unsigned long nValue;
    unsigned long nMax = nMask >> nShift;
    if (!nMask || !nMax) return 0;

    nValue = (nPixel & nMask) >> nShift;
    return (uint8_t)((nValue * 255UL) / nMax);
}

static void DirectGate_Desktop_ComputeFrameSize(directgate_desktop_t *pDesktop)
{
    uint32_t nWidth = pDesktop->nCaptureWidth ? pDesktop->nCaptureWidth : pDesktop->nScreenWidth;
    uint32_t nHeight = pDesktop->nCaptureHeight ? pDesktop->nCaptureHeight : pDesktop->nScreenHeight;

    if (!nWidth) nWidth = 1;
    if (!nHeight) nHeight = 1;
    DirectGate_Desktop_LimitFrameSize(pDesktop, &nWidth, &nHeight);

    pDesktop->nFrameWidth = nWidth;
    pDesktop->nFrameHeight = nHeight;
}

static void DirectGate_Desktop_SetCapture(directgate_desktop_t *pDesktop,
                                      const char *pMonitorId,
                                      int32_t nX,
                                      int32_t nY,
                                      uint32_t nWidth,
                                      uint32_t nHeight)
{
    XCHECK_VOID_NL((pDesktop != NULL));

    pDesktop->nCaptureX = nX;
    pDesktop->nCaptureY = nY;
    pDesktop->nCaptureWidth = nWidth ? nWidth : pDesktop->nScreenWidth;
    pDesktop->nCaptureHeight = nHeight ? nHeight : pDesktop->nScreenHeight;
    xstrncpy(pDesktop->sSelectedMonitor, sizeof(pDesktop->sSelectedMonitor),
        xstrused(pMonitorId) ? pMonitorId : "all");
    pDesktop->bCaptureReady = XTRUE;
    DirectGate_Desktop_ComputeFrameSize(pDesktop);
}

static void DirectGate_Desktop_AddMonitor(directgate_desktop_t *pDesktop,
                                      const char *pId,
                                      const char *pName,
                                      int32_t nX,
                                      int32_t nY,
                                      uint32_t nWidth,
                                      uint32_t nHeight,
                                      xbool_t bPrimary)
{
    XCHECK_VOID_NL((pDesktop != NULL));
    XCHECK_VOID_NL((pDesktop->nMonitorCount < DIRECTGATE_DESKTOP_MAX_MONITORS));
    XCHECK_VOID_NL((nWidth > 0 && nHeight > 0));

    directgate_desktop_monitor_t *pMonitor = &pDesktop->monitors[pDesktop->nMonitorCount++];
    xstrncpy(pMonitor->sId, sizeof(pMonitor->sId), xstrused(pId) ? pId : "monitor");
    xstrncpy(pMonitor->sName, sizeof(pMonitor->sName), xstrused(pName) ? pName : pMonitor->sId);
    pMonitor->nX = nX;
    pMonitor->nY = nY;
    pMonitor->nWidth = nWidth;
    pMonitor->nHeight = nHeight;
    pMonitor->bPrimary = bPrimary;
}

static void DirectGate_Desktop_EnumerateMonitors(directgate_desktop_t *pDesktop)
{
    Display *pDisplay = (Display*)pDesktop->pDisplay;
    int nScreen = DefaultScreen(pDisplay);
    Window root = RootWindow(pDisplay, nScreen);

    DirectGate_Desktop_AddMonitor(pDesktop, "all", "All displays", 0, 0,
        pDesktop->nScreenWidth, pDesktop->nScreenHeight, XFALSE);

    int nMonitorCount = 0;
    XRRMonitorInfo *pMonitors = XRRGetMonitors(pDisplay, root, True, &nMonitorCount);
    if (pMonitors == NULL || nMonitorCount <= 0)
        return;

    for (int i = 0; i < nMonitorCount && pDesktop->nMonitorCount < DIRECTGATE_DESKTOP_MAX_MONITORS; i++)
    {
        XRRMonitorInfo *pInfo = &pMonitors[i];
        char sId[DIRECTGATE_DESKTOP_MONITOR_ID_LEN];
        char sName[DIRECTGATE_DESKTOP_MONITOR_NAME_LEN];
        char *pAtomName = XGetAtomName(pDisplay, pInfo->name);

        snprintf(sId, sizeof(sId), "monitor-%d", i + 1);
        if (xstrused(pAtomName))
            xstrncpy(sName, sizeof(sName), pAtomName);
        else snprintf(sName, sizeof(sName), "Monitor %d", i + 1);

        DirectGate_Desktop_AddMonitor(pDesktop, sId, sName,
            pInfo->x, pInfo->y, (uint32_t)pInfo->width, (uint32_t)pInfo->height,
            pInfo->primary ? XTRUE : XFALSE);

        if (pInfo->noutput > 0)
        {
            directgate_desktop_monitor_t *pAdded = &pDesktop->monitors[pDesktop->nMonitorCount - 1U];
            pAdded->nNativeId = (uint64_t)pInfo->outputs[0];
            snprintf(pAdded->sDeviceId, sizeof(pAdded->sDeviceId), "%lu", (unsigned long)pInfo->outputs[0]);
        }

        if (pAtomName != NULL)
            XFree(pAtomName);
    }

    XRRFreeMonitors(pMonitors);
}

static void DirectGate_Desktop_RefreshLinuxMonitors(directgate_desktop_t *pDesktop)
{
    Display *pDisplay = (Display*)pDesktop->pDisplay;
    if (pDisplay == NULL) return;
    int nScreen = DefaultScreen(pDisplay);
    Window root = RootWindow(pDisplay, nScreen);
    XWindowAttributes attrs;
    if (XGetWindowAttributes(pDisplay, root, &attrs) && attrs.width > 0 && attrs.height > 0)
    {
        pDesktop->nScreenWidth = (uint32_t)attrs.width;
        pDesktop->nScreenHeight = (uint32_t)attrs.height;
    }
    pDesktop->nMonitorCount = 0;
    memset(pDesktop->monitors, 0, sizeof(pDesktop->monitors));
    DirectGate_Desktop_EnumerateMonitors(pDesktop);
}

static const directgate_desktop_monitor_t* DirectGate_Desktop_FindMonitor(
    const directgate_desktop_t *pDesktop, const char *pMonitorId)
{
    if (pDesktop == NULL || !xstrused(pMonitorId)) return NULL;
    for (uint32_t i = 0; i < pDesktop->nMonitorCount; i++)
        if (xstrcmp(pDesktop->monitors[i].sId, pMonitorId))
            return &pDesktop->monitors[i];
    return NULL;
}

static RRMode DirectGate_Desktop_ClosestXrandrMode(const XRRScreenResources *pResources,
                                               const XRROutputInfo *pOutput,
                                               uint32_t nWidth, uint32_t nHeight)
{
    RRMode nBest = None;
    uint64_t nBestScore = UINT64_MAX;
    if (pResources == NULL || pOutput == NULL) return None;
    for (int i = 0; i < pOutput->nmode; i++)
    {
        const XRRModeInfo *pMode = NULL;
        for (int j = 0; j < pResources->nmode; j++)
            if (pResources->modes[j].id == pOutput->modes[i])
            {
                pMode = &pResources->modes[j];
                break;
            }
        if (pMode == NULL) continue;
        uint64_t nDx = pMode->width > nWidth ? pMode->width - nWidth : nWidth - pMode->width;
        uint64_t nDy = pMode->height > nHeight ? pMode->height - nHeight : nHeight - pMode->height;
        uint64_t nAspect = (uint64_t)llabs((long long)pMode->width * nHeight -
            (long long)nWidth * pMode->height);
        uint64_t nScore = (nDx + nDy) * 1000000ULL + nAspect;
        if (nScore < nBestScore)
        {
            nBestScore = nScore;
            nBest = pMode->id;
        }
    }
    return nBest;
}

static int DirectGate_Desktop_SetDisplayResolution(directgate_desktop_t *pDesktop,
                                                const directgate_desktop_monitor_t *pMonitor,
                                                uint32_t nWidth, uint32_t nHeight)
{
    Display *pDisplay = (Display*)pDesktop->pDisplay;
    if (pDisplay == NULL || pMonitor == NULL || pMonitor->nNativeId == 0U)
    {
        DirectGate_Desktop_SetReason(pDesktop,
            "Display mode requires one physical monitor; All displays cannot be resized.");
        return XSTDERR;
    }

    Window root = RootWindow(pDisplay, DefaultScreen(pDisplay));
    XRRScreenResources *pResources = XRRGetScreenResourcesCurrent(pDisplay, root);
    if (pResources == NULL)
    {
        DirectGate_Desktop_SetReason(pDesktop, "Failed to read XRandR display modes.");
        return XSTDERR;
    }
    XRROutputInfo *pOutput = XRRGetOutputInfo(pDisplay, pResources, (RROutput)pMonitor->nNativeId);
    XRRCrtcInfo *pCrtc = (pOutput != NULL && pOutput->crtc != None) ?
        XRRGetCrtcInfo(pDisplay, pResources, pOutput->crtc) : NULL;
    RRMode nMode = DirectGate_Desktop_ClosestXrandrMode(pResources, pOutput, nWidth, nHeight);
    if (pOutput == NULL || pCrtc == NULL || nMode == None)
    {
        if (pCrtc != NULL) XRRFreeCrtcInfo(pCrtc);
        if (pOutput != NULL) XRRFreeOutputInfo(pOutput);
        XRRFreeScreenResources(pResources);
        DirectGate_Desktop_SetReason(pDesktop, "No usable XRandR mode is available for this monitor.");
        return XSTDERR;
    }

    if (!pDesktop->bDisplayModeChanged)
    {
        pDesktop->nOriginalModeId = (uint64_t)pCrtc->mode;
        pDesktop->nOriginalModeX = pCrtc->x;
        pDesktop->nOriginalModeY = pCrtc->y;
        pDesktop->nOriginalModeRotation = (uint32_t)pCrtc->rotation;
        pDesktop->nModeNativeId = (uint64_t)pOutput->crtc;
        xstrncpy(pDesktop->sModeMonitorId, sizeof(pDesktop->sModeMonitorId), pMonitor->sId);
        xstrncpy(pDesktop->sModeDeviceId, sizeof(pDesktop->sModeDeviceId), pMonitor->sDeviceId);
    }

    Status nStatus = XRRSetCrtcConfig(pDisplay, pResources, pOutput->crtc, CurrentTime,
        pCrtc->x, pCrtc->y, nMode, pCrtc->rotation, pCrtc->outputs, pCrtc->noutput);
    XRRFreeCrtcInfo(pCrtc);
    XRRFreeOutputInfo(pOutput);
    XRRFreeScreenResources(pResources);
    if (nStatus != Success)
    {
        DirectGate_Desktop_SetReason(pDesktop, "XRandR rejected the requested display mode.");
        return XSTDERR;
    }

    pDesktop->bDisplayModeChanged = XTRUE;
    XSync(pDisplay, False);
    DirectGate_Desktop_RefreshLinuxMonitors(pDesktop);
    return XSTDOK;
}

static void DirectGate_Desktop_RestoreDisplayMode(directgate_desktop_t *pDesktop)
{
    Display *pDisplay = pDesktop != NULL ? (Display*)pDesktop->pDisplay : NULL;
    if (pDisplay == NULL || !pDesktop->bDisplayModeChanged) return;

    Window root = RootWindow(pDisplay, DefaultScreen(pDisplay));
    XRRScreenResources *pResources = XRRGetScreenResourcesCurrent(pDisplay, root);
    XRRCrtcInfo *pCrtc = pResources != NULL ? XRRGetCrtcInfo(pDisplay, pResources, (RRCrtc)pDesktop->nModeNativeId) : NULL;

    if (pResources != NULL && pCrtc != NULL)
    {
        (void)XRRSetCrtcConfig(pDisplay, pResources, (RRCrtc)pDesktop->nModeNativeId,
            CurrentTime, pDesktop->nOriginalModeX, pDesktop->nOriginalModeY,
            (RRMode)pDesktop->nOriginalModeId, (Rotation)pDesktop->nOriginalModeRotation,
            pCrtc->outputs, pCrtc->noutput);
        XSync(pDisplay, False);
    }

    if (pCrtc != NULL) XRRFreeCrtcInfo(pCrtc);
    if (pResources != NULL) XRRFreeScreenResources(pResources);

    pDesktop->bDisplayModeChanged = XFALSE;
    pDesktop->nModeNativeId = 0U;
    pDesktop->nOriginalModeId = 0U;
    DirectGate_Desktop_RefreshLinuxMonitors(pDesktop);
}

static void DirectGate_Desktop_LoadXTest(directgate_desktop_t *pDesktop)
{
    pDesktop->pXtst = dlopen("libXtst.so.6", RTLD_LAZY | RTLD_LOCAL);
    if (pDesktop->pXtst == NULL)
    {
        xlogw("Desktop input disabled: libXtst.so.6 not found");
        return;
    }

    pDesktop->pFakeMotion = dlsym(pDesktop->pXtst, "XTestFakeMotionEvent");
    pDesktop->pFakeButton = dlsym(pDesktop->pXtst, "XTestFakeButtonEvent");
    pDesktop->pFakeKey = dlsym(pDesktop->pXtst, "XTestFakeKeyEvent");

    pDesktop->bInputReady = (pDesktop->pFakeMotion != NULL &&
                            pDesktop->pFakeButton != NULL &&
                            pDesktop->pFakeKey != NULL);

    if (!pDesktop->bInputReady)
        xlogw("Desktop input disabled: XTest symbols are unavailable");
}

static const char* DirectGate_Desktop_FindX11Display(char *pBuf, size_t nBufSize)
{
    const char *pEnvDisplay = getenv("DISPLAY");
    if (xstrused(pEnvDisplay)) return pEnvDisplay;

    DIR *pDir = opendir("/tmp/.X11-unix");
    if (pDir == NULL) return NULL;

    struct dirent *pEntry = NULL;
    while ((pEntry = readdir(pDir)) != NULL)
    {
        if (pEntry->d_name[0] != 'X' || !pEntry->d_name[1])
            continue;

        xstrncpy(pBuf, nBufSize, ":");
        strncat(pBuf, pEntry->d_name + 1, nBufSize - strlen(pBuf) - 1U);
        break;
    }

    closedir(pDir);
    return xstrused(pBuf) ? pBuf : NULL;
}

static void DirectGate_Desktop_SetXAuthority(const directgate_session_t *pSession)
{
    if (xstrused(getenv("XAUTHORITY"))) return;
    if (pSession == NULL || pSession->pCfg == NULL ||
        !xstrused(pSession->pCfg->sShellHome)) return;

    char sPath[XPATH_MAX];
    if (strlen(pSession->pCfg->sShellHome) + sizeof("/.Xauthority") > sizeof(sPath))
        return;

    snprintf(sPath, sizeof(sPath), "%s/.Xauthority", pSession->pCfg->sShellHome);
    if (access(sPath, R_OK) == 0)
        setenv("XAUTHORITY", sPath, 0);
}

static int DirectGate_Desktop_OpenX11(directgate_session_t *pSession)
{
    directgate_desktop_t *pDesktop = &pSession->desktop;
    char sDisplay[DIRECTGATE_DESKTOP_DISPLAY_LEN];
    memset(sDisplay, 0, sizeof(sDisplay));
    const char *pDisplayName = DirectGate_Desktop_FindX11Display(sDisplay, sizeof(sDisplay));

    if (!xstrused(pDisplayName))
    {
        if (xstrused(getenv("WAYLAND_DISPLAY")) ||
            (xstrused(getenv("XDG_SESSION_TYPE")) && xstrcmp(getenv("XDG_SESSION_TYPE"), "wayland")))
        {
            xstrncpy(pDesktop->sBackend, sizeof(pDesktop->sBackend), "wayland");
            DirectGate_Desktop_SetReason(pDesktop, "Wayland desktop streaming is not implemented yet.");
            return XSTDERR;
        }

        xstrncpy(pDesktop->sBackend, sizeof(pDesktop->sBackend), "none");
        DirectGate_Desktop_SetReason(pDesktop,
            "No display is available on this host. Headless servers without "
            "a graphical session cannot stream a desktop.");
        return XSTDERR;
    }

    XInitThreads();
    DirectGate_Desktop_SetXAuthority(pSession);
    Display *pDisplay = XOpenDisplay(pDisplayName);
    if (pDisplay == NULL)
    {
        xstrncpy(pDesktop->sBackend, sizeof(pDesktop->sBackend), "x11");
        xstrncpy(pDesktop->sDisplay, sizeof(pDesktop->sDisplay), pDisplayName);
        DirectGate_Desktop_SetReason(pDesktop, "Failed to open X11 display. Check DISPLAY and XAUTHORITY for the directgate service user.");
        return XSTDERR;
    }

    int nScreen = DefaultScreen(pDisplay);
    Window root = RootWindow(pDisplay, nScreen);
    XWindowAttributes attrs;

    if (!XGetWindowAttributes(pDisplay, root, &attrs) || attrs.width <= 0 || attrs.height <= 0)
    {
        XCloseDisplay(pDisplay);
        xstrncpy(pDesktop->sBackend, sizeof(pDesktop->sBackend), "x11");
        xstrncpy(pDesktop->sDisplay, sizeof(pDesktop->sDisplay), pDisplayName);
        DirectGate_Desktop_SetReason(pDesktop, "Failed to read X11 root window size.");
        return XSTDERR;
    }

    pDesktop->pDisplay = pDisplay;
    pDesktop->nScreenWidth = (uint32_t)attrs.width;
    pDesktop->nScreenHeight = (uint32_t)attrs.height;
    xstrncpy(pDesktop->sBackend, sizeof(pDesktop->sBackend), "x11");
    xstrncpy(pDesktop->sDisplay, sizeof(pDesktop->sDisplay), pDisplayName);
    DirectGate_Desktop_EnumerateMonitors(pDesktop);
    DirectGate_Desktop_LoadXTest(pDesktop);

    return XSTDOK;
}

static int DirectGate_Desktop_StartTimer(directgate_desktop_t *pDesktop)
{
    int nFd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (nFd < 0)
    {
        DirectGate_Desktop_SetReason(pDesktop, "Failed to create desktop frame timer.");
        return XSTDERR;
    }

    uint32_t nFps = pDesktop->nFps ? pDesktop->nFps : DIRECTGATE_DESKTOP_DEFAULT_FPS;
    uint64_t nNs = 1000000000ULL / nFps;
    struct itimerspec spec;
    memset(&spec, 0, sizeof(spec));
    spec.it_interval.tv_sec = (time_t)(nNs / 1000000000ULL);
    spec.it_interval.tv_nsec = (long)(nNs % 1000000000ULL);
    spec.it_value = spec.it_interval;

    if (timerfd_settime(nFd, 0, &spec, NULL) < 0)
    {
        close(nFd);
        DirectGate_Desktop_SetReason(pDesktop, "Failed to arm desktop frame timer.");
        return XSTDERR;
    }

    pDesktop->nTimerFd = nFd;
    return XSTDOK;
}

/* Mirrors DirectGate_Desktop_StartMacPipeline: prefer the H.264 pipeline and
 * demote to raw RGBA when the encoder cannot start (missing OpenH264
 * library, unsupported pixel format, capture probe failure, ...). */
static int DirectGate_Desktop_StartLinuxPipeline(directgate_session_t *pSession)
{
    directgate_desktop_t *pDesktop = &pSession->desktop;

    if (pDesktop->bForceRaw)
    {
        pDesktop->ePipeline = DIRECTGATE_DESKTOP_PIPELINE_RAW;
        xstrncpy(pDesktop->sCodec, sizeof(pDesktop->sCodec), "raw-rgba");

        DirectGate_Desktop_SetFallbackReason(pDesktop, "Raw RGBA forced by DIRECTGATE_DESKTOP_FORCE_RAW.");
        DirectGate_Desktop_ComputeFrameSize(pDesktop);
        return XSTDOK;
    }

    if (DirectGate_Desktop_LinuxEncoder_Start(pSession,
        pDesktop->nCaptureX, pDesktop->nCaptureY,
        pDesktop->nCaptureWidth, pDesktop->nCaptureHeight) < 0)
    {
        const char *pErr = DirectGate_Desktop_LinuxEncoder_LastError(pSession);
        xlogw("Linux H.264 encoder unavailable, falling back to raw RGBA: sid(%u), reason(%s)",
            pSession->nSessionId, xstrused(pErr) ? pErr : "unknown");

        pDesktop->bForceRaw = XTRUE;
        pDesktop->ePipeline = DIRECTGATE_DESKTOP_PIPELINE_RAW;
        xstrncpy(pDesktop->sCodec, sizeof(pDesktop->sCodec), "raw-rgba");

        DirectGate_Desktop_SetFallbackReason(pDesktop, xstrused(pErr) ? pErr : "OpenH264 encoder failed; using raw RGBA.");
        DirectGate_Desktop_ComputeFrameSize(pDesktop);
        return XSTDOK;
    }

    xstrncpy(pDesktop->sCodec, sizeof(pDesktop->sCodec), "h264");
    if (!pDesktop->bWebRTCVideoFailed && DirectGate_WebRTC_IsVideoOpen(&pSession->webrtc))
    {
        pDesktop->ePipeline = DIRECTGATE_DESKTOP_PIPELINE_WEBRTC_VIDEO;
        DirectGate_Desktop_SetFallbackReason(pDesktop, NULL);
    }
    else
    {
        pDesktop->ePipeline = DIRECTGATE_DESKTOP_PIPELINE_H264_DC;
        DirectGate_Desktop_SetFallbackReason(pDesktop,
            "WebRTC video track is unavailable; using encrypted H.264 data channel.");
    }

    return XSTDOK;
}

static void DirectGate_Desktop_MaybePromoteWebRTCVideo(directgate_session_t *pSession)
{
    XCHECK_VOID_NL((pSession != NULL));
    directgate_desktop_t *pDesktop = &pSession->desktop;

    if (pDesktop->bForceRaw || pDesktop->bWebRTCVideoFailed)
        return;

    if (pDesktop->ePipeline != DIRECTGATE_DESKTOP_PIPELINE_H264_DC)
        return;

    if (!DirectGate_WebRTC_IsVideoOpen(&pSession->webrtc))
        return;

    pDesktop->ePipeline = DIRECTGATE_DESKTOP_PIPELINE_WEBRTC_VIDEO;
    DirectGate_Desktop_SetFallbackReason(pDesktop, NULL);
    DirectGate_Desktop_LinuxEncoder_RequestKeyframe(pSession);
    DirectGate_Desktop_SendStatus(pSession, "streaming", NULL);
}

/* Runtime failure demotion: too many consecutive capture/encode failures
 * flip the session to the raw RGBA path so the operator keeps a picture. */
static void DirectGate_Desktop_DemoteToRaw(directgate_session_t *pSession)
{
    directgate_desktop_t *pDesktop = &pSession->desktop;
    const char *pErr = DirectGate_Desktop_LinuxEncoder_LastError(pSession);

    xlogw("Linux H.264 pipeline failed, falling back to raw RGBA: sid(%u), reason(%s)",
        pSession->nSessionId, xstrused(pErr) ? pErr : "unknown");

    DirectGate_Desktop_SetFallbackReason(pDesktop,
        xstrused(pErr) ? pErr : "H.264 pipeline failed at runtime; using raw RGBA.");
    DirectGate_Desktop_LinuxEncoder_StopDesktop(pDesktop);

    pDesktop->ePipeline = DIRECTGATE_DESKTOP_PIPELINE_RAW;
    pDesktop->bForceRaw = XTRUE;
    xstrncpy(pDesktop->sCodec, sizeof(pDesktop->sCodec), "raw-rgba");

    DirectGate_Desktop_ComputeFrameSize(pDesktop);
    DirectGate_Desktop_SendStatus(pSession, "streaming", NULL);
}

int DirectGate_Desktop_Start(directgate_session_t *pSession)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    directgate_desktop_t *pDesktop = &pSession->desktop;

    if (pDesktop->bRunning)
        return XAPI_CONTINUE;

    DirectGate_Desktop_Clear(pDesktop);
    DirectGate_Desktop_Init(pDesktop);
    pDesktop->nSessionId = pSession->nSessionId;

    if (DirectGate_Desktop_OpenX11(pSession) < 0)
    {
        xlogw("Desktop mode unavailable: sid(%u), reason(%s)",
            pSession->nSessionId, DirectGate_Desktop_GetReason(pDesktop));
        DirectGate_Desktop_SendStatus(pSession, "error", DirectGate_Desktop_GetReason(pDesktop));
        DirectGate_Session_SendErrorMsg(pSession, DirectGate_Desktop_GetReason(pDesktop));
        return XSTDERR;
    }

    if (DirectGate_Desktop_StartTimer(pDesktop) < 0)
    {
        xlogw("Desktop timer failed: sid(%u), reason(%s)",
            pSession->nSessionId, DirectGate_Desktop_GetReason(pDesktop));
        DirectGate_Desktop_SendStatus(pSession, "error", DirectGate_Desktop_GetReason(pDesktop));
        DirectGate_Desktop_Clear(pDesktop);
        DirectGate_Session_SendErrorMsg(pSession, DirectGate_Desktop_GetReason(pDesktop));
        return XSTDERR;
    }

    pDesktop->bRunning = XTRUE;
    xlogi("Desktop mode activated: sid(%u), backend(%s), display(%s), screen(%ux%u), frame(%ux%u), input(%s)",
        pSession->nSessionId, pDesktop->sBackend, pDesktop->sDisplay,
        pDesktop->nScreenWidth, pDesktop->nScreenHeight,
        pDesktop->nFrameWidth, pDesktop->nFrameHeight,
        pDesktop->bInputReady ? "yes" : "no");

    return DirectGate_Desktop_SendStatus(pSession, "ready", NULL);
}

static int DirectGate_Desktop_SendFrameChunks(directgate_session_t *pSession, const uint8_t *pFrame, size_t nFrameSize)
{
    directgate_desktop_t *pDesktop = &pSession->desktop;
    uint32_t nChunks = (uint32_t)((nFrameSize + DIRECTGATE_DESKTOP_CHUNK_SIZE - 1U) / DIRECTGATE_DESKTOP_CHUNK_SIZE);
    uint64_t nFrameId = ++pDesktop->nFrameId;

    for (uint32_t i = 0; i < nChunks; i++)
    {
        size_t nOffset = (size_t)i * DIRECTGATE_DESKTOP_CHUNK_SIZE;
        size_t nChunk = nFrameSize - nOffset;
        if (nChunk > DIRECTGATE_DESKTOP_CHUNK_SIZE) nChunk = DIRECTGATE_DESKTOP_CHUNK_SIZE;

        xjson_obj_t *pHeader = DirectGate_Proto_BuildData(pSession->nSessionId);
        XCHECK((pHeader != NULL), XAPI_DISCONNECT);

        XJSON_AddString(pHeader, "payloadType", "desktop-frame-chunk");
        XJSON_AddU64(pHeader, "frameId", nFrameId);
        XJSON_AddU32(pHeader, "chunkIndex", i);
        XJSON_AddU32(pHeader, "chunks", nChunks);
        XJSON_AddU32(pHeader, "width", pDesktop->nFrameWidth);
        XJSON_AddU32(pHeader, "height", pDesktop->nFrameHeight);
        XJSON_AddU32(pHeader, "screenWidth", pDesktop->nCaptureWidth);
        XJSON_AddU32(pHeader, "screenHeight", pDesktop->nCaptureHeight);
        XJSON_AddString(pHeader, "monitorId", pDesktop->sSelectedMonitor);
        XJSON_AddString(pHeader, "encoding", "raw-rgba");

        int nStatus = DirectGate_Session_Send(pSession, pHeader, pFrame + nOffset, nChunk);
        XJSON_FreeObject(pHeader);
        if (nStatus < 0) return nStatus;
    }

    return XAPI_CONTINUE;
}

static int DirectGate_Desktop_CaptureFrame(directgate_session_t *pSession)
{
    directgate_desktop_t *pDesktop = &pSession->desktop;
    Display *pDisplay = (Display*)pDesktop->pDisplay;
    XCHECK((pDisplay != NULL), XAPI_CONTINUE);
    XCHECK_NL((pDesktop->bCaptureReady), XAPI_CONTINUE);

    /* Transport backpressure (mirrors the macOS capture callback). A raw 1080p
     * RGBA frame is ~8 MB - far more than the data channel can drain per tick.
     * Without this guard the SCTP send buffer grows without bound and frames
     * arrive seconds-to-minutes behind live. Skipping the whole capture (no
     * XGetImage, no send) lets the channel drain and keeps the stream live at
     * an adaptive frame rate. */
    if (DirectGate_Desktop_ShouldSkipForBackpressure(pSession))
        return XAPI_CONTINUE;

    int nScreen = DefaultScreen(pDisplay);
    Window root = RootWindow(pDisplay, nScreen);
    XImage *pImage = XGetImage(pDisplay, root, pDesktop->nCaptureX, pDesktop->nCaptureY,
        pDesktop->nCaptureWidth, pDesktop->nCaptureHeight, AllPlanes, ZPixmap);
    if (pImage == NULL)
    {
        xlogw("Failed to capture X11 frame: sid(%u)", pSession->nSessionId);
        return XAPI_CONTINUE;
    }

    size_t nFrameSize = (size_t)pDesktop->nFrameWidth * pDesktop->nFrameHeight * 4U;
    uint8_t *pFrame = (uint8_t*)malloc(nFrameSize);
    if (pFrame == NULL)
    {
        XDestroyImage(pImage);
        xloge("Failed to allocate desktop frame: sid(%u), bytes(%zu)",
            pSession->nSessionId, nFrameSize);
        return XAPI_CONTINUE;
    }

    uint32_t nRShift = DirectGate_Desktop_MaskShift(pImage->red_mask);
    uint32_t nGShift = DirectGate_Desktop_MaskShift(pImage->green_mask);
    uint32_t nBShift = DirectGate_Desktop_MaskShift(pImage->blue_mask);

    for (uint32_t y = 0; y < pDesktop->nFrameHeight; y++)
    {
        uint32_t nSrcY = (uint32_t)(((uint64_t)y * pDesktop->nCaptureHeight) / pDesktop->nFrameHeight);
        for (uint32_t x = 0; x < pDesktop->nFrameWidth; x++)
        {
            uint32_t nSrcX = (uint32_t)(((uint64_t)x * pDesktop->nCaptureWidth) / pDesktop->nFrameWidth);
            unsigned long nPixel = XGetPixel(pImage, (int)nSrcX, (int)nSrcY);
            size_t nDst = ((size_t)y * pDesktop->nFrameWidth + x) * 4U;
            pFrame[nDst + 0] = DirectGate_Desktop_PixelComponent(nPixel, pImage->red_mask, nRShift);
            pFrame[nDst + 1] = DirectGate_Desktop_PixelComponent(nPixel, pImage->green_mask, nGShift);
            pFrame[nDst + 2] = DirectGate_Desktop_PixelComponent(nPixel, pImage->blue_mask, nBShift);
            pFrame[nDst + 3] = 255;
        }
    }

    XDestroyImage(pImage);
    int nStatus = DirectGate_Desktop_SendFrameChunks(pSession, pFrame, nFrameSize);

    free(pFrame);
    return nStatus;
}

int DirectGate_Desktop_Process(directgate_session_t *pSession)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    directgate_desktop_t *pDesktop = &pSession->desktop;

    XCHECK_NL((pDesktop->bRunning), XAPI_CONTINUE);
    if (pDesktop->nTimerFd != XSOCK_INVALID)
    {
        uint64_t nTicks = 0;
        while (read(pDesktop->nTimerFd, &nTicks, sizeof(nTicks)) > 0) {}
    }

    /* The H.264 pipeline captures + encodes synchronously on each tick;
     * the raw path keeps the legacy pull-per-tick behavior. */
    if (pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_WEBRTC_VIDEO ||
        pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_H264_DC)
    {
        if (DirectGate_WebRTC_TakeVideoKeyframeRequest(&pSession->webrtc))
            DirectGate_Desktop_LinuxEncoder_RequestKeyframe(pSession);

        DirectGate_Desktop_MaybePromoteWebRTCVideo(pSession);
        DirectGate_Desktop_AdaptBitrate(pSession);

        if (DirectGate_Desktop_LinuxEncoder_HasFailed(pSession))
        {
            DirectGate_Desktop_DemoteToRaw(pSession);
            return XAPI_CONTINUE;
        }

        return DirectGate_Desktop_LinuxEncoder_ProcessTick(pSession);
    }

    return DirectGate_Desktop_CaptureFrame(pSession);
}

static int DirectGate_Desktop_FrameToScreenX(const directgate_desktop_t *pDesktop, int nX)
{
    if (pDesktop->nFrameWidth <= 1) return 0;
    if (nX < 0) nX = 0;
    if ((uint32_t)nX >= pDesktop->nFrameWidth) nX = (int)pDesktop->nFrameWidth - 1;
    return pDesktop->nCaptureX +
        (int)(((uint64_t)(uint32_t)nX * pDesktop->nCaptureWidth) / pDesktop->nFrameWidth);
}

static int DirectGate_Desktop_FrameToScreenY(const directgate_desktop_t *pDesktop, int nY)
{
    if (pDesktop->nFrameHeight <= 1) return 0;
    if (nY < 0) nY = 0;
    if ((uint32_t)nY >= pDesktop->nFrameHeight) nY = (int)pDesktop->nFrameHeight - 1;
    return pDesktop->nCaptureY +
        (int)(((uint64_t)(uint32_t)nY * pDesktop->nCaptureHeight) / pDesktop->nFrameHeight);
}

static KeySym DirectGate_Desktop_KeySymFromJson(xjson_obj_t *pRoot)
{
    const char *pKey = XJSON_GetString(XJSON_GetObject(pRoot, "key"));
    const char *pCode = XJSON_GetString(XJSON_GetObject(pRoot, "code"));

    if (xstrused(pKey))
    {
        if (strlen(pKey) == 1)
        {
            char sKey[2] = { pKey[0], '\0' };
            KeySym sym = XStringToKeysym(sKey);
            if (sym != NoSymbol) return sym;
        }

        if (xstrcmp(pKey, "Enter")) return XK_Return;
        if (xstrcmp(pKey, "Backspace")) return XK_BackSpace;
        if (xstrcmp(pKey, "Tab")) return XK_Tab;
        if (xstrcmp(pKey, "Escape")) return XK_Escape;
        if (xstrcmp(pKey, "Delete")) return XK_Delete;
        if (xstrcmp(pKey, "Home")) return XK_Home;
        if (xstrcmp(pKey, "End")) return XK_End;
        if (xstrcmp(pKey, "PageUp")) return XK_Page_Up;
        if (xstrcmp(pKey, "PageDown")) return XK_Page_Down;
        if (xstrcmp(pKey, "ArrowLeft")) return XK_Left;
        if (xstrcmp(pKey, "ArrowRight")) return XK_Right;
        if (xstrcmp(pKey, "ArrowUp")) return XK_Up;
        if (xstrcmp(pKey, "ArrowDown")) return XK_Down;
        if (xstrcmp(pKey, " ")) return XK_space;
        if (xstrcmp(pKey, "Shift")) return XK_Shift_L;
        if (xstrcmp(pKey, "Control")) return XK_Control_L;
        if (xstrcmp(pKey, "Alt")) return XK_Alt_L;
        if (xstrcmp(pKey, "Meta")) return XK_Super_L;
    }

    if (xstrused(pCode) && strlen(pCode) == 4 && !strncmp(pCode, "Key", 3))
    {
        char sKey[2] = { (char)tolower((unsigned char)pCode[3]), '\0' };
        return XStringToKeysym(sKey);
    }

    if (xstrused(pCode) && strlen(pCode) == 6 && !strncmp(pCode, "Digit", 5))
    {
        char sKey[2] = { pCode[5], '\0' };
        return XStringToKeysym(sKey);
    }

    return NoSymbol;
}

int DirectGate_Desktop_HandleInput(directgate_session_t *pSession, const uint8_t *pPayload, size_t nPayloadLength)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    directgate_desktop_t *pDesktop = &pSession->desktop;

    if (!pDesktop->bRunning || pDesktop->pDisplay == NULL || !pDesktop->bInputReady)
        return XAPI_CONTINUE;

    if (pPayload == NULL || !nPayloadLength)
        return XAPI_CONTINUE;

    char *pJsonText = (char*)calloc(1, nPayloadLength + 1U);
    XCHECK((pJsonText != NULL), XAPI_CONTINUE);
    memcpy(pJsonText, pPayload, nPayloadLength);

    xjson_t json;
    if (!XJSON_Parse(&json, NULL, pJsonText, nPayloadLength))
    {
        free(pJsonText);
        return XAPI_CONTINUE;
    }

    xjson_obj_t *pRoot = json.pRootObj;
    const char *pAction = XJSON_GetString(XJSON_GetObject(pRoot, "action"));
    const char *pEvent = XJSON_GetString(XJSON_GetObject(pRoot, "event"));
    Display *pDisplay = (Display*)pDesktop->pDisplay;
    int nScreen = DefaultScreen(pDisplay);

    if (xstrcmp(pAction, "pointer"))
    {
        int nX = XJSON_GetInt(XJSON_GetObject(pRoot, "x"));
        int nY = XJSON_GetInt(XJSON_GetObject(pRoot, "y"));
        int nScreenX = DirectGate_Desktop_FrameToScreenX(pDesktop, nX);
        int nScreenY = DirectGate_Desktop_FrameToScreenY(pDesktop, nY);
        ((directgate_xtest_motion_fn)pDesktop->pFakeMotion)(pDisplay, nScreen, nScreenX, nScreenY, CurrentTime);

        if (xstrcmp(pEvent, "button"))
        {
            uint32_t nButton = XJSON_GetU32(XJSON_GetObject(pRoot, "button"));
            xbool_t bDown = XJSON_GetBool(XJSON_GetObject(pRoot, "down"));
            if (nButton >= 1 && nButton <= 5)
                ((directgate_xtest_button_fn)pDesktop->pFakeButton)(pDisplay, nButton, bDown ? True : False, CurrentTime);
        }
        else if (xstrcmp(pEvent, "wheel"))
        {
            int nDeltaY = XJSON_GetInt(XJSON_GetObject(pRoot, "deltaY"));
            uint32_t nButton = nDeltaY < 0 ? 4U : 5U;
            ((directgate_xtest_button_fn)pDesktop->pFakeButton)(pDisplay, nButton, True, CurrentTime);
            ((directgate_xtest_button_fn)pDesktop->pFakeButton)(pDisplay, nButton, False, CurrentTime);
        }
    }
    else if (xstrcmp(pAction, "key"))
    {
        KeySym sym = DirectGate_Desktop_KeySymFromJson(pRoot);
        if (sym != NoSymbol)
        {
            KeyCode code = XKeysymToKeycode(pDisplay, sym);
            xbool_t bDown = XJSON_GetBool(XJSON_GetObject(pRoot, "down"));
            if (code != 0)
                ((directgate_xtest_key_fn)pDesktop->pFakeKey)(pDisplay, code, bDown ? True : False, CurrentTime);
        }
    }

    XFlush(pDisplay);
    XJSON_Destroy(&json);
    free(pJsonText);
    return XAPI_CONTINUE;
}

int DirectGate_Desktop_HandleControl(directgate_session_t *pSession, const uint8_t *pPayload, size_t nPayloadLength)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    directgate_desktop_t *pDesktop = &pSession->desktop;

    if (!pDesktop->bRunning || pPayload == NULL || !nPayloadLength)
        return XAPI_CONTINUE;

    char *pJsonText = (char*)calloc(1, nPayloadLength + 1U);
    XCHECK((pJsonText != NULL), XAPI_CONTINUE);
    memcpy(pJsonText, pPayload, nPayloadLength);

    xjson_t json;
    if (!XJSON_Parse(&json, NULL, pJsonText, nPayloadLength))
    {
        free(pJsonText);
        return XAPI_CONTINUE;
    }

    xjson_obj_t *pRoot = json.pRootObj;
    const char *pAction = XJSON_GetString(XJSON_GetObject(pRoot, "action"));
    const char *pMonitorId = XJSON_GetString(XJSON_GetObject(pRoot, "monitorId"));

    if (xstrcmp(pAction, "select-monitor") && xstrused(pMonitorId))
    {
        DirectGate_Desktop_ReadResizeRequest(pDesktop, pRoot);
        const directgate_desktop_monitor_t *pSelected = NULL;
        for (uint32_t i = 0; i < pDesktop->nMonitorCount; i++)
        {
            if (xstrcmp(pDesktop->monitors[i].sId, pMonitorId))
            {
                pSelected = &pDesktop->monitors[i];
                break;
            }
        }

        if (pSelected != NULL)
        {
            char sSelectedId[DIRECTGATE_DESKTOP_MONITOR_ID_LEN];
            xstrncpy(sSelectedId, sizeof(sSelectedId), pSelected->sId);
            const char *pResizeReason = NULL;

            if (pDesktop->eResizeMode == DIRECTGATE_DESKTOP_RESIZE_DISPLAY &&
                DirectGate_Desktop_SetDisplayResolution(pDesktop, pSelected,
                    pDesktop->nTargetWidth, pDesktop->nTargetHeight) != XSTDOK)
            {
                pResizeReason = DirectGate_Desktop_GetReason(pDesktop);
                pDesktop->eResizeMode = DIRECTGATE_DESKTOP_RESIZE_SCALE;
            }

            pSelected = DirectGate_Desktop_FindMonitor(pDesktop, sSelectedId);
            if (pSelected == NULL)
            {
                DirectGate_Desktop_SendStatus(pSession, "error",
                    "Selected monitor disappeared after its display mode changed.");
                XJSON_Destroy(&json);
                free(pJsonText);
                return XAPI_CONTINUE;
            }

            DirectGate_Desktop_SetCapture(pDesktop, pSelected->sId, pSelected->nX,
                pSelected->nY, pSelected->nWidth, pSelected->nHeight);

            if (DirectGate_Desktop_StartLinuxPipeline(pSession) < 0)
            {
                XJSON_Destroy(&json);
                free(pJsonText);

                DirectGate_Desktop_SendStatus(pSession, "error", "Failed to start desktop pipeline.");
                return XAPI_CONTINUE;
            }

            DirectGate_Desktop_SendStatus(pSession, "streaming", pResizeReason);
            xlogi("Desktop monitor selected: sid(%u), monitor(%s), rect(%d,%d %ux%u), pipeline(%s), preset(%s)",
                pSession->nSessionId, pSelected->sId, pSelected->nX, pSelected->nY,
                pSelected->nWidth, pSelected->nHeight,
                DirectGate_Desktop_PipelineName(pDesktop->ePipeline),
                DirectGate_Desktop_PresetName(pDesktop->quality.ePreset));
        }
        else
        {
            DirectGate_Desktop_SendStatus(pSession, "error", "Selected monitor is not available.");
        }
    }
    else if (xstrcmp(pAction, "set-resolution"))
    {
        directgate_desktop_resize_mode_t ePreviousMode = pDesktop->eResizeMode;
        DirectGate_Desktop_ReadResizeRequest(pDesktop, pRoot);
        char sSelectedId[DIRECTGATE_DESKTOP_MONITOR_ID_LEN];
        xstrncpy(sSelectedId, sizeof(sSelectedId), pDesktop->sSelectedMonitor);
        const directgate_desktop_monitor_t *pSelected = DirectGate_Desktop_FindMonitor(pDesktop, sSelectedId);
        const char *pResizeReason = NULL;
        xbool_t bCaptureChanged = XFALSE;

        if (pDesktop->bCaptureReady && ePreviousMode == DIRECTGATE_DESKTOP_RESIZE_DISPLAY &&
            pDesktop->eResizeMode == DIRECTGATE_DESKTOP_RESIZE_SCALE)
        {
            DirectGate_Desktop_LinuxEncoder_Stop(pSession);
            DirectGate_Desktop_RestoreDisplayMode(pDesktop);
            pSelected = DirectGate_Desktop_FindMonitor(pDesktop, sSelectedId);
            bCaptureChanged = XTRUE;
        }
        else if (pDesktop->bCaptureReady &&
            pDesktop->eResizeMode == DIRECTGATE_DESKTOP_RESIZE_DISPLAY)
        {
            DirectGate_Desktop_LinuxEncoder_Stop(pSession);
            if (DirectGate_Desktop_SetDisplayResolution(pDesktop, pSelected,
                pDesktop->nTargetWidth, pDesktop->nTargetHeight) != XSTDOK)
            {
                pResizeReason = DirectGate_Desktop_GetReason(pDesktop);
                if (!pDesktop->bDisplayModeChanged)
                    pDesktop->eResizeMode = DIRECTGATE_DESKTOP_RESIZE_SCALE;
            }
            pSelected = DirectGate_Desktop_FindMonitor(pDesktop, sSelectedId);
            bCaptureChanged = XTRUE;
        }

        if (pDesktop->bCaptureReady && pSelected != NULL && bCaptureChanged)
        {
            DirectGate_Desktop_SetCapture(pDesktop, pSelected->sId, pSelected->nX,
                pSelected->nY, pSelected->nWidth, pSelected->nHeight);
            (void)DirectGate_Desktop_StartLinuxPipeline(pSession);
        }
        else if (pDesktop->bCaptureReady &&
            (pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_WEBRTC_VIDEO ||
             pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_H264_DC))
            DirectGate_Desktop_LinuxEncoder_ApplyQuality(pSession);
        else if (pDesktop->bCaptureReady)
            DirectGate_Desktop_ComputeFrameSize(pDesktop);

        DirectGate_Desktop_SendStatus(pSession,
            pDesktop->bCaptureReady ? "streaming" : "ready", pResizeReason);
    }
    else if (xstrcmp(pAction, "set-preset"))
    {
        const char *pPreset = XJSON_GetString(XJSON_GetObject(pRoot, "preset"));
        directgate_desktop_preset_t eNext = pDesktop->quality.ePreset;
        if (xstrcmp(pPreset, "quality")) eNext = DIRECTGATE_DESKTOP_PRESET_QUALITY;
        else if (xstrcmp(pPreset, "low-latency")) eNext = DIRECTGATE_DESKTOP_PRESET_LOW_LATENCY;
        else if (xstrcmp(pPreset, "balanced")) eNext = DIRECTGATE_DESKTOP_PRESET_BALANCED;

        DirectGate_Desktop_ApplyPreset(pDesktop, eNext);
        if (pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_WEBRTC_VIDEO ||
            pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_H264_DC)
            DirectGate_Desktop_LinuxEncoder_ApplyQuality(pSession);
        else if (pDesktop->bCaptureReady)
            DirectGate_Desktop_ComputeFrameSize(pDesktop);

        DirectGate_Desktop_SendStatus(pSession, "streaming", NULL);
        xlogi("Desktop preset updated: sid(%u), preset(%s), fps(%u), bitrate(%u kbps)",
            pSession->nSessionId,
            DirectGate_Desktop_PresetName(pDesktop->quality.ePreset),
            pDesktop->quality.nFps, pDesktop->quality.nBitrateKbps);
    }
    else if (xstrcmp(pAction, "request-keyframe"))
    {
        if (pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_WEBRTC_VIDEO ||
            pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_H264_DC)
            DirectGate_Desktop_LinuxEncoder_RequestKeyframe(pSession);
    }

    XJSON_Destroy(&json);
    free(pJsonText);
    return XAPI_CONTINUE;
}

#elif defined(__APPLE__)

static void DirectGate_Desktop_ComputeFrameSize(directgate_desktop_t *pDesktop)
{
    uint32_t nWidth = pDesktop->nCaptureWidth ? pDesktop->nCaptureWidth : pDesktop->nScreenWidth;
    uint32_t nHeight = pDesktop->nCaptureHeight ? pDesktop->nCaptureHeight : pDesktop->nScreenHeight;

    if (!nWidth) nWidth = 1;
    if (!nHeight) nHeight = 1;
    DirectGate_Desktop_LimitFrameSize(pDesktop, &nWidth, &nHeight);

    pDesktop->nFrameWidth = nWidth;
    pDesktop->nFrameHeight = nHeight;
}

static int DirectGate_Desktop_StartMacPipeline(directgate_session_t *pSession);

static void DirectGate_Desktop_SetCapture(directgate_desktop_t *pDesktop,
                                      const char *pMonitorId,
                                      int32_t nX,
                                      int32_t nY,
                                      uint32_t nWidth,
                                      uint32_t nHeight)
{
    XCHECK_VOID_NL((pDesktop != NULL));

    pDesktop->nCaptureX = nX;
    pDesktop->nCaptureY = nY;
    pDesktop->nCaptureWidth = nWidth ? nWidth : pDesktop->nScreenWidth;
    pDesktop->nCaptureHeight = nHeight ? nHeight : pDesktop->nScreenHeight;
    xstrncpy(pDesktop->sSelectedMonitor, sizeof(pDesktop->sSelectedMonitor),
        xstrused(pMonitorId) ? pMonitorId : "all");
    pDesktop->bCaptureReady = XTRUE;
    DirectGate_Desktop_ComputeFrameSize(pDesktop);
}

static void DirectGate_Desktop_AddMonitor(directgate_desktop_t *pDesktop,
                                      const char *pId,
                                      const char *pName,
                                      int32_t nX,
                                      int32_t nY,
                                      uint32_t nWidth,
                                      uint32_t nHeight,
                                      xbool_t bPrimary)
{
    XCHECK_VOID_NL((pDesktop != NULL));
    XCHECK_VOID_NL((pDesktop->nMonitorCount < DIRECTGATE_DESKTOP_MAX_MONITORS));
    XCHECK_VOID_NL((nWidth > 0 && nHeight > 0));

    directgate_desktop_monitor_t *pMonitor = &pDesktop->monitors[pDesktop->nMonitorCount++];
    xstrncpy(pMonitor->sId, sizeof(pMonitor->sId), xstrused(pId) ? pId : "display");
    xstrncpy(pMonitor->sName, sizeof(pMonitor->sName), xstrused(pName) ? pName : pMonitor->sId);
    pMonitor->nX = nX;
    pMonitor->nY = nY;
    pMonitor->nWidth = nWidth;
    pMonitor->nHeight = nHeight;
    pMonitor->bPrimary = bPrimary;
}

static uint32_t DirectGate_Desktop_RectWidth(CGRect rect)
{
    return rect.size.width > 0 ? (uint32_t)ceil(rect.size.width) : 0;
}

static uint32_t DirectGate_Desktop_RectHeight(CGRect rect)
{
    return rect.size.height > 0 ? (uint32_t)ceil(rect.size.height) : 0;
}

static int DirectGate_Desktop_OpenMacOS(directgate_session_t *pSession)
{
    directgate_desktop_t *pDesktop = &pSession->desktop;
    CGDirectDisplayID displays[DIRECTGATE_DESKTOP_MAX_MONITORS];
    uint32_t nDisplayCount = 0;

    CGError err = CGGetActiveDisplayList(DIRECTGATE_DESKTOP_MAX_MONITORS,
        displays, &nDisplayCount);
    if (err != kCGErrorSuccess || nDisplayCount == 0)
    {
        xstrncpy(pDesktop->sBackend, sizeof(pDesktop->sBackend), "macos");
        DirectGate_Desktop_SetReason(pDesktop, "No active macOS display is available.");
        return XSTDERR;
    }

    CGRect unionRect = CGRectNull;
    for (uint32_t i = 0; i < nDisplayCount; i++)
    {
        CGRect rect = CGDisplayBounds(displays[i]);
        unionRect = CGRectIsNull(unionRect) ? rect : CGRectUnion(unionRect, rect);
    }

    if (CGRectIsNull(unionRect) ||
        DirectGate_Desktop_RectWidth(unionRect) == 0 ||
        DirectGate_Desktop_RectHeight(unionRect) == 0)
    {
        xstrncpy(pDesktop->sBackend, sizeof(pDesktop->sBackend), "macos");
        DirectGate_Desktop_SetReason(pDesktop, "Failed to read macOS display bounds.");
        return XSTDERR;
    }

    pDesktop->nScreenWidth = DirectGate_Desktop_RectWidth(unionRect);
    pDesktop->nScreenHeight = DirectGate_Desktop_RectHeight(unionRect);
    xstrncpy(pDesktop->sBackend, sizeof(pDesktop->sBackend), "macos");
    xstrncpy(pDesktop->sDisplay, sizeof(pDesktop->sDisplay), "CoreGraphics");

    DirectGate_Desktop_AddMonitor(pDesktop, "all", "All displays",
        (int32_t)floor(unionRect.origin.x), (int32_t)floor(unionRect.origin.y),
        DirectGate_Desktop_RectWidth(unionRect),
        DirectGate_Desktop_RectHeight(unionRect), XFALSE);

    for (uint32_t i = 0; i < nDisplayCount && pDesktop->nMonitorCount < DIRECTGATE_DESKTOP_MAX_MONITORS; i++)
    {
        CGRect rect = CGDisplayBounds(displays[i]);
        char sId[DIRECTGATE_DESKTOP_MONITOR_ID_LEN];
        char sName[DIRECTGATE_DESKTOP_MONITOR_NAME_LEN];

        snprintf(sId, sizeof(sId), "display-%u", i + 1);
        snprintf(sName, sizeof(sName), "Display %u", i + 1);

        DirectGate_Desktop_AddMonitor(pDesktop, sId, sName,
            (int32_t)floor(rect.origin.x), (int32_t)floor(rect.origin.y),
            DirectGate_Desktop_RectWidth(rect), DirectGate_Desktop_RectHeight(rect),
            CGDisplayIsMain(displays[i]) ? XTRUE : XFALSE);
        directgate_desktop_monitor_t *pAdded = &pDesktop->monitors[pDesktop->nMonitorCount - 1U];
        pAdded->nNativeId = (uint64_t)displays[i];
        snprintf(pAdded->sDeviceId, sizeof(pAdded->sDeviceId), "%u", displays[i]);
    }

#if defined(__MAC_OS_X_VERSION_MAX_ALLOWED) && __MAC_OS_X_VERSION_MAX_ALLOWED >= 101500
    if (!CGPreflightScreenCaptureAccess())
    {
        xlogw("macOS desktop capture requires Screen Recording permission for directgate");
        DirectGate_Desktop_SetReason(pDesktop,
            "macOS requires Screen Recording permission for desktop streaming. "
            "Grant it to the DirectGate agent process in System Settings > Privacy & Security > Screen Recording, "
            "then restart the agent.");
        if (!CGRequestScreenCaptureAccess())
        {
            xlogw("macOS Screen Recording permission was not granted for directgate");
            return XSTDERR;
        }
    }
#endif

    pDesktop->bInputReady = AXIsProcessTrusted() ? XTRUE : XFALSE;
    if (!pDesktop->bInputReady)
        xlogw("macOS desktop input disabled: grant Accessibility permission to directgate");

    return XSTDOK;
}

static void DirectGate_Desktop_RefreshMacMonitors(directgate_desktop_t *pDesktop)
{
    CGDirectDisplayID displays[DIRECTGATE_DESKTOP_MAX_MONITORS];
    uint32_t nDisplayCount = 0;
    if (CGGetActiveDisplayList(DIRECTGATE_DESKTOP_MAX_MONITORS, displays,
        &nDisplayCount) != kCGErrorSuccess || nDisplayCount == 0) return;

    CGRect unionRect = CGRectNull;
    for (uint32_t i = 0; i < nDisplayCount; i++)
    {
        CGRect rect = CGDisplayBounds(displays[i]);
        unionRect = CGRectIsNull(unionRect) ? rect : CGRectUnion(unionRect, rect);
    }
    pDesktop->nScreenWidth = DirectGate_Desktop_RectWidth(unionRect);
    pDesktop->nScreenHeight = DirectGate_Desktop_RectHeight(unionRect);
    pDesktop->nMonitorCount = 0;
    memset(pDesktop->monitors, 0, sizeof(pDesktop->monitors));
    DirectGate_Desktop_AddMonitor(pDesktop, "all", "All displays",
        (int32_t)floor(unionRect.origin.x), (int32_t)floor(unionRect.origin.y),
        DirectGate_Desktop_RectWidth(unionRect), DirectGate_Desktop_RectHeight(unionRect), XFALSE);

    for (uint32_t i = 0; i < nDisplayCount &&
        pDesktop->nMonitorCount < DIRECTGATE_DESKTOP_MAX_MONITORS; i++)
    {
        CGRect rect = CGDisplayBounds(displays[i]);
        char sId[DIRECTGATE_DESKTOP_MONITOR_ID_LEN];
        char sName[DIRECTGATE_DESKTOP_MONITOR_NAME_LEN];
        snprintf(sId, sizeof(sId), "display-%u", i + 1U);
        snprintf(sName, sizeof(sName), "Display %u", i + 1U);
        DirectGate_Desktop_AddMonitor(pDesktop, sId, sName,
            (int32_t)floor(rect.origin.x), (int32_t)floor(rect.origin.y),
            DirectGate_Desktop_RectWidth(rect), DirectGate_Desktop_RectHeight(rect),
            CGDisplayIsMain(displays[i]) ? XTRUE : XFALSE);
        directgate_desktop_monitor_t *pAdded =
            &pDesktop->monitors[pDesktop->nMonitorCount - 1U];
        pAdded->nNativeId = (uint64_t)displays[i];
        snprintf(pAdded->sDeviceId, sizeof(pAdded->sDeviceId), "%u", displays[i]);
    }
}

static const directgate_desktop_monitor_t* DirectGate_Desktop_FindMonitor(
    const directgate_desktop_t *pDesktop, const char *pMonitorId)
{
    if (pDesktop == NULL || !xstrused(pMonitorId)) return NULL;
    for (uint32_t i = 0; i < pDesktop->nMonitorCount; i++)
        if (xstrcmp(pDesktop->monitors[i].sId, pMonitorId))
            return &pDesktop->monitors[i];
    return NULL;
}

static int DirectGate_Desktop_SetDisplayResolution(directgate_desktop_t *pDesktop,
                                                const directgate_desktop_monitor_t *pMonitor,
                                                uint32_t nWidth, uint32_t nHeight)
{
    if (pMonitor == NULL || pMonitor->nNativeId == 0U)
    {
        DirectGate_Desktop_SetReason(pDesktop,
            "Display mode requires one physical monitor; All displays cannot be resized.");
        return XSTDERR;
    }

    CGDirectDisplayID nDisplay = (CGDirectDisplayID)pMonitor->nNativeId;
    CGDisplayModeRef pCurrent = CGDisplayCopyDisplayMode(nDisplay);
    CFArrayRef pModes = CGDisplayCopyAllDisplayModes(nDisplay, NULL);

    if (pCurrent == NULL || pModes == NULL)
    {
        if (pCurrent != NULL) CGDisplayModeRelease(pCurrent);
        if (pModes != NULL) CFRelease(pModes);
        DirectGate_Desktop_SetReason(pDesktop, "Failed to read macOS display modes.");
        return XSTDERR;
    }

    CGDisplayModeRef pBest = NULL;
    uint64_t nBestScore = UINT64_MAX;
    CFIndex nCount = CFArrayGetCount(pModes);

    for (CFIndex i = 0; i < nCount; i++)
    {
        CGDisplayModeRef pMode = (CGDisplayModeRef)CFArrayGetValueAtIndex(pModes, i);
        uint32_t nModeWidth = (uint32_t)CGDisplayModeGetWidth(pMode);
        uint32_t nModeHeight = (uint32_t)CGDisplayModeGetHeight(pMode);
        uint64_t nDx = nModeWidth > nWidth ? nModeWidth - nWidth : nWidth - nModeWidth;
        uint64_t nDy = nModeHeight > nHeight ? nModeHeight - nHeight : nHeight - nModeHeight;
        uint64_t nAspect = (uint64_t)llabs((long long)nModeWidth * nHeight - (long long)nWidth * nModeHeight);
        uint64_t nScore = (nDx + nDy) * 1000000ULL + nAspect;

        if (nScore < nBestScore)
        {
            nBestScore = nScore;
            pBest = pMode;
        }
    }

    if (pBest != NULL) CGDisplayModeRetain(pBest);
    CFRelease(pModes);

    if (pBest == NULL || CGDisplaySetDisplayMode(nDisplay, pBest, NULL) != kCGErrorSuccess)
    {
        if (pBest != NULL) CGDisplayModeRelease(pBest);
        CGDisplayModeRelease(pCurrent);
        DirectGate_Desktop_SetReason(pDesktop, "macOS rejected the requested display mode.");
        return XSTDERR;
    }

    CGDisplayModeRelease(pBest);

    if (!pDesktop->bDisplayModeChanged)
    {
        pDesktop->pOriginalDisplayMode = pCurrent;
        pDesktop->nModeNativeId = (uint64_t)nDisplay;
        xstrncpy(pDesktop->sModeMonitorId, sizeof(pDesktop->sModeMonitorId), pMonitor->sId);
    }
    else
    {
        CGDisplayModeRelease(pCurrent);
    }

    pDesktop->bDisplayModeChanged = XTRUE;
    DirectGate_Desktop_RefreshMacMonitors(pDesktop);
    return XSTDOK;
}

static void DirectGate_Desktop_RestoreDisplayMode(directgate_desktop_t *pDesktop)
{
    if (pDesktop == NULL || !pDesktop->bDisplayModeChanged ||
        pDesktop->pOriginalDisplayMode == NULL) return;

    CGDisplayModeRef pMode = (CGDisplayModeRef)pDesktop->pOriginalDisplayMode;
    (void)CGDisplaySetDisplayMode((CGDirectDisplayID)pDesktop->nModeNativeId, pMode, NULL);
    CGDisplayModeRelease(pMode);

    pDesktop->pOriginalDisplayMode = NULL;
    pDesktop->bDisplayModeChanged = XFALSE;
    pDesktop->nModeNativeId = 0U;
    DirectGate_Desktop_RefreshMacMonitors(pDesktop);
}

static int DirectGate_Desktop_SetFdNonBlocking(int nFd)
{
    int nFlags = fcntl(nFd, F_GETFL, 0);
    XCHECK((nFlags >= 0), XSTDERR);
    XCHECK((fcntl(nFd, F_SETFL, nFlags | O_NONBLOCK) == 0), XSTDERR);
    (void)fcntl(nFd, F_SETFD, FD_CLOEXEC);
    return XSTDOK;
}

static void* DirectGate_Desktop_TimerThread(void *pArg)
{
    directgate_desktop_t *pDesktop = (directgate_desktop_t*)pArg;
    uint32_t nFps = pDesktop->nFps ? pDesktop->nFps : DIRECTGATE_DESKTOP_DEFAULT_FPS;
    uint64_t nNs = 1000000000ULL / nFps;
    struct timespec delay;
    memset(&delay, 0, sizeof(delay));
    delay.tv_sec = (time_t)(nNs / 1000000000ULL);
    delay.tv_nsec = (long)(nNs % 1000000000ULL);

    while (pDesktop->bTimerThreadRunning)
    {
        nanosleep(&delay, NULL);
        if (!pDesktop->bTimerThreadRunning) break;
        if (pDesktop->nTimerWriteFd != XSOCK_INVALID)
        {
            const char cTick = 't';
            ssize_t nWrite = write(pDesktop->nTimerWriteFd, &cTick, sizeof(cTick));
            (void)nWrite;
        }
    }

    return NULL;
}

static int DirectGate_Desktop_StartTimer(directgate_desktop_t *pDesktop)
{
    int fds[2] = { XSOCK_INVALID, XSOCK_INVALID };
    if (pipe(fds) < 0)
    {
        DirectGate_Desktop_SetReason(pDesktop, "Failed to create macOS desktop frame pipe.");
        return XSTDERR;
    }

    if (DirectGate_Desktop_SetFdNonBlocking(fds[0]) < 0 ||
        DirectGate_Desktop_SetFdNonBlocking(fds[1]) < 0)
    {
        close(fds[0]);
        close(fds[1]);
        DirectGate_Desktop_SetReason(pDesktop, "Failed to configure macOS desktop frame pipe.");
        return XSTDERR;
    }

    pDesktop->nTimerFd = fds[0];
    pDesktop->nTimerWriteFd = fds[1];
    pDesktop->bTimerThreadRunning = XTRUE;

    if (pthread_create(&pDesktop->timerThread, NULL, DirectGate_Desktop_TimerThread, pDesktop) != 0)
    {
        pDesktop->bTimerThreadRunning = XFALSE;
        close(pDesktop->nTimerFd);
        close(pDesktop->nTimerWriteFd);
        pDesktop->nTimerFd = XSOCK_INVALID;
        pDesktop->nTimerWriteFd = XSOCK_INVALID;
        DirectGate_Desktop_SetReason(pDesktop, "Failed to start macOS desktop frame timer.");
        return XSTDERR;
    }

    return XSTDOK;
}

static int DirectGate_Desktop_SendFrameChunks(directgate_session_t *pSession, const uint8_t *pFrame, size_t nFrameSize)
{
    directgate_desktop_t *pDesktop = &pSession->desktop;
    uint32_t nChunks = (uint32_t)((nFrameSize + DIRECTGATE_DESKTOP_CHUNK_SIZE - 1U) / DIRECTGATE_DESKTOP_CHUNK_SIZE);
    uint64_t nFrameId = ++pDesktop->nFrameId;

    for (uint32_t i = 0; i < nChunks; i++)
    {
        size_t nOffset = (size_t)i * DIRECTGATE_DESKTOP_CHUNK_SIZE;
        size_t nChunk = nFrameSize - nOffset;
        if (nChunk > DIRECTGATE_DESKTOP_CHUNK_SIZE) nChunk = DIRECTGATE_DESKTOP_CHUNK_SIZE;

        xjson_obj_t *pHeader = DirectGate_Proto_BuildData(pSession->nSessionId);
        XCHECK((pHeader != NULL), XAPI_DISCONNECT);

        XJSON_AddString(pHeader, "payloadType", "desktop-frame-chunk");
        XJSON_AddU64(pHeader, "frameId", nFrameId);
        XJSON_AddU32(pHeader, "chunkIndex", i);
        XJSON_AddU32(pHeader, "chunks", nChunks);
        XJSON_AddU32(pHeader, "width", pDesktop->nFrameWidth);
        XJSON_AddU32(pHeader, "height", pDesktop->nFrameHeight);
        XJSON_AddU32(pHeader, "screenWidth", pDesktop->nCaptureWidth);
        XJSON_AddU32(pHeader, "screenHeight", pDesktop->nCaptureHeight);
        XJSON_AddString(pHeader, "monitorId", pDesktop->sSelectedMonitor);
        XJSON_AddString(pHeader, "encoding", "raw-rgba");

        int nStatus = DirectGate_Session_Send(pSession, pHeader, pFrame + nOffset, nChunk);
        XJSON_FreeObject(pHeader);
        if (nStatus < 0) return nStatus;
    }

    return XAPI_CONTINUE;
}

static int DirectGate_Desktop_CaptureFrameRaw(directgate_session_t *pSession)
{
    directgate_desktop_t *pDesktop = &pSession->desktop;
    XCHECK_NL((pDesktop->bCaptureReady), XAPI_CONTINUE);

    /* The Objective-C bridge uses ScreenCaptureKit on current macOS releases.
     * Keep the raw fallback here because it is also useful when H.264 setup
     * fails, but do not reference CoreGraphics' obsoleted capture API. */
    char sCaptureError[160] = {0};
    CGImageRef image = (CGImageRef)DirectGate_Desktop_MacCaptureImage(
        pDesktop->nCaptureX, pDesktop->nCaptureY,
        pDesktop->nCaptureWidth, pDesktop->nCaptureHeight,
        sCaptureError, sizeof(sCaptureError));
    if (image == NULL)
    {
        xlogw("Failed to capture macOS frame: sid(%u), reason(%s)",
            pSession->nSessionId, xstrused(sCaptureError) ? sCaptureError : "unknown");
        pDesktop->bCaptureReady = XFALSE;
        DirectGate_Desktop_SendStatus(pSession, "error",
            xstrused(sCaptureError) ? sCaptureError :
            "macOS screen capture failed. Grant Screen Recording permission to directgate and restart it.");
        return XAPI_CONTINUE;
    }

    size_t nSourceWidth = CGImageGetWidth(image);
    size_t nSourceHeight = CGImageGetHeight(image);
    if (nSourceWidth == 0 || nSourceHeight == 0 ||
        nSourceWidth > UINT32_MAX || nSourceHeight > UINT32_MAX)
    {
        CGImageRelease(image);
        return XAPI_CONTINUE;
    }

    uint32_t nFrameWidth = (uint32_t)nSourceWidth;
    uint32_t nFrameHeight = (uint32_t)nSourceHeight;
    DirectGate_Desktop_LimitFrameSize(pDesktop, &nFrameWidth, &nFrameHeight);

    size_t nFrameSize = (size_t)nFrameWidth * nFrameHeight * 4U;
    uint8_t *pFrame = (uint8_t*)calloc(1, nFrameSize);
    if (pFrame == NULL)
    {
        CGImageRelease(image);
        xloge("Failed to allocate macOS desktop frame: sid(%u), bytes(%zu)",
            pSession->nSessionId, nFrameSize);
        return XAPI_CONTINUE;
    }

    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    CGContextRef ctx = CGBitmapContextCreate(pFrame, nFrameWidth, nFrameHeight, 8,
        (size_t)nFrameWidth * 4U, colorSpace,
        kCGBitmapByteOrder32Big | kCGImageAlphaPremultipliedLast);
    if (ctx == NULL)
    {
        if (colorSpace != NULL) CGColorSpaceRelease(colorSpace);
        CGImageRelease(image);
        free(pFrame);
        return XAPI_CONTINUE;
    }

    CGContextDrawImage(ctx, CGRectMake(0, 0, (CGFloat)nFrameWidth, (CGFloat)nFrameHeight), image);

    pDesktop->nFrameWidth = nFrameWidth;
    pDesktop->nFrameHeight = nFrameHeight;

    CGContextRelease(ctx);
    if (colorSpace != NULL) CGColorSpaceRelease(colorSpace);
    CGImageRelease(image);

    int nStatus = DirectGate_Desktop_SendFrameChunks(pSession, pFrame, nFrameSize);
    free(pFrame);
    return nStatus;
}

static int DirectGate_Desktop_StartMacPipeline(directgate_session_t *pSession)
{
    directgate_desktop_t *pDesktop = &pSession->desktop;

    if (pDesktop->bForceRaw)
    {
        pDesktop->ePipeline = DIRECTGATE_DESKTOP_PIPELINE_RAW;
        xstrncpy(pDesktop->sCodec, sizeof(pDesktop->sCodec), "raw-rgba");
        DirectGate_Desktop_SetFallbackReason(pDesktop,
            "Raw RGBA forced by DIRECTGATE_DESKTOP_FORCE_RAW.");
        return XSTDOK;
    }

    if (DirectGate_Desktop_MacEncoder_Start(pSession,
        pDesktop->nCaptureX, pDesktop->nCaptureY,
        pDesktop->nCaptureWidth, pDesktop->nCaptureHeight) < 0)
    {
        const char *pErr = DirectGate_Desktop_MacEncoder_LastError(pSession);
        xlogw("macOS H.264 encoder unavailable, falling back to raw RGBA: sid(%u), reason(%s)",
            pSession->nSessionId, xstrused(pErr) ? pErr : "unknown");
        pDesktop->ePipeline = DIRECTGATE_DESKTOP_PIPELINE_RAW;
        xstrncpy(pDesktop->sCodec, sizeof(pDesktop->sCodec), "raw-rgba");
        pDesktop->bForceRaw = XTRUE;
        DirectGate_Desktop_SetFallbackReason(pDesktop,
            xstrused(pErr) ? pErr : "VideoToolbox H.264 encoder failed; using raw RGBA.");
        return XSTDOK;
    }

    xstrncpy(pDesktop->sCodec, sizeof(pDesktop->sCodec), "h264");
    if (!pDesktop->bWebRTCVideoFailed && DirectGate_WebRTC_IsVideoOpen(&pSession->webrtc))
    {
        pDesktop->ePipeline = DIRECTGATE_DESKTOP_PIPELINE_WEBRTC_VIDEO;
        DirectGate_Desktop_SetFallbackReason(pDesktop, NULL);
    }
    else
    {
        pDesktop->ePipeline = DIRECTGATE_DESKTOP_PIPELINE_H264_DC;
        DirectGate_Desktop_SetFallbackReason(pDesktop,
            "WebRTC video track is unavailable; using encrypted H.264 data channel.");
    }

    return XSTDOK;
}

static void DirectGate_Desktop_MaybePromoteWebRTCVideo(directgate_session_t *pSession)
{
    XCHECK_VOID_NL((pSession != NULL));
    directgate_desktop_t *pDesktop = &pSession->desktop;

    if (pDesktop->bForceRaw || pDesktop->bWebRTCVideoFailed)
        return;

    if (pDesktop->ePipeline != DIRECTGATE_DESKTOP_PIPELINE_H264_DC)
        return;

    if (!DirectGate_WebRTC_IsVideoOpen(&pSession->webrtc))
        return;

    pDesktop->ePipeline = DIRECTGATE_DESKTOP_PIPELINE_WEBRTC_VIDEO;
    DirectGate_Desktop_SetFallbackReason(pDesktop, NULL);
    DirectGate_Desktop_MacEncoder_RequestKeyframe(pSession);
    DirectGate_Desktop_SendStatus(pSession, "streaming", NULL);
}

int DirectGate_Desktop_Start(directgate_session_t *pSession)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    directgate_desktop_t *pDesktop = &pSession->desktop;

    if (pDesktop->bRunning)
        return XAPI_CONTINUE;

    DirectGate_Desktop_Clear(pDesktop);
    DirectGate_Desktop_Init(pDesktop);
    pDesktop->nSessionId = pSession->nSessionId;

    if (DirectGate_Desktop_OpenMacOS(pSession) < 0)
    {
        xlogw("Desktop mode unavailable: sid(%u), reason(%s)",
            pSession->nSessionId, DirectGate_Desktop_GetReason(pDesktop));
        DirectGate_Desktop_SendStatus(pSession, "error", DirectGate_Desktop_GetReason(pDesktop));
        DirectGate_Session_SendErrorMsg(pSession, DirectGate_Desktop_GetReason(pDesktop));
        return XSTDERR;
    }

    if (DirectGate_Desktop_StartTimer(pDesktop) < 0)
    {
        xlogw("Desktop timer failed: sid(%u), reason(%s)",
            pSession->nSessionId, DirectGate_Desktop_GetReason(pDesktop));
        DirectGate_Desktop_SendStatus(pSession, "error", DirectGate_Desktop_GetReason(pDesktop));
        DirectGate_Desktop_Clear(pDesktop);
        DirectGate_Session_SendErrorMsg(pSession, DirectGate_Desktop_GetReason(pDesktop));
        return XSTDERR;
    }

    pDesktop->bRunning = XTRUE;
    xlogi("Desktop mode activated: sid(%u), backend(%s), display(%s), screen(%ux%u), pipeline(%s), preset(%s), input(%s)",
        pSession->nSessionId, pDesktop->sBackend, pDesktop->sDisplay,
        pDesktop->nScreenWidth, pDesktop->nScreenHeight,
        DirectGate_Desktop_PipelineName(pDesktop->ePipeline),
        DirectGate_Desktop_PresetName(pDesktop->quality.ePreset),
        pDesktop->bInputReady ? "yes" : "no");

    return DirectGate_Desktop_SendStatus(pSession, "ready", NULL);
}

int DirectGate_Desktop_Process(directgate_session_t *pSession)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    directgate_desktop_t *pDesktop = &pSession->desktop;

    XCHECK_NL((pDesktop->bRunning), XAPI_CONTINUE);
    if (pDesktop->nTimerFd != XSOCK_INVALID)
    {
        char sBuf[128];
        while (read(pDesktop->nTimerFd, sBuf, sizeof(sBuf)) > 0) {}
    }

    /* The H.264 pipeline pushes frames from the SCK delegate; the timer
     * wake-up is just a signal to drain the encoder mailbox. The raw
     * path still pulls per tick. */
    if (pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_WEBRTC_VIDEO ||
        pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_H264_DC)
    {
        if (DirectGate_WebRTC_TakeVideoKeyframeRequest(&pSession->webrtc))
            DirectGate_Desktop_MacEncoder_RequestKeyframe(pSession);

        DirectGate_Desktop_MaybePromoteWebRTCVideo(pSession);
        DirectGate_Desktop_AdaptBitrate(pSession);
        return DirectGate_Desktop_MacEncoder_DrainMain(pSession);
    }

    return DirectGate_Desktop_CaptureFrameRaw(pSession);
}

static int DirectGate_Desktop_FrameToScreenX(const directgate_desktop_t *pDesktop, int nX)
{
    if (pDesktop->nFrameWidth <= 1) return pDesktop->nCaptureX;
    if (nX < 0) nX = 0;
    if ((uint32_t)nX >= pDesktop->nFrameWidth) nX = (int)pDesktop->nFrameWidth - 1;
    return pDesktop->nCaptureX +
        (int)(((uint64_t)(uint32_t)nX * pDesktop->nCaptureWidth) / pDesktop->nFrameWidth);
}

static int DirectGate_Desktop_FrameToScreenY(const directgate_desktop_t *pDesktop, int nY)
{
    if (pDesktop->nFrameHeight <= 1) return pDesktop->nCaptureY;
    if (nY < 0) nY = 0;
    if ((uint32_t)nY >= pDesktop->nFrameHeight) nY = (int)pDesktop->nFrameHeight - 1;
    return pDesktop->nCaptureY +
        (int)(((uint64_t)(uint32_t)nY * pDesktop->nCaptureHeight) / pDesktop->nFrameHeight);
}

static CGEventType DirectGate_Desktop_MacMouseEvent(uint32_t nButton, xbool_t bDown)
{
    if (nButton == 3) return bDown ? kCGEventRightMouseDown : kCGEventRightMouseUp;
    if (nButton == 2) return bDown ? kCGEventOtherMouseDown : kCGEventOtherMouseUp;
    return bDown ? kCGEventLeftMouseDown : kCGEventLeftMouseUp;
}

static CGEventType DirectGate_Desktop_MacDragEvent(uint32_t nButtons)
{
    if (nButtons & (1U << 2U)) return kCGEventRightMouseDragged;
    if (nButtons & (1U << 1U)) return kCGEventOtherMouseDragged;
    if (nButtons & 1U) return kCGEventLeftMouseDragged;
    return kCGEventMouseMoved;
}

static CGMouseButton DirectGate_Desktop_MacMouseButton(uint32_t nButton)
{
    if (nButton == 3) return kCGMouseButtonRight;
    if (nButton == 2) return kCGMouseButtonCenter;
    return kCGMouseButtonLeft;
}

typedef struct directgate_mac_key_ {
    const char *pCode;
    CGKeyCode nKeyCode;
} directgate_mac_key_t;

static const directgate_mac_key_t g_MacKeys[] = {
    { "KeyA", kVK_ANSI_A }, { "KeyB", kVK_ANSI_B }, { "KeyC", kVK_ANSI_C },
    { "KeyD", kVK_ANSI_D }, { "KeyE", kVK_ANSI_E }, { "KeyF", kVK_ANSI_F },
    { "KeyG", kVK_ANSI_G }, { "KeyH", kVK_ANSI_H }, { "KeyI", kVK_ANSI_I },
    { "KeyJ", kVK_ANSI_J }, { "KeyK", kVK_ANSI_K }, { "KeyL", kVK_ANSI_L },
    { "KeyM", kVK_ANSI_M }, { "KeyN", kVK_ANSI_N }, { "KeyO", kVK_ANSI_O },
    { "KeyP", kVK_ANSI_P }, { "KeyQ", kVK_ANSI_Q }, { "KeyR", kVK_ANSI_R },
    { "KeyS", kVK_ANSI_S }, { "KeyT", kVK_ANSI_T }, { "KeyU", kVK_ANSI_U },
    { "KeyV", kVK_ANSI_V }, { "KeyW", kVK_ANSI_W }, { "KeyX", kVK_ANSI_X },
    { "KeyY", kVK_ANSI_Y }, { "KeyZ", kVK_ANSI_Z },
    { "Digit0", kVK_ANSI_0 }, { "Digit1", kVK_ANSI_1 }, { "Digit2", kVK_ANSI_2 },
    { "Digit3", kVK_ANSI_3 }, { "Digit4", kVK_ANSI_4 }, { "Digit5", kVK_ANSI_5 },
    { "Digit6", kVK_ANSI_6 }, { "Digit7", kVK_ANSI_7 }, { "Digit8", kVK_ANSI_8 },
    { "Digit9", kVK_ANSI_9 },
    { "Backquote", kVK_ANSI_Grave }, { "Minus", kVK_ANSI_Minus },
    { "Equal", kVK_ANSI_Equal }, { "BracketLeft", kVK_ANSI_LeftBracket },
    { "BracketRight", kVK_ANSI_RightBracket }, { "Backslash", kVK_ANSI_Backslash },
    { "Semicolon", kVK_ANSI_Semicolon }, { "Quote", kVK_ANSI_Quote },
    { "Comma", kVK_ANSI_Comma }, { "Period", kVK_ANSI_Period },
    { "Slash", kVK_ANSI_Slash },
    { "Enter", kVK_Return }, { "NumpadEnter", kVK_Return },
    { "Backspace", kVK_Delete }, { "Delete", kVK_ForwardDelete },
    { "Tab", kVK_Tab }, { "Escape", kVK_Escape }, { "Space", kVK_Space },
    { "ArrowLeft", kVK_LeftArrow }, { "ArrowRight", kVK_RightArrow },
    { "ArrowUp", kVK_UpArrow }, { "ArrowDown", kVK_DownArrow },
    { "Home", kVK_Home }, { "End", kVK_End },
    { "PageUp", kVK_PageUp }, { "PageDown", kVK_PageDown },
    { "ShiftLeft", kVK_Shift }, { "ShiftRight", kVK_RightShift },
    { "ControlLeft", kVK_Control }, { "ControlRight", kVK_RightControl },
    { "AltLeft", kVK_Option }, { "AltRight", kVK_RightOption },
    { "MetaLeft", kVK_Command }, { "MetaRight", kVK_Command },
    { "F1", kVK_F1 }, { "F2", kVK_F2 }, { "F3", kVK_F3 }, { "F4", kVK_F4 },
    { "F5", kVK_F5 }, { "F6", kVK_F6 }, { "F7", kVK_F7 }, { "F8", kVK_F8 },
    { "F9", kVK_F9 }, { "F10", kVK_F10 }, { "F11", kVK_F11 }, { "F12", kVK_F12 },
};

static CGKeyCode DirectGate_Desktop_MacKeyCodeFromJson(xjson_obj_t *pRoot, xbool_t *pFound)
{
    const char *pCode = XJSON_GetString(XJSON_GetObject(pRoot, "code"));
    const char *pKey = XJSON_GetString(XJSON_GetObject(pRoot, "key"));
    *pFound = XFALSE;

    if (xstrused(pCode))
    {
        for (size_t i = 0; i < sizeof(g_MacKeys) / sizeof(g_MacKeys[0]); i++)
        {
            if (xstrcmp(g_MacKeys[i].pCode, pCode))
            {
                *pFound = XTRUE;
                return g_MacKeys[i].nKeyCode;
            }
        }
    }

    if (xstrused(pKey))
    {
        if (xstrcmp(pKey, "Enter")) { *pFound = XTRUE; return kVK_Return; }
        if (xstrcmp(pKey, "Backspace")) { *pFound = XTRUE; return kVK_Delete; }
        if (xstrcmp(pKey, "Tab")) { *pFound = XTRUE; return kVK_Tab; }
        if (xstrcmp(pKey, "Escape")) { *pFound = XTRUE; return kVK_Escape; }
        if (xstrcmp(pKey, "Delete")) { *pFound = XTRUE; return kVK_ForwardDelete; }
        if (xstrcmp(pKey, "Home")) { *pFound = XTRUE; return kVK_Home; }
        if (xstrcmp(pKey, "End")) { *pFound = XTRUE; return kVK_End; }
        if (xstrcmp(pKey, "PageUp")) { *pFound = XTRUE; return kVK_PageUp; }
        if (xstrcmp(pKey, "PageDown")) { *pFound = XTRUE; return kVK_PageDown; }
        if (xstrcmp(pKey, "ArrowLeft")) { *pFound = XTRUE; return kVK_LeftArrow; }
        if (xstrcmp(pKey, "ArrowRight")) { *pFound = XTRUE; return kVK_RightArrow; }
        if (xstrcmp(pKey, "ArrowUp")) { *pFound = XTRUE; return kVK_UpArrow; }
        if (xstrcmp(pKey, "ArrowDown")) { *pFound = XTRUE; return kVK_DownArrow; }
        if (xstrcmp(pKey, " ")) { *pFound = XTRUE; return kVK_Space; }
    }

    return 0;
}

int DirectGate_Desktop_HandleInput(directgate_session_t *pSession, const uint8_t *pPayload, size_t nPayloadLength)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    directgate_desktop_t *pDesktop = &pSession->desktop;

    if (!pDesktop->bRunning || !pDesktop->bInputReady)
        return XAPI_CONTINUE;

    if (pPayload == NULL || !nPayloadLength)
        return XAPI_CONTINUE;

    char *pJsonText = (char*)calloc(1, nPayloadLength + 1U);
    XCHECK((pJsonText != NULL), XAPI_CONTINUE);
    memcpy(pJsonText, pPayload, nPayloadLength);

    xjson_t json;
    if (!XJSON_Parse(&json, NULL, pJsonText, nPayloadLength))
    {
        free(pJsonText);
        return XAPI_CONTINUE;
    }

    xjson_obj_t *pRoot = json.pRootObj;
    const char *pAction = XJSON_GetString(XJSON_GetObject(pRoot, "action"));
    const char *pEvent = XJSON_GetString(XJSON_GetObject(pRoot, "event"));

    if (xstrcmp(pAction, "pointer"))
    {
        int nX = XJSON_GetInt(XJSON_GetObject(pRoot, "x"));
        int nY = XJSON_GetInt(XJSON_GetObject(pRoot, "y"));
        CGPoint point = CGPointMake((CGFloat)DirectGate_Desktop_FrameToScreenX(pDesktop, nX),
            (CGFloat)DirectGate_Desktop_FrameToScreenY(pDesktop, nY));

        if (xstrcmp(pEvent, "button"))
        {
            uint32_t nButton = XJSON_GetU32(XJSON_GetObject(pRoot, "button"));
            xbool_t bDown = XJSON_GetBool(XJSON_GetObject(pRoot, "down"));
            if (nButton >= 1 && nButton <= 3)
            {
                if (bDown) pDesktop->nPointerButtons |= (1U << (nButton - 1U));
                else pDesktop->nPointerButtons &= ~(1U << (nButton - 1U));

                CGEventRef event = CGEventCreateMouseEvent(NULL,
                    DirectGate_Desktop_MacMouseEvent(nButton, bDown),
                    point, DirectGate_Desktop_MacMouseButton(nButton));
                if (event != NULL)
                {
                    CGEventPost(kCGHIDEventTap, event);
                    CFRelease(event);
                }
            }
        }
        else if (xstrcmp(pEvent, "wheel"))
        {
            int nDeltaY = XJSON_GetInt(XJSON_GetObject(pRoot, "deltaY"));
            CGEventRef event = CGEventCreateScrollWheelEvent(NULL,
                kCGScrollEventUnitPixel, 1, -nDeltaY);
            if (event != NULL)
            {
                CGEventPost(kCGHIDEventTap, event);
                CFRelease(event);
            }
        }
        else
        {
            CGEventRef event = CGEventCreateMouseEvent(NULL,
                DirectGate_Desktop_MacDragEvent(pDesktop->nPointerButtons),
                point, DirectGate_Desktop_MacMouseButton(1));
            if (event != NULL)
            {
                CGEventPost(kCGHIDEventTap, event);
                CFRelease(event);
            }
        }
    }
    else if (xstrcmp(pAction, "key"))
    {
        xbool_t bFound = XFALSE;
        CGKeyCode keyCode = DirectGate_Desktop_MacKeyCodeFromJson(pRoot, &bFound);
        if (bFound)
        {
            xbool_t bDown = XJSON_GetBool(XJSON_GetObject(pRoot, "down"));
            CGEventRef event = CGEventCreateKeyboardEvent(NULL, keyCode, bDown ? true : false);
            if (event != NULL)
            {
                CGEventPost(kCGHIDEventTap, event);
                CFRelease(event);
            }
        }
    }

    XJSON_Destroy(&json);
    free(pJsonText);
    return XAPI_CONTINUE;
}

int DirectGate_Desktop_HandleControl(directgate_session_t *pSession, const uint8_t *pPayload, size_t nPayloadLength)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    directgate_desktop_t *pDesktop = &pSession->desktop;

    if (!pDesktop->bRunning || pPayload == NULL || !nPayloadLength)
        return XAPI_CONTINUE;

    char *pJsonText = (char*)calloc(1, nPayloadLength + 1U);
    XCHECK((pJsonText != NULL), XAPI_CONTINUE);
    memcpy(pJsonText, pPayload, nPayloadLength);

    xjson_t json;
    if (!XJSON_Parse(&json, NULL, pJsonText, nPayloadLength))
    {
        free(pJsonText);
        return XAPI_CONTINUE;
    }

    xjson_obj_t *pRoot = json.pRootObj;
    const char *pAction = XJSON_GetString(XJSON_GetObject(pRoot, "action"));
    const char *pMonitorId = XJSON_GetString(XJSON_GetObject(pRoot, "monitorId"));

    if (xstrcmp(pAction, "select-monitor") && xstrused(pMonitorId))
    {
        DirectGate_Desktop_ReadResizeRequest(pDesktop, pRoot);
        const directgate_desktop_monitor_t *pSelected = NULL;
        for (uint32_t i = 0; i < pDesktop->nMonitorCount; i++)
        {
            if (xstrcmp(pDesktop->monitors[i].sId, pMonitorId))
            {
                pSelected = &pDesktop->monitors[i];
                break;
            }
        }

        if (pSelected != NULL)
        {
            char sSelectedId[DIRECTGATE_DESKTOP_MONITOR_ID_LEN];
            xstrncpy(sSelectedId, sizeof(sSelectedId), pSelected->sId);
            const char *pResizeReason = NULL;

            if (pDesktop->eResizeMode == DIRECTGATE_DESKTOP_RESIZE_DISPLAY &&
                DirectGate_Desktop_SetDisplayResolution(pDesktop, pSelected,
                    pDesktop->nTargetWidth, pDesktop->nTargetHeight) != XSTDOK)
            {
                pResizeReason = DirectGate_Desktop_GetReason(pDesktop);
                pDesktop->eResizeMode = DIRECTGATE_DESKTOP_RESIZE_SCALE;
            }

            pSelected = DirectGate_Desktop_FindMonitor(pDesktop, sSelectedId);
            if (pSelected == NULL)
            {
                DirectGate_Desktop_SendStatus(pSession, "error",
                    "Selected display disappeared after its display mode changed.");
                XJSON_Destroy(&json);
                free(pJsonText);
                return XAPI_CONTINUE;
            }

            DirectGate_Desktop_SetCapture(pDesktop, pSelected->sId, pSelected->nX,
                pSelected->nY, pSelected->nWidth, pSelected->nHeight);

            if (DirectGate_Desktop_StartMacPipeline(pSession) < 0)
            {
                XJSON_Destroy(&json);
                free(pJsonText);

                DirectGate_Desktop_SendStatus(pSession, "error", "Failed to start desktop pipeline.");
                return XAPI_CONTINUE;
            }

            DirectGate_Desktop_SendStatus(pSession, "streaming", pResizeReason);
            xlogi("Desktop monitor selected: sid(%u), monitor(%s), rect(%d,%d %ux%u), pipeline(%s), preset(%s)",
                pSession->nSessionId, pSelected->sId, pSelected->nX, pSelected->nY,
                pSelected->nWidth, pSelected->nHeight,
                DirectGate_Desktop_PipelineName(pDesktop->ePipeline),
                DirectGate_Desktop_PresetName(pDesktop->quality.ePreset));
        }
        else
        {
            DirectGate_Desktop_SendStatus(pSession, "error", "Selected display is not available.");
        }
    }
    else if (xstrcmp(pAction, "set-resolution"))
    {
        directgate_desktop_resize_mode_t ePreviousMode = pDesktop->eResizeMode;
        DirectGate_Desktop_ReadResizeRequest(pDesktop, pRoot);
        char sSelectedId[DIRECTGATE_DESKTOP_MONITOR_ID_LEN];
        xstrncpy(sSelectedId, sizeof(sSelectedId), pDesktop->sSelectedMonitor);
        const directgate_desktop_monitor_t *pSelected = DirectGate_Desktop_FindMonitor(pDesktop, sSelectedId);
        const char *pResizeReason = NULL;
        xbool_t bCaptureChanged = XFALSE;

        if (pDesktop->bCaptureReady && ePreviousMode == DIRECTGATE_DESKTOP_RESIZE_DISPLAY &&
            pDesktop->eResizeMode == DIRECTGATE_DESKTOP_RESIZE_SCALE)
        {
            DirectGate_Desktop_MacEncoder_Stop(pSession);
            DirectGate_Desktop_RestoreDisplayMode(pDesktop);
            pSelected = DirectGate_Desktop_FindMonitor(pDesktop, sSelectedId);
            bCaptureChanged = XTRUE;
        }
        else if (pDesktop->bCaptureReady &&
            pDesktop->eResizeMode == DIRECTGATE_DESKTOP_RESIZE_DISPLAY)
        {
            DirectGate_Desktop_MacEncoder_Stop(pSession);
            if (DirectGate_Desktop_SetDisplayResolution(pDesktop, pSelected,
                pDesktop->nTargetWidth, pDesktop->nTargetHeight) != XSTDOK)
            {
                pResizeReason = DirectGate_Desktop_GetReason(pDesktop);
                if (!pDesktop->bDisplayModeChanged)
                    pDesktop->eResizeMode = DIRECTGATE_DESKTOP_RESIZE_SCALE;
            }

            pSelected = DirectGate_Desktop_FindMonitor(pDesktop, sSelectedId);
            bCaptureChanged = XTRUE;
        }

        if (pDesktop->bCaptureReady && pSelected != NULL && bCaptureChanged)
        {
            DirectGate_Desktop_SetCapture(pDesktop, pSelected->sId, pSelected->nX,
                pSelected->nY, pSelected->nWidth, pSelected->nHeight);
            (void)DirectGate_Desktop_StartMacPipeline(pSession);
        }
        else if (pDesktop->bCaptureReady &&
            (pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_WEBRTC_VIDEO ||
             pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_H264_DC))
            DirectGate_Desktop_MacEncoder_ApplyQuality(pSession);
        else if (pDesktop->bCaptureReady)
            DirectGate_Desktop_ComputeFrameSize(pDesktop);

        DirectGate_Desktop_SendStatus(pSession,
            pDesktop->bCaptureReady ? "streaming" : "ready", pResizeReason);
    }
    else if (xstrcmp(pAction, "set-preset"))
    {
        const char *pPreset = XJSON_GetString(XJSON_GetObject(pRoot, "preset"));
        directgate_desktop_preset_t eNext = pDesktop->quality.ePreset;
        if (xstrcmp(pPreset, "quality")) eNext = DIRECTGATE_DESKTOP_PRESET_QUALITY;
        else if (xstrcmp(pPreset, "low-latency")) eNext = DIRECTGATE_DESKTOP_PRESET_LOW_LATENCY;
        else if (xstrcmp(pPreset, "balanced")) eNext = DIRECTGATE_DESKTOP_PRESET_BALANCED;

        DirectGate_Desktop_ApplyPreset(pDesktop, eNext);
        if (pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_WEBRTC_VIDEO ||
            pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_H264_DC)
        {
            DirectGate_Desktop_MacEncoder_ApplyQuality(pSession);

            /* A max-edge change rebuilds the encoder; when that rebuild
             * fails the encoder is gone, so demote to raw RGBA instead of
             * leaving a silently frozen stream. */
            if (pDesktop->pEncoder == NULL)
            {
                const char *pErr = DirectGate_Desktop_MacEncoder_LastError(pSession);
                xlogw("macOS H.264 encoder rebuild failed, falling back to raw RGBA: sid(%u), reason(%s)",
                    pSession->nSessionId, xstrused(pErr) ? pErr : "unknown");

                pDesktop->ePipeline = DIRECTGATE_DESKTOP_PIPELINE_RAW;
                pDesktop->bForceRaw = XTRUE;

                xstrncpy(pDesktop->sCodec, sizeof(pDesktop->sCodec), "raw-rgba");
                DirectGate_Desktop_SetFallbackReason(pDesktop,
                    xstrused(pErr) ? pErr : "VideoToolbox H.264 encoder rebuild failed; using raw RGBA.");
            }
        }

        DirectGate_Desktop_SendStatus(pSession, "streaming", NULL);
        xlogi("Desktop preset updated: sid(%u), preset(%s), fps(%u), bitrate(%u kbps)",
            pSession->nSessionId,
            DirectGate_Desktop_PresetName(pDesktop->quality.ePreset),
            pDesktop->quality.nFps, pDesktop->quality.nBitrateKbps);
    }
    else if (xstrcmp(pAction, "request-keyframe"))
    {
        if (pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_WEBRTC_VIDEO ||
            pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_H264_DC)
            DirectGate_Desktop_MacEncoder_RequestKeyframe(pSession);
    }

    XJSON_Destroy(&json);
    free(pJsonText);
    return XAPI_CONTINUE;
}

#elif defined(_WIN32)

static void DirectGate_Desktop_ComputeFrameSize(directgate_desktop_t *pDesktop)
{
    uint32_t nWidth = pDesktop->nCaptureWidth ? pDesktop->nCaptureWidth : pDesktop->nScreenWidth;
    uint32_t nHeight = pDesktop->nCaptureHeight ? pDesktop->nCaptureHeight : pDesktop->nScreenHeight;

    if (!nWidth) nWidth = 1;
    if (!nHeight) nHeight = 1;
    DirectGate_Desktop_LimitFrameSize(pDesktop, &nWidth, &nHeight);

    pDesktop->nFrameWidth = nWidth;
    pDesktop->nFrameHeight = nHeight;
}

static void DirectGate_Desktop_SetCapture(directgate_desktop_t *pDesktop,
                                      const char *pMonitorId,
                                      int32_t nX,
                                      int32_t nY,
                                      uint32_t nWidth,
                                      uint32_t nHeight)
{
    XCHECK_VOID_NL((pDesktop != NULL));

    pDesktop->nCaptureX = nX;
    pDesktop->nCaptureY = nY;
    pDesktop->nCaptureWidth = nWidth ? nWidth : pDesktop->nScreenWidth;
    pDesktop->nCaptureHeight = nHeight ? nHeight : pDesktop->nScreenHeight;
    xstrncpy(pDesktop->sSelectedMonitor, sizeof(pDesktop->sSelectedMonitor),
        xstrused(pMonitorId) ? pMonitorId : "all");
    pDesktop->bCaptureReady = XTRUE;
    DirectGate_Desktop_ComputeFrameSize(pDesktop);
}

static void DirectGate_Desktop_AddMonitor(directgate_desktop_t *pDesktop,
                                      const char *pId,
                                      const char *pName,
                                      int32_t nX,
                                      int32_t nY,
                                      uint32_t nWidth,
                                      uint32_t nHeight,
                                      xbool_t bPrimary)
{
    XCHECK_VOID_NL((pDesktop != NULL));
    XCHECK_VOID_NL((pDesktop->nMonitorCount < DIRECTGATE_DESKTOP_MAX_MONITORS));
    XCHECK_VOID_NL((nWidth > 0 && nHeight > 0));

    directgate_desktop_monitor_t *pMonitor = &pDesktop->monitors[pDesktop->nMonitorCount++];
    xstrncpy(pMonitor->sId, sizeof(pMonitor->sId), xstrused(pId) ? pId : "display");
    xstrncpy(pMonitor->sName, sizeof(pMonitor->sName), xstrused(pName) ? pName : pMonitor->sId);
    pMonitor->nX = nX;
    pMonitor->nY = nY;
    pMonitor->nWidth = nWidth;
    pMonitor->nHeight = nHeight;
    pMonitor->bPrimary = bPrimary;
}

static BOOL CALLBACK DirectGate_Desktop_MonitorEnumProc(HMONITOR hMonitor, HDC hDC,
                                                    LPRECT pRect, LPARAM lParam)
{
    (void)hDC;
    (void)pRect;
    directgate_desktop_t *pDesktop = (directgate_desktop_t*)lParam;

    MONITORINFOEXA info;
    memset(&info, 0, sizeof(info));
    info.cbSize = sizeof(info);
    if (!GetMonitorInfoA(hMonitor, (LPMONITORINFO)&info)) return TRUE;

    char sId[DIRECTGATE_DESKTOP_MONITOR_ID_LEN];
    char sName[DIRECTGATE_DESKTOP_MONITOR_NAME_LEN];
    uint32_t nIndex = pDesktop->nMonitorCount; /* slot 0 is "all" */
    snprintf(sId, sizeof(sId), "display-%u", nIndex);
    snprintf(sName, sizeof(sName), "Display %u", nIndex);

    DirectGate_Desktop_AddMonitor(pDesktop, sId, sName,
        (int32_t)info.rcMonitor.left, (int32_t)info.rcMonitor.top,
        (uint32_t)(info.rcMonitor.right - info.rcMonitor.left),
        (uint32_t)(info.rcMonitor.bottom - info.rcMonitor.top),
        (info.dwFlags & MONITORINFOF_PRIMARY) ? XTRUE : XFALSE);

    directgate_desktop_monitor_t *pAdded =
        &pDesktop->monitors[pDesktop->nMonitorCount - 1U];
    xstrncpy(pAdded->sDeviceId, sizeof(pAdded->sDeviceId), info.szDevice);
    pAdded->nNativeId = (uint64_t)(uintptr_t)hMonitor;

    return (pDesktop->nMonitorCount < DIRECTGATE_DESKTOP_MAX_MONITORS) ? TRUE : FALSE;
}

static void DirectGate_Desktop_RefreshWindowsMonitors(directgate_desktop_t *pDesktop)
{
    int32_t nVirtualX = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int32_t nVirtualY = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int32_t nVirtualWidth = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int32_t nVirtualHeight = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    if (nVirtualWidth <= 0 || nVirtualHeight <= 0) return;

    pDesktop->nScreenWidth = (uint32_t)nVirtualWidth;
    pDesktop->nScreenHeight = (uint32_t)nVirtualHeight;
    pDesktop->nMonitorCount = 0;
    memset(pDesktop->monitors, 0, sizeof(pDesktop->monitors));

    DirectGate_Desktop_AddMonitor(pDesktop, "all", "All displays", nVirtualX, nVirtualY,
        (uint32_t)nVirtualWidth, (uint32_t)nVirtualHeight, XFALSE);
    EnumDisplayMonitors(NULL, NULL, DirectGate_Desktop_MonitorEnumProc, (LPARAM)pDesktop);
}

static const directgate_desktop_monitor_t* DirectGate_Desktop_FindMonitor(
    const directgate_desktop_t *pDesktop, const char *pMonitorId)
{
    if (pDesktop == NULL || !xstrused(pMonitorId)) return NULL;
    for (uint32_t i = 0; i < pDesktop->nMonitorCount; i++)
        if (xstrcmp(pDesktop->monitors[i].sId, pMonitorId))
            return &pDesktop->monitors[i];
    return NULL;
}

static int DirectGate_Desktop_SetDisplayResolution(directgate_desktop_t *pDesktop,
                                                   const directgate_desktop_monitor_t *pMonitor,
                                                   uint32_t nWidth, uint32_t nHeight)
{
    if (pMonitor == NULL || !xstrused(pMonitor->sDeviceId))
    {
        DirectGate_Desktop_SetReason(pDesktop,
            "Display mode requires one physical monitor; All displays cannot be resized.");
        return XSTDERR;
    }

    DEVMODEA current;
    memset(&current, 0, sizeof(current));
    current.dmSize = sizeof(current);
    if (!EnumDisplaySettingsExA(pMonitor->sDeviceId, ENUM_CURRENT_SETTINGS, &current, 0))
    {
        DirectGate_Desktop_SetReason(pDesktop, "Failed to read the current Windows display mode.");
        return XSTDERR;
    }

    DEVMODEA best;
    memset(&best, 0, sizeof(best));
    uint64_t nBestScore = UINT64_MAX;
    for (DWORD i = 0;; i++)
    {
        DEVMODEA candidate;
        memset(&candidate, 0, sizeof(candidate));
        candidate.dmSize = sizeof(candidate);

        if (!EnumDisplaySettingsExA(pMonitor->sDeviceId, i, &candidate, 0)) break;
        if (candidate.dmBitsPerPel != current.dmBitsPerPel) continue;

        uint64_t nDx = candidate.dmPelsWidth > nWidth ? candidate.dmPelsWidth - nWidth : nWidth - candidate.dmPelsWidth;
        uint64_t nDy = candidate.dmPelsHeight > nHeight ? candidate.dmPelsHeight - nHeight : nHeight - candidate.dmPelsHeight;
        uint64_t nAspect = (uint64_t)llabs((long long)candidate.dmPelsWidth * nHeight - (long long)nWidth * candidate.dmPelsHeight);
        uint64_t nScore = (nDx + nDy) * 1000000ULL + nAspect;

        if (nScore < nBestScore)
        {
            nBestScore = nScore;
            best = candidate;
        }
    }
    if (nBestScore == UINT64_MAX)
    {
        DirectGate_Desktop_SetReason(pDesktop, "No usable Windows display mode is available.");
        return XSTDERR;
    }

    if (!pDesktop->bDisplayModeChanged)
    {
        xstrncpy(pDesktop->sModeMonitorId, sizeof(pDesktop->sModeMonitorId), pMonitor->sId);
        xstrncpy(pDesktop->sModeDeviceId, sizeof(pDesktop->sModeDeviceId), pMonitor->sDeviceId);
        pDesktop->nOriginalModeX = current.dmPosition.x;
        pDesktop->nOriginalModeY = current.dmPosition.y;
        pDesktop->nOriginalModeWidth = current.dmPelsWidth;
        pDesktop->nOriginalModeHeight = current.dmPelsHeight;
        pDesktop->nOriginalModeRefresh = current.dmDisplayFrequency;
        pDesktop->nOriginalModeRotation = current.dmDisplayOrientation;
        pDesktop->nOriginalModeId = current.dmBitsPerPel;
    }

    LONG nResult = ChangeDisplaySettingsExA(pMonitor->sDeviceId, &best, NULL, CDS_FULLSCREEN, NULL);
    if (nResult != DISP_CHANGE_SUCCESSFUL)
    {
        DirectGate_Desktop_SetReason(pDesktop, "Windows rejected the requested display mode.");
        return XSTDERR;
    }

    pDesktop->bDisplayModeChanged = XTRUE;
    DirectGate_Desktop_RefreshWindowsMonitors(pDesktop);
    return XSTDOK;
}

static void DirectGate_Desktop_RestoreDisplayMode(directgate_desktop_t *pDesktop)
{
    if (pDesktop == NULL || !pDesktop->bDisplayModeChanged ||
        !xstrused(pDesktop->sModeDeviceId)) return;

    DEVMODEA mode;
    memset(&mode, 0, sizeof(mode));
    mode.dmSize = sizeof(mode);
    mode.dmFields = DM_POSITION | DM_PELSWIDTH | DM_PELSHEIGHT |
        DM_BITSPERPEL | DM_DISPLAYFREQUENCY | DM_DISPLAYORIENTATION;
    mode.dmPosition.x = pDesktop->nOriginalModeX;
    mode.dmPosition.y = pDesktop->nOriginalModeY;
    mode.dmPelsWidth = pDesktop->nOriginalModeWidth;
    mode.dmPelsHeight = pDesktop->nOriginalModeHeight;
    mode.dmBitsPerPel = (DWORD)pDesktop->nOriginalModeId;
    mode.dmDisplayFrequency = pDesktop->nOriginalModeRefresh;
    mode.dmDisplayOrientation = pDesktop->nOriginalModeRotation;
    (void)ChangeDisplaySettingsExA(pDesktop->sModeDeviceId, &mode, NULL, CDS_FULLSCREEN, NULL);
    pDesktop->bDisplayModeChanged = XFALSE;
    pDesktop->sModeDeviceId[0] = '\0';
    DirectGate_Desktop_RefreshWindowsMonitors(pDesktop);
}

/* Physical-pixel coordinates everywhere: without per-monitor DPI awareness
 * Windows virtualizes GetSystemMetrics/monitor rects on scaled displays and
 * the capture rectangle no longer matches what duplication/BitBlt return.
 * Resolved dynamically - the API needs Win10 1703+ and may already have
 * been applied by the application manifest. */
typedef BOOL (WINAPI *directgate_dpi_context_fn)(DPI_AWARENESS_CONTEXT);

static void DirectGate_Desktop_EnableDpiAwareness(void)
{
    HMODULE hUser32 = GetModuleHandleW(L"user32.dll");
    if (hUser32 != NULL)
    {
        directgate_dpi_context_fn setContext = (directgate_dpi_context_fn)(void*)
            GetProcAddress(hUser32, "SetProcessDpiAwarenessContext");
        if (setContext != NULL &&
            setContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)) return;
    }

    SetProcessDPIAware();
}

static int DirectGate_Desktop_OpenWindows(directgate_session_t *pSession)
{
    directgate_desktop_t *pDesktop = &pSession->desktop;
    DirectGate_Desktop_EnableDpiAwareness();

    int32_t nVirtualX = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int32_t nVirtualY = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int32_t nVirtualWidth = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int32_t nVirtualHeight = GetSystemMetrics(SM_CYVIRTUALSCREEN);

    xstrncpy(pDesktop->sBackend, sizeof(pDesktop->sBackend), "windows");
    if (nVirtualWidth <= 0 || nVirtualHeight <= 0)
    {
        DirectGate_Desktop_SetReason(pDesktop,
            "No interactive desktop session is available for the agent process. "
            "Desktop streaming requires a logged-on user session.");
        return XSTDERR;
    }

    /* Informational only: the name of the desktop this process runs on
     * (normally "Default" in the interactive window station). */
    char sDesktopName[64] = { 0 };
    DWORD nNameLen = 0;
    HDESK hDesktop = GetThreadDesktop(GetCurrentThreadId());
    if (hDesktop == NULL ||
        !GetUserObjectInformationA(hDesktop, UOI_NAME, sDesktopName, sizeof(sDesktopName), &nNameLen) ||
        !xstrused(sDesktopName))
        xstrncpy(sDesktopName, sizeof(sDesktopName), "Default");
    xstrncpy(pDesktop->sDisplay, sizeof(pDesktop->sDisplay), sDesktopName);

    pDesktop->nScreenWidth = (uint32_t)nVirtualWidth;
    pDesktop->nScreenHeight = (uint32_t)nVirtualHeight;

    DirectGate_Desktop_AddMonitor(pDesktop, "all", "All displays",
        nVirtualX, nVirtualY, (uint32_t)nVirtualWidth, (uint32_t)nVirtualHeight, XFALSE);
    EnumDisplayMonitors(NULL, NULL, DirectGate_Desktop_MonitorEnumProc, (LPARAM)pDesktop);

    /* SendInput works on the interactive desktop the launcher started the
     * agent in; there is no runtime permission to probe (unlike macOS). */
    pDesktop->bInputReady = XTRUE;
    return XSTDOK;
}

static DWORD WINAPI DirectGate_Desktop_TimerThread(LPVOID pArg)
{
    directgate_desktop_t *pDesktop = (directgate_desktop_t*)pArg;
    uint32_t nFps = pDesktop->nFps ? pDesktop->nFps : DIRECTGATE_DESKTOP_DEFAULT_FPS;
    DWORD nDelayMs = 1000U / nFps;
    if (!nDelayMs) nDelayMs = 1U;

    /* Sleep granularity (~16 ms) is fine here: on the H.264 pipeline these
     * ticks only drive the bitrate controller and drain fallback (frames
     * wake the loop straight from the capture thread), and the raw path is
     * a fallback anyway. */
    while (pDesktop->bTimerThreadRunning)
    {
        Sleep(nDelayMs);
        if (!pDesktop->bTimerThreadRunning) break;
        if (pDesktop->nTimerWriteFd != XSOCK_INVALID)
        {
            const char cTick = 't';
            send(pDesktop->nTimerWriteFd, &cTick, sizeof(cTick), 0);
        }
    }

    return 0;
}

static int DirectGate_Desktop_StartTimer(directgate_desktop_t *pDesktop)
{
    XSOCKET pair[2] = { XSOCK_INVALID, XSOCK_INVALID };
    if (XSock_CreatePair(pair) < 0)
    {
        DirectGate_Desktop_SetReason(pDesktop, "Failed to create desktop frame socket pair.");
        return XSTDERR;
    }

    u_long nNonBlock = 1;
    ioctlsocket(pair[0], FIONBIO, &nNonBlock);
    ioctlsocket(pair[1], FIONBIO, &nNonBlock);

    pDesktop->nTimerFd = pair[0];
    pDesktop->nTimerWriteFd = pair[1];
    pDesktop->bTimerThreadRunning = XTRUE;

    HANDLE hThread = CreateThread(NULL, 0, DirectGate_Desktop_TimerThread, pDesktop, 0, NULL);
    if (hThread == NULL)
    {
        pDesktop->bTimerThreadRunning = XFALSE;
        xclosesock(pDesktop->nTimerFd);
        xclosesock(pDesktop->nTimerWriteFd);
        pDesktop->nTimerFd = XSOCK_INVALID;
        pDesktop->nTimerWriteFd = XSOCK_INVALID;
        DirectGate_Desktop_SetReason(pDesktop, "Failed to start desktop frame timer thread.");
        return XSTDERR;
    }

    pDesktop->pTimerThread = hThread;
    return XSTDOK;
}

static int DirectGate_Desktop_SendFrameChunks(directgate_session_t *pSession, const uint8_t *pFrame, size_t nFrameSize)
{
    directgate_desktop_t *pDesktop = &pSession->desktop;
    uint32_t nChunks = (uint32_t)((nFrameSize + DIRECTGATE_DESKTOP_CHUNK_SIZE - 1U) / DIRECTGATE_DESKTOP_CHUNK_SIZE);
    uint64_t nFrameId = ++pDesktop->nFrameId;

    for (uint32_t i = 0; i < nChunks; i++)
    {
        size_t nOffset = (size_t)i * DIRECTGATE_DESKTOP_CHUNK_SIZE;
        size_t nChunk = nFrameSize - nOffset;
        if (nChunk > DIRECTGATE_DESKTOP_CHUNK_SIZE) nChunk = DIRECTGATE_DESKTOP_CHUNK_SIZE;

        xjson_obj_t *pHeader = DirectGate_Proto_BuildData(pSession->nSessionId);
        XCHECK((pHeader != NULL), XAPI_DISCONNECT);

        XJSON_AddString(pHeader, "payloadType", "desktop-frame-chunk");
        XJSON_AddU64(pHeader, "frameId", nFrameId);
        XJSON_AddU32(pHeader, "chunkIndex", i);
        XJSON_AddU32(pHeader, "chunks", nChunks);
        XJSON_AddU32(pHeader, "width", pDesktop->nFrameWidth);
        XJSON_AddU32(pHeader, "height", pDesktop->nFrameHeight);
        XJSON_AddU32(pHeader, "screenWidth", pDesktop->nCaptureWidth);
        XJSON_AddU32(pHeader, "screenHeight", pDesktop->nCaptureHeight);
        XJSON_AddString(pHeader, "monitorId", pDesktop->sSelectedMonitor);
        XJSON_AddString(pHeader, "encoding", "raw-rgba");

        int nStatus = DirectGate_Session_Send(pSession, pHeader, pFrame + nOffset, nChunk);
        XJSON_FreeObject(pHeader);
        if (nStatus < 0) return nStatus;
    }

    return XAPI_CONTINUE;
}

/* Raw RGBA fallback: GDI StretchBlt straight to the frame size, then an
 * in-place BGRX -> RGBA swizzle inside the DIB section (no extra frame
 * allocation). Mirrors the per-tick pull model of the Linux raw path. */
static int DirectGate_Desktop_CaptureFrameRaw(directgate_session_t *pSession)
{
    directgate_desktop_t *pDesktop = &pSession->desktop;
    XCHECK_NL((pDesktop->bCaptureReady), XAPI_CONTINUE);

    /* Transport backpressure (see the Linux raw path for the rationale). */
    if (DirectGate_Desktop_ShouldSkipForBackpressure(pSession))
        return XAPI_CONTINUE;

    uint32_t nFrameWidth = pDesktop->nFrameWidth ? pDesktop->nFrameWidth : 1U;
    uint32_t nFrameHeight = pDesktop->nFrameHeight ? pDesktop->nFrameHeight : 1U;

    HDC hScreenDC = GetDC(NULL);
    if (hScreenDC == NULL)
    {
        xlogw("Failed to open screen DC for desktop capture: sid(%u)", pSession->nSessionId);
        return XAPI_CONTINUE;
    }

    HDC hMemDC = CreateCompatibleDC(hScreenDC);
    BITMAPINFO info;
    memset(&info, 0, sizeof(info));
    info.bmiHeader.biSize = sizeof(info.bmiHeader);
    info.bmiHeader.biWidth = (LONG)nFrameWidth;
    info.bmiHeader.biHeight = -(LONG)nFrameHeight; /* top-down rows */
    info.bmiHeader.biPlanes = 1;
    info.bmiHeader.biBitCount = 32;
    info.bmiHeader.biCompression = BI_RGB;

    void *pBits = NULL;
    HBITMAP hDib = (hMemDC != NULL) ?
        CreateDIBSection(hScreenDC, &info, DIB_RGB_COLORS, &pBits, NULL, 0) : NULL;

    if (hDib == NULL || pBits == NULL)
    {
        if (hDib != NULL) DeleteObject(hDib);
        if (hMemDC != NULL) DeleteDC(hMemDC);
        ReleaseDC(NULL, hScreenDC);
        xlogw("Failed to create desktop capture bitmap: sid(%u)", pSession->nSessionId);
        return XAPI_CONTINUE;
    }

    HGDIOBJ hOldBitmap = SelectObject(hMemDC, hDib);
    SetStretchBltMode(hMemDC, COLORONCOLOR); /* nearest: matches the Linux raw path */

    BOOL bOk = StretchBlt(hMemDC, 0, 0, (int)nFrameWidth, (int)nFrameHeight,
        hScreenDC, pDesktop->nCaptureX, pDesktop->nCaptureY,
        (int)pDesktop->nCaptureWidth, (int)pDesktop->nCaptureHeight, SRCCOPY);
    GdiFlush();

    int nStatus = XAPI_CONTINUE;
    if (bOk)
    {
        uint8_t *pPixels = (uint8_t*)pBits;
        size_t nFrameSize = (size_t)nFrameWidth * nFrameHeight * 4U;

        for (size_t i = 0; i < nFrameSize; i += 4U)
        {
            uint8_t nBlue = pPixels[i];
            pPixels[i] = pPixels[i + 2U];
            pPixels[i + 2U] = nBlue;
            pPixels[i + 3U] = 255U;
        }

        nStatus = DirectGate_Desktop_SendFrameChunks(pSession, pPixels, nFrameSize);
    }
    else
    {
        xlogw("Failed to capture GDI frame: sid(%u)", pSession->nSessionId);
    }

    SelectObject(hMemDC, hOldBitmap);
    DeleteObject(hDib);
    DeleteDC(hMemDC);
    ReleaseDC(NULL, hScreenDC);
    return nStatus;
}

/* Mirrors DirectGate_Desktop_StartLinuxPipeline: prefer the H.264 pipeline
 * and demote to raw RGBA when the encoder cannot start (Media Foundation
 * missing on N editions, no encoder MFT, capture probe failure, ...). */
static int DirectGate_Desktop_StartWinPipeline(directgate_session_t *pSession)
{
    directgate_desktop_t *pDesktop = &pSession->desktop;

    if (pDesktop->bForceRaw)
    {
        pDesktop->ePipeline = DIRECTGATE_DESKTOP_PIPELINE_RAW;
        xstrncpy(pDesktop->sCodec, sizeof(pDesktop->sCodec), "raw-rgba");

        DirectGate_Desktop_SetFallbackReason(pDesktop, "Raw RGBA forced by DIRECTGATE_DESKTOP_FORCE_RAW.");
        DirectGate_Desktop_ComputeFrameSize(pDesktop);
        return XSTDOK;
    }

    if (DirectGate_Desktop_WinEncoder_Start(pSession,
        pDesktop->nCaptureX, pDesktop->nCaptureY,
        pDesktop->nCaptureWidth, pDesktop->nCaptureHeight) < 0)
    {
        const char *pErr = DirectGate_Desktop_WinEncoder_LastError(pSession);
        xlogw("Windows H.264 encoder unavailable, falling back to raw RGBA: sid(%u), reason(%s)",
            pSession->nSessionId, xstrused(pErr) ? pErr : "unknown");

        pDesktop->bForceRaw = XTRUE;
        pDesktop->ePipeline = DIRECTGATE_DESKTOP_PIPELINE_RAW;
        xstrncpy(pDesktop->sCodec, sizeof(pDesktop->sCodec), "raw-rgba");

        DirectGate_Desktop_SetFallbackReason(pDesktop,
            xstrused(pErr) ? pErr : "Media Foundation encoder failed; using raw RGBA.");
        DirectGate_Desktop_ComputeFrameSize(pDesktop);
        return XSTDOK;
    }

    xstrncpy(pDesktop->sCodec, sizeof(pDesktop->sCodec), "h264");
    if (!pDesktop->bWebRTCVideoFailed && DirectGate_WebRTC_IsVideoOpen(&pSession->webrtc))
    {
        pDesktop->ePipeline = DIRECTGATE_DESKTOP_PIPELINE_WEBRTC_VIDEO;
        DirectGate_Desktop_SetFallbackReason(pDesktop, NULL);
    }
    else
    {
        pDesktop->ePipeline = DIRECTGATE_DESKTOP_PIPELINE_H264_DC;
        DirectGate_Desktop_SetFallbackReason(pDesktop,
            "WebRTC video track is unavailable; using encrypted H.264 data channel.");
    }

    return XSTDOK;
}

static void DirectGate_Desktop_MaybePromoteWebRTCVideo(directgate_session_t *pSession)
{
    XCHECK_VOID_NL((pSession != NULL));
    directgate_desktop_t *pDesktop = &pSession->desktop;

    if (pDesktop->bForceRaw || pDesktop->bWebRTCVideoFailed)
        return;

    if (pDesktop->ePipeline != DIRECTGATE_DESKTOP_PIPELINE_H264_DC)
        return;

    if (!DirectGate_WebRTC_IsVideoOpen(&pSession->webrtc))
        return;

    pDesktop->ePipeline = DIRECTGATE_DESKTOP_PIPELINE_WEBRTC_VIDEO;
    DirectGate_Desktop_SetFallbackReason(pDesktop, NULL);
    DirectGate_Desktop_WinEncoder_RequestKeyframe(pSession);
    DirectGate_Desktop_SendStatus(pSession, "streaming", NULL);
}

/* Runtime failure demotion: too many consecutive capture/encode failures
 * flip the session to the raw RGBA path so the operator keeps a picture. */
static void DirectGate_Desktop_DemoteToRaw(directgate_session_t *pSession)
{
    directgate_desktop_t *pDesktop = &pSession->desktop;
    const char *pErr = DirectGate_Desktop_WinEncoder_LastError(pSession);

    xlogw("Windows H.264 pipeline failed, falling back to raw RGBA: sid(%u), reason(%s)",
        pSession->nSessionId, xstrused(pErr) ? pErr : "unknown");

    DirectGate_Desktop_SetFallbackReason(pDesktop,
        xstrused(pErr) ? pErr : "H.264 pipeline failed at runtime; using raw RGBA.");
    DirectGate_Desktop_WinEncoder_StopDesktop(pDesktop);

    pDesktop->ePipeline = DIRECTGATE_DESKTOP_PIPELINE_RAW;
    pDesktop->bForceRaw = XTRUE;
    xstrncpy(pDesktop->sCodec, sizeof(pDesktop->sCodec), "raw-rgba");

    DirectGate_Desktop_ComputeFrameSize(pDesktop);
    DirectGate_Desktop_SendStatus(pSession, "streaming", NULL);
}

int DirectGate_Desktop_Start(directgate_session_t *pSession)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    directgate_desktop_t *pDesktop = &pSession->desktop;

    if (pDesktop->bRunning)
        return XAPI_CONTINUE;

    DirectGate_Desktop_Clear(pDesktop);
    DirectGate_Desktop_Init(pDesktop);
    pDesktop->nSessionId = pSession->nSessionId;

    if (DirectGate_Desktop_OpenWindows(pSession) < 0)
    {
        xlogw("Desktop mode unavailable: sid(%u), reason(%s)",
            pSession->nSessionId, DirectGate_Desktop_GetReason(pDesktop));
        DirectGate_Desktop_SendStatus(pSession, "error", DirectGate_Desktop_GetReason(pDesktop));
        DirectGate_Session_SendErrorMsg(pSession, DirectGate_Desktop_GetReason(pDesktop));
        return XSTDERR;
    }

    if (DirectGate_Desktop_StartTimer(pDesktop) < 0)
    {
        xlogw("Desktop timer failed: sid(%u), reason(%s)",
            pSession->nSessionId, DirectGate_Desktop_GetReason(pDesktop));
        DirectGate_Desktop_SendStatus(pSession, "error", DirectGate_Desktop_GetReason(pDesktop));
        DirectGate_Desktop_Clear(pDesktop);
        DirectGate_Session_SendErrorMsg(pSession, DirectGate_Desktop_GetReason(pDesktop));
        return XSTDERR;
    }

    pDesktop->bRunning = XTRUE;
    xlogi("Desktop mode activated: sid(%u), backend(%s), display(%s), "
          "screen(%ux%u), pipeline(%s), preset(%s), input(%s)",
           pSession->nSessionId, pDesktop->sBackend, pDesktop->sDisplay,
           pDesktop->nScreenWidth, pDesktop->nScreenHeight,
           DirectGate_Desktop_PipelineName(pDesktop->ePipeline),
           DirectGate_Desktop_PresetName(pDesktop->quality.ePreset),
           pDesktop->bInputReady ? "yes" : "no");

    return DirectGate_Desktop_SendStatus(pSession, "ready", NULL);
}

int DirectGate_Desktop_Process(directgate_session_t *pSession)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    directgate_desktop_t *pDesktop = &pSession->desktop;

    XCHECK_NL((pDesktop->bRunning), XAPI_CONTINUE);
    if (pDesktop->nTimerFd != XSOCK_INVALID)
    {
        char sBuf[128];
        while (recv(pDesktop->nTimerFd, sBuf, sizeof(sBuf), 0) > 0) {}
    }

    /* The H.264 pipeline pushes frames from the capture thread; the wake-up
     * is just a signal to drain the encoder mailbox. The raw path still
     * pulls per tick. */
    if (pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_WEBRTC_VIDEO ||
        pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_H264_DC)
    {
        if (DirectGate_WebRTC_TakeVideoKeyframeRequest(&pSession->webrtc))
            DirectGate_Desktop_WinEncoder_RequestKeyframe(pSession);

        DirectGate_Desktop_MaybePromoteWebRTCVideo(pSession);
        DirectGate_Desktop_AdaptBitrate(pSession);

        if (DirectGate_Desktop_WinEncoder_HasFailed(pSession))
        {
            DirectGate_Desktop_DemoteToRaw(pSession);
            return XAPI_CONTINUE;
        }

        return DirectGate_Desktop_WinEncoder_DrainMain(pSession);
    }

    return DirectGate_Desktop_CaptureFrameRaw(pSession);
}

static int DirectGate_Desktop_FrameToScreenX(const directgate_desktop_t *pDesktop, int nX)
{
    if (pDesktop->nFrameWidth <= 1) return pDesktop->nCaptureX;
    if (nX < 0) nX = 0;
    if ((uint32_t)nX >= pDesktop->nFrameWidth) nX = (int)pDesktop->nFrameWidth - 1;
    return pDesktop->nCaptureX + (int)(((uint64_t)(uint32_t)nX * pDesktop->nCaptureWidth) / pDesktop->nFrameWidth);
}

static int DirectGate_Desktop_FrameToScreenY(const directgate_desktop_t *pDesktop, int nY)
{
    if (pDesktop->nFrameHeight <= 1) return pDesktop->nCaptureY;
    if (nY < 0) nY = 0;
    if ((uint32_t)nY >= pDesktop->nFrameHeight) nY = (int)pDesktop->nFrameHeight - 1;
    return pDesktop->nCaptureY + (int)(((uint64_t)(uint32_t)nY * pDesktop->nCaptureHeight) / pDesktop->nFrameHeight);
}

/* Absolute pointer injection over the whole virtual desktop: SendInput
 * expects 0..65535 normalized coordinates with MOUSEEVENTF_VIRTUALDESK. */
static void DirectGate_Desktop_SendMouseInput(DWORD nFlags, DWORD nMouseData,
                                          int nScreenX, int nScreenY)
{
    int nVirtualX = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int nVirtualY = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int nVirtualWidth = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int nVirtualHeight = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    if (nVirtualWidth <= 1 || nVirtualHeight <= 1) return;

    INPUT input;
    memset(&input, 0, sizeof(input));
    input.type = INPUT_MOUSE;
    input.mi.dx = (LONG)(((int64_t)(nScreenX - nVirtualX) * 65535LL) / (nVirtualWidth - 1));
    input.mi.dy = (LONG)(((int64_t)(nScreenY - nVirtualY) * 65535LL) / (nVirtualHeight - 1));
    input.mi.mouseData = nMouseData;
    input.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK | nFlags;
    SendInput(1, &input, sizeof(input));
}

static DWORD DirectGate_Desktop_MouseButtonFlag(uint32_t nButton, xbool_t bDown)
{
    if (nButton == 3) return bDown ? MOUSEEVENTF_RIGHTDOWN : MOUSEEVENTF_RIGHTUP;
    if (nButton == 2) return bDown ? MOUSEEVENTF_MIDDLEDOWN : MOUSEEVENTF_MIDDLEUP;
    return bDown ? MOUSEEVENTF_LEFTDOWN : MOUSEEVENTF_LEFTUP;
}

typedef struct directgate_win_key_ {
    const char *pCode;
    WORD nVirtualKey;
    xbool_t bExtended;
} directgate_win_key_t;

static const directgate_win_key_t g_WinKeys[] = {
    { "KeyA", 'A', XFALSE }, { "KeyB", 'B', XFALSE }, { "KeyC", 'C', XFALSE },
    { "KeyD", 'D', XFALSE }, { "KeyE", 'E', XFALSE }, { "KeyF", 'F', XFALSE },
    { "KeyG", 'G', XFALSE }, { "KeyH", 'H', XFALSE }, { "KeyI", 'I', XFALSE },
    { "KeyJ", 'J', XFALSE }, { "KeyK", 'K', XFALSE }, { "KeyL", 'L', XFALSE },
    { "KeyM", 'M', XFALSE }, { "KeyN", 'N', XFALSE }, { "KeyO", 'O', XFALSE },
    { "KeyP", 'P', XFALSE }, { "KeyQ", 'Q', XFALSE }, { "KeyR", 'R', XFALSE },
    { "KeyS", 'S', XFALSE }, { "KeyT", 'T', XFALSE }, { "KeyU", 'U', XFALSE },
    { "KeyV", 'V', XFALSE }, { "KeyW", 'W', XFALSE }, { "KeyX", 'X', XFALSE },
    { "KeyY", 'Y', XFALSE }, { "KeyZ", 'Z', XFALSE },
    { "Digit0", '0', XFALSE }, { "Digit1", '1', XFALSE }, { "Digit2", '2', XFALSE },
    { "Digit3", '3', XFALSE }, { "Digit4", '4', XFALSE }, { "Digit5", '5', XFALSE },
    { "Digit6", '6', XFALSE }, { "Digit7", '7', XFALSE }, { "Digit8", '8', XFALSE },
    { "Digit9", '9', XFALSE },
    { "Backquote", VK_OEM_3, XFALSE }, { "Minus", VK_OEM_MINUS, XFALSE },
    { "Equal", VK_OEM_PLUS, XFALSE }, { "BracketLeft", VK_OEM_4, XFALSE },
    { "BracketRight", VK_OEM_6, XFALSE }, { "Backslash", VK_OEM_5, XFALSE },
    { "Semicolon", VK_OEM_1, XFALSE }, { "Quote", VK_OEM_7, XFALSE },
    { "Comma", VK_OEM_COMMA, XFALSE }, { "Period", VK_OEM_PERIOD, XFALSE },
    { "Slash", VK_OEM_2, XFALSE },
    { "Enter", VK_RETURN, XFALSE }, { "NumpadEnter", VK_RETURN, XTRUE },
    { "Backspace", VK_BACK, XFALSE }, { "Delete", VK_DELETE, XTRUE },
    { "Insert", VK_INSERT, XTRUE }, { "CapsLock", VK_CAPITAL, XFALSE },
    { "Tab", VK_TAB, XFALSE }, { "Escape", VK_ESCAPE, XFALSE }, { "Space", VK_SPACE, XFALSE },
    { "ArrowLeft", VK_LEFT, XTRUE }, { "ArrowRight", VK_RIGHT, XTRUE },
    { "ArrowUp", VK_UP, XTRUE }, { "ArrowDown", VK_DOWN, XTRUE },
    { "Home", VK_HOME, XTRUE }, { "End", VK_END, XTRUE },
    { "PageUp", VK_PRIOR, XTRUE }, { "PageDown", VK_NEXT, XTRUE },
    { "ShiftLeft", VK_LSHIFT, XFALSE }, { "ShiftRight", VK_RSHIFT, XFALSE },
    { "ControlLeft", VK_LCONTROL, XFALSE }, { "ControlRight", VK_RCONTROL, XTRUE },
    { "AltLeft", VK_LMENU, XFALSE }, { "AltRight", VK_RMENU, XTRUE },
    { "MetaLeft", VK_LWIN, XTRUE }, { "MetaRight", VK_RWIN, XTRUE },
    { "ContextMenu", VK_APPS, XTRUE },
    { "F1", VK_F1, XFALSE }, { "F2", VK_F2, XFALSE }, { "F3", VK_F3, XFALSE },
    { "F4", VK_F4, XFALSE }, { "F5", VK_F5, XFALSE }, { "F6", VK_F6, XFALSE },
    { "F7", VK_F7, XFALSE }, { "F8", VK_F8, XFALSE }, { "F9", VK_F9, XFALSE },
    { "F10", VK_F10, XFALSE }, { "F11", VK_F11, XFALSE }, { "F12", VK_F12, XFALSE },
};

static WORD DirectGate_Desktop_WinKeyFromJson(xjson_obj_t *pRoot, xbool_t *pExtended, xbool_t *pFound)
{
    const char *pCode = XJSON_GetString(XJSON_GetObject(pRoot, "code"));
    const char *pKey = XJSON_GetString(XJSON_GetObject(pRoot, "key"));
    *pExtended = XFALSE;
    *pFound = XFALSE;

    if (xstrused(pCode))
    {
        for (size_t i = 0; i < sizeof(g_WinKeys) / sizeof(g_WinKeys[0]); i++)
        {
            if (xstrcmp(g_WinKeys[i].pCode, pCode))
            {
                *pExtended = g_WinKeys[i].bExtended;
                *pFound = XTRUE;
                return g_WinKeys[i].nVirtualKey;
            }
        }
    }

    if (xstrused(pKey))
    {
        if (xstrcmp(pKey, "Enter")) { *pFound = XTRUE; return VK_RETURN; }
        if (xstrcmp(pKey, "Backspace")) { *pFound = XTRUE; return VK_BACK; }
        if (xstrcmp(pKey, "Tab")) { *pFound = XTRUE; return VK_TAB; }
        if (xstrcmp(pKey, "Escape")) { *pFound = XTRUE; return VK_ESCAPE; }
        if (xstrcmp(pKey, "Delete")) { *pExtended = XTRUE; *pFound = XTRUE; return VK_DELETE; }
        if (xstrcmp(pKey, "Home")) { *pExtended = XTRUE; *pFound = XTRUE; return VK_HOME; }
        if (xstrcmp(pKey, "End")) { *pExtended = XTRUE; *pFound = XTRUE; return VK_END; }
        if (xstrcmp(pKey, "PageUp")) { *pExtended = XTRUE; *pFound = XTRUE; return VK_PRIOR; }
        if (xstrcmp(pKey, "PageDown")) { *pExtended = XTRUE; *pFound = XTRUE; return VK_NEXT; }
        if (xstrcmp(pKey, "ArrowLeft")) { *pExtended = XTRUE; *pFound = XTRUE; return VK_LEFT; }
        if (xstrcmp(pKey, "ArrowRight")) { *pExtended = XTRUE; *pFound = XTRUE; return VK_RIGHT; }
        if (xstrcmp(pKey, "ArrowUp")) { *pExtended = XTRUE; *pFound = XTRUE; return VK_UP; }
        if (xstrcmp(pKey, "ArrowDown")) { *pExtended = XTRUE; *pFound = XTRUE; return VK_DOWN; }
        if (xstrcmp(pKey, " ")) { *pFound = XTRUE; return VK_SPACE; }
        if (xstrcmp(pKey, "Shift")) { *pFound = XTRUE; return VK_LSHIFT; }
        if (xstrcmp(pKey, "Control")) { *pFound = XTRUE; return VK_LCONTROL; }
        if (xstrcmp(pKey, "Alt")) { *pFound = XTRUE; return VK_LMENU; }
        if (xstrcmp(pKey, "Meta")) { *pExtended = XTRUE; *pFound = XTRUE; return VK_LWIN; }
    }

    return 0;
}

static void DirectGate_Desktop_SendKeyInput(WORD nVirtualKey, xbool_t bExtended, xbool_t bDown)
{
    INPUT input;
    memset(&input, 0, sizeof(input));
    input.type = INPUT_KEYBOARD;
    input.ki.wVk = nVirtualKey;
    input.ki.wScan = (WORD)MapVirtualKeyW(nVirtualKey, MAPVK_VK_TO_VSC);
    input.ki.dwFlags = (bExtended ? KEYEVENTF_EXTENDEDKEY : 0) | (bDown ? 0 : KEYEVENTF_KEYUP);
    SendInput(1, &input, sizeof(input));
}

int DirectGate_Desktop_HandleInput(directgate_session_t *pSession, const uint8_t *pPayload, size_t nPayloadLength)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    directgate_desktop_t *pDesktop = &pSession->desktop;

    if (!pDesktop->bRunning || !pDesktop->bInputReady)
        return XAPI_CONTINUE;

    if (pPayload == NULL || !nPayloadLength)
        return XAPI_CONTINUE;

    char *pJsonText = (char*)calloc(1, nPayloadLength + 1U);
    XCHECK((pJsonText != NULL), XAPI_CONTINUE);
    memcpy(pJsonText, pPayload, nPayloadLength);

    xjson_t json;
    if (!XJSON_Parse(&json, NULL, pJsonText, nPayloadLength))
    {
        free(pJsonText);
        return XAPI_CONTINUE;
    }

    xjson_obj_t *pRoot = json.pRootObj;
    const char *pAction = XJSON_GetString(XJSON_GetObject(pRoot, "action"));
    const char *pEvent = XJSON_GetString(XJSON_GetObject(pRoot, "event"));

    if (xstrcmp(pAction, "pointer"))
    {
        int nX = XJSON_GetInt(XJSON_GetObject(pRoot, "x"));
        int nY = XJSON_GetInt(XJSON_GetObject(pRoot, "y"));
        int nScreenX = DirectGate_Desktop_FrameToScreenX(pDesktop, nX);
        int nScreenY = DirectGate_Desktop_FrameToScreenY(pDesktop, nY);

        if (xstrcmp(pEvent, "button"))
        {
            uint32_t nButton = XJSON_GetU32(XJSON_GetObject(pRoot, "button"));
            xbool_t bDown = XJSON_GetBool(XJSON_GetObject(pRoot, "down"));
            if (nButton >= 1 && nButton <= 3)
                DirectGate_Desktop_SendMouseInput(
                    DirectGate_Desktop_MouseButtonFlag(nButton, bDown), 0, nScreenX, nScreenY);
        }
        else if (xstrcmp(pEvent, "wheel"))
        {
            /* One notch per event, like the Linux X11 button-4/5 mapping. */
            int nDeltaY = XJSON_GetInt(XJSON_GetObject(pRoot, "deltaY"));
            DWORD nWheel = (DWORD)(nDeltaY < 0 ? WHEEL_DELTA : -WHEEL_DELTA);
            DirectGate_Desktop_SendMouseInput(MOUSEEVENTF_WHEEL, nWheel, nScreenX, nScreenY);
        }
        else
        {
            DirectGate_Desktop_SendMouseInput(0, 0, nScreenX, nScreenY);
        }
    }
    else if (xstrcmp(pAction, "key"))
    {
        xbool_t bExtended = XFALSE, bFound = XFALSE;
        WORD nVirtualKey = DirectGate_Desktop_WinKeyFromJson(pRoot, &bExtended, &bFound);
        if (bFound)
        {
            xbool_t bDown = XJSON_GetBool(XJSON_GetObject(pRoot, "down"));
            DirectGate_Desktop_SendKeyInput(nVirtualKey, bExtended, bDown);
        }
    }

    XJSON_Destroy(&json);
    free(pJsonText);
    return XAPI_CONTINUE;
}

int DirectGate_Desktop_HandleControl(directgate_session_t *pSession, const uint8_t *pPayload, size_t nPayloadLength)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    directgate_desktop_t *pDesktop = &pSession->desktop;

    if (!pDesktop->bRunning || pPayload == NULL || !nPayloadLength)
        return XAPI_CONTINUE;

    char *pJsonText = (char*)calloc(1, nPayloadLength + 1U);
    XCHECK((pJsonText != NULL), XAPI_CONTINUE);
    memcpy(pJsonText, pPayload, nPayloadLength);

    xjson_t json;
    if (!XJSON_Parse(&json, NULL, pJsonText, nPayloadLength))
    {
        free(pJsonText);
        return XAPI_CONTINUE;
    }

    xjson_obj_t *pRoot = json.pRootObj;
    const char *pAction = XJSON_GetString(XJSON_GetObject(pRoot, "action"));
    const char *pMonitorId = XJSON_GetString(XJSON_GetObject(pRoot, "monitorId"));

    if (xstrcmp(pAction, "select-monitor") && xstrused(pMonitorId))
    {
        DirectGate_Desktop_ReadResizeRequest(pDesktop, pRoot);
        const directgate_desktop_monitor_t *pSelected = NULL;
        for (uint32_t i = 0; i < pDesktop->nMonitorCount; i++)
        {
            if (xstrcmp(pDesktop->monitors[i].sId, pMonitorId))
            {
                pSelected = &pDesktop->monitors[i];
                break;
            }
        }

        if (pSelected != NULL)
        {
            char sSelectedId[DIRECTGATE_DESKTOP_MONITOR_ID_LEN];
            xstrncpy(sSelectedId, sizeof(sSelectedId), pSelected->sId);
            const char *pResizeReason = NULL;

            if (pDesktop->eResizeMode == DIRECTGATE_DESKTOP_RESIZE_DISPLAY &&
                DirectGate_Desktop_SetDisplayResolution(pDesktop, pSelected,
                    pDesktop->nTargetWidth, pDesktop->nTargetHeight) != XSTDOK)
            {
                pResizeReason = DirectGate_Desktop_GetReason(pDesktop);
                pDesktop->eResizeMode = DIRECTGATE_DESKTOP_RESIZE_SCALE;
            }

            pSelected = DirectGate_Desktop_FindMonitor(pDesktop, sSelectedId);
            if (pSelected == NULL)
            {
                DirectGate_Desktop_SendStatus(pSession, "error",
                    "Selected display disappeared after its display mode changed.");
                XJSON_Destroy(&json);
                free(pJsonText);
                return XAPI_CONTINUE;
            }

            DirectGate_Desktop_SetCapture(pDesktop, pSelected->sId, pSelected->nX,
                pSelected->nY, pSelected->nWidth, pSelected->nHeight);

            if (DirectGate_Desktop_StartWinPipeline(pSession) < 0)
            {
                XJSON_Destroy(&json);
                free(pJsonText);

                DirectGate_Desktop_SendStatus(pSession, "error", "Failed to start desktop pipeline.");
                return XAPI_CONTINUE;
            }

            DirectGate_Desktop_SendStatus(pSession, "streaming", pResizeReason);
            xlogi("Desktop monitor selected: sid(%u), monitor(%s), rect(%d,%d %ux%u), pipeline(%s), preset(%s)",
                pSession->nSessionId, pSelected->sId, pSelected->nX, pSelected->nY,
                pSelected->nWidth, pSelected->nHeight,
                DirectGate_Desktop_PipelineName(pDesktop->ePipeline),
                DirectGate_Desktop_PresetName(pDesktop->quality.ePreset));
        }
        else
        {
            DirectGate_Desktop_SendStatus(pSession, "error", "Selected display is not available.");
        }
    }
    else if (xstrcmp(pAction, "set-resolution"))
    {
        directgate_desktop_resize_mode_t ePreviousMode = pDesktop->eResizeMode;
        DirectGate_Desktop_ReadResizeRequest(pDesktop, pRoot);
        char sSelectedId[DIRECTGATE_DESKTOP_MONITOR_ID_LEN];
        xstrncpy(sSelectedId, sizeof(sSelectedId), pDesktop->sSelectedMonitor);
        const directgate_desktop_monitor_t *pSelected = DirectGate_Desktop_FindMonitor(pDesktop, sSelectedId);
        const char *pResizeReason = NULL;
        xbool_t bCaptureChanged = XFALSE;

        if (pDesktop->bCaptureReady && ePreviousMode == DIRECTGATE_DESKTOP_RESIZE_DISPLAY &&
            pDesktop->eResizeMode == DIRECTGATE_DESKTOP_RESIZE_SCALE)
        {
            DirectGate_Desktop_WinEncoder_StopDesktop(pDesktop);
            DirectGate_Desktop_RestoreDisplayMode(pDesktop);
            pSelected = DirectGate_Desktop_FindMonitor(pDesktop, sSelectedId);
            bCaptureChanged = XTRUE;
        }
        else if (pDesktop->bCaptureReady &&
            pDesktop->eResizeMode == DIRECTGATE_DESKTOP_RESIZE_DISPLAY)
        {
            DirectGate_Desktop_WinEncoder_StopDesktop(pDesktop);
            if (DirectGate_Desktop_SetDisplayResolution(pDesktop, pSelected,
                pDesktop->nTargetWidth, pDesktop->nTargetHeight) != XSTDOK)
            {
                pResizeReason = DirectGate_Desktop_GetReason(pDesktop);
                if (!pDesktop->bDisplayModeChanged)
                    pDesktop->eResizeMode = DIRECTGATE_DESKTOP_RESIZE_SCALE;
            }
            pSelected = DirectGate_Desktop_FindMonitor(pDesktop, sSelectedId);
            bCaptureChanged = XTRUE;
        }

        if (pDesktop->bCaptureReady && pSelected != NULL && bCaptureChanged)
        {
            DirectGate_Desktop_SetCapture(pDesktop, pSelected->sId, pSelected->nX,
                pSelected->nY, pSelected->nWidth, pSelected->nHeight);
            (void)DirectGate_Desktop_StartWinPipeline(pSession);
        }
        else if (pDesktop->bCaptureReady &&
            (pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_WEBRTC_VIDEO ||
             pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_H264_DC))
            DirectGate_Desktop_WinEncoder_ApplyQuality(pSession);
        else if (pDesktop->bCaptureReady)
            DirectGate_Desktop_ComputeFrameSize(pDesktop);

        DirectGate_Desktop_SendStatus(pSession,
            pDesktop->bCaptureReady ? "streaming" : "ready", pResizeReason);
    }
    else if (xstrcmp(pAction, "set-preset"))
    {
        const char *pPreset = XJSON_GetString(XJSON_GetObject(pRoot, "preset"));
        directgate_desktop_preset_t eNext = pDesktop->quality.ePreset;
        if (xstrcmp(pPreset, "quality")) eNext = DIRECTGATE_DESKTOP_PRESET_QUALITY;
        else if (xstrcmp(pPreset, "low-latency")) eNext = DIRECTGATE_DESKTOP_PRESET_LOW_LATENCY;
        else if (xstrcmp(pPreset, "balanced")) eNext = DIRECTGATE_DESKTOP_PRESET_BALANCED;

        DirectGate_Desktop_ApplyPreset(pDesktop, eNext);
        if (pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_WEBRTC_VIDEO ||
            pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_H264_DC)
        {
            DirectGate_Desktop_WinEncoder_ApplyQuality(pSession);

            /* A max-edge change rebuilds the pipeline; when that rebuild
             * fails the encoder is gone, so demote to raw RGBA instead of
             * leaving a silently frozen stream. */
            if (pDesktop->pEncoder == NULL)
            {
                const char *pErr = DirectGate_Desktop_WinEncoder_LastError(pSession);
                xlogw("Windows H.264 pipeline rebuild failed, falling back to raw RGBA: sid(%u), reason(%s)",
                    pSession->nSessionId, xstrused(pErr) ? pErr : "unknown");

                pDesktop->ePipeline = DIRECTGATE_DESKTOP_PIPELINE_RAW;
                pDesktop->bForceRaw = XTRUE;

                xstrncpy(pDesktop->sCodec, sizeof(pDesktop->sCodec), "raw-rgba");
                DirectGate_Desktop_SetFallbackReason(pDesktop,
                    xstrused(pErr) ? pErr : "Media Foundation pipeline rebuild failed; using raw RGBA.");
                DirectGate_Desktop_ComputeFrameSize(pDesktop);
            }
        }
        else if (pDesktop->bCaptureReady)
        {
            DirectGate_Desktop_ComputeFrameSize(pDesktop);
        }

        DirectGate_Desktop_SendStatus(pSession, "streaming", NULL);
        xlogi("Desktop preset updated: sid(%u), preset(%s), fps(%u), bitrate(%u kbps)",
            pSession->nSessionId,
            DirectGate_Desktop_PresetName(pDesktop->quality.ePreset),
            pDesktop->quality.nFps, pDesktop->quality.nBitrateKbps);
    }
    else if (xstrcmp(pAction, "request-keyframe"))
    {
        if (pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_WEBRTC_VIDEO ||
            pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_H264_DC)
            DirectGate_Desktop_WinEncoder_RequestKeyframe(pSession);
    }

    XJSON_Destroy(&json);
    free(pJsonText);
    return XAPI_CONTINUE;
}

#else

int DirectGate_Desktop_Start(directgate_session_t *pSession)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    DirectGate_Desktop_SetReason(&pSession->desktop, "Desktop streaming is currently implemented only for Linux X11, macOS, and Windows.");
    DirectGate_Session_SendErrorMsg(pSession, DirectGate_Desktop_GetReason(&pSession->desktop));
    return XSTDERR;
}

int DirectGate_Desktop_Process(directgate_session_t *pSession)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    return XAPI_CONTINUE;
}

int DirectGate_Desktop_HandleInput(directgate_session_t *pSession, const uint8_t *pPayload, size_t nPayloadLength)
{
    (void)pPayload;
    (void)nPayloadLength;
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    return XAPI_CONTINUE;
}

int DirectGate_Desktop_HandleControl(directgate_session_t *pSession, const uint8_t *pPayload, size_t nPayloadLength)
{
    (void)pPayload;
    (void)nPayloadLength;
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    return XAPI_CONTINUE;
}

#endif
