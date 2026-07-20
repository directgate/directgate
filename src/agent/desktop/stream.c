/*!
 * @file directgate-agent/src/agent/desktop/stream.c
 * @brief Agent-side desktop frame timer, capture pipeline and control messages.
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
#include "priv.h"

#if defined(__linux__)
#include <sys/timerfd.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#elif defined(__APPLE__)
#include <stdbool.h>
#include <ApplicationServices/ApplicationServices.h>
#endif

#define DIRECTGATE_DESKTOP_CHUNK_SIZE        (128U * 1024U)

/* Adaptive bitrate bounds: never throttle below this floor, and step back
 * up toward the preset target when the link stays clean. */
#define DIRECTGATE_DESKTOP_MIN_BITRATE_KBPS   1000U
#define DIRECTGATE_DESKTOP_ABR_HOLD_TICKS     60U  /* ~2s at 30 fps */
#define DIRECTGATE_DESKTOP_ABR_RAISE_TICKS    150U /* ~5s clean before raising */
#define DIRECTGATE_DESKTOP_ABR_LOSS_THRESHOLD 8U   /* ~3% fraction lost */

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

    uint32_t nCurrent = pDesktop->nCurrentBitrateKbps ? pDesktop->nCurrentBitrateKbps : nTarget;
    xbool_t bCongested = XFALSE;
    uint8_t nFractionLost = 0;

    if (DirectGate_WebRTC_TakeVideoLossReport(&pSession->webrtc, &nFractionLost) &&
        nFractionLost >= DIRECTGATE_DESKTOP_ABR_LOSS_THRESHOLD) bCongested = XTRUE;

    if (pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_H264_DC &&
        DirectGate_Desktop_ShouldSkipForBackpressure(pSession)) bCongested = XTRUE;

    if (pDesktop->nAbrHoldTicks > 0) pDesktop->nAbrHoldTicks--;
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
        pSession->nSessionId, nNext < nCurrent ? "down" : "up", nCurrent, nNext, nTarget);
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

static void DirectGate_Desktop_MaybePromoteWebRTCVideo(directgate_session_t *pSession)
{
    XCHECK_VOID_NL((pSession != NULL));
    directgate_desktop_t *pDesktop = &pSession->desktop;

    if (pDesktop->bForceRaw || pDesktop->bWebRTCVideoFailed ||
        pDesktop->bPreferDataChannel)
        return;

    if (pDesktop->ePipeline != DIRECTGATE_DESKTOP_PIPELINE_H264_DC)
        return;

    if (!DirectGate_WebRTC_IsVideoOpen(&pSession->webrtc))
        return;

    pDesktop->ePipeline = DIRECTGATE_DESKTOP_PIPELINE_WEBRTC_VIDEO;
    DirectGate_Desktop_SetFallbackReason(pDesktop, NULL);
#if defined(__linux__)
    DirectGate_Desktop_LinuxEncoder_RequestKeyframe(pSession);
#elif defined(__APPLE__)
    DirectGate_Desktop_MacEncoder_RequestKeyframe(pSession);
#elif defined(_WIN32)
    DirectGate_Desktop_WinEncoder_RequestKeyframe(pSession);
#endif
    DirectGate_Desktop_SendStatus(pSession, "streaming", NULL);
}

/* Runtime failure demotion: too many consecutive capture/encode failures
 * flip the session to the raw RGBA path so the operator keeps a picture. */
#if defined(__linux__) || defined(_WIN32)
static void DirectGate_Desktop_DemoteToRaw(directgate_session_t *pSession)
{
    directgate_desktop_t *pDesktop = &pSession->desktop;
#if defined(__linux__)
    const char *pErr = DirectGate_Desktop_LinuxEncoder_LastError(pSession);

    xlogw("Linux H.264 pipeline failed, falling back to raw RGBA: sid(%u), reason(%s)",
        pSession->nSessionId, xstrused(pErr) ? pErr : "unknown");
#else
    const char *pErr = DirectGate_Desktop_WinEncoder_LastError(pSession);

    xlogw("Windows H.264 pipeline failed, falling back to raw RGBA: sid(%u), reason(%s)",
        pSession->nSessionId, xstrused(pErr) ? pErr : "unknown");
#endif

    DirectGate_Desktop_SetFallbackReason(pDesktop,
        xstrused(pErr) ? pErr : "H.264 pipeline failed at runtime; using raw RGBA.");
#if defined(__linux__)
    DirectGate_Desktop_LinuxEncoder_StopDesktop(pDesktop);
#else
    DirectGate_Desktop_WinEncoder_StopDesktop(pDesktop);
#endif

    pDesktop->ePipeline = DIRECTGATE_DESKTOP_PIPELINE_RAW;
    pDesktop->bForceRaw = XTRUE;
    xstrncpy(pDesktop->sCodec, sizeof(pDesktop->sCodec), "raw-rgba");

    DirectGate_Desktop_ComputeFrameSize(pDesktop);
    DirectGate_Desktop_SendStatus(pSession, "streaming", NULL);
}
#endif

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

    if (!pDesktop->bWebRTCVideoFailed && !pDesktop->bPreferDataChannel &&
        DirectGate_WebRTC_IsVideoOpen(&pSession->webrtc))
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
    if (DirectGate_Desktop_ShouldSkipForBackpressure(pSession)) return XAPI_CONTINUE;

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
        xloge("Failed to allocate desktop frame: sid(%u), bytes(%zu)", pSession->nSessionId, nFrameSize);
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

#ifdef DIRECTGATE_DESKTOP_HAS_AUDIO
    /* Ship any encoded Opus frames the capture thread queued. Runs before the
     * video encode so audio is never delayed by this tick's frame, and is a
     * no-op unless the audio track is open. */
    DirectGate_Desktop_AudioDrainMain(pSession);
#endif

    /* The H.264 pipeline captures + encodes synchronously on each tick;
     * the raw path keeps the legacy pull-per-tick behavior. */
    if (pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_WEBRTC_VIDEO ||
        pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_H264_DC)
    {
        if (DirectGate_WebRTC_TakeVideoKeyframeRequest(&pSession->webrtc))
        {
            DirectGate_Desktop_LinuxEncoder_RequestKeyframe(pSession);
            if (DirectGate_WebRTC_IsVideoOpen(&pSession->webrtc))
                pDesktop->bWebRTCVideoFailed = XFALSE;
        }

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

int DirectGate_Desktop_HandleControl(directgate_session_t *pSession, const uint8_t *pPayload, size_t nPayloadLength)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    directgate_desktop_t *pDesktop = &pSession->desktop;
    if (!pDesktop->bRunning || pPayload == NULL || !nPayloadLength) return XAPI_CONTINUE;

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
        else if (pDesktop->bCaptureReady && pDesktop->eResizeMode == DIRECTGATE_DESKTOP_RESIZE_DISPLAY)
        {
            DirectGate_Desktop_LinuxEncoder_Stop(pSession);

            if (DirectGate_Desktop_SetDisplayResolution(pDesktop, pSelected,
                pDesktop->nTargetWidth, pDesktop->nTargetHeight) != XSTDOK)
            {
                pResizeReason = DirectGate_Desktop_GetReason(pDesktop);
                if (!pDesktop->bDisplayModeChanged) pDesktop->eResizeMode = DIRECTGATE_DESKTOP_RESIZE_SCALE;
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
        {
            DirectGate_Desktop_LinuxEncoder_ApplyQuality(pSession);
        }
        else if (pDesktop->bCaptureReady)
        {
            DirectGate_Desktop_ComputeFrameSize(pDesktop);
        }

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
            DirectGate_Desktop_LinuxEncoder_ApplyQuality(pSession);
        }
        else if (pDesktop->bCaptureReady)
        {
            DirectGate_Desktop_ComputeFrameSize(pDesktop);
        }

        DirectGate_Desktop_SendStatus(pSession, "streaming", NULL);

        xlogi("Desktop preset updated: sid(%u), preset(%s), fps(%u), bitrate(%u kbps)",
            pSession->nSessionId, DirectGate_Desktop_PresetName(pDesktop->quality.ePreset),
            pDesktop->quality.nFps, pDesktop->quality.nBitrateKbps);
    }
    else if (xstrcmp(pAction, "request-keyframe"))
    {
        if (pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_WEBRTC_VIDEO ||
            pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_H264_DC)
            DirectGate_Desktop_LinuxEncoder_RequestKeyframe(pSession);
    }
    else if (xstrcmp(pAction, "fallback-datachannel"))
    {
        if (DirectGate_Desktop_FallbackToDataChannel(pSession))
            DirectGate_Desktop_LinuxEncoder_RequestKeyframe(pSession);
    }
    else if (xstrcmp(pAction, "audio"))
    {
        /* Opt-in system-audio toggle. Capture never runs until the viewer asks
         * for it; a failed start reports "unavailable" and leaves video alone. */
        xbool_t bEnable = XJSON_GetBool(XJSON_GetObject(pRoot, "enabled")) ? XTRUE : XFALSE;
        pDesktop->bAudioRequested = bEnable;

        if (bEnable) (void)DirectGate_Desktop_AudioStart(pSession);
        else DirectGate_Desktop_AudioStop(pDesktop);

        DirectGate_Desktop_SendStatus(pSession, "streaming", NULL);
    }

    XJSON_Destroy(&json);
    free(pJsonText);
    return XAPI_CONTINUE;
}

#elif defined(__APPLE__)

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
        pDesktop->bCaptureReady = XFALSE;

        xlogw("Failed to capture macOS frame: sid(%u), reason(%s)",
            pSession->nSessionId, xstrused(sCaptureError) ? sCaptureError : "unknown");

        DirectGate_Desktop_SendStatus(pSession, "error", xstrused(sCaptureError) ? sCaptureError :
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
        (size_t)nFrameWidth * 4U, colorSpace, kCGBitmapByteOrder32Big | kCGImageAlphaPremultipliedLast);
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
        pDesktop->bForceRaw = XTRUE;
        xstrncpy(pDesktop->sCodec, sizeof(pDesktop->sCodec), "raw-rgba");

        DirectGate_Desktop_SetFallbackReason(pDesktop,
            xstrused(pErr) ? pErr : "VideoToolbox H.264 encoder failed; using raw RGBA.");

        return XSTDOK;
    }

    xstrncpy(pDesktop->sCodec, sizeof(pDesktop->sCodec), "h264");

    if (!pDesktop->bWebRTCVideoFailed && !pDesktop->bPreferDataChannel &&
        DirectGate_WebRTC_IsVideoOpen(&pSession->webrtc))
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

#ifdef DIRECTGATE_DESKTOP_HAS_AUDIO
    /* Ship any encoded Opus frames the capture thread queued (no-op unless the
     * audio track is open). */
    DirectGate_Desktop_AudioDrainMain(pSession);
#endif

    /* The H.264 pipeline pushes frames from the SCK delegate; the timer
     * wake-up is just a signal to drain the encoder mailbox. The raw
     * path still pulls per tick. */
    if (pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_WEBRTC_VIDEO ||
        pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_H264_DC)
    {
        if (DirectGate_WebRTC_TakeVideoKeyframeRequest(&pSession->webrtc))
        {
            DirectGate_Desktop_MacEncoder_RequestKeyframe(pSession);
            if (DirectGate_WebRTC_IsVideoOpen(&pSession->webrtc))
                pDesktop->bWebRTCVideoFailed = XFALSE;
        }

        DirectGate_Desktop_MaybePromoteWebRTCVideo(pSession);
        DirectGate_Desktop_AdaptBitrate(pSession);
        return DirectGate_Desktop_MacEncoder_DrainMain(pSession);
    }

    return DirectGate_Desktop_CaptureFrameRaw(pSession);
}

int DirectGate_Desktop_HandleControl(directgate_session_t *pSession, const uint8_t *pPayload, size_t nPayloadLength)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    directgate_desktop_t *pDesktop = &pSession->desktop;
    if (!pDesktop->bRunning || pPayload == NULL || !nPayloadLength) return XAPI_CONTINUE;

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
                XJSON_Destroy(&json);
                free(pJsonText);

                DirectGate_Desktop_SendStatus(pSession, "error", "Selected display disappeared after its display mode changed.");
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
        else if (pDesktop->bCaptureReady && pDesktop->eResizeMode == DIRECTGATE_DESKTOP_RESIZE_DISPLAY)
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
        {
            DirectGate_Desktop_MacEncoder_ApplyQuality(pSession);
        }
        else if (pDesktop->bCaptureReady)
        {
            DirectGate_Desktop_ComputeFrameSize(pDesktop);
        }

        DirectGate_Desktop_SendStatus(pSession, pDesktop->bCaptureReady ? "streaming" : "ready", pResizeReason);
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
    else if (xstrcmp(pAction, "fallback-datachannel"))
    {
        if (DirectGate_Desktop_FallbackToDataChannel(pSession))
            DirectGate_Desktop_MacEncoder_RequestKeyframe(pSession);
    }
    else if (xstrcmp(pAction, "audio"))
    {
        /* Opt-in system-audio toggle. Capture never runs until the viewer asks
         * for it; a failed start reports "unavailable" and leaves video alone. */
        xbool_t bEnable = XJSON_GetBool(XJSON_GetObject(pRoot, "enabled")) ? XTRUE : XFALSE;
        pDesktop->bAudioRequested = bEnable;

        if (bEnable) (void)DirectGate_Desktop_AudioStart(pSession);
        else DirectGate_Desktop_AudioStop(pDesktop);

        DirectGate_Desktop_SendStatus(pSession, "streaming", NULL);
    }

    XJSON_Destroy(&json);
    free(pJsonText);
    return XAPI_CONTINUE;
}

#elif defined(_WIN32)

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
    HBITMAP hDib = (hMemDC != NULL) ? CreateDIBSection(hScreenDC, &info, DIB_RGB_COLORS, &pBits, NULL, 0) : NULL;
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

        DirectGate_Desktop_SetFallbackReason(pDesktop, xstrused(pErr) ? pErr : "Media Foundation encoder failed; using raw RGBA.");
        DirectGate_Desktop_ComputeFrameSize(pDesktop);
        return XSTDOK;
    }

    xstrncpy(pDesktop->sCodec, sizeof(pDesktop->sCodec), "h264");

    if (!pDesktop->bWebRTCVideoFailed && !pDesktop->bPreferDataChannel &&
        DirectGate_WebRTC_IsVideoOpen(&pSession->webrtc))
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

#ifdef DIRECTGATE_DESKTOP_HAS_AUDIO
    /* Ship any encoded Opus frames the capture thread queued (no-op unless the
     * audio track is open). */
    DirectGate_Desktop_AudioDrainMain(pSession);
#endif

    /* The H.264 pipeline pushes frames from the capture thread; the wake-up
     * is just a signal to drain the encoder mailbox. The raw path still
     * pulls per tick. */
    if (pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_WEBRTC_VIDEO ||
        pDesktop->ePipeline == DIRECTGATE_DESKTOP_PIPELINE_H264_DC)
    {
        if (DirectGate_WebRTC_TakeVideoKeyframeRequest(&pSession->webrtc))
        {
            DirectGate_Desktop_WinEncoder_RequestKeyframe(pSession);
            if (DirectGate_WebRTC_IsVideoOpen(&pSession->webrtc))
                pDesktop->bWebRTCVideoFailed = XFALSE;
        }

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

int DirectGate_Desktop_HandleControl(directgate_session_t *pSession, const uint8_t *pPayload, size_t nPayloadLength)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    directgate_desktop_t *pDesktop = &pSession->desktop;
    if (!pDesktop->bRunning || pPayload == NULL || !nPayloadLength) return XAPI_CONTINUE;

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
                XJSON_Destroy(&json);
                free(pJsonText);

                DirectGate_Desktop_SendStatus(pSession, "error",  "Selected display disappeared after its display mode changed.");
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
        else if (pDesktop->bCaptureReady && pDesktop->eResizeMode == DIRECTGATE_DESKTOP_RESIZE_DISPLAY)
        {
            DirectGate_Desktop_WinEncoder_StopDesktop(pDesktop);

            if (DirectGate_Desktop_SetDisplayResolution(pDesktop, pSelected,
                pDesktop->nTargetWidth, pDesktop->nTargetHeight) != XSTDOK)
            {
                pResizeReason = DirectGate_Desktop_GetReason(pDesktop);
                if (!pDesktop->bDisplayModeChanged) pDesktop->eResizeMode = DIRECTGATE_DESKTOP_RESIZE_SCALE;
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
        {
            DirectGate_Desktop_WinEncoder_ApplyQuality(pSession);
        }
        else if (pDesktop->bCaptureReady)
        {
            DirectGate_Desktop_ComputeFrameSize(pDesktop);
        }

        DirectGate_Desktop_SendStatus(pSession, pDesktop->bCaptureReady ? "streaming" : "ready", pResizeReason);
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
    else if (xstrcmp(pAction, "fallback-datachannel"))
    {
        if (DirectGate_Desktop_FallbackToDataChannel(pSession))
            DirectGate_Desktop_WinEncoder_RequestKeyframe(pSession);
    }
    else if (xstrcmp(pAction, "audio"))
    {
        /* Opt-in system-audio toggle. Capture never runs until the viewer asks
         * for it; a failed start reports "unavailable" and leaves video alone. */
        xbool_t bEnable = XJSON_GetBool(XJSON_GetObject(pRoot, "enabled")) ? XTRUE : XFALSE;
        pDesktop->bAudioRequested = bEnable;

        if (bEnable) (void)DirectGate_Desktop_AudioStart(pSession);
        else DirectGate_Desktop_AudioStop(pDesktop);

        DirectGate_Desktop_SendStatus(pSession, "streaming", NULL);
    }

    XJSON_Destroy(&json);
    free(pJsonText);
    return XAPI_CONTINUE;
}

#endif /* platform capture + control */

int DirectGate_Desktop_Start(directgate_session_t *pSession)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    directgate_desktop_t *pDesktop = &pSession->desktop;
    if (pDesktop->bRunning) return XAPI_CONTINUE;

    DirectGate_Desktop_Clear(pDesktop);
    DirectGate_Desktop_Init(pDesktop);
    pDesktop->nSessionId = pSession->nSessionId;

#if defined(__linux__)
    if (DirectGate_Desktop_OpenX11(pSession) < 0)
#elif defined(__APPLE__)
    if (DirectGate_Desktop_OpenMacOS(pSession) < 0)
#else
    if (DirectGate_Desktop_OpenWindows(pSession) < 0)
#endif
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
#if defined(__linux__)
    xlogi("Desktop mode activated: sid(%u), backend(%s), display(%s), screen(%ux%u), frame(%ux%u), input(%s)",
        pSession->nSessionId, pDesktop->sBackend, pDesktop->sDisplay,
        pDesktop->nScreenWidth, pDesktop->nScreenHeight,
        pDesktop->nFrameWidth, pDesktop->nFrameHeight,
        pDesktop->bInputReady ? "yes" : "no");
#else
    xlogi("Desktop mode activated: sid(%u), backend(%s), display(%s), "
          "screen(%ux%u), pipeline(%s), preset(%s), input(%s)",
           pSession->nSessionId, pDesktop->sBackend, pDesktop->sDisplay,
           pDesktop->nScreenWidth, pDesktop->nScreenHeight,
           DirectGate_Desktop_PipelineName(pDesktop->ePipeline),
           DirectGate_Desktop_PresetName(pDesktop->quality.ePreset),
           pDesktop->bInputReady ? "yes" : "no");
#endif

    return DirectGate_Desktop_SendStatus(pSession, "ready", NULL);
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

int DirectGate_Desktop_HandleControl(directgate_session_t *pSession, const uint8_t *pPayload, size_t nPayloadLength)
{
    (void)pPayload;
    (void)nPayloadLength;
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    return XAPI_CONTINUE;
}

#endif /* __linux__ || __APPLE__ || _WIN32 */
