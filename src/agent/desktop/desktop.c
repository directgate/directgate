/*!
 * @file directgate-agent/src/agent/desktop/desktop.c
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
#include "priv.h"

/* The raw-RGBA path keeps a conservative FPS budget; the H.264 path
 * picks its own FPS from the active preset. The encoded path supersedes
 * the raw path on macOS unless DIRECTGATE_DESKTOP_FORCE_RAW is set. */
#define DIRECTGATE_DESKTOP_MAX_FRAME_EDGE    1280U
#define DIRECTGATE_DESKTOP_RAW_BALANCED_EDGE 1600U

/* H.264 encoded transport never sends more than one frame in flight to the
 * data channel; this is the backpressure threshold (bytes) above which we
 * skip a capture and ask the encoder for a fresh keyframe later. 256 KB is
 * ~250 ms of queue at the balanced 8 Mbps target: enough to ride out jitter
 * without letting the fallback path accumulate a second of latency. */
#define DIRECTGATE_DESKTOP_ENCODED_BUFFER_LIMIT (256U * 1024U)

#if defined(__linux__)
#include <dlfcn.h>
#include <X11/Xlib.h>
#endif

void DirectGate_Desktop_SetReason(directgate_desktop_t *pDesktop, const char *pReason)
{
    XCHECK_VOID_NL((pDesktop != NULL));
    xstrncpy(pDesktop->sReason, sizeof(pDesktop->sReason),
        xstrused(pReason) ? pReason : "desktop unavailable");
}

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

void DirectGate_Desktop_SetFallbackReason(directgate_desktop_t *pDesktop, const char *pReason)
{
    XCHECK_VOID_NL((pDesktop != NULL));
    xstrncpy(pDesktop->sFallbackReason, sizeof(pDesktop->sFallbackReason), xstrused(pReason) ? pReason : "");
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
#if defined(_WIN32)
            /* Windows has an event-driven DXGI capture thread and a hardware
             * Media Foundation path, so make Low the first gaming-grade
             * preset. Keeping Linux/macOS at 30 here preserves the requested
             * Windows-first rollout until their pipelines are tuned next. */
            pDesktop->quality.nFps = 60U;
            pDesktop->quality.nBitrateKbps = 6000U;
#else
            pDesktop->quality.nFps = 30U;
            pDesktop->quality.nBitrateKbps = 4000U;
#endif
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
        xbool_t bVideoTrackOpen = DirectGate_WebRTC_IsVideoOpen(&pSession->webrtc);
        if (bVideoTrackOpen && DirectGate_WebRTC_SendH264AnnexB(&pSession->webrtc,
            pPayload, nPayloadLength, nPtsUs) >= 0)
        {
            pDesktop->nFrameWidth = nWidth;
            pDesktop->nFrameHeight = nHeight;
            return XAPI_CONTINUE;
        }

        pDesktop->ePipeline = DIRECTGATE_DESKTOP_PIPELINE_H264_DC;
        pDesktop->bWebRTCVideoFailed = bVideoTrackOpen;

        DirectGate_Desktop_SetFallbackReason(pDesktop, bVideoTrackOpen ?
            "WebRTC video track send failed; using encrypted H.264 data channel." :
            "WebRTC video track is reconnecting; using encrypted H.264 data channel.");
        DirectGate_Desktop_SendStatus(pSession, "streaming", NULL);
    }

    uint64_t nFrameId = ++pDesktop->nFrameId;
    uint32_t nChunks = (uint32_t)((nPayloadLength + DIRECTGATE_DESKTOP_CHUNK_BYTES - 1U) / DIRECTGATE_DESKTOP_CHUNK_BYTES);
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

/* A media track may be open while the browser receives no decodable frame
 * (lost first IDR, decoder rejection, or a half-open route after TURN/P2P
 * replacement). In that case the browser explicitly asks for the already
 * supported encrypted H.264 data-channel path. Keep that choice latched for
 * this desktop session so a later RTCP PLI cannot immediately promote the
 * same broken media track and start a black-screen loop. */
xbool_t DirectGate_Desktop_FallbackToDataChannel(directgate_session_t *pSession)
{
    XCHECK_NL((pSession != NULL), XFALSE);
    directgate_desktop_t *pDesktop = &pSession->desktop;

    if (pDesktop->bForceRaw ||
        (pDesktop->ePipeline != DIRECTGATE_DESKTOP_PIPELINE_WEBRTC_VIDEO &&
         pDesktop->ePipeline != DIRECTGATE_DESKTOP_PIPELINE_H264_DC))
        return XFALSE;

    pDesktop->bPreferDataChannel = XTRUE;
    pDesktop->bWebRTCVideoFailed = XTRUE;
    pDesktop->ePipeline = DIRECTGATE_DESKTOP_PIPELINE_H264_DC;

    DirectGate_Desktop_SetFallbackReason(pDesktop,
        "Browser did not receive WebRTC video; using encrypted H.264 data channel.");
    DirectGate_Desktop_SendStatus(pSession, "streaming", NULL);

    xlogw("WebRTC video handoff timed out, using data-channel fallback: sid(%u)", pSession->nSessionId);
    return XTRUE;
}

xbool_t DirectGate_Desktop_ShouldSkipForBackpressure(const directgate_session_t *pSession)
{
    XCHECK_NL((pSession != NULL), XFALSE);
    if (pSession->desktop.ePipeline == DIRECTGATE_DESKTOP_PIPELINE_WEBRTC_VIDEO) return XFALSE;

    int nBuffered = DirectGate_WebRTC_GetBufferedAmount(&pSession->webrtc);
    if (nBuffered < 0) return XFALSE;
    return ((size_t)nBuffered > DIRECTGATE_DESKTOP_ENCODED_BUFFER_LIMIT) ? XTRUE : XFALSE;
}

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

void DirectGate_Desktop_LimitFrameSize(const directgate_desktop_t *pDesktop,
                                       uint32_t *pWidth, uint32_t *pHeight)
{
    uint32_t nWidth = (pWidth != NULL && *pWidth) ? *pWidth : 1U;
    uint32_t nHeight = (pHeight != NULL && *pHeight) ? *pHeight : 1U;
    DirectGate_Desktop_ComputeOutputSize(pDesktop, nWidth, nHeight, pWidth, pHeight);
}

void DirectGate_Desktop_ReadResizeRequest(directgate_desktop_t *pDesktop, xjson_obj_t *pRoot)
{
    XCHECK_VOID_NL((pDesktop != NULL && pRoot != NULL));
    const char *pMode = XJSON_GetString(XJSON_GetObject(pRoot, "mode"));
    uint32_t nWidth = XJSON_GetU32(XJSON_GetObject(pRoot, "width"));
    uint32_t nHeight = XJSON_GetU32(XJSON_GetObject(pRoot, "height"));

    if (xstrcmp(pMode, "display")) pDesktop->eResizeMode = DIRECTGATE_DESKTOP_RESIZE_DISPLAY;
    else if (xstrcmp(pMode, "scale")) pDesktop->eResizeMode = DIRECTGATE_DESKTOP_RESIZE_SCALE;

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
    pDesktop->bPreferDataChannel = XFALSE;
    pDesktop->sFallbackReason[0] = '\0';
    xstrncpy(pDesktop->sCodec, sizeof(pDesktop->sCodec), "raw-rgba");
    DirectGate_Desktop_ApplyPreset(pDesktop, DIRECTGATE_DESKTOP_PRESET_BALANCED);

#if defined(__APPLE__) || defined(__linux__) || defined(_WIN32)
    const char *pForce = getenv("DIRECTGATE_DESKTOP_FORCE_RAW");
    if (xstrused(pForce) && pForce[0] != '0') pDesktop->bForceRaw = XTRUE;

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
    if (pDesktop->pEncoder != NULL) DirectGate_Desktop_LinuxEncoder_StopDesktop(pDesktop);
    DirectGate_Desktop_RestoreDisplayMode(pDesktop);

    if (pDesktop->pDisplay != NULL && pDesktop->nScratchKeycode != 0U)
    {
        KeySym clearSyms[2] = { NoSymbol, NoSymbol };
        XChangeKeyboardMapping((Display*)pDesktop->pDisplay, (int)pDesktop->nScratchKeycode, 2, clearSyms, 1);
        XSync((Display*)pDesktop->pDisplay, XFALSE);
    }

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
    if (pDesktop->pEncoder != NULL) DirectGate_Desktop_WinEncoder_StopDesktop(pDesktop);
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

    pDesktop->eResizeMode = DIRECTGATE_DESKTOP_RESIZE_SCALE;
    pDesktop->ePipeline = DIRECTGATE_DESKTOP_PIPELINE_RAW;
    pDesktop->bRunning = XFALSE;
    pDesktop->bInputReady = XFALSE;
    pDesktop->bCaptureReady = XFALSE;
    pDesktop->bDisplayModeChanged = XFALSE;
    pDesktop->bRequestKeyframe = XFALSE;
    pDesktop->bWebRTCVideoFailed = XFALSE;
    pDesktop->bPreferDataChannel = XFALSE;
    pDesktop->pOriginalDisplayMode = NULL;
    pDesktop->pFakeRelativeMotion = NULL;
    pDesktop->pFakeMotion = NULL;
    pDesktop->pFakeButton = NULL;
    pDesktop->pFakeKey = NULL;
    pDesktop->pEncoder = NULL;
    pDesktop->nFrameId = 0;
    pDesktop->nScreenWidth = 0;
    pDesktop->nScreenHeight = 0;
    pDesktop->nCaptureX = 0;
    pDesktop->nCaptureY = 0;
    pDesktop->nCaptureWidth = 0;
    pDesktop->nCaptureHeight = 0;
    pDesktop->nFrameWidth = 0;
    pDesktop->nFrameHeight = 0;
    pDesktop->nTargetWidth = 0;
    pDesktop->nTargetHeight = 0;
    pDesktop->nPointerButtons = 0;
    pDesktop->nPointerSequence = 0;
    pDesktop->nWheelAccumX = 0;
    pDesktop->nWheelAccumY = 0;
    pDesktop->nLastClickMs = 0;
    pDesktop->nLastClickX = 0;
    pDesktop->nLastClickY = 0;
    pDesktop->nClickCount = 0;
    pDesktop->nLastClickButton = 0;
    pDesktop->nInputRecheckMs = 0;
    pDesktop->nScratchKeycode = 0;
    pDesktop->nScratchKeysym = 0;
    pDesktop->nMonitorCount = 0;
    pDesktop->sSelectedMonitor[0] = '\0';
    pDesktop->sInputReason[0] = '\0';
    pDesktop->sFallbackReason[0] = '\0';
    memset(pDesktop->monitors, 0, sizeof(pDesktop->monitors));
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

int DirectGate_Desktop_SendStatus(directgate_session_t *pSession, const char *pStatus, const char *pReason)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);

    xjson_obj_t *pRoot = XJSON_NewObject(NULL, NULL, XFALSE);
    XCHECK((pRoot != NULL), XAPI_DISCONNECT);

    XJSON_AddString(pRoot, "status", xstrused(pStatus) ? pStatus : "unknown");
    XJSON_AddString(pRoot, "backend", xstrused(pSession->desktop.sBackend) ? pSession->desktop.sBackend : "unknown");
    XJSON_AddString(pRoot, "display", xstrused(pSession->desktop.sDisplay) ? pSession->desktop.sDisplay : "");
    XJSON_AddString(pRoot, "codec", xstrused(pSession->desktop.sCodec) ? pSession->desktop.sCodec : "raw-rgba");
    XJSON_AddString(pRoot, "pipeline", DirectGate_Desktop_PipelineName(pSession->desktop.ePipeline));
    XJSON_AddString(pRoot, "preset", DirectGate_Desktop_PresetName(pSession->desktop.quality.ePreset));
    XJSON_AddString(pRoot, "transport", DirectGate_Desktop_TransportName(pSession->desktop.ePipeline));
    XJSON_AddString(pRoot, "resizeMode", DirectGate_Desktop_ResizeModeName(pSession->desktop.eResizeMode));
    XJSON_AddStrIfUsed(pRoot, "inputReason", pSession->desktop.sInputReason);
    XJSON_AddStrIfUsed(pRoot, "fallbackReason", pSession->desktop.sFallbackReason);
    XJSON_AddStrIfUsed(pRoot, "selectedMonitor", pSession->desktop.sSelectedMonitor);
    XJSON_AddBool(pRoot, "input", pSession->desktop.bInputReady);
    XJSON_AddBool(pRoot, "textInput", XTRUE);
    XJSON_AddBool(pRoot, "cursorSync", XTRUE);
    XJSON_AddBool(pRoot, "p2pMigration", XTRUE);
    XJSON_AddBool(pRoot, "captureReady", pSession->desktop.bCaptureReady);
    XJSON_AddBool(pRoot, "fallbackRaw", pSession->desktop.bForceRaw);
    XJSON_AddU32(pRoot, "fps", pSession->desktop.quality.nFps);
    XJSON_AddU32(pRoot, "frameWidth", pSession->desktop.nFrameWidth);
    XJSON_AddU32(pRoot, "frameHeight", pSession->desktop.nFrameHeight);
    XJSON_AddU32(pRoot, "targetWidth", pSession->desktop.nTargetWidth);
    XJSON_AddU32(pRoot, "targetHeight", pSession->desktop.nTargetHeight);
    XJSON_AddU32(pRoot, "screenWidth", pSession->desktop.nScreenWidth);
    XJSON_AddU32(pRoot, "screenHeight", pSession->desktop.nScreenHeight);
    XJSON_AddU32(pRoot, "bitrateKbps", pSession->desktop.nCurrentBitrateKbps ?
        pSession->desktop.nCurrentBitrateKbps : pSession->desktop.quality.nBitrateKbps);

#if defined(_WIN32)
    XJSON_AddBool(pRoot, "fastInput", XTRUE);
#else
    XJSON_AddBool(pRoot, "fastInput", XFALSE);
#endif

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

void DirectGate_Desktop_SendCursorPosition(directgate_session_t *pSession,
                                           int nScreenX, int nScreenY,
                                           uint32_t nSequence)
{
    XCHECK_VOID_NL((pSession != NULL));
    directgate_desktop_t *pDesktop = &pSession->desktop;

    uint32_t nWidth = pDesktop->nCaptureWidth ? pDesktop->nCaptureWidth : 1U;
    uint32_t nHeight = pDesktop->nCaptureHeight ? pDesktop->nCaptureHeight : 1U;
    int64_t nX = (int64_t)nScreenX - pDesktop->nCaptureX;
    int64_t nY = (int64_t)nScreenY - pDesktop->nCaptureY;

    if (nX < 0) nX = 0;
    if (nY < 0) nY = 0;
    if ((uint64_t)nX >= nWidth) nX = (int64_t)nWidth - 1;
    if ((uint64_t)nY >= nHeight) nY = (int64_t)nHeight - 1;

    xjson_obj_t *pHeader = DirectGate_Proto_BuildData(pSession->nSessionId);
    if (pHeader == NULL) return;

    XJSON_AddString(pHeader, "payloadType", "desktop-cursor");
    XJSON_AddInt(pHeader, "x", (int)nX);
    XJSON_AddInt(pHeader, "y", (int)nY);
    XJSON_AddU32(pHeader, "screenWidth", nWidth);
    XJSON_AddU32(pHeader, "screenHeight", nHeight);
    XJSON_AddU32(pHeader, "sequence", nSequence);

    (void)DirectGate_Session_Send(pSession, pHeader, NULL, 0);
    XJSON_FreeObject(pHeader);
}

xbool_t DirectGate_Desktop_ClampCursorToCapture(const directgate_desktop_t *pDesktop, int *pScreenX, int *pScreenY)
{
    if (pDesktop == NULL || pScreenX == NULL || pScreenY == NULL || !pDesktop->bCaptureReady ||
        !xstrused(pDesktop->sSelectedMonitor) || xstrcmp(pDesktop->sSelectedMonitor, "all") ||
        !pDesktop->nCaptureWidth || !pDesktop->nCaptureHeight) return XFALSE;

    int nOriginalX = *pScreenX;
    int nOriginalY = *pScreenY;

    int64_t nMaxX = (int64_t)pDesktop->nCaptureX + pDesktop->nCaptureWidth - 1;
    int64_t nMaxY = (int64_t)pDesktop->nCaptureY + pDesktop->nCaptureHeight - 1;

    if (*pScreenX < pDesktop->nCaptureX) *pScreenX = pDesktop->nCaptureX;
    else if ((int64_t)*pScreenX > nMaxX) *pScreenX = (int)nMaxX;

    if (*pScreenY < pDesktop->nCaptureY) *pScreenY = pDesktop->nCaptureY;
    else if ((int64_t)*pScreenY > nMaxY) *pScreenY = (int)nMaxY;

    return (*pScreenX != nOriginalX || *pScreenY != nOriginalY) ? XTRUE : XFALSE;
}

/* Shared geometry and monitor-table helpers. The bodies are identical across
 * the supported platforms; a single definition (with a small #ifdef for the
 * default monitor id) replaces what used to be one copy per platform block. */
void DirectGate_Desktop_ComputeFrameSize(directgate_desktop_t *pDesktop)
{
    uint32_t nWidth = pDesktop->nCaptureWidth ? pDesktop->nCaptureWidth : pDesktop->nScreenWidth;
    uint32_t nHeight = pDesktop->nCaptureHeight ? pDesktop->nCaptureHeight : pDesktop->nScreenHeight;

    if (!nWidth) nWidth = 1;
    if (!nHeight) nHeight = 1;
    DirectGate_Desktop_LimitFrameSize(pDesktop, &nWidth, &nHeight);

    pDesktop->nFrameWidth = nWidth;
    pDesktop->nFrameHeight = nHeight;
}

void DirectGate_Desktop_SetCapture(directgate_desktop_t *pDesktop,
                                    const char *pMonitorId,
                                    int32_t nX,
                                    int32_t nY,
                                    uint32_t nWidth,
                                    uint32_t nHeight)
{
    XCHECK_VOID_NL((pDesktop != NULL));

    pDesktop->bCaptureReady = XTRUE;
    pDesktop->nCaptureX = nX;
    pDesktop->nCaptureY = nY;
    pDesktop->nCaptureWidth = nWidth ? nWidth : pDesktop->nScreenWidth;
    pDesktop->nCaptureHeight = nHeight ? nHeight : pDesktop->nScreenHeight;
    xstrncpy(pDesktop->sSelectedMonitor, sizeof(pDesktop->sSelectedMonitor),
        xstrused(pMonitorId) ? pMonitorId : "all");

    DirectGate_Desktop_ComputeFrameSize(pDesktop);
}

void DirectGate_Desktop_AddMonitor(directgate_desktop_t *pDesktop,
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
#if defined(__linux__)
    xstrncpy(pMonitor->sId, sizeof(pMonitor->sId), xstrused(pId) ? pId : "monitor");
#else
    xstrncpy(pMonitor->sId, sizeof(pMonitor->sId), xstrused(pId) ? pId : "display");
#endif
    xstrncpy(pMonitor->sName, sizeof(pMonitor->sName), xstrused(pName) ? pName : pMonitor->sId);

    pMonitor->nX = nX;
    pMonitor->nY = nY;
    pMonitor->nWidth = nWidth;
    pMonitor->nHeight = nHeight;
    pMonitor->bPrimary = bPrimary;
}

const directgate_desktop_monitor_t* DirectGate_Desktop_FindMonitor(const directgate_desktop_t *pDesktop, const char *pMonitorId)
{
    if (pDesktop == NULL || !xstrused(pMonitorId)) return NULL;

    for (uint32_t i = 0; i < pDesktop->nMonitorCount; i++)
    {
        if (xstrcmp(pDesktop->monitors[i].sId, pMonitorId))
            return &pDesktop->monitors[i];
    }

    return NULL;
}
