/*!
 * @file directgate-agent/src/agent/desktop.h
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

#ifndef __DIRECTGATE_DESKTOP_H__
#define __DIRECTGATE_DESKTOP_H__

#include "includes.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DIRECTGATE_DESKTOP_BACKEND_LEN 16
#define DIRECTGATE_DESKTOP_REASON_LEN  160
#define DIRECTGATE_DESKTOP_DISPLAY_LEN 128
#define DIRECTGATE_DESKTOP_MONITOR_ID_LEN   32
#define DIRECTGATE_DESKTOP_MONITOR_NAME_LEN 96
#define DIRECTGATE_DESKTOP_MAX_MONITORS     16
#define DIRECTGATE_DESKTOP_CODEC_LEN        16
#define DIRECTGATE_DESKTOP_PRESET_LEN       16
#define DIRECTGATE_DESKTOP_PIPELINE_LEN     24
#define DIRECTGATE_DESKTOP_TRANSPORT_LEN    32
#define DIRECTGATE_DESKTOP_DEVICE_ID_LEN    128

/* Encoded desktop frame transport (cross-platform).
 * Chunk size matches the raw-RGBA path so the relay/WebRTC fragments stay
 * predictable. Each chunk goes through DirectGate_Session_Send and therefore
 * benefits from the standard AES-SIV E2E wrapping. */
/* 64 KB balances libdatachannel SCTP throughput against the cost of the
 * per-chunk JSON+AES-SIV+send round-trip the main loop pays. Going below
 * ~32 KB starts adding noticeable encoder-to-wire latency on IDR-sized
 * frames; going above ~128 KB starts head-of-line-blocking smaller
 * messages on the data channel. */
#define DIRECTGATE_DESKTOP_CHUNK_BYTES      (64U * 1024U)

typedef enum {
    DIRECTGATE_DESKTOP_PIPELINE_RAW = 0,    /* legacy raw RGBA fallback/debug */
    DIRECTGATE_DESKTOP_PIPELINE_H264_DC,    /* H.264 chunks over encrypted DataChannel */
    DIRECTGATE_DESKTOP_PIPELINE_WEBRTC_VIDEO/* H.264 RTP over WebRTC media track */
} directgate_desktop_pipeline_t;

typedef enum {
    DIRECTGATE_DESKTOP_PRESET_BALANCED = 0, /* 1080p 30fps 8 Mbps (default) */
    DIRECTGATE_DESKTOP_PRESET_QUALITY,      /* 1080p 30fps 12 Mbps */
    DIRECTGATE_DESKTOP_PRESET_LOW_LATENCY   /*  720p 30fps 4 Mbps */
} directgate_desktop_preset_t;

typedef enum {
    DIRECTGATE_DESKTOP_RESIZE_SCALE = 0,
    DIRECTGATE_DESKTOP_RESIZE_DISPLAY
} directgate_desktop_resize_mode_t;

typedef struct directgate_desktop_quality_ {
    directgate_desktop_preset_t ePreset;
    uint32_t nMaxEdge;       /* longest edge of encoded output, e.g. 1920 */
    uint32_t nFps;           /* target capture/encode FPS */
    uint32_t nBitrateKbps;   /* hardware encoder bitrate target */
    uint32_t nKeyframeFrames;/* GOP length, in frames */
    xbool_t bRealtime;       /* enables low-latency encoder hints */
} directgate_desktop_quality_t;

typedef struct directgate_session_ directgate_session_t;

typedef struct directgate_desktop_monitor_ {
    char sId[DIRECTGATE_DESKTOP_MONITOR_ID_LEN];
    char sName[DIRECTGATE_DESKTOP_MONITOR_NAME_LEN];
    int32_t nX;
    int32_t nY;
    uint32_t nWidth;
    uint32_t nHeight;
    xbool_t bPrimary;
    /* Native display identifier. It is intentionally not exposed over the
     * wire: Linux stores the XRandR monitor index, Windows the display device
     * name, and macOS the CGDirectDisplayID. */
    char sDeviceId[DIRECTGATE_DESKTOP_DEVICE_ID_LEN];
    uint64_t nNativeId;
} directgate_desktop_monitor_t;

typedef struct directgate_desktop_ {
    xbool_t bRunning;
    xbool_t bInputReady;
    xbool_t bCaptureReady;
    /* POSIX: timerfd (Linux) / pipe read end (macOS); Windows: socket pair
     * read end (XSOCKET == int on POSIX, SOCKET on Windows). */
    XSOCKET nTimerFd;
    uint32_t nSessionId;
    uint32_t nScreenWidth;
    uint32_t nScreenHeight;
    int32_t nCaptureX;
    int32_t nCaptureY;
    uint32_t nCaptureWidth;
    uint32_t nCaptureHeight;
    uint32_t nFrameWidth;
    uint32_t nFrameHeight;
    directgate_desktop_resize_mode_t eResizeMode;
    uint32_t nTargetWidth;
    uint32_t nTargetHeight;
    xbool_t bDisplayModeChanged;
    char sModeMonitorId[DIRECTGATE_DESKTOP_MONITOR_ID_LEN];
    char sModeDeviceId[DIRECTGATE_DESKTOP_DEVICE_ID_LEN];
    uint64_t nModeNativeId;
    uint64_t nOriginalModeId;
    int32_t nOriginalModeX;
    int32_t nOriginalModeY;
    uint32_t nOriginalModeWidth;
    uint32_t nOriginalModeHeight;
    uint32_t nOriginalModeRefresh;
    uint32_t nOriginalModeRotation;
    void *pOriginalDisplayMode;
    uint32_t nFps;
    uint32_t nPointerButtons;
    uint64_t nFrameId;
    uint32_t nMonitorCount;
    directgate_desktop_monitor_t monitors[DIRECTGATE_DESKTOP_MAX_MONITORS];
    char sBackend[DIRECTGATE_DESKTOP_BACKEND_LEN];
    char sReason[DIRECTGATE_DESKTOP_REASON_LEN];
    char sDisplay[DIRECTGATE_DESKTOP_DISPLAY_LEN];
    char sSelectedMonitor[DIRECTGATE_DESKTOP_MONITOR_ID_LEN];
    void *pDisplay;
    void *pXtst;
    void *pFakeMotion;
    void *pFakeButton;
    void *pFakeKey;
    /* Encoded pipeline state */
    directgate_desktop_pipeline_t ePipeline;
    directgate_desktop_quality_t quality;
    char sCodec[DIRECTGATE_DESKTOP_CODEC_LEN];
    char sFallbackReason[DIRECTGATE_DESKTOP_REASON_LEN];
    xbool_t bForceRaw;       /* true when fallback raw RGBA path is forced */
    xbool_t bRequestKeyframe;/* set by preset change / drop recovery */
    xbool_t bWebRTCVideoFailed; /* suppress retry until track/ICE recovery */
    /* Adaptive bitrate controller state: current encoder rate (<= preset
     * target), ticks since the last congestion signal, and the cooldown
     * ticks left before the next downward step is allowed. */
    uint32_t nCurrentBitrateKbps;
    uint32_t nAbrCleanTicks;
    uint32_t nAbrHoldTicks;
    /* Platform encoder state (opaque to cross-platform code): the macOS
     * ScreenCaptureKit/VideoToolbox encoder, the Linux X11/OpenH264
     * pipeline or the Windows DXGI/MediaFoundation pipeline, owned by
     * desktop_mac.m / desktop_linux.c / desktop_win.c respectively. */
    void *pEncoder;
#if defined(__APPLE__) || defined(_WIN32)
    /* macOS and Windows have no timerfd: a pipe/socket pair plus a timer
     * thread emulate the periodic wake-up (write end below, read end in
     * nTimerFd). Platform encoders also write to the pair to wake the main
     * loop as soon as an encoded frame lands in their mailbox. */
    XSOCKET nTimerWriteFd;
    xbool_t bTimerThreadRunning;
#endif
#if defined(__APPLE__)
    pthread_t timerThread;
#elif defined(_WIN32)
    void *pTimerThread;      /* HANDLE of the tick thread */
#endif
} directgate_desktop_t;

void DirectGate_Desktop_Init(directgate_desktop_t *pDesktop);
void DirectGate_Desktop_Clear(directgate_desktop_t *pDesktop);
void DirectGate_Desktop_DetachEvent(directgate_desktop_t *pDesktop);

int DirectGate_Desktop_Start(directgate_session_t *pSession);
int DirectGate_Desktop_Process(directgate_session_t *pSession);
int DirectGate_Desktop_HandleInput(directgate_session_t *pSession,
                               const uint8_t *pPayload,
                               size_t nPayloadLength);
int DirectGate_Desktop_HandleControl(directgate_session_t *pSession,
                                 const uint8_t *pPayload,
                                 size_t nPayloadLength);

int DirectGate_Desktop_GetTimerFd(const directgate_desktop_t *pDesktop);
xbool_t DirectGate_Desktop_IsRunning(const directgate_desktop_t *pDesktop);
const char* DirectGate_Desktop_GetReason(const directgate_desktop_t *pDesktop);

/* Cross-platform encoded-frame send. The encoded payload is split into
 * DIRECTGATE_DESKTOP_CHUNK_BYTES-sized chunks; each chunk goes through the
 * standard DirectGate_Session_Send path (E2E-encrypted, WebRTC-preferred). */
int DirectGate_Desktop_SendEncodedFrame(directgate_session_t *pSession,
                                    const uint8_t *pPayload,
                                    size_t nPayloadLength,
                                    uint32_t nWidth,
                                    uint32_t nHeight,
                                    xbool_t bKeyframe,
                                    uint64_t nPtsUs);

/* Preset helpers (shared by platform encoders + control message handler). */
void DirectGate_Desktop_ApplyPreset(directgate_desktop_t *pDesktop, directgate_desktop_preset_t ePreset);
const char* DirectGate_Desktop_PresetName(directgate_desktop_preset_t ePreset);
const char* DirectGate_Desktop_PipelineName(directgate_desktop_pipeline_t ePipeline);
const char* DirectGate_Desktop_ResizeModeName(directgate_desktop_resize_mode_t eMode);

/* Chooses the encoded dimensions for a capture rectangle. An explicit scale
 * target is an aspect-fit box and never permits upscaling. Display mode sends
 * the capture at its native size because the OS display itself was resized. */
void DirectGate_Desktop_ComputeOutputSize(const directgate_desktop_t *pDesktop,
                                          uint32_t nSourceWidth, uint32_t nSourceHeight,
                                          uint32_t *pWidth, uint32_t *pHeight);

/* True while the transport (WebRTC data channel) is too backed up to accept
 * another frame; platform encoders skip the capture entirely in that case. */
xbool_t DirectGate_Desktop_ShouldSkipForBackpressure(const directgate_session_t *pSession);

#if defined(__APPLE__)
/* Returns an owned CGImageRef as an opaque pointer. The caller must release it
 * with CGImageRelease. Keeping the CoreGraphics type out of this header avoids
 * leaking Apple framework headers into cross-platform translation units. */
void* DirectGate_Desktop_MacCaptureImage(int32_t nX, int32_t nY,
                                     uint32_t nWidth, uint32_t nHeight,
                                     char *pError, size_t nErrorSize);

/* ScreenCaptureKit + VideoToolbox encoder lifecycle. Implemented in
 * desktop_mac.m and only called by desktop.c on Darwin. */
int DirectGate_Desktop_MacEncoder_Start(directgate_session_t *pSession,
                                    int32_t nX, int32_t nY,
                                    uint32_t nWidth, uint32_t nHeight);
int DirectGate_Desktop_MacEncoder_UpdateRect(directgate_session_t *pSession,
                                        int32_t nX, int32_t nY,
                                        uint32_t nWidth, uint32_t nHeight);
void DirectGate_Desktop_MacEncoder_ApplyQuality(directgate_session_t *pSession);
void DirectGate_Desktop_MacEncoder_SetBitrate(directgate_session_t *pSession, uint32_t nBitrateKbps);
void DirectGate_Desktop_MacEncoder_RequestKeyframe(directgate_session_t *pSession);
void DirectGate_Desktop_MacEncoder_Stop(directgate_session_t *pSession);
void DirectGate_Desktop_MacEncoder_StopDesktop(directgate_desktop_t *pDesktop);
const char* DirectGate_Desktop_MacEncoder_LastError(const directgate_session_t *pSession);

/* Drains the encoder mailbox on the main loop. Called from
 * DirectGate_Desktop_Process after the timer pipe wakes the loop. */
int DirectGate_Desktop_MacEncoder_DrainMain(directgate_session_t *pSession);
#endif

#if defined(__linux__)
/* X11 (XShm) capture + OpenH264 encoder pipeline. Implemented in
 * desktop_linux.c and only called by desktop.c on Linux. */
int DirectGate_Desktop_LinuxEncoder_Start(directgate_session_t *pSession,
                                      int32_t nX, int32_t nY,
                                      uint32_t nWidth, uint32_t nHeight);
void DirectGate_Desktop_LinuxEncoder_ApplyQuality(directgate_session_t *pSession);
void DirectGate_Desktop_LinuxEncoder_SetBitrate(directgate_session_t *pSession, uint32_t nBitrateKbps);
void DirectGate_Desktop_LinuxEncoder_RequestKeyframe(directgate_session_t *pSession);
void DirectGate_Desktop_LinuxEncoder_Stop(directgate_session_t *pSession);
void DirectGate_Desktop_LinuxEncoder_StopDesktop(directgate_desktop_t *pDesktop);
const char* DirectGate_Desktop_LinuxEncoder_LastError(const directgate_session_t *pSession);

/* True after too many consecutive capture/encode failures; desktop.c then
 * demotes the session to the raw RGBA pipeline. */
xbool_t DirectGate_Desktop_LinuxEncoder_HasFailed(const directgate_session_t *pSession);

/* Captures, encodes and sends one frame. Called from
 * DirectGate_Desktop_Process on every timer tick while an encoded
 * pipeline is active. */
int DirectGate_Desktop_LinuxEncoder_ProcessTick(directgate_session_t *pSession);
#endif

#if defined(_WIN32)
/* DXGI Desktop Duplication (GDI fallback) capture + Media Foundation H.264
 * encoder pipeline. Implemented in desktop_win.c and only called by
 * desktop.c on Windows. Capture and encode run on a dedicated thread (the
 * push model of desktop_mac.m); encoded frames land in a single-slot
 * mailbox drained by DirectGate_Desktop_WinEncoder_DrainMain on the main
 * loop after a timer-pair wake-up. */
int DirectGate_Desktop_WinEncoder_Start(directgate_session_t *pSession,
                                    int32_t nX, int32_t nY,
                                    uint32_t nWidth, uint32_t nHeight);
void DirectGate_Desktop_WinEncoder_ApplyQuality(directgate_session_t *pSession);
void DirectGate_Desktop_WinEncoder_SetBitrate(directgate_session_t *pSession, uint32_t nBitrateKbps);
void DirectGate_Desktop_WinEncoder_RequestKeyframe(directgate_session_t *pSession);
void DirectGate_Desktop_WinEncoder_StopDesktop(directgate_desktop_t *pDesktop);
const char* DirectGate_Desktop_WinEncoder_LastError(const directgate_session_t *pSession);

/* True after too many consecutive capture/encode failures; desktop.c then
 * demotes the session to the raw RGBA pipeline. */
xbool_t DirectGate_Desktop_WinEncoder_HasFailed(const directgate_session_t *pSession);

/* Drains the encoder mailbox on the main loop. Called from
 * DirectGate_Desktop_Process after the timer pair wakes the loop. */
int DirectGate_Desktop_WinEncoder_DrainMain(directgate_session_t *pSession);
#endif

#ifdef __cplusplus
}
#endif

#endif
