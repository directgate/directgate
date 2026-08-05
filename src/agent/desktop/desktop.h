/*!
 * @file directgate-agent/src/agent/desktop/desktop.h
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

#define DIRECTGATE_DESKTOP_BACKEND_LEN       16
#define DIRECTGATE_DESKTOP_REASON_LEN        160
#define DIRECTGATE_DESKTOP_DISPLAY_LEN       128
#define DIRECTGATE_DESKTOP_MONITOR_ID_LEN    32
#define DIRECTGATE_DESKTOP_MONITOR_NAME_LEN  96
#define DIRECTGATE_DESKTOP_MAX_MONITORS      16
#define DIRECTGATE_DESKTOP_MAX_MODES         64
#define DIRECTGATE_DESKTOP_CODEC_LEN         16
#define DIRECTGATE_DESKTOP_RESOLUTION_LEN    16
#define DIRECTGATE_DESKTOP_KEY_CODE_LEN      24
#define DIRECTGATE_DESKTOP_MAX_HELD_KEYS     32
#define DIRECTGATE_DESKTOP_MAX_SCRATCH_KEYS  48
#define DIRECTGATE_DESKTOP_PRESET_LEN        16
#define DIRECTGATE_DESKTOP_PIPELINE_LEN      24
#define DIRECTGATE_DESKTOP_TRANSPORT_LEN     32
#define DIRECTGATE_DESKTOP_DEVICE_ID_LEN     128
#define DIRECTGATE_DESKTOP_TURN_BITRATE_KBPS 4000U

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
    DIRECTGATE_DESKTOP_PRESET_LOW_LATENCY   /*  gaming: 720p60 on all platforms */
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
    /* The preset's own figure, before it is scaled for the encode size.
     * Kept so the scaling stays idempotent across pipeline rebuilds. */
    uint32_t nBaseBitrateKbps;
    uint32_t nKeyframeFrames;/* GOP length, in frames */
    xbool_t bRealtime;       /* enables low-latency encoder hints */
} directgate_desktop_quality_t;

typedef struct directgate_session_ directgate_session_t;

typedef struct directgate_desktop_mode_ {
    uint32_t nWidth;
    uint32_t nHeight;
} directgate_desktop_mode_t;

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
    uint32_t nModeCount;
    directgate_desktop_mode_t modes[DIRECTGATE_DESKTOP_MAX_MODES];
} directgate_desktop_monitor_t;

typedef struct directgate_desktop_held_key_ {
    char sCode[DIRECTGATE_DESKTOP_KEY_CODE_LEN];
    uint32_t nKeycode;
    /* Whether nKeycode is a physical key or a character: a Wayland session
     * releases the two through different portal calls, and releasing one as
     * the other leaves the key down for good. */
    xbool_t bPhysical;
} directgate_desktop_held_key_t;

/* One spare X11 keycode and the keysym currently bound to it. */
typedef struct directgate_desktop_scratch_key_ {
    uint32_t nKeycode;
    uint64_t nKeysym;   /* NoSymbol while the slot is unused */
    uint64_t nUsedSeq;  /* Monotonic use counter, drives LRU reclaim */
    xbool_t bHeld;      /* Injected press outstanding, must not be rebound */
} directgate_desktop_scratch_key_t;

typedef struct directgate_desktop_ {
    xbool_t bRunning;
    xbool_t bInputReady;
    xbool_t bCaptureReady;
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
    char sResolution[DIRECTGATE_DESKTOP_RESOLUTION_LEN];
    uint32_t nSettingsRevision;
    uint32_t nTargetWidth;
    uint32_t nTargetHeight;
    xbool_t bDisplayModeChanged;
    uint64_t nModeNativeId;
    uint64_t nOriginalModeId;
    int32_t nOriginalModeX;
    int32_t nOriginalModeY;
    uint32_t nOriginalModeWidth;
    uint32_t nOriginalModeHeight;
    uint32_t nOriginalModeRefresh;
    uint32_t nOriginalModeRotation;
    uint32_t nFps;
    uint32_t nPointerButtons;
    uint32_t nPointerSequence;
    /* Browsers report wheel motion in pixels (trackpads emit many small
     * samples); the accumulators collect them into whole wheel notches on
     * the platforms that inject discrete wheel clicks (X11 / Windows). */
    int32_t nWheelAccumX;
    int32_t nWheelAccumY;
    /* Wayland: where the agent last put the pointer, in capture-local pixels.
     * The other platforms ask the display server where the pointer is; a
     * Wayland client is never told, so mouse capture integrates the browser's
     * relative deltas here and replays them as absolute portal motion. That
     * also keeps the cursor the browser draws and the pointer the compositor
     * moves on the same arithmetic - relative portal motion is accelerated by
     * the compositor, and the two would part company within a second. */
    double nWlPointerX;
    double nWlPointerY;
    xbool_t bWlPointerValid;
    /* Double/triple click tracking for platforms where the injected event
     * must carry an explicit click count (macOS kCGMouseEventClickState). */
    uint64_t nLastClickMs;
    int32_t nLastClickX;
    int32_t nLastClickY;
    uint32_t nClickCount;
    uint32_t nLastClickButton;
    /* macOS: last accessibility-permission recheck while input is disabled. */
    uint64_t nInputRecheckMs;
    /* When the last input event of any kind arrived, for the held-key
     * watchdog: a release that is lost in flight (or that the browser never
     * saw, because a reserved shortcut stole the keyup) would otherwise leave
     * a modifier down on the host until the session ends. */
    uint64_t nLastInputMs;
    /* X11: spare keycodes temporarily bound to keysyms missing from the
     * active layout (e.g. non-Latin text typed from the browser). Bindings
     * persist so a repeated character reuses its slot instead of rewriting
     * the keymap, which applications observe asynchronously. */
    uint32_t nScratchCount;
    uint64_t nScratchSeq;
    xbool_t bScratchProbed;
    directgate_desktop_scratch_key_t scratchKeys[DIRECTGATE_DESKTOP_MAX_SCRATCH_KEYS];
    uint32_t nHeldKeyCount;
    uint64_t nFrameId;
    uint32_t nMonitorCount;
    directgate_desktop_held_key_t heldKeys[DIRECTGATE_DESKTOP_MAX_HELD_KEYS];
    directgate_desktop_monitor_t monitors[DIRECTGATE_DESKTOP_MAX_MONITORS];
    char sBackend[DIRECTGATE_DESKTOP_BACKEND_LEN];
    char sReason[DIRECTGATE_DESKTOP_REASON_LEN];
    /* Why bInputReady is false (surfaced to the browser in desktop-status
     * as `inputReason`, e.g. a missing macOS Accessibility permission). */
    char sInputReason[DIRECTGATE_DESKTOP_REASON_LEN];
    char sDisplay[DIRECTGATE_DESKTOP_DISPLAY_LEN];
    char sSelectedMonitor[DIRECTGATE_DESKTOP_MONITOR_ID_LEN];
    char sModeMonitorId[DIRECTGATE_DESKTOP_MONITOR_ID_LEN];
    char sModeDeviceId[DIRECTGATE_DESKTOP_DEVICE_ID_LEN];
    char sFallbackReason[DIRECTGATE_DESKTOP_REASON_LEN];
    char sCodec[DIRECTGATE_DESKTOP_CODEC_LEN];
    void *pOriginalDisplayMode;
    void *pFakeRelativeMotion;
    void *pFakeMotion;
    void *pFakeButton;
    void *pFakeKey;
    void *pDisplay;
    void *pXtst;
    /* One-shot: the raw capture path cannot work on a Wayland session, and
     * the tick would otherwise report that every frame for the rest of it. */
    xbool_t bWarnedWaylandRaw;
    /* The granted Wayland stream has ended (revoked from the remote screen or
     * broken). Reported once; the tick has nothing left to do after it. */
    xbool_t bWaylandLost;
    /* The Wayland portal prompt is on someone's screen and the session is
     * running only to wait for it: no capture, no input, nothing to encode
     * until they answer. Answering can take minutes, so the wait belongs on
     * the tick rather than in the call that started the session. */
    xbool_t bAwaitingGrant;
    /* directgate_wl_source_t on a Wayland session; NULL everywhere else. It
     * outlives a failed start attempt on purpose: the portal prompt the user
     * has not answered yet is attached to it, and dropping the source would
     * take the prompt away just as they reach for it. */
    void *pWayland;
    /* Encoded pipeline state */
    directgate_desktop_pipeline_t ePipeline;
    directgate_desktop_quality_t quality;
    xbool_t bForceRaw;       /* true when fallback raw RGBA path is forced */
    xbool_t bRequestKeyframe;/* set by preset change / drop recovery */
    xbool_t bWebRTCVideoFailed; /* suppress retry until track/ICE recovery */
    xbool_t bPreferDataChannel; /* browser could not decode RTP; avoid pipeline flapping */
    /* Adaptive bitrate controller state: current encoder rate (<= preset
     * target), clean recovery evidence (RTCP reports for RTP, ticks for the
     * DataChannel fallback), and the cooldown ticks left before the next
     * downward step is allowed. */
    uint32_t nCurrentBitrateKbps;
    uint32_t nAbrCeilingKbps; /* temporary route-specific cap; zero = preset target */
    uint32_t nAbrCleanEvidence;
    uint32_t nAbrHoldTicks;
    /* Consecutive receiver reports that came back lossy. Congestion is only
     * declared once this reaches DIRECTGATE_DESKTOP_ABR_LOSS_REPORTS; a
     * single lossy report is not evidence of a link that cannot carry the
     * rate, and treating it as such ratchets the session down for good. */
    uint32_t nAbrLossReports;
    /* Platform encoder state (opaque to cross-platform code): the macOS
     * ScreenCaptureKit/VideoToolbox encoder, the Linux X11/OpenH264
     * pipeline or the Windows DXGI/MediaFoundation pipeline, owned by
     * desktop_mac.m / desktop_linux.c / desktop_win.c respectively. */
    void *pEncoder;
    /* System-audio capture -> Opus -> WebRTC audio track (opaque
     * directgate_audio_t*, owned by desktop/audio.c). Strictly additive to the
     * video pipeline; opt-in via desktop-control so nothing is captured until
     * the viewer enables sound. */
    void *pAudio;
    xbool_t bAudioRequested;  /* browser opted in to system audio */
    xbool_t bAudioReady;      /* capture + encode thread is live */
    char sAudioReason[DIRECTGATE_DESKTOP_REASON_LEN]; /* why audio is unavailable */
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

#if defined(__linux__)
/* Releases every key the session still holds on the host - X server keycodes
 * on Xorg, portal keysyms on Wayland. Must run while the display connection
 * or the portal session is still open, or the keys stay latched for everyone
 * else on that machine. */
void DirectGate_Desktop_ReleaseHeldKeys(directgate_desktop_t *pDesktop);

/* Lets go of keys that are still down after a long silence, and reports
 * whether it decided they were stuck. Called every tick; a no-op unless
 * something is held. */
xbool_t DirectGate_Desktop_ExpireHeldKeys(directgate_desktop_t *pDesktop);
#endif

int DirectGate_Desktop_GetTimerFd(const directgate_desktop_t *pDesktop);
xbool_t DirectGate_Desktop_IsRunning(const directgate_desktop_t *pDesktop);
const char* DirectGate_Desktop_GetReason(const directgate_desktop_t *pDesktop);
void DirectGate_Desktop_AddMonitorMode(directgate_desktop_monitor_t *pMonitor,
                                       uint32_t nWidth, uint32_t nHeight);

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

/* System-audio streaming (desktop/audio.c + per-platform capture backend).
 * DIRECTGATE_DESKTOP_HAS_AUDIO gates the call sites; every desktop platform now
 * ships a backend (PulseAudio/PipeWire on Linux, WASAPI on Windows,
 * ScreenCaptureKit on macOS). */
#if defined(__linux__) || defined(_WIN32) || defined(__APPLE__)
#define DIRECTGATE_DESKTOP_HAS_AUDIO 1
#endif

#ifdef DIRECTGATE_DESKTOP_HAS_AUDIO
/* Starts opt-in system-audio capture: creates the Opus encoder, opens the
 * platform loopback source and spawns the capture/encode thread. Returns
 * XSTDOK, or XSTDERR with pDesktop->sAudioReason set (video is untouched). */
int  DirectGate_Desktop_AudioStart(directgate_session_t *pSession);
/* Stops capture and tears down the thread/encoder/backend (idempotent). Takes
 * the desktop struct so it can run from DirectGate_Desktop_Clear. */
void DirectGate_Desktop_AudioStop(directgate_desktop_t *pDesktop);
/* Drains the encoded-Opus mailbox on the main loop and sends each frame over
 * the WebRTC audio track. Called from DirectGate_Desktop_Process every tick;
 * a no-op unless the audio track is open. */
void DirectGate_Desktop_AudioDrainMain(directgate_session_t *pSession);
#endif

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
 * desktop_linux.c and only called by desktop.c on Linux. Capture and encode
 * run on a dedicated thread with its own Xlib connection; encoded frames
 * land in a single-slot mailbox drained by
 * DirectGate_Desktop_LinuxEncoder_DrainMain on the main loop. */
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

/* Drains the encoder mailbox on the main loop. Capture and encode run on
 * the pipeline's own thread (like the Windows and macOS backends); this is
 * called from DirectGate_Desktop_Process after a frame or the periodic tick
 * wakes the loop. */
int DirectGate_Desktop_LinuxEncoder_DrainMain(directgate_session_t *pSession);
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
