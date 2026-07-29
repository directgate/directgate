/*!
 * @file directgate-agent/src/agent/desktop/elevated.h
 * @brief Windows elevated-UI bridge: shared protocol between the agent, the
 *        SYSTEM launcher and the in-session SYSTEM desktop helper.
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

/*
 * Why this exists
 * ---------------
 * The agent runs as shell.user at medium integrity on winsta0\Default, which
 * Windows deliberately walls off from privileged UI in two different ways:
 *
 *   1. A UAC consent prompt, the lock screen and Ctrl+Alt+Del run on the
 *      separate winsta0\Winlogon "secure desktop". Duplication dies with
 *      DXGI_ERROR_ACCESS_LOST and OpenInputDesktop is refused, so the operator
 *      sees the frozen pre-prompt image and no input arrives.
 *   2. Task Manager and elevated application windows stay on Default, but UIPI
 *      silently drops synthesized input from a lower-integrity process while
 *      one of them is foreground.
 *
 * Both are lifted by a SYSTEM process, which UIPI does not restrict and which
 * may attach to the Winlogon desktop. A session-0 service cannot do it itself
 * (it lives on Service-0x0-3e7$ and has no reach into the interactive session),
 * so the existing LocalSystem launcher spawns a helper - the same executable
 * under --win-desktop-helper - inside the agent's session.
 *
 * Latency policy
 * --------------
 * The bridge is strictly a fallback. Normal operation keeps the agent's own
 * duplication and its own SendInput; the helper is engaged only after a real
 * refusal has been observed (SendInput returning ERROR_ACCESS_DENIED, or a lost
 * duplication that OpenInputDesktop confirms is the secure desktop). Nothing
 * here runs on the hot path.
 *
 * Trust boundary
 * --------------
 * Every kernel object below is minted by the launcher and duplicated into
 * exactly the two intended processes; nothing is named, so there is no object
 * namespace entry to squat and no DACL to get wrong. The helper accepts only
 * the fixed-size records defined here - it must never contain a parser for
 * attacker-shaped data, because the agent's untrusted protocol parsing is
 * exactly what the privilege-separation model keeps away from SYSTEM.
 */

#ifndef __DIRECTGATE_DESKTOP_ELEVATED_H__
#define __DIRECTGATE_DESKTOP_ELEVATED_H__
#ifdef _WIN32

#include "includes.h"
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DIRECTGATE_ELEV_HELPER_FLAG   "--win-desktop-helper"

/* Guards against a stray write landing on a channel: every record carries it
 * and a mismatch tears the channel down instead of being resynchronised. */
#define DIRECTGATE_ELEV_MAGIC         0x56454744U  /* "DGEV" */
#define DIRECTGATE_ELEV_SHM_MAGIC     0x4D485345U  /* "ESHM" */

/* The helper scales into a single slot sized for the capture rectangle. Beyond
 * this it scales to the cap and the agent scales the rest of the way - a 3+
 * monitor "all displays" rectangle is not worth 100 MB of committed section for
 * what is only ever a still dialog. */
#define DIRECTGATE_ELEV_MAX_WIDTH     3840U
#define DIRECTGATE_ELEV_MAX_HEIGHT    2160U

/* Helper start-up budget, and how long a frame wait may block the capture
 * thread before it gives up and reuses the previous picture. */
#define DIRECTGATE_ELEV_ATTACH_WAIT_MS 5000U
#define DIRECTGATE_ELEV_FRAME_WAIT_MS  250U

/* Operator-facing explanation of why privileged UI is unreachable; goes out
 * verbatim in desktop-status as `elevatedReason`. */
#define DIRECTGATE_ELEV_REASON_LEN     192

typedef enum {
    /* agent -> helper */
    DIRECTGATE_ELEV_MSG_INPUT          = 1,
    DIRECTGATE_ELEV_MSG_CURSOR         = 2,
    DIRECTGATE_ELEV_MSG_CAPTURE_START  = 3,
    DIRECTGATE_ELEV_MSG_CAPTURE_STOP   = 4,

    /* agent -> launcher */
    DIRECTGATE_ELEV_MSG_HELPER_REQUEST = 64,
    DIRECTGATE_ELEV_MSG_HELPER_RELEASE = 65,
    DIRECTGATE_ELEV_MSG_SAS_REQUEST    = 66,

    /* launcher -> agent */
    DIRECTGATE_ELEV_MSG_HELPER_READY   = 96
} directgate_elev_msg_t;

/* nLength counts payload bytes only and is validated against the exact size
 * expected for nType; anything else drops the record. */
typedef struct directgate_elev_hdr_ {
    uint32_t nMagic;
    uint16_t nType;
    uint16_t nLength;
} directgate_elev_hdr_t;

typedef enum {
    DIRECTGATE_ELEV_INPUT_MOUSE = 0,
    DIRECTGATE_ELEV_INPUT_KEY   = 1
} directgate_elev_input_kind_t;

/* Deliberately pre-resolved: the agent has already turned the viewer's event
 * into the exact INPUT fields it would have passed to SendInput itself, so the
 * helper does no geometry, no key mapping and no interpretation. */
typedef struct directgate_elev_input_ {
    uint32_t nKind;    /* directgate_elev_input_kind_t */
    uint32_t nFlags;   /* mi.dwFlags or ki.dwFlags */
    uint32_t nData;    /* mi.mouseData, or ki.wVk */
    uint32_t nScan;    /* ki.wScan */
    int32_t  nX;       /* mi.dx */
    int32_t  nY;       /* mi.dy */
} directgate_elev_input_t;

typedef struct directgate_elev_cursor_ {
    int32_t nX;
    int32_t nY;
} directgate_elev_cursor_t;

typedef struct directgate_elev_capture_ {
    int32_t  nX;
    int32_t  nY;
    uint32_t nWidth;        /* capture rectangle on the virtual desktop */
    uint32_t nHeight;
    uint32_t nEncodeWidth;  /* size the helper must scale into the slot */
    uint32_t nEncodeHeight;
    uint32_t nFps;
} directgate_elev_capture_t;

typedef struct directgate_elev_helper_req_ {
    uint32_t nCaptureWidth;
    uint32_t nCaptureHeight;
} directgate_elev_helper_req_t;

/* Handle values already valid in the agent's own handle table: the launcher
 * duplicated them in before sending this. nStatus is XSTDOK or XSTDERR. */
typedef struct directgate_elev_helper_ready_ {
    int32_t  nStatus;
    uint32_t nSectionBytes;
    uint64_t hCommand;      /* write end of the agent -> helper pipe */
    uint64_t hSection;      /* frame section */
    uint64_t hFrameReady;   /* helper signals: a frame is in the slot */
    uint64_t hFrameTaken;   /* agent signals: slot is free again */
} directgate_elev_helper_ready_t;

typedef enum {
    DIRECTGATE_ELEV_DESKTOP_UNKNOWN = 0,
    DIRECTGATE_ELEV_DESKTOP_DEFAULT = 1,
    DIRECTGATE_ELEV_DESKTOP_SECURE  = 2
} directgate_elev_desktop_t;

/*
 * Shared frame section: this header followed by one BGRA slot.
 *
 * One slot rather than two, with an explicit hand-off: the helper fills the
 * slot, signals hFrameReady and waits on hFrameTaken before touching it again.
 * That cannot tear, needs no seqlock, applies natural backpressure and halves
 * the committed memory - the same shape as the encoder mailbox in
 * desktop_win.c. The event pair also orders the pixel and timestamp writes, so
 * only the fields the agent may sample at any moment are interlocked.
 */
typedef struct directgate_elev_shm_ {
    uint32_t nMagic;
    uint32_t nHeaderBytes;
    uint32_t nSlotBytes;
    uint32_t nMaxWidth;         /* largest frame the slot can hold */
    uint32_t nMaxHeight;

    /* Written before hFrameReady, read after it: no atomics needed. */
    uint32_t nWidth;
    uint32_t nHeight;
    uint32_t nStride;
    uint64_t nCapturedUs;       /* QPC microseconds; the same clock in both processes */

    /* Sampled by the agent at arbitrary times. */
    volatile LONG nInputDesktop;   /* directgate_elev_desktop_t */
    volatile LONG nCaptureFailed;  /* helper could not capture the input desktop */
    volatile LONG nCursorX;
    volatile LONG nCursorY;
    volatile LONG nHeartbeatMs;    /* GetTickCount() of the helper's last loop pass */
} directgate_elev_shm_t;

/* ---- framed record I/O ------------------------------------------------- */

/* Shared by all three processes so the framing has exactly one implementation.
 * pPayload must have room for DIRECTGATE_ELEV_MAX_PAYLOAD bytes; a bad magic or
 * an over-long record is reported as a dead channel rather than skipped. */
#define DIRECTGATE_ELEV_MAX_PAYLOAD 64

xbool_t DirectGate_Elevated_SendRecord(HANDLE hPipe, uint16_t nType,
                                       const void *pPayload, uint16_t nLength);
xbool_t DirectGate_Elevated_RecvRecord(HANDLE hPipe, uint16_t *pType,
                                       void *pPayload, uint16_t *pLength);

/* ---- agent side -------------------------------------------------------- */

/* Installed once at start-up from the handles the launcher inherited into the
 * agent. Without them the bridge stays unavailable and every entry point below
 * is a no-op, which is exactly what a console run or a launcher-less setup
 * should get. */
void DirectGate_Elevated_SetControlChannel(HANDLE hRead, HANDLE hWrite);
void DirectGate_Elevated_SetEnabled(xbool_t bElevatedInput, xbool_t bLockScreen);
xbool_t DirectGate_Elevated_Supported(void);

/* Desktop-session lifetime; reference counted so concurrent viewer sessions
 * share one helper. The frame slot is sized from the virtual desktop, so no
 * monitor or preset change can outgrow it and the helper is never rebuilt
 * mid-session. Attach is best effort - a failure only means privileged UI
 * stays unreachable, never that the session fails. */
int  DirectGate_Elevated_Attach(void);
void DirectGate_Elevated_Detach(void);
xbool_t DirectGate_Elevated_Ready(void);
const char* DirectGate_Elevated_Reason(void);

/* Input re-sends, called only once a direct injection has been refused. The
 * INPUT is the one the agent already built, so the helper reproduces the same
 * event rather than reinterpreting the viewer's. */
xbool_t DirectGate_Elevated_SendInput(const INPUT *pInput);
xbool_t DirectGate_Elevated_SetCursorPos(int nX, int nY);
xbool_t DirectGate_Elevated_GetCursorPos(int *pX, int *pY);
xbool_t DirectGate_Elevated_SendSAS(void);

/* Capture hand-over, driven by the capture thread while the secure desktop is
 * up. ReadFrame returns XSTDOK on a fresh frame, XSTDNON on a timeout and
 * XSTDERR when the helper is gone. */
int  DirectGate_Elevated_StartCapture(int32_t nX, int32_t nY,
                                      uint32_t nCaptureWidth, uint32_t nCaptureHeight,
                                      uint32_t nEncodeWidth, uint32_t nEncodeHeight,
                                      uint32_t nFps);
void DirectGate_Elevated_StopCapture(void);
int  DirectGate_Elevated_ReadFrame(uint8_t *pDstBGRA, uint32_t nWidth, uint32_t nHeight,
                                   uint32_t nTimeoutMs, uint64_t *pCapturedUs);

/* True when the input desktop is not "Default" - the agent can answer this
 * itself, because OpenInputDesktop being refused is the signal. */
xbool_t DirectGate_Elevated_SecureDesktopActive(void);

/* ---- helper side ------------------------------------------------------- */

/* Entry point for --win-desktop-helper. Runs as SYSTEM inside the agent's
 * session and never returns until the agent exits or the channel breaks. */
XSTATUS DirectGate_Elevated_HelperMain(int argc, char *argv[]);

#ifdef __cplusplus
}
#endif

#endif /* _WIN32 */
#endif /* __DIRECTGATE_DESKTOP_ELEVATED_H__ */
