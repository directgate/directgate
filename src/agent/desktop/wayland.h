/*!
 * @file directgate-agent/src/agent/desktop/wayland.h
 * @brief Wayland desktop capture: xdg-desktop-portal session + PipeWire stream.
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

#ifndef __DIRECTGATE_WAYLAND_H__
#define __DIRECTGATE_WAYLAND_H__

#include "includes.h"

#ifdef DIRECTGATE_DESKTOP_HAS_WAYLAND

#ifdef __cplusplus
extern "C" {
#endif

/* Wayland has no equivalent of the X11 root window: a client cannot read the
 * screen, and cannot synthesise input, without the compositor agreeing to it.
 * Both capabilities are therefore obtained from xdg-desktop-portal over
 * D-Bus, in one session so the user is asked once, and the pixels then arrive
 * over PipeWire rather than from the display server.
 *
 * libpipewire-0.3 and libdbus-1 are opened at runtime, the way this agent
 * already treats OpenH264, libavcodec, libopus and libpulse. Nothing is
 * linked, so an X11-only host that has neither library keeps working exactly
 * as before, and a build with Wayland support still runs there - the feature
 * simply reports that it is unavailable. */

/* One frame, borrowed for the duration of the callback only.
 *
 * @a pPixels is BGRA in memory order, matching what the X11 path produces, so
 * the existing scale + I420 conversion applies unchanged. @a nStride is the
 * byte distance between rows and is routinely larger than nWidth * 4 -
 * treating the buffer as packed shears the image. */
typedef struct directgate_wl_frame_ {
    const uint8_t *pPixels;
    uint32_t nWidth;
    uint32_t nHeight;
    uint32_t nStride;
} directgate_wl_frame_t;

/* Called on the PipeWire stream thread, never on the agent's event loop.
 * The frame is invalid once it returns. */
typedef void (*directgate_wl_frame_cb_t)(void *pUserCtx, const directgate_wl_frame_t *pFrame);

typedef struct directgate_wl_capture_ directgate_wl_capture_t;

/* Loads libpipewire-0.3 once per process (idempotent). Returns XSTDOK, or
 * XSTDERR with a human-readable reason in pErrBuf. */
int DirectGate_WL_PipeWireLoad(char *pErrBuf, size_t nErrSize);

/* Connects to the PipeWire instance behind @p nPipeWireFd (the file
 * descriptor the portal handed back) and subscribes to stream @p nNodeId.
 *
 * Takes ownership of the descriptor either way. Returns NULL on failure with
 * the reason in pErrBuf. The stream is running when this returns, but the
 * format is negotiated asynchronously - see WaitFormat. */
directgate_wl_capture_t* DirectGate_WL_CaptureStart(int nPipeWireFd,
                                                    uint32_t nNodeId,
                                                    directgate_wl_frame_cb_t fnFrame,
                                                    void *pUserCtx,
                                                    char *pErrBuf,
                                                    size_t nErrSize);

/* Blocks until the stream has negotiated a video format or @p nTimeoutMs
 * passes. Must not be called from the agent's event loop. */
int DirectGate_WL_CaptureWaitFormat(directgate_wl_capture_t *pCapture, uint32_t nTimeoutMs);

/* Negotiated frame size; XFALSE before a format exists. */
xbool_t DirectGate_WL_CaptureSize(directgate_wl_capture_t *pCapture,
                                  uint32_t *pWidth, uint32_t *pHeight);

/* XTRUE once the stream has stopped for good it errored, or the compositor
 * took the screen back when someone pressed "Stop sharing". @p pErrBuf gets
 * the reason. Frames simply stop arriving, so a session that does not ask
 * shows the last one for ever. */
xbool_t DirectGate_WL_CaptureLost(directgate_wl_capture_t *pCapture, char *pErrBuf, size_t nErrSize);

void DirectGate_WL_CaptureStop(directgate_wl_capture_t *pCapture);

typedef struct directgate_wl_portal_ directgate_wl_portal_t;

/* Screens the portal actually granted. More than one only when the person
 * picked more than one; the portal never volunteers screens they did not. */
#define DIRECTGATE_WL_MAX_STREAMS 8

typedef struct directgate_wl_stream_ {
    uint32_t nNodeId;   /* PipeWire node carrying this screen */
    uint32_t nWidth;
    uint32_t nHeight;
    int32_t nX;
    int32_t nY;
} directgate_wl_stream_t;

/* Loads libdbus-1 once per process (idempotent). */
int DirectGate_WL_DBusLoad(char *pErrBuf, size_t nErrSize);

/* Runs the whole xdg-desktop-portal handshake and returns a session that owns
 * both the screen cast and the input capability.
 *
 * Capture and input are deliberately obtained from ONE RemoteDesktop session
 * rather than a ScreenCast session plus a RemoteDesktop session: the portal
 * asks the user once instead of twice, and the two stay consistent - the
 * stream that is being watched is the stream input is delivered to.
 *
 * This blocks for as long as the user takes to answer the compositor's
 * prompt, which can be minutes. It must therefore never be called from the
 * agent's event loop; see the setup worker in desktop_wayland.c.
 *
 * @p pRestoreToken (may be NULL) is a token from a previous grant; when the
 * compositor accepts it the prompt is skipped. The token it hands back for
 * next time is written to @p pNewToken.
 *
 * @p pDeclined (may be NULL) separates "they said no" from "it did not work",
 * so a caller can retry the second without putting a second prompt in front
 * of someone who already refused the first.
 *
 * Returns NULL on failure or refusal with the reason in pErrBuf. */
directgate_wl_portal_t* DirectGate_WL_PortalOpen(const char *pRestoreToken,
                                                 char *pNewToken, size_t nTokenSize,
                                                 xbool_t *pDeclined,
                                                 char *pErrBuf, size_t nErrSize);

/* PipeWire node id of the granted stream, and a descriptor connected to the
 * portal's PipeWire instance. The descriptor is opened once per call and the
 * caller owns it. */
uint32_t DirectGate_WL_PortalNodeId(const directgate_wl_portal_t *pPortal);
uint32_t DirectGate_WL_PortalStreamCount(const directgate_wl_portal_t *pPortal);

/* Did the compositor grant keyboard/pointer injection with the capture? */
xbool_t DirectGate_WL_PortalHasInput(const directgate_wl_portal_t *pPortal);

/* XTRUE once this portal has refused to type by character. Everything the
 * host keyboard layout carries still works - that goes in by position - but
 * a character it does not have cannot be typed at all, which is worth saying
 * out loud rather than dropping the keystroke. */
xbool_t DirectGate_WL_PortalKeysymRefused(const directgate_wl_portal_t *pPortal);
const directgate_wl_stream_t* DirectGate_WL_PortalStream(const directgate_wl_portal_t *pPortal, uint32_t nIndex);
int DirectGate_WL_PortalOpenPipeWire(directgate_wl_portal_t *pPortal, char *pErrBuf, size_t nErrSize);

/* Input injection. Coordinates are relative to the granted stream, not to the
 * desktop, because that is the only frame of reference a Wayland client is
 * given. Keysyms are XKB keysyms, the same values the X11 path resolves. */
int DirectGate_WL_PortalPointerMotion(directgate_wl_portal_t *pPortal, uint32_t nStream, double nX, double nY);
int DirectGate_WL_PortalPointerButton(directgate_wl_portal_t *pPortal, int32_t nButton, xbool_t bPressed);
int DirectGate_WL_PortalPointerAxis(directgate_wl_portal_t *pPortal, double nDx, double nDy);
int DirectGate_WL_PortalKeysym(directgate_wl_portal_t *pPortal, int32_t nKeysym, xbool_t bPressed);

/* A key by position rather than by character: @p nKeycode is the Linux evdev
 * code, and the compositor's own layout decides what it types. This is how a
 * host whose keyboard is set to another script types that script - a keysym
 * asks for a character the host layout may not even have. */
int DirectGate_WL_PortalKeycode(directgate_wl_portal_t *pPortal, int32_t nKeycode, xbool_t bPressed);

/* Maps a browser/X11 button number (1 left, 2 middle, 3 right, 8/9 side) to
 * the evdev code the portal expects. Returns 0 when there is no mapping. */
int32_t DirectGate_WL_PortalButtonCode(uint32_t nX11Button);

void DirectGate_WL_PortalClose(directgate_wl_portal_t *pPortal);

/* Portal grant plus PipeWire stream, driven to readiness on a thread of its
 * own and then presented to the encoder as "here is the newest frame".
 *
 * The thread is not an optimisation. Opening the portal waits for a person to
 * answer a prompt, and doing that on the agent's event loop stops everything
 * else it owes the session - ICE candidates above all, which arrive during
 * exactly that window and are dropped if nothing is reading them. So Create
 * returns at once and the caller polls State. */
typedef struct directgate_wl_source_ directgate_wl_source_t;

typedef enum {
    DIRECTGATE_WL_PENDING = 0,  /* still negotiating, or waiting on the user */
    DIRECTGATE_WL_READY,        /* streaming; frames can be taken */
    DIRECTGATE_WL_FAILED        /* refused or broken, see SourceError */
} directgate_wl_state_t;

/* Returns NULL only when the thread could not be started at all. */
directgate_wl_source_t* DirectGate_WL_SourceCreate(const char *pTokenPath);

directgate_wl_state_t DirectGate_WL_SourceState(directgate_wl_source_t *pSource);
const char* DirectGate_WL_SourceError(directgate_wl_source_t *pSource);
xbool_t DirectGate_WL_SourceSize(directgate_wl_source_t *pSource, uint32_t *pWidth, uint32_t *pHeight);

/* Scales the newest frame into @p pDst (BGRA, @p nWidth x @p nHeight packed).
 * XSTDNON when nothing new has arrived since the last call, which lets the
 * caller skip a whole convert-encode-send pass on an idle desktop. */
int DirectGate_WL_SourceTakeFrame(directgate_wl_source_t *pSource, uint8_t *pDst,
                                  uint32_t nWidth, uint32_t nHeight);

/* Screens this grant covers, for the monitor list the viewer is offered. */
uint32_t DirectGate_WL_SourceScreenCount(directgate_wl_source_t *pSource);
const directgate_wl_stream_t* DirectGate_WL_SourceScreen(directgate_wl_source_t *pSource, uint32_t nIndex);

xbool_t DirectGate_WL_SourceHasInput(directgate_wl_source_t *pSource);

/* XTRUE when the granted stream has ended - revoked from the remote screen,
 * or broken. Polled from the session tick, because the only other symptom is
 * frames quietly never arriving again. */
xbool_t DirectGate_WL_SourceLost(directgate_wl_source_t *pSource, char *pErrBuf, size_t nErrSize);

/* Node the capture is bound to right now. Pointer motion is addressed to a
 * stream, so this has to follow the screen the viewer switched to. */
uint32_t DirectGate_WL_SourceActiveNode(directgate_wl_source_t *pSource);

/* Points the capture at one of the granted screens. Reconnecting the
 * PipeWire stream is cheap; the portal grant is untouched, so switching
 * screens never re-prompts. Returns XSTDOK when the new screen is streaming. */
int DirectGate_WL_SourceSelect(directgate_wl_source_t *pSource, uint32_t nNodeId);

/* The portal session that owns input for this source, for input.c. */
directgate_wl_portal_t* DirectGate_WL_SourcePortal(directgate_wl_source_t *pSource);

void DirectGate_WL_SourceDestroy(directgate_wl_source_t *pSource);

#ifdef __cplusplus
}
#endif

#endif /* DIRECTGATE_DESKTOP_HAS_WAYLAND */
#endif
