/*!
 * @file directgate-agent/src/agent/desktop/priv.h
 * @brief Internal helpers shared across the desktop streaming units.
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

/* Cross-unit declarations for the desktop streaming code. desktop.c carries
 * the shared controller/state and geometry helpers; the platform capture,
 * input and display units (display.c / input.c /
 * stream.c) reuse them through this internal header. None of these
 * symbols are part of the public desktop API (see desktop.h). */

#ifndef __DIRECTGATE_DESKTOP_PRIV_H__
#define __DIRECTGATE_DESKTOP_PRIV_H__

#include "desktop.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Default capture/encode rate used before a preset is applied and by the
 * platform frame timers. Shared by desktop.c and stream.c. */
#define DIRECTGATE_DESKTOP_DEFAULT_FPS       6U

/* Shared controller/state helpers (desktop.c). */
void DirectGate_Desktop_SetReason(directgate_desktop_t *pDesktop, const char *pReason);
void DirectGate_Desktop_SetFallbackReason(directgate_desktop_t *pDesktop, const char *pReason);
int DirectGate_Desktop_SendStatus(directgate_session_t *pSession, const char *pStatus, const char *pReason);
void DirectGate_Desktop_SendCursorPosition(directgate_session_t *pSession, int nScreenX, int nScreenY, uint32_t nSequence);
xbool_t DirectGate_Desktop_ClampCursorToCapture(const directgate_desktop_t *pDesktop, int *pScreenX, int *pScreenY);
xbool_t DirectGate_Desktop_FallbackToDataChannel(directgate_session_t *pSession);
void DirectGate_Desktop_ReadResizeRequest(directgate_desktop_t *pDesktop, xjson_obj_t *pRoot);
void DirectGate_Desktop_LimitFrameSize(const directgate_desktop_t *pDesktop, uint32_t *pWidth, uint32_t *pHeight);

/* Shared geometry / monitor-table helpers (desktop.c). */
void DirectGate_Desktop_SetCapture(directgate_desktop_t *pDesktop,
                                   const char *pMonitorId,
                                   int32_t nX,
                                   int32_t nY,
                                   uint32_t nWidth,
                                   uint32_t nHeight);

void DirectGate_Desktop_AddMonitor(directgate_desktop_t *pDesktop,
                                   const char *pId,
                                   const char *pName,
                                   int32_t nX,
                                   int32_t nY,
                                   uint32_t nWidth,
                                   uint32_t nHeight,
                                   xbool_t bPrimary);

void DirectGate_Desktop_ComputeFrameSize(directgate_desktop_t *pDesktop);
const directgate_desktop_monitor_t* DirectGate_Desktop_FindMonitor(const directgate_desktop_t *pDesktop, const char *pMonitorId);

#if defined(__linux__) || defined(__APPLE__) || defined(_WIN32)
/* Platform display open, monitor enumeration and mode switching
 * (display.c). */
void DirectGate_Desktop_RestoreDisplayMode(directgate_desktop_t *pDesktop);
int DirectGate_Desktop_SetDisplayResolution(directgate_desktop_t *pDesktop,
                                            const directgate_desktop_monitor_t *pMonitor,
                                            uint32_t nWidth, uint32_t nHeight);
#endif

#if defined(__linux__)
int DirectGate_Desktop_OpenX11(directgate_session_t *pSession);
#elif defined(__APPLE__)
int DirectGate_Desktop_OpenMacOS(directgate_session_t *pSession);
#elif defined(_WIN32)
int DirectGate_Desktop_OpenWindows(directgate_session_t *pSession);
#endif

#ifdef __cplusplus
}
#endif

#endif
