/*!
 * @file directgate-agent/src/agent/desktop.h
 * @brief Shared desktop session core and platform backend contract.
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

#define DIRECTGATE_DESKTOP_MONITOR_ID_SIZE 64
#define DIRECTGATE_DESKTOP_MONITOR_NAME_SIZE 128
#define DIRECTGATE_DESKTOP_MAX_MONITORS 16
#define DIRECTGATE_DESKTOP_MAX_PREVIEW_WIDTH 480

typedef enum directgate_desktop_quality_ {
    DIRECTGATE_DESKTOP_QUALITY_BALANCED = 0,
    DIRECTGATE_DESKTOP_QUALITY_HIGH,
    DIRECTGATE_DESKTOP_QUALITY_LOW_LATENCY,
} directgate_desktop_quality_t;

typedef enum directgate_desktop_preview_format_ {
    DIRECTGATE_DESKTOP_PREVIEW_JPEG = 0,
    DIRECTGATE_DESKTOP_PREVIEW_PNG,
} directgate_desktop_preview_format_t;

typedef struct directgate_desktop_monitor_ {
    char sId[DIRECTGATE_DESKTOP_MONITOR_ID_SIZE];
    char sName[DIRECTGATE_DESKTOP_MONITOR_NAME_SIZE];
    int32_t nX;
    int32_t nY;
    uint32_t nWidth;
    uint32_t nHeight;
    double fScale;
    xbool_t bPrimary;
} directgate_desktop_monitor_t;

typedef struct directgate_desktop_preview_ {
    char sMonitorId[DIRECTGATE_DESKTOP_MONITOR_ID_SIZE];
    uint32_t nGeneration;
    directgate_desktop_preview_format_t eFormat;
    uint32_t nWidth;
    uint32_t nHeight;
    uint8_t *pData;
    size_t nDataLen;
} directgate_desktop_preview_t;

typedef struct directgate_desktop_input_ {
    const char *pType;
    int32_t nX;
    int32_t nY;
    int32_t nButton;
    int32_t nDeltaX;
    int32_t nDeltaY;
    uint32_t nKeyCode;
    uint32_t nModifiers;
} directgate_desktop_input_t;

struct directgate_desktop_;
struct directgate_session_;
struct directgate_pkg_;

typedef struct directgate_desktop_backend_ops_ {
    XSTATUS (*init)(struct directgate_desktop_ *pDesktop);
    void (*cleanup)(struct directgate_desktop_ *pDesktop);
    XSTATUS (*enumerate_monitors)(struct directgate_desktop_ *pDesktop);
    XSTATUS (*capture_monitor_preview)(struct directgate_desktop_ *pDesktop,
                                       const char *pMonitorId,
                                       uint32_t nMaxWidth,
                                       directgate_desktop_preview_t *pPreview);
    XSTATUS (*start_stream)(struct directgate_desktop_ *pDesktop);
    XSTATUS (*stop_stream)(struct directgate_desktop_ *pDesktop);
    XSTATUS (*restart_stream_with_preset)(struct directgate_desktop_ *pDesktop,
                                          directgate_desktop_quality_t ePreset);
    XSTATUS (*request_keyframe)(struct directgate_desktop_ *pDesktop);
    XSTATUS (*send_input)(struct directgate_desktop_ *pDesktop,
                          const directgate_desktop_input_t *pInput);
    XSTATUS (*set_selected_monitor)(struct directgate_desktop_ *pDesktop,
                                    const char *pMonitorId);
} directgate_desktop_backend_ops_t;

typedef struct directgate_desktop_ {
    void *pPlatformCtx;
    const directgate_desktop_backend_ops_t *pOps;
    directgate_desktop_monitor_t monitors[DIRECTGATE_DESKTOP_MAX_MONITORS];
    uint8_t nMonitorCount;
    uint32_t nPreviewGeneration;
    directgate_desktop_quality_t ePreset;
    char sSelectedMonitorId[DIRECTGATE_DESKTOP_MONITOR_ID_SIZE];
    xbool_t bInitialized;
    xbool_t bStreaming;
} directgate_desktop_t;

void DirectGate_Desktop_Init(directgate_desktop_t *pDesktop);
void DirectGate_Desktop_Cleanup(directgate_desktop_t *pDesktop);
void DirectGate_Desktop_ResetPreview(directgate_desktop_preview_t *pPreview);
void DirectGate_Desktop_FreePreview(directgate_desktop_preview_t *pPreview);

XSTATUS DirectGate_Desktop_SetBackend(directgate_desktop_t *pDesktop,
                                      const directgate_desktop_backend_ops_t *pOps,
                                      void *pPlatformCtx);
XSTATUS DirectGate_Desktop_EnumerateMonitors(directgate_desktop_t *pDesktop);
XSTATUS DirectGate_Desktop_CaptureMonitorPreview(directgate_desktop_t *pDesktop,
                                                const char *pMonitorId,
                                                uint32_t nMaxWidth,
                                                directgate_desktop_preview_t *pPreview);
XSTATUS DirectGate_Desktop_StartStream(directgate_desktop_t *pDesktop);
XSTATUS DirectGate_Desktop_StopStream(directgate_desktop_t *pDesktop);
XSTATUS DirectGate_Desktop_RestartStreamWithPreset(directgate_desktop_t *pDesktop,
                                                  directgate_desktop_quality_t ePreset);
XSTATUS DirectGate_Desktop_RequestKeyframe(directgate_desktop_t *pDesktop);
XSTATUS DirectGate_Desktop_SendInput(directgate_desktop_t *pDesktop,
                                    const directgate_desktop_input_t *pInput);
XSTATUS DirectGate_Desktop_SetSelectedMonitor(directgate_desktop_t *pDesktop,
                                             const char *pMonitorId);
int DirectGate_Desktop_SendStatus(struct directgate_session_ *pSession,
                                  const char *pFallbackReason);
int DirectGate_Desktop_HandleMessage(struct directgate_session_ *pSession,
                                     struct directgate_pkg_ *pPkg);

#ifdef __cplusplus
}
#endif

#endif
