/*!
 * @file directgate-agent/src/agent/desktop.c
 * @brief Shared desktop session core and platform backend dispatch.
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

const directgate_desktop_backend_ops_t* DirectGate_Desktop_GetPlatformBackend(void);

static XSTATUS DirectGate_Desktop_NoBackend(void)
{
    return XSTDERR;
}

static const char* DirectGate_Desktop_DefaultMonitorId(const directgate_desktop_t *pDesktop)
{
    XCHECK((pDesktop != NULL), NULL);
    if (xstrused(pDesktop->sSelectedMonitorId))
        return pDesktop->sSelectedMonitorId;

    if (pDesktop->nMonitorCount > 0 && xstrused(pDesktop->monitors[0].sId))
        return pDesktop->monitors[0].sId;

    return NULL;
}

void DirectGate_Desktop_Init(directgate_desktop_t *pDesktop)
{
    XCHECK_VOID_NL((pDesktop != NULL));
    memset(pDesktop, 0, sizeof(*pDesktop));
    pDesktop->ePreset = DIRECTGATE_DESKTOP_QUALITY_BALANCED;

    const directgate_desktop_backend_ops_t *pOps = DirectGate_Desktop_GetPlatformBackend();
    if (pOps != NULL)
        DirectGate_Desktop_SetBackend(pDesktop, pOps, NULL);
}

void DirectGate_Desktop_Cleanup(directgate_desktop_t *pDesktop)
{
    XCHECK_VOID_NL((pDesktop != NULL));

    if (pDesktop->pOps != NULL && pDesktop->pOps->cleanup != NULL)
        pDesktop->pOps->cleanup(pDesktop);

    memset(pDesktop, 0, sizeof(*pDesktop));
}

void DirectGate_Desktop_ResetPreview(directgate_desktop_preview_t *pPreview)
{
    XCHECK_VOID_NL((pPreview != NULL));
    memset(pPreview, 0, sizeof(*pPreview));
    pPreview->eFormat = DIRECTGATE_DESKTOP_PREVIEW_JPEG;
}

void DirectGate_Desktop_FreePreview(directgate_desktop_preview_t *pPreview)
{
    XCHECK_VOID_NL((pPreview != NULL));
    free(pPreview->pData);
    DirectGate_Desktop_ResetPreview(pPreview);
}

XSTATUS DirectGate_Desktop_SetBackend(directgate_desktop_t *pDesktop,
                                      const directgate_desktop_backend_ops_t *pOps,
                                      void *pPlatformCtx)
{
    XCHECK((pDesktop != NULL), XSTDERR);
    XCHECK((pOps != NULL), XSTDERR);

    if (pDesktop->pOps != NULL && pDesktop->pOps->cleanup != NULL)
        pDesktop->pOps->cleanup(pDesktop);

    pDesktop->pOps = pOps;
    pDesktop->pPlatformCtx = pPlatformCtx;
    pDesktop->bInitialized = XFALSE;

    if (pOps->init == NULL)
    {
        pDesktop->bInitialized = XTRUE;
        return XSTDOK;
    }

    XSTATUS nStatus = pOps->init(pDesktop);
    pDesktop->bInitialized = (nStatus == XSTDOK) ? XTRUE : XFALSE;
    return nStatus;
}

XSTATUS DirectGate_Desktop_EnumerateMonitors(directgate_desktop_t *pDesktop)
{
    XCHECK((pDesktop != NULL), XSTDERR);
    if (pDesktop->pOps == NULL || pDesktop->pOps->enumerate_monitors == NULL)
        return DirectGate_Desktop_NoBackend();

    XSTATUS nStatus = pDesktop->pOps->enumerate_monitors(pDesktop);
    if (nStatus == XSTDOK)
        ++pDesktop->nPreviewGeneration;

    return nStatus;
}

XSTATUS DirectGate_Desktop_CaptureMonitorPreview(directgate_desktop_t *pDesktop,
                                                const char *pMonitorId,
                                                uint32_t nMaxWidth,
                                                directgate_desktop_preview_t *pPreview)
{
    XCHECK((pDesktop != NULL), XSTDERR);
    XCHECK((pPreview != NULL), XSTDERR);
    if (pDesktop->pOps == NULL || pDesktop->pOps->capture_monitor_preview == NULL)
        return DirectGate_Desktop_NoBackend();

    const char *pUseMonitorId = xstrused(pMonitorId) ?
        pMonitorId : DirectGate_Desktop_DefaultMonitorId(pDesktop);
    XCHECK(xstrused(pUseMonitorId), XSTDERR);

    uint32_t nUseMaxWidth = nMaxWidth > 0 ?
        XSTD_MIN(nMaxWidth, DIRECTGATE_DESKTOP_MAX_PREVIEW_WIDTH) :
        DIRECTGATE_DESKTOP_MAX_PREVIEW_WIDTH;

    DirectGate_Desktop_FreePreview(pPreview);
    xstrncpy(pPreview->sMonitorId, sizeof(pPreview->sMonitorId), pUseMonitorId);
    pPreview->nGeneration = pDesktop->nPreviewGeneration;

    return pDesktop->pOps->capture_monitor_preview(
        pDesktop, pUseMonitorId, nUseMaxWidth, pPreview);
}

XSTATUS DirectGate_Desktop_StartStream(directgate_desktop_t *pDesktop)
{
    XCHECK((pDesktop != NULL), XSTDERR);
    if (pDesktop->pOps == NULL || pDesktop->pOps->start_stream == NULL)
        return DirectGate_Desktop_NoBackend();

    XSTATUS nStatus = pDesktop->pOps->start_stream(pDesktop);
    if (nStatus == XSTDOK)
        pDesktop->bStreaming = XTRUE;

    return nStatus;
}

XSTATUS DirectGate_Desktop_StopStream(directgate_desktop_t *pDesktop)
{
    XCHECK((pDesktop != NULL), XSTDERR);
    if (pDesktop->pOps == NULL || pDesktop->pOps->stop_stream == NULL)
        return DirectGate_Desktop_NoBackend();

    XSTATUS nStatus = pDesktop->pOps->stop_stream(pDesktop);
    if (nStatus == XSTDOK)
        pDesktop->bStreaming = XFALSE;

    return nStatus;
}

XSTATUS DirectGate_Desktop_RestartStreamWithPreset(directgate_desktop_t *pDesktop,
                                                  directgate_desktop_quality_t ePreset)
{
    XCHECK((pDesktop != NULL), XSTDERR);
    if (pDesktop->pOps == NULL || pDesktop->pOps->restart_stream_with_preset == NULL)
        return DirectGate_Desktop_NoBackend();

    XSTATUS nStatus = pDesktop->pOps->restart_stream_with_preset(pDesktop, ePreset);
    if (nStatus == XSTDOK)
        pDesktop->ePreset = ePreset;

    return nStatus;
}

XSTATUS DirectGate_Desktop_RequestKeyframe(directgate_desktop_t *pDesktop)
{
    XCHECK((pDesktop != NULL), XSTDERR);
    if (pDesktop->pOps == NULL || pDesktop->pOps->request_keyframe == NULL)
        return DirectGate_Desktop_NoBackend();

    return pDesktop->pOps->request_keyframe(pDesktop);
}

XSTATUS DirectGate_Desktop_SendInput(directgate_desktop_t *pDesktop,
                                    const directgate_desktop_input_t *pInput)
{
    XCHECK((pDesktop != NULL), XSTDERR);
    XCHECK((pInput != NULL), XSTDERR);
    if (pDesktop->pOps == NULL || pDesktop->pOps->send_input == NULL)
        return DirectGate_Desktop_NoBackend();

    return pDesktop->pOps->send_input(pDesktop, pInput);
}

XSTATUS DirectGate_Desktop_SetSelectedMonitor(directgate_desktop_t *pDesktop,
                                             const char *pMonitorId)
{
    XCHECK((pDesktop != NULL), XSTDERR);
    XCHECK(xstrused(pMonitorId), XSTDERR);
    if (pDesktop->pOps == NULL || pDesktop->pOps->set_selected_monitor == NULL)
        return DirectGate_Desktop_NoBackend();

    XSTATUS nStatus = pDesktop->pOps->set_selected_monitor(pDesktop, pMonitorId);
    if (nStatus == XSTDOK)
        xstrncpy(pDesktop->sSelectedMonitorId, sizeof(pDesktop->sSelectedMonitorId), pMonitorId);

    return nStatus;
}

static const char* DirectGate_Desktop_PresetStr(directgate_desktop_quality_t ePreset)
{
    switch (ePreset)
    {
        case DIRECTGATE_DESKTOP_QUALITY_HIGH: return "quality";
        case DIRECTGATE_DESKTOP_QUALITY_LOW_LATENCY: return "low-latency";
        case DIRECTGATE_DESKTOP_QUALITY_BALANCED:
        default: return "balanced";
    }
}

static directgate_desktop_quality_t DirectGate_Desktop_PresetFromStr(const char *pPreset)
{
    if (xstrused(pPreset) && xstrcmp(pPreset, "quality"))
        return DIRECTGATE_DESKTOP_QUALITY_HIGH;
    if (xstrused(pPreset) && xstrcmp(pPreset, "low-latency"))
        return DIRECTGATE_DESKTOP_QUALITY_LOW_LATENCY;
    return DIRECTGATE_DESKTOP_QUALITY_BALANCED;
}

static void DirectGate_Desktop_PresetTargets(directgate_desktop_quality_t ePreset,
                                             uint32_t *pFps,
                                             uint32_t *pBitrateKbps)
{
    XCHECK_VOID_NL((pFps != NULL));
    XCHECK_VOID_NL((pBitrateKbps != NULL));
    *pFps = 30;

    switch (ePreset)
    {
        case DIRECTGATE_DESKTOP_QUALITY_HIGH:
            *pBitrateKbps = 10000;
            break;
        case DIRECTGATE_DESKTOP_QUALITY_LOW_LATENCY:
            *pBitrateKbps = 3000;
            break;
        case DIRECTGATE_DESKTOP_QUALITY_BALANCED:
        default:
            *pBitrateKbps = 6000;
            break;
    }
}

static xjson_obj_t* DirectGate_Desktop_BuildMonitorJson(xjson_obj_t *pArray,
                                                        const directgate_desktop_monitor_t *pMonitor)
{
    XCHECK((pArray != NULL), NULL);
    XCHECK((pMonitor != NULL), NULL);

    xjson_obj_t *pObj = XJSON_NewObject(pArray->pPool, NULL, XFALSE);
    XCHECK((pObj != NULL), NULL);

    XJSON_AddString(pObj, "id", xstrused(pMonitor->sId) ? pMonitor->sId : "display-0");
    XJSON_AddString(pObj, "name", xstrused(pMonitor->sName) ? pMonitor->sName : "Desktop");
    XJSON_AddInt(pObj, "x", (int)pMonitor->nX);
    XJSON_AddInt(pObj, "y", (int)pMonitor->nY);
    XJSON_AddU32(pObj, "width", pMonitor->nWidth);
    XJSON_AddU32(pObj, "height", pMonitor->nHeight);
    XJSON_AddBool(pObj, "primary", pMonitor->bPrimary);
    XJSON_AddObject(pArray, pObj);

    return pObj;
}

int DirectGate_Desktop_SendStatus(struct directgate_session_ *pSession,
                                  const char *pFallbackReason)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);

    directgate_desktop_t *pDesktop = &pSession->desktop;
    XSTATUS nEnumStatus = DirectGate_Desktop_EnumerateMonitors(pDesktop);

    uint32_t nFps = 30;
    uint32_t nBitrateKbps = 6000;
    DirectGate_Desktop_PresetTargets(pDesktop->ePreset, &nFps, &nBitrateKbps);

    xjson_obj_t *pRoot = XJSON_NewObject(NULL, NULL, XFALSE);
    XCHECK((pRoot != NULL), XAPI_DISCONNECT);

    XJSON_AddString(pRoot, "pipeline", "raw-rgba");
    XJSON_AddString(pRoot, "codec", "none");
    XJSON_AddString(pRoot, "preset", DirectGate_Desktop_PresetStr(pDesktop->ePreset));
    XJSON_AddU32(pRoot, "fps", nFps);
    XJSON_AddU32(pRoot, "bitrateKbps", nBitrateKbps);
    XJSON_AddString(pRoot, "transport", "relay");

    const char *pReason = pFallbackReason;
    if (!xstrused(pReason) && nEnumStatus != XSTDOK)
        pReason = "Desktop capture backend is unavailable on this host";
    if (xstrused(pReason))
        XJSON_AddString(pRoot, "fallbackReason", pReason);

    if (xstrused(pDesktop->sSelectedMonitorId))
        XJSON_AddString(pRoot, "selectedMonitorId", pDesktop->sSelectedMonitorId);

    xjson_obj_t *pMonitors = XJSON_NewArray(pRoot->pPool, "monitors", XFALSE);
    if (pMonitors != NULL)
    {
        for (uint8_t i = 0; i < pDesktop->nMonitorCount; i++)
            DirectGate_Desktop_BuildMonitorJson(pMonitors, &pDesktop->monitors[i]);
        XJSON_AddObject(pRoot, pMonitors);
    }

    size_t nPayloadLen = 0;
    char *pPayload = XJSON_DumpObj(pRoot, 0, &nPayloadLen);
    XJSON_FreeObject(pRoot);
    XCHECK((pPayload != NULL), XAPI_DISCONNECT);

    xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("desktop-status", pSession->nSessionId);
    if (pHeader == NULL)
    {
        free(pPayload);
        return XAPI_DISCONNECT;
    }

    XJSON_AddString(pHeader, "payloadType", "json");
    int nStatus = DirectGate_Session_Send(pSession, pHeader, (const uint8_t*)pPayload, nPayloadLen);
    XJSON_FreeObject(pHeader);
    free(pPayload);

    return nStatus;
}

static int DirectGate_Desktop_SendPreview(directgate_session_t *pSession, const char *pMonitorId)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);

    directgate_desktop_preview_t preview;
    DirectGate_Desktop_ResetPreview(&preview);

    if (DirectGate_Desktop_CaptureMonitorPreview(
            &pSession->desktop, pMonitorId, DIRECTGATE_DESKTOP_MAX_PREVIEW_WIDTH, &preview) != XSTDOK)
    {
        DirectGate_Desktop_SendStatus(pSession, "Desktop preview capture failed or permission is missing");
        DirectGate_Desktop_FreePreview(&preview);
        return XAPI_CONTINUE;
    }

    xjson_obj_t *pHeader = DirectGate_Proto_NewHeader("desktop", pSession->nSessionId);
    if (pHeader == NULL)
    {
        DirectGate_Desktop_FreePreview(&preview);
        return XAPI_DISCONNECT;
    }

    XJSON_AddString(pHeader, "payloadType", "desktop-monitor-preview");
    XJSON_AddString(pHeader, "monitorId", preview.sMonitorId);
    XJSON_AddU32(pHeader, "generation", preview.nGeneration);
    XJSON_AddString(pHeader, "format",
        preview.eFormat == DIRECTGATE_DESKTOP_PREVIEW_PNG ? "png" : "jpeg");
    XJSON_AddU32(pHeader, "width", preview.nWidth);
    XJSON_AddU32(pHeader, "height", preview.nHeight);

    int nStatus = DirectGate_Session_Send(pSession, pHeader, preview.pData, preview.nDataLen);
    XJSON_FreeObject(pHeader);
    DirectGate_Desktop_FreePreview(&preview);

    return nStatus;
}

static int DirectGate_Desktop_SendAllPreviews(directgate_session_t *pSession)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);

    if (DirectGate_Desktop_EnumerateMonitors(&pSession->desktop) != XSTDOK)
        return DirectGate_Desktop_SendStatus(pSession, "Desktop monitor enumeration failed");

    if (pSession->desktop.nMonitorCount == 0)
        return DirectGate_Desktop_SendStatus(pSession, "No desktop monitors are available");

    for (uint8_t i = 0; i < pSession->desktop.nMonitorCount; i++)
    {
        int nStatus = DirectGate_Desktop_SendPreview(pSession, pSession->desktop.monitors[i].sId);
        if (nStatus < 0) return nStatus;
    }

    return XAPI_CONTINUE;
}

int DirectGate_Desktop_HandleMessage(struct directgate_session_ *pSession,
                                     struct directgate_pkg_ *pPkg)
{
    XCHECK((pSession != NULL), XAPI_DISCONNECT);
    XCHECK((pPkg != NULL), XAPI_DISCONNECT);
    XCHECK((pPkg->pPackage != NULL), XAPI_DISCONNECT);

    if (DirectGate_Session_EnsureMode(pSession, DIRECTGATE_SESSION_MODE_DESKTOP,
        "desktop session not started") != XSTDOK) return XAPI_CONTINUE;

    const directgate_pkg_desktop_t *pDesk = (const directgate_pkg_desktop_t*)pPkg->pPackage;
    if (!xstrused(pDesk->pAction))
        return DirectGate_Desktop_SendStatus(pSession, "Desktop action is missing");

    if (xstrcmp(pDesk->pAction, "refresh-monitors"))
        return DirectGate_Desktop_SendStatus(pSession, NULL);

    if (xstrcmp(pDesk->pAction, "refresh-monitor-previews"))
    {
        if (xstrused(pDesk->pMonitorId))
            return DirectGate_Desktop_SendPreview(pSession, pDesk->pMonitorId);
        return DirectGate_Desktop_SendAllPreviews(pSession);
    }

    if (xstrcmp(pDesk->pAction, "select-monitor"))
    {
        if (DirectGate_Desktop_SetSelectedMonitor(&pSession->desktop, pDesk->pMonitorId) != XSTDOK)
            return DirectGate_Desktop_SendStatus(pSession, "Monitor selection failed");

        DirectGate_Desktop_RequestKeyframe(&pSession->desktop);
        return DirectGate_Desktop_SendStatus(pSession, NULL);
    }

    if (xstrcmp(pDesk->pAction, "set-preset"))
    {
        directgate_desktop_quality_t ePreset = DirectGate_Desktop_PresetFromStr(pDesk->pPreset);
        if (DirectGate_Desktop_RestartStreamWithPreset(&pSession->desktop, ePreset) != XSTDOK)
            pSession->desktop.ePreset = ePreset;
        return DirectGate_Desktop_SendStatus(pSession, NULL);
    }

    if (xstrcmp(pDesk->pAction, "request-keyframe"))
    {
        DirectGate_Desktop_RequestKeyframe(&pSession->desktop);
        return DirectGate_Desktop_SendStatus(pSession, NULL);
    }

    if (xstrcmp(pDesk->pAction, "input"))
    {
        directgate_desktop_input_t input;
        memset(&input, 0, sizeof(input));
        input.pType = pDesk->pInputType;
        input.nX = pDesk->nX;
        input.nY = pDesk->nY;
        input.nButton = pDesk->nButton;
        input.nDeltaX = pDesk->nDeltaX;
        input.nDeltaY = pDesk->nDeltaY;
        input.nKeyCode = pDesk->nKeyCode;
        input.nModifiers = pDesk->nModifiers;

        if (DirectGate_Desktop_SendInput(&pSession->desktop, &input) != XSTDOK)
            return DirectGate_Desktop_SendStatus(pSession, "Desktop input failed or permission is missing");
        return XAPI_CONTINUE;
    }

    return DirectGate_Desktop_SendStatus(pSession, "Unknown desktop action");
}
