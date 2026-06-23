/*!
 * @file directgate-agent/src/agent/desktop_macos.c
 * @brief macOS desktop monitor enumeration and preview capture backend.
 */

#include "desktop.h"

#ifdef __APPLE__

#include <ApplicationServices/ApplicationServices.h>
#include <CoreFoundation/CoreFoundation.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static XSTATUS DirectGate_DesktopMac_Enumerate(directgate_desktop_t *pDesktop)
{
    CGDirectDisplayID displays[DIRECTGATE_DESKTOP_MAX_MONITORS];
    uint32_t nCount = 0;

    if (CGGetActiveDisplayList(DIRECTGATE_DESKTOP_MAX_MONITORS, displays, &nCount) != kCGErrorSuccess)
        return XSTDERR;

    memset(pDesktop->monitors, 0, sizeof(pDesktop->monitors));
    pDesktop->nMonitorCount = (uint8_t)XSTD_MIN(nCount, DIRECTGATE_DESKTOP_MAX_MONITORS);

    CGDirectDisplayID mainDisplay = CGMainDisplayID();
    for (uint8_t i = 0; i < pDesktop->nMonitorCount; i++)
    {
        directgate_desktop_monitor_t *pMonitor = &pDesktop->monitors[i];
        CGRect bounds = CGDisplayBounds(displays[i]);

        snprintf(pMonitor->sId, sizeof(pMonitor->sId), "display-%u", (unsigned int)displays[i]);
        snprintf(pMonitor->sName, sizeof(pMonitor->sName), "Display %u", (unsigned int)(i + 1));
        pMonitor->nX = (int32_t)bounds.origin.x;
        pMonitor->nY = (int32_t)bounds.origin.y;
        pMonitor->nWidth = (uint32_t)CGDisplayPixelsWide(displays[i]);
        pMonitor->nHeight = (uint32_t)CGDisplayPixelsHigh(displays[i]);
        pMonitor->fScale = bounds.size.width > 0.0 ? ((double)pMonitor->nWidth / (double)bounds.size.width) : 1.0;
        pMonitor->bPrimary = displays[i] == mainDisplay;

        if (pMonitor->bPrimary && !xstrused(pDesktop->sSelectedMonitorId))
            xstrncpy(pDesktop->sSelectedMonitorId, sizeof(pDesktop->sSelectedMonitorId), pMonitor->sId);
    }

    if (!xstrused(pDesktop->sSelectedMonitorId) && pDesktop->nMonitorCount > 0)
        xstrncpy(pDesktop->sSelectedMonitorId, sizeof(pDesktop->sSelectedMonitorId), pDesktop->monitors[0].sId);

    return XSTDOK;
}

static xbool_t DirectGate_DesktopMac_ReadFile(const char *pPath,
                                              directgate_desktop_preview_t *pPreview)
{
    FILE *pFile = fopen(pPath, "rb");
    if (pFile == NULL) return XFALSE;

    if (fseek(pFile, 0, SEEK_END) != 0)
    {
        fclose(pFile);
        return XFALSE;
    }

    long nLen = ftell(pFile);
    if (nLen <= 0)
    {
        fclose(pFile);
        return XFALSE;
    }
    rewind(pFile);

    pPreview->pData = (uint8_t*)malloc((size_t)nLen);
    if (pPreview->pData == NULL)
    {
        fclose(pFile);
        return XFALSE;
    }

    size_t nRead = fread(pPreview->pData, 1, (size_t)nLen, pFile);
    fclose(pFile);

    if (nRead != (size_t)nLen)
    {
        free(pPreview->pData);
        pPreview->pData = NULL;
        return XFALSE;
    }

    pPreview->nDataLen = (size_t)nLen;
    pPreview->eFormat = DIRECTGATE_DESKTOP_PREVIEW_JPEG;
    return XTRUE;
}

static XSTATUS DirectGate_DesktopMac_CapturePreview(directgate_desktop_t *pDesktop,
                                                    const char *pMonitorId,
                                                    uint32_t nMaxWidth,
                                                    directgate_desktop_preview_t *pPreview)
{
    (void)nMaxWidth;
    char sBase[] = "/tmp/directgate-preview-XXXXXX";

    int nFd = mkstemp(sBase);
    if (nFd < 0) return XSTDERR;

    close(nFd);
    unlink(sBase);

    char sPath[sizeof(sBase) + 4];
    snprintf(sPath, sizeof(sPath), "%s.jpg", sBase);

    char sCmd[1024];
    snprintf(sCmd, sizeof(sCmd), "/usr/sbin/screencapture -x -t jpg '%s' >/dev/null 2>&1", sPath);

    int nStatus = system(sCmd);
    if (nStatus == -1 || !WIFEXITED(nStatus) || WEXITSTATUS(nStatus) != 0)
    {
        unlink(sPath);
        return XSTDERR;
    }

    XSTATUS nReadStatus = DirectGate_DesktopMac_ReadFile(sPath, pPreview) ? XSTDOK : XSTDERR;
    unlink(sPath);

    if (nReadStatus == XSTDOK)
    {
        for (uint8_t i = 0; i < pDesktop->nMonitorCount; i++)
        {
            if (xstrcmp(pDesktop->monitors[i].sId, pMonitorId))
            {
                pPreview->nWidth = pDesktop->monitors[i].nWidth;
                pPreview->nHeight = pDesktop->monitors[i].nHeight;
                break;
            }
        }
    }

    return nReadStatus;
}

static XSTATUS DirectGate_DesktopMac_SetSelectedMonitor(directgate_desktop_t *pDesktop,
                                                        const char *pMonitorId)
{
    for (uint8_t i = 0; i < pDesktop->nMonitorCount; i++)
    {
        if (xstrcmp(pDesktop->monitors[i].sId, pMonitorId))
            return XSTDOK;
    }

    return XSTDERR;
}

static XSTATUS DirectGate_DesktopMac_UnsupportedStream(directgate_desktop_t *pDesktop)
{
    (void)pDesktop;
    return XSTDERR;
}

static XSTATUS DirectGate_DesktopMac_UnsupportedPreset(directgate_desktop_t *pDesktop,
                                                       directgate_desktop_quality_t ePreset)
{
    (void)pDesktop;
    (void)ePreset;
    return XSTDERR;
}

static XSTATUS DirectGate_DesktopMac_UnsupportedInput(directgate_desktop_t *pDesktop,
                                                      const directgate_desktop_input_t *pInput)
{
    (void)pDesktop;
    (void)pInput;
    return XSTDERR;
}

static const directgate_desktop_backend_ops_t g_desktopMacOps = {
    NULL,
    NULL,
    DirectGate_DesktopMac_Enumerate,
    DirectGate_DesktopMac_CapturePreview,
    DirectGate_DesktopMac_UnsupportedStream,
    DirectGate_DesktopMac_UnsupportedStream,
    DirectGate_DesktopMac_UnsupportedPreset,
    DirectGate_DesktopMac_UnsupportedStream,
    DirectGate_DesktopMac_UnsupportedInput,
    DirectGate_DesktopMac_SetSelectedMonitor,
};

const directgate_desktop_backend_ops_t* DirectGate_Desktop_GetPlatformBackend(void)
{
    return &g_desktopMacOps;
}

#endif
