/*!
 * @file directgate-agent/src/agent/desktop_win.c
 * @brief Windows desktop monitor enumeration and preview capture backend.
 */

#include "desktop.h"

#ifdef _WIN32

#include <windows.h>

static XSTATUS DirectGate_DesktopWin_Enumerate(directgate_desktop_t *pDesktop)
{
    memset(pDesktop->monitors, 0, sizeof(pDesktop->monitors));
    pDesktop->nMonitorCount = 1;

    directgate_desktop_monitor_t *pMonitor = &pDesktop->monitors[0];
    xstrncpy(pMonitor->sId, sizeof(pMonitor->sId), "desktop-0");
    xstrncpy(pMonitor->sName, sizeof(pMonitor->sName), "Desktop");
    pMonitor->nX = GetSystemMetrics(SM_XVIRTUALSCREEN);
    pMonitor->nY = GetSystemMetrics(SM_YVIRTUALSCREEN);
    pMonitor->nWidth = (uint32_t)XSTD_MAX(GetSystemMetrics(SM_CXVIRTUALSCREEN), 0);
    pMonitor->nHeight = (uint32_t)XSTD_MAX(GetSystemMetrics(SM_CYVIRTUALSCREEN), 0);
    pMonitor->fScale = 1.0;
    pMonitor->bPrimary = XTRUE;

    if (!xstrused(pDesktop->sSelectedMonitorId))
        xstrncpy(pDesktop->sSelectedMonitorId, sizeof(pDesktop->sSelectedMonitorId), pMonitor->sId);

    return XSTDOK;
}

static xbool_t DirectGate_DesktopWin_ReadFile(const char *pPath,
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

static XSTATUS DirectGate_DesktopWin_CapturePreview(directgate_desktop_t *pDesktop,
                                                    const char *pMonitorId,
                                                    uint32_t nMaxWidth,
                                                    directgate_desktop_preview_t *pPreview)
{
    (void)pDesktop;
    (void)pMonitorId;
    (void)nMaxWidth;

    char sTempDir[MAX_PATH];
    char sPath[MAX_PATH];
    if (GetTempPathA(sizeof(sTempDir), sTempDir) == 0) return XSTDERR;
    if (GetTempFileNameA(sTempDir, "dg", 0, sPath) == 0) return XSTDERR;

    char sCmd[4096];
    snprintf(sCmd, sizeof(sCmd),
        "powershell -NoProfile -ExecutionPolicy Bypass -Command "
        "\"Add-Type -AssemblyName System.Windows.Forms; "
        "Add-Type -AssemblyName System.Drawing; "
        "$b=[System.Windows.Forms.SystemInformation]::VirtualScreen; "
        "$bmp=New-Object System.Drawing.Bitmap $b.Width,$b.Height; "
        "$g=[System.Drawing.Graphics]::FromImage($bmp); "
        "$g.CopyFromScreen($b.Left,$b.Top,0,0,$bmp.Size); "
        "$bmp.Save('%s',[System.Drawing.Imaging.ImageFormat]::Jpeg); "
        "$g.Dispose(); $bmp.Dispose()\"",
        sPath);

    int nStatus = system(sCmd);
    if (nStatus != 0)
    {
        DeleteFileA(sPath);
        return XSTDERR;
    }

    XSTATUS nReadStatus = DirectGate_DesktopWin_ReadFile(sPath, pPreview) ? XSTDOK : XSTDERR;
    DeleteFileA(sPath);

    if (nReadStatus == XSTDOK)
    {
        pPreview->nWidth = (uint32_t)XSTD_MAX(GetSystemMetrics(SM_CXVIRTUALSCREEN), 0);
        pPreview->nHeight = (uint32_t)XSTD_MAX(GetSystemMetrics(SM_CYVIRTUALSCREEN), 0);
    }

    return nReadStatus;
}

static XSTATUS DirectGate_DesktopWin_SetSelectedMonitor(directgate_desktop_t *pDesktop,
                                                        const char *pMonitorId)
{
    return xstrcmp(pMonitorId, "desktop-0") || pDesktop->nMonitorCount == 1 ? XSTDOK : XSTDERR;
}

static XSTATUS DirectGate_DesktopWin_UnsupportedStream(directgate_desktop_t *pDesktop)
{
    (void)pDesktop;
    return XSTDERR;
}

static XSTATUS DirectGate_DesktopWin_UnsupportedPreset(directgate_desktop_t *pDesktop,
                                                       directgate_desktop_quality_t ePreset)
{
    (void)pDesktop;
    (void)ePreset;
    return XSTDERR;
}

static XSTATUS DirectGate_DesktopWin_UnsupportedInput(directgate_desktop_t *pDesktop,
                                                      const directgate_desktop_input_t *pInput)
{
    (void)pDesktop;
    (void)pInput;
    return XSTDERR;
}

static const directgate_desktop_backend_ops_t g_desktopWinOps = {
    NULL,
    NULL,
    DirectGate_DesktopWin_Enumerate,
    DirectGate_DesktopWin_CapturePreview,
    DirectGate_DesktopWin_UnsupportedStream,
    DirectGate_DesktopWin_UnsupportedStream,
    DirectGate_DesktopWin_UnsupportedPreset,
    DirectGate_DesktopWin_UnsupportedStream,
    DirectGate_DesktopWin_UnsupportedInput,
    DirectGate_DesktopWin_SetSelectedMonitor,
};

const directgate_desktop_backend_ops_t* DirectGate_Desktop_GetPlatformBackend(void)
{
    return &g_desktopWinOps;
}

#endif
